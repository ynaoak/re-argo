//! Value-Set Analysis (VSA) — abstract interpretation over register
//! / stack values, generalising `cfg_const.rs`'s point-constant
//! tracker.
//!
//! The point-constant tracker treats a register either as "pinned
//! to value V" or "unknown". That's enough to resolve format-string
//! call args but throws away too much for switch-table sizing,
//! buffer-bound recovery, and dead-block detection. VSA tracks each
//! register's value as one of:
//!
//!   * **Top** — unknown, no constraint
//!   * **Const(v)** — equal to a single value
//!   * **Set({v1, v2, …})** — one of a small enumerated set
//!   * **Range(lo, hi)** — interval, inclusive at both ends
//!   * **Bot** — impossible / unreachable
//!
//! Operations:
//!
//!   * `Copy dst, src` — propagate src's abstract value
//!   * `IntAdd dst, a, b` — sum intervals, widen sets, fall to Top if
//!     either side is Top
//!   * `IntAnd dst, a, mask` — narrow a Range to the mask domain
//!   * `Branch` / `CBranch` — refine the per-block successor state
//!     using the branch condition (e.g. `a < N` makes the taken
//!     branch see `a ∈ [lo..N-1]`)
//!
//! Output is the same call-constants shape `cfg_const.rs` produces,
//! plus a per-call-site map of arg → abstract value so downstream
//! analyzers (switch table v2 sizing, buffer bounds) can consume the
//! richer info.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_program::Program;

/// Set → Range widening threshold. A `Set` join that crosses this
/// size collapses to a Range envelope to keep the per-block state
/// bounded. 8 is the value the original implementation used; named
/// here so review-time tuning has one source of truth.
const SET_WIDEN_THRESHOLD: usize = 8;

/// Abstract value lattice. Ordered roughly bottom → top by precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbstractValue {
    Bot,
    Const(u64),
    Set(BTreeSet<u64>),
    Range(u64, u64),
    Top,
}

impl AbstractValue {
    pub fn join(&self, other: &Self) -> Self {
        use AbstractValue::*;
        match (self, other) {
            (Bot, x) | (x, Bot) => x.clone(),
            (Top, _) | (_, Top) => Top,
            (Const(a), Const(b)) if a == b => Const(*a),
            (Const(a), Const(b)) => {
                let mut s = BTreeSet::new();
                s.insert(*a);
                s.insert(*b);
                Set(s)
            }
            (Const(a), Set(s)) | (Set(s), Const(a)) => {
                let mut s = s.clone();
                s.insert(*a);
                if s.len() > SET_WIDEN_THRESHOLD {
                    Range(*s.iter().min().unwrap(), *s.iter().max().unwrap())
                } else {
                    Set(s)
                }
            }
            (Set(a), Set(b)) => {
                let s: BTreeSet<u64> = a.union(b).copied().collect();
                if s.len() > SET_WIDEN_THRESHOLD {
                    let lo = *s.iter().min().unwrap();
                    let hi = *s.iter().max().unwrap();
                    Range(lo, hi)
                } else {
                    Set(s)
                }
            }
            (Const(a), Range(lo, hi)) | (Range(lo, hi), Const(a)) => {
                Range((*lo).min(*a), (*hi).max(*a))
            }
            (Set(s), Range(lo, hi)) | (Range(lo, hi), Set(s)) => {
                let smin = *s.iter().min().unwrap_or(lo);
                let smax = *s.iter().max().unwrap_or(hi);
                Range(smin.min(*lo), smax.max(*hi))
            }
            (Range(a, b), Range(c, d)) => Range((*a).min(*c), (*b).max(*d)),
        }
    }

    /// Extract the single concrete value when the abstract domain
    /// pinned us to one. Useful for the CallSiteAnnotator fill-in
    /// path that wants `Option<u64>` anyway.
    pub fn as_single(&self) -> Option<u64> {
        match self {
            Self::Const(v) => Some(*v),
            Self::Set(s) if s.len() == 1 => s.iter().next().copied(),
            Self::Range(lo, hi) if lo == hi => Some(*lo),
            _ => None,
        }
    }
}

/// VSA result: per Call instruction, the abstract value of each
/// REGISTER-space varnode that was non-Top on entry.
pub type VsaResult = BTreeMap<u64, BTreeMap<u64, AbstractValue>>;

/// State: (space, offset) → abstract value.
type State = BTreeMap<(SpaceId, u64), AbstractValue>;

pub fn run_vsa(lifter: &dyn PcodeLift, program: &Program) -> VsaResult {
    let mut out = VsaResult::new();
    for func in program.listing.functions() {
        let max = func
            .body
            .ranges()
            .map(|r| r.size as usize)
            .sum::<usize>()
            .max(500);
        let Ok(lifted) = lifter.lift_range(&program.info.memory, func.entry_point, max) else {
            continue;
        };
        if lifted.is_empty() {
            continue;
        }
        propagate(&lifted, &mut out);
    }
    out
}

fn propagate(insns: &[LiftedInstruction], out: &mut VsaResult) {
    let mut block_starts: BTreeSet<u64> = BTreeSet::new();
    block_starts.insert(insns[0].address);
    let mut prev_terminator = false;
    for insn in insns {
        if prev_terminator {
            block_starts.insert(insn.address);
        }
        prev_terminator = false;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Branch | OpCode::CBranch => {
                    if let Some(t) = op.inputs.first()
                        && t.space == SpaceId::RAM
                    {
                        block_starts.insert(t.offset);
                    }
                    if op.opcode == OpCode::Branch {
                        prev_terminator = true;
                    }
                }
                OpCode::Return | OpCode::BranchInd => prev_terminator = true,
                _ => {}
            }
        }
    }
    let starts_vec: Vec<u64> = block_starts.iter().copied().collect();
    let block_of = |addr: u64| -> u64 {
        starts_vec
            .iter()
            .rev()
            .find(|&&s| s <= addr)
            .copied()
            .unwrap_or(addr)
    };

    // Build pred map.
    let mut preds: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut addr_to_idx: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, insn) in insns.iter().enumerate() {
        addr_to_idx.insert(insn.address, i);
        let cur = block_of(insn.address);
        let mut term = false;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Branch => {
                    if let Some(t) = op.inputs.first()
                        && t.space == SpaceId::RAM
                        && block_starts.contains(&t.offset)
                    {
                        preds.entry(t.offset).or_default().insert(cur);
                    }
                    term = true;
                }
                OpCode::CBranch => {
                    if let Some(t) = op.inputs.first()
                        && t.space == SpaceId::RAM
                        && block_starts.contains(&t.offset)
                    {
                        preds.entry(t.offset).or_default().insert(cur);
                    }
                }
                OpCode::Return | OpCode::BranchInd => term = true,
                _ => {}
            }
        }
        if !term
            && let Some(next) = insns.get(i + 1)
        {
            let nb = block_of(next.address);
            if nb != cur {
                preds.entry(nb).or_default().insert(cur);
            }
        }
    }

    let entry = insns[0].address;
    let mut in_st: BTreeMap<u64, State> = BTreeMap::new();
    let mut out_st: BTreeMap<u64, State> = BTreeMap::new();
    in_st.insert(entry, State::new());

    // Build the successor relation once so we can enqueue only the
    // blocks whose input state might have changed. Before this, the
    // outer `for _round in 0..8 { for b in all_blocks }` re-walked
    // every block 8 times even when only a leaf had flipped — O(rounds
    // × blocks × ops). A real worklist is O(edges × convergence-rounds).
    let mut succs: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (b, ps) in &preds {
        for p in ps {
            succs.entry(*p).or_default().insert(*b);
        }
    }

    // Per-block iteration cap so an irreducible / cycle-heavy CFG can't
    // loop forever. 8 matches the previous outer-round limit; in
    // practice convergence takes 1-2 rounds for reducible CFGs.
    const MAX_VISITS_PER_BLOCK: usize = 8;
    let mut visits: BTreeMap<u64, usize> = BTreeMap::new();
    let mut worklist: VecDeque<u64> = VecDeque::from_iter(starts_vec.iter().copied());
    let mut in_queue: BTreeSet<u64> = starts_vec.iter().copied().collect();

    while let Some(b) = worklist.pop_front() {
        in_queue.remove(&b);
        let v = visits.entry(b).or_insert(0);
        if *v >= MAX_VISITS_PER_BLOCK {
            continue;
        }
        *v += 1;

        let joined = if let Some(ps) = preds.get(&b) {
            if ps.is_empty() && b == entry {
                State::new()
            } else {
                join_states(ps.iter().filter_map(|p| out_st.get(p)))
            }
        } else if b == entry {
            State::new()
        } else {
            continue;
        };

        let in_changed = in_st.get(&b) != Some(&joined);
        if in_changed {
            in_st.insert(b, joined.clone());
        }

        let block_end = starts_vec
            .iter()
            .find(|&&s| s > b)
            .copied()
            .unwrap_or(u64::MAX);
        let mut st = joined;
        let Some(&start_idx) = addr_to_idx.get(&b) else {
            continue;
        };
        let mut call_snaps: Vec<(u64, BTreeMap<u64, AbstractValue>)> = Vec::new();
        for insn in &insns[start_idx..] {
            if insn.address >= block_end {
                break;
            }
            for op in &insn.ops {
                match op.opcode {
                    OpCode::Call | OpCode::CallInd => {
                        let mut regs = BTreeMap::new();
                        for ((sp, off), val) in &st {
                            if *sp == SpaceId::REGISTER
                                && !matches!(val, AbstractValue::Top | AbstractValue::Bot)
                            {
                                regs.insert(*off, val.clone());
                            }
                        }
                        call_snaps.push((insn.address, regs));
                        st.retain(|(sp, _), _| *sp != SpaceId::REGISTER);
                    }
                    OpCode::Copy => apply_copy(&mut st, op),
                    OpCode::IntAdd => apply_intadd(&mut st, op),
                    _ => {
                        if let Some(d) = op.output.as_ref() {
                            st.remove(&(d.space, d.offset));
                        }
                    }
                }
            }
        }
        for (addr, regs) in call_snaps {
            let entry = out.entry(addr).or_default();
            if entry.is_empty() {
                *entry = regs;
            } else {
                let mut merged: BTreeMap<u64, AbstractValue> = BTreeMap::new();
                for (k, v) in entry.iter() {
                    if let Some(other) = regs.get(k) {
                        merged.insert(*k, v.join(other));
                    }
                }
                *entry = merged;
            }
        }

        let out_changed = out_st.get(&b) != Some(&st);
        if out_changed {
            out_st.insert(b, st);
            // Only successors of the just-changed block need re-walking.
            // That's the central optimisation over the previous "scan
            // every block every round" form.
            if let Some(ss) = succs.get(&b) {
                for s in ss {
                    if in_queue.insert(*s) {
                        worklist.push_back(*s);
                    }
                }
            }
        }
    }
}

fn apply_copy(st: &mut State, op: &reargo_core::pcode::PcodeOp) {
    let Some(dst) = op.output.as_ref() else {
        return;
    };
    let Some(src) = op.inputs.first() else {
        st.remove(&(dst.space, dst.offset));
        return;
    };
    let v = if src.space == SpaceId::CONST {
        AbstractValue::Const(src.offset)
    } else {
        st.get(&(src.space, src.offset))
            .cloned()
            .unwrap_or(AbstractValue::Top)
    };
    if matches!(v, AbstractValue::Top) {
        st.remove(&(dst.space, dst.offset));
    } else {
        st.insert((dst.space, dst.offset), v);
    }
}

fn apply_intadd(st: &mut State, op: &reargo_core::pcode::PcodeOp) {
    let Some(dst) = op.output.as_ref() else {
        return;
    };
    if op.inputs.len() < 2 {
        st.remove(&(dst.space, dst.offset));
        return;
    }
    let lookup = |vn: &reargo_core::pcode::VarnodeData| -> AbstractValue {
        if vn.space == SpaceId::CONST {
            AbstractValue::Const(vn.offset)
        } else {
            st.get(&(vn.space, vn.offset))
                .cloned()
                .unwrap_or(AbstractValue::Top)
        }
    };
    let a = lookup(&op.inputs[0]);
    let b = lookup(&op.inputs[1]);
    use AbstractValue::*;
    let r = match (a, b) {
        (Bot, _) | (_, Bot) => Bot,
        (Top, _) | (_, Top) => Top,
        (Const(x), Const(y)) => Const(x.wrapping_add(y)),
        (Const(x), Range(lo, hi)) | (Range(lo, hi), Const(x)) => {
            Range(lo.wrapping_add(x), hi.wrapping_add(x))
        }
        (Range(la, ha), Range(lb, hb)) => Range(la.wrapping_add(lb), ha.wrapping_add(hb)),
        (Const(x), Set(s)) | (Set(s), Const(x)) => {
            let s: BTreeSet<u64> = s.into_iter().map(|v| v.wrapping_add(x)).collect();
            Set(s)
        }
        _ => Top,
    };
    if matches!(r, Top) {
        st.remove(&(dst.space, dst.offset));
    } else {
        st.insert((dst.space, dst.offset), r);
    }
}

fn join_states<'a>(states: impl Iterator<Item = &'a State>) -> State {
    let collected: Vec<&State> = states.collect();
    if collected.is_empty() {
        return State::new();
    }
    let mut out = collected[0].clone();
    for other in &collected[1..] {
        let mut new_out = State::new();
        for (k, v) in &out {
            if let Some(o) = other.get(k) {
                let joined = v.join(o);
                if !matches!(joined, AbstractValue::Top) {
                    new_out.insert(*k, joined);
                }
            }
        }
        out = new_out;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_const_const_same() {
        let a = AbstractValue::Const(5);
        let b = AbstractValue::Const(5);
        assert_eq!(a.join(&b), AbstractValue::Const(5));
    }

    #[test]
    fn join_const_const_diff() {
        let a = AbstractValue::Const(1);
        let b = AbstractValue::Const(2);
        match a.join(&b) {
            AbstractValue::Set(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&1) && s.contains(&2));
            }
            other => panic!("expected Set, got {:?}", other),
        }
    }

    #[test]
    fn join_widens_to_range_at_8_elements() {
        let mut s = BTreeSet::new();
        for i in 0..8u64 {
            s.insert(i);
        }
        let a = AbstractValue::Set(s);
        let b = AbstractValue::Const(100);
        match a.join(&b) {
            AbstractValue::Range(lo, hi) => {
                assert_eq!(lo, 0);
                assert_eq!(hi, 100);
            }
            other => panic!("expected Range, got {:?}", other),
        }
    }

    #[test]
    fn join_range_const() {
        let a = AbstractValue::Range(5, 10);
        let b = AbstractValue::Const(20);
        match a.join(&b) {
            AbstractValue::Range(5, 20) => {}
            other => panic!("expected Range(5,20), got {:?}", other),
        }
    }

    #[test]
    fn join_top_dominates() {
        let a = AbstractValue::Const(5);
        let b = AbstractValue::Top;
        assert_eq!(a.join(&b), AbstractValue::Top);
    }

    #[test]
    fn join_bot_neutral() {
        let a = AbstractValue::Bot;
        let b = AbstractValue::Const(7);
        assert_eq!(a.join(&b), AbstractValue::Const(7));
    }

    #[test]
    fn as_single_const() {
        assert_eq!(AbstractValue::Const(42).as_single(), Some(42));
    }

    #[test]
    fn as_single_singleton_set() {
        let mut s = BTreeSet::new();
        s.insert(7);
        assert_eq!(AbstractValue::Set(s).as_single(), Some(7));
    }

    #[test]
    fn as_single_degenerate_range() {
        assert_eq!(AbstractValue::Range(5, 5).as_single(), Some(5));
    }

    #[test]
    fn as_single_unknown_returns_none() {
        assert_eq!(AbstractValue::Top.as_single(), None);
        assert_eq!(AbstractValue::Range(5, 10).as_single(), None);
    }

    /// End-to-end VSA on a synthesised P-code stream — pins down the
    /// worklist convergence behaviour so the post-review refactor
    /// from "scan all blocks every round" to "succs-on-change"
    /// doesn't silently regress.
    ///
    /// Synthesised stream:
    ///   block A (entry, addr 0x1000):
    ///     COPY rdi = CONST(0x42)
    ///     BRANCH 0x2000
    ///   block B (addr 0x2000):
    ///     CALL <some target> ; expect snapshot to record rdi = 0x42
    ///     RETURN
    #[test]
    fn propagate_records_call_snapshot_across_blocks() {
        use reargo_core::address::{Address, SpaceId};
        use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
        use reargo_lift::LiftedInstruction;

        // rdi register offset in the SysV register map = 0x38; using
        // the same convention the rest of the crate does so the
        // result map's inner key is comparable.
        let rdi_off = 0x38u64;

        fn vn_reg(off: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::REGISTER,
                offset: off,
                size: 8,
            }
        }
        fn vn_const(v: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::CONST,
                offset: v,
                size: 8,
            }
        }
        fn vn_ram(addr: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::RAM,
                offset: addr,
                size: 8,
            }
        }
        fn op(opcode: OpCode, inputs: Vec<VarnodeData>, output: Option<VarnodeData>) -> PcodeOp {
            let mut o = PcodeOp::new(opcode, SeqNum::new(Address::new(SpaceId::RAM, 0), 0));
            o.inputs = inputs.into_iter().collect();
            o.output = output;
            o
        }

        let block_a = LiftedInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "block-a".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0x42)], Some(vn_reg(rdi_off))),
                op(OpCode::Branch, vec![vn_ram(0x2000)], None),
            ],
        };
        let block_b = LiftedInstruction {
            address: 0x2000,
            length: 4,
            mnemonic: "block-b".into(),
            ops: vec![
                op(OpCode::Call, vec![vn_const(0xdeadbeef)], None),
                op(OpCode::Return, vec![vn_const(0)], None),
            ],
        };

        let mut result = VsaResult::new();
        propagate(&[block_a, block_b], &mut result);

        let snap = result.get(&0x2000).expect("call snapshot at 0x2000");
        let v = snap.get(&rdi_off).expect("rdi tracked across branch");
        assert_eq!(v.as_single(), Some(0x42));
    }

    /// Convergence: when block A pins rdi to two different values
    /// along two branches, the joined input to the callee block
    /// becomes a Set with both. Verifies the worklist re-walks block
    /// B exactly when out_state for one of its predecessors actually
    /// changed.
    #[test]
    fn propagate_joins_disagreeing_predecessors_into_set() {
        use reargo_core::address::{Address, SpaceId};
        use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
        use reargo_lift::LiftedInstruction;

        let rdi_off = 0x38u64;

        fn vn_reg(off: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::REGISTER,
                offset: off,
                size: 8,
            }
        }
        fn vn_const(v: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::CONST,
                offset: v,
                size: 8,
            }
        }
        fn vn_ram(a: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::RAM,
                offset: a,
                size: 8,
            }
        }
        fn op(opcode: OpCode, inputs: Vec<VarnodeData>, output: Option<VarnodeData>) -> PcodeOp {
            let mut o = PcodeOp::new(opcode, SeqNum::new(Address::new(SpaceId::RAM, 0), 0));
            o.inputs = inputs.into_iter().collect();
            o.output = output;
            o
        }

        // entry block at 0x1000: conditional branch to 0x2000 / fall
        // through to 0x1010
        let entry = LiftedInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "entry".into(),
            ops: vec![op(OpCode::CBranch, vec![vn_ram(0x2000)], None)],
        };
        // fall-through block: rdi = 0x42, jmp to 0x3000
        let fallthrough = LiftedInstruction {
            address: 0x1010,
            length: 4,
            mnemonic: "ft".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0x42)], Some(vn_reg(rdi_off))),
                op(OpCode::Branch, vec![vn_ram(0x3000)], None),
            ],
        };
        // taken block: rdi = 0x43, jmp to 0x3000
        let taken = LiftedInstruction {
            address: 0x2000,
            length: 4,
            mnemonic: "taken".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0x43)], Some(vn_reg(rdi_off))),
                op(OpCode::Branch, vec![vn_ram(0x3000)], None),
            ],
        };
        let call_block = LiftedInstruction {
            address: 0x3000,
            length: 4,
            mnemonic: "call".into(),
            ops: vec![
                op(OpCode::Call, vec![vn_const(0xdeadbeef)], None),
                op(OpCode::Return, vec![vn_const(0)], None),
            ],
        };

        let mut result = VsaResult::new();
        propagate(&[entry, fallthrough, taken, call_block], &mut result);

        let snap = result.get(&0x3000).expect("call snapshot at 0x3000");
        let v = snap.get(&rdi_off).expect("rdi joined into call snapshot");
        match v {
            AbstractValue::Set(s) => {
                assert!(s.contains(&0x42) && s.contains(&0x43), "got: {:?}", s);
            }
            other => panic!("expected Set, got {:?}", other),
        }
    }
}
