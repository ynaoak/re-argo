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

use std::collections::{BTreeMap, BTreeSet};

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, PcodeOp, VarnodeData};
use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_program::Program;
use rayon::prelude::*;

use crate::blockflow::{self, FlowState};
use crate::byteconst::{bit_mask, eval, is_unmodeled, is_view_refresh, ByteConst};
use crate::func_lift::{external_entries, function_jobs, in_extent, lift_function, owns};

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

/// One register (8 bytes at `offset & !7`) or temporary: its known
/// bytes, or an abstract `Set` / `Range` of its low `size` bytes with
/// the bytes above unknown. Constants are always `Bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Slot {
    Bytes(ByteConst),
    Low(u32, AbstractValue),
}

impl Slot {
    /// The known bytes (none for an abstract value).
    fn bytes(&self) -> ByteConst {
        match self {
            Slot::Bytes(b) => *b,
            Slot::Low(..) => ByteConst::UNKNOWN,
        }
    }

    /// The `size` bytes at byte `pos` as an abstract value.
    fn read(&self, pos: u32, size: u32) -> AbstractValue {
        match self {
            Slot::Bytes(b) => b.bytes_at(pos, size).get(size).map_or(AbstractValue::Top, AbstractValue::Const),
            Slot::Low(ls, v) if pos == 0 && size <= *ls => fit(v.clone(), size),
            Slot::Low(..) => AbstractValue::Top,
        }
    }

    /// The widest low part this slot pins: `(width, value)`.
    fn view(&self) -> Option<(u32, AbstractValue)> {
        match self {
            Slot::Bytes(b) => [8, 4, 2, 1].into_iter().find_map(|w| b.get(w).map(|v| (w, AbstractValue::Const(v)))),
            Slot::Low(s, v) => Some((*s, v.clone())),
        }
    }

    /// CFG join; `None` when nothing survives.
    fn join(&self, other: &Slot) -> Option<Slot> {
        if self == other {
            return Some(self.clone());
        }
        if let (Some((wa, va)), Some((wb, vb))) = (self.view(), other.view()) {
            let w = wa.min(wb);
            let j = normalize(fit(va, w).join(&fit(vb, w)));
            if matches!(j, AbstractValue::Set(_) | AbstractValue::Range(..)) {
                return Some(Slot::Low(w, j));
            }
        }
        let b = self.bytes().intersect(other.bytes());
        (!b.is_unknown()).then_some(Slot::Bytes(b))
    }
}

/// A computed value: known bytes, or an abstract value of the whole
/// output.
enum Val {
    Bytes(ByteConst),
    Abs(AbstractValue),
}

/// `Set` of one value / `Range` of one value → `Const`.
fn normalize(v: AbstractValue) -> AbstractValue {
    match v {
        AbstractValue::Set(s) if s.len() == 1 => AbstractValue::Const(*s.iter().next().unwrap()),
        AbstractValue::Set(s) if s.is_empty() => AbstractValue::Bot,
        AbstractValue::Range(lo, hi) if lo == hi => AbstractValue::Const(lo),
        v => v,
    }
}

/// `v` as a `size`-byte value (truncated); a range that does not fit
/// is unknown.
fn fit(v: AbstractValue, size: u32) -> AbstractValue {
    let m = bit_mask(size);
    normalize(match v {
        AbstractValue::Const(c) => AbstractValue::Const(c & m),
        AbstractValue::Set(s) => AbstractValue::Set(s.into_iter().map(|x| x & m).collect()),
        AbstractValue::Range(lo, hi) if hi <= m => AbstractValue::Range(lo, hi),
        AbstractValue::Range(..) => AbstractValue::Top,
        v => v,
    })
}

/// Sign-extend a `from`-byte value.
fn sext(v: AbstractValue, from: u32) -> AbstractValue {
    let ext = |x: u64| -> u64 {
        let bits = from.min(8) * 8;
        if bits >= 64 { x } else { (((x << (64 - bits)) as i64) >> (64 - bits)) as u64 }
    };
    let sign = |x: u64| from < 8 && x & (1u64 << (from * 8 - 1)) != 0;
    match v {
        AbstractValue::Const(c) => AbstractValue::Const(ext(c)),
        AbstractValue::Set(s) => AbstractValue::Set(s.into_iter().map(ext).collect()),
        AbstractValue::Range(lo, hi) if sign(lo) == sign(hi) => AbstractValue::Range(ext(lo), ext(hi)),
        AbstractValue::Range(..) => AbstractValue::Top,
        v => v,
    }
}

/// `a + b` as an `size`-byte value. A range that wraps is unknown.
fn add(a: AbstractValue, b: AbstractValue, size: u32) -> AbstractValue {
    use AbstractValue::*;
    let m = bit_mask(size);
    let r = match (a, b) {
        (Bot, _) | (_, Bot) => Bot,
        (Top, _) | (_, Top) => Top,
        (Const(x), Const(y)) => Const(x.wrapping_add(y) & m),
        (Const(x), Range(lo, hi)) | (Range(lo, hi), Const(x)) => {
            let (l, h) = (lo.wrapping_add(x) & m, hi.wrapping_add(x) & m);
            if l <= h && h - l == hi - lo { Range(l, h) } else { Top }
        }
        (Range(la, ha), Range(lb, hb)) => match (la.checked_add(lb), ha.checked_add(hb)) {
            (Some(l), Some(h)) if h <= m => Range(l, h),
            _ => Top,
        },
        (Const(x), Set(s)) | (Set(s), Const(x)) => Set(s.into_iter().map(|v| v.wrapping_add(x) & m).collect()),
        _ => Top,
    };
    normalize(r)
}

/// State: registers by base offset, other varnodes by `(space, offset)`
/// with their size. A missing entry is Top.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    regs: BTreeMap<u64, Slot>,
    temps: BTreeMap<(SpaceId, i64), (u32, Slot)>,
}

impl State {
    /// The known bytes of a varnode.
    fn read_bytes(&self, vn: &VarnodeData) -> ByteConst {
        match vn.space {
            SpaceId::CONST => ByteConst::konst(vn.offset, vn.size),
            SpaceId::REGISTER => match split(vn.offset, vn.size) {
                Some((base, pos)) => self.regs.get(&base).map_or(ByteConst::UNKNOWN, |s| s.bytes().bytes_at(pos, vn.size)),
                None => ByteConst::UNKNOWN,
            },
            s => match self.temps.get(&(s, vn.offset as i64)) {
                Some((sz, slot)) if *sz >= vn.size => slot.bytes().trunc(vn.size),
                _ => ByteConst::UNKNOWN,
            },
        }
    }

    /// The abstract value of a varnode.
    fn read(&self, vn: &VarnodeData) -> AbstractValue {
        match vn.space {
            SpaceId::CONST => AbstractValue::Const(vn.offset & bit_mask(vn.size)),
            SpaceId::REGISTER => match split(vn.offset, vn.size) {
                Some((base, pos)) => self.regs.get(&base).map_or(AbstractValue::Top, |s| s.read(pos, vn.size)),
                None => AbstractValue::Top,
            },
            s => match self.temps.get(&(s, vn.offset as i64)) {
                Some((sz, slot)) if *sz >= vn.size => slot.read(0, vn.size),
                _ => AbstractValue::Top,
            },
        }
    }

    fn write(&mut self, out: &VarnodeData, v: Val) {
        let v = match v {
            Val::Abs(AbstractValue::Const(c)) => Val::Bytes(ByteConst::konst(c, out.size)),
            Val::Abs(AbstractValue::Top | AbstractValue::Bot) => Val::Bytes(ByteConst::UNKNOWN),
            v => v,
        };
        if out.space == SpaceId::REGISTER {
            let Some((base, pos)) = split(out.offset, out.size) else {
                let end = out.offset.saturating_add(u64::from(out.size.max(1)));
                let bases: Vec<u64> = self.regs.range(out.offset & !7..end).map(|(b, _)| *b).collect();
                for b in bases {
                    self.regs.remove(&b);
                }
                return;
            };
            let next = match v {
                Val::Abs(a) if pos == 0 => Slot::Low(out.size, a),
                Val::Abs(_) => Slot::Bytes(self.regs.get(&base).map_or(ByteConst::UNKNOWN, Slot::bytes).merge(
                    pos,
                    out.size,
                    ByteConst::UNKNOWN,
                )),
                Val::Bytes(b) => {
                    Slot::Bytes(self.regs.get(&base).map_or(ByteConst::UNKNOWN, Slot::bytes).merge(pos, out.size, b))
                }
            };
            if next == Slot::Bytes(ByteConst::UNKNOWN) {
                self.regs.remove(&base);
            } else {
                self.regs.insert(base, next);
            }
            return;
        }
        let off = out.offset as i64;
        let end = off.saturating_add(i64::from(out.size.max(1)));
        let overlapping: smallvec::SmallVec<[(SpaceId, i64); 4]> = self
            .temps
            .range((out.space, off.saturating_sub(8))..(out.space, end))
            .filter(|((_, o), (sz, _))| o.saturating_add(i64::from(*sz)) > off)
            .map(|(k, _)| *k)
            .collect();
        for k in overlapping {
            self.temps.remove(&k);
        }
        if out.size > 8 {
            return;
        }
        let slot = match v {
            Val::Abs(a) => Slot::Low(out.size, a),
            Val::Bytes(b) if !b.trunc(out.size).is_unknown() => Slot::Bytes(b.trunc(out.size)),
            Val::Bytes(_) => return,
        };
        self.temps.insert((out.space, off), (out.size, slot));
    }

    /// The output value of a non-call op.
    fn eval(&self, op: &PcodeOp) -> Val {
        let Some(out) = op.output.as_ref() else {
            return Val::Bytes(ByteConst::UNKNOWN);
        };
        if op.opcode == OpCode::Load {
            return Val::Bytes(ByteConst::UNKNOWN);
        }
        let bytes = eval(op, |vn| self.read_bytes(vn));
        if let Some(b) = bytes
            && b.get(out.size).is_some()
        {
            return Val::Bytes(b);
        }
        let input = |i: usize| op.inputs.get(i).map_or(AbstractValue::Top, |vn| self.read(vn));
        let abs = match op.opcode {
            OpCode::Copy | OpCode::IntZExt => input(0),
            OpCode::IntSExt => op.inputs.first().map_or(AbstractValue::Top, |vn| sext(self.read(vn), vn.size)),
            OpCode::Subpiece => match op.inputs.get(1) {
                Some(k) if k.space == SpaceId::CONST && k.offset == 0 => input(0),
                Some(k) if k.space == SpaceId::CONST && k.offset < 8 => match input(0) {
                    AbstractValue::Set(s) => AbstractValue::Set(s.into_iter().map(|v| v >> (k.offset * 8)).collect()),
                    _ => AbstractValue::Top,
                },
                _ => AbstractValue::Top,
            },
            OpCode::IntAdd => add(input(0), input(1), out.size),
            _ => AbstractValue::Top,
        };
        match fit(abs, out.size.min(8)) {
            a @ (AbstractValue::Set(_) | AbstractValue::Range(..)) if out.size <= 8 => Val::Abs(a),
            AbstractValue::Const(c) if out.size <= 8 => Val::Bytes(ByteConst::konst(c, out.size)),
            _ => Val::Bytes(bytes.unwrap_or(ByteConst::UNKNOWN)),
        }
    }

    /// Apply one non-call op.
    fn apply(&mut self, op: &PcodeOp) {
        if is_unmodeled(op) {
            *self = State::default();
            return;
        }
        let Some(out) = op.output.as_ref() else {
            return;
        };
        if is_view_refresh(op) {
            return;
        }
        let v = self.eval(op);
        self.write(out, v);
    }

    /// Every register whose 8 bytes are pinned, at a call.
    fn call_snapshot(&self) -> BTreeMap<u64, AbstractValue> {
        self.regs
            .iter()
            .filter_map(|(b, s)| {
                let v = s.read(0, 8);
                (!matches!(v, AbstractValue::Top | AbstractValue::Bot)).then_some((*b, v))
            })
            .collect()
    }

    /// CFG join.
    fn join(&self, other: &State) -> State {
        let regs = self
            .regs
            .iter()
            .filter_map(|(b, s)| Some((*b, s.join(other.regs.get(b)?)?)))
            .collect();
        let temps = self
            .temps
            .iter()
            .filter_map(|(k, (sz, s))| {
                let (osz, o) = other.temps.get(k)?;
                (osz == sz).then_some(())?;
                Some((*k, (*sz, s.join(o)?)))
            })
            .collect();
        State { regs, temps }
    }
}

/// `(base, byte position)` of a REGISTER access inside one 8-byte
/// register.
fn split(offset: u64, size: u32) -> Option<(u64, u32)> {
    let pos = (offset & 7) as u32;
    (size > 0 && pos + size <= 8).then_some((offset & !7, pos))
}

pub fn run_vsa(lifter: &dyn PcodeLift, program: &Program) -> VsaResult {
    // Lift + propagate each function in parallel (a function's
    // propagation reads only its own lift), then merge the snapshots
    // in listing order, exactly as the sequential walk would.
    let per_func: Vec<Option<CallSnapshots>> = function_jobs(program)
        .par_iter()
        .map(|&(entry, max)| {
            lift_function(lifter, program, entry, max).map(|insns| function_snapshots(program, entry, &insns))
        })
        .collect();
    let mut out = VsaResult::new();
    for snaps in per_func.into_iter().flatten() {
        merge_snapshots(&mut out, snaps);
    }
    out
}

/// One function's call snapshots, in the order its worklist records
/// them (a site may appear once per visit).
pub type CallSnapshots = Vec<(u64, BTreeMap<u64, AbstractValue>)>;

/// Propagate the lifted instructions of the function at `entry`
/// (empty for an empty lift), keeping the call sites it owns. Merge
/// the results of every function, in listing order, with
/// [`merge_snapshots`] to get [`run_vsa`].
pub fn function_snapshots(program: &Program, entry: u64, insns: &[LiftedInstruction]) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    function_snapshots_with(program, entry, insns, &external_entries(program, insns))
}

/// [`function_snapshots`] with the lift's [`external_entries`] already
/// computed.
pub(crate) fn function_snapshots_with(
    program: &Program,
    entry: u64,
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    let mut snaps = propagate_with(insns, external, |a| in_extent(program, entry, a));
    snaps.retain(|(addr, _)| owns(program, entry, *addr));
    snaps
}

/// Fold one function's call snapshots into the program-wide map.
pub fn merge_snapshots(out: &mut VsaResult, snaps: CallSnapshots) {
    for (addr, regs) in snaps {
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
}

#[cfg(test)]
fn propagate(insns: &[LiftedInstruction]) -> CallSnapshots {
    propagate_with(insns, &BTreeSet::new(), |_| true)
}

fn propagate_with(
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
    in_body: impl Fn(u64) -> bool,
) -> CallSnapshots {
    blockflow::propagate::<State, _>(insns, external, in_body, State::call_snapshot)
}

impl FlowState for State {
    fn join(&self, other: &Self) -> Self {
        State::join(self, other)
    }
    fn apply(&mut self, op: &PcodeOp) {
        State::apply(self, op);
    }
    /// SysV: caller-saved registers clobbered (conservatively every
    /// register); temporaries are kept.
    fn after_call(&mut self) {
        self.regs.clear();
    }
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
        merge_snapshots(&mut result, propagate(&[block_a, block_b]));

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
        merge_snapshots(&mut result, propagate(&[entry, fallthrough, taken, call_block]));

        let snap = result.get(&0x3000).expect("call snapshot at 0x3000");
        let v = snap.get(&rdi_off).expect("rdi joined into call snapshot");
        match v {
            AbstractValue::Set(s) => {
                assert!(s.contains(&0x42) && s.contains(&0x43), "got: {:?}", s);
            }
            other => panic!("expected Set, got {:?}", other),
        }
    }

    /// The lifter's sub-register sequences, each followed by a call.
    #[test]
    fn sub_register_sequences_resolve() {
        use crate::byteconst::testseq::*;
        let snap = |ops: Vec<PcodeOp>| {
            let mut ops = ops;
            ops.push(op(OpCode::Call, None, &[k(0xdead, 8)]));
            let insn = LiftedInstruction { address: 0x1000, length: 4, mnemonic: "x".into(), ops };
            let mut result = VsaResult::new();
            merge_snapshots(&mut result, propagate(&[insn]));
            let s = result.remove(&0x1000).expect("call snapshot");
            move |r: u64| s.get(&r).and_then(AbstractValue::as_single)
        };
        assert_eq!(snap(mov_esi_imm32())(0x30), Some(0x2a));
        let s = snap(lea_rax_mov_rdi());
        assert_eq!((s(0), s(0x38)), (Some(0x402004), Some(0x402004)));
        assert_eq!(snap(mov_rax_then_al())(0), Some(0x7fff_1234_5605));
        let s = snap(ah_write_read());
        assert_eq!((s(0), s(0x08)), (Some(0x0734), Some(7)));
        let s = snap(movsx_movzx());
        assert_eq!(s(0x38), Some(0xffff_ff80));
        assert_eq!(s(0x30), Some(0x80));
        assert_eq!(s(0x80), Some(0xffff_ffff_ffff_ff80));
        assert_eq!(s(0x10), None);
    }

    /// A set flows through a 32-bit move and its view refreshes:
    /// `mov esi, {1|2}` joined, then `mov edi, esi` keeps the set in rdi.
    #[test]
    fn set_survives_32bit_move_and_views() {
        use crate::byteconst::testseq::*;
        let ram = |a: u64| VarnodeData { space: SpaceId::RAM, offset: a, size: 8 };
        let insn = |address: u64, ops: Vec<PcodeOp>| LiftedInstruction { address, length: 4, mnemonic: "x".into(), ops };
        let mut a = with_views(op(OpCode::Copy, Some(reg(0x30, 4)), &[k(1, 4)]));
        a.push(op(OpCode::Branch, None, &[ram(0x3000)]));
        let mut b = with_views(op(OpCode::Copy, Some(reg(0x30, 4)), &[k(2, 4)]));
        b.push(op(OpCode::Branch, None, &[ram(0x3000)]));
        let mut c = with_views(op(OpCode::Copy, Some(reg(0x38, 4)), &[reg(0x30, 4)]));
        c.push(op(OpCode::Call, None, &[k(0xdead, 8)]));
        let insns = [
            insn(0x1000, vec![op(OpCode::CBranch, None, &[ram(0x2000), reg(0x206, 1)])]),
            insn(0x1010, a),
            insn(0x2000, b),
            insn(0x3000, c),
        ];
        let mut result = VsaResult::new();
        merge_snapshots(&mut result, propagate(&insns));
        let snap = result.get(&0x3000).expect("call snapshot");
        assert_eq!(snap.get(&0x38), Some(&AbstractValue::Set([1u64, 2].into_iter().collect())));
    }
}
