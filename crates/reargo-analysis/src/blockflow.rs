//! Forward data flow over the basic blocks of one function's lifted
//! P-code, shared by `cfg_const` (point constants) and `vsa` (value
//! sets). Records the state at every call instruction.
//!
//! Blocks start at the function entry, at every jump target inside the
//! lift and after every instruction that jumps or returns; each edge
//! carries the state at its jump: a conditional jump's taken edge the
//! state when it jumps, the fall-through the state at the end of the
//! block. (Edges taken from the end of the block would give
//! `je L; …; mov ecx, 0xe0; jmp M` an `ecx = 0xe0` at `L`.) A block's
//! entry state joins the states of the edges into it that have been
//! computed; blocks no edge reaches (jump-table cases, code past the
//! function) are not walked.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use reargo_core::pcode::{OpCode, PcodeOp};
use reargo_lift::{InsnShape, LiftedInstruction};

/// Per-block visit cap, so an irreducible / cycle-heavy CFG cannot
/// loop forever; reducible CFGs converge in a few visits. A block
/// visited this often is walked a last time from the empty state
/// (nothing known), which stays sound whatever its inputs become.
const MAX_VISITS_PER_BLOCK: usize = 8;

/// A data-flow state.
pub trait FlowState: Clone + PartialEq + Default {
    /// Join at a control-flow merge.
    fn join(&self, other: &Self) -> Self;
    /// Apply a non-call, non-branch op.
    fn apply(&mut self, op: &PcodeOp);
    /// Clobber what a call clobbers.
    fn after_call(&mut self);
}

/// Jump target of a `Branch` / `CBranch` inside the lift.
fn target(op: &PcodeOp) -> Option<u64> {
    InsnShape::branch_target(op)
}

/// What the block structure and the linear call-site walk need of each
/// lifted instruction, read from its P-code once (the walks over a lift
/// otherwise scan every instruction's ops several times).
pub struct LiftShape {
    /// The addresses strictly increase.
    pub increasing: bool,
    /// Each instruction's address.
    pub addrs: Vec<u64>,
    /// It has a `Call` / `CallInd` op.
    pub has_call: Vec<bool>,
    /// `(instruction index, target)` of every `Branch` / `CBranch` with
    /// a jump target in the lift's space ([`target`]), in op order.
    pub branches: Vec<(usize, u64)>,
    /// It has a `Branch`, `CBranch`, `Return` or `BranchInd` op (it
    /// ends its block).
    pub ends_block: Vec<bool>,
    /// It has a `Branch`, `Return` or `BranchInd` op (no fall-through).
    pub stops: Vec<bool>,
}

impl LiftShape {
    pub fn of<I: Borrow<LiftedInstruction>>(insns: &[I]) -> LiftShape {
        Self::build(insns, |i| InsnShape::of(insns[i].borrow()))
    }

    /// [`LiftShape::of`] from the [`InsnShape`] of each instruction.
    pub fn from_shapes<I: Borrow<LiftedInstruction>>(insns: &[I], shapes: &[InsnShape]) -> LiftShape {
        debug_assert_eq!(insns.len(), shapes.len());
        Self::build(insns, |i| shapes[i])
    }

    fn build<I: Borrow<LiftedInstruction>>(insns: &[I], shape_of: impl Fn(usize) -> InsnShape) -> LiftShape {
        let n = insns.len();
        let mut shape = LiftShape {
            increasing: true,
            addrs: Vec::with_capacity(n),
            has_call: Vec::with_capacity(n),
            branches: Vec::new(),
            ends_block: Vec::with_capacity(n),
            stops: Vec::with_capacity(n),
        };
        for i in 0..n {
            let s = shape_of(i);
            if s.flags & InsnShape::TARGET != 0 {
                shape.branches.push((i, s.target));
            } else if s.flags & InsnShape::TARGETS != 0 {
                for op in &insns[i].borrow().ops {
                    if matches!(op.opcode, OpCode::Branch | OpCode::CBranch)
                        && let Some(t) = target(op)
                    {
                        shape.branches.push((i, t));
                    }
                }
            }
            if shape.addrs.last().is_some_and(|&last| last >= s.address) {
                shape.increasing = false;
            }
            shape.addrs.push(s.address);
            shape.has_call.push(s.flags & InsnShape::CALL != 0);
            shape.ends_block.push(s.flags & InsnShape::ENDS != 0);
            shape.stops.push(s.flags & InsnShape::STOPS != 0);
        }
        shape
    }
}

/// The blocks of one function's lift, computed once and walked by
/// every [`propagate_cfg`] over it.
pub struct Cfg {
    /// Index in `insns` of each block's first instruction, ascending.
    start_idx: Vec<usize>,
    /// Address of each block's first instruction, ascending.
    start_addr: Vec<u64>,
    /// Blocks walked from the empty state (entered from somewhere
    /// unknown), other than the entry block 0.
    unknown_entry: Vec<bool>,
    /// Static successors: block `b`'s are `succs[succ_at[b]..succ_at[b + 1]]`.
    succs: Vec<usize>,
    succ_at: Vec<usize>,
    /// Blocks that can reach a call whose snapshot is wanted (all when
    /// `None`): see [`Cfg::keep_calls`].
    relevant: Option<Vec<bool>>,
    /// The lift's addresses do not strictly increase: [`propagate_cfg`]
    /// runs the address-keyed walk instead.
    legacy: bool,
    /// For the legacy walk.
    external: BTreeSet<u64>,
    in_body_blocks: BTreeSet<u64>,
}

impl Cfg {
    /// The blocks of `insns` (see [`propagate`] for `external` and
    /// `in_body`).
    pub fn build<I: Borrow<LiftedInstruction>>(
        insns: &[I],
        external: &BTreeSet<u64>,
        in_body: impl Fn(u64) -> bool,
    ) -> Cfg {
        Cfg::build_shaped(&LiftShape::of(insns), external, in_body)
    }

    /// [`Cfg::build`] from the [`LiftShape`] of the instructions.
    pub fn build_shaped(shape: &LiftShape, external: &BTreeSet<u64>, in_body: impl Fn(u64) -> bool) -> Cfg {
        let addrs = &shape.addrs;
        let addr = |i: usize| addrs[i];
        if !shape.increasing || addrs.is_empty() {
            // the legacy walk asks `in_body` per block start; keep the
            // answers for every instruction address
            let in_body_blocks = addrs.iter().copied().filter(|a| in_body(*a)).collect();
            return Cfg {
                start_idx: Vec::new(),
                start_addr: Vec::new(),
                unknown_entry: Vec::new(),
                succs: Vec::new(),
                succ_at: Vec::new(),
                relevant: None,
                legacy: true,
                external: external.clone(),
                in_body_blocks,
            };
        }
        let idx_of = |a: u64| addrs.binary_search(&a).ok();
        let n = addrs.len();
        let mut is_start = vec![false; n];
        is_start[0] = true;
        for &a in external {
            if let Some(i) = idx_of(a) {
                is_start[i] = true;
            }
        }
        // Branch / CBranch targets, by instruction; whether an
        // instruction stops the fall-through (Branch, Return, BranchInd)
        for &(_, t) in &shape.branches {
            if let Some(t) = idx_of(t) {
                is_start[t] = true;
            }
        }
        for (start, &ends) in is_start[1..].iter_mut().zip(&shape.ends_block) {
            *start |= ends;
        }
        let targets = &shape.branches;
        let stops = &shape.stops;
        let start_idx: Vec<usize> = (0..n).filter(|&i| is_start[i]).collect();
        let start_addr: Vec<u64> = start_idx.iter().map(|&i| addr(i)).collect();
        let nb = start_idx.len();
        let block_of = |a: u64| start_addr.binary_search(&a).ok();
        // Static successors, to find the blocks the entry reaches: an
        // instruction that branches ends its block, so only a block's
        // last instruction branches or stops the fall-through.
        // (block `b`'s successors are `succs[succ_at[b]..succ_at[b + 1]]`)
        let mut succs: Vec<usize> = Vec::with_capacity(nb + targets.len());
        let mut succ_at: Vec<usize> = Vec::with_capacity(nb + 1);
        let mut ti = 0;
        for b in 0..nb {
            succ_at.push(succs.len());
            let last = start_idx.get(b + 1).copied().unwrap_or(n) - 1;
            while ti < targets.len() && targets[ti].0 < start_idx[b] {
                ti += 1;
            }
            while ti < targets.len() && targets[ti].0 <= last {
                succs.extend(block_of(targets[ti].1));
                ti += 1;
            }
            if !stops[last] && b + 1 < nb {
                succs.push(b + 1);
            }
        }
        succ_at.push(succs.len());
        let mut reached = vec![false; nb];
        reached[0] = true;
        let mut stack = vec![0usize];
        while let Some(b) = stack.pop() {
            for &s in &succs[succ_at[b]..succ_at[b + 1]] {
                if !reached[s] {
                    reached[s] = true;
                    stack.push(s);
                }
            }
        }
        let unknown_entry: Vec<bool> = (0..nb)
            .map(|b| b != 0 && (external.contains(&start_addr[b]) || (!reached[b] && in_body(start_addr[b]))))
            .collect();
        Cfg {
            start_idx,
            start_addr,
            unknown_entry,
            succs,
            succ_at,
            relevant: None,
            legacy: false,
            external: BTreeSet::new(),
            in_body_blocks: BTreeSet::new(),
        }
    }

    /// Walk only the blocks that can reach (along the static edges) a
    /// block holding an instruction of `insns` that `wanted` accepts:
    /// [`propagate_cfg`] then records the snapshots of the calls of
    /// those blocks only — the same, in the same order, as without the
    /// restriction. A block that cannot reach them has no edge into
    /// one that can (its successors cannot reach them either), so it
    /// changes no state, visit count or worklist order of theirs.
    pub fn keep_calls<I: Borrow<LiftedInstruction>>(&mut self, insns: &[I], wanted: impl Fn(&LiftedInstruction) -> bool) {
        self.keep_calls_at(insns.len(), |i| wanted(insns[i].borrow()));
    }

    /// [`Cfg::keep_calls`] with `wanted` asked of instruction indices
    /// (of the `n` instructions the blocks were built from).
    pub fn keep_calls_at(&mut self, n: usize, wanted: impl Fn(usize) -> bool) {
        if self.legacy {
            return;
        }
        let nb = self.start_idx.len();
        let mut preds_at = vec![0usize; nb + 1];
        for &s in &self.succs {
            preds_at[s + 1] += 1;
        }
        for b in 0..nb {
            preds_at[b + 1] += preds_at[b];
        }
        let mut fill = preds_at.clone();
        let mut preds = vec![0usize; self.succs.len()];
        for b in 0..nb {
            for &s in &self.succs[self.succ_at[b]..self.succ_at[b + 1]] {
                preds[fill[s]] = b;
                fill[s] += 1;
            }
        }
        let mut relevant = vec![false; nb];
        let mut stack: Vec<usize> = Vec::new();
        for (b, rel) in relevant.iter_mut().enumerate() {
            let end = self.start_idx.get(b + 1).copied().unwrap_or(n);
            if (self.start_idx[b]..end).any(&wanted) {
                *rel = true;
                stack.push(b);
            }
        }
        while let Some(b) = stack.pop() {
            for &p in &preds[preds_at[b]..preds_at[b + 1]] {
                if !relevant[p] {
                    relevant[p] = true;
                    stack.push(p);
                }
            }
        }
        self.relevant = Some(relevant);
    }
}

/// Run the flow over `insns` (one function's lift, entry first) and
/// return `(call address, snapshot(state at the call))` for every
/// visit of every call.
///
/// Blocks starting at an address of `external` (entered by a jump the
/// lift does not show, see [`crate::func_lift::external_entries`]) and
/// blocks of the function's extent (`in_body`) that no jump or
/// fall-through from the entry reaches (unrecovered jump-table cases)
/// start from the empty state: what reaches them is unknown. Other
/// unreached blocks (code past the function's end) are not walked.
pub fn propagate<S: FlowState, T>(
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
    in_body: impl Fn(u64) -> bool,
    snapshot: impl Fn(&S) -> T,
) -> Vec<(u64, T)> {
    propagate_cfg(&Cfg::build(insns, external, in_body), insns, snapshot)
}

/// [`propagate`] over the blocks `cfg` of `insns` built.
pub fn propagate_cfg<S: FlowState, T, I: Borrow<LiftedInstruction>>(
    cfg: &Cfg,
    insns: &[I],
    snapshot: impl Fn(&S) -> T,
) -> Vec<(u64, T)> {
    if cfg.legacy {
        return propagate_legacy(insns, &cfg.external, |a| cfg.in_body_blocks.contains(&a), snapshot);
    }
    let mut snaps = Vec::new();
    let nb = cfg.start_idx.len();
    if nb == 0 {
        return snaps;
    }
    let n = insns.len();
    let block_of = |a: u64| cfg.start_addr.binary_search(&a).ok();
    // edges into each block: (from block, state on the edge), by `from`
    let mut in_edges: Vec<Vec<(usize, S)>> = (0..nb).map(|_| Vec::new()).collect();
    let mut visits: Vec<usize> = vec![0; nb];
    let mut saturated: Vec<bool> = vec![false; nb];
    let relevant = |b: usize| cfg.relevant.as_ref().is_none_or(|r| r[b]);
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.extend((0..nb).filter(|&b| (b == 0 || cfg.unknown_entry[b]) && relevant(b)));
    let mut queued: Vec<bool> = vec![false; nb];
    for &b in &worklist {
        queued[b] = true;
    }
    // edges out of the block being walked, by `to`
    let mut out: Vec<(usize, S)> = Vec::new();

    while let Some(b) = worklist.pop_front() {
        queued[b] = false;
        if saturated[b] {
            continue;
        }
        visits[b] += 1;
        let v = visits[b];

        let mut st = if b == 0 || cfg.unknown_entry[b] {
            S::default()
        } else if v > MAX_VISITS_PER_BLOCK {
            // Not converged: walk it once more from "nothing known",
            // which every later input refines, and stop.
            saturated[b] = true;
            S::default()
        } else {
            let mut incoming = in_edges[b].iter().map(|(_, s)| s);
            let Some(first) = incoming.next() else {
                continue;
            };
            incoming.fold(first.clone(), |acc, s| acc.join(s))
        };

        let end = cfg.start_idx.get(b + 1).copied().unwrap_or(n);
        out.clear();
        let add_edge = |out: &mut Vec<(usize, S)>, to: usize, s: &S| match out.iter_mut().find(|(t, _)| *t == to) {
            Some((_, prev)) => *prev = prev.join(s),
            None => out.push((to, s.clone())),
        };
        let mut falls_through = true;
        for insn in &insns[cfg.start_idx[b]..end] {
            let insn = insn.borrow();
            for op in &insn.ops {
                match op.opcode {
                    OpCode::Call | OpCode::CallInd => {
                        snaps.push((insn.address, snapshot(&st)));
                        st.after_call();
                    }
                    OpCode::CBranch => {
                        if let Some(t) = target(op).and_then(block_of) {
                            add_edge(&mut out, t, &st);
                        }
                    }
                    OpCode::Branch => {
                        if let Some(t) = target(op).and_then(block_of) {
                            add_edge(&mut out, t, &st);
                        }
                        falls_through = false;
                    }
                    OpCode::Return | OpCode::BranchInd => falls_through = false,
                    _ => st.apply(op),
                }
            }
            if !falls_through {
                break;
            }
        }
        if falls_through && b + 1 < nb {
            add_edge(&mut out, b + 1, &st);
        }
        out.sort_unstable_by_key(|(to, _)| *to);
        for (to, s) in out.drain(..) {
            if !relevant(to) {
                continue;
            }
            let edges = &mut in_edges[to];
            match edges.binary_search_by_key(&b, |(from, _)| *from) {
                Ok(i) if edges[i].1 == s => {}
                Ok(i) => {
                    edges[i].1 = s;
                    if !queued[to] {
                        queued[to] = true;
                        worklist.push_back(to);
                    }
                }
                Err(i) => {
                    edges.insert(i, (b, s));
                    if !queued[to] {
                        queued[to] = true;
                        worklist.push_back(to);
                    }
                }
            }
        }
    }
    snaps
}

/// [`propagate`] over a lift whose addresses do not strictly increase
/// (a range wrapping around the address space): the block maps are
/// keyed by address. Run the flow over `insns` (one function's lift, entry first) and
/// return `(call address, snapshot(state at the call))` for every
/// visit of every call.
///
/// Blocks starting at an address of `external` (entered by a jump the
/// lift does not show, see [`crate::func_lift::external_entries`]) and
/// blocks of the function's extent (`in_body`) that no jump or
/// fall-through from the entry reaches (unrecovered jump-table cases)
/// start from the empty state: what reaches them is unknown. Other
/// unreached blocks (code past the function's end) are not walked.
fn propagate_legacy<S: FlowState, T, I: Borrow<LiftedInstruction>>(
    insns: &[I],
    external: &BTreeSet<u64>,
    in_body: impl Fn(u64) -> bool,
    snapshot: impl Fn(&S) -> T,
) -> Vec<(u64, T)> {
    let mut snaps = Vec::new();
    let Some(first) = insns.first() else {
        return snaps;
    };
    let entry = first.borrow().address;
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn)| (insn.borrow().address, i))
        .collect();

    let mut starts: BTreeSet<u64> = BTreeSet::new();
    starts.insert(entry);
    starts.extend(external.iter().filter(|a| index.contains_key(a)));
    let mut ends_block = false;
    for insn in insns {
        let insn = insn.borrow();
        if ends_block {
            starts.insert(insn.address);
        }
        ends_block = false;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Branch | OpCode::CBranch => {
                    if let Some(t) = target(op)
                        && index.contains_key(&t)
                    {
                        starts.insert(t);
                    }
                    ends_block = true;
                }
                OpCode::Return | OpCode::BranchInd => ends_block = true,
                _ => {}
            }
        }
    }
    let starts_vec: Vec<u64> = starts.iter().copied().collect();
    let block_end = |b: u64| {
        starts_vec
            .get(starts_vec.partition_point(|&s| s <= b))
            .copied()
            .unwrap_or(u64::MAX)
    };

    // Static successors, to find the blocks the entry reaches.
    let mut succs: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &b in &starts_vec {
        let end = block_end(b);
        let mut out = Vec::new();
        let mut falls = true;
        for insn in insns[index[&b]..].iter().map(Borrow::borrow).take_while(|i| i.address < end) {
            for op in &insn.ops {
                match op.opcode {
                    OpCode::CBranch | OpCode::Branch => {
                        out.extend(target(op).filter(|t| starts.contains(t)));
                        if op.opcode == OpCode::Branch {
                            falls = false;
                        }
                    }
                    OpCode::Return | OpCode::BranchInd => falls = false,
                    _ => {}
                }
            }
            if !falls {
                break;
            }
        }
        if falls && index.contains_key(&end) {
            out.push(end);
        }
        succs.insert(b, out);
    }
    let mut reached: BTreeSet<u64> = BTreeSet::from([entry]);
    let mut stack = vec![entry];
    while let Some(b) = stack.pop() {
        for s in succs.get(&b).into_iter().flatten() {
            if reached.insert(*s) {
                stack.push(*s);
            }
        }
    }
    // Blocks entered from somewhere unknown: walked from the empty state.
    let unknown_entry: BTreeSet<u64> = starts_vec
        .iter()
        .copied()
        .filter(|b| *b != entry && (external.contains(b) || (!reached.contains(b) && in_body(*b))))
        .collect();

    // edge (from, to) -> state on it
    let mut edges: BTreeMap<(u64, u64), S> = BTreeMap::new();
    let mut preds: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut visits: BTreeMap<u64, usize> = BTreeMap::new();
    let mut saturated: BTreeSet<u64> = BTreeSet::new();
    let mut worklist: VecDeque<u64> = VecDeque::from([entry]);
    worklist.extend(unknown_entry.iter().copied());
    let mut queued: BTreeSet<u64> = worklist.iter().copied().collect();

    while let Some(b) = worklist.pop_front() {
        queued.remove(&b);
        if saturated.contains(&b) {
            continue;
        }
        let v = visits.entry(b).or_insert(0);
        *v += 1;

        let mut st = if b == entry || unknown_entry.contains(&b) {
            S::default()
        } else if *v > MAX_VISITS_PER_BLOCK {
            // Not converged: walk it once more from "nothing known",
            // which every later input refines, and stop.
            saturated.insert(b);
            S::default()
        } else {
            let mut incoming = preds
                .get(&b)
                .into_iter()
                .flatten()
                .filter_map(|p| edges.get(&(*p, b)));
            let Some(first) = incoming.next() else {
                continue;
            };
            incoming.fold(first.clone(), |acc, s| acc.join(s))
        };

        let end = block_end(b);
        let Some(&start_idx) = index.get(&b) else {
            continue;
        };
        let mut out: BTreeMap<u64, S> = BTreeMap::new();
        let add_edge = |out: &mut BTreeMap<u64, S>, to: u64, s: &S| {
            let joined = match out.get(&to) {
                Some(prev) => prev.join(s),
                None => s.clone(),
            };
            out.insert(to, joined);
        };
        let mut falls_through = true;
        for insn in insns[start_idx..].iter().map(Borrow::borrow).take_while(|i| i.address < end) {
            for op in &insn.ops {
                match op.opcode {
                    OpCode::Call | OpCode::CallInd => {
                        snaps.push((insn.address, snapshot(&st)));
                        st.after_call();
                    }
                    OpCode::CBranch => {
                        if let Some(t) = target(op).filter(|t| starts.contains(t)) {
                            add_edge(&mut out, t, &st);
                        }
                    }
                    OpCode::Branch => {
                        if let Some(t) = target(op).filter(|t| starts.contains(t)) {
                            add_edge(&mut out, t, &st);
                        }
                        falls_through = false;
                    }
                    OpCode::Return | OpCode::BranchInd => falls_through = false,
                    _ => st.apply(op),
                }
            }
            if !falls_through {
                break;
            }
        }
        if falls_through && end != u64::MAX && index.contains_key(&end) {
            add_edge(&mut out, end, &st);
        }
        for (to, s) in out {
            preds.entry(to).or_default().insert(b);
            if edges.get(&(b, to)) != Some(&s) {
                edges.insert((b, to), s);
                if queued.insert(to) {
                    worklist.push_back(to);
                }
            }
        }
    }
    snaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{SeqNum, VarnodeData};

    /// Point constants of registers, joined by intersection.
    #[derive(Debug, Clone, PartialEq, Default)]
    struct Consts(BTreeMap<u64, u64>);

    impl FlowState for Consts {
        fn join(&self, other: &Self) -> Self {
            Consts(self.0.iter().filter(|(k, v)| other.0.get(k) == Some(v)).map(|(k, v)| (*k, *v)).collect())
        }
        fn apply(&mut self, op: &PcodeOp) {
            if let Some(out) = op.output {
                match op.inputs.first() {
                    Some(c) if op.opcode == OpCode::Copy && c.space == SpaceId::CONST => {
                        self.0.insert(out.offset, c.offset);
                    }
                    _ => {
                        self.0.remove(&out.offset);
                    }
                }
            }
        }
        fn after_call(&mut self) {
            self.0.remove(&0);
        }
    }

    fn op(opcode: OpCode, inputs: &[VarnodeData], output: Option<VarnodeData>) -> PcodeOp {
        let mut o = PcodeOp::new(opcode, SeqNum::new(Address::new(SpaceId::RAM, 0), 0));
        o.inputs = inputs.iter().copied().collect();
        o.output = output;
        o
    }

    /// A random lift: copies of constants into 3 registers, register
    /// moves, calls, conditional and unconditional jumps (inside and
    /// outside the lift, to instruction starts or not) and returns.
    fn random_lift(seed: &mut u64, n: usize) -> Vec<LiftedInstruction> {
        let mut next = move || {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        };
        let reg = |r: u64| VarnodeData::new(SpaceId::REGISTER, r % 3, 8);
        (0..n)
            .map(|i| {
                let address = 0x1000 + 4 * i as u64;
                let (kind, a, b) = (next() % 12, next(), next());
                let target = VarnodeData::new(SpaceId::RAM, 0x1000 + 2 * (a % (2 * n as u64 + 8)), 8);
                let ops = match kind {
                    0..=3 => vec![op(OpCode::Copy, &[VarnodeData::new(SpaceId::CONST, a % 3, 8)], Some(reg(b)))],
                    4 | 5 => vec![op(OpCode::Copy, &[reg(a)], Some(reg(b)))],
                    6 | 7 => vec![op(OpCode::Call, &[VarnodeData::new(SpaceId::RAM, 0x9000, 8)], None)],
                    8 | 9 => vec![op(OpCode::CBranch, &[target, reg(0)], None)],
                    10 => vec![op(OpCode::Branch, &[target], None)],
                    _ => vec![op(OpCode::Return, &[], None)],
                };
                LiftedInstruction { address, length: 4, mnemonic: "x".into(), ops }
            })
            .collect()
    }

    /// The block-indexed walk gives exactly the address-keyed one, and
    /// walking only the blocks that reach the wanted calls keeps their
    /// snapshots, in order.
    #[test]
    fn indexed_walk_matches_address_keyed_walk() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let (mut snaps, mut kept_snaps) = (0, 0);
        for round in 0..400 {
            let n = 1 + round % 60;
            let insns = random_lift(&mut seed, n);
            let external: BTreeSet<u64> = insns.iter().map(|i| i.address).filter(|a| a.is_multiple_of(28)).collect();
            let in_body = |a: u64| a < 0x1000 + 2 * n as u64;
            let snap = |s: &Consts| s.0.clone();
            let legacy = propagate_legacy::<Consts, _, _>(&insns, &external, in_body, snap);
            let mut cfg = Cfg::build(&insns, &external, in_body);
            assert_eq!(propagate_cfg::<Consts, _, _>(&cfg, &insns, snap), legacy, "round {round}");
            let wanted = |i: usize| insns[i].ops[0].opcode == OpCode::Call && !insns[i].address.is_multiple_of(3);
            cfg.keep_calls(&insns, |insn| {
                wanted(insns.iter().position(|i| i.address == insn.address).expect("lifted"))
            });
            let want = |a: &u64| insns.iter().position(|i| i.address == *a).is_some_and(wanted);
            let kept: Vec<_> = propagate_cfg::<Consts, _, _>(&cfg, &insns, snap).into_iter().filter(|(a, _)| want(a)).collect();
            snaps += legacy.len();
            let all: Vec<_> = legacy.into_iter().filter(|(a, _)| want(a)).collect();
            assert_eq!(kept, all, "round {round}");
            kept_snaps += kept.len();
        }
        // the lifts exercise the walk: calls are reached, some wanted
        assert!(snaps > 1000 && kept_snaps > 300, "{snaps} {kept_snaps}");
    }
}
