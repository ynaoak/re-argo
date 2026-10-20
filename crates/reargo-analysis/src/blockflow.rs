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

use std::borrow::{Borrow, Cow};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use reargo_core::pcode::{OpCode, PcodeOp};
use reargo_lift::{InsnShape, LiftedInstruction, RangeShapes};

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
pub struct LiftShape<'a> {
    /// The addresses strictly increase.
    pub increasing: bool,
    /// Each instruction's address.
    pub addrs: Cow<'a, [u64]>,
    /// Each instruction's [`InsnShape`] flags: see
    /// [`LiftShape::has_call`], [`LiftShape::ends_block`],
    /// [`LiftShape::stops`].
    pub flags: Cow<'a, [u8]>,
    /// `(instruction index, target)` of every `Branch` / `CBranch` with
    /// a jump target in the lift's space ([`target`]), in op order.
    pub branches: Vec<(usize, u64)>,
    /// The indices of the instructions with flags (a call, a jump, a
    /// return), ascending: the passes that look only at those step
    /// through them instead of every instruction.
    pub special: Vec<u32>,
}

impl<'a> LiftShape<'a> {
    /// Instruction `i` has a `Call` / `CallInd` op.
    #[inline]
    pub fn has_call(&self, i: usize) -> bool {
        self.flags[i] & InsnShape::CALL != 0
    }

    /// Instruction `i` has a `Branch`, `CBranch`, `Return` or
    /// `BranchInd` op (it ends its block).
    #[inline]
    pub fn ends_block(&self, i: usize) -> bool {
        self.flags[i] & InsnShape::ENDS != 0
    }

    /// Instruction `i` has a `Branch`, `Return` or `BranchInd` op (no
    /// fall-through).
    #[inline]
    pub fn stops(&self, i: usize) -> bool {
        self.flags[i] & InsnShape::STOPS != 0
    }

    pub fn of<I: Borrow<LiftedInstruction>>(insns: &[I]) -> LiftShape<'static> {
        let n = insns.len();
        let (mut addrs, mut flags) = (Vec::with_capacity(n), Vec::with_capacity(n));
        let mut branches = Vec::new();
        let mut special = Vec::new();
        for (i, insn) in insns.iter().enumerate() {
            let s = InsnShape::of(insn.borrow());
            if s.flags != 0 {
                special.push(i as u32);
                push_branches(&mut branches, i, s, || insn.borrow());
            }
            addrs.push(s.address);
            flags.push(s.flags);
        }
        LiftShape { increasing: increasing(&addrs), addrs: Cow::Owned(addrs), flags: Cow::Owned(flags), branches, special }
    }

    /// [`LiftShape::of`] from the [`RangeShapes`] of the instructions
    /// (read in place: only the instructions with flags are looked at).
    pub fn from_shapes<I: Borrow<LiftedInstruction>>(insns: &[I], shapes: &'a RangeShapes<'_>) -> LiftShape<'a> {
        debug_assert_eq!(insns.len(), shapes.len());
        let mut branches = Vec::new();
        let mut special = Vec::with_capacity(shapes.special().len());
        for i in shapes.special() {
            special.push(i as u32);
            push_branches(&mut branches, i, shapes.shape(i), || insns[i].borrow());
        }
        LiftShape {
            increasing: shapes.increasing,
            addrs: Cow::Borrowed(&shapes.addrs),
            flags: Cow::Borrowed(&shapes.flags),
            branches,
            special,
        }
    }

    /// A shape from its parts (`special` found from `flags`).
    #[cfg(test)]
    pub fn from_parts(increasing: bool, addrs: Vec<u64>, flags: Vec<u8>, branches: Vec<(usize, u64)>) -> LiftShape<'static> {
        let special = flags.iter().enumerate().filter(|(_, f)| **f != 0).map(|(i, _)| i as u32).collect();
        LiftShape { increasing, addrs: Cow::Owned(addrs), flags: Cow::Owned(flags), branches, special }
    }
}

/// Whether `addrs` strictly increase (compared without stopping early,
/// which vectorises).
fn increasing(addrs: &[u64]) -> bool {
    addrs.windows(2).fold(true, |ok, w| ok & (w[0] < w[1]))
}

/// The `(i, target)` of the jumps of instruction `i` (shape `s`, lifted
/// as `insn()`, read only for several targets) with a target, in op order.
fn push_branches<'a>(branches: &mut Vec<(usize, u64)>, i: usize, s: InsnShape, insn: impl FnOnce() -> &'a LiftedInstruction) {
    if s.flags & InsnShape::TARGET != 0 {
        branches.push((i, s.target));
    } else if s.flags & InsnShape::TARGETS != 0 {
        for op in &insn().ops {
            if matches!(op.opcode, OpCode::Branch | OpCode::CBranch)
                && let Some(t) = target(op)
            {
                branches.push((i, t));
            }
        }
    }
}

/// Per-instruction facts the call-site walk and the blocks both need of
/// an increasing lift ([`LiftShape::increasing`]), found once: which
/// instructions a jump inside the lift targets, which are entered from
/// outside it ([`crate::func_lift::external_entries`]) and which calls
/// the function owns.
pub struct LiftMarks {
    /// Per instruction: [`LiftMarks::TARGET`], [`LiftMarks::EXTERNAL`],
    /// [`LiftMarks::OWNED_CALL`].
    pub flags: Vec<u8>,
    /// Per entry of [`LiftShape::branches`]: the index of the
    /// instruction it targets, when one is lifted.
    pub target_idx: Vec<Option<usize>>,
    /// Indices of the calls the function owns, ascending.
    pub owned_calls: Vec<usize>,
    /// Every call instruction: its address and whether the function
    /// owns it, by address (for the caller to take).
    pub calls: Vec<(u64, bool)>,
}

impl LiftMarks {
    /// A jump inside the lift targets it.
    pub const TARGET: u8 = 1;
    /// It is one of the lift's external entries.
    pub const EXTERNAL: u8 = 2;
    /// It is a call the function owns.
    pub const OWNED_CALL: u8 = 4;
    /// The instruction before it ends a block ([`LiftShape::ends_block`]).
    pub const AFTER_END: u8 = 8;

    /// The marks of an increasing lift's `shape`: `external` its
    /// external entries, `owns(i)` whether the function owns the call
    /// instruction `i`.
    pub fn new<'a>(shape: &LiftShape, external: impl IntoIterator<Item = &'a u64>, owns: impl Fn(usize) -> bool) -> LiftMarks {
        debug_assert!(shape.increasing);
        let addrs = &shape.addrs;
        let mut flags = vec![0u8; addrs.len()];
        let target_idx: Vec<Option<usize>> = shape
            .branches
            .iter()
            .map(|&(from, t)| {
                let i = find_near(addrs, from, t)?;
                flags[i] |= Self::TARGET;
                Some(i)
            })
            .collect();
        for a in external {
            if let Ok(i) = addrs.binary_search(a) {
                flags[i] |= Self::EXTERNAL;
            }
        }
        let mut owned_calls = Vec::new();
        let mut calls = Vec::new();
        for &i in &shape.special {
            let i = i as usize;
            if shape.ends_block(i) && i + 1 < addrs.len() {
                flags[i + 1] |= Self::AFTER_END;
            }
        }
        for i in shape.special.iter().map(|&i| i as usize).filter(|&i| shape.has_call(i)) {
            let owned = owns(i);
            if owned {
                flags[i] |= Self::OWNED_CALL;
                owned_calls.push(i);
            }
            calls.push((addrs[i], owned));
        }
        LiftMarks { flags, target_idx, owned_calls, calls }
    }
}

impl LiftMarks {
    /// How many of the lift's first instructions hold every block that can
    /// reach a call the function owns (0: there is none), for
    /// [`Cfg::build_marked_upto`]: up to the end of the block of the last
    /// owned call, when no jump after that block targets an instruction up
    /// to that call (every path back to the calls would take such a jump: a
    /// fall-through only goes on); else the whole lift. The blocks after it
    /// can then not reach those calls, so [`propagate_cfg`] over the blocks
    /// [`Cfg::keep_owned_calls`] keeps walks no block after it.
    pub fn reach(&self, shape: &LiftShape) -> usize {
        let n = self.flags.len();
        let Some(&last) = self.owned_calls.last() else { return 0 };
        // the next block start after the last owned call
        const MASK: u8 = LiftMarks::TARGET | LiftMarks::EXTERNAL | LiftMarks::AFTER_END;
        let end = self.flags[last + 1..].iter().position(|&f| f & MASK != 0).map_or(n, |k| last + 1 + k);
        let (lo, hi) = (shape.addrs[0], shape.addrs[last]);
        let back = shape.branches[shape.branches.partition_point(|t| t.0 < end)..].iter().any(|&(_, t)| t >= lo && t <= hi);
        if back { n } else { end }
    }
}

/// The index of `t` in the strictly increasing `addrs`, searched
/// outwards from index `from` (a jump's own: most jumps are short) —
/// what `addrs.binary_search(&t).ok()` gives.
fn find_near(addrs: &[u64], from: usize, t: u64) -> Option<usize> {
    let n = addrs.len();
    if t >= addrs[from] {
        // addrs[lo] <= t; the first probe at or past `t` bounds it
        let (mut lo, mut step) = (from, 1);
        loop {
            let hi = from + step;
            if hi >= n {
                return addrs[lo..].binary_search(&t).ok().map(|k| lo + k);
            }
            if addrs[hi] >= t {
                return addrs[lo..=hi].binary_search(&t).ok().map(|k| lo + k);
            }
            lo = hi;
            step *= 2;
        }
    }
    // addrs[hi] > t
    let (mut hi, mut step) = (from, 1);
    loop {
        if step > from {
            return addrs[..hi].binary_search(&t).ok();
        }
        let lo = from - step;
        if addrs[lo] <= t {
            return addrs[lo..hi].binary_search(&t).ok().map(|k| lo + k);
        }
        hi = lo;
        step *= 2;
    }
}

/// The blocks of one function's lift, computed once and walked by
/// every [`propagate_cfg`] over it.
#[cfg_attr(test, derive(Debug, PartialEq))]
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
        for (start, &f) in is_start[1..].iter_mut().zip(shape.flags.iter()) {
            *start |= f & InsnShape::ENDS != 0;
        }
        let targets = &shape.branches;
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
            if !shape.stops(last) && b + 1 < nb {
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

    /// [`Cfg::build_shaped`] of an increasing lift from its
    /// [`LiftMarks`] (`external` the entries the marks were made with).
    pub fn build_marked(shape: &LiftShape, marks: &LiftMarks, in_body: impl Fn(u64) -> bool) -> Cfg {
        Cfg::build_marked_upto(shape, marks, in_body, shape.addrs.len())
    }

    /// [`Cfg::build_marked`] of the first `end` instructions: the blocks
    /// before `end` and their edges between them, as [`Cfg::build_marked`]
    /// has them when no jump from `end` on targets an instruction before it
    /// and `end` starts a block (or is the end of the lift) — what
    /// [`LiftMarks::reach`] finds.
    pub fn build_marked_upto(shape: &LiftShape, marks: &LiftMarks, in_body: impl Fn(u64) -> bool, end: usize) -> Cfg {
        debug_assert!(shape.increasing);
        let addrs = &shape.addrs[..end];
        let n = addrs.len();
        if n == 0 {
            return Cfg::build_shaped(&LiftShape::of::<&LiftedInstruction>(&[]), &BTreeSet::new(), in_body);
        }
        let flags = &marks.flags[..n];
        // a block starts at the entry, at a jump target or an external
        // entry, and after an instruction that ends a block
        let mut start_idx: Vec<usize> = Vec::with_capacity(n / 4 + 1);
        start_idx.push(0);
        // (the marked instructions found eight flags at a time: most are unmarked)
        const MASK: u8 = LiftMarks::TARGET | LiftMarks::EXTERNAL | LiftMarks::AFTER_END;
        let wide = u64::from_ne_bytes([MASK; 8]);
        let mut chunks = flags.chunks_exact(8);
        for (c, chunk) in chunks.by_ref().enumerate() {
            let mut word = u64::from_le_bytes(chunk.try_into().expect("8 flags")) & wide;
            while word != 0 {
                let k = (word.trailing_zeros() / 8) as usize;
                if 8 * c + k > 0 {
                    start_idx.push(8 * c + k);
                }
                word &= !(0xffu64 << (8 * k));
            }
        }
        let tail = n - chunks.remainder().len();
        for (k, &f) in chunks.remainder().iter().enumerate() {
            if tail + k > 0 && f & MASK != 0 {
                start_idx.push(tail + k);
            }
        }
        let start_addr: Vec<u64> = start_idx.iter().map(|&i| addrs[i]).collect();
        let nb = start_idx.len();
        // (a jump target is a block start)
        let block_of = |i: usize| start_idx.binary_search(&i).ok();
        let targets = &shape.branches[..shape.branches.partition_point(|t| t.0 < n)];
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
                succs.extend(marks.target_idx[ti].and_then(block_of));
                ti += 1;
            }
            if !shape.stops(last) && b + 1 < nb {
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
            .map(|b| {
                b != 0
                    && (flags[start_idx[b]] & LiftMarks::EXTERNAL != 0 || (!reached[b] && in_body(start_addr[b])))
            })
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

    /// [`Cfg::keep_calls_at`] keeping the calls the function owns (the
    /// [`LiftMarks`] the blocks were built from).
    pub fn keep_owned_calls(&mut self, marks: &LiftMarks) {
        if self.legacy {
            return;
        }
        let nb = self.start_idx.len();
        let mut relevant = vec![false; nb];
        let mut stack: Vec<usize> = Vec::new();
        for &i in &marks.owned_calls {
            let b = self.start_idx.partition_point(|&s| s <= i) - 1;
            if !relevant[b] {
                relevant[b] = true;
                stack.push(b);
            }
        }
        if stack.is_empty() {
            self.relevant = Some(relevant);
            return;
        }
        self.mark_preds(relevant, stack);
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
        let mut relevant = vec![false; nb];
        let mut stack: Vec<usize> = Vec::new();
        for (b, rel) in relevant.iter_mut().enumerate() {
            let end = self.start_idx.get(b + 1).copied().unwrap_or(n);
            if (self.start_idx[b]..end).any(&wanted) {
                *rel = true;
                stack.push(b);
            }
        }
        self.mark_preds(relevant, stack);
    }

    /// Mark relevant every block that reaches one of `relevant` (the
    /// blocks on `stack`) and keep the set.
    fn mark_preds(&mut self, mut relevant: Vec<bool>, mut stack: Vec<usize>) {
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
            // (the state is not read after: moved onto the edge unless one is there)
            match out.iter_mut().find(|(t, _)| *t == b + 1) {
                Some((_, prev)) => *prev = prev.join(&st),
                None => out.push((b + 1, st)),
            }
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

    #[test]
    fn find_near_is_binary_search() {
        let mut seed = 0x5555_aaaa_1234_9876_u64;
        let mut next = move |m: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % m
        };
        for _ in 0..2000 {
            let n = 1 + next(80) as usize;
            let mut a = next(10);
            let addrs: Vec<u64> = (0..n)
                .map(|_| {
                    a += 1 + next(6);
                    a
                })
                .collect();
            let from = next(n as u64) as usize;
            for t in 0..a + 8 {
                assert_eq!(find_near(&addrs, from, t), addrs.binary_search(&t).ok(), "{addrs:?} {from} {t}");
            }
        }
    }

    /// The blocks built from [`LiftMarks`] are the blocks built from the
    /// lift's shape, and keep the same calls.
    #[test]
    fn marked_blocks_match_shaped_blocks() {
        let mut seed = 0x1234_5678_9abc_def1_u64;
        let mut kept = 0;
        for round in 0..400 {
            let n = 1 + round % 60;
            let insns = random_lift(&mut seed, n);
            let external: BTreeSet<u64> = insns.iter().map(|i| i.address).filter(|a| a.is_multiple_of(28)).collect();
            let in_body = |a: u64| a < 0x1000 + 2 * n as u64;
            let shape = LiftShape::of(&insns);
            let owns = |i: usize| !insns[i].address.is_multiple_of(3);
            let marks = LiftMarks::new(&shape, &external, owns);
            let mut a = Cfg::build_shaped(&shape, &external, in_body);
            let mut b = Cfg::build_marked(&shape, &marks, in_body);
            assert_eq!(a, b, "round {round}");
            a.keep_calls_at(n, |i| shape.has_call(i) && owns(i));
            b.keep_owned_calls(&marks);
            assert_eq!(a, b, "round {round}");
            kept += a.relevant.as_ref().map_or(0, |r| r.iter().filter(|r| **r).count());
            let calls: Vec<(u64, bool)> =
                (0..n).filter(|&i| shape.has_call(i)).map(|i| (insns[i].address, owns(i))).collect();
            assert_eq!(marks.calls, calls);
        }
        assert!(kept > 1000, "{kept}");
    }

    /// The shapes read in place from a lift cache's arrays give the lift's shape the ops do.
    #[test]
    fn shape_from_cached_shapes_matches_ops() {
        let mut seed = 0x7a5c_3e19_d2b4_6081_u64;
        for round in 0..200 {
            let n = round % 60;
            let insns = random_lift(&mut seed, n);
            let shapes = RangeShapes::of(&insns);
            let (a, b) = (LiftShape::of(&insns), LiftShape::from_shapes(&insns, &shapes));
            assert_eq!((a.increasing, &a.addrs, &a.flags, &a.branches, &a.special), (b.increasing, &b.addrs, &b.flags, &b.branches, &b.special));
        }
    }

    /// The flows over the blocks up to [`LiftMarks::reach`] record the snapshots of the calls
    /// the function owns that the flows over every block do, in order.
    #[test]
    fn flows_up_to_the_reach_match_flows_over_all() {
        let mut seed = 0x3141_5926_5358_9793_u64;
        let (mut cut, mut snaps) = (0, 0);
        for round in 0..600 {
            let n = 1 + round % 60;
            let mut insns = random_lift(&mut seed, n);
            // (fewer jumps back from the end, so that the reach often ends before it)
            for insn in insns.iter_mut().skip(n / 2) {
                if let Some(t) = insn.ops[0].inputs.first_mut()
                    && t.space == SpaceId::RAM
                    && t.offset < insn.address
                    && round % 2 == 0
                {
                    t.offset = insn.address + 4;
                }
            }
            let external: BTreeSet<u64> = insns.iter().map(|i| i.address).filter(|a| a.is_multiple_of(28)).collect();
            let in_body = |a: u64| a < 0x1000 + 2 * n as u64;
            let shape = LiftShape::of(&insns);
            let owns = |i: usize| i < n / 2 && !insns[i].address.is_multiple_of(3);
            let marks = LiftMarks::new(&shape, &external, owns);
            let snap = |s: &Consts| s.0.clone();
            let mut all = Cfg::build_marked(&shape, &marks, in_body);
            all.keep_owned_calls(&marks);
            let reach = marks.reach(&shape);
            let mut some = Cfg::build_marked_upto(&shape, &marks, in_body, reach);
            some.keep_owned_calls(&marks);
            let owned = |a: &u64| insns.iter().position(|i| i.address == *a).is_some_and(owns);
            let full: Vec<_> = propagate_cfg::<Consts, _, _>(&all, &insns, snap).into_iter().filter(|(a, _)| owned(a)).collect();
            let part: Vec<_> = if reach == 0 {
                Vec::new()
            } else {
                propagate_cfg::<Consts, _, _>(&some, &insns[..reach], snap).into_iter().filter(|(a, _)| owned(a)).collect()
            };
            assert_eq!(full, part, "round {round} reach {reach}");
            cut += usize::from(reach < n);
            snaps += full.len();
        }
        // the lifts exercise the cut and the walk
        assert!(cut > 200 && snaps > 300, "{cut} {snaps}");
    }

    /// The call-site walk from [`LiftMarks`] records what the walk from
    /// the lift's shape does.
    #[test]
    fn marked_walk_matches_shaped_walk() {
        use crate::callsite::{walk_function_shaped, walk_prefix, ParamSummaries, WalkPrefix};
        let mut seed = 0x0f1e_2d3c_4b5a_6978_u64;
        let (mut sites, mut known) = (0, 0);
        for round in 0..400 {
            let n = 1 + round % 60;
            let mut insns = random_lift(&mut seed, n);
            // registers 0..3 as the first argument registers
            for insn in &mut insns {
                for op in &mut insn.ops {
                    for vn in op.inputs.iter_mut().chain(op.output.as_mut()) {
                        if vn.space == SpaceId::REGISTER {
                            vn.offset = [0x38, 0x30, 0x10][vn.offset as usize];
                        }
                    }
                }
            }
            let external: BTreeSet<u64> = insns.iter().map(|i| i.address).filter(|a| a.is_multiple_of(28)).collect();
            let shape = LiftShape::of(&insns);
            let owns = |i: usize| !insns[i].address.is_multiple_of(3);
            let owns_at = |a: u64| insns.iter().position(|i| i.address == a).is_some_and(owns);
            let marks = LiftMarks::new(&shape, &external, owns);
            let none = ParamSummaries::default();
            let a = walk_function_shaped(0x1000, &insns, &shape, &none, &external, owns_at);
            let prefix = WalkPrefix::of_marks(&shape, &marks, true);
            let b = walk_prefix(0x1000, &insns, &prefix.flags, &none);
            assert_eq!(a, b, "round {round}");
            sites += a.len();
            known += a.iter().flat_map(|s| &s.args).filter(|r| r.value.is_some()).count();
        }
        assert!(sites > 1000 && known > 300, "{sites} {known}");
    }

    /// The prefix walk, which steps over the runs that give nothing once a
    /// stack address escaped and `rbp` was written, records what the walk
    /// from the lift's shape does (lifts that write `rbp` and pass stack
    /// addresses around).
    #[test]
    fn marked_walk_with_frame_registers_matches_shaped_walk() {
        use crate::callsite::{walk_function_shaped, walk_prefix, ParamSummaries, WalkPrefix};
        let mut seed = 0x7a3c_91e5_02d4_b86f_u64;
        let (mut sites, mut known) = (0, 0);
        for round in 0..600 {
            let n = 1 + round % 80;
            let mut insns = random_lift(&mut seed, n);
            // registers 0..3 as rdi, rbp and rsp: copies of rsp leave stack
            // addresses in rdi / rbp
            for insn in &mut insns {
                for op in &mut insn.ops {
                    for vn in op.inputs.iter_mut().chain(op.output.as_mut()) {
                        if vn.space == SpaceId::REGISTER {
                            vn.offset = [0x38, 0x28, 0x20][vn.offset as usize];
                        }
                    }
                }
            }
            let external: BTreeSet<u64> = insns.iter().map(|i| i.address).filter(|a| a.is_multiple_of(28)).collect();
            let shape = LiftShape::of(&insns);
            let owns = |i: usize| insns[i].address.is_multiple_of(5);
            let owns_at = |a: u64| insns.iter().position(|i| i.address == a).is_some_and(owns);
            let marks = LiftMarks::new(&shape, &external, owns);
            let none = ParamSummaries::default();
            let a = walk_function_shaped(0x1000, &insns, &shape, &none, &external, owns_at);
            let prefix = WalkPrefix::of_marks(&shape, &marks, true);
            let b = walk_prefix(0x1000, &insns, &prefix.flags, &none);
            assert_eq!(a, b, "round {round}");
            sites += a.len();
            known += a.iter().flat_map(|s| &s.args).filter(|r| r.value.is_some()).count();
        }
        assert!(sites > 500 && known > 50, "{sites} {known}");
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
