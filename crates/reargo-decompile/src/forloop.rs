//! `for` loops (WS97): a loop whose last statements step its induction variables by
//! constants prints them as the update clause of a `for`:
//!
//! ```c
//! while (rdi != rsi) { …; rdi = rdi + 8; }        ->  for (; rdi != rsi; rdi += 8) { … }
//! rax = 0; do { …; rax = rax + 1; } while (rax != rdx)   (entered only when rdx != 0)
//!                                                  ->  for (rax = 0; rax != rdx; rax++) { … }
//! ```
//!
//! An induction variable is a register with a phi at the loop header whose value from the back
//! edge is that phi plus or minus a constant, written by no other statement printed in the
//! loop (nor through an overlapping part of the register). The update clause runs the moved
//! statements where they ran before — at the end of the body, before the test — so:
//!
//! * the moved statements are the last ones the body prints (in their order), in a block that
//!   ends the body and is no `goto` target;
//! * a `while` with a `continue` for it stays a `while` (its `continue` skips the update, a
//!   `for`'s runs it);
//! * a `do … while` becomes a `for` only when its test is known to hold on entry: the test with
//!   the induction variables at their entry values must follow from the condition of a branch
//!   every way into the loop passes (the same SSA values compared — `rdi != rsi` before a loop
//!   ending in `while (rdi != rsi)`, `rdx != 0` for `rax = 0; … while (rax != rdx)`), else the
//!   first test of a `for` could stop a loop the program runs once;
//! * the test must read one of the moved registers.
//!
//! The statement right before the loop that sets an induction variable moves into the init
//! clause (it ran right before the first test anyway); the emitters do that on their text.
//!
//! For the Rust output a `for` whose test is `R < n` (unsigned, at the register's width), steps
//! `R` by one, compares with a value the loop does not change and whose `R` nothing reads after
//! the loop is `for R in a..n` ([`RangeInfo`]).

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use rustc_hash::FxHashMap;

use crate::cfg::BlockId;
use crate::condition::{value_key, Readers, ValueKey};
use crate::ssa::{OpIdx, SsaFunction, VarId};
use crate::structure::StructuredBlock;

/// A loop printed as a `for`, by its condition block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForInfo {
    /// The update statements moved to the header, in order.
    pub updates: Vec<OpIdx>,
    /// The registers they step (`(offset, size)`).
    pub regs: Vec<(u64, u32)>,
    /// It was a `do … while` (whose test was proved to hold on entry).
    pub do_while: bool,
    /// `for R in a..n` in the Rust output.
    pub range: Option<RangeInfo>,
    /// The test is a merged condition (`a && b`) of a `while`: the emitter checks that its text
    /// reads a stepped register.
    pub test_unknown: bool,
    /// The updates whose stepped value the rest of the latch reads: there it prints as `R + k`
    /// (the update now runs at the end).
    pub sunk: Vec<OpIdx>,
}

/// `for R in a..n`: the update stepping `R` by one and the comparison `R < n` (its input `bound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RangeInfo {
    pub update: OpIdx,
    pub cmp: OpIdx,
    pub bound: usize,
}

/// What the emitter prints (`printed(op)`: the op prints a statement of its own) and how it
/// structured the function.
pub(crate) struct Context<'a> {
    pub structured: &'a StructuredBlock,
    pub goto_targets: &'a std::collections::BTreeSet<usize>,
    /// Blocks whose condition the short-circuit merge rewrote (their branch is not the test).
    pub merged: &'a dyn Fn(BlockId) -> bool,
    pub printed: &'a dyn Fn(OpIdx) -> bool,
}

/// The loops of the structured function printed as `for`, by condition block.
pub(crate) fn find(func: &SsaFunction, ctx: &Context<'_>) -> FxHashMap<BlockId, ForInfo> {
    let mut loops = Vec::new();
    collect_loops(ctx.structured, &mut loops);
    let mut out = FxHashMap::default();
    if loops.is_empty() {
        return out;
    }
    let mut seen = FxHashMap::default();
    count_blocks(ctx.structured, &mut seen);
    let a = Analysis::new(func);
    for l in loops {
        if let Some(info) = a.for_loop(&l, ctx, &seen) {
            out.insert(l.cond, info);
        }
    }
    out
}

/// A `while` / `do … while` of the structured function.
struct LoopNode<'a> {
    cond: BlockId,
    body: &'a StructuredBlock,
    do_while: bool,
}

fn collect_loops<'a>(n: &'a StructuredBlock, out: &mut Vec<LoopNode<'a>>) {
    use StructuredBlock::*;
    match n {
        WhileLoop { condition_block, body, .. } => {
            out.push(LoopNode { cond: *condition_block, body, do_while: false });
            collect_loops(body, out);
        }
        DoWhileLoop { body, condition_block, .. } => {
            out.push(LoopNode { cond: *condition_block, body, do_while: true });
            collect_loops(body, out);
        }
        Sequence(v) => v.iter().for_each(|x| collect_loops(x, out)),
        IfThen { then_body, .. } => collect_loops(then_body, out),
        IfThenElse { then_body, else_body, .. } => {
            collect_loops(then_body, out);
            collect_loops(else_body, out);
        }
        Switch { cases, default, .. } => {
            cases.iter().for_each(|(_, c)| collect_loops(c, out));
            if let Some(d) = default {
                collect_loops(d, out);
            }
        }
        ForLoop { body, .. } | ShortCircuitAnd { body, .. } | ShortCircuitOr { body, .. } | Loop { body, .. } | Handler { body, .. } => collect_loops(body, out),
        Basic(_) | Goto(_) | Break | Continue => {}
    }
}

/// How often each block is printed (a tail copied into two places prints twice).
fn count_blocks(n: &StructuredBlock, seen: &mut FxHashMap<BlockId, usize>) {
    use StructuredBlock::*;
    let mut one = |b: BlockId| *seen.entry(b).or_default() += 1;
    match n {
        Basic(b) => one(*b),
        WhileLoop { condition_block, body, .. } | DoWhileLoop { body, condition_block, .. } => {
            one(*condition_block);
            count_blocks(body, seen);
        }
        IfThen { condition_block, then_body, .. } => {
            one(*condition_block);
            count_blocks(then_body, seen);
        }
        IfThenElse { condition_block, then_body, else_body } => {
            one(*condition_block);
            count_blocks(then_body, seen);
            count_blocks(else_body, seen);
        }
        Switch { condition_block, cases, default } => {
            one(*condition_block);
            cases.iter().for_each(|(_, c)| count_blocks(c, seen));
            if let Some(d) = default {
                count_blocks(d, seen);
            }
        }
        Sequence(v) => v.iter().for_each(|x| count_blocks(x, seen)),
        ForLoop { init_block, condition_block, update_block, body } => {
            one(*init_block);
            one(*condition_block);
            one(*update_block);
            count_blocks(body, seen);
        }
        ShortCircuitAnd { left_block, right_block, body } | ShortCircuitOr { left_block, right_block, body } => {
            one(*left_block);
            one(*right_block);
            count_blocks(body, seen);
        }
        Loop { body, .. } | Handler { body, .. } => count_blocks(body, seen),
        Goto(_) | Break | Continue => {}
    }
}

/// The last block a structured body prints, when the body ends in it (no `if` / loop after it).
fn last_basic(n: &StructuredBlock) -> Option<BlockId> {
    match n {
        StructuredBlock::Basic(b) => Some(*b),
        StructuredBlock::Sequence(v) => last_basic(v.last()?),
        _ => None,
    }
}

/// The first block a structured body prints.
fn first_block(n: &StructuredBlock) -> Option<BlockId> {
    use StructuredBlock::*;
    match n {
        Basic(b) => Some(*b),
        Sequence(v) => first_block(v.first()?),
        IfThen { condition_block, .. } | IfThenElse { condition_block, .. } | WhileLoop { condition_block, .. } | Switch { condition_block, .. } => Some(*condition_block),
        DoWhileLoop { body, condition_block, .. } => first_block(body).or(Some(*condition_block)),
        Loop { header, .. } => Some(*header),
        _ => None,
    }
}

/// Does the node contain a `continue` of the loop it sits in (not of a nested loop)?
fn continues(n: &StructuredBlock) -> bool {
    use StructuredBlock::*;
    match n {
        Continue => true,
        Sequence(v) => v.iter().any(continues),
        IfThen { then_body, .. } => continues(then_body),
        IfThenElse { then_body, else_body, .. } => continues(then_body) || continues(else_body),
        Switch { cases, default, .. } => cases.iter().any(|(_, c)| continues(c)) || default.as_ref().is_some_and(|d| continues(d)),
        ShortCircuitAnd { body, .. } | ShortCircuitOr { body, .. } => continues(body),
        _ => false,
    }
}

/// A comparison `a op b` (signed / unsigned `<`, `<=`, `==`, `!=`) of two terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rel {
    Eq,
    Ne,
    Ult,
    Ule,
    Slt,
    Sle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Term {
    /// A value plus a constant (modulo its size), by the value's key.
    Val(ValueKey, u64),
    /// A constant `(value, size)`, masked to its size.
    Const(u64, u32),
    /// The low `size` bytes of a value.
    Low(ValueKey, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cmp {
    rel: Rel,
    a: Term,
    b: Term,
}

impl Cmp {
    fn negate(self) -> Cmp {
        let Cmp { rel, a, b } = self;
        match rel {
            Rel::Eq => Cmp { rel: Rel::Ne, a, b },
            Rel::Ne => Cmp { rel: Rel::Eq, a, b },
            Rel::Ult => Cmp { rel: Rel::Ule, a: b, b: a },
            Rel::Ule => Cmp { rel: Rel::Ult, a: b, b: a },
            Rel::Slt => Cmp { rel: Rel::Sle, a: b, b: a },
            Rel::Sle => Cmp { rel: Rel::Slt, a: b, b: a },
        }
    }

    /// One form per meaning: `0 <u x` is `x != 0`, `x <=u 0` is `x == 0`, the operands of `==` /
    /// `!=` in one order.
    fn canonical(self) -> Cmp {
        let zero = |t: Term| matches!(t, Term::Const(0, _));
        let mut c = match self.rel {
            Rel::Ult if zero(self.a) => Cmp { rel: Rel::Ne, a: self.b, b: self.a },
            Rel::Ule if zero(self.b) => Cmp { rel: Rel::Eq, a: self.a, b: self.b },
            _ => self,
        };
        if matches!(c.rel, Rel::Eq | Rel::Ne) && order(&c.b) < order(&c.a) {
            std::mem::swap(&mut c.a, &mut c.b);
        }
        c
    }

    /// The comparison's value when both sides are constants, or one value plus two different
    /// constants (`x != x + 0x128`).
    fn eval(self) -> Option<bool> {
        if let (Term::Val(k1, c1), Term::Val(k2, c2)) = (self.a, self.b)
            && k1 == k2
        {
            return match self.rel {
                Rel::Eq => Some(c1 == c2),
                Rel::Ne => Some(c1 != c2),
                _ if c1 == c2 => Some(matches!(self.rel, Rel::Ule | Rel::Sle)),
                _ => None,
            };
        }
        let (Term::Const(x, s), Term::Const(y, t)) = (self.a, self.b) else { return None };
        if s != t || s == 0 || s > 8 {
            return None;
        }
        let sx = |v: u64| ((v << (64 - 8 * s)) as i64) >> (64 - 8 * s);
        Some(match self.rel {
            Rel::Eq => x == y,
            Rel::Ne => x != y,
            Rel::Ult => x < y,
            Rel::Ule => x <= y,
            Rel::Slt => sx(x) < sx(y),
            Rel::Sle => sx(x) <= sx(y),
        })
    }
}

fn order(t: &Term) -> (u8, ValueKey, u64) {
    match *t {
        Term::Val(k, c) => (0, k, c),
        Term::Low(k, s) => (1, k, s as u64),
        Term::Const(v, s) => (2, (0, 0, 0, 0), v ^ ((s as u64) << 56)),
    }
}

/// Does `g` (known to hold) make `c` hold?
fn implies(g: Cmp, c: Cmp) -> bool {
    let (g, c) = (g.canonical(), c.canonical());
    if c.eval() == Some(true) || g == c {
        return true;
    }
    // `a < b` makes `a != b` and `a <= b` hold
    let same = g.a == c.a && g.b == c.b;
    let swapped = g.a == c.b && g.b == c.a;
    match (g.rel, c.rel) {
        (Rel::Ult | Rel::Slt, Rel::Ne) => same || swapped || Cmp { rel: Rel::Ne, ..g }.canonical() == c,
        (Rel::Ult, Rel::Ule) | (Rel::Slt, Rel::Sle) => same,
        _ => false,
    }
}

struct Analysis<'f> {
    func: &'f SsaFunction,
    idom: Vec<Option<BlockId>>,
    /// The live op defining each value.
    defs: FxHashMap<ValueKey, OpIdx>,
    readers: Readers,
    /// The induction variables' values of the loop looked at: a term of their own (`R` is the
    /// register, whatever its update adds).
    opaque: std::cell::RefCell<rustc_hash::FxHashSet<ValueKey>>,
}

impl<'f> Analysis<'f> {
    fn new(func: &'f SsaFunction) -> Self {
        let mut defs = FxHashMap::default();
        for op in func.ops.iter().filter(|o| !o.dead) {
            if let Some(o) = op.output {
                defs.insert(value_key(func, o), op.index);
            }
        }
        Self { func, idom: crate::dominator::compute_idom(&func.cfg), defs, readers: Readers::new(func), opaque: Default::default() }
    }

    fn def(&self, v: VarId) -> Option<&'f crate::ssa::SsaOp> {
        let f = self.func;
        self.defs.get(&value_key(f, v)).map(|&d| &f.ops[d])
    }

    fn reg(&self, v: VarId) -> Option<(u64, u32)> {
        let d = &self.func.varnodes[v as usize].data;
        (d.space == SpaceId::REGISTER).then_some((d.offset, d.size))
    }

    /// The blocks of the natural loop with header `h` (in the original CFG).
    fn natural_loop(&self, h: BlockId) -> Option<Vec<bool>> {
        let cfg = &self.func.cfg;
        let mut body = vec![false; cfg.blocks.len()];
        body[h] = true;
        let mut work: Vec<BlockId> = cfg.blocks[h].predecessors.iter().copied().filter(|&p| crate::dominator::dominates(&self.idom, h, p)).collect();
        if work.is_empty() {
            return None;
        }
        while let Some(b) = work.pop() {
            if !body[b] && self.reachable(b) {
                body[b] = true;
                work.extend(cfg.blocks[b].predecessors.iter().copied());
            }
        }
        Some(body)
    }

    fn for_loop(&self, l: &LoopNode<'_>, ctx: &Context<'_>, seen: &FxHashMap<BlockId, usize>) -> Option<ForInfo> {
        let func = self.func;
        let cfg = &func.cfg;
        // the block whose last statements are the update: the test block of a `do … while`,
        // the block ending a `while`'s body (which jumps back to the header)
        let (h, latch) = if l.do_while {
            let h = first_block(l.body).unwrap_or(l.cond);
            (h, l.cond)
        } else {
            if continues(l.body) {
                return None;
            }
            let latch = last_basic(l.body)?;
            if cfg.blocks[latch].successors != [l.cond] {
                return None;
            }
            (l.cond, latch)
        };
        if ctx.goto_targets.contains(&latch) || seen.get(&latch) != Some(&1) {
            return None;
        }
        if !cfg.blocks[latch].successors.contains(&h) {
            return None;
        }
        let body = self.natural_loop(h)?;
        if !body[latch] || !body[l.cond] {
            return None;
        }
        // a `while`'s header prints no statement (else it is `while (true) { …; if (!c) break; }`)
        let block_ops = |b: BlockId| func.ops.iter().filter(move |o| o.block == b && !o.dead);
        let is_stmt = |o: &crate::ssa::SsaOp| !matches!(o.opcode, OpCode::Branch | OpCode::CBranch | OpCode::BranchInd) && (ctx.printed)(o.index);
        if !l.do_while && block_ops(h).any(is_stmt) {
            return None;
        }
        // the induction-variable updates of the latch
        let stmts: Vec<&crate::ssa::SsaOp> = block_ops(latch).filter(|o| is_stmt(o)).collect();
        let order: FxHashMap<OpIdx, usize> = block_ops(latch).enumerate().map(|(k, o)| (o.index, k)).collect();
        let mut cands: Vec<(OpIdx, (u64, u32), VarId, VarId)> = Vec::new();
        for op in &stmts {
            if let Some((reg, phi, next)) = self.induction_update(op, h, &body)
                && !cands.iter().any(|u| overlaps(u.1, reg))
            {
                cands.push((op.index, reg, phi, next));
            }
        }
        // no other op of the loop writes an updated register (or a part of it), printed or not
        // (a copy a temporary prints as)
        cands.retain(|u| {
            !(0..cfg.blocks.len()).filter(|&b| body[b]).any(|b| {
                block_ops(b).any(|o| o.index != u.0 && o.opcode != OpCode::MultiEqual && o.output.and_then(|v| self.reg(v)).is_some_and(|r| overlaps(u.1, r)))
            })
        });
        // after the update the loop reads the stepped value only in the rest of the latch (where
        // it prints as `R + k`: `R` is stepped at the end now), its test and the header's phi;
        // the value before the update not at all
        let mut sunk: Vec<OpIdx> = Vec::new();
        cands.retain(|u| {
            let at = order[&u.0];
            let mut later = false;
            for &r in self.readers.of(func, u.3) {
                let ro = &func.ops[r];
                if !body[ro.block] || (ro.block == h && ro.opcode == OpCode::MultiEqual) {
                    continue;
                }
                if ro.block != latch || order.get(&r).is_none_or(|&k| k <= at) {
                    return false;
                }
                later |= !self.only_tests(r, 4, ctx);
            }
            if self.readers.of(func, u.2).iter().any(|&r| func.ops[r].block == latch && order.get(&r).is_some_and(|&k| k > at)) {
                return false;
            }
            if later {
                sunk.push(u.0);
            }
            true
        });
        if cands.is_empty() {
            return None;
        }
        // the test reads an updated register (a `while` whose test the short-circuit merge
        // rewrote: the emitter checks its text, and only updates read by nothing after them move)
        if !l.do_while && (ctx.merged)(l.cond) {
            cands.retain(|u| !sunk.contains(&u.0));
            if cands.is_empty() {
                return None;
            }
            return Some(ForInfo { updates: cands.iter().map(|u| u.0).collect(), regs: cands.iter().map(|u| u.1).collect(), do_while: false, range: None, test_unknown: true, sunk: Vec::new() });
        }
        *self.opaque.borrow_mut() = cands.iter().flat_map(|u| [value_key(func, u.2), value_key(func, u.3)]).collect();
        let test = self.test(l.cond, &body, ctx)?;
        let tested = |u: &(OpIdx, (u64, u32), VarId, VarId)| {
            let ks = [value_key(func, u.2), value_key(func, u.3)];
            [test.cmp.a, test.cmp.b].iter().any(|t| matches!(*t, Term::Val(k, _) | Term::Low(k, _) if ks.contains(&k)))
        };
        if !cands.iter().any(tested) {
            return None;
        }
        // (a register the test does not read moves only when nothing reads it after its update)
        let updates: Vec<(OpIdx, (u64, u32), VarId, VarId)> = cands.iter().copied().filter(|u| tested(u) || !sunk.contains(&u.0)).collect();
        sunk.retain(|s| updates.iter().any(|u| u.0 == *s));
        if l.do_while && !self.holds_on_entry(h, &body, &test, &updates) {
            return None;
        }
        let range = self.range(l, &body, &test, &updates).filter(|r| !sunk.contains(&r.update));
        Some(ForInfo { updates: updates.iter().map(|u| u.0).collect(), regs: updates.iter().map(|u| u.1).collect(), do_while: l.do_while, range, test_unknown: false, sunk })
    }

    /// `op` is `R = R ± k` stepping an induction variable of the loop at `h` (blocks `body`):
    /// the register, the header's phi and the stepped value. `R` read by the update is the
    /// header's phi, or a phi of the body joining only it; the header's phi takes the stepped
    /// value from every back edge.
    fn induction_update(&self, op: &crate::ssa::SsaOp, h: BlockId, body: &[bool]) -> Option<((u64, u32), VarId, VarId)> {
        let func = self.func;
        if !matches!(op.opcode, OpCode::IntAdd | OpCode::IntSub) || op.inputs.len() != 2 {
            return None;
        }
        let next = op.output?;
        let reg = self.reg(next)?;
        if func.varnodes[op.inputs[1] as usize].data.space != SpaceId::CONST || self.reg(op.inputs[0]) != Some(reg) {
            return None;
        }
        let phi = self.header_phi(op.inputs[0], h, body)?;
        let nk = value_key(func, next);
        let preds = &func.cfg.blocks[h].predecessors;
        let phi_op = self.def(phi)?;
        let back: Vec<usize> = (0..preds.len()).filter(|&i| body[preds[i]] && self.reachable(preds[i])).collect();
        if back.is_empty() || !back.iter().all(|&i| phi_op.inputs.get(i).is_some_and(|&v| value_key(func, v) == nk)) {
            return None;
        }
        Some((reg, phi, next))
    }

    /// Value `v` is the phi of the loop header `h`: that phi itself, or a phi of the body all of
    /// whose inputs from reachable blocks are, through other phis of the body.
    fn header_phi(&self, v: VarId, h: BlockId, body: &[bool]) -> Option<VarId> {
        let func = self.func;
        let mut found: Option<VarId> = None;
        let mut seen: FxHashMap<ValueKey, ()> = FxHashMap::default();
        let mut work = vec![v];
        while let Some(x) = work.pop() {
            if seen.insert(value_key(func, x), ()).is_some() {
                continue;
            }
            if seen.len() > 64 {
                return None;
            }
            let d = self.def(x)?;
            if d.opcode != OpCode::MultiEqual || !body[d.block] {
                return None;
            }
            if d.block == h {
                match found {
                    Some(f) if value_key(func, f) != value_key(func, x) => return None,
                    _ => found = Some(x),
                }
                continue;
            }
            let preds = &func.cfg.blocks[d.block].predecessors;
            for (i, &p) in preds.iter().enumerate() {
                if self.reachable(p) {
                    work.push(*d.inputs.get(i)?);
                }
            }
        }
        found
    }

    /// The one value phi `p` joins, through other phis, from the blocks reached from the entry
    /// (a phi of a register no reached block changes, kept by an unreached predecessor such as
    /// alignment padding).
    fn trivial_phi(&self, p: OpIdx) -> Option<VarId> {
        let func = self.func;
        let mut seen: FxHashMap<ValueKey, ()> = FxHashMap::default();
        let mut work = vec![p];
        let mut value: Option<VarId> = None;
        while let Some(o) = work.pop() {
            let op = &func.ops[o];
            if seen.insert(value_key(func, op.output?), ()).is_some() {
                continue;
            }
            if seen.len() > 16 {
                return None;
            }
            let preds = &func.cfg.blocks[op.block].predecessors;
            for (i, &v) in op.inputs.iter().enumerate() {
                if preds.get(i).is_some_and(|&b| !self.reachable(b)) {
                    continue;
                }
                match self.def(v) {
                    Some(d) if d.opcode == OpCode::MultiEqual => work.push(d.index),
                    _ => match value {
                        Some(x) if value_key(func, x) != value_key(func, v) => return None,
                        _ => value = Some(v),
                    },
                }
            }
        }
        value
    }

    /// Op `r` only computes a branch condition: it is the branch, or prints no statement and
    /// every reader of its value is such an op (through `depth` more).
    fn only_tests(&self, r: OpIdx, depth: usize, ctx: &Context<'_>) -> bool {
        let func = self.func;
        let op = &func.ops[r];
        if op.opcode == OpCode::CBranch {
            return true;
        }
        // (a statement of its own prints in the body)
        if (ctx.printed)(r) {
            return false;
        }
        let Some(o) = op.output else { return false };
        let rs = self.readers.of(func, o);
        depth > 0 && !rs.is_empty() && rs.iter().all(|&x| func.ops[x].block == op.block && self.only_tests(x, depth - 1, ctx))
    }

    /// Block `b` is reached from the function's entry.
    fn reachable(&self, b: BlockId) -> bool {
        b == self.func.cfg.entry_block || self.idom.get(b).copied().flatten().is_some()
    }

    /// The loop's continue condition: the test block's comparison, true when the loop goes on
    /// (to its successor inside the loop).
    fn test(&self, cond: BlockId, body: &[bool], ctx: &Context<'_>) -> Option<Test> {
        let func = self.func;
        if (ctx.merged)(cond) {
            return None;
        }
        let succ = &func.cfg.blocks[cond].successors;
        if succ.len() != 2 || body[succ[0]] == body[succ[1]] {
            return None;
        }
        let br = func.ops.iter().rev().find(|o| o.block == cond && !o.dead && o.opcode == OpCode::CBranch)?;
        let flag = *br.inputs.get(1)?;
        let ((cmp_op, neg), mut cmp) = self.compare(flag)?;
        // (the branch goes to its first successor when the flag is true)
        let on = usize::from(!body[succ[0]]);
        if on == 1 {
            cmp = cmp.negate();
        }
        Some(Test { cmp, cmp_op, negated: neg ^ (on == 1) })
    }

    /// The comparison computing boolean `v` (through copies and negations): the comparison op,
    /// whether `v` is its negation, and the comparison `v` means.
    fn compare(&self, v: VarId) -> Option<((OpIdx, bool), Cmp)> {
        let mut v = v;
        let mut neg = false;
        for _ in 0..8 {
            let d = self.def(v)?;
            match d.opcode {
                OpCode::BoolNegate => {
                    neg = !neg;
                    v = d.inputs[0];
                }
                OpCode::Copy => v = d.inputs[0],
                op => {
                    let rel = match op {
                        OpCode::IntEqual => Rel::Eq,
                        OpCode::IntNotEqual => Rel::Ne,
                        OpCode::IntLess => Rel::Ult,
                        OpCode::IntLessEqual => Rel::Ule,
                        OpCode::IntSLess => Rel::Slt,
                        OpCode::IntSLessEqual => Rel::Sle,
                        _ => return None,
                    };
                    if d.inputs.len() != 2 {
                        return None;
                    }
                    let c = Cmp { rel, a: self.term(d.inputs[0]), b: self.term(d.inputs[1]) };
                    return Some(((d.index, neg), if neg { c.negate() } else { c }));
                }
            }
        }
        None
    }

    /// The term of value `v`: through copies, the low part of a value (`SUBPIECE x, 0`), and the
    /// value under an extension it is the low part of.
    fn term(&self, v: VarId) -> Term {
        let func = self.func;
        let mut v = v;
        for _ in 0..8 {
            let d = &func.varnodes[v as usize].data;
            if d.space == SpaceId::CONST {
                return Term::Const(mask(d.offset, d.size), d.size);
            }
            match self.def(v) {
                Some(op) if op.opcode == OpCode::Copy => v = op.inputs[0],
                Some(op) if op.opcode == OpCode::MultiEqual && self.trivial_phi(op.index).is_some() => v = self.trivial_phi(op.index).expect("checked"),
                Some(op) if op.opcode == OpCode::Subpiece && op.inputs.len() == 2 && func.varnodes[op.inputs[1] as usize].data.offset == 0 => {
                    return self.low(op.inputs[0], d.size);
                }
                // `x + c` (not through an induction variable's update: its value is the register's)
                Some(op)
                    if op.opcode == OpCode::IntAdd
                        && op.inputs.len() == 2
                        && func.varnodes[op.inputs[1] as usize].data.space == SpaceId::CONST
                        && !self.opaque.borrow().contains(&value_key(func, v)) =>
                {
                    let c = &func.varnodes[op.inputs[1] as usize].data;
                    return match self.term(op.inputs[0]) {
                        Term::Val(k, o) if k.2 == d.size => Term::Val(k, mask(o.wrapping_add(c.offset), d.size)),
                        _ => Term::Val(value_key(func, v), 0),
                    };
                }
                _ => return Term::Val(value_key(func, v), 0),
            }
        }
        Term::Val(value_key(func, v), 0)
    }

    /// The low `size` bytes of `v` as a term.
    fn low(&self, v: VarId, size: u32) -> Term {
        let func = self.func;
        let d = &func.varnodes[v as usize].data;
        if d.space == SpaceId::CONST {
            return Term::Const(mask(d.offset, size), size);
        }
        match self.def(v) {
            Some(op) if op.opcode == OpCode::Copy => self.low(op.inputs[0], size),
            Some(op) if matches!(op.opcode, OpCode::IntZExt | OpCode::IntSExt) && func.varnodes[op.inputs[0] as usize].data.size == size => self.term(op.inputs[0]),
            _ if d.size == size => self.term(v),
            _ => Term::Low(value_key(func, v), size),
        }
    }

    /// Does the test of a `do … while` hold with the induction variables at their entry values,
    /// by the condition of a branch every entry into the loop passes?
    fn holds_on_entry(&self, h: BlockId, body: &[bool], test: &Test, updates: &[(OpIdx, (u64, u32), VarId, VarId)]) -> bool {
        let func = self.func;
        let cfg = &func.cfg;
        let preds = &cfg.blocks[h].predecessors;
        let entries: Vec<usize> = (0..preds.len()).filter(|&i| !body[preds[i]] && self.reachable(preds[i])).collect();
        if entries.len() != 1 || (h == cfg.entry_block) {
            return false;
        }
        let e = entries[0];
        // the entry value of each induction variable, by the stepped value's / phi's key
        let mut subst: FxHashMap<ValueKey, VarId> = FxHashMap::default();
        for u in updates {
            let Some(phi) = self.def(u.2) else { return false };
            let Some(&init) = phi.inputs.get(e) else { return false };
            subst.insert(value_key(func, u.2), init);
            subst.insert(value_key(func, u.3), init);
        }
        let entry_term = |t: Term| -> Option<Term> {
            match t {
                Term::Val(k, c) => match subst.get(&k) {
                    Some(&i) => match self.term(i) {
                        Term::Val(ki, ci) => Some(Term::Val(ki, mask(ci.wrapping_add(c), ki.2))),
                        Term::Const(x, s) => Some(Term::Const(mask(x.wrapping_add(c), s), s)),
                        Term::Low(..) if c != 0 => None,
                        l => Some(l),
                    },
                    None => self.invariant(k, body).then_some(t),
                },
                Term::Low(k, s) => match subst.get(&k) {
                    Some(&i) => Some(self.low(i, s)),
                    None => self.invariant(k, body).then_some(t),
                },
                Term::Const(..) => Some(t),
            }
        };
        let (Some(a), Some(b)) = (entry_term(test.cmp.a), entry_term(test.cmp.b)) else { return false };
        let c = Cmp { rel: test.cmp.rel, a, b };
        if c.canonical().eval() == Some(true) {
            return true;
        }
        // the branches every way into the loop passes: up the dominator tree from the entry
        // edge, an edge `x -> t` with `t` the only way on (`t`'s one predecessor is `x`)
        let mut t = preds[e];
        let mut from = h;
        for _ in 0..16 {
            // (the edge `t -> from` is taken on every way in when `from` has `t` as its only
            // predecessor outside the loop)
            let outside: Vec<BlockId> = cfg.blocks[from].predecessors.iter().copied().filter(|&p| !body[p] && self.reachable(p)).collect();
            if outside != [t] {
                return false;
            }
            if let Some(g) = self.branch_condition(t, from)
                && implies(g, c)
            {
                return true;
            }
            from = t;
            match self.idom.get(t).copied().flatten() {
                Some(p) if p != t => t = p,
                _ => return false,
            }
        }
        false
    }

    /// Value `k` is the same on every iteration (defined outside the loop, or a parameter).
    fn invariant(&self, k: ValueKey, body: &[bool]) -> bool {
        match self.defs.get(&k) {
            Some(&d) => !body[self.func.ops[d].block],
            None => true,
        }
    }

    /// The condition under which block `x` goes on to `t` (`x` ends in a conditional branch).
    fn branch_condition(&self, x: BlockId, t: BlockId) -> Option<Cmp> {
        let func = self.func;
        let succ = &func.cfg.blocks[x].successors;
        if succ.len() != 2 || succ[0] == succ[1] || !succ.contains(&t) {
            return None;
        }
        let br = func.ops.iter().rev().find(|o| o.block == x && !o.dead && o.opcode == OpCode::CBranch)?;
        let (_, c) = self.compare(*br.inputs.get(1)?)?;
        Some(if succ[0] == t { c } else { c.negate() })
    }

    /// `for R in a..n` (Rust): the test `R < n` unsigned, `R` stepped by one, `n` the same on
    /// every iteration, and nothing after the loop reads `R`.
    fn range(&self, l: &LoopNode<'_>, body: &[bool], test: &Test, updates: &[(OpIdx, (u64, u32), VarId, VarId)]) -> Option<RangeInfo> {
        let func = self.func;
        let [u] = updates else { return None };
        let op = &func.ops[u.0];
        let k = func.varnodes[op.inputs[1] as usize].data;
        if op.opcode != OpCode::IntAdd || mask(k.offset, k.size) != 1 || test.negated {
            return None;
        }
        // the comparison op is `R < n` itself (not its negation), on the whole register
        let c = &func.ops[test.cmp_op];
        if c.opcode != OpCode::IntLess || c.inputs.len() != 2 {
            return None;
        }
        let cur = if l.do_while { u.3 } else { u.2 };
        if value_key(func, c.inputs[0]) != value_key(func, cur) {
            return None;
        }
        let (Term::Val(n, _) | Term::Low(n, _)) = self.term(c.inputs[1]) else { return None };
        if !self.invariant(n, body) {
            return None;
        }
        // nothing outside the loop reads the variable's values
        for v in [u.2, u.3] {
            for &r in self.readers.of(func, v) {
                if !body[func.ops[r].block] {
                    return None;
                }
            }
        }
        Some(RangeInfo { update: u.0, cmp: c.index, bound: 1 })
    }
}

/// A loop's test: the comparison true when the loop goes on, the op computing it and whether
/// the loop goes on when that op is false.
struct Test {
    cmp: Cmp,
    cmp_op: OpIdx,
    negated: bool,
}

fn mask(v: u64, size: u32) -> u64 {
    if size >= 8 { v } else { v & ((1u64 << (8 * size)) - 1) }
}

/// Do two registers `(offset, size)` share a byte?
fn overlaps(a: (u64, u32), b: (u64, u32)) -> bool {
    a.0 < b.0 + b.1 as u64 && b.0 < a.0 + a.1 as u64
}

/// The update clause of a C statement `R = R + k;` / `R = R - k;` (WS97): the register and
/// `R++` / `R += k` / `R--` / `R -= k`.
pub(crate) fn c_update(line: &str) -> Option<(String, String)> {
    let (r, rhs) = line.strip_suffix(';')?.split_once(" = ")?;
    let (a, k, plus) = match rhs.split_once(" + ") {
        Some((a, k)) => (a, k, true),
        None => {
            let (a, k) = rhs.split_once(" - ")?;
            (a, k, false)
        }
    };
    let word = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !s.starts_with(|c: char| c.is_ascii_digit());
    let num = |s: &str| s.strip_prefix("0x").map_or(!s.is_empty() && s.chars().all(|c| c.is_ascii_digit()), |h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()));
    if !(word(r) && a == r && num(k)) {
        return None;
    }
    Some((r.to_string(), match (plus, k) {
        (true, "1") => cat!(r, "++"),
        (false, "1") => cat!(r, "--"),
        (true, _) => cat!(r, " += ", k),
        (false, _) => cat!(r, " -= ", k),
    }))
}

/// A C statement `R = X;` (at most 80 characters, no comment) setting one of `regs`: `R = X`,
/// the init clause of its loop's `for`.
pub(crate) fn c_init(stmt: &str, regs: &[String]) -> Option<String> {
    let s = stmt.strip_suffix(';')?;
    let (r, rhs) = s.split_once(" = ")?;
    if stmt.len() > 80 || stmt.contains("//") || !regs.iter().any(|g| g == r) || rhs.is_empty() || rhs.contains(';') {
        return None;
    }
    Some(s.to_string())
}

/// Does C text `text` name `name` (as a whole word)?
pub(crate) fn reads_name(text: &str, name: &str) -> bool {
    let b = text.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    text.match_indices(name).any(|(i, _)| (i == 0 || !word(b[i - 1])) && b.get(i + name.len()).is_none_or(|&c| !word(c)))
}

/// The init clause from the statements printed right before a loop (`stmts`, in order, the
/// last one right before it): the statements `R = X;` setting one of `regs` among the last ones,
/// past at most two register assignments they do not depend on (moving `R = X` after them
/// changes nothing: neither reads what the other writes, and none calls or stores). Their
/// indices and init texts, in order.
pub(crate) fn split_init(stmts: &[&str], regs: &[String]) -> Option<(Vec<usize>, Vec<String>)> {
    let mut taken: Vec<(usize, String)> = Vec::new();
    // the assignments passed: (target's register, the names read)
    let mut passed: Vec<(String, Vec<String>)> = Vec::new();
    for (k, stmt) in stmts.iter().enumerate().rev() {
        let parts = simple_assignment(stmt);
        if let Some(init) = c_init(stmt, regs)
            && let Some((target, reads)) = &parts
            && !taken.iter().any(|t| family(t.1.split(" = ").next().unwrap_or("")) == family(target))
            && passed.iter().all(|(t, rs)| family(t) != family(target) && !rs.iter().any(|r| family(r) == family(target)) && !reads.iter().any(|r| family(r) == family(t)))
            && (passed.is_empty() || pure(stmt))
        {
            taken.push((k, init));
            continue;
        }
        match parts {
            Some((t, reads)) if passed.len() < 2 && pure(stmt) && is_register(&t) => passed.push((t, reads)),
            _ => break,
        }
    }
    if taken.is_empty() {
        return None;
    }
    taken.reverse();
    Some((taken.iter().map(|t| t.0).collect(), taken.into_iter().map(|t| t.1).collect()))
}

/// `X = Y;` with `X` a name: `X` and the names `Y` reads.
fn simple_assignment(stmt: &str) -> Option<(String, Vec<String>)> {
    let (t, rhs) = stmt.strip_suffix(';')?.split_once(" = ")?;
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || stmt.contains("//") {
        return None;
    }
    let mut names = Vec::new();
    let mut cur = String::new();
    for c in rhs.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else if !cur.is_empty() {
            if !cur.starts_with(|c: char| c.is_ascii_digit()) {
                names.push(std::mem::take(&mut cur));
            }
            cur.clear();
        }
    }
    Some((t.to_string(), names))
}

/// No call in the statement (`f(`, `)(`): a cast's `(` follows a space or another `(`.
fn pure(stmt: &str) -> bool {
    let b = stmt.as_bytes();
    !(1..b.len()).any(|i| b[i] == b'(' && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_' || b[i - 1] == b')' || b[i - 1] == b'@'))
}

fn is_register(name: &str) -> bool {
    family(name) != name || matches!(name, "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp")
}

/// The 64-bit register a printed register name is part of (`eax`, `ax`, `al`, `ah` -> `rax`;
/// `r8d` -> `r8`; `xmm0_d` -> `xmm0`); any other name is its own.
fn family(name: &str) -> &str {
    const LEGACY: [(&str, [&str; 5]); 8] = [
        ("rax", ["eax", "ax", "al", "ah", "rax"]),
        ("rbx", ["ebx", "bx", "bl", "bh", "rbx"]),
        ("rcx", ["ecx", "cx", "cl", "ch", "rcx"]),
        ("rdx", ["edx", "dx", "dl", "dh", "rdx"]),
        ("rsi", ["esi", "si", "sil", "rsi", "rsi"]),
        ("rdi", ["edi", "di", "dil", "rdi", "rdi"]),
        ("rbp", ["ebp", "bp", "bpl", "rbp", "rbp"]),
        ("rsp", ["esp", "sp", "spl", "rsp", "rsp"]),
    ];
    for (r, names) in LEGACY {
        if names.contains(&name) {
            return r;
        }
    }
    if let Some(n) = name.strip_prefix('r') {
        let digits = n.trim_end_matches(['d', 'w', 'b']);
        if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) && n.len() - digits.len() <= 1 {
            return &name[..1 + digits.len()];
        }
    }
    if name.starts_with("xmm")
        && let Some((x, _)) = name.split_once('_')
    {
        return x;
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u32) -> Term {
        Term::Val((1, n as u64, 8, 1), 0)
    }

    #[test]
    fn update_and_init_clauses() {
        assert_eq!(c_update("rax = rax + 1;"), Some(("rax".into(), "rax++".into())));
        assert_eq!(c_update("rdi = rdi + 0x18;"), Some(("rdi".into(), "rdi += 0x18".into())));
        assert_eq!(c_update("r12 = r12 - 0x18;"), Some(("r12".into(), "r12 -= 0x18".into())));
        assert_eq!(c_update("ebx = ebx - 1;"), Some(("ebx".into(), "ebx--".into())));
        assert_eq!(c_update("rax = rcx + 1;"), None);
        assert_eq!(c_update("rax = rax + rcx;"), None);
        assert_eq!(c_update("rax = (rax + 1) + 2;"), None);
        let regs = ["rax".to_string()];
        assert_eq!(c_init("rax = 0;", &regs), Some("rax = 0".into()));
        assert_eq!(c_init("rdx = 0;", &regs), None);
        assert_eq!(c_init("rax = 0;  // x", &regs), None);
        // past an assignment it does not depend on, not past one reading it or a call
        assert_eq!(split_init(&["rax = 0;", "rdx = 0;"], &regs), Some((vec![0], vec!["rax = 0".into()])));
        assert_eq!(split_init(&["rax = 0;", "rdx = rax + 1;"], &regs), None);
        assert_eq!(split_init(&["rax = 0;", "edx = eax;"], &regs), None);
        assert_eq!(split_init(&["rax = rdx;", "edx = 5;"], &regs), None);
        assert_eq!(split_init(&["rax = 0;", "rdx = f(rdi);"], &regs), None);
        assert_eq!(split_init(&["rax = 0;", "*(uint64_t*)rdi = 0;"], &regs), None);
        let two = ["rax".to_string(), "rdi".to_string()];
        assert_eq!(split_init(&["rdi = rsi;", "rax = 0;"], &two), Some((vec![0, 1], vec!["rdi = rsi".into(), "rax = 0".into()])));
        assert_eq!(family("r8d"), "r8");
        assert_eq!(family("sil"), "rsi");
        assert_eq!(family("local_30"), "local_30");
    }

    #[test]
    fn guard_implies_the_first_test() {
        let ne = |a, b| Cmp { rel: Rel::Ne, a, b };
        // `rdi != rsi` before `while (rdi != rsi)`, either order
        assert!(implies(ne(v(1), v(2)), ne(v(2), v(1))));
        // `n != 0` makes `0 != n` and `0 <u n` hold
        assert!(implies(ne(v(3), Term::Const(0, 8)), ne(Term::Const(0, 8), v(3))));
        assert!(implies(ne(v(3), Term::Const(0, 8)), Cmp { rel: Rel::Ult, a: Term::Const(0, 8), b: v(3) }));
        // `!(n <=s 0)` is `0 <s n`
        let g = Cmp { rel: Rel::Sle, a: v(3), b: Term::Const(0, 4) }.negate();
        assert!(implies(g, Cmp { rel: Rel::Slt, a: Term::Const(0, 4), b: v(3) }));
        // `a <u b` makes `a != b`
        assert!(implies(Cmp { rel: Rel::Ult, a: v(1), b: v(2) }, ne(v(2), v(1))));
        // not: other values, the other sign
        assert!(!implies(ne(v(1), v(3)), ne(v(1), v(2))));
        // (`0 <s n` makes `n != 0`, so `0 <u n`; not the other way)
        assert!(implies(Cmp { rel: Rel::Slt, a: Term::Const(0, 4), b: v(3) }, Cmp { rel: Rel::Ult, a: Term::Const(0, 4), b: v(3) }));
        assert!(!implies(Cmp { rel: Rel::Ult, a: Term::Const(0, 4), b: v(3) }, Cmp { rel: Rel::Slt, a: Term::Const(0, 4), b: v(3) }));
        assert!(!implies(Cmp { rel: Rel::Ule, a: v(1), b: v(2) }, ne(v(1), v(2))));
        // one value plus two different constants
        let off = |c| Term::Val((1, 1, 8, 1), c);
        assert!(implies(ne(v(5), v(6)), ne(off(0), off(0x128))));
        assert!(!implies(ne(v(5), v(6)), ne(off(8), off(8))));
        assert!(!implies(ne(v(5), v(6)), Cmp { rel: Rel::Eq, a: off(0), b: off(8) }));
        // constants decide on their own
        assert!(implies(ne(v(1), v(2)), Cmp { rel: Rel::Slt, a: Term::Const(0, 4), b: Term::Const(5, 4) }));
        assert!(!implies(ne(v(1), v(2)), Cmp { rel: Rel::Slt, a: Term::Const(0xffff_ffff, 4), b: Term::Const(0xffff_fffe, 4) }));
    }
}
