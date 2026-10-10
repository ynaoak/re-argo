//! Control-flow structuring: CFG -> nested `if` / loops / `break` / `continue` / `goto`.
//!
//! The structurer walks *regions*. A two-way branch is closed at its **immediate
//! post-dominator** (the first block every path from the branch passes through, see
//! [`crate::dominator::compute_post_dominators`]): both arms are walked up to that join and
//! the walk continues after the `if` at the join. Loops are **natural loops** of the dominator
//! tree (a back edge `n -> h` with `h` dominating `n`); the loop's *follow* (where the code
//! after the loop starts) is the header's exit, else the single latch's exit, else the first
//! post-dominator of the header outside the loop. Inside a loop, reaching the header prints
//! `continue`, reaching the follow prints `break`; anything else that cannot be nested
//! (irreducible flow, a jump to a block already printed elsewhere, a jump out of two loops)
//! prints a `goto` to the block, which is printed exactly once with a label.
//!
//! Every reachable block is printed exactly once: as a `Basic`, or as the condition block of
//! an `if` / `while` / `do … while`.

use crate::cfg::{BlockId, ControlFlowGraph};
use crate::dominator::{compute_idom, compute_post_dominators, dominates, reverse_post_order};

#[derive(Debug, Clone)]
pub enum StructuredBlock {
    Basic(BlockId),
    Sequence(Vec<StructuredBlock>),
    /// `if (cond) { then_body }` — `if (!cond)` when `negated`. The condition block's own
    /// statements are printed before the `if`.
    IfThen {
        condition_block: BlockId,
        then_body: Box<StructuredBlock>,
        negated: bool,
    },
    /// `if (cond) { then_body } else { else_body }`; the then-arm is the branch's jump target.
    IfThenElse {
        condition_block: BlockId,
        then_body: Box<StructuredBlock>,
        else_body: Box<StructuredBlock>,
    },
    /// `loop { <condition_block stmts>; if (!cond) break; body }` — printed as
    /// `while (cond) { body }` when the condition block has no statements of its own.
    /// `negated` inverts `cond`.
    WhileLoop {
        condition_block: BlockId,
        body: Box<StructuredBlock>,
        negated: bool,
    },
    /// `do { body; <condition_block stmts> } while (cond)` (`!cond` when `negated`).
    DoWhileLoop {
        body: Box<StructuredBlock>,
        condition_block: BlockId,
        negated: bool,
    },
    /// `while (true) { body }`. `body` starts with the header block's own code.
    Loop {
        header: BlockId,
        body: Box<StructuredBlock>,
    },
    ForLoop {
        init_block: BlockId,
        condition_block: BlockId,
        update_block: BlockId,
        body: Box<StructuredBlock>,
    },
    ShortCircuitAnd {
        left_block: BlockId,
        right_block: BlockId,
        body: Box<StructuredBlock>,
    },
    ShortCircuitOr {
        left_block: BlockId,
        right_block: BlockId,
        body: Box<StructuredBlock>,
    },
    Switch {
        condition_block: BlockId,
        cases: Vec<(u64, StructuredBlock)>,
        default: Option<Box<StructuredBlock>>,
    },
    Goto(BlockId),
    /// Leave the innermost loop.
    Break,
    /// Next iteration of the innermost loop.
    Continue,
}

pub fn structure_cfg(cfg: &ControlFlowGraph) -> StructuredBlock {
    if cfg.blocks.is_empty() {
        return StructuredBlock::Sequence(Vec::new());
    }
    let mut s = Structurer::new(cfg);
    let mut items = s.walk(cfg.entry_block, None, false);
    // Safety net: a `goto` whose target the walk never printed (it was left to a region
    // owner that did not get there) — print the target region at the end.
    loop {
        let mut targets = Vec::new();
        for it in &items {
            collect_gotos(it, &mut targets);
        }
        let Some(&missing) = targets.iter().find(|&&t| !s.emitted[t]) else { break };
        s.loop_stack.clear();
        s.follow_stack.clear();
        items.extend(s.walk(missing, None, false));
    }
    let mut root = seq(items);
    inline_return_tails(cfg, &mut root);
    root
}

/// Longest straight-line tail (instructions) copied in place of a `goto`.
const MAX_TAIL_INSNS: usize = 6;
/// Most calls in a tail copied in place of a `goto`.
const MAX_TAIL_CALLS: usize = 1;

/// Longest block (instructions) printed a second time in place of a `goto` to it.
const MAX_COPY_INSNS: usize = 4;
/// Most instructions of a region printed a second time in place of a `goto` to it.
const MAX_COPY_REGION_INSNS: usize = 6;
/// Most calls in a region printed a second time (the call is printed on both paths).
const MAX_COPY_CALLS: usize = 1;
/// Most blocks on a path through a region printed a second time.
const MAX_COPY_DEPTH: usize = 2;

/// The blocks of a short tail that ends the function (`goto` to it can print the tail
/// itself): a chain of single-successor blocks into a `ret`, a trap or a call that never
/// returns (WS81), at most [`MAX_TAIL_INSNS`] instructions and [`MAX_TAIL_CALLS`] call
/// (`unlock(m); return x;`, `throw_length_error("vector");`). The epilogue's frame restore
/// (`pop`, `add rsp`, `ret`, see [`crate::cfg::is_epilogue_insn`]) prints nothing and does
/// not count.
fn return_tail(cfg: &ControlFlowGraph, start: BlockId) -> Option<Vec<BlockId>> {
    use reargo_core::pcode::OpCode;
    let mut chain = Vec::new();
    let (mut insns, mut calls) = (0, 0);
    let mut b = start;
    loop {
        let block = &cfg.blocks[b];
        insns += block.instructions.iter().filter(|i| !crate::cfg::is_epilogue_insn(&i.mnemonic)).count();
        calls += block
            .instructions
            .iter()
            .filter(|i| i.ops.iter().any(|o| matches!(o.opcode, OpCode::Call | OpCode::CallInd)))
            .count();
        if insns > MAX_TAIL_INSNS || calls > MAX_TAIL_CALLS || chain.contains(&b) {
            return None;
        }
        chain.push(b);
        match block.successors.as_slice() {
            [] => {
                let ends = block.is_return() || block.instructions.last().is_some_and(crate::cfg::is_trap);
                return ends.then_some(chain);
            }
            [next] => b = *next,
            _ => return None,
        }
    }
}

/// Replace each `goto` to a short return tail by a copy of the tail (`{ …; return x; }`),
/// the way a compiler's shared epilogue is usually read.
fn inline_return_tails(cfg: &ControlFlowGraph, node: &mut StructuredBlock) {
    use StructuredBlock::*;
    match node {
        Goto(t) => {
            if let Some(chain) = return_tail(cfg, *t) {
                *node = seq(chain.into_iter().map(Basic).collect());
            }
        }
        Sequence(v) => v.iter_mut().for_each(|x| inline_return_tails(cfg, x)),
        IfThen { then_body, .. } => inline_return_tails(cfg, then_body),
        IfThenElse { then_body, else_body, .. } => {
            inline_return_tails(cfg, then_body);
            inline_return_tails(cfg, else_body);
        }
        WhileLoop { body, .. }
        | DoWhileLoop { body, .. }
        | Loop { body, .. }
        | ForLoop { body, .. }
        | ShortCircuitAnd { body, .. }
        | ShortCircuitOr { body, .. } => inline_return_tails(cfg, body),
        Switch { cases, default, .. } => {
            cases.iter_mut().for_each(|(_, c)| inline_return_tails(cfg, c));
            if let Some(d) = default {
                inline_return_tails(cfg, d);
            }
        }
        Basic(_) | Break | Continue => {}
    }
}

struct LoopInfo {
    body: Vec<bool>,
    follow: Option<BlockId>,
}

struct Structurer<'a> {
    cfg: &'a ControlFlowGraph,
    ipdom: Vec<Option<BlockId>>,
    pdom: crate::dominator::PostDominators,
    /// header -> loop
    loops: Vec<Option<LoopInfo>>,
    emitted: Vec<bool>,
    /// Headers of the loops being structured, innermost last.
    loop_stack: Vec<BlockId>,
    /// Joins of the `if`s whose arms are being structured (not yet printed).
    follow_stack: Vec<BlockId>,
}

impl<'a> Structurer<'a> {
    fn new(cfg: &'a ControlFlowGraph) -> Self {
        let n = cfg.blocks.len();
        let idom = compute_idom(cfg);
        let pdom = compute_post_dominators(cfg);
        let rpo = reverse_post_order(cfg);
        let mut rpo_num = vec![usize::MAX; n];
        for (i, &b) in rpo.iter().enumerate() {
            rpo_num[b] = i;
        }

        // natural loops: back edge n -> h with h dominating n
        let mut latches: Vec<Vec<BlockId>> = vec![Vec::new(); n];
        for &b in &rpo {
            for &s in &cfg.blocks[b].successors {
                if s < n && idom[s].is_some() && dominates(&idom, s, b) {
                    latches[s].push(b);
                }
            }
        }
        let mut loops: Vec<Option<LoopInfo>> = (0..n).map(|_| None).collect();
        for h in 0..n {
            if latches[h].is_empty() {
                continue;
            }
            let mut body = vec![false; n];
            body[h] = true;
            let mut stack: Vec<BlockId> = latches[h].clone();
            while let Some(x) = stack.pop() {
                if body[x] || idom[x].is_none() {
                    continue;
                }
                body[x] = true;
                for &p in &cfg.blocks[x].predecessors {
                    if !body[p] {
                        stack.push(p);
                    }
                }
            }
            let outside = |b: BlockId| !body[b];
            let exit_of = |b: BlockId| -> Option<BlockId> {
                let succ = &cfg.blocks[b].successors;
                let exits: Vec<BlockId> = succ.iter().copied().filter(|&s| outside(s)).collect();
                (exits.len() == 1 && succ.len() == 2).then(|| exits[0])
            };
            // 1. the header's exit (a `while`), 2. the single latch's exit (a `do … while`),
            // 3. the header's first post-dominator outside the loop, 4. the exit target most
            // edges leave to
            let mut follow = exit_of(h);
            if follow.is_none() && latches[h].len() == 1 {
                follow = exit_of(latches[h][0]);
            }
            if follow.is_none() {
                let mut p = pdom.ipdom[h];
                while let Some(x) = p {
                    if !body[x] {
                        break;
                    }
                    p = pdom.ipdom[x];
                }
                follow = p;
            }
            if follow.is_none() {
                let mut count: Vec<(usize, usize, BlockId)> = Vec::new();
                for b in (0..n).filter(|&b| body[b]) {
                    for &s in &cfg.blocks[b].successors {
                        if outside(s) {
                            match count.iter_mut().find(|c| c.2 == s) {
                                Some(c) => c.0 += 1,
                                None => count.push((1, usize::MAX - rpo_num[s], s)),
                            }
                        }
                    }
                }
                follow = count.into_iter().max().map(|c| c.2);
            }
            loops[h] = Some(LoopInfo { body, follow });
        }

        Structurer {
            cfg,
            ipdom: pdom.ipdom.clone(),
            pdom,
            loops,
            emitted: vec![false; n],
            loop_stack: Vec::new(),
            follow_stack: Vec::new(),
        }
    }

    fn succs(&self, b: BlockId) -> Vec<BlockId> {
        let mut v: Vec<BlockId> = Vec::with_capacity(2);
        for &s in &self.cfg.blocks[b].successors {
            if !v.contains(&s) {
                v.push(s);
            }
        }
        v
    }

    fn loop_info(&self, h: BlockId) -> &LoopInfo {
        self.loops[h].as_ref().expect("loop header")
    }

    /// The jump that reaching `b` turns into, given the loops and `if`s being structured.
    fn jump_for(&self, b: BlockId) -> Option<StructuredBlock> {
        if let Some((&inner, outer)) = self.loop_stack.split_last() {
            if b == inner {
                return Some(StructuredBlock::Continue);
            }
            let info = self.loop_info(inner);
            if Some(b) == info.follow {
                return Some(StructuredBlock::Break);
            }
            for &h in outer {
                if b == h || Some(b) == self.loop_info(h).follow {
                    return Some(StructuredBlock::Goto(b));
                }
            }
            // code after a loop that the loop's normal exit also reaches: leave it to the
            // walk after the loop instead of printing it inside the body
            for &h in &self.loop_stack {
                let info = self.loop_info(h);
                if let Some(f) = info.follow
                    && !info.body[b]
                    && self.pdom.post_dominates(b, f)
                {
                    return Some(StructuredBlock::Goto(b));
                }
            }
        }
        if self.follow_stack.contains(&b) {
            return Some(StructuredBlock::Goto(b));
        }
        None
    }

    /// The jump that walking into `b` would print right away, if any.
    fn immediate_jump(&self, b: BlockId) -> Option<StructuredBlock> {
        self.jump_for(b).or_else(|| self.emitted[b].then_some(StructuredBlock::Goto(b)))
    }

    /// Print the short region from `b` (already printed elsewhere) again instead of a `goto`
    /// to it: blocks of at most [`MAX_COPY_INSNS`] instructions, at most
    /// [`MAX_COPY_REGION_INSNS`] and [`MAX_COPY_CALLS`] call in all and [`MAX_COPY_DEPTH`]
    /// deep (`rdi = r12; …; memcpy(rdi, rsi, rdx);` shared by two arms), whose every way out is
    /// reachable here without a `goto` of its own — the end of the region being walked
    /// (`stop`), a `break` / `continue`, or a return tail (copied later). A `goto` that
    /// still names a copied block lands on either copy; both go on the same way.
    fn copy_region(&self, b: BlockId, stop: Option<BlockId>) -> Option<Vec<StructuredBlock>> {
        let mut budget = (MAX_COPY_REGION_INSNS, MAX_COPY_CALLS);
        self.copy_from(b, stop, MAX_COPY_DEPTH, &mut budget, true)
    }

    fn copy_from(
        &self,
        b: BlockId,
        stop: Option<BlockId>,
        depth: usize,
        budget: &mut (usize, usize),
        first: bool,
    ) -> Option<Vec<StructuredBlock>> {
        use reargo_core::pcode::OpCode;
        use StructuredBlock::*;
        if !first {
            if Some(b) == stop {
                return Some(Vec::new());
            }
            match self.jump_for(b) {
                Some(j @ (Break | Continue)) => return Some(vec![j]),
                Some(_) => return None,
                None => {}
            }
            if self.emitted[b] && return_tail(self.cfg, b).is_some() {
                return Some(vec![Goto(b)]);
            }
        }
        let block = &self.cfg.blocks[b];
        let insns = block.instructions.iter().filter(|i| !crate::cfg::is_epilogue_insn(&i.mnemonic)).count();
        let calls = block
            .instructions
            .iter()
            .filter(|i| i.ops.iter().any(|o| matches!(o.opcode, OpCode::Call | OpCode::CallInd)))
            .count();
        if depth == 0 || insns > MAX_COPY_INSNS || self.loops[b].is_some() {
            return None;
        }
        budget.0 = budget.0.checked_sub(insns)?;
        budget.1 = budget.1.checked_sub(calls)?;
        match *self.succs(b).as_slice() {
            [s] if s != b => {
                let mut v = vec![Basic(b)];
                v.extend(self.copy_from(s, stop, depth - 1, budget, false)?);
                Some(v)
            }
            [t, f] if t != b && f != b => {
                let jt = self.copy_from(t, stop, depth - 1, budget, false)?;
                let jf = self.copy_from(f, stop, depth - 1, budget, false)?;
                let if_then = |body: Vec<StructuredBlock>, negated: bool| IfThen {
                    condition_block: b,
                    then_body: Box::new(seq(body)),
                    negated,
                };
                Some(if ends_flow(self.cfg, &jt) {
                    let mut v = vec![if_then(jt, false)];
                    v.extend(jf);
                    v
                } else if ends_flow(self.cfg, &jf) || jt.is_empty() {
                    let mut v = vec![if_then(jf, true)];
                    v.extend(jt);
                    v
                } else if jf.is_empty() {
                    vec![if_then(jt, false)]
                } else {
                    vec![IfThenElse { condition_block: b, then_body: Box::new(seq(jt)), else_body: Box::new(seq(jf)) }]
                })
            }
            _ => None,
        }
    }

    /// Structure the code from `start` until `stop` (exclusive; `None` = until the flow ends).
    /// `header_first`: `start` is the header of the innermost loop being entered (print it
    /// rather than `continue`).
    fn walk(&mut self, start: BlockId, stop: Option<BlockId>, header_first: bool) -> Vec<StructuredBlock> {
        let mut out = Vec::new();
        let mut cur = Some(start);
        let mut first = header_first;
        while let Some(b) = cur {
            let is_first = std::mem::replace(&mut first, false);
            if Some(b) == stop {
                break;
            }
            if !is_first {
                if let Some(j) = self.jump_for(b) {
                    out.push(j);
                    break;
                }
                if self.emitted[b] {
                    // a short block printed elsewhere, whose successor is reachable from
                    // here too: print it again instead of `goto` to it
                    if let Some(copy) = self.copy_region(b, stop) {
                        out.extend(copy);
                        break;
                    }
                    out.push(StructuredBlock::Goto(b));
                    break;
                }
                if self.loops[b].is_some() && !self.loop_stack.contains(&b) {
                    let (node, next) = self.structure_loop(b);
                    out.push(node);
                    cur = next;
                    continue;
                }
            }
            self.emitted[b] = true;
            let succs = self.succs(b);
            match succs.len() {
                0 => {
                    out.push(StructuredBlock::Basic(b));
                    cur = None;
                }
                1 => {
                    out.push(StructuredBlock::Basic(b));
                    cur = Some(succs[0]);
                }
                _ => {
                    // (the CFG never builds more than two successors)
                    let (items, next) = self.structure_if(b, succs[0], succs[1]);
                    out.extend(items);
                    cur = next;
                }
            }
        }
        out
    }

    fn structure_if(&mut self, b: BlockId, t: BlockId, f: BlockId) -> (Vec<StructuredBlock>, Option<BlockId>) {
        // the join: the immediate post-dominator, unless it lies outside the innermost loop
        // while the branch is inside it (then every arm ends in break / continue / return:
        // `if (c) break;` rather than an empty arm that falls out to a `break` after the if)
        let mut join = self.ipdom[b];
        if let (Some(&h), Some(j)) = (self.loop_stack.last(), join) {
            let body = &self.loop_info(h).body;
            if body[b] && !body[j] {
                join = None;
            }
        }
        // the fall-through is only a jump (`break`, `continue`, a `goto` to code printed
        // elsewhere): `if (!c) break;` and carry on with the taken branch in this sequence
        // (when both are jumps, the one worse as a fall-through goes in the `if`: a
        // trailing `continue` disappears at the end of a loop body, a `goto` never does)
        let rank = |j: &Option<StructuredBlock>| match j {
            None => 0,
            Some(StructuredBlock::Continue) => 1,
            Some(StructuredBlock::Break) => 2,
            Some(_) => 3,
        };
        let (jt, jf) = (self.immediate_jump(t), self.immediate_jump(f));
        if Some(f) != join
            && rank(&jf) > rank(&jt)
            && let Some(jump) = jf
        {
            // a `goto` to a short region printed elsewhere that ends the flow (in `break`,
            // `continue` or a return tail): print the region again instead (WS81)
            let body = match jump {
                StructuredBlock::Goto(x) => self
                    .copy_region(x, None)
                    .filter(|c| ends_flow(self.cfg, c))
                    .map_or(jump, seq),
                j => j,
            };
            let node = StructuredBlock::IfThen { condition_block: b, then_body: Box::new(body), negated: true };
            return (vec![node], Some(t));
        }
        if let Some(j) = join {
            self.follow_stack.push(j);
        }
        let then_items = self.walk(t, join, false);
        let then_ends = ends_flow(self.cfg, &then_items);
        if then_ends && !then_items.is_empty() {
            // `if (c) { …; return; }` then carry on with the other arm in this sequence
            if join.is_some() {
                self.follow_stack.pop();
            }
            let node = StructuredBlock::IfThen { condition_block: b, then_body: Box::new(seq(then_items)), negated: false };
            return (vec![node], Some(f));
        }
        let else_items = self.walk(f, join, false);
        if join.is_some() {
            self.follow_stack.pop();
        }
        let else_ends = ends_flow(self.cfg, &else_items);
        let items = match (then_items.is_empty(), else_items.is_empty()) {
            (true, true) => vec![StructuredBlock::Basic(b)],
            (false, true) => vec![StructuredBlock::IfThen { condition_block: b, then_body: Box::new(seq(then_items)), negated: false }],
            (true, false) => vec![StructuredBlock::IfThen { condition_block: b, then_body: Box::new(seq(else_items)), negated: true }],
            (false, false) if else_ends => {
                // guard clause: `if (!c) { …; return; }` then the then-arm inline
                let mut v = vec![StructuredBlock::IfThen { condition_block: b, then_body: Box::new(seq(else_items)), negated: true }];
                v.extend(then_items);
                v
            }
            (false, false) => vec![StructuredBlock::IfThenElse {
                condition_block: b,
                then_body: Box::new(seq(then_items)),
                else_body: Box::new(seq(else_items)),
            }],
        };
        (items, join)
    }

    fn structure_loop(&mut self, h: BlockId) -> (StructuredBlock, Option<BlockId>) {
        let follow = self.loop_info(h).follow;
        self.loop_stack.push(h);
        let mut body = self.walk(h, None, true);
        self.loop_stack.pop();
        if matches!(body.last(), Some(StructuredBlock::Continue)) {
            body.pop();
        }
        let next = follow.filter(|&f| f != h);
        (refine_loop(h, body), next)
    }
}

/// Turn `while (true) { … }` into `while (c)` / `do … while (c)` where the shape allows.
fn refine_loop(h: BlockId, mut body: Vec<StructuredBlock>) -> StructuredBlock {
    use StructuredBlock::*;
    let is_break = |n: &StructuredBlock| matches!(n, Break) || matches!(n, Sequence(v) if v.len() == 1 && matches!(v[0], Break));
    let is_continue = |n: &StructuredBlock| matches!(n, Continue) || matches!(n, Sequence(v) if v.len() == 1 && matches!(v[0], Continue));

    // do … while: the body ends in the latch's test `if (c) break;` (or `if (c) continue;
    // break;`) and nothing else continues the loop (a `continue` in a `do … while` would
    // run the test instead of going back to the header)
    let tail = match body.as_slice() {
        [.., IfThen { condition_block, then_body, negated }] if is_break(then_body) => {
            Some((body.len() - 1, *condition_block, !*negated))
        }
        [.., IfThen { condition_block, then_body, negated }, Break] if is_continue(then_body) => {
            Some((body.len() - 2, *condition_block, *negated))
        }
        _ => None,
    };
    // while: the body starts with the header's test `if (c) break;`
    let head = match body.first() {
        Some(IfThen { condition_block, then_body, negated }) if *condition_block == h && is_break(then_body) => {
            Some(!*negated)
        }
        _ => None,
    };
    let single_block = body.len() <= 2 && tail.is_some_and(|(i, c, _)| i == 0 && c == h);
    if let (Some(neg), false) = (head, single_block) {
        body.remove(0);
        return WhileLoop { condition_block: h, body: Box::new(seq(body)), negated: neg };
    }
    if let Some((i, cond, neg)) = tail {
        let rest = &body[..i];
        if !rest.iter().any(continues_loop) {
            body.truncate(i);
            return DoWhileLoop { body: Box::new(seq(body)), condition_block: cond, negated: neg };
        }
    }
    Loop { header: h, body: Box::new(seq(body)) }
}

/// Does the node contain a `continue` for the loop it sits in (not one of a nested loop)?
fn continues_loop(n: &StructuredBlock) -> bool {
    use StructuredBlock::*;
    match n {
        Continue => true,
        Sequence(v) => v.iter().any(continues_loop),
        IfThen { then_body, .. } => continues_loop(then_body),
        IfThenElse { then_body, else_body, .. } => continues_loop(then_body) || continues_loop(else_body),
        Switch { cases, default, .. } => {
            cases.iter().any(|(_, c)| continues_loop(c)) || default.as_ref().is_some_and(|d| continues_loop(d))
        }
        ShortCircuitAnd { body, .. } | ShortCircuitOr { body, .. } => continues_loop(body),
        _ => false,
    }
}

/// Control never falls out of the end of `items` (a return, a jump, `break`, `continue`).
fn ends_flow(cfg: &ControlFlowGraph, items: &[StructuredBlock]) -> bool {
    use StructuredBlock::*;
    match items.last() {
        Some(Goto(_)) | Some(Break) | Some(Continue) => true,
        Some(Basic(b)) => cfg.blocks[*b].successors.is_empty(),
        Some(Sequence(v)) => ends_flow(cfg, v),
        Some(IfThenElse { then_body, else_body, .. }) => {
            ends_flow(cfg, std::slice::from_ref(then_body)) && ends_flow(cfg, std::slice::from_ref(else_body))
        }
        _ => false,
    }
}

fn seq(mut items: Vec<StructuredBlock>) -> StructuredBlock {
    if items.len() == 1 {
        items.pop().unwrap()
    } else {
        StructuredBlock::Sequence(items)
    }
}

fn collect_gotos(n: &StructuredBlock, out: &mut Vec<BlockId>) {
    use StructuredBlock::*;
    match n {
        Goto(t) => out.push(*t),
        Sequence(v) => v.iter().for_each(|x| collect_gotos(x, out)),
        IfThen { then_body, .. } => collect_gotos(then_body, out),
        IfThenElse { then_body, else_body, .. } => {
            collect_gotos(then_body, out);
            collect_gotos(else_body, out);
        }
        WhileLoop { body, .. }
        | DoWhileLoop { body, .. }
        | Loop { body, .. }
        | ForLoop { body, .. }
        | ShortCircuitAnd { body, .. }
        | ShortCircuitOr { body, .. } => collect_gotos(body, out),
        Switch { cases, default, .. } => {
            cases.iter().for_each(|(_, c)| collect_gotos(c, out));
            if let Some(d) = default {
                collect_gotos(d, out);
            }
        }
        Basic(_) | Break | Continue => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;
    use smallvec::SmallVec;

    fn lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction { address: addr, length: 1, mnemonic: "t".into(), ops }
    }

    fn seq(addr: u64) -> SeqNum {
        SeqNum::new(Address::new(SpaceId(1), addr), 0)
    }

    fn cbranch(addr: u64, target: u64) -> PcodeOp {
        PcodeOp {
            opcode: OpCode::CBranch,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(SpaceId(1), target, 8),
                VarnodeData::new(SpaceId(0), 1, 1),
            ]),
        }
    }

    fn branch(addr: u64, target: u64) -> PcodeOp {
        PcodeOp {
            opcode: OpCode::Branch,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), target, 8)]),
        }
    }

    fn ret(addr: u64) -> PcodeOp {
        PcodeOp {
            opcode: OpCode::Return,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(0), 0, 8)]),
        }
    }

    fn count<F: Fn(&StructuredBlock) -> bool>(node: &StructuredBlock, pred: &F) -> usize {
        let mut n = if pred(node) { 1 } else { 0 };
        match node {
            StructuredBlock::Sequence(xs) => xs.iter().for_each(|x| n += count(x, pred)),
            StructuredBlock::IfThen { then_body, .. } => n += count(then_body, pred),
            StructuredBlock::IfThenElse { then_body, else_body, .. } => {
                n += count(then_body, pred);
                n += count(else_body, pred);
            }
            StructuredBlock::WhileLoop { body, .. }
            | StructuredBlock::DoWhileLoop { body, .. }
            | StructuredBlock::Loop { body, .. }
            | StructuredBlock::ForLoop { body, .. }
            | StructuredBlock::ShortCircuitAnd { body, .. }
            | StructuredBlock::ShortCircuitOr { body, .. } => n += count(body, pred),
            StructuredBlock::Switch { cases, default, .. } => {
                for (_, b) in cases { n += count(b, pred); }
                if let Some(d) = default { n += count(d, pred); }
            }
            _ => {}
        }
        n
    }

    #[test]
    fn loop_backedge_emits_while_not_unconditional() {
        // 0x1000: cmp ; cbranch back to 0x1000 (true_target = self) else fall to 0x1002
        // 0x1001: cbranch 0x1000 -- back-edge
        // 0x1002: ret
        // Build: A (header) -> B; B cbranch -> A (back), fall -> C; C ret.
        let insns = vec![
            lifted(0x1000, vec![]),
            lifted(0x1001, vec![cbranch(0x1001, 0x1000)]),
            lifted(0x1002, vec![ret(0x1002)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        let whiles = count(&s, &|n| matches!(n, StructuredBlock::WhileLoop { .. }));
        let dos = count(&s, &|n| matches!(n, StructuredBlock::DoWhileLoop { .. }));
        let infinite = count(&s, &|n| matches!(n, StructuredBlock::Loop { .. }));
        assert!(whiles + dos >= 1,
            "loop with conditional back-edge must produce a While or DoWhile, not an unconditional Loop ({:?})", s);
        assert_eq!(infinite, 0,
            "unconditional Loop would lose the loop's exit-condition: {:?}", s);
    }

    #[test]
    fn forward_merge_emits_if_goto_not_degenerate_while() {
        // A: cbranch D else B ; B: cbranch D else C ; C: ret ; D: ret
        // When structuring B, its true-target D is already *visited* (it is the
        // join of A's diamond) but NOT on the active path — a forward merge,
        // not a loop. The old code modeled every visited branch target as a
        // `while (cond) { goto D; }` (a degenerate single-pass loop). With
        // path-tracking it must instead be `if (cond) goto D;` — an IfThen — so
        // no WhileLoop/DoWhileLoop appears anywhere in the structured form.
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1003)]),
            lifted(0x1001, vec![cbranch(0x1001, 0x1003)]),
            lifted(0x1002, vec![ret(0x1002)]),
            lifted(0x1003, vec![ret(0x1003)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        let whiles = count(&s, &|n| matches!(n, StructuredBlock::WhileLoop { .. }));
        let dos = count(&s, &|n| matches!(n, StructuredBlock::DoWhileLoop { .. }));
        let ifthens = count(&s, &|n| matches!(n, StructuredBlock::IfThen { .. }));
        assert_eq!(whiles, 0, "forward merge must not become a while: {:?}", s);
        assert_eq!(dos, 0, "forward merge must not become a do-while: {:?}", s);
        assert!(ifthens >= 1, "forward-merge branch should be an IfThen goto: {:?}", s);
    }

    #[test]
    fn diamond_shared_tail_lifted_out_of_arms() {
        // A: cbranch C else B ; B: branch D ; C: branch D ; D: ret
        // The cbranch target must differ from the fall-through, otherwise
        // both arms collapse onto the same block and no diamond exists.
        // We point cbranch at 0x1002 (C); fall-through is 0x1001 (B).
        // Both arms join at D; previously D was consumed in the then-arm and
        // the else-arm `Goto`'d into it, falling through on emit. Verify
        // the structured form lifts D out as a join after the IfThenElse.
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1002)]),
            lifted(0x1001, vec![branch(0x1001, 0x1003)]),
            lifted(0x1002, vec![branch(0x1002, 0x1003)]),
            lifted(0x1003, vec![ret(0x1003)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        // After the fix the IfThenElse is wrapped in a Sequence whose tail
        // contains the join block; before the fix, D was inside one arm and
        // the other arm was a bare Goto.
        let if_count = count(&s, &|n| matches!(n, StructuredBlock::IfThenElse { .. }));
        assert_eq!(if_count, 1, "expected exactly one IfThenElse, got {:?}", s);
        // Whichever arm is structured "first" must not contain a Basic for
        // block D twice (one in arm, one in tail) — emit would duplicate it.
        // Verify the structured form mentions block 3 (D) at most once via
        // Basic counting. (Goto references are allowed.)
        fn count_basic(node: &StructuredBlock, target: BlockId) -> usize {
            match node {
                StructuredBlock::Basic(b) if *b == target => 1,
                StructuredBlock::Sequence(xs) => xs.iter().map(|x| count_basic(x, target)).sum(),
                StructuredBlock::IfThen { then_body, .. } => count_basic(then_body, target),
                StructuredBlock::IfThenElse { then_body, else_body, .. } => {
                    count_basic(then_body, target) + count_basic(else_body, target)
                }
                StructuredBlock::WhileLoop { body, .. }
                | StructuredBlock::DoWhileLoop { body, .. }
                | StructuredBlock::Loop { body, .. } => count_basic(body, target),
                _ => 0,
            }
        }
        // D is block 3 (after A=0, B=1, C=2).
        assert!(count_basic(&s, 3) <= 1,
            "join block D must appear in at most one place: {:?}", s);
    }

    #[test]
    fn multi_successor_no_inline_fallthrough() {
        // A: an indirect jump whose CFG-modelled successors are B and C.
        // Without dedicated switch recovery the previous code structured the
        // first un-visited successor inline (B's body fell through into the
        // goto stubs for C). Verify the 3+-succ arm now emits goto stubs for
        // every successor, with no recursive structuring of a successor body.
        //
        // Construct by hand: make a fake jump-table CFG by directly building a
        // ControlFlowGraph wrapper isn't accessible; emulate with two Branches
        // chained through an "indirect-jump-like" pattern that the CFG builder
        // resolves into multiple successors via fallthrough leaders.
        // (BranchInd terminates the block but leaves no successor, so use
        // multiple distinct Branch ops in one instruction's op list — the CFG
        // collects each Branch's target as a leader.)
        let insns = vec![
            lifted(0x1000, vec![
                cbranch(0x1000, 0x1001),
                branch(0x1000, 0x1002),
            ]),
            lifted(0x1001, vec![ret(0x1001)]),
            lifted(0x1002, vec![ret(0x1002)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        // We don't assert specifics about whether the CFG recognises this as
        // 3+ successors (it depends on builder details), but we do guarantee
        // the routine doesn't panic or infinitely recurse.
        let _ = structure_cfg(&cfg);
    }

    /// WS81: a shared tail that ends in a call that never returns is copied like a `ret` tail.
    #[test]
    fn goto_to_short_noreturn_tail_is_copied() {
        let call = |addr: u64| PcodeOp {
            opcode: OpCode::Call,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), 0x5000, 8)]),
        };
        let mark = |addr: u64| PcodeOp {
            opcode: OpCode::CallOther,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId::CONST, reargo_core::pcode::intrinsic::NORETURN, 4)]),
        };
        // E: jcc T ; B: nop ; C: jcc T ; D: ret ; T: call abort (never returns)
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1004)]),
            nop(0x1001),
            lifted(0x1002, vec![cbranch(0x1002, 0x1004)]),
            lifted(0x1003, vec![ret(0x1003)]),
            lifted(0x1004, vec![call(0x1004), mark(0x1004)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let t = cfg.block_at(0x1004).unwrap().id;
        let s = structure_cfg(&cfg);
        assert_eq!(gotos(&s), 0, "{s:?}");
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::Basic(b) if *b == t)), 2, "{s:?}");
    }

    /// WS81: a short shared block with one call (`memcpy(…)` set up and called in both arms)
    /// is copied too.
    #[test]
    fn short_shared_block_with_a_call_is_copied() {
        // A: jcc L ; X: nop ; B: jcc L ; Y: jmp J ; L: nop ; call g ; J: call ; ret
        let call = |addr: u64, target: u64| PcodeOp {
            opcode: OpCode::Call,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), target, 8)]),
        };
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1005)]),
            nop(0x1001),
            lifted(0x1002, vec![cbranch(0x1002, 0x1005)]),
            nop(0x1003),
            lifted(0x1004, vec![branch(0x1004, 0x1007)]),
            nop(0x1005),
            lifted(0x1006, vec![call(0x1006, 0x3000)]),
            lifted(0x1007, vec![call(0x1007, 0x2000)]),
            lifted(0x1008, vec![ret(0x1008)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        assert_eq!(gotos(&s), 0, "{s:?}");
    }

    /// WS81: a test whose fall-through is a short "next iteration" region already printed
    /// (`n = n->next; if (!n) break; continue;`) prints the region again instead of a `goto`.
    #[test]
    fn jump_to_short_loop_step_is_copied() {
        // H: nop ; P: jcc N ; Q: jcc R ; N: nop ; jcc H ; E: ret ; R: ret
        let insns = vec![
            nop(0x1000),
            lifted(0x1001, vec![cbranch(0x1001, 0x1003)]),
            lifted(0x1002, vec![cbranch(0x1002, 0x1006)]),
            nop(0x1003),
            lifted(0x1004, vec![cbranch(0x1004, 0x1000)]),
            lifted(0x1005, vec![ret(0x1005)]),
            lifted(0x1006, vec![ret(0x1006)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        assert_eq!(gotos(&s), 0, "{s:?}");
    }

    fn nop(addr: u64) -> LiftedInstruction {
        lifted(addr, vec![])
    }

    fn gotos(s: &StructuredBlock) -> usize {
        count(s, &|n| matches!(n, StructuredBlock::Goto(_)))
    }

    fn empty_arms(s: &StructuredBlock) -> usize {
        let empty = |b: &StructuredBlock| matches!(b, StructuredBlock::Sequence(v) if v.is_empty());
        count(s, &|n| match n {
            StructuredBlock::IfThen { then_body, .. } => empty(then_body),
            StructuredBlock::IfThenElse { then_body, else_body, .. } => empty(then_body) || empty(else_body),
            _ => false,
        })
    }

    fn top_level(s: &StructuredBlock) -> Vec<&StructuredBlock> {
        match s {
            StructuredBlock::Sequence(v) => v.iter().collect(),
            n => vec![n],
        }
    }

    #[test]
    fn if_join_is_post_dominator_not_lowest_shared_block() {
        // A: jcc C ; B: jcc X else fall to J?  Layout:
        // 0x1000 A: cbranch C(0x1003)        fall B
        // 0x1001 B: cbranch J(0x1005)        fall X
        // 0x1002 X: branch J... (X is shared by B and C but does not post-dominate A)
        // 0x1003 C: branch X
        // 0x1004 (dead)
        // 0x1005 J: ret
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1003)]),
            lifted(0x1001, vec![cbranch(0x1001, 0x1005)]),
            lifted(0x1002, vec![branch(0x1002, 0x1005)]),
            lifted(0x1003, vec![branch(0x1003, 0x1002)]),
            lifted(0x1005, vec![ret(0x1005)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let j = cfg.block_at(0x1005).unwrap().id;
        let s = structure_cfg(&cfg);
        // the join J is printed once, after the if, not inside an arm
        let top = top_level(&s);
        assert!(matches!(top.last(), Some(StructuredBlock::Basic(b)) if *b == j), "{s:?}");
        assert_eq!(empty_arms(&s), 0, "{s:?}");
    }

    #[test]
    fn goto_to_short_return_tail_is_copied() {
        // E: jcc R ; B: nop ; C: jcc R ; D: ret ; R: ret  — R is reached from E and C
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1004)]),
            nop(0x1001),
            lifted(0x1002, vec![cbranch(0x1002, 0x1004)]),
            lifted(0x1003, vec![ret(0x1003)]),
            lifted(0x1004, vec![ret(0x1004)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let r = cfg.block_at(0x1004).unwrap().id;
        let s = structure_cfg(&cfg);
        assert_eq!(gotos(&s), 0, "{s:?}");
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::Basic(b) if *b == r)), 2, "{s:?}");
    }

    #[test]
    fn empty_then_arm_becomes_negated_if() {
        // A: jcc J ; B: nop ; J: ret  — `if (c) {} else { B }` before
        let insns = vec![lifted(0x1000, vec![cbranch(0x1000, 0x1002)]), nop(0x1001), lifted(0x1002, vec![ret(0x1002)])];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        assert_eq!(empty_arms(&s), 0, "{s:?}");
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::IfThen { negated: true, .. })), 1, "{s:?}");
        assert_eq!(gotos(&s), 0, "{s:?}");
    }

    #[test]
    fn top_tested_loop_is_while_without_goto() {
        // E: nop ; H: jcc X ; B: nop ; jmp H ; X: ret
        let insns = vec![
            nop(0x1000),
            lifted(0x1001, vec![cbranch(0x1001, 0x1004)]),
            nop(0x1002),
            lifted(0x1003, vec![branch(0x1003, 0x1001)]),
            lifted(0x1004, vec![ret(0x1004)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::WhileLoop { .. })), 1, "{s:?}");
        assert_eq!(gotos(&s), 0, "{s:?}");
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::Break | StructuredBlock::Continue)), 0, "{s:?}");
    }

    #[test]
    fn bottom_tested_loop_is_do_while_without_goto() {
        // E: nop ; B: nop ; L: jcc B ; X: ret   (`while (c) { goto B; }` before)
        let insns = vec![
            nop(0x1000),
            nop(0x1001),
            lifted(0x1002, vec![cbranch(0x1002, 0x1001)]),
            lifted(0x1003, vec![ret(0x1003)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::DoWhileLoop { negated: false, .. })), 1, "{s:?}");
        assert_eq!(gotos(&s), 0, "{s:?}");
    }

    #[test]
    fn early_exit_from_loop_is_break() {
        // H: jcc X ; B1: jcc X (break) ; B2: jmp H ; X: ret
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1003)]),
            lifted(0x1001, vec![cbranch(0x1001, 0x1003)]),
            lifted(0x1002, vec![branch(0x1002, 0x1000)]),
            lifted(0x1003, vec![ret(0x1003)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        assert_eq!(gotos(&s), 0, "{s:?}");
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::Break)), 1, "{s:?}");
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::WhileLoop { .. })), 1, "{s:?}");
    }

    #[test]
    fn every_reachable_block_printed_once() {
        // irreducible: E: jcc L2 ; L1: nop ; L2: jcc L1 ; ret
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1002)]),
            nop(0x1001),
            lifted(0x1002, vec![cbranch(0x1002, 0x1001)]),
            lifted(0x1003, vec![ret(0x1003)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        fn printed(n: &StructuredBlock, out: &mut Vec<BlockId>) {
            use StructuredBlock::*;
            match n {
                Basic(b) => out.push(*b),
                Sequence(v) => v.iter().for_each(|x| printed(x, out)),
                IfThen { condition_block, then_body, .. } => {
                    out.push(*condition_block);
                    printed(then_body, out);
                }
                IfThenElse { condition_block, then_body, else_body } => {
                    out.push(*condition_block);
                    printed(then_body, out);
                    printed(else_body, out);
                }
                WhileLoop { condition_block, body, .. } | DoWhileLoop { condition_block, body, .. } => {
                    out.push(*condition_block);
                    printed(body, out);
                }
                Loop { body, .. } => printed(body, out),
                _ => {}
            }
        }
        let mut v = Vec::new();
        printed(&s, &mut v);
        v.sort();
        assert_eq!(v, (0..cfg.blocks.len()).collect::<Vec<_>>(), "{s:?}");
        assert!(gotos(&s) >= 1, "irreducible flow needs a goto: {s:?}");
    }

    #[test]
    fn epilogue_does_not_count_against_the_return_tail() {
        // E: jcc R ; B: nop ; C: jcc R ; D: ret ; R: nop + six pops + ret — R is reached from
        // E and C, copied in place of the `goto` although it has 8 instructions
        let named = |addr: u64, m: &str, ops: Vec<PcodeOp>| LiftedInstruction { address: addr, length: 1, mnemonic: m.into(), ops };
        let mut insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1004)]),
            nop(0x1001),
            lifted(0x1002, vec![cbranch(0x1002, 0x1004)]),
            lifted(0x1003, vec![ret(0x1003)]),
            nop(0x1004),
        ];
        for (i, r) in ["rbx", "rbp", "r12", "r13", "r14", "r15"].iter().enumerate() {
            insns.push(named(0x1005 + i as u64, &format!("pop {r}"), vec![]));
        }
        insns.push(named(0x100b, "ret", vec![ret(0x100b)]));
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        assert_eq!(gotos(&s), 0, "{s:?}");
    }


    #[test]
    fn short_shared_block_is_copied_instead_of_goto() {
        // A: jcc L ; X: nop ; B: jcc L ; Y: jmp J ; L: nop nop ; J: call ; ret
        // L is shared by A's then-arm and B (in A's else-arm) and falls into the join J
        let call = PcodeOp {
            opcode: OpCode::Call,
            seq: seq(0x1007),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), 0x2000, 8)]),
        };
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1005)]),
            nop(0x1001),
            lifted(0x1002, vec![cbranch(0x1002, 0x1005)]),
            nop(0x1003),
            lifted(0x1004, vec![branch(0x1004, 0x1007)]),
            nop(0x1005),
            nop(0x1006),
            lifted(0x1007, vec![call]),
            lifted(0x1008, vec![ret(0x1008)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let l = cfg.block_at(0x1005).unwrap().id;
        let s = structure_cfg(&cfg);
        assert_eq!(gotos(&s), 0, "{s:?}");
        assert_eq!(count(&s, &|n| matches!(n, StructuredBlock::Basic(b) if *b == l)), 2, "{s:?}");
    }


    #[test]
    fn shared_test_that_breaks_or_continues_is_copied() {
        // loop: H: jcc X ; A: jcc S ; B: nop ; C: jcc S ; D: jmp H ;
        //       S: nop ; T: jcc X ; U: jmp H ;  X: call ; ret
        // S..T is shared by A and C; its ways out are `break` (X) and `continue` (H)
        let call = PcodeOp {
            opcode: OpCode::Call,
            seq: seq(0x1008),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), 0x2000, 8)]),
        };
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1008)]),
            lifted(0x1001, vec![cbranch(0x1001, 0x1005)]),
            nop(0x1002),
            lifted(0x1003, vec![cbranch(0x1003, 0x1005)]),
            lifted(0x1004, vec![branch(0x1004, 0x1000)]),
            nop(0x1005),
            lifted(0x1006, vec![cbranch(0x1006, 0x1008)]),
            lifted(0x1007, vec![branch(0x1007, 0x1000)]),
            lifted(0x1008, vec![call]),
            lifted(0x1009, vec![ret(0x1009)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        assert_eq!(gotos(&s), 0, "{s:?}");
    }

}
