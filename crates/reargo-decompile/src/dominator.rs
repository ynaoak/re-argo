//! Dominator tree and dominance frontiers.
//!
//! `compute_idom` is the Cooper–Harvey–Kennedy iterative algorithm ("A Simple,
//! Fast Dominance Algorithm", 2001) run over a reverse post-order of the
//! blocks reachable from the entry. Block ids are address order, which is not
//! a topological order once a loop's header sits after its body
//! (`jmp cond; body: ..; cond: cmp; jl body`); intersecting by block id (the
//! earlier version) then climbs past the real common dominator. Here the
//! `intersect` walk compares RPO numbers, which is what the algorithm needs.
//! Blocks not reachable from the entry get `None`.

use crate::cfg::{BlockId, ControlFlowGraph};

/// Reverse post-order of the blocks reachable from the entry.
pub fn reverse_post_order(cfg: &ControlFlowGraph) -> Vec<BlockId> {
    let n = cfg.blocks.len();
    if n == 0 {
        return Vec::new();
    }
    let mut seen = vec![false; n];
    let mut post: Vec<BlockId> = Vec::with_capacity(n);
    // explicit DFS: (block, index of the next successor to visit)
    let mut stack: Vec<(BlockId, usize)> = vec![(cfg.entry_block, 0)];
    seen[cfg.entry_block] = true;
    while let Some(top) = stack.last_mut() {
        let (b, i) = *top;
        if let Some(&s) = cfg.blocks[b].successors.get(i) {
            top.1 += 1;
            if s < n && !seen[s] {
                seen[s] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(b);
            stack.pop();
        }
    }
    post.reverse();
    post
}

/// Immediate dominators: `idom[entry] == Some(entry)`, `None` for blocks the
/// entry does not reach.
pub fn compute_idom(cfg: &ControlFlowGraph) -> Vec<Option<BlockId>> {
    let n = cfg.blocks.len();
    if n == 0 {
        return Vec::new();
    }
    let entry = cfg.entry_block;
    let rpo = reverse_post_order(cfg);
    let mut order = vec![usize::MAX; n]; // block -> RPO number
    for (i, &b) in rpo.iter().enumerate() {
        order[b] = i;
    }
    let mut idom: Vec<Option<BlockId>> = vec![None; n];
    idom[entry] = Some(entry);

    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter().skip(1) {
            let mut new_idom: Option<BlockId> = None;
            for &p in &cfg.blocks[b].predecessors {
                if idom[p].is_none() {
                    continue; // unreachable, or not processed yet
                }
                new_idom = Some(match new_idom {
                    None => p,
                    Some(cur) => intersect(&idom, &order, cur, p),
                });
            }
            if new_idom.is_some() && new_idom != idom[b] {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    idom
}

/// Immediate dominators over the entry and every block without predecessors (an exception
/// landing pad, reached only by unwinding) as the roots of one forest (WS82): a virtual root
/// precedes them all. A root, and a block two roots both reach first (a cleanup tail shared
/// by two landing pads), is its own `idom`; `None` for blocks no root reaches. SSA renames
/// along this forest, so a value set in a landing pad reaches the code after it.
pub fn compute_idom_forest(cfg: &ControlFlowGraph) -> Vec<Option<BlockId>> {
    let n = cfg.blocks.len();
    if n == 0 {
        return Vec::new();
    }
    let v = n; // the virtual root
    let mut roots = vec![cfg.entry_block];
    roots.extend((0..n).filter(|&b| b != cfg.entry_block && cfg.blocks[b].predecessors.is_empty()));
    if roots.len() == 1 {
        return compute_idom(cfg);
    }
    let succs = |b: usize| -> &[BlockId] { if b == v { &roots } else { &cfg.blocks[b].successors } };
    // reverse post-order from the virtual root
    let mut seen = vec![false; n + 1];
    let mut post: Vec<BlockId> = Vec::with_capacity(n + 1);
    let mut stack: Vec<(BlockId, usize)> = vec![(v, 0)];
    seen[v] = true;
    while let Some(top) = stack.last_mut() {
        let (b, i) = *top;
        if let Some(&s) = succs(b).get(i) {
            top.1 += 1;
            if s < n && !seen[s] {
                seen[s] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(b);
            stack.pop();
        }
    }
    post.reverse();
    let mut order = vec![usize::MAX; n + 1];
    for (i, &b) in post.iter().enumerate() {
        order[b] = i;
    }
    let mut idom: Vec<Option<BlockId>> = vec![None; n + 1];
    idom[v] = Some(v);
    let is_root: Vec<bool> = (0..n).map(|b| roots.contains(&b)).collect();
    let mut changed = true;
    while changed {
        changed = false;
        for &b in post.iter().skip(1) {
            let mut new_idom: Option<BlockId> = is_root[b].then_some(v);
            for &p in &cfg.blocks[b].predecessors {
                if idom[p].is_none() {
                    continue;
                }
                new_idom = Some(match new_idom {
                    None => p,
                    Some(cur) => intersect(&idom, &order, cur, p),
                });
            }
            if new_idom.is_some() && new_idom != idom[b] {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    idom.truncate(n);
    idom.iter().enumerate().map(|(b, d)| d.map(|d| if d == v { b } else { d })).collect()
}

fn intersect(idom: &[Option<BlockId>], order: &[usize], mut a: BlockId, mut b: BlockId) -> BlockId {
    while a != b {
        while order[a] > order[b] {
            a = idom[a].expect("processed block has an idom");
        }
        while order[b] > order[a] {
            b = idom[b].expect("processed block has an idom");
        }
    }
    a
}

/// Does `a` dominate `b` (reflexively)? `false` when `b` is unreachable.
pub fn dominates(idom: &[Option<BlockId>], a: BlockId, mut b: BlockId) -> bool {
    loop {
        if a == b {
            return true;
        }
        match idom.get(b) {
            Some(&Some(p)) if p != b => b = p,
            _ => return false,
        }
    }
}

/// Dominance frontiers (Cooper–Harvey–Kennedy). Only reachable blocks take
/// part. The entry is never put in a frontier: SSA construction has no input
/// slot for the value a φ at the entry would receive from the caller.
pub fn compute_dominance_frontier(cfg: &ControlFlowGraph, idom: &[Option<BlockId>]) -> Vec<Vec<BlockId>> {
    let n = cfg.blocks.len();
    let mut df_sets: Vec<std::collections::BTreeSet<BlockId>> = vec![std::collections::BTreeSet::new(); n];

    for b in 0..n {
        if b == cfg.entry_block {
            continue;
        }
        let Some(stop) = idom[b] else { continue };
        let preds: Vec<BlockId> = cfg.blocks[b].predecessors.iter().copied().filter(|&p| idom[p].is_some()).collect();
        if preds.len() < 2 {
            continue;
        }
        for p in preds {
            let mut runner = p;
            while runner != stop {
                df_sets[runner].insert(b);
                match idom[runner] {
                    Some(up) if up != runner => runner = up,
                    _ => break, // reached the entry
                }
            }
        }
    }
    df_sets.into_iter().map(|s| s.into_iter().collect()).collect()
}

/// Immediate post-dominators over the blocks reachable from the entry, computed as the
/// dominator tree of the reversed CFG rooted at a *virtual exit*.
///
/// Every block without successors (a `ret`, a `jmp reg`, a block that falls off the lifted
/// body, a call the lifter ended the block at) gets an edge to the virtual exit, so a function
/// with several returns still has one root. A region that cannot reach any exit (an infinite
/// loop, or a loop whose only way out is a `noreturn` call that still has a fall-through edge
/// back in) would otherwise be missing from the tree: the deepest block (highest reverse
/// post-order number) of such a region gets an edge to the exit too, repeated until every
/// reachable block reaches it.
///
/// `ipdom[b]` is `None` when `b`'s immediate post-dominator is the virtual exit (or `b` is
/// unreachable from the entry).
#[derive(Debug, Clone)]
pub struct PostDominators {
    /// `Some(p)`: `p` is the immediate post-dominator of the block. `None`: the virtual exit.
    pub ipdom: Vec<Option<BlockId>>,
    /// Reachable from the entry (blocks that are not take no part).
    pub reachable: Vec<bool>,
}

impl PostDominators {
    /// Does `a` post-dominate `b` (reflexively)?
    pub fn post_dominates(&self, a: BlockId, mut b: BlockId) -> bool {
        loop {
            if a == b {
                return true;
            }
            match self.ipdom.get(b) {
                Some(&Some(p)) if p != b => b = p,
                _ => return false,
            }
        }
    }
}

pub fn compute_post_dominators(cfg: &ControlFlowGraph) -> PostDominators {
    let n = cfg.blocks.len();
    let exit = n; // virtual node
    let rpo = reverse_post_order(cfg);
    let mut reachable = vec![false; n];
    for &b in &rpo {
        reachable[b] = true;
    }
    // reverse-graph successors of a node = CFG predecessors (restricted to reachable blocks);
    // the virtual exit's reverse successors are the blocks wired to it
    let mut to_exit: Vec<BlockId> = rpo
        .iter()
        .copied()
        .filter(|&b| cfg.blocks[b].successors.iter().all(|&s| s >= n))
        .collect();

    // make every reachable block reach the exit (infinite loops)
    let reaches_exit = |to_exit: &[BlockId]| {
        let mut seen = vec![false; n];
        let mut stack: Vec<BlockId> = to_exit.to_vec();
        for &b in to_exit {
            seen[b] = true;
        }
        while let Some(b) = stack.pop() {
            for &p in &cfg.blocks[b].predecessors {
                if p < n && reachable[p] && !seen[p] {
                    seen[p] = true;
                    stack.push(p);
                }
            }
        }
        seen
    };
    let mut seen = reaches_exit(&to_exit);
    while let Some(&deepest) = rpo.iter().rev().find(|&&b| !seen[b]) {
        to_exit.push(deepest);
        // incremental: everything that reaches `deepest` now reaches the exit
        let mut stack = vec![deepest];
        seen[deepest] = true;
        while let Some(b) = stack.pop() {
            for &p in &cfg.blocks[b].predecessors {
                if p < n && reachable[p] && !seen[p] {
                    seen[p] = true;
                    stack.push(p);
                }
            }
        }
    }

    // reverse post-order of the reversed graph from the virtual exit
    let rsucc = |v: usize| -> &[BlockId] {
        if v == exit { &to_exit } else { &cfg.blocks[v].predecessors }
    };
    let mut order = vec![usize::MAX; n + 1];
    let mut post: Vec<usize> = Vec::with_capacity(n + 1);
    let mut visited = vec![false; n + 1];
    let mut stack: Vec<(usize, usize)> = vec![(exit, 0)];
    visited[exit] = true;
    while let Some(top) = stack.last_mut() {
        let (v, i) = *top;
        let succs = rsucc(v);
        if let Some(&s) = succs.get(i) {
            top.1 += 1;
            if s < n && reachable[s] && !visited[s] {
                visited[s] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(v);
            stack.pop();
        }
    }
    post.reverse();
    for (i, &v) in post.iter().enumerate() {
        order[v] = i;
    }
    // reverse-graph predecessors of v = CFG successors of v (+ exit when wired)
    let mut wired = vec![false; n];
    for &b in &to_exit {
        wired[b] = true;
    }
    let mut idom: Vec<Option<usize>> = vec![None; n + 1];
    idom[exit] = Some(exit);
    let mut changed = true;
    while changed {
        changed = false;
        for &v in post.iter().skip(1) {
            let mut new_idom: Option<usize> = None;
            let preds = cfg.blocks[v]
                .successors
                .iter()
                .copied()
                .filter(|&s| s < n)
                .chain(wired[v].then_some(exit));
            for p in preds {
                if idom[p].is_none() {
                    continue;
                }
                new_idom = Some(match new_idom {
                    None => p,
                    Some(cur) => intersect(&idom, &order, cur, p),
                });
            }
            if new_idom.is_some() && new_idom != idom[v] {
                idom[v] = new_idom;
                changed = true;
            }
        }
    }
    let ipdom = (0..n)
        .map(|b| match idom[b] {
            Some(p) if p != exit => Some(p),
            _ => None,
        })
        .collect();
    PostDominators { ipdom, reachable }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;
    use smallvec::SmallVec;

    fn nop_insn(addr: u64) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "nop".into(),
            ops: vec![],
        }
    }

    fn ret_insn(addr: u64) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "ret".into(),
            ops: vec![PcodeOp {
                opcode: OpCode::Return,
                seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
                output: None,
                inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(0), 0, 8)]),
            }],
        }
    }

    #[test]
    fn idom_linear() {
        let insns = vec![nop_insn(0x1000), nop_insn(0x1001), ret_insn(0x1002)];
        let cfg = ControlFlowGraph::build(&insns);
        let idom = compute_idom(&cfg);
        assert_eq!(idom[cfg.entry_block], Some(cfg.entry_block));
    }

    #[test]
    fn dominance_frontier_basic() {
        let insns = vec![nop_insn(0x1000), ret_insn(0x1001)];
        let cfg = ControlFlowGraph::build(&insns);
        let idom = compute_idom(&cfg);
        let df = compute_dominance_frontier(&cfg, &idom);
        assert_eq!(df.len(), cfg.blocks.len());
    }

    fn jmp_insn(addr: u64, target: u64) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "jmp".into(),
            ops: vec![PcodeOp {
                opcode: OpCode::Branch,
                seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
                output: None,
                inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), target, 8)]),
            }],
        }
    }

    fn jcc_insn(addr: u64, target: u64) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "jcc".into(),
            ops: vec![PcodeOp {
                opcode: OpCode::CBranch,
                seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
                output: None,
                inputs: SmallVec::from_slice(&[
                    VarnodeData::new(SpaceId(1), target, 8),
                    VarnodeData::new(SpaceId(0), 1, 1),
                ]),
            }],
        }
    }

    /// `jmp cond; body: jcc out; cond: jcc body; out: ret` — the loop header sits after
    /// its body, so block-id order is not a topological order. `out` is reached from the
    /// header and from the body (a `break`), so its idom is the header, not the entry.
    fn bottom_tested_loop() -> ControlFlowGraph {
        let insns = vec![
            jmp_insn(0x1000, 0x1003),  // B0 entry
            nop_insn(0x1001),          // B1 body
            jcc_insn(0x1002, 0x1005),  //    break -> out, else fall into the header
            nop_insn(0x1003),          // B2 header
            jcc_insn(0x1004, 0x1001),  //    -> body, else fall out
            ret_insn(0x1005),          // B3 out
        ];
        ControlFlowGraph::build(&insns)
    }

    /// Reference: idom from the (slow, set-based) `ControlFlowGraph::dominators`.
    fn reference_idom(cfg: &ControlFlowGraph, b: BlockId) -> BlockId {
        let doms = cfg.dominators();
        if b == cfg.entry_block {
            return b;
        }
        *doms[b]
            .iter()
            .filter(|&&d| d != b)
            .max_by_key(|&&d| doms[d].len())
            .unwrap()
    }

    #[test]
    fn idom_bottom_tested_loop_matches_reference() {
        let cfg = bottom_tested_loop();
        let at = |a: u64| cfg.block_at(a).unwrap().id;
        let (b0, b1, b2, b3) = (at(0x1000), at(0x1001), at(0x1003), at(0x1005));
        let idom = compute_idom(&cfg);
        assert_eq!(idom[b1], Some(b2));
        assert_eq!(idom[b2], Some(b0));
        assert_eq!(idom[b3], Some(b2), "the loop exit is dominated by the header");
        for (b, d) in idom.iter().enumerate() {
            assert_eq!(*d, Some(reference_idom(&cfg, b)), "block {b}");
        }
    }

    #[test]
    fn dominance_frontier_bottom_tested_loop() {
        let cfg = bottom_tested_loop();
        let at = |a: u64| cfg.block_at(a).unwrap().id;
        let (b1, b2, b3) = (at(0x1001), at(0x1003), at(0x1005));
        let idom = compute_idom(&cfg);
        let df = compute_dominance_frontier(&cfg, &idom);
        // body: both the header (back edge) and the exit (break) are in its frontier
        assert_eq!(df[b1], vec![b2.min(b3), b2.max(b3)]);
        // the header dominates the exit, so the exit is not in the header's frontier;
        // the header is in its own frontier (loop)
        assert_eq!(df[b2], vec![b2]);
        assert!(df[b3].is_empty());
    }

    #[test]
    fn unreachable_block_has_no_idom() {
        // B0: jmp 0x1002; B1 (dead): nop; B2: ret
        let insns = vec![jmp_insn(0x1000, 0x1002), nop_insn(0x1001), ret_insn(0x1002)];
        let cfg = ControlFlowGraph::build(&insns);
        let idom = compute_idom(&cfg);
        let dead = cfg.block_at(0x1001).unwrap().id;
        let live = cfg.block_at(0x1002).unwrap().id;
        assert_eq!(idom[dead], None);
        assert_eq!(idom[live], Some(cfg.entry_block));
    }
    /// Two landing pads (no predecessors) sharing a cleanup tail (WS82): each pad is a root
    /// of the forest and the tail, reached first from both, is its own; a register a pad
    /// sets reaches the tail through a phi instead of reading the function's input.
    #[test]
    fn landing_pads_are_roots_of_the_dominator_forest() {
        let reg = |off| VarnodeData::new(SpaceId(2), off, 8);
        let copy = |addr: u64, dst: u64, src: u64| LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "mov".into(),
            ops: vec![PcodeOp {
                opcode: OpCode::Copy,
                seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
                output: Some(reg(dst)),
                inputs: SmallVec::from_slice(&[reg(src)]),
            }],
        };
        let insns = vec![
            ret_insn(0x1000),
            copy(0x1001, 0x60, 0x00), // pad 1: mov r12, rax
            jmp_insn(0x1002, 0x1005),
            copy(0x1003, 0x60, 0x00), // pad 2: mov r12, rax
            jmp_insn(0x1004, 0x1005),
            copy(0x1005, 0x38, 0x60), // tail: mov rdi, r12
            ret_insn(0x1006),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let at = |a: u64| cfg.block_at(a).unwrap().id;
        let plain = compute_idom(&cfg);
        assert_eq!(plain[at(0x1005)], None);
        let idom = compute_idom_forest(&cfg);
        assert_eq!(idom[at(0x1000)], Some(at(0x1000)));
        assert_eq!(idom[at(0x1001)], Some(at(0x1001)));
        assert_eq!(idom[at(0x1003)], Some(at(0x1003)));
        assert_eq!(idom[at(0x1005)], Some(at(0x1005)), "reached first from both pads");
        let ssa = crate::ssa::SsaFunction::from_cfg("f".into(), 0x1000, cfg);
        let read = ssa.ops.iter().find(|o| o.address == 0x1005 && o.opcode == OpCode::Copy).unwrap();
        let r12 = &ssa.varnodes[read.inputs[0] as usize];
        let def = r12.def_op.map(|d| ssa.ops[d].opcode);
        assert_eq!(def, Some(OpCode::MultiEqual), "the tail reads the pads' r12: {}", ssa.display_ssa());
    }
}

#[cfg(test)]
mod post_dom_tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;
    use smallvec::SmallVec;

    fn insn(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction { address: addr, length: 1, mnemonic: "t".into(), ops }
    }
    fn op(addr: u64, opcode: OpCode, inputs: &[VarnodeData]) -> PcodeOp {
        PcodeOp {
            opcode,
            seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
            output: None,
            inputs: SmallVec::from_slice(inputs),
        }
    }
    fn jcc(a: u64, t: u64) -> LiftedInstruction {
        insn(a, vec![op(a, OpCode::CBranch, &[VarnodeData::new(SpaceId(1), t, 8), VarnodeData::new(SpaceId(0), 1, 1)])])
    }
    fn jmp(a: u64, t: u64) -> LiftedInstruction {
        insn(a, vec![op(a, OpCode::Branch, &[VarnodeData::new(SpaceId(1), t, 8)])])
    }
    fn ret(a: u64) -> LiftedInstruction {
        insn(a, vec![op(a, OpCode::Return, &[VarnodeData::new(SpaceId(0), 0, 8)])])
    }
    fn nop(a: u64) -> LiftedInstruction {
        insn(a, vec![])
    }

    #[test]
    fn diamond_join_is_ipdom_not_lowest_id() {
        // B0: jcc B2 ; B1: jmp B3 ; B2: nop (falls into B3) ; B3: ret
        let cfg = ControlFlowGraph::build(&[jcc(0x1000, 0x1002), jmp(0x1001, 0x1003), nop(0x1002), ret(0x1003)]);
        let at = |a: u64| cfg.block_at(a).unwrap().id;
        let pd = compute_post_dominators(&cfg);
        assert_eq!(pd.ipdom[at(0x1000)], Some(at(0x1003)));
        assert_eq!(pd.ipdom[at(0x1001)], Some(at(0x1003)));
        assert_eq!(pd.ipdom[at(0x1002)], Some(at(0x1003)));
        assert_eq!(pd.ipdom[at(0x1003)], None, "the return's ipdom is the virtual exit");
    }

    #[test]
    fn two_returns_meet_at_virtual_exit() {
        // B0: jcc B2 ; B1: ret ; B2: ret
        let cfg = ControlFlowGraph::build(&[jcc(0x1000, 0x1002), ret(0x1001), ret(0x1002)]);
        let pd = compute_post_dominators(&cfg);
        assert_eq!(pd.ipdom[cfg.entry_block], None);
    }

    #[test]
    fn loop_exit_post_dominates_header() {
        // B0: nop ; B1 header: jcc B3 (exit) ; B2 body: jmp B1 ; B3: ret
        let cfg = ControlFlowGraph::build(&[nop(0x1000), jcc(0x1001, 0x1003), jmp(0x1002, 0x1001), ret(0x1003)]);
        let at = |a: u64| cfg.block_at(a).unwrap().id;
        let pd = compute_post_dominators(&cfg);
        assert_eq!(pd.ipdom[at(0x1001)], Some(at(0x1003)));
        assert_eq!(pd.ipdom[at(0x1002)], Some(at(0x1001)));
        assert!(pd.post_dominates(at(0x1003), at(0x1000)));
    }

    #[test]
    fn infinite_loop_still_in_tree() {
        // B0: jcc B2 ; B1: ret ; B2: nop ; B3: jmp B2 (no way out)
        let cfg = ControlFlowGraph::build(&[jcc(0x1000, 0x1002), ret(0x1001), nop(0x1002), jmp(0x1003, 0x1002)]);
        let at = |a: u64| cfg.block_at(a).unwrap().id;
        let pd = compute_post_dominators(&cfg);
        assert!(pd.reachable.iter().all(|&r| r));
        // the loop is wired to the exit at its deepest block, so the entry's ipdom is the exit
        assert_eq!(pd.ipdom[cfg.entry_block], None);
        assert_eq!(pd.ipdom[at(0x1002)], None, "the self-loop block is wired to the exit");
    }
}
