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
}
