use crate::cfg::{BlockId, ControlFlowGraph};

pub fn compute_idom(cfg: &ControlFlowGraph) -> Vec<Option<BlockId>> {
    let n = cfg.blocks.len();
    if n == 0 {
        return Vec::new();
    }
    let entry = cfg.entry_block;
    let mut idom: Vec<Option<BlockId>> = vec![None; n];
    idom[entry] = Some(entry);

    let mut changed = true;
    while changed {
        changed = false;
        for b in 0..n {
            if b == entry {
                continue;
            }
            let preds = &cfg.blocks[b].predecessors;
            if preds.is_empty() {
                continue;
            }
            let mut new_idom: Option<BlockId> = None;
            for &p in preds {
                if idom[p].is_some() {
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(current) => intersect(&idom, current, p, entry),
                    });
                }
            }
            if new_idom != idom[b] {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    idom
}

fn intersect(idom: &[Option<BlockId>], mut a: BlockId, mut b: BlockId, entry: BlockId) -> BlockId {
    let mut steps = 0;
    while a != b && steps < 1000 {
        while a > b {
            a = idom[a].unwrap_or(entry);
        }
        while b > a {
            b = idom[b].unwrap_or(entry);
        }
        steps += 1;
    }
    a
}

pub fn compute_dominance_frontier(cfg: &ControlFlowGraph, idom: &[Option<BlockId>]) -> Vec<Vec<BlockId>> {
    let n = cfg.blocks.len();
    let mut df_sets: Vec<std::collections::BTreeSet<BlockId>> = vec![std::collections::BTreeSet::new(); n];

    for b in 0..n {
        let preds = &cfg.blocks[b].predecessors;
        if preds.len() < 2 {
            continue;
        }
        for &p in preds {
            let mut runner = p;
            while runner != idom[b].unwrap_or(b) {
                df_sets[runner].insert(b);
                runner = idom[runner].unwrap_or(runner);
                if runner == idom[runner].unwrap_or(runner) {
                    break;
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
    use gr_core::address::{Address, SpaceId};
    use gr_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
    use gr_lift::LiftedInstruction;
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
}
