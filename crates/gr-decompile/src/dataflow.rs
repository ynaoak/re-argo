// Data flow analysis: def-use chains, liveness, reaching definitions.

use std::collections::{BTreeMap, BTreeSet};
use crate::ssa::{SsaFunction, VarId};
use crate::cfg::BlockId;

#[derive(Debug, Default)]
pub struct LivenessInfo {
    pub live_in: BTreeMap<BlockId, BTreeSet<VarId>>,
    pub live_out: BTreeMap<BlockId, BTreeSet<VarId>>,
}

pub fn compute_liveness(func: &SsaFunction) -> LivenessInfo {
    let mut info = LivenessInfo::default();
    let block_count = func.cfg.blocks.len();

    for b in 0..block_count {
        info.live_in.insert(b, BTreeSet::new());
        info.live_out.insert(b, BTreeSet::new());
    }

    let mut defs: BTreeMap<BlockId, BTreeSet<VarId>> = BTreeMap::new();
    let mut uses: BTreeMap<BlockId, BTreeSet<VarId>> = BTreeMap::new();

    for op in &func.ops {
        if op.dead { continue; }
        let block = op.block;
        for &inp in &op.inputs {
            if !defs.entry(block).or_default().contains(&inp) {
                uses.entry(block).or_default().insert(inp);
            }
        }
        if let Some(out) = op.output {
            defs.entry(block).or_default().insert(out);
        }
    }

    let cached_defs: Vec<BTreeSet<VarId>> = (0..block_count)
        .map(|b| defs.get(&b).cloned().unwrap_or_default())
        .collect();
    let cached_uses: Vec<BTreeSet<VarId>> = (0..block_count)
        .map(|b| uses.get(&b).cloned().unwrap_or_default())
        .collect();

    let mut changed = true;
    let mut scratch_diff = BTreeSet::new();
    while changed {
        changed = false;
        for b in (0..block_count).rev() {
            let mut new_out = BTreeSet::new();
            for &succ in &func.cfg.blocks[b].successors {
                if let Some(li) = info.live_in.get(&succ) {
                    new_out.extend(li.iter().copied());
                }
            }
            scratch_diff.clear();
            for v in new_out.difference(&cached_defs[b]) {
                scratch_diff.insert(*v);
            }
            let new_in: BTreeSet<VarId> = cached_uses[b].union(&scratch_diff).copied().collect();

            if info.live_in.get(&b) != Some(&new_in) || info.live_out.get(&b) != Some(&new_out) {
                info.live_in.insert(b, new_in);
                info.live_out.insert(b, new_out);
                changed = true;
            }
        }
    }
    info
}

pub fn find_dead_variables(func: &SsaFunction) -> Vec<VarId> {
    let liveness = compute_liveness(func);
    let mut dead = Vec::new();
    for vn in &func.varnodes {
        if vn.def_op.is_some() && vn.uses.is_empty() {
            let is_live = liveness.live_out.values().any(|set| set.contains(&vn.id));
            if !is_live {
                dead.push(vn.id);
            }
        }
    }
    dead
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use gr_core::address::{Address, SpaceId};
    use gr_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
    use gr_lift::LiftedInstruction;
    use smallvec::SmallVec;

    #[test]
    fn liveness_basic() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg = VarnodeData::new(SpaceId(2), 0, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![
            LiftedInstruction {
                address: 0x1000, length: 1, mnemonic: "test".into(),
                ops: vec![PcodeOp { opcode: OpCode::Copy, seq: seq(0x1000),
                    output: Some(reg), inputs: SmallVec::from_slice(&[imm]) }],
            },
            LiftedInstruction {
                address: 0x1001, length: 1, mnemonic: "ret".into(),
                ops: vec![PcodeOp { opcode: OpCode::Return, seq: seq(0x1001),
                    output: None, inputs: SmallVec::from_slice(&[reg]) }],
            },
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let liveness = compute_liveness(&ssa);
        assert!(!liveness.live_in.is_empty());
    }
}
