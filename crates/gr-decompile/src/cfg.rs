use std::collections::{BTreeMap, BTreeSet};

use gr_core::pcode::OpCode;
use gr_lift::LiftedInstruction;

fn empty_cfg() -> ControlFlowGraph {
    ControlFlowGraph {
        blocks: vec![BasicBlock {
            id: 0,
            start_addr: 0,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }],
        entry_block: 0,
        addr_to_block: BTreeMap::new(),
    }
}

fn compute_leaders(instructions: &[LiftedInstruction]) -> Vec<u64> {
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(instructions[0].address);
    for insn in instructions {
        let has_branch = insn.ops.iter().any(|op| {
            matches!(op.opcode, OpCode::Branch | OpCode::CBranch | OpCode::BranchInd)
        });
        let has_return = insn.ops.iter().any(|op| op.opcode == OpCode::Return);
        if has_branch || has_return {
            for op in &insn.ops {
                if matches!(op.opcode, OpCode::Branch | OpCode::CBranch)
                    && let Some(target_vn) = op.inputs.first()
                    && target_vn.space == gr_core::address::SpaceId::RAM
                {
                    leaders.insert(target_vn.offset);
                }
            }
            let fall = insn.address + insn.length as u64;
            leaders.insert(fall);
        }
    }
    leaders.into_iter().collect()
}

fn finalize_cfg(
    mut blocks: Vec<BasicBlock>,
    addr_to_block: BTreeMap<u64, BlockId>,
    entry_addr: u64,
) -> ControlFlowGraph {
    let block_count = blocks.len();
    #[allow(clippy::needless_range_loop)]
    for i in 0..block_count {
        let last_insn = blocks[i].instructions.last();
        let has_unconditional_branch =
            last_insn.is_some_and(|insn| insn.ops.iter().any(|op| op.opcode == OpCode::Branch));
        let has_cbranch =
            last_insn.is_some_and(|insn| insn.ops.iter().any(|op| op.opcode == OpCode::CBranch));
        let has_return =
            last_insn.is_some_and(|insn| insn.ops.iter().any(|op| op.opcode == OpCode::Return));
        let has_branch_ind = last_insn
            .is_some_and(|insn| insn.ops.iter().any(|op| op.opcode == OpCode::BranchInd));
        if has_return || has_branch_ind {
            continue;
        }
        if has_unconditional_branch && !has_cbranch {
            if let Some(target) = blocks[i].branch_target()
                && let Some(&target_id) = addr_to_block.get(&target)
            {
                blocks[i].successors.push(target_id);
            }
        } else if has_cbranch {
            if let Some(target) = blocks[i].branch_target()
                && let Some(&target_id) = addr_to_block.get(&target)
            {
                blocks[i].successors.push(target_id);
            }
            let fall = blocks[i].end_addr();
            if let Some(&fall_id) = addr_to_block.get(&fall) {
                blocks[i].successors.push(fall_id);
            }
        } else {
            let fall = blocks[i].end_addr();
            if let Some(&fall_id) = addr_to_block.get(&fall) {
                blocks[i].successors.push(fall_id);
            }
        }
    }
    for i in 0..block_count {
        let succs: Vec<BlockId> = blocks[i].successors.clone();
        for s in succs {
            if !blocks[s].predecessors.contains(&i) {
                blocks[s].predecessors.push(i);
            }
        }
    }
    let entry_block = *addr_to_block.get(&entry_addr).unwrap_or(&0);
    ControlFlowGraph {
        blocks,
        entry_block,
        addr_to_block,
    }
}

pub type BlockId = usize;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    pub start_addr: u64,
    pub instructions: Vec<LiftedInstruction>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
}

impl BasicBlock {
    pub fn end_addr(&self) -> u64 {
        self.instructions
            .last()
            .map(|i| i.address + i.length as u64)
            .unwrap_or(self.start_addr)
    }

    pub fn is_return(&self) -> bool {
        self.instructions.last().is_some_and(|i| {
            i.ops.iter().any(|op| op.opcode == OpCode::Return)
        })
    }

    pub fn is_branch(&self) -> bool {
        self.instructions.last().is_some_and(|i| {
            i.ops
                .iter()
                .any(|op| matches!(op.opcode, OpCode::Branch | OpCode::CBranch))
        })
    }

    pub fn branch_target(&self) -> Option<u64> {
        self.instructions.last().and_then(|i| {
            i.ops.iter().rev().find_map(|op| {
                if matches!(op.opcode, OpCode::Branch | OpCode::CBranch | OpCode::Call) {
                    // Only a RAM-space operand is a real code address; the
                    // leader pass applies the same guard, so successor wiring
                    // must too, or a constant/register operand whose offset
                    // happens to equal a block start would create a bogus edge.
                    op.inputs.first().and_then(|vn| {
                        if vn.space == gr_core::address::SpaceId::RAM {
                            Some(vn.offset)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
        })
    }
}

#[derive(Debug)]
pub struct ControlFlowGraph {
    pub blocks: Vec<BasicBlock>,
    pub entry_block: BlockId,
    addr_to_block: BTreeMap<u64, BlockId>,
}

impl ControlFlowGraph {
    pub fn build(instructions: &[LiftedInstruction]) -> Self {
        // Borrow form: clone each instruction into its block. Kept
        // around for tests and other call sites that don't have
        // ownership of the lifted Vec. The decompile hot path uses
        // `build_owned` to skip the clones entirely.
        Self::build_inner(instructions, |i: &LiftedInstruction| i.clone())
    }

    /// Like `build`, but consumes the instruction Vec so each
    /// `LiftedInstruction` can be *moved* into its block instead of
    /// cloned. Each `LiftedInstruction` owns a `String` mnemonic and
    /// a `Vec<PcodeOp>`; the borrow form does a deep clone per
    /// instruction (heap copy of mnemonic + heap copy of every
    /// PcodeOp), which is the dominant cost in CFG::build on real
    /// binaries. `build_owned` borrows once for the leader scan and
    /// then `IntoIter`s the original Vec straight into the blocks.
    pub fn build_owned(instructions: Vec<LiftedInstruction>) -> Self {
        if instructions.is_empty() {
            return empty_cfg();
        }
        let leader_vec = compute_leaders(&instructions);
        let entry_addr = instructions[0].address;

        let mut blocks = Vec::new();
        let mut addr_to_block: BTreeMap<u64, BlockId> = BTreeMap::new();
        let mut iter = instructions.into_iter().peekable();

        for (idx, &leader_addr) in leader_vec.iter().enumerate() {
            let next_leader = leader_vec.get(idx + 1).copied().unwrap_or(u64::MAX);
            let mut block_insns = Vec::new();
            while let Some(insn) = iter.peek() {
                if insn.address < leader_addr {
                    iter.next();
                    continue;
                }
                if insn.address >= next_leader {
                    break;
                }
                // Move out of the iterator -- no clone.
                block_insns.push(iter.next().unwrap());
            }
            if block_insns.is_empty() {
                continue;
            }
            let block_id = blocks.len();
            addr_to_block.insert(leader_addr, block_id);
            blocks.push(BasicBlock {
                id: block_id,
                start_addr: leader_addr,
                instructions: block_insns,
                successors: Vec::new(),
                predecessors: Vec::new(),
            });
        }
        finalize_cfg(blocks, addr_to_block, entry_addr)
    }

    fn build_inner(
        instructions: &[LiftedInstruction],
        mut take: impl FnMut(&LiftedInstruction) -> LiftedInstruction,
    ) -> Self {
        if instructions.is_empty() {
            return empty_cfg();
        }
        let leader_vec = compute_leaders(instructions);
        let mut blocks = Vec::new();
        let mut addr_to_block: BTreeMap<u64, BlockId> = BTreeMap::new();
        let mut insn_iter = instructions.iter().peekable();
        for (idx, &leader_addr) in leader_vec.iter().enumerate() {
            let next_leader = leader_vec.get(idx + 1).copied().unwrap_or(u64::MAX);
            let mut block_insns = Vec::new();
            while let Some(&insn) = insn_iter.peek() {
                if insn.address < leader_addr {
                    insn_iter.next();
                    continue;
                }
                if insn.address >= next_leader {
                    break;
                }
                block_insns.push(take(insn));
                insn_iter.next();
            }
            if block_insns.is_empty() {
                continue;
            }
            let block_id = blocks.len();
            addr_to_block.insert(leader_addr, block_id);
            blocks.push(BasicBlock {
                id: block_id,
                start_addr: leader_addr,
                instructions: block_insns,
                successors: Vec::new(),
                predecessors: Vec::new(),
            });
        }
        let entry_addr = instructions[0].address;
        finalize_cfg(blocks, addr_to_block, entry_addr)
    }



    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn get_block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(id)
    }

    pub fn block_at(&self, addr: u64) -> Option<&BasicBlock> {
        self.addr_to_block
            .get(&addr)
            .and_then(|&id| self.blocks.get(id))
    }

    pub fn dominators(&self) -> Vec<BTreeSet<BlockId>> {
        let n = self.blocks.len();
        let all: BTreeSet<BlockId> = (0..n).collect();
        let mut dom: Vec<BTreeSet<BlockId>> = vec![all.clone(); n];
        dom[self.entry_block] = BTreeSet::from([self.entry_block]);

        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..n {
                if i == self.entry_block {
                    continue;
                }
                let mut new_dom = all.clone();
                for &pred in &self.blocks[i].predecessors {
                    new_dom = new_dom.intersection(&dom[pred]).copied().collect();
                }
                new_dom.insert(i);
                if new_dom != dom[i] {
                    dom[i] = new_dom;
                    changed = true;
                }
            }
        }
        dom
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gr_core::address::{Address, SpaceId};
    use gr_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use smallvec::SmallVec;

    fn make_insn(addr: u64, len: u32, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: len,
            mnemonic: format!("insn_{:x}", addr),
            ops,
        }
    }

    fn nop_insn(addr: u64) -> LiftedInstruction {
        make_insn(addr, 1, vec![])
    }

    fn ret_insn(addr: u64) -> LiftedInstruction {
        make_insn(addr, 1, vec![PcodeOp {
            opcode: OpCode::Return,
            seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(0), 0, 8)]),
        }])
    }

    fn jmp_insn(addr: u64, target: u64) -> LiftedInstruction {
        make_insn(addr, 2, vec![PcodeOp {
            opcode: OpCode::Branch,
            seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), target, 8)]),
        }])
    }

    fn cbranch_insn(addr: u64, target: u64) -> LiftedInstruction {
        make_insn(addr, 2, vec![PcodeOp {
            opcode: OpCode::CBranch,
            seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
            output: None,
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(SpaceId(1), target, 8),
                VarnodeData::new(SpaceId(0), 1, 1),
            ]),
        }])
    }

    #[test]
    fn linear_cfg() {
        let insns = vec![nop_insn(0x1000), nop_insn(0x1001), ret_insn(0x1002)];
        let cfg = ControlFlowGraph::build(&insns);
        assert_eq!(cfg.block_count(), 1);
        assert!(cfg.blocks[0].is_return());
    }

    #[test]
    fn branch_cfg() {
        // 0x1000: nop
        // 0x1001: jmp 0x1000
        let insns = vec![nop_insn(0x1000), jmp_insn(0x1001, 0x1000)];
        let cfg = ControlFlowGraph::build(&insns);
        assert!(cfg.block_count() >= 1);
    }

    #[test]
    fn if_else_cfg() {
        // 0x1000: cbranch 0x1004
        // 0x1002: nop (then)
        // 0x1003: ret
        // 0x1004: nop (else)
        // 0x1005: ret
        let insns = vec![
            cbranch_insn(0x1000, 0x1004),
            nop_insn(0x1002),
            ret_insn(0x1003),
            nop_insn(0x1004),
            ret_insn(0x1005),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        assert!(cfg.block_count() >= 3);
        let entry = &cfg.blocks[cfg.entry_block];
        assert_eq!(entry.successors.len(), 2);
    }

    #[test]
    fn dominators_linear() {
        let insns = vec![nop_insn(0x1000), nop_insn(0x1001), ret_insn(0x1002)];
        let cfg = ControlFlowGraph::build(&insns);
        let doms = cfg.dominators();
        assert!(doms[cfg.entry_block].contains(&cfg.entry_block));
    }

    fn branch_ind_insn(addr: u64) -> LiftedInstruction {
        make_insn(addr, 4, vec![PcodeOp {
            opcode: OpCode::BranchInd,
            seq: SeqNum::new(Address::new(SpaceId(1), addr), 0),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(3), 0, 4)]),
        }])
    }

    #[test]
    fn branch_ind_ends_block_without_falling_through() {
        // `ldr pc, [...]` (now lifted to BranchInd) must end the block
        // and NOT chain into the following instruction.
        let insns = vec![branch_ind_insn(0x1000), nop_insn(0x1004), ret_insn(0x1005)];
        let cfg = ControlFlowGraph::build(&insns);
        // The BranchInd block must have no successor (target unknown).
        let bi_block = cfg.block_at(0x1000).unwrap();
        assert!(bi_block.successors.is_empty());
        // The following address starts its own block.
        assert!(cfg.block_at(0x1004).is_some());
    }
}
