use gr_core::pcode::OpCode;

use crate::ssa::SsaFunction;

pub fn dead_code_elimination(func: &mut SsaFunction) -> usize {
    let mut removed = 0;
    let mut changed = true;

    while changed {
        changed = false;
        for i in 0..func.ops.len() {
            if func.ops[i].dead {
                continue;
            }
            if func.ops[i].output.is_none() {
                continue;
            }
            if matches!(
                func.ops[i].opcode,
                OpCode::Call | OpCode::CallInd | OpCode::CallOther
                    | OpCode::Store | OpCode::Return
                    | OpCode::Branch | OpCode::CBranch | OpCode::BranchInd
            ) {
                continue;
            }

            let out_id = func.ops[i].output.unwrap();
            let has_live_use = func.varnodes[out_id as usize]
                .uses
                .iter()
                .any(|&use_idx| !func.ops[use_idx].dead);

            if !has_live_use {
                func.ops[i].dead = true;
                removed += 1;
                changed = true;
            }
        }
    }
    removed
}

pub fn constant_fold(func: &mut SsaFunction) -> usize {
    let mut folded = 0;

    for i in 0..func.ops.len() {
        if func.ops[i].dead || func.ops[i].output.is_none() {
            continue;
        }

        let all_const = func.ops[i]
            .inputs
            .iter()
            .all(|&id| func.varnodes[id as usize].data.space == gr_core::address::SpaceId(0));

        if !all_const || func.ops[i].inputs.is_empty() {
            continue;
        }

        let result = match func.ops[i].opcode {
            OpCode::IntAdd => {
                let a = func.varnodes[func.ops[i].inputs[0] as usize].data.offset;
                let b = func.varnodes[func.ops[i].inputs[1] as usize].data.offset;
                Some(a.wrapping_add(b))
            }
            OpCode::IntSub => {
                let a = func.varnodes[func.ops[i].inputs[0] as usize].data.offset;
                let b = func.varnodes[func.ops[i].inputs[1] as usize].data.offset;
                Some(a.wrapping_sub(b))
            }
            OpCode::IntAnd => {
                let a = func.varnodes[func.ops[i].inputs[0] as usize].data.offset;
                let b = func.varnodes[func.ops[i].inputs[1] as usize].data.offset;
                Some(a & b)
            }
            OpCode::IntOr => {
                let a = func.varnodes[func.ops[i].inputs[0] as usize].data.offset;
                let b = func.varnodes[func.ops[i].inputs[1] as usize].data.offset;
                Some(a | b)
            }
            OpCode::IntXor => {
                let a = func.varnodes[func.ops[i].inputs[0] as usize].data.offset;
                let b = func.varnodes[func.ops[i].inputs[1] as usize].data.offset;
                Some(a ^ b)
            }
            OpCode::IntEqual => {
                let a = func.varnodes[func.ops[i].inputs[0] as usize].data.offset;
                let b = func.varnodes[func.ops[i].inputs[1] as usize].data.offset;
                Some(if a == b { 1 } else { 0 })
            }
            OpCode::IntMult => {
                let a = func.varnodes[func.ops[i].inputs[0] as usize].data.offset;
                let b = func.varnodes[func.ops[i].inputs[1] as usize].data.offset;
                Some(a.wrapping_mul(b))
            }
            _ => None,
        };

        if let Some(val) = result {
            let out_id = func.ops[i].output.unwrap();
            let out_size = func.varnodes[out_id as usize].data.size;
            let const_id = func.varnodes.len() as u32;
            func.varnodes.push(crate::ssa::SsaVarnode {
                id: const_id,
                data: gr_core::pcode::VarnodeData::new(gr_core::address::SpaceId(0), val, out_size),
                version: 0,
                def_op: None,
                uses: vec![i],
            });
            func.ops[i].opcode = OpCode::Copy;
            func.ops[i].inputs = vec![const_id];
            folded += 1;
        }
    }
    folded
}

pub fn copy_propagation(func: &mut SsaFunction) -> usize {
    let mut propagated = 0;

    for i in 0..func.ops.len() {
        if func.ops[i].dead || func.ops[i].opcode != OpCode::Copy {
            continue;
        }
        if func.ops[i].output.is_none() || func.ops[i].inputs.is_empty() {
            continue;
        }

        let out_id = func.ops[i].output.unwrap();
        let src_id = func.ops[i].inputs[0];

        let src_is_const =
            func.varnodes[src_id as usize].data.space == gr_core::address::SpaceId(0);
        if !src_is_const {
            continue;
        }

        let uses: Vec<usize> = func.varnodes[out_id as usize].uses.clone();
        for use_idx in uses {
            if func.ops[use_idx].dead {
                continue;
            }
            for inp in &mut func.ops[use_idx].inputs {
                if *inp == out_id {
                    *inp = src_id;
                    propagated += 1;
                }
            }
        }
    }
    propagated
}

pub fn run_optimization_passes(func: &mut SsaFunction) -> OptimizationStats {
    let mut stats = OptimizationStats::default();

    for _ in 0..10 {
        let cf = constant_fold(func);
        let cp = copy_propagation(func);
        let dce = dead_code_elimination(func);
        stats.constants_folded += cf;
        stats.copies_propagated += cp;
        stats.dead_ops_removed += dce;
        if cf == 0 && cp == 0 && dce == 0 {
            break;
        }
    }
    stats
}

#[derive(Debug, Default)]
pub struct OptimizationStats {
    pub dead_ops_removed: usize,
    pub constants_folded: usize,
    pub copies_propagated: usize,
}

impl std::fmt::Display for OptimizationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "folded={}, propagated={}, dce={}",
            self.constants_folded, self.copies_propagated, self.dead_ops_removed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use crate::ssa::SsaFunction;
    use gr_core::address::{Address, SpaceId};
    use gr_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use gr_lift::LiftedInstruction;
    use smallvec::SmallVec;

    fn make_lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "test".into(),
            ops,
        }
    }

    #[test]
    fn dead_code_elimination_removes_unused() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let reg_rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![
            make_lifted(0x1000, vec![
                PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x1000),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[imm]),
                },
            ]),
            make_lifted(0x1001, vec![
                PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x1001),
                    output: Some(reg_rcx),
                    inputs: SmallVec::from_slice(&[imm]),
                },
            ]),
            make_lifted(0x1002, vec![
                PcodeOp {
                    opcode: OpCode::Return,
                    seq: seq(0x1002),
                    output: None,
                    inputs: SmallVec::from_slice(&[reg_rax]),
                },
            ]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);

        let before = ssa.op_count();
        let removed = dead_code_elimination(&mut ssa);
        assert!(removed > 0);
        assert!(ssa.live_op_count() < before);
    }

    #[test]
    fn constant_folding() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm_a = VarnodeData::new(SpaceId(0), 10, 8);
        let imm_b = VarnodeData::new(SpaceId(0), 20, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000),
                output: Some(reg_rax),
                inputs: SmallVec::from_slice(&[imm_a, imm_b]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[reg_rax]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let folded = constant_fold(&mut ssa);
        assert!(folded > 0);
    }
}
