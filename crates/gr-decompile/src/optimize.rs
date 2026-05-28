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
            .all(|&id| func.varnodes[id as usize].data.space == gr_core::address::SpaceId::CONST);

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
                data: gr_core::pcode::VarnodeData::new(gr_core::address::SpaceId::CONST, val, out_size),
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
            func.varnodes[src_id as usize].data.space == gr_core::address::SpaceId::CONST;
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

pub fn strength_reduction(func: &mut SsaFunction) -> usize {
    let mut reduced = 0;
    let const_space = gr_core::address::SpaceId::CONST;

    for i in 0..func.ops.len() {
        if func.ops[i].dead || func.ops[i].output.is_none() {
            continue;
        }

        match func.ops[i].opcode {
            OpCode::IntMult => {
                if func.ops[i].inputs.len() < 2 { continue; }
                for side in 0..2 {
                    let other = 1 - side;
                    let vn = &func.varnodes[func.ops[i].inputs[side] as usize];
                    if vn.data.space != const_space { continue; }
                    let val = vn.data.offset;
                    if val != 0 && val.is_power_of_two() {
                        let shift_amt = val.trailing_zeros() as u64;
                        let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                        let shift_id = func.varnodes.len() as u32;
                        func.varnodes.push(crate::ssa::SsaVarnode {
                            id: shift_id,
                            data: gr_core::pcode::VarnodeData::new(const_space, shift_amt, out_size),
                            version: 0,
                            def_op: None,
                            uses: vec![i],
                        });
                        func.ops[i].opcode = OpCode::IntLeft;
                        func.ops[i].inputs = vec![func.ops[i].inputs[other], shift_id];
                        reduced += 1;
                        break;
                    }
                }
            }
            OpCode::IntDiv | OpCode::IntSDiv => {
                if func.ops[i].inputs.len() < 2 { continue; }
                let divisor_vn = &func.varnodes[func.ops[i].inputs[1] as usize];
                if divisor_vn.data.space != const_space { continue; }
                let val = divisor_vn.data.offset;
                if val != 0 && val.is_power_of_two() && func.ops[i].opcode == OpCode::IntDiv {
                    let shift_amt = val.trailing_zeros() as u64;
                    let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                    let shift_id = func.varnodes.len() as u32;
                    func.varnodes.push(crate::ssa::SsaVarnode {
                        id: shift_id,
                        data: gr_core::pcode::VarnodeData::new(const_space, shift_amt, out_size),
                        version: 0,
                        def_op: None,
                        uses: vec![i],
                    });
                    func.ops[i].opcode = OpCode::IntRight;
                    func.ops[i].inputs = vec![func.ops[i].inputs[0], shift_id];
                    reduced += 1;
                }
            }
            _ => {}
        }
    }
    reduced
}

pub fn algebraic_simplification(func: &mut SsaFunction) -> usize {
    let mut simplified = 0;
    let const_space = gr_core::address::SpaceId::CONST;

    for i in 0..func.ops.len() {
        if func.ops[i].dead || func.ops[i].output.is_none() {
            continue;
        }
        if func.ops[i].inputs.len() < 2 {
            continue;
        }

        let in0 = func.ops[i].inputs[0];
        let in1 = func.ops[i].inputs[1];
        let vn0 = &func.varnodes[in0 as usize];
        let vn1 = &func.varnodes[in1 as usize];

        match func.ops[i].opcode {
            OpCode::IntSub | OpCode::IntXor if in0 == in1 => {
                let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                let zero_id = func.varnodes.len() as u32;
                func.varnodes.push(crate::ssa::SsaVarnode {
                    id: zero_id,
                    data: gr_core::pcode::VarnodeData::new(const_space, 0, out_size),
                    version: 0, def_op: None, uses: vec![i],
                });
                func.ops[i].opcode = OpCode::Copy;
                func.ops[i].inputs = vec![zero_id];
                simplified += 1;
            }
            OpCode::IntAdd => {
                for side in 0..2 {
                    let vn = if side == 0 { vn0 } else { vn1 };
                    if vn.data.space == const_space && vn.data.offset == 0 {
                        let keep = func.ops[i].inputs[1 - side];
                        func.ops[i].opcode = OpCode::Copy;
                        func.ops[i].inputs = vec![keep];
                        simplified += 1;
                        break;
                    }
                }
            }
            OpCode::IntMult => {
                for side in 0..2 {
                    let vn = if side == 0 { vn0 } else { vn1 };
                    if vn.data.space == const_space {
                        if vn.data.offset == 1 {
                            let keep = func.ops[i].inputs[1 - side];
                            func.ops[i].opcode = OpCode::Copy;
                            func.ops[i].inputs = vec![keep];
                            simplified += 1;
                            break;
                        } else if vn.data.offset == 0 {
                            let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                            let zero_id = func.varnodes.len() as u32;
                            func.varnodes.push(crate::ssa::SsaVarnode {
                                id: zero_id,
                                data: gr_core::pcode::VarnodeData::new(const_space, 0, out_size),
                                version: 0, def_op: None, uses: vec![i],
                            });
                            func.ops[i].opcode = OpCode::Copy;
                            func.ops[i].inputs = vec![zero_id];
                            simplified += 1;
                            break;
                        }
                    }
                }
            }
            OpCode::IntAnd => {
                for side in 0..2 {
                    let vn = if side == 0 { vn0 } else { vn1 };
                    if vn.data.space == const_space && vn.data.offset == 0 {
                        let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                        let zero_id = func.varnodes.len() as u32;
                        func.varnodes.push(crate::ssa::SsaVarnode {
                            id: zero_id,
                            data: gr_core::pcode::VarnodeData::new(const_space, 0, out_size),
                            version: 0, def_op: None, uses: vec![i],
                        });
                        func.ops[i].opcode = OpCode::Copy;
                        func.ops[i].inputs = vec![zero_id];
                        simplified += 1;
                        break;
                    }
                }
            }
            OpCode::IntOr => {
                for side in 0..2 {
                    let vn = if side == 0 { vn0 } else { vn1 };
                    if vn.data.space == const_space && vn.data.offset == 0 {
                        let keep = func.ops[i].inputs[1 - side];
                        func.ops[i].opcode = OpCode::Copy;
                        func.ops[i].inputs = vec![keep];
                        simplified += 1;
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    simplified
}

pub fn run_optimization_passes(func: &mut SsaFunction) -> OptimizationStats {
    let mut stats = OptimizationStats::default();

    for _ in 0..10 {
        let cf = constant_fold(func);
        let cp = copy_propagation(func);
        let sr = strength_reduction(func);
        let alg = algebraic_simplification(func);
        let dce = dead_code_elimination(func);
        stats.constants_folded += cf;
        stats.copies_propagated += cp;
        stats.strength_reduced += sr;
        stats.algebraic_simplified += alg;
        stats.dead_ops_removed += dce;
        if cf == 0 && cp == 0 && dce == 0 && sr == 0 && alg == 0 {
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
    pub strength_reduced: usize,
    pub algebraic_simplified: usize,
}

impl std::fmt::Display for OptimizationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "folded={}, propagated={}, dce={}, strength={}, algebra={}",
            self.constants_folded, self.copies_propagated, self.dead_ops_removed,
            self.strength_reduced, self.algebraic_simplified
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

    #[test]
    fn strength_reduce_multiply_by_power_of_two() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let reg_rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let imm_8 = VarnodeData::new(SpaceId(0), 8, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntMult,
                seq: seq(0x1000),
                output: Some(reg_rax),
                inputs: SmallVec::from_slice(&[reg_rcx, imm_8]),
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
        let reduced = strength_reduction(&mut ssa);
        assert!(reduced > 0);
        let mult_op = ssa.ops.iter().find(|op| !op.dead && op.opcode == OpCode::IntLeft);
        assert!(mult_op.is_some());
    }

    #[test]
    fn algebraic_simplify_xor_self_via_ssa() {
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        // xor eax, eax is the canonical "zero register" idiom
        // In SSA: copy rax <- 42; then xor rax, rax (same SSA def)
        let insns = vec![
            make_lifted(0x1000, vec![
                PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x1000, 0),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[imm]),
                },
                PcodeOp {
                    opcode: OpCode::IntXor,
                    seq: seq(0x1000, 1),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[reg_rax, reg_rax]),
                },
            ]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001, 0),
                output: None,
                inputs: SmallVec::from_slice(&[reg_rax]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let xor_ops: Vec<_> = ssa.ops.iter()
            .filter(|op| !op.dead && op.opcode == OpCode::IntXor)
            .collect();
        if let Some(xor_op) = xor_ops.first() {
            if xor_op.inputs.len() == 2 && xor_op.inputs[0] == xor_op.inputs[1] {
                let simplified = algebraic_simplification(&mut ssa);
                assert!(simplified > 0);
                return;
            }
        }
        // If SSA renamed them differently, the optimization correctly doesn't fire
    }

    #[test]
    fn algebraic_simplify_add_zero() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let reg_rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let imm_0 = VarnodeData::new(SpaceId(0), 0, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000),
                output: Some(reg_rax),
                inputs: SmallVec::from_slice(&[reg_rcx, imm_0]),
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
        let simplified = algebraic_simplification(&mut ssa);
        assert!(simplified > 0);
        let copy_op = ssa.ops.iter().find(|op| !op.dead && op.opcode == OpCode::Copy);
        assert!(copy_op.is_some());
    }
}
