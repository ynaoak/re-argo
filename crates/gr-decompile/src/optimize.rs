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
            // Truncate to the operand width: a folded 32-bit `0xFFFFFFFF + 1`
            // must be 0, not 0x1_0000_0000. The constant is emitted from its
            // raw offset, so an unmasked value would print (and re-fold) wrong.
            let masked = if out_size >= 8 {
                val
            } else {
                val & ((1u64 << (out_size * 8)) - 1)
            };
            let const_id = func.varnodes.len() as u32;
            func.varnodes.push(crate::ssa::SsaVarnode {
                id: const_id,
                data: gr_core::pcode::VarnodeData::new(gr_core::address::SpaceId::CONST, masked, out_size),
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

/// SSA value identity: the simplified SSA allocates a fresh varnode per read,
/// so the same value is correlated by (space, offset, size, version).
type ValueKey = (u32, u64, u32, u32);

fn value_key(func: &SsaFunction, var_id: u32) -> ValueKey {
    let vn = &func.varnodes[var_id as usize];
    (vn.data.space.0, vn.data.offset, vn.data.size, vn.version)
}

fn is_cse_pure(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult
            | OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor
            | OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight
            | OpCode::IntNegate | OpCode::Int2Comp
            | OpCode::IntEqual | OpCode::IntNotEqual
            | OpCode::IntLess | OpCode::IntLessEqual
            | OpCode::IntSLess | OpCode::IntSLessEqual
            | OpCode::IntZExt | OpCode::IntSExt
            | OpCode::IntDiv | OpCode::IntSDiv | OpCode::IntRem | OpCode::IntSRem
    )
}

fn is_commutative(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::IntAdd | OpCode::IntMult | OpCode::IntAnd
            | OpCode::IntOr | OpCode::IntXor
            | OpCode::IntEqual | OpCode::IntNotEqual
    )
}

/// Rewrite every varnode identifying value `from` to identify value `to`,
/// redirecting all reads of `from` onto `to`.
fn redirect_value(func: &mut SsaFunction, from: ValueKey, to: ValueKey) {
    let new_data = gr_core::pcode::VarnodeData::new(
        gr_core::address::SpaceId(to.0),
        to.1,
        to.2,
    );
    for vn in &mut func.varnodes {
        if (vn.data.space.0, vn.data.offset, vn.data.size, vn.version) == from {
            vn.data = new_data;
            vn.version = to.3;
        }
    }
}

/// Local common subexpression elimination.
///
/// Within each basic block, a pure op that recomputes a value already produced
/// by an earlier pure op (same opcode and inputs by value identity) is removed,
/// and its uses are redirected to the earlier result. Restricting to a single
/// block keeps the rewrite safe without dominator analysis.
pub fn common_subexpression_elimination(func: &mut SsaFunction) -> usize {
    let mut eliminated = 0;
    // (block, opcode name, input value keys) -> output value key
    let mut seen: std::collections::BTreeMap<(usize, &'static str, Vec<ValueKey>), ValueKey> =
        std::collections::BTreeMap::new();

    for i in 0..func.ops.len() {
        if func.ops[i].dead {
            continue;
        }
        let opcode = func.ops[i].opcode;
        if !is_cse_pure(opcode) {
            continue;
        }
        let Some(out_id) = func.ops[i].output else { continue };
        if func.ops[i].inputs.is_empty() {
            continue;
        }

        let mut in_keys: Vec<ValueKey> =
            func.ops[i].inputs.iter().map(|&id| value_key(func, id)).collect();
        if is_commutative(opcode) {
            in_keys.sort();
        }
        let key = (func.ops[i].block, opcode.name(), in_keys);
        let out_key = value_key(func, out_id);

        if let Some(&existing) = seen.get(&key) {
            redirect_value(func, out_key, existing);
            func.ops[i].dead = true;
            eliminated += 1;
        } else {
            seen.insert(key, out_key);
        }
    }
    eliminated
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
        let cse = common_subexpression_elimination(func);
        let dce = dead_code_elimination(func);
        stats.constants_folded += cf;
        stats.copies_propagated += cp;
        stats.strength_reduced += sr;
        stats.algebraic_simplified += alg;
        stats.cse_eliminated += cse;
        stats.dead_ops_removed += dce;
        if cf == 0 && cp == 0 && dce == 0 && sr == 0 && alg == 0 && cse == 0 {
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
    pub cse_eliminated: usize,
}

impl std::fmt::Display for OptimizationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "folded={}, propagated={}, dce={}, strength={}, algebra={}, cse={}",
            self.constants_folded, self.copies_propagated, self.dead_ops_removed,
            self.strength_reduced, self.algebraic_simplified, self.cse_eliminated
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
    fn constant_folding_truncates_to_operand_width() {
        // 32-bit 0xFFFFFFFF + 1 must fold to 0, not 0x1_0000_0000.
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg = VarnodeData::new(SpaceId(2), 0x00, 4); // 4-byte result
        let a = VarnodeData::new(SpaceId(0), 0xFFFF_FFFF, 4);
        let b = VarnodeData::new(SpaceId(0), 1, 4);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000),
                output: Some(reg),
                inputs: SmallVec::from_slice(&[a, b]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[reg]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        assert!(constant_fold(&mut ssa) > 0);
        // The folded op is now a Copy of a CONST whose value is masked to 4 bytes.
        let folded_const = ssa.ops.iter()
            .find(|o| o.opcode == OpCode::Copy && !o.dead)
            .and_then(|o| o.inputs.first().copied())
            .map(|id| ssa.varnodes[id as usize].data.offset)
            .expect("expected a folded Copy of a constant");
        assert_eq!(folded_const, 0, "0xFFFFFFFF + 1 at 4 bytes must wrap to 0");
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
        if let Some(xor_op) = xor_ops.first()
            && xor_op.inputs.len() == 2 && xor_op.inputs[0] == xor_op.inputs[1]
        {
            let simplified = algebraic_simplification(&mut ssa);
            assert!(simplified > 0);
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

    #[test]
    fn cse_eliminates_duplicate_expression() {
        // rax = rdi + rsi; rbx = rdi + rsi (duplicate)
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let rdi = VarnodeData::new(SpaceId(2), 0x38, 8);
        let rsi = VarnodeData::new(SpaceId(2), 0x30, 8);

        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 0),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 1),
                output: Some(rbx),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
        ])];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let eliminated = common_subexpression_elimination(&mut ssa);
        assert_eq!(eliminated, 1, "duplicate add should be eliminated");
        let live_adds = ssa.ops.iter().filter(|op| !op.dead && op.opcode == OpCode::IntAdd).count();
        assert_eq!(live_adds, 1);
    }

    #[test]
    fn cse_commutative_match() {
        // rax = rdi + rsi; rbx = rsi + rdi (commutative duplicate)
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let rdi = VarnodeData::new(SpaceId(2), 0x38, 8);
        let rsi = VarnodeData::new(SpaceId(2), 0x30, 8);

        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 0),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 1),
                output: Some(rbx),
                inputs: SmallVec::from_slice(&[rsi, rdi]),
            },
        ])];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let eliminated = common_subexpression_elimination(&mut ssa);
        assert_eq!(eliminated, 1, "commutative duplicate should be eliminated");
    }

    #[test]
    fn cse_keeps_distinct_expressions() {
        // rax = rdi + rsi; rbx = rdi - rsi (different opcode, not a duplicate)
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let rdi = VarnodeData::new(SpaceId(2), 0x38, 8);
        let rsi = VarnodeData::new(SpaceId(2), 0x30, 8);

        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 0),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
            PcodeOp {
                opcode: OpCode::IntSub,
                seq: seq(0x1000, 1),
                output: Some(rbx),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
        ])];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let eliminated = common_subexpression_elimination(&mut ssa);
        assert_eq!(eliminated, 0, "different opcodes must not be merged");
    }

    /// DCE must not delete a Copy that defines a register subsequently
    /// read by Return. Pre-fix the SSA builder minted a fresh varnode for
    /// every read, so the def-side `uses` list stayed empty and DCE
    /// flagged the live Copy as dead.
    #[test]
    fn dce_keeps_live_def_used_by_return() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::Copy,
                seq: seq(0x1000),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[imm]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[rax]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let removed = dead_code_elimination(&mut ssa);
        assert_eq!(removed, 0, "Copy of rax is live (Return reads rax)");
        let copy_live = ssa.ops.iter().any(|op| !op.dead && op.opcode == OpCode::Copy);
        assert!(copy_live, "the live Copy must survive DCE: {:?}", ssa.ops);
    }

    /// copy_propagation pushes a constant Copy's value through to the
    /// consuming op. Pre-fix the input ids never coincided with the
    /// output id, so the `*inp == out_id` substitution never fired.
    #[test]
    fn copy_propagation_replaces_const_use_downstream() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let imm_99 = VarnodeData::new(SpaceId(0), 99, 8);
        let imm_2 = VarnodeData::new(SpaceId(0), 2, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::Copy,
                seq: seq(0x1000),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[imm_99]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::IntMult,
                seq: seq(0x1001),
                output: Some(rbx),
                inputs: SmallVec::from_slice(&[rax, imm_2]),
            }]),
            make_lifted(0x1002, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1002),
                output: None,
                inputs: SmallVec::from_slice(&[rbx]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let propagated = copy_propagation(&mut ssa);
        assert!(propagated > 0, "rax=99 should propagate into the IntMult");
        let mult_op = ssa
            .ops
            .iter()
            .find(|op| !op.dead && op.opcode == OpCode::IntMult)
            .expect("IntMult op must still be present");
        let all_const = mult_op
            .inputs
            .iter()
            .all(|&id| ssa.varnodes[id as usize].data.space == SpaceId::CONST);
        assert!(
            all_const,
            "after propagation, IntMult inputs must all be CONST: {:?}",
            mult_op
        );
    }

    /// Same SSA value read twice (e.g., `xor rax, rax` after rax is set)
    /// must yield matching input VarIds so algebraic_simplification can
    /// fold `x ^ x` to 0. Pre-fix the two reads minted distinct varnodes
    /// and the optimization was silently skipped.
    #[test]
    fn xor_self_simplifies_after_def() {
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp {
                opcode: OpCode::Copy,
                seq: seq(0x1000, 0),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[imm]),
            },
            PcodeOp {
                opcode: OpCode::IntXor,
                seq: seq(0x1000, 1),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[rax, rax]),
            },
        ])];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let xor = ssa
            .ops
            .iter()
            .find(|op| op.opcode == OpCode::IntXor)
            .expect("IntXor op present");
        assert_eq!(
            xor.inputs[0], xor.inputs[1],
            "both reads of rax at the same version must share a VarId: {:?}",
            xor
        );
        let simplified = algebraic_simplification(&mut ssa);
        assert!(simplified > 0, "x ^ x should fold to 0");
    }
}
