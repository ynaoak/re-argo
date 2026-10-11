//! Float compares and their parity checks (WS85).
//!
//! `ucomiss a, b` sets ZF for "equal or unordered" and PF for "unordered" (a NaN), so the
//! lifter's ZF is `a == b || isnan(a) || isnan(b)`. Compilers test equality with the parity
//! check next to it: `a != b` is `jne T; jp T` (or `jp T; jne T`), `a == b` is `jp F; je T`,
//! and a `cmovne` + `cmovp` pair selects on `a != b`. Read one flag at a time, the decompiler
//! printed `if (!((a == b) || isnan(a) || isnan(b)) || isnan(a) || isnan(b))`.
//!
//! [`fold_parity_checks`] rewrites the lifted instructions before the CFG is built:
//! * `jne T; jp T` / `jp T; jne T`: the first jumps on `a != b` (FLOAT_NOTEQUAL, true for a
//!   NaN: the NaN case went to `T` through the parity jump anyway), the second jumps nowhere;
//! * `jp F; je T` / `jp F; jne T`: past the parity jump the operands are ordered, so ZF is
//!   `a == b`;
//! * `cmovne r, s; cmovp r, s` (either order): one select on `a != b`;
//! * `jbe` / `ja` / `setbe` / `cmova` …: `CF || ZF` is `CF || a == b` (CF, "below or
//!   unordered", already holds for a NaN), which the condition folding prints as `!(b < a)`.
//!
//! Only flags read in the straight line after the compare count: every instruction between
//! the compare and the reader writes no flag and neither operand, and none is the target of a
//! jump (where the flags could come from elsewhere).

use reargo_core::address::{Address, SpaceId};
use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use reargo_lift::LiftedInstruction;
use rustc_hash::FxHashSet;
use smallvec::SmallVec;

const CF: u64 = 0x201;
const PF: u64 = 0x202;
const ZF: u64 = 0x206;
/// The lifter's `a == b` temporary of a float compare.
const EQ_TMP: u64 = 0x54e;
/// The `a != b` this pass adds.
const NE_TMP: u64 = 0x2f80;
/// Instructions looked at after the compare.
const MAX_READERS: usize = 6;

fn is_reg(v: &VarnodeData, off: u64) -> bool {
    v.space == SpaceId::REGISTER && v.offset == off && v.size == 1
}

fn overlaps(x: &VarnodeData, w: &VarnodeData) -> bool {
    x.space == w.space && x.offset < w.offset + w.size as u64 && w.offset < x.offset + x.size as u64
}

/// `(a, b, eq)` of a float compare: its operands and its `a == b` temporary.
fn float_compare(insn: &LiftedInstruction) -> Option<(VarnodeData, VarnodeData, VarnodeData)> {
    let eq = insn.ops.iter().find(|o| {
        o.opcode == OpCode::FloatEqual
            && o.inputs.len() == 2
            && o.output.is_some_and(|v| v.space == SpaceId::UNIQUE && v.offset == EQ_TMP)
    })?;
    insn.ops.iter().any(|o| o.opcode == OpCode::BoolOr && o.output.is_some_and(|v| is_reg(&v, ZF))).then_some(())?;
    Some((eq.inputs[0], eq.inputs[1], eq.output?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Jump {
    /// `jp`
    P,
    /// `je`
    E,
    /// `jne`
    Ne,
}

/// A `jp` / `je` / `jne` and its target.
fn flag_jump(insn: &LiftedInstruction) -> Option<(Jump, u64)> {
    let br = insn.ops.last()?;
    if br.opcode != OpCode::CBranch || br.inputs.len() != 2 || br.inputs[0].space != SpaceId::RAM {
        return None;
    }
    let (target, cond) = (br.inputs[0].offset, br.inputs[1]);
    match insn.ops.as_slice() {
        [_] if is_reg(&cond, PF) => Some((Jump::P, target)),
        [_] if is_reg(&cond, ZF) => Some((Jump::E, target)),
        [neg, _] if neg.opcode == OpCode::BoolNegate && neg.output == Some(cond) && is_reg(&neg.inputs[0], ZF) => {
            Some((Jump::Ne, target))
        }
        _ => None,
    }
}

/// `cmovne` / `cmovp` and its operand text.
fn cmov(insn: &LiftedInstruction) -> Option<(&str, &str)> {
    let (m, rest) = insn.mnemonic.split_once(' ')?;
    matches!(m, "cmovne" | "cmovp").then_some((m, rest.trim()))
}

fn renumber(insn: &mut LiftedInstruction) {
    for (k, op) in insn.ops.iter_mut().enumerate() {
        op.seq = SeqNum::new(Address::new(SpaceId::RAM, insn.address), k as u32);
    }
}

/// `t = a != b` (a new op at `insn`).
fn not_equal(insn: &LiftedInstruction, a: VarnodeData, b: VarnodeData) -> (PcodeOp, VarnodeData) {
    let t = VarnodeData::new(SpaceId::UNIQUE, NE_TMP, 1);
    let op = PcodeOp {
        opcode: OpCode::FloatNotEqual,
        seq: SeqNum::new(Address::new(SpaceId::RAM, insn.address), 0),
        output: Some(t),
        inputs: SmallVec::from_slice(&[a, b]),
    };
    (op, t)
}

/// Rewrite the parity checks after float compares (see the module documentation). `targets`
/// are jump targets not visible as branch ops (jump-table cases). Returns the rewrites made.
pub fn fold_parity_checks(lifted: &mut [LiftedInstruction], targets: impl IntoIterator<Item = u64>) -> usize {
    if !lifted.iter().any(|i| float_compare(i).is_some()) {
        return 0;
    }
    let mut jumped_to: FxHashSet<u64> = targets.into_iter().collect();
    for op in lifted.iter().flat_map(|i| i.ops.iter()) {
        if matches!(op.opcode, OpCode::Branch | OpCode::CBranch)
            && let Some(t) = op.inputs.first()
            && t.space == SpaceId::RAM
        {
            jumped_to.insert(t.offset);
        }
    }
    let mut done = 0;
    for i in 0..lifted.len() {
        let Some((a, b, eq)) = float_compare(&lifted[i]) else { continue };
        // the instructions after the compare that still see its flags and operands
        let mut readers = Vec::new();
        let mut k = i + 1;
        while k < lifted.len() && readers.len() < MAX_READERS {
            let (prev, insn) = (&lifted[k - 1], &lifted[k]);
            if insn.address != prev.address + u64::from(prev.length) || jumped_to.contains(&insn.address) {
                break;
            }
            readers.push(k);
            let writes = |v: &VarnodeData| {
                (v.space == SpaceId::REGISTER && (0x200..0x210).contains(&v.offset))
                    || overlaps(&a, v)
                    || overlaps(&b, v)
                    || *v == eq
            };
            let ends = insn.ops.iter().any(|o| {
                o.output.as_ref().is_some_and(writes)
                    || matches!(o.opcode, OpCode::Branch | OpCode::BranchInd | OpCode::Call | OpCode::CallInd | OpCode::Return | OpCode::CallOther)
            });
            if ends {
                break;
            }
            k += 1;
        }
        let mut r = 0;
        while r < readers.len() {
            let x = readers[r];
            let next = readers.get(r + 1).copied();
            // jne T; jp T  /  jp T; jne T
            if let (Some((j1, t1)), Some(y)) = (flag_jump(&lifted[x]), next)
                && let Some((j2, t2)) = flag_jump(&lifted[y])
            {
                match (j1, j2) {
                    (Jump::Ne, Jump::P) | (Jump::P, Jump::Ne) if t1 == t2 => {
                        let (ne, t) = not_equal(&lifted[x], a, b);
                        let br = PcodeOp {
                            opcode: OpCode::CBranch,
                            seq: ne.seq,
                            output: None,
                            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId::RAM, t1, 8), t]),
                        };
                        lifted[x].ops = vec![ne, br];
                        renumber(&mut lifted[x]);
                        lifted[y].ops.clear();
                        done += 1;
                        r += 2;
                        continue;
                    }
                    // jp F; je T / jp F; jne T: ordered past the parity jump
                    (Jump::P, Jump::E | Jump::Ne) => {
                        for op in lifted[y].ops.iter_mut() {
                            for v in op.inputs.iter_mut() {
                                if is_reg(v, ZF) {
                                    *v = eq;
                                }
                            }
                        }
                        done += 1;
                        r += 2;
                        continue;
                    }
                    _ => {}
                }
            }
            // cmovne r, s; cmovp r, s (either order)
            if let (Some((m1, o1)), Some(y)) = (cmov(&lifted[x]), next)
                && let Some((m2, o2)) = cmov(&lifted[y])
                && m1 != m2
                && o1 == o2
            {
                let (ne_at, p_at) = if m1 == "cmovne" { (x, y) } else { (y, x) };
                let sel = lifted[ne_at].ops.iter().position(|o| o.opcode == OpCode::Select && is_reg(&o.inputs[0], ZF));
                let psel = lifted[p_at].ops.iter().position(|o| o.opcode == OpCode::Select && is_reg(&o.inputs[0], PF));
                if let (Some(s), Some(ps)) = (sel, psel) {
                    let (ne, t) = not_equal(&lifted[ne_at], a, b);
                    let op = &mut lifted[ne_at].ops[s];
                    // cmovne = SELECT(ZF, dst, src): on `a != b` it is SELECT(ne, src, dst)
                    op.inputs = SmallVec::from_slice(&[t, op.inputs[2], op.inputs[1]]);
                    lifted[ne_at].ops.insert(s, ne);
                    renumber(&mut lifted[ne_at]);
                    // (its other ops only re-derive the views of the same destination)
                    let _ = ps;
                    lifted[p_at].ops.clear();
                    done += 1;
                    r += 2;
                    continue;
                }
            }
            // CF || ZF (jbe / ja / setbe / cmova …): CF already holds for a NaN
            let mut changed = false;
            for op in lifted[x].ops.iter_mut() {
                if op.opcode == OpCode::BoolOr && op.inputs.len() == 2 {
                    let (c, z) = (op.inputs[0], op.inputs[1]);
                    if is_reg(&c, CF) && is_reg(&z, ZF) {
                        op.inputs[1] = eq;
                        changed = true;
                    } else if is_reg(&z, CF) && is_reg(&c, ZF) {
                        op.inputs[0] = eq;
                        changed = true;
                    }
                }
            }
            done += usize::from(changed);
            r += 1;
        }
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_lift::x86::X86Lifter;
    use reargo_lift::PcodeLift;
    use reargo_loader::memory::{Memory, MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn lift(code: &[u8]) -> Vec<LiftedInstruction> {
        let mut mem = Memory::new(SpaceId(1), reargo_core::address::Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: 0x1000,
            size: code.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(code)),
        });
        X86Lifter::new_64().lift_range(&mem, 0x1000, 16).unwrap()
    }

    #[test]
    fn jne_jp_to_one_target_is_one_not_equal_jump() {
        // ucomiss xmm0, xmm1; jne +2; jp +0; ret; ret
        let mut l = lift(&[0x0f, 0x2e, 0xc1, 0x75, 0x03, 0x7a, 0x01, 0xc3, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        assert_eq!(l[1].ops[0].opcode, OpCode::FloatNotEqual);
        assert!(l[2].ops.is_empty(), "{:?}", l[2].ops);
    }

    #[test]
    fn a_jump_target_between_keeps_the_flags() {
        // the jp is also reached from elsewhere: nothing changes
        let mut l = lift(&[0x0f, 0x2e, 0xc1, 0x75, 0x03, 0x7a, 0x01, 0xc3, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, [0x1005]), 0);
    }

    #[test]
    fn jbe_reads_equal_not_the_unordered_zf() {
        // ucomiss xmm0, xmm1; jbe +0; ret
        let mut l = lift(&[0x0f, 0x2e, 0xc1, 0x76, 0x00, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        let or = l[1].ops.iter().find(|o| o.opcode == OpCode::BoolOr).unwrap();
        assert_eq!(or.inputs[1].offset, EQ_TMP);
    }
}
