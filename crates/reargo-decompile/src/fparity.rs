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
//! * `jne F; jnp T` with `F` right after the `jnp` (WS87, jt 0x414c4d0): `T` exactly when
//!   `a == b` — the first jumps there on FLOAT_EQUAL (false for a NaN), the second goes;
//! * WS88: the pair with instructions between the jumps (they run only when the first does
//!   not jump, so the two cannot become one): `jne T; …; jp T'` — the `jne` jumps on "ordered
//!   and not equal", `a < b || b < a`, the `jp` on `isnan(a) || isnan(b)`; `jp F; …; je T` /
//!   `jne T` — past the parity jump ZF is `a == b`;
//! * `cmovne r, s; cmovp r, s` (either order): one select on `a != b`;
//! * `jbe` / `ja` / `setbe` / `cmova` …: `CF || ZF` is `CF || a == b` (CF, "below or
//!   unordered", already holds for a NaN), which the condition folding prints as `!(b < a)`;
//! * `ucomisd x, x`: PF is `isnan(x)` (WS86);
//! * `setnp r1; sete r2; and r2, r1` (either order of the sets / of the `and`'s operands): the
//!   `and` writes `a == b` (WS86); `setp r1; setne r2; or r2, r1` writes `a != b`.
//!
//! Only flags read in the straight line after the compare count: every instruction between
//! the compare and the reader writes no flag, and none is the target of a jump (where the
//! flags could come from elsewhere). A rewrite that compares the operands again at the reader
//! also needs them unchanged up to it; one that reads the compare's own `a == b` (`CF || ZF`,
//! ZF past the parity jump) does not (WS88: `ucomiss xmm1, xmm0; …; andps xmm1, xmm2; …; jbe`).

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
/// The `a < b`, `b < a` and their `||` it adds for an ordered `!=` (WS88).
const LT_TMP: u64 = 0x2f90;
/// Instructions looked at after the compare.
const MAX_READERS: usize = 12;

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
    /// `jnp` (WS87)
    Np,
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
        [neg, _] if neg.opcode == OpCode::BoolNegate && neg.output == Some(cond) && is_reg(&neg.inputs[0], PF) => {
            Some((Jump::Np, target))
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

/// The ops of a jump to `target` on "ordered and not equal" (`a < b || b < a`, false for a
/// NaN) at `insn` (WS88).
fn ordered_not_equal_jump(insn: &LiftedInstruction, a: VarnodeData, b: VarnodeData, target: u64) -> Vec<PcodeOp> {
    let t = |k: u64| VarnodeData::new(SpaceId::UNIQUE, LT_TMP + k, 1);
    let op = |opcode: OpCode, output: Option<VarnodeData>, inputs: &[VarnodeData]| PcodeOp {
        opcode,
        seq: SeqNum::new(Address::new(SpaceId::RAM, insn.address), 0),
        output,
        inputs: SmallVec::from_slice(inputs),
    };
    vec![
        op(OpCode::FloatLess, Some(t(0)), &[a, b]),
        op(OpCode::FloatLess, Some(t(1)), &[b, a]),
        op(OpCode::BoolOr, Some(t(2)), &[t(0), t(1)]),
        op(OpCode::CBranch, None, &[VarnodeData::new(SpaceId::RAM, target, 8), t(2)]),
    ]
}

/// The ops of a jump to `target` on `isnan(a) || isnan(b)` (`negated`: on neither) computed at
/// `insn` (WS88): a parity jump away from its compare reads the operands, not the flag.
fn unordered_jump(insn: &LiftedInstruction, a: VarnodeData, b: VarnodeData, target: u64, negated: bool) -> Vec<PcodeOp> {
    let t = |k: u64| VarnodeData::new(SpaceId::UNIQUE, LT_TMP + k, 1);
    let op = |opcode: OpCode, output: Option<VarnodeData>, inputs: &[VarnodeData]| PcodeOp {
        opcode,
        seq: SeqNum::new(Address::new(SpaceId::RAM, insn.address), 0),
        output,
        inputs: SmallVec::from_slice(inputs),
    };
    let mut ops = vec![op(OpCode::FloatNan, Some(t(3)), &[a])];
    let mut c = t(3);
    if a != b {
        ops.push(op(OpCode::FloatNan, Some(t(4)), &[b]));
        ops.push(op(OpCode::BoolOr, Some(t(5)), &[t(3), t(4)]));
        c = t(5);
    }
    if negated {
        ops.push(op(OpCode::BoolNegate, Some(t(6)), &[c]));
        c = t(6);
    }
    ops.push(op(OpCode::CBranch, None, &[VarnodeData::new(SpaceId::RAM, target, 8), c]));
    ops
}

/// `(register, reads ZF (else PF), negated)` of a `setcc` of ZF / PF into a byte register.
fn flag_set(insn: &LiftedInstruction) -> Option<(VarnodeData, bool, bool)> {
    let m = insn.mnemonic.split_whitespace().next()?;
    let (zf, neg) = match m {
        "sete" | "setz" => (true, false),
        "setne" | "setnz" => (true, true),
        "setp" | "setpe" => (false, false),
        "setnp" | "setpo" => (false, true),
        _ => return None,
    };
    let w = insn.ops.iter().find(|o| o.opcode == OpCode::Copy && o.output.is_some_and(|v| v.space == SpaceId::REGISTER && v.size == 1))?;
    Some((w.output?, zf, neg))
}

/// `setnp; sete; and` / `setp; setne; or` among `readers` (see the module documentation): the
/// `and` / `or` writes `a == b` / `a != b`. Returns whether it rewrote one.
fn fold_set_pair(lifted: &mut [LiftedInstruction], readers: &[usize], a: VarnodeData, b: VarnodeData, eq: VarnodeData) -> bool {
    let Some(&z) = readers.last() else { return false };
    let combine = lifted[z].ops.iter().position(|o| {
        matches!(o.opcode, OpCode::IntAnd | OpCode::IntOr)
            && o.inputs.len() == 2
            && o.output.is_some_and(|v| v.space == SpaceId::REGISTER && v.size == 1)
    });
    let Some(c) = combine else { return false };
    let (op, ins) = (lifted[z].ops[c].opcode, lifted[z].ops[c].inputs.clone());
    // the two sets, each the last write of its register before the combination
    let sets: Vec<(usize, VarnodeData, bool, bool)> =
        readers[..readers.len() - 1].iter().filter_map(|&k| flag_set(&lifted[k]).map(|(r, zf, neg)| (k, r, zf, neg))).collect();
    let find = |r: &VarnodeData| sets.iter().rev().find(|s| s.1 == *r).copied();
    let (Some(s1), Some(s2)) = (find(&ins[0]), find(&ins[1])) else { return false };
    if s1.1 == s2.1 {
        return false;
    }
    let (zs, ps) = if s1.2 { (s1, s2) } else { (s2, s1) };
    if !zs.2 || ps.2 {
        return false;
    }
    // and: ZF && !PF (sete, setnp) = a == b; or: !ZF || PF (setne, setp) = a != b
    let want = match op {
        OpCode::IntAnd => !zs.3 && ps.3,
        _ => zs.3 && !ps.3,
    };
    if !want {
        return false;
    }
    // nothing after a set writes its register before the combination; the one the combination
    // writes is not read in between either (it now holds the comparison from its set on)
    let dst = lifted[z].ops[c].output.expect("checked");
    let (ds, os) = if dst == zs.1 { (zs, ps) } else { (ps, zs) };
    if dst != ds.1 || ds.0 >= z || os.0 >= z {
        return false;
    }
    let between = |from: usize| lifted[from + 1..z].iter().flat_map(|i| i.ops.iter());
    if between(os.0).any(|o| o.output.is_some_and(|w| overlaps(&os.1, &w)))
        || between(ds.0).any(|o| o.output.is_some_and(|w| overlaps(&ds.1, &w)) || o.inputs.iter().any(|i| overlaps(&ds.1, i)))
    {
        return false;
    }
    // the set of the destination writes the comparison; the combination goes
    let k = ds.0;
    let w = lifted[k].ops.iter().position(|o| o.opcode == OpCode::Copy && o.output == Some(dst)).expect("flag_set found it");
    if op == OpCode::IntAnd {
        lifted[k].ops[w].inputs = SmallVec::from_slice(&[eq]);
    } else {
        let (ne, t) = not_equal(&lifted[k], a, b);
        lifted[k].ops[w].inputs = SmallVec::from_slice(&[t]);
        lifted[k].ops.insert(w, ne);
    }
    renumber(&mut lifted[k]);
    lifted[z].ops.remove(c);
    renumber(&mut lifted[z]);
    true
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
        // `ucomisd x, x` (a NaN test): PF is `isnan(x)`, not `isnan(x) || isnan(x)` (WS86)
        if a == b
            && let Some(or) = lifted[i].ops.iter_mut().find(|o| o.opcode == OpCode::BoolOr && o.output.is_some_and(|v| is_reg(&v, PF)))
        {
            or.opcode = OpCode::Copy;
            or.inputs.truncate(1);
            done += 1;
        }
        // the instructions after the compare that still see its flags; the first `intact` of
        // them also see its operands
        let mut readers = Vec::new();
        let mut intact = usize::MAX;
        let mut k = i + 1;
        while k < lifted.len() && readers.len() < MAX_READERS {
            let (prev, insn) = (&lifted[k - 1], &lifted[k]);
            if insn.address != prev.address + u64::from(prev.length) || jumped_to.contains(&insn.address) {
                break;
            }
            readers.push(k);
            let writes = |v: &VarnodeData| (v.space == SpaceId::REGISTER && (0x200..0x210).contains(&v.offset)) || *v == eq;
            let ends = insn.ops.iter().any(|o| {
                o.output.as_ref().is_some_and(writes)
                    || matches!(o.opcode, OpCode::Branch | OpCode::BranchInd | OpCode::Call | OpCode::CallInd | OpCode::Return | OpCode::CallOther)
            });
            if ends {
                break;
            }
            if intact == usize::MAX && insn.ops.iter().any(|o| o.output.as_ref().is_some_and(|v| overlaps(&a, v) || overlaps(&b, v))) {
                intact = readers.len() - 1;
            }
            k += 1;
        }
        if fold_set_pair(lifted, &readers[..intact.min(readers.len())], a, b, eq) {
            done += 1;
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
                    (Jump::Ne, Jump::P) | (Jump::P, Jump::Ne) if t1 == t2 && r + 1 < intact => {
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
                    // jne F; jnp T, F right after the jnp: to T exactly on `a == b` (WS87)
                    (Jump::Ne, Jump::Np) if t1 == lifted[y].address + u64::from(lifted[y].length) => {
                        let br = PcodeOp {
                            opcode: OpCode::CBranch,
                            seq: SeqNum::new(Address::new(SpaceId::RAM, lifted[x].address), 0),
                            output: None,
                            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId::RAM, t2, 8), eq]),
                        };
                        lifted[x].ops = vec![br];
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
            // the pair with instructions between the jumps (WS88): the next jump of the readers,
            // with nothing but straight-line code before it
            if let Some((j1, t1)) = flag_jump(&lifted[x])
                && let Some(&y) = readers[r + 1..].iter().find(|&&k| lifted[k].ops.iter().any(|o| o.opcode == OpCode::CBranch))
                && Some(y) != next
                && let Some((j2, t2)) = flag_jump(&lifted[y])
            {
                match (j1, j2) {
                    // jne T; …; jp / jnp: the jne on `a < b || b < a`, the parity jump on the
                    // operands' NaN test
                    (Jump::Ne, Jump::P | Jump::Np) if readers.iter().position(|&k| k == y).is_some_and(|q| q < intact) => {
                        lifted[x].ops = ordered_not_equal_jump(&lifted[x], a, b, t1);
                        renumber(&mut lifted[x]);
                        lifted[y].ops = unordered_jump(&lifted[y], a, b, t2, j2 == Jump::Np);
                        renumber(&mut lifted[y]);
                        done += 1;
                    }
                    // jp F; …; je / jne: ordered past the parity jump
                    (Jump::P, Jump::E | Jump::Ne) => {
                        for op in lifted[y].ops.iter_mut() {
                            for v in op.inputs.iter_mut() {
                                if is_reg(v, ZF) {
                                    *v = eq;
                                }
                            }
                        }
                        done += 1;
                    }
                    _ => {}
                }
                r += 1;
                continue;
            }
            // cmovne r, s; cmovp r, s (either order)
            if let (Some((m1, o1)), Some(y)) = (cmov(&lifted[x]), next)
                && r + 1 < intact
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
    fn setnp_sete_and_is_equal() {
        // ucomiss xmm1, xmm0; setnp dl; sete al; and al, dl; ret
        let mut l = lift(&[0x0f, 0x2e, 0xc8, 0x0f, 0x9b, 0xc2, 0x0f, 0x94, 0xc0, 0x20, 0xd0, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        assert_eq!(l[2].ops[0].opcode, OpCode::Copy);
        assert_eq!(l[2].ops[0].inputs[0].offset, EQ_TMP);
        assert!(!l[3].ops.iter().any(|o| o.opcode == OpCode::IntAnd));
        // setp; setne; or: not equal
        let mut l = lift(&[0x0f, 0x2e, 0xc8, 0x0f, 0x9a, 0xc2, 0x0f, 0x95, 0xc0, 0x08, 0xd0, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        assert!(l[2].ops.iter().any(|o| o.opcode == OpCode::FloatNotEqual));
        assert!(!l[3].ops.iter().any(|o| o.opcode == OpCode::IntOr));
        // setp; sete; and is no comparison of its own: unchanged
        let mut l = lift(&[0x0f, 0x2e, 0xc8, 0x0f, 0x9a, 0xc2, 0x0f, 0x94, 0xc0, 0x20, 0xd0, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 0);
    }

    /// WS87: `jne F; jnp T` with `F` right after it is one jump to `T` on `a == b`.
    #[test]
    fn jne_past_a_jnp_is_one_equal_jump() {
        // ucomisd xmm0, xmm1; jne +2 (past the jnp); jnp +1; ret; ret
        let mut l = lift(&[0x66, 0x0f, 0x2e, 0xc1, 0x75, 0x02, 0x7b, 0x01, 0xc3, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        assert_eq!(l[1].ops.len(), 1);
        let br = &l[1].ops[0];
        assert_eq!((br.opcode, br.inputs[0].offset, br.inputs[1].offset), (OpCode::CBranch, 0x1009, EQ_TMP));
        assert!(l[2].ops.is_empty());
        // the jne elsewhere: unchanged
        let mut l = lift(&[0x66, 0x0f, 0x2e, 0xc1, 0x75, 0x03, 0x7b, 0x01, 0xc3, 0xc3, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 0);
    }

    /// WS88: `jne T; mov; jp T`: the `mov` runs only when the jne does not jump, so the jne
    /// jumps on "ordered and not equal" and the jp stays; `jp F; mov; jne T`: the jne reads
    /// `a == b`.
    #[test]
    fn parity_pair_with_an_instruction_between() {
        // ucomiss xmm0, xmm1; jne +5; mov eax, edi; jp +0; ret; ret
        let mut l = lift(&[0x0f, 0x2e, 0xc1, 0x75, 0x05, 0x89, 0xf8, 0x7a, 0x01, 0xc3, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        let ops: Vec<OpCode> = l[1].ops.iter().map(|o| o.opcode).collect();
        assert_eq!(ops, [OpCode::FloatLess, OpCode::FloatLess, OpCode::BoolOr, OpCode::CBranch]);
        assert_eq!(l[1].ops[3].inputs[0].offset, 0x100a);
        let ops: Vec<OpCode> = l[3].ops.iter().map(|o| o.opcode).collect();
        assert_eq!(ops, [OpCode::FloatNan, OpCode::FloatNan, OpCode::BoolOr, OpCode::CBranch]);
        // ucomiss xmm0, xmm1; jp +5; mov eax, edi; jne +0; ret; ret
        let mut l = lift(&[0x0f, 0x2e, 0xc1, 0x7a, 0x05, 0x89, 0xf8, 0x75, 0x01, 0xc3, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        assert!(l[3].ops.iter().any(|o| o.inputs.iter().any(|v| v.offset == EQ_TMP)), "{:?}", l[3].ops);
        // a compare between: no pair
        let mut l = lift(&[0x0f, 0x2e, 0xc1, 0x75, 0x05, 0x39, 0xf8, 0x7a, 0x01, 0xc3, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 0);
    }

    /// WS88: `jbe` after an operand is written still reads the compare's `a == b`; a `jne; jp`
    /// pair there is left alone (it would compare the new value).
    #[test]
    fn jbe_after_an_operand_write_reads_equal() {
        // ucomiss xmm1, xmm0; andps xmm1, xmm2; jbe +0; ret
        let mut l = lift(&[0x0f, 0x2e, 0xc8, 0x0f, 0x54, 0xca, 0x76, 0x00, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        let or = l[2].ops.iter().find(|o| o.opcode == OpCode::BoolOr).unwrap();
        assert_eq!(or.inputs[1].offset, EQ_TMP);
        // ucomiss xmm0, xmm1; movaps xmm0, xmm2; jne +2; jp +0; ret; ret
        let mut l = lift(&[0x0f, 0x2e, 0xc1, 0x0f, 0x28, 0xc2, 0x75, 0x03, 0x7a, 0x01, 0xc3, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 0);
        assert!(!l[2].ops.iter().any(|o| o.opcode == OpCode::FloatNotEqual));
    }

    #[test]
    fn nan_test_of_one_register_is_one_isnan() {
        // ucomisd xmm0, xmm0; jp +0; ret
        let mut l = lift(&[0x66, 0x0f, 0x2e, 0xc0, 0x7a, 0x00, 0xc3]);
        assert_eq!(fold_parity_checks(&mut l, []), 1);
        let pf = l[0].ops.iter().find(|o| o.output.is_some_and(|v| is_reg(&v, PF))).unwrap();
        assert_eq!((pf.opcode, pf.inputs.len()), (OpCode::Copy, 1));
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
