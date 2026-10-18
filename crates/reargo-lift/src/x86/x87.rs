//! x87 FPU instructions (WS89), lifted with a static register stack.
//!
//! The x87 registers are a stack whose top (`TOP`) moves at run time, so `ST(i)` names a
//! different register after each push or pop. A compiler keeps the number of values on the
//! stack (its *depth*) the same at every point of a function whatever the path, so
//! [`X86Lifter::lift_range`] works the depth out for each instruction ([`flow`]) and the lift
//! names the values by their place from the bottom of the stack: the first value pushed is
//! `st0` (register [`ST_BASE`]), the next `st1`, … — `ST(i)` at depth `d` is slot `d - 1 - i`.
//! A push or pop therefore moves no value (Ghidra shifts all eight registers instead), and each
//! value keeps one name for as long as it is on the stack.
//!
//! Values are 80-bit floats (`long double`, size-10 FLOAT_* p-code; the emulator computes them
//! as the x87 does). Memory operands convert exactly (`fld dword` is FLOAT2FLOAT, `fild` is
//! INT2FLOAT); stores round to nearest. `fucomi` / `fcomi` set ZF / PF / CF as `ucomisd` does,
//! `fcom` / `fucom` / `ftst` set the condition codes C0 / C2 / C3 that `fnstsw` puts into `ax`
//! (with `TOP`, known from the depth) for `sahf` or a `test ah`. `fistp` rounds as the control
//! word says: [`flow`] follows its rounding control through the usual
//! `fnstcw [m]; or ax, 0xc00; mov [m2], ax; fldcw [m2]; fistp; fldcw [m]` (truncation, then
//! the saved word back); a known truncation lifts to FLOAT_TRUNC, anything else to
//! `fist(x, fpucw)`. Arithmetic always rounds to nearest at 64-bit precision (the control word's
//! precision and rounding are not applied to it).
//!
//! An instruction whose depth is not known (an inconsistent merge, a stack overflow or
//! underflow, code reached only through an unrecovered jump) stays `__unmodeled_insn()`.

use super::*;
use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use rustc_hash::FxHashMap as HashMap;

/// The stack slots `st0`..`st7` (10 bytes each, 0x10 apart).
pub(crate) const ST_BASE: u64 = 0x1100;
/// The control word (2 bytes).
pub(crate) const FPUCW: u64 = 0x10a0;
/// The condition codes C0..C3 of the status word (1 byte each).
pub(crate) const FPU_C0: u64 = 0x10a8;
pub(crate) const FPU_C1: u64 = 0x10a9;
pub(crate) const FPU_C2: u64 = 0x10aa;
pub(crate) const FPU_C3: u64 = 0x10ab;

/// Temporaries of these lifts.
const TMP_BASE: u64 = 0x3800;

/// The 80-bit constants of `fldpi` … `fldln2` (round to nearest): (sign+exponent, significand).
const PI: (u64, u64) = (0x4000, 0xc90f_daa2_2168_c235);
const L2T: (u64, u64) = (0x4000, 0xd49a_784b_cd1b_8afe);
const L2E: (u64, u64) = (0x3fff, 0xb8aa_3b29_5c17_f0bc);
const LG2: (u64, u64) = (0x3ffd, 0x9a20_9a84_fbcf_f799);
const LN2: (u64, u64) = (0x3ffe, 0xb172_17f7_d1cf_79ac);

/// Slot `k` from the bottom of the stack.
pub(crate) fn slot(k: u8) -> VarnodeData {
    reg(ST_BASE + 0x10 * u64::from(k), 10)
}

/// What [`flow`] knows before an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X87Ctx {
    /// values on the stack
    pub depth: u8,
    /// the control word's rounding control (0 nearest, 1 down, 2 up, 3 toward zero), if known
    pub rc: Option<u8>,
}

/// What an instruction does to the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    NotX87,
    /// reads `needs` values from the top, then pops `pops` and pushes `pushes`
    Stack { needs: u8, pops: u8, pushes: u8 },
    /// `fninit` / `fnsave`: the stack is empty after it
    Reset,
    /// changes the stack in a way not followed (`fincstp`, `frstor`, …)
    Unknown,
}

fn st_index(r: Register) -> Option<u8> {
    let (n, s0) = (r as u32, Register::ST0 as u32);
    (s0..s0 + 8).contains(&n).then(|| (n - s0) as u8)
}

/// The deepest `ST(i)` an instruction names (0 when none).
fn max_st(insn: &Instruction) -> u8 {
    (0..insn.op_count())
        .filter(|&i| insn.op_kind(i) == OpKind::Register)
        .filter_map(|i| st_index(insn.op_register(i)))
        .max()
        .unwrap_or(0)
}

fn has_memory(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|i| insn.op_kind(i) == OpKind::Memory)
}

pub(crate) fn kind(insn: &Instruction) -> Kind {
    use Mnemonic::*;
    // (the deepest register named, read only for an x87 instruction: most are none)
    let i = || max_st(insn);
    let s = |needs: u8, pops: u8, pushes: u8| Kind::Stack { needs, pops, pushes };
    let top = || (i() + 1).max(1);
    match insn.mnemonic() {
        Fld if has_memory(insn) => s(0, 0, 1),
        Fld => s(i() + 1, 0, 1),
        Fild | Fbld | Fldz | Fld1 | Fldpi | Fldl2e | Fldl2t | Fldlg2 | Fldln2 => s(0, 0, 1),
        Fst | Fist => s(top(), 0, 0),
        Fstp | Fstpnce | Fistp | Fisttp | Fbstp => s(top(), 1, 0),
        Fxch => s(top(), 0, 0),
        Fadd | Fsub | Fsubr | Fmul | Fdiv | Fdivr => s(top(), 0, 0),
        Faddp | Fsubp | Fsubrp | Fmulp | Fdivp | Fdivrp => s(top().max(2), 1, 0),
        Fiadd | Fisub | Fisubr | Fimul | Fidiv | Fidivr => s(1, 0, 0),
        Fchs | Fabs | Fsqrt | Frndint | Fxam | Ftst | Fsin | Fcos | F2xm1 => s(1, 0, 0),
        Fptan | Fsincos | Fxtract => s(1, 0, 1),
        Fpatan | Fyl2x | Fyl2xp1 => s(2, 1, 0),
        Fscale | Fprem | Fprem1 => s(2, 0, 0),
        Fcom | Fucom | Ficom => s(if has_memory(insn) { 1 } else { top().max(2) }, 0, 0),
        Fcomp | Fucomp | Ficomp => s(if has_memory(insn) { 1 } else { top().max(2) }, 1, 0),
        Fcompp | Fucompp => s(2, 2, 0),
        Fcomi | Fucomi => s(top(), 0, 0),
        Fcomip | Fucomip => s(top(), 1, 0),
        Fcmovb | Fcmove | Fcmovbe | Fcmovu | Fcmovnb | Fcmovne | Fcmovnbe | Fcmovnu => s(top(), 0, 0),
        Ffreep => s(top(), 1, 0),
        Ffree | Fnstcw | Fstcw | Fldcw | Fnstsw | Fstsw | Wait | Fnop | Fnclex | Fclex | Fneni | Feni | Fndisi
        | Fdisi | Fnsetpm | Fsetpm | Fnstenv | Fstenv | Fxsave | Fxsave64 => s(0, 0, 0),
        Fninit | Finit | Fnsave | Fsave => Kind::Reset,
        Fincstp | Fdecstp | Frstor | Fldenv | Fxrstor | Fxrstor64 | Frstpm | Fstdw | Fstsg => Kind::Unknown,
        _ => Kind::NotX87,
    }
}

/// Emits the p-code of one instruction.
struct E<'a> {
    lifter: &'a X86Lifter,
    insn: &'a Instruction,
    ops: Vec<PcodeOp>,
    sb: u32,
    address: u64,
    next: u64,
}

impl E<'_> {
    fn put(&mut self, opcode: OpCode, output: Option<VarnodeData>, inputs: &[VarnodeData]) {
        self.ops.push(PcodeOp {
            opcode,
            seq: SeqNum::new(Address::new(RAM_SPACE, self.address), self.sb),
            output,
            inputs: SmallVec::from_slice(inputs),
        });
        self.sb += 1;
    }

    fn set(&mut self, opcode: OpCode, output: VarnodeData, inputs: &[VarnodeData]) {
        self.put(opcode, Some(output), inputs);
    }

    fn tmp(&mut self, opcode: OpCode, size: u32, inputs: &[VarnodeData]) -> VarnodeData {
        let out = unique(self.next, size);
        self.next += 0x10;
        self.set(opcode, out, inputs);
        out
    }

    fn address_of_memory(&mut self) -> Result<VarnodeData, LiftError> {
        self.lifter.compute_memory_address(self.insn, &mut self.ops, &mut self.sb, self.address)
    }

    /// The memory operand's value (`size` bytes).
    fn load(&mut self, size: u32) -> Result<VarnodeData, LiftError> {
        let a = self.address_of_memory()?;
        Ok(self.tmp(OpCode::Load, size, &[constant(RAM_SPACE.0 as u64, 4), a]))
    }

    fn store(&mut self, value: VarnodeData) -> Result<(), LiftError> {
        let a = self.address_of_memory()?;
        self.put(OpCode::Store, None, &[constant(RAM_SPACE.0 as u64, 4), a, value]);
        Ok(())
    }

    /// The memory operand as an 80-bit float (a float of its size, or an integer for `fild`,
    /// `fiadd`, …: `int`).
    fn load_ext(&mut self, int: bool) -> Result<VarnodeData, LiftError> {
        let size = self.insn.memory_size().size() as u32;
        let v = self.load(size)?;
        Ok(match (int, size) {
            (false, 10) => v,
            (false, _) => self.tmp(OpCode::FloatFloat2Float, 10, &[v]),
            (true, _) => self.tmp(OpCode::FloatInt2Float, 10, &[v]),
        })
    }

    /// The 80-bit constant (sign+exponent, significand).
    fn const80(&mut self, (hi, lo): (u64, u64)) -> VarnodeData {
        self.tmp(OpCode::Piece, 10, &[constant(hi, 2), constant(lo, 8)])
    }

    /// C0 / C2 / C3 (`fcom`) or CF / PF / ZF (`fcomi`) of comparing `a` with `b`: less or
    /// unordered, unordered, equal or unordered.
    fn compare(&mut self, a: VarnodeData, b: VarnodeData, flags: [u64; 3]) {
        let [less_f, unord_f, eq_f] = flags;
        let na = self.tmp(OpCode::FloatNan, 1, &[a]);
        let nb = self.tmp(OpCode::FloatNan, 1, &[b]);
        self.set(OpCode::BoolOr, reg(unord_f, 1), &[na, nb]);
        let ge = self.tmp(OpCode::FloatLessEqual, 1, &[b, a]);
        self.set(OpCode::BoolNegate, reg(less_f, 1), &[ge]);
        // (`fucomi`'s `a == b` in the temporary `ucomisd` uses: the decompiler's parity folding
        // finds a float compare by it — `jbe` reads `!(b < a)`)
        let eq = if eq_f == ZF_OFFSET { unique(0x54e, 1) } else { unique(self.next, 1) };
        self.next += 0x10;
        self.set(OpCode::FloatEqual, eq, &[a, b]);
        self.set(OpCode::BoolOr, reg(eq_f, 1), &[eq, reg(unord_f, 1)]);
    }

    fn unmodeled(&mut self) {
        self.put(OpCode::CallOther, None, &[constant(0, 4)]);
    }
}

impl X86Lifter {
    /// Lift an x87 instruction (`None` for another one). `ctx`: what [`flow`] found before it;
    /// without it only the instructions that do not touch the stack are lifted.
    pub(super) fn lift_x87(
        &self,
        insn: &Instruction,
        address: u64,
        ctx: Option<X87Ctx>,
    ) -> Option<Result<Vec<PcodeOp>, LiftError>> {
        let k = kind(insn);
        if k == Kind::NotX87 {
            return None;
        }
        let mut e = E { lifter: self, insn, ops: Vec::new(), sb: 0, address, next: TMP_BASE };
        Some(self.x87_ops(&mut e, k, ctx).map(|()| e.ops))
    }

    fn x87_ops(&self, e: &mut E<'_>, k: Kind, ctx: Option<X87Ctx>) -> Result<(), LiftError> {
        use Mnemonic::*;
        let insn = e.insn;
        let m = insn.mnemonic();
        // the control word, and the instructions that change nothing modelled
        match m {
            Fnstcw | Fstcw => return e.store(reg(FPUCW, 2)),
            Fldcw => {
                let v = e.load(2)?;
                e.set(OpCode::Copy, reg(FPUCW, 2), &[v]);
                return Ok(());
            }
            Fninit | Finit => {
                e.set(OpCode::Copy, reg(FPUCW, 2), &[constant(0x37f, 2)]);
                return Ok(());
            }
            Wait | Fnop | Fnclex | Fclex | Ffree | Fneni | Feni | Fndisi | Fdisi | Fnsetpm | Fsetpm => return Ok(()),
            _ => {}
        }
        let (Some(c), Kind::Stack { needs, pops, pushes }) = (ctx, k) else {
            e.unmodeled();
            return Ok(());
        };
        let d = c.depth;
        if needs > d || d - pops + pushes > 8 {
            e.unmodeled();
            return Ok(());
        }
        // ST(i)
        let st = |i: u8| slot(d - 1 - i);
        let op_st = |n: u32| (n < insn.op_count() && insn.op_kind(n) == OpKind::Register).then(|| st_index(insn.op_register(n))).flatten();
        let memory = has_memory(insn);
        let new = slot(d);
        match m {
            Fld => {
                let v = if memory { e.load_ext(false)? } else { st(max_st(insn)) };
                e.set(OpCode::Copy, new, &[v]);
            }
            Fild => {
                let v = e.load_ext(true)?;
                e.set(OpCode::Copy, new, &[v]);
            }
            Fldz => e.set(OpCode::FloatFloat2Float, new, &[constant(0, 8)]),
            Fld1 => e.set(OpCode::FloatFloat2Float, new, &[constant(1.0f64.to_bits(), 8)]),
            Fldpi | Fldl2t | Fldl2e | Fldlg2 | Fldln2 => {
                let k = match m {
                    Fldpi => PI,
                    Fldl2t => L2T,
                    Fldl2e => L2E,
                    Fldlg2 => LG2,
                    _ => LN2,
                };
                let v = e.const80(k);
                e.set(OpCode::Copy, new, &[v]);
            }
            Fst | Fstp | Fstpnce if memory => {
                let size = insn.memory_size().size() as u32;
                let v = if size == 10 { st(0) } else { e.tmp(OpCode::FloatFloat2Float, size, &[st(0)]) };
                e.store(v)?;
            }
            Fst | Fstp | Fstpnce => {
                let i = max_st(insn);
                if i != 0 {
                    e.set(OpCode::Copy, st(i), &[st(0)]);
                }
            }
            Fist | Fistp | Fisttp => {
                let size = insn.memory_size().size() as u32;
                let v = if m == Fisttp || c.rc == Some(3) {
                    e.tmp(OpCode::FloatTrunc, size, &[st(0)])
                } else {
                    let tag = constant(reargo_core::pcode::intrinsic::FIST, 8);
                    e.tmp(OpCode::CallOther, size, &[tag, st(0), reg(FPUCW, 2)])
                };
                e.store(v)?;
            }
            Fxch => {
                let i = max_st(insn);
                if i != 0 {
                    let t = e.tmp(OpCode::Copy, 10, &[st(0)]);
                    e.set(OpCode::Copy, st(0), &[st(i)]);
                    e.set(OpCode::Copy, st(i), &[t]);
                }
            }
            Fadd | Faddp | Fiadd | Fsub | Fsubp | Fisub | Fsubr | Fsubrp | Fisubr | Fmul | Fmulp | Fimul | Fdiv
            | Fdivp | Fidiv | Fdivr | Fdivrp | Fidivr => {
                let int = matches!(m, Fiadd | Fisub | Fisubr | Fimul | Fidiv | Fidivr);
                let (dst, src) = if memory {
                    (st(0), e.load_ext(int)?)
                } else {
                    (st(op_st(0).unwrap_or(1)), st(op_st(1).unwrap_or(0)))
                };
                let (opcode, reverse) = match m {
                    Fadd | Faddp | Fiadd => (OpCode::FloatAdd, false),
                    Fsub | Fsubp | Fisub => (OpCode::FloatSub, false),
                    Fsubr | Fsubrp | Fisubr => (OpCode::FloatSub, true),
                    Fmul | Fmulp | Fimul => (OpCode::FloatMult, false),
                    Fdiv | Fdivp | Fidiv => (OpCode::FloatDiv, false),
                    _ => (OpCode::FloatDiv, true),
                };
                let inputs = if reverse { [src, dst] } else { [dst, src] };
                e.set(opcode, dst, &inputs);
            }
            Fchs => e.set(OpCode::FloatNeg, st(0), &[st(0)]),
            Fabs => e.set(OpCode::FloatAbs, st(0), &[st(0)]),
            Fsqrt => e.set(OpCode::FloatSqrt, st(0), &[st(0)]),
            Fcomi | Fcomip | Fucomi | Fucomip => {
                let b = st(max_st(insn));
                e.compare(st(0), b, [CF_OFFSET, PF_OFFSET, ZF_OFFSET]);
                // OF, SF and AF are cleared
                e.set(OpCode::Copy, reg(OF_OFFSET, 1), &[constant(0, 1)]);
                e.set(OpCode::Copy, reg(SF_OFFSET, 1), &[constant(0, 1)]);
            }
            Fcom | Fcomp | Fucom | Fucomp | Ficom | Ficomp | Fcompp | Fucompp | Ftst => {
                let b = match m {
                    Ftst => e.tmp(OpCode::FloatFloat2Float, 10, &[constant(0, 8)]),
                    _ if memory => e.load_ext(matches!(m, Ficom | Ficomp))?,
                    _ => st(max_st(insn).max(1)),
                };
                e.compare(st(0), b, [FPU_C0, FPU_C2, FPU_C3]);
                e.set(OpCode::Copy, reg(FPU_C1, 1), &[constant(0, 1)]);
            }
            Fcmovb | Fcmove | Fcmovbe | Fcmovu | Fcmovnb | Fcmovne | Fcmovnbe | Fcmovnu => {
                use iced_x86::ConditionCode as C;
                let cc = match m {
                    Fcmovb => C::b,
                    Fcmove => C::e,
                    Fcmovbe => C::be,
                    Fcmovu => C::p,
                    Fcmovnb => C::ae,
                    Fcmovne => C::ne,
                    Fcmovnbe => C::a,
                    _ => C::np,
                };
                let cond = self.cc_condition(cc, &mut e.ops, &mut e.sb, e.address).unwrap_or(constant(0, 1));
                let src = st(max_st(insn));
                e.set(OpCode::Select, st(0), &[cond, src, st(0)]);
            }
            // the status word: C0 (bit 8), C1 (9), C2 (10), TOP (11-13), C3 (14); the exception
            // flags (bits 0-7) are not modelled (0)
            Fnstsw | Fstsw => {
                let top = u64::from((8 - d) & 7);
                let mut w = constant(top << 11, 2);
                for (flag, bit) in [(FPU_C0, 8), (FPU_C1, 9), (FPU_C2, 10), (FPU_C3, 14)] {
                    let z = e.tmp(OpCode::IntZExt, 2, &[reg(flag, 1)]);
                    let b = e.tmp(OpCode::IntLeft, 2, &[z, constant(bit, 4)]);
                    w = e.tmp(OpCode::IntOr, 2, &[w, b]);
                }
                if memory {
                    e.store(w)?;
                } else {
                    e.set(OpCode::Copy, rax(2), &[w]);
                }
            }
            // popping, nothing else modelled
            Ffreep => {}
            _ => e.unmodeled(),
        }
        Ok(())
    }
}

/// What [`flow`] found for a range of instructions.
pub(crate) struct Flow {
    /// before each instruction (None: not known)
    pub ctx: Vec<Option<X87Ctx>>,
    /// a call whose callee returned a `long double` on the stack: the slot it defines
    pub call_result: Vec<Option<u8>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum St {
    Unset,
    Known(X87Ctx),
    Conflict,
}

fn join(a: St, b: St) -> St {
    match (a, b) {
        (St::Unset, x) | (x, St::Unset) => x,
        (St::Known(x), St::Known(y)) if x.depth == y.depth => {
            St::Known(X87Ctx { depth: x.depth, rc: if x.rc == y.rc { x.rc } else { None } })
        }
        _ => St::Conflict,
    }
}

/// How control leaves an instruction (from its p-code).
enum Exit {
    Next,
    Jump(u64),
    Cond(u64),
    Call,
    End,
    /// an indirect jump (a jump table: its cases are not known here)
    Indirect,
}

fn exit_of(insn: &LiftedInstruction) -> Exit {
    for op in &insn.ops {
        let target = || op.inputs.first().filter(|v| v.space == RAM_SPACE).map(|v| v.offset);
        match op.opcode {
            OpCode::Return => return Exit::End,
            OpCode::BranchInd => return Exit::Indirect,
            OpCode::Branch => {
                if let Some(t) = target() {
                    return Exit::Jump(t);
                }
            }
            OpCode::CBranch => {
                if let Some(t) = target() {
                    return Exit::Cond(t);
                }
            }
            OpCode::Call | OpCode::CallInd => return Exit::Call,
            // int3 (tag 3)
            OpCode::CallOther if op.inputs.first().is_some_and(|v| v.space == CONST_SPACE && v.offset == 3) => {
                return Exit::End;
            }
            _ => {}
        }
    }
    Exit::Next
}

/// Does the callee of the call at `i` return a `long double`? It does when the code after the
/// call (straight on, through unconditional jumps, until the next call or return) reads a value
/// below an empty stack — the `fstp` that stores or drops the result.
fn returns_ld<L: std::borrow::Borrow<LiftedInstruction>>(i: usize, lifted: &[L], decoded: &[Option<Instruction>], index: &HashMap<u64, usize>) -> bool {
    let mut depth: i32 = 0;
    let mut at = i + 1;
    for _ in 0..64 {
        let Some(insn) = lifted.get(at).map(|l| l.borrow()) else { return false };
        if let Some(Some(d)) = decoded.get(at) {
            match kind(d) {
                Kind::Stack { needs, pops, pushes } => {
                    if i32::from(needs) > depth {
                        return true;
                    }
                    depth += i32::from(pushes) - i32::from(pops);
                }
                Kind::NotX87 => {}
                Kind::Reset | Kind::Unknown => return false,
            }
        }
        match exit_of(insn) {
            Exit::Next | Exit::Cond(_) => at += 1,
            Exit::Jump(t) => match index.get(&t) {
                Some(&j) => at = j,
                None => return false,
            },
            Exit::Call | Exit::End | Exit::Indirect => return false,
        }
    }
    false
}

/// The memory operand of an instruction, to compare two of them: (base, index, scale,
/// displacement, size).
fn mem_key(insn: &Instruction) -> Option<(Register, Register, u32, u64)> {
    has_memory(insn).then(|| (insn.memory_base(), insn.memory_index(), insn.memory_index_scale(), insn.memory_displacement64()))
}

/// The rounding control a `fldcw [m]` at `i` loads: the word stored to `m` by the straight-line
/// code before it — a `fnstcw [m]` (the rounding then), or a register built from such a saved
/// word (or a constant) with `or` / `and` masks (`movzx eax, word [s]; or eax, 0xc00;
/// mov [m], ax` = toward zero).
fn fldcw_rc<L: std::borrow::Borrow<LiftedInstruction>>(i: usize, lifted: &[L], decoded: &[Option<Instruction>], state: &[St]) -> Option<u8> {
    let key = mem_key(decoded[i].as_ref()?)?;
    let straight = |j: usize| {
        j + 1 < lifted.len()
            && lifted[j].borrow().address + u64::from(lifted[j].borrow().length) == lifted[j + 1].borrow().address
            && matches!(exit_of(lifted[j].borrow()), Exit::Next)
    };
    let rc_at = |j: usize| match state[j] {
        St::Known(c) => c.rc,
        _ => None,
    };
    // the store to `key`
    let mut j = i;
    let (store, reg) = loop {
        if j == 0 || i - j > 16 || !straight(j - 1) {
            return None;
        }
        j -= 1;
        let d = decoded[j].as_ref()?;
        let writes_key = mem_key(d) == Some(key) && d.op_count() > 0 && d.op_kind(0) == OpKind::Memory;
        if !writes_key {
            continue;
        }
        match d.mnemonic() {
            Mnemonic::Fnstcw | Mnemonic::Fstcw => return rc_at(j),
            Mnemonic::Mov if d.op_kind(1) == OpKind::Register => break (j, d.op_register(1).full_register()),
            Mnemonic::Mov if d.op_kind(1) == OpKind::Immediate16 => return Some((d.immediate16() >> 10) as u8 & 3),
            _ => return None,
        }
    };
    // the register's value: (bits known, their value) of the 2-bit rounding control, from the
    // masks applied to it, back to its load
    let mut masks: Vec<(Mnemonic, u64)> = Vec::new();
    let mut j = store;
    let base = loop {
        if j == 0 || store - j > 16 || !straight(j - 1) {
            return None;
        }
        j -= 1;
        let d = decoded[j].as_ref()?;
        if d.op_count() == 0 || d.op_kind(0) != OpKind::Register || d.op_register(0).full_register() != reg {
            continue;
        }
        // (`or ah, 0xc` is bits 8-15)
        let shift = if matches!(d.op_register(0), Register::AH | Register::BH | Register::CH | Register::DH) { 8 } else { 0 };
        let imm = || (d.op_count() > 1).then(|| d.immediate(1) << shift);
        match d.mnemonic() {
            Mnemonic::Or | Mnemonic::And if d.op_count() > 1 && d.op_kind(1) != OpKind::Register && d.op_kind(1) != OpKind::Memory => {
                masks.push((d.mnemonic(), imm()?));
            }
            Mnemonic::Mov | Mnemonic::Movzx if d.op_kind(1) == OpKind::Memory => {
                // a load of a word `fnstcw` saved
                let k = mem_key(d);
                let mut s = j;
                let mut found = None;
                while s > 0 && j - s < 16 && straight(s - 1) {
                    s -= 1;
                    let w = decoded[s].as_ref()?;
                    if matches!(w.mnemonic(), Mnemonic::Fnstcw | Mnemonic::Fstcw) && mem_key(w) == k {
                        found = Some(rc_at(s));
                        break;
                    }
                }
                break found?.map(|rc| (3u8, rc));
            }
            Mnemonic::Mov if d.op_kind(1) != OpKind::Register && d.op_kind(1) != OpKind::Memory => {
                break Some((3u8, (d.immediate(1) >> 10) as u8 & 3));
            }
            _ => return None,
        }
    };
    let (mut known, mut value) = base.unwrap_or((0, 0));
    for (m, imm) in masks.into_iter().rev() {
        let bits = (imm >> 10) as u8 & 3;
        match m {
            Mnemonic::Or => {
                known |= bits;
                value |= bits;
            }
            _ => {
                known |= !bits & 3;
                value &= bits;
            }
        }
    }
    (known == 3).then_some(value & 3)
}

/// The x87 depth and rounding before each instruction of `lifted` (a function lifted from its
/// entry, where the stack is empty and the rounding is to nearest — the System V state at a
/// call), by a forward data flow over its direct jumps. A call empties nothing (the stack must
/// be empty at a call) and leaves one value when its callee returns a `long double`
/// ([`returns_ld`]). Code no jump reaches (the cases of a jump table, landing pads) starts at
/// the depth of the last indirect jump before it, else empty.
pub(crate) fn flow<L: std::borrow::Borrow<LiftedInstruction>>(lifted: &[L], decoded: &[Option<Instruction>]) -> Flow {
    let n = lifted.len();
    let index: HashMap<u64, usize> = lifted.iter().enumerate().map(|(i, l)| (l.borrow().address, i)).collect();
    let mut state = vec![St::Unset; n];
    let mut call_result = vec![None; n];
    let nearest = |depth| St::Known(X87Ctx { depth, rc: Some(0) });
    let exits: Vec<Exit> = lifted.iter().map(|l| exit_of(l.borrow())).collect();
    // the last indirect jump before each instruction
    let mut last_indirect = Vec::with_capacity(n);
    let mut last = None;
    for (i, x) in exits.iter().enumerate() {
        last_indirect.push(last);
        if matches!(x, Exit::Indirect) {
            last = Some(i);
        }
    }
    let mut work: Vec<usize> = Vec::new();
    let mut cursor = 0;
    // which run set each state (0 = from the entry): a run from a guessed start does not merge
    // into what an earlier run found — it stops there (the alignment `nop` after a `jmp` falls
    // into code a jump reaches with values on the stack)
    let mut run = vec![0u32; n];
    let mut this_run = 0u32;
    let mut seed = Some((0usize, nearest(0)));
    while let Some((start, s)) = seed.take() {
        state[start] = join(state[start], s);
        run[start] = this_run;
        work.push(start);
        while let Some(i) = work.pop() {
            let before = state[i];
            let after = match before {
                St::Known(c) => match decoded[i].as_ref().map(kind).unwrap_or(Kind::NotX87) {
                    Kind::Stack { needs, pops, pushes } => {
                        let depth = c.depth + pushes;
                        if needs > c.depth || depth < pops || depth - pops > 8 {
                            St::Conflict
                        } else {
                            let rc = match decoded[i].as_ref().map(|d| d.mnemonic()) {
                                Some(Mnemonic::Fldcw) => fldcw_rc(i, lifted, decoded, &state),
                                _ => c.rc,
                            };
                            St::Known(X87Ctx { depth: depth - pops, rc })
                        }
                    }
                    Kind::Reset => nearest(0),
                    Kind::Unknown => St::Conflict,
                    Kind::NotX87 if matches!(exits[i], Exit::Call) => {
                        if returns_ld(i, lifted, decoded, &index) {
                            call_result[i] = Some(c.depth);
                            if c.depth < 8 { St::Known(X87Ctx { depth: c.depth + 1, rc: c.rc }) } else { St::Conflict }
                        } else {
                            before
                        }
                    }
                    Kind::NotX87 => before,
                },
                other => other,
            };
            let next = (i + 1 < n && lifted[i].borrow().address + u64::from(lifted[i].borrow().length) == lifted[i + 1].borrow().address).then_some(i + 1);
            let succ: [Option<usize>; 2] = match exits[i] {
                Exit::Next | Exit::Call => [next, None],
                Exit::Jump(t) => [index.get(&t).copied(), None],
                Exit::Cond(t) => [next, index.get(&t).copied()],
                Exit::End | Exit::Indirect => [None, None],
            };
            for s in succ.into_iter().flatten() {
                if state[s] != St::Unset && run[s] != this_run {
                    continue;
                }
                run[s] = this_run;
                let j = join(state[s], after);
                if j != state[s] {
                    state[s] = j;
                    work.push(s);
                }
            }
        }
        // the next instruction nothing reached
        while cursor < n && state[cursor] != St::Unset {
            cursor += 1;
        }
        if cursor < n {
            let depth = last_indirect[cursor]
                .and_then(|j| match state[j] {
                    St::Known(c) => Some(c.depth),
                    _ => None,
                })
                .unwrap_or(0);
            this_run += 1;
            seed = Some((cursor, nearest(depth)));
        }
    }
    let ctx = state
        .iter()
        .map(|s| match s {
            St::Known(c) => Some(*c),
            _ => None,
        })
        .collect();
    Flow { ctx, call_result }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PcodeLift;
    use reargo_core::address::Endian;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn lift(code: &[u8]) -> Vec<LiftedInstruction> {
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: 0x1000,
            size: code.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(code)),
        });
        X86Lifter::new_64().lift_range(&mem, 0x1000, 64).unwrap()
    }

    fn at(l: &[LiftedInstruction], address: u64) -> &LiftedInstruction {
        l.iter().find(|i| i.address == address).unwrap()
    }

    fn unmodeled(i: &LiftedInstruction) -> bool {
        i.ops.iter().any(|o| o.opcode == OpCode::CallOther && o.output.is_none())
    }

    /// The depth is the same around a loop: `fld1` pushes slot 1, `faddp` adds it into slot 0.
    #[test]
    fn depth_flows_around_a_loop() {
        // fldz; L: fld1; faddp st(1), st; dec ecx; jne L; fstp tbyte [rsp+8]; ret
        let l = lift(&[0xd9, 0xee, 0xd9, 0xe8, 0xde, 0xc1, 0xff, 0xc9, 0x75, 0xf8, 0xdb, 0x7c, 0x24, 0x08, 0xc3]);
        assert!(!l.iter().any(unmodeled), "{l:#?}");
        assert_eq!(at(&l, 0x1002).ops[0].output, Some(slot(1)));
        let add = at(&l, 0x1004).ops.iter().find(|o| o.opcode == OpCode::FloatAdd).unwrap();
        assert_eq!((add.output, add.inputs.as_slice()), (Some(slot(0)), &[slot(0), slot(1)][..]));
        let store = at(&l, 0x100a).ops.iter().find(|o| o.opcode == OpCode::Store).unwrap();
        assert_eq!(store.inputs[2], slot(0));
    }

    /// A call followed by a pop of an empty stack returned a `long double`: the call defines it.
    #[test]
    fn a_call_can_return_a_long_double() {
        // call 0x2000; fstp tbyte [rsp+8]; ret
        let l = lift(&[0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xdb, 0x7c, 0x24, 0x08, 0xc3]);
        assert!(!l.iter().any(unmodeled), "{l:#?}");
        let def = at(&l, 0x1000).ops.iter().find(|o| o.opcode == OpCode::Indirect).expect("defines st0");
        assert_eq!(def.output, Some(slot(0)));
        // a call whose result nothing pops returns nothing on the stack
        let l = lift(&[0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xd9, 0xee, 0xdb, 0x7c, 0x24, 0x08, 0xc3]);
        assert!(!at(&l, 0x1000).ops.iter().any(|o| o.opcode == OpCode::Indirect));
        assert!(!l.iter().any(unmodeled));
    }

    /// The truncation idiom around `fistp` is followed through memory: FLOAT_TRUNC; after the
    /// saved control word is loaded back the rounding is to nearest again (`fist(x, fpucw)`).
    #[test]
    fn fistp_rounding_follows_the_control_word() {
        let l = lift(&[
            0xdb, 0x6c, 0x24, 0x08, // fld tbyte [rsp+8]
            0xd9, 0x7c, 0x24, 0x1e, // fnstcw [rsp+0x1e]
            0x0f, 0xb7, 0x44, 0x24, 0x1e, // movzx eax, word [rsp+0x1e]
            0x0d, 0x00, 0x0c, 0x00, 0x00, // or eax, 0xc00
            0x66, 0x89, 0x44, 0x24, 0x22, // mov [rsp+0x22], ax
            0xd9, 0x6c, 0x24, 0x22, // fldcw [rsp+0x22]
            0xdf, 0x7c, 0x24, 0x38, // fistp qword [rsp+0x38]
            0xd9, 0x6c, 0x24, 0x1e, // fldcw [rsp+0x1e]
            0xdb, 0x6c, 0x24, 0x08, // fld tbyte [rsp+8]
            0xdf, 0x7c, 0x24, 0x30, // fistp qword [rsp+0x30]
            0xc3,
        ]);
        let fistp1 = at(&l, 0x101b);
        assert!(fistp1.ops.iter().any(|o| o.opcode == OpCode::FloatTrunc), "{fistp1:#?}");
        assert!(!fistp1.ops.iter().any(|o| o.opcode == OpCode::CallOther));
        let fistp2 = at(&l, 0x1027);
        let fist = fistp2.ops.iter().find(|o| o.opcode == OpCode::CallOther).expect("fist");
        assert_eq!(fist.inputs[0].offset, reargo_core::pcode::intrinsic::FIST);
    }

    /// Two paths reaching an instruction with different depths: it stays unmodelled.
    #[test]
    fn inconsistent_depths_stay_unmodelled() {
        // test edi, edi; je +2; fldz; fstp tbyte [rsp+8]; ret
        let l = lift(&[0x85, 0xff, 0x74, 0x02, 0xd9, 0xee, 0xdb, 0x7c, 0x24, 0x08, 0xc3]);
        assert!(!unmodeled(at(&l, 0x1004)));
        assert!(unmodeled(at(&l, 0x1006)));
    }

    /// The alignment padding after a `jmp` (no jump reaches it) falls into code a jump reaches
    /// with a value on the stack: the padding's guessed depth does not merge into it.
    #[test]
    fn padding_does_not_spoil_the_depth() {
        // fldz; jmp L; nop word cs:[rax+rax]; xchg ax, ax; L: fstp tbyte [rsp+8]; ret
        let l = lift(&[
            0xd9, 0xee, 0xeb, 0x0c, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x90, 0xdb, 0x7c,
            0x24, 0x08, 0xc3,
        ]);
        assert!(!l.iter().any(unmodeled), "{l:#?}");
    }

    /// A `ret` with a value on the stack returns it (`long double`).
    #[test]
    fn ret_returns_the_top_of_the_stack() {
        // fld tbyte [rsp+8]; ret
        let l = lift(&[0xdb, 0x6c, 0x24, 0x08, 0xc3]);
        let ret = at(&l, 0x1004).ops.iter().find(|o| o.opcode == OpCode::Return).unwrap();
        assert_eq!(ret.inputs.get(1), Some(&slot(0)));
    }

    /// Without the range (one instruction lifted alone) the depth is unknown.
    #[test]
    fn a_lone_instruction_has_no_depth() {
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        let code = [0xd9u8, 0xee];
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: 0x1000,
            size: 2,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(&code[..])),
        });
        let one = X86Lifter::new_64().lift_instruction(&mem, 0x1000).unwrap();
        assert!(unmodeled(&one));
    }
}
