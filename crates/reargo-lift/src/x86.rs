use reargo_core::address::{Address, SpaceId};
use iced_x86::Formatter as _;
use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use reargo_loader::Memory;
use smallvec::SmallVec;

use crate::lift::{LiftError, LiftedInstruction, PcodeLift};

const CONST_SPACE: SpaceId = SpaceId::CONST;
const RAM_SPACE: SpaceId = SpaceId::RAM;
const REG_SPACE: SpaceId = SpaceId::REGISTER;
const UNIQUE_SPACE: SpaceId = SpaceId::UNIQUE;

const ZF_OFFSET: u64 = 0x206;
const SF_OFFSET: u64 = 0x207;
const CF_OFFSET: u64 = 0x201;
const OF_OFFSET: u64 = 0x20B;

fn reg(offset: u64, size: u32) -> VarnodeData {
    VarnodeData::new(REG_SPACE, offset, size)
}

fn constant(value: u64, size: u32) -> VarnodeData {
    VarnodeData::new(CONST_SPACE, value, size)
}

fn ram(offset: u64, size: u32) -> VarnodeData {
    VarnodeData::new(RAM_SPACE, offset, size)
}

fn unique(offset: u64, size: u32) -> VarnodeData {
    VarnodeData::new(UNIQUE_SPACE, offset, size)
}

fn rax(sz: u32) -> VarnodeData { reg(0x00, sz) }
fn rcx(sz: u32) -> VarnodeData { reg(0x08, sz) }
fn rdx(sz: u32) -> VarnodeData { reg(0x10, sz) }
fn rbx(sz: u32) -> VarnodeData { reg(0x18, sz) }
fn rsp(sz: u32) -> VarnodeData { reg(0x20, sz) }
fn rbp(sz: u32) -> VarnodeData { reg(0x28, sz) }
fn rsi(sz: u32) -> VarnodeData { reg(0x30, sz) }
fn rdi(sz: u32) -> VarnodeData { reg(0x38, sz) }

fn iced_reg_to_varnode(r: iced_x86::Register) -> Option<VarnodeData> {
    use std::sync::OnceLock;
    use std::collections::HashMap;
    use iced_x86::Register;

    static REG_MAP: OnceLock<HashMap<Register, VarnodeData>> = OnceLock::new();
    let map = REG_MAP.get_or_init(|| {
        let mut m = HashMap::with_capacity(48);
        m.insert(Register::RAX, rax(8)); m.insert(Register::EAX, rax(4));
        m.insert(Register::AX, rax(2)); m.insert(Register::AL, rax(1));
        m.insert(Register::RCX, rcx(8)); m.insert(Register::ECX, rcx(4));
        m.insert(Register::CX, rcx(2)); m.insert(Register::CL, rcx(1));
        m.insert(Register::RDX, rdx(8)); m.insert(Register::EDX, rdx(4));
        m.insert(Register::DX, rdx(2)); m.insert(Register::DL, rdx(1));
        m.insert(Register::RBX, rbx(8)); m.insert(Register::EBX, rbx(4));
        m.insert(Register::BX, rbx(2)); m.insert(Register::BL, rbx(1));
        m.insert(Register::RSP, rsp(8)); m.insert(Register::ESP, rsp(4));
        m.insert(Register::SP, rsp(2));
        m.insert(Register::RBP, rbp(8)); m.insert(Register::EBP, rbp(4));
        m.insert(Register::BP, rbp(2));
        m.insert(Register::RSI, rsi(8)); m.insert(Register::ESI, rsi(4));
        m.insert(Register::SI, rsi(2));
        m.insert(Register::RDI, rdi(8)); m.insert(Register::EDI, rdi(4));
        m.insert(Register::DI, rdi(2));
        m.insert(Register::R8, reg(0x80, 8)); m.insert(Register::R8D, reg(0x80, 4));
        m.insert(Register::R9, reg(0x88, 8)); m.insert(Register::R9D, reg(0x88, 4));
        m.insert(Register::R10, reg(0x90, 8)); m.insert(Register::R10D, reg(0x90, 4));
        m.insert(Register::R11, reg(0x98, 8)); m.insert(Register::R11D, reg(0x98, 4));
        m.insert(Register::R12, reg(0xA0, 8)); m.insert(Register::R12D, reg(0xA0, 4));
        m.insert(Register::R13, reg(0xA8, 8)); m.insert(Register::R13D, reg(0xA8, 4));
        m.insert(Register::R14, reg(0xB0, 8)); m.insert(Register::R14D, reg(0xB0, 4));
        m.insert(Register::R15, reg(0xB8, 8)); m.insert(Register::R15D, reg(0xB8, 4));
        m
    });
    map.get(&r).copied()
}

/// XMM register file base in REGISTER space. Mirrors Ghidra's x86-64 SLEIGH
/// layout (xmm registers begin at 0x1200, stride 0x10). Scalar SSE ops view
/// the low 4 (ss) / 8 (sd) bytes at the same offset; the SSA layer keys on
/// (offset,size) so the aliasing is exact for dataflow purposes.
const XMM_BASE: u64 = 0x1200;

/// Map an iced XMM register to its REGISTER-space base offset. Returns `None`
/// for non-XMM (incl. YMM/ZMM, which we don't model yet).
fn iced_xmm_offset(r: iced_x86::Register) -> Option<u64> {
    let rn = r as u32;
    let x0 = iced_x86::Register::XMM0 as u32;
    let x31 = iced_x86::Register::XMM31 as u32;
    if rn >= x0 && rn <= x31 {
        Some(XMM_BASE + (rn - x0) as u64 * 0x10)
    } else {
        None
    }
}

/// True if any operand is an XMM register. Used to route SSE/float
/// instructions away from the integer match (and to disambiguate the
/// `movsd`/`movss` mnemonic, which iced shares with the string instruction —
/// the string form has no XMM operand).
fn insn_touches_xmm(insn: &iced_x86::Instruction) -> bool {
    (0..insn.op_count()).any(|i| {
        insn.op_kind(i) == iced_x86::OpKind::Register
            && iced_xmm_offset(insn.op_register(i)).is_some()
    })
}

pub struct X86Lifter {
    is_64: bool,
}

impl X86Lifter {
    pub fn new_64() -> Self {
        Self { is_64: true }
    }

    pub fn new_32() -> Self {
        Self { is_64: false }
    }

    fn ptr_size(&self) -> u32 {
        if self.is_64 { 8 } else { 4 }
    }

    fn sp(&self) -> VarnodeData {
        rsp(self.ptr_size())
    }

    fn lift_iced(
        &self,
        insn: &iced_x86::Instruction,
        address: u64,
    ) -> Result<Vec<PcodeOp>, LiftError> {
        use iced_x86::Mnemonic::*;
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let mut seq_base: u32 = 0;
        let ps = self.ptr_size();

        // SSE / scalar-float instructions are lifted to FLOAT_* p-code so the
        // SSA/dataflow passes can track noise/biome math (the BDS world-gen is
        // almost entirely scalar SSE). Routed by XMM-operand presence, which
        // also disambiguates `movsd`/`movss` from the string instruction.
        if insn_touches_xmm(insn) {
            return self.lift_sse(insn, address);
        }

        match insn.mnemonic() {
            Nop | Endbr64 | Endbr32 => {}

            Mov => {
                use iced_x86::OpKind;
                if insn.op_kind(0) == OpKind::Memory {
                    // Write-only memory destination: compute the address ONCE
                    // and STORE the source. Previously the destination was
                    // lifted as a *value* (`lift_two_operands` → `lift_operand`
                    // on the dest), which emitted a dead `LOAD [dst]` (its
                    // result is immediately overwritten by the Copy) AND a first
                    // address computation; `write_back_if_memory` then computed
                    // the address a SECOND time for the Store. CSE merged the
                    // two identical address temps, and the merged unique offset
                    // collided with an unrelated earlier use of the same offset
                    // — so e.g. `mov [rbx+8], 1` decompiled as a store to a
                    // stale `rsp+0x30` temp. One address, one Store, no LOAD.
                    let src_raw = self.lift_operand(insn, 1, &mut ops, &mut seq_base, address)?;
                    let dst_size = match insn.memory_size().size() as u32 {
                        0 => self.ptr_size(),
                        s => s,
                    };
                    let src = if src_raw.size != dst_size && src_raw.space == CONST_SPACE {
                        constant(src_raw.offset, dst_size)
                    } else {
                        src_raw
                    };
                    let addr_vn =
                        self.compute_memory_address(insn, &mut ops, &mut seq_base, address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::Store,
                        seq: seq(seq_base),
                        output: None,
                        inputs: SmallVec::from_slice(&[
                            constant(RAM_SPACE.0 as u64, 4),
                            addr_vn,
                            src,
                        ]),
                    });
                    seq_base += 1;
                } else {
                    let (dst, src) =
                        self.lift_two_operands(insn, &mut ops, &mut seq_base, address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::Copy,
                        seq: seq(seq_base),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[src]),
                    });
                    seq_base += 1;
                }
            }

            Push => {
                let src = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                let sp = self.sp();
                ops.push(PcodeOp {
                    opcode: OpCode::IntSub,
                    seq: seq(seq_base),
                    output: Some(sp),
                    inputs: SmallVec::from_slice(&[sp, constant(src.size as u64, ps)]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::Store,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), sp, src]),
                });
            }

            Pop => {
                let dst = self.lift_operand_no_load(insn, 0, &mut ops, &mut seq_base, address)?;
                let sp = self.sp();
                let pop_size = if insn.op_kind(0) == iced_x86::OpKind::Register {
                    iced_reg_to_varnode(insn.op_register(0)).map(|v| v.size).unwrap_or(ps)
                } else {
                    ps
                };
                let loaded = unique(seq_base as u64 * 0x10 + 0x700, pop_size);
                ops.push(PcodeOp {
                    opcode: OpCode::Load,
                    seq: seq(seq_base),
                    output: Some(loaded),
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), sp]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[loaded]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq: seq(seq_base),
                    output: Some(sp),
                    inputs: SmallVec::from_slice(&[sp, constant(pop_size as u64, ps)]),
                });
            }

            Add | Sub | And | Or | Xor | Shl | Shr | Sar => {
                let mnem = insn.mnemonic();
                let opcode = match mnem {
                    Add => OpCode::IntAdd,
                    Sub => OpCode::IntSub,
                    And => OpCode::IntAnd,
                    Or => OpCode::IntOr,
                    Xor => OpCode::IntXor,
                    Shl => OpCode::IntLeft,
                    Shr => OpCode::IntRight,
                    Sar => OpCode::IntSRight,
                    _ => unreachable!(),
                };
                let (dst, src) = self.lift_two_operands(insn, &mut ops, &mut seq_base, address)?;
                let shift_src = if matches!(mnem, Shl | Shr | Sar) {
                    // x86 masks the shift count to 5 bits for operands up to
                    // 32-bit and 6 bits for 64-bit; without this a `shl r, cl`
                    // with cl >= width collapses to 0 under P-code at-width
                    // shift semantics instead of wrapping the count.
                    let mask = if dst.size >= 8 { 0x3F } else { 0x1F };
                    let amt = VarnodeData::new(UNIQUE_SPACE, 0x340, dst.size);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntAnd,
                        seq: seq(seq_base),
                        output: Some(amt),
                        inputs: SmallVec::from_slice(&[src, VarnodeData::new(CONST_SPACE, mask, dst.size)]),
                    });
                    seq_base += 1;
                    amt
                } else {
                    src
                };
                // For Add/Sub, CF/OF are derived from the *pre-op* operands,
                // so compute them before the operation overwrites `dst`.
                // Without these, `sub eax, eax; je L` never branched (ZF
                // stayed stale) and `add reg, reg; jc L` misread CF.
                match mnem {
                    Add => self.emit_add_carry_flags(dst, shift_src, &mut ops, &mut seq_base, address),
                    Sub => self.emit_sub_carry_flags(dst, shift_src, &mut ops, &mut seq_base, address),
                    _ => {}
                }
                ops.push(PcodeOp {
                    opcode,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[dst, shift_src]),
                });
                seq_base += 1;
                match mnem {
                    Add | Sub => {
                        self.emit_zf_sf_from(dst, &mut ops, &mut seq_base, address);
                    }
                    And | Or | Xor => {
                        // Logical ops set ZF/SF from the result and clear
                        // CF/OF unconditionally (x86 manual).
                        self.emit_zf_sf_from(dst, &mut ops, &mut seq_base, address);
                        self.emit_clear_cf_of(&mut ops, &mut seq_base, address);
                    }
                    Shl | Shr | Sar => {
                        // Shifts set ZF/SF/PF from the result; only CF/OF are
                        // count-dependent (CF = last bit shifted out, OF for
                        // 1-bit shifts) and remain unmodelled. Previously ZF/SF
                        // were skipped entirely, so `shr rcx, 0x20; je L` read a
                        // stale ZF from an earlier op (e.g. the prologue
                        // `sub rsp, N`) and decompiled as `if (rsp == 0)`.
                        // (Strictly, a masked count of 0 leaves flags unchanged;
                        // that rare case is not modelled — setting ZF/SF from the
                        // result is correct for every non-zero shift.)
                        self.emit_zf_sf_from(dst, &mut ops, &mut seq_base, address);
                    }
                    _ => {}
                }
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
            }

            Xadd => {
                // xadd dst, src: old = dst; dst = dst + src; src = old.
                // (LOCK is a no-op for single-threaded dataflow.) Unhandled, it
                // dropped to CallOther → `__builtin_trap()` (the atomic refcount
                // bump `lock xadd [mem], ax` in the climate selector). dst is
                // read here, so lifting it as a value (LOAD for memory) is
                // correct — unlike the write-only `mov` case.
                let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                let src = self.lift_operand(insn, 1, &mut ops, &mut seq_base, address)?;
                let old = unique(0x720, dst.size);
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_base),
                    output: Some(old),
                    inputs: SmallVec::from_slice(&[dst]),
                });
                seq_base += 1;
                // Carry/overflow from the pre-op operands (like ADD).
                self.emit_add_carry_flags(dst, src, &mut ops, &mut seq_base, address);
                let sum = unique(0x730, dst.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq: seq(seq_base),
                    output: Some(sum),
                    inputs: SmallVec::from_slice(&[dst, src]),
                });
                seq_base += 1;
                self.emit_zf_sf_from(sum, &mut ops, &mut seq_base, address);
                // dst = sum (register Copy, or Store back if memory).
                if insn.op_kind(0) == iced_x86::OpKind::Memory {
                    self.write_back_if_memory(insn, 0, sum, &mut ops, &mut seq_base, address)?;
                } else {
                    ops.push(PcodeOp {
                        opcode: OpCode::Copy,
                        seq: seq(seq_base),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[sum]),
                    });
                    seq_base += 1;
                }
                // src = old.
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_base),
                    output: Some(src),
                    inputs: SmallVec::from_slice(&[old]),
                });
                seq_base += 1;
            }

            // Rotates: no p-code rotate op, so synthesize from shifts + or.
            // ror x,n = (x >> n) | (x << (w-n)); rol x,n = (x << n) | (x >> (w-n)).
            // Flags (CF/OF only) are count-dependent and left unmodelled.
            Rol | Ror => {
                let is_ror = insn.mnemonic() == Ror;
                let (dst, cnt) = self.lift_two_operands(insn, &mut ops, &mut seq_base, address)?;
                let wbits = (dst.size as u64) * 8;
                // Mask the count to (width-1) = count mod width. Using the x86
                // 5/6-bit shift mask (0x1F/0x3F) would leave a byte/word count
                // >= width (e.g. `ror byte, 0x11`), and `x >> 17` / `x << -9`
                // on an 8-bit value both yield 0 → wrong. (width-1) is the
                // correct rotate modulus for these power-of-two widths.
                let mask = wbits - 1;
                let n = unique(0x4c0, dst.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntAnd,
                    seq: seq(seq_base),
                    output: Some(n),
                    inputs: SmallVec::from_slice(&[cnt, constant(mask, dst.size)]),
                });
                seq_base += 1;
                let comp = unique(0x4c2, dst.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntSub,
                    seq: seq(seq_base),
                    output: Some(comp),
                    inputs: SmallVec::from_slice(&[constant(wbits, dst.size), n]),
                });
                seq_base += 1;
                let (prim_op, prim_amt, sec_op, sec_amt) = if is_ror {
                    (OpCode::IntRight, n, OpCode::IntLeft, comp)
                } else {
                    (OpCode::IntLeft, n, OpCode::IntRight, comp)
                };
                let a = unique(0x4c4, dst.size);
                ops.push(PcodeOp {
                    opcode: prim_op,
                    seq: seq(seq_base),
                    output: Some(a),
                    inputs: SmallVec::from_slice(&[dst, prim_amt]),
                });
                seq_base += 1;
                let b = unique(0x4c6, dst.size);
                ops.push(PcodeOp {
                    opcode: sec_op,
                    seq: seq(seq_base),
                    output: Some(b),
                    inputs: SmallVec::from_slice(&[dst, sec_amt]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntOr,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
                seq_base += 1;
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
            }

            // ADC/SBB: add/sub with carry. value + ZF/SF + a correct CF (carry
            // out from either sub-step) so multi-word chains stay consistent.
            Adc | Sbb => {
                let is_sbb = insn.mnemonic() == Sbb;
                let (dst, src) = self.lift_two_operands(insn, &mut ops, &mut seq_base, address)?;
                let cf_in = unique(0x4d0, dst.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntZExt,
                    seq: seq(seq_base),
                    output: Some(cf_in),
                    inputs: SmallVec::from_slice(&[reg(CF_OFFSET, 1)]),
                });
                seq_base += 1;
                // First carry/borrow: from dst (op) src.
                let c1 = unique(0x4d2, 1);
                ops.push(PcodeOp {
                    opcode: if is_sbb { OpCode::IntLess } else { OpCode::IntCarry },
                    seq: seq(seq_base),
                    output: Some(c1),
                    inputs: SmallVec::from_slice(&[dst, src]),
                });
                seq_base += 1;
                let step = unique(0x4d4, dst.size);
                ops.push(PcodeOp {
                    opcode: if is_sbb { OpCode::IntSub } else { OpCode::IntAdd },
                    seq: seq(seq_base),
                    output: Some(step),
                    inputs: SmallVec::from_slice(&[dst, src]),
                });
                seq_base += 1;
                // Second carry/borrow: from step (op) cf_in.
                let c2 = unique(0x4d6, 1);
                ops.push(PcodeOp {
                    opcode: if is_sbb { OpCode::IntLess } else { OpCode::IntCarry },
                    seq: seq(seq_base),
                    output: Some(c2),
                    inputs: SmallVec::from_slice(&[step, cf_in]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: if is_sbb { OpCode::IntSub } else { OpCode::IntAdd },
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[step, cf_in]),
                });
                seq_base += 1;
                // CF = c1 | c2.
                ops.push(PcodeOp {
                    opcode: OpCode::BoolOr,
                    seq: seq(seq_base),
                    output: Some(reg(CF_OFFSET, 1)),
                    inputs: SmallVec::from_slice(&[c1, c2]),
                });
                seq_base += 1;
                self.emit_zf_sf_from(dst, &mut ops, &mut seq_base, address);
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
            }

            Div | Idiv => {
                // (I)DIV r/m: quotient → A-reg, remainder → D-reg. The true
                // dividend is the D:A pair (128/64/32-bit); compiler code sets
                // D = sign/zero extension of A (via cqo/cdq or xor edx,edx), so
                // we model the dividend as the accumulator alone — quotient and
                // remainder both derive from the *old* accumulator. Unhandled,
                // this dropped to CallOther → trap. One explicit operand: the
                // divisor.
                use iced_x86::Register as R;
                let signed = insn.mnemonic() == Idiv;
                let src = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                let (acc_r, hi_r) = match src.size {
                    8 => (R::RAX, R::RDX),
                    4 => (R::EAX, R::EDX),
                    2 => (R::AX, R::DX),
                    _ => (R::AL, R::AH), // byte form: dividend AX, quot AL, rem AH
                };
                let acc = iced_reg_to_varnode(acc_r).unwrap_or_else(|| constant(0, ps));
                let hi = iced_reg_to_varnode(hi_r).unwrap_or_else(|| constant(0, ps));
                let old = unique(0x740, acc.size);
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_base),
                    output: Some(old),
                    inputs: SmallVec::from_slice(&[acc]),
                });
                seq_base += 1;
                let (div_op, rem_op) = if signed {
                    (OpCode::IntSDiv, OpCode::IntSRem)
                } else {
                    (OpCode::IntDiv, OpCode::IntRem)
                };
                ops.push(PcodeOp {
                    opcode: div_op,
                    seq: seq(seq_base),
                    output: Some(acc),
                    inputs: SmallVec::from_slice(&[old, src]),
                });
                seq_base += 1;
                // Remainder to the D register (skip for the byte form, whose AH
                // high-byte varnode may be unavailable in the register map).
                if src.size >= 2 {
                    ops.push(PcodeOp {
                        opcode: rem_op,
                        seq: seq(seq_base),
                        output: Some(hi),
                        inputs: SmallVec::from_slice(&[old, src]),
                    });
                    seq_base += 1;
                }
            }

            Imul => {
                if insn.op_count() >= 2 {
                    let (dst, src) = self.lift_two_operands(insn, &mut ops, &mut seq_base, address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::IntMult,
                        seq: seq(seq_base),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[dst, src]),
                    });
                }
            }

            Not => {
                let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntNegate,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[dst]),
                });
                seq_base += 1;
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
            }

            Neg => {
                let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Int2Comp,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[dst]),
                });
                seq_base += 1;
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
            }

            Inc => {
                // INC sets OF/SF/ZF (and PF/AF) but leaves CF unchanged.
                let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                let one = constant(1, dst.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntSCarry,
                    seq: seq(seq_base),
                    output: Some(reg(OF_OFFSET, 1)),
                    inputs: SmallVec::from_slice(&[dst, one]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[dst, one]),
                });
                seq_base += 1;
                self.emit_zf_sf_from(dst, &mut ops, &mut seq_base, address);
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
            }

            Dec => {
                // DEC sets OF/SF/ZF (and PF/AF) but leaves CF unchanged.
                let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                let one = constant(1, dst.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntSBorrow,
                    seq: seq(seq_base),
                    output: Some(reg(OF_OFFSET, 1)),
                    inputs: SmallVec::from_slice(&[dst, one]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntSub,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[dst, one]),
                });
                seq_base += 1;
                self.emit_zf_sf_from(dst, &mut ops, &mut seq_base, address);
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
            }

            Cmp => {
                let (left, right) = self.lift_two_operands(insn, &mut ops, &mut seq_base, address)?;
                let tmp = unique(0x100, left.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntSub,
                    seq: seq(seq_base),
                    output: Some(tmp),
                    inputs: SmallVec::from_slice(&[left, right]),
                });
                seq_base += 1;
                let zf = reg(ZF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::IntEqual,
                    seq: seq(seq_base),
                    output: Some(zf),
                    inputs: SmallVec::from_slice(&[tmp, constant(0, tmp.size)]),
                });
                seq_base += 1;
                let sf = reg(SF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::IntSLess,
                    seq: seq(seq_base),
                    output: Some(sf),
                    inputs: SmallVec::from_slice(&[tmp, constant(0, tmp.size)]),
                });
                seq_base += 1;
                let cf = reg(CF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::IntLess,
                    seq: seq(seq_base),
                    output: Some(cf),
                    inputs: SmallVec::from_slice(&[left, right]),
                });
                seq_base += 1;
                // OF for CMP: signed-borrow of (left - right). Without
                // this, JL / JGE silently flipped on signed overflow (the
                // canonical `cmp INT_MIN, 1; jl L` failure mode).
                ops.push(PcodeOp {
                    opcode: OpCode::IntSBorrow,
                    seq: seq(seq_base),
                    output: Some(reg(OF_OFFSET, 1)),
                    inputs: SmallVec::from_slice(&[left, right]),
                });
            }

            Test => {
                let (left, right) = self.lift_two_operands(insn, &mut ops, &mut seq_base, address)?;
                let tmp = unique(0x100, left.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntAnd,
                    seq: seq(seq_base),
                    output: Some(tmp),
                    inputs: SmallVec::from_slice(&[left, right]),
                });
                seq_base += 1;
                let zf = reg(ZF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::IntEqual,
                    seq: seq(seq_base),
                    output: Some(zf),
                    inputs: SmallVec::from_slice(&[tmp, constant(0, tmp.size)]),
                });
                seq_base += 1;
                let sf = reg(SF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::IntSLess,
                    seq: seq(seq_base),
                    output: Some(sf),
                    inputs: SmallVec::from_slice(&[tmp, constant(0, tmp.size)]),
                });
            }

            Lea => {
                let dst = self.lift_operand_no_load(insn, 0, &mut ops, &mut seq_base, address)?;
                let addr_vn = self.compute_memory_address(insn, &mut ops, &mut seq_base, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[addr_vn]),
                });
            }

            Movzx => {
                let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                let src = self.lift_operand(insn, 1, &mut ops, &mut seq_base, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntZExt,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            Movsx | Movsxd => {
                let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                let src = self.lift_operand(insn, 1, &mut ops, &mut seq_base, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntSExt,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // Accumulator sign-extension (no explicit operands). CBW/CWDE/CDQE
            // widen AL→AX→EAX→RAX in place; previously these dropped to an
            // opaque CallOther → `__builtin_trap()` mid-function, severing the
            // dataflow (e.g. the `cdqe` in the BE noise sampler's index calc).
            Cbw | Cwde | Cdqe => {
                use iced_x86::Register as R;
                let (dst_r, src_r) = match insn.mnemonic() {
                    Cbw => (R::AX, R::AL),
                    Cwde => (R::EAX, R::AX),
                    _ => (R::RAX, R::EAX), // Cdqe
                };
                let dst = iced_reg_to_varnode(dst_r).unwrap_or_else(|| constant(0, ps));
                let src = iced_reg_to_varnode(src_r).unwrap_or_else(|| constant(0, ps));
                ops.push(PcodeOp {
                    opcode: OpCode::IntSExt,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // Sign-extend the accumulator into the D register: CWD/CDQ/CQO fill
            // (D)X/EDX/RDX with the sign bit of (A)X/EAX/RAX, the standard
            // idiom before `idiv`. Modeled as an arithmetic right shift of the
            // accumulator by (width-1), which broadcasts the sign bit.
            Cwd | Cdq | Cqo => {
                use iced_x86::Register as R;
                let (acc_r, hi_r, width) = match insn.mnemonic() {
                    Cwd => (R::AX, R::DX, 16u64),
                    Cdq => (R::EAX, R::EDX, 32u64),
                    _ => (R::RAX, R::RDX, 64u64), // Cqo
                };
                let acc = iced_reg_to_varnode(acc_r).unwrap_or_else(|| constant(0, ps));
                let hi = iced_reg_to_varnode(hi_r).unwrap_or_else(|| constant(0, ps));
                ops.push(PcodeOp {
                    opcode: OpCode::IntSRight,
                    seq: seq(seq_base),
                    output: Some(hi),
                    inputs: SmallVec::from_slice(&[acc, constant(width - 1, 4)]),
                });
            }

            Call => {
                // A `call` pushes the return address (sp -= 8) and the callee's
                // `ret` pops it — net zero on sp from the *caller's* dataflow,
                // which is all we model (callees are opaque). Emitting the
                // push as `sp -= 8; *sp = ret_addr` and never restoring it (the
                // callee's ret is a different function) desynced sp by 8 per
                // call, corrupting every subsequent stack-local offset, and
                // littered the decompile with `rsp = rsp - 8; *rsp = 0x...`
                // return-address noise. So model the opaque call as net-zero on
                // sp: no push. (The function's own Ret still pops the caller's
                // return address from the entry sp.)
                //
                // Direct `call rel` → Call to the resolved target. Indirect
                // `call reg` / `call [mem]` (e.g. C++ virtual dispatch) →
                // CallInd to the actual target operand, so the callee — a
                // register or a `[vtable+offset]` deref — survives instead of
                // collapsing to `call 0x0`.
                use iced_x86::OpKind;
                let is_direct = matches!(
                    insn.op_kind(0),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                );
                if is_direct {
                    let target = insn.near_branch_target();
                    ops.push(PcodeOp {
                        opcode: OpCode::Call,
                        seq: seq(seq_base),
                        output: None,
                        inputs: SmallVec::from_slice(&[ram(target, ps)]),
                    });
                } else {
                    let target =
                        self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::CallInd,
                        seq: seq(seq_base),
                        output: None,
                        inputs: SmallVec::from_slice(&[target]),
                    });
                }
            }

            Ret => {
                let sp = self.sp();
                let ret_tmp = unique(0x300, ps);
                ops.push(PcodeOp {
                    opcode: OpCode::Load,
                    seq: seq(seq_base),
                    output: Some(ret_tmp),
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), sp]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq: seq(seq_base),
                    output: Some(sp),
                    inputs: SmallVec::from_slice(&[sp, constant(ps as u64, ps)]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::Return,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ret_tmp]),
                });
            }

            Jmp => {
                let target = insn.near_branch_target();
                ops.push(PcodeOp {
                    opcode: OpCode::Branch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps)]),
                });
            }

            Je => {
                let target = insn.near_branch_target();
                let zf = reg(ZF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), zf]),
                });
            }

            Jne => {
                let target = insn.near_branch_target();
                let zf = reg(ZF_OFFSET, 1);
                let not_zf = unique(0x410, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::BoolNegate,
                    seq: seq(seq_base),
                    output: Some(not_zf),
                    inputs: SmallVec::from_slice(&[zf]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), not_zf]),
                });
            }

            Jl => {
                // JL: SF != OF. Without OF, this previously emitted CBranch
                // on plain SF — wrong whenever the comparison's
                // subtraction signed-overflowed.
                let target = insn.near_branch_target();
                let cond = self.emit_sf_xor_of(&mut ops, &mut seq_base, address);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }

            Jge => {
                // JGE: SF == OF
                let target = insn.near_branch_target();
                let cond = self.emit_not(
                    self.emit_sf_xor_of(&mut ops, &mut seq_base, address),
                    0x424, &mut ops, &mut seq_base, address,
                );
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }

            Jb => {
                let target = insn.near_branch_target();
                let cf = reg(CF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cf]),
                });
            }

            Jae => {
                let target = insn.near_branch_target();
                let cond = self.emit_not(reg(CF_OFFSET, 1), 0x430, &mut ops, &mut seq_base, address);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }

            // Sign-flag jumps used the wrong flag entirely (ZF instead of
            // SF). After this fix `js`/`jns` branch on the sign of the
            // last result, matching x86 semantics.
            Js => {
                let target = insn.near_branch_target();
                let sf = reg(SF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), sf]),
                });
            }
            Jns => {
                let target = insn.near_branch_target();
                let cond = self.emit_not(reg(SF_OFFSET, 1), 0x440, &mut ops, &mut seq_base, address);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }

            // Overflow-flag jumps need OF, which Cmp/Sub/Add/Inc/Dec now
            // populate. They previously misread ZF.
            Jo => {
                let target = insn.near_branch_target();
                let of = reg(OF_OFFSET, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), of]),
                });
            }
            Jno => {
                let target = insn.near_branch_target();
                let cond = self.emit_not(reg(OF_OFFSET, 1), 0x450, &mut ops, &mut seq_base, address);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }

            // Unsigned-pair: JA = !CF & !ZF, JBE = CF | ZF.
            Ja => {
                let target = insn.near_branch_target();
                // !(CF | ZF) == (!CF & !ZF) by De Morgan.
                let cf_or_zf = unique(0x460, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::BoolOr,
                    seq: seq(seq_base),
                    output: Some(cf_or_zf),
                    inputs: SmallVec::from_slice(&[reg(CF_OFFSET, 1), reg(ZF_OFFSET, 1)]),
                });
                seq_base += 1;
                let cond = self.emit_not(cf_or_zf, 0x464, &mut ops, &mut seq_base, address);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }
            Jbe => {
                let target = insn.near_branch_target();
                let cond = unique(0x468, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::BoolOr,
                    seq: seq(seq_base),
                    output: Some(cond),
                    inputs: SmallVec::from_slice(&[reg(CF_OFFSET, 1), reg(ZF_OFFSET, 1)]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }

            // Signed-pair: JLE = ZF | (SF != OF), JG = !JLE.
            Jle => {
                let target = insn.near_branch_target();
                let sf_xor_of = self.emit_sf_xor_of(&mut ops, &mut seq_base, address);
                let cond = unique(0x470, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::BoolOr,
                    seq: seq(seq_base),
                    output: Some(cond),
                    inputs: SmallVec::from_slice(&[reg(ZF_OFFSET, 1), sf_xor_of]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }
            Jg => {
                let target = insn.near_branch_target();
                let sf_xor_of = self.emit_sf_xor_of(&mut ops, &mut seq_base, address);
                let zf_or_sxo = unique(0x478, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::BoolOr,
                    seq: seq(seq_base),
                    output: Some(zf_or_sxo),
                    inputs: SmallVec::from_slice(&[reg(ZF_OFFSET, 1), sf_xor_of]),
                });
                seq_base += 1;
                let cond = self.emit_not(zf_or_sxo, 0x47c, &mut ops, &mut seq_base, address);
                ops.push(PcodeOp {
                    opcode: OpCode::CBranch,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps), cond]),
                });
            }

            // SETcc r/m8: dst byte = condition (0/1). Was unhandled → CallOther.
            // Reuses the shared cc_condition flag formulas. Parity codes (no PF)
            // fall back to writing 0.
            Seta | Setae | Setb | Setbe | Sete | Setne | Setg | Setge | Setl | Setle
            | Seto | Setno | Sets | Setns => {
                let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                let cond = self
                    .cc_condition(insn.condition_code(), &mut ops, &mut seq_base, address)
                    .unwrap_or_else(|| constant(0, 1));
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[cond]),
                });
                seq_base += 1;
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
            }

            // CMOVcc dst, src: dst = cond ? src : dst. We have no select op and
            // can't micro-branch inside one instruction, so use a branchless
            // select: mask = -zext(cond) (0 → 0, 1 → all-ones), then
            // dst = dst ^ ((dst ^ src) & mask). dst is read (preserved when the
            // condition is false), so lifting it as a value is correct. Parity
            // codes (no PF) leave dst unchanged.
            Cmova | Cmovae | Cmovb | Cmovbe | Cmove | Cmovne | Cmovg | Cmovge
            | Cmovl | Cmovle | Cmovo | Cmovno | Cmovs | Cmovns => {
                if let Some(cond) =
                    self.cc_condition(insn.condition_code(), &mut ops, &mut seq_base, address)
                {
                    let dst = self.lift_operand(insn, 0, &mut ops, &mut seq_base, address)?;
                    let src = self.lift_operand(insn, 1, &mut ops, &mut seq_base, address)?;
                    // cond (1 byte) → width of dst.
                    let cond_w = if dst.size == 1 {
                        cond
                    } else {
                        let z = unique(0x4b0, dst.size);
                        ops.push(PcodeOp {
                            opcode: OpCode::IntZExt,
                            seq: seq(seq_base),
                            output: Some(z),
                            inputs: SmallVec::from_slice(&[cond]),
                        });
                        seq_base += 1;
                        z
                    };
                    // mask = -cond_w  (0 or all-ones)
                    let mask = unique(0x4b4, dst.size);
                    ops.push(PcodeOp {
                        opcode: OpCode::Int2Comp,
                        seq: seq(seq_base),
                        output: Some(mask),
                        inputs: SmallVec::from_slice(&[cond_w]),
                    });
                    seq_base += 1;
                    // diff = dst ^ src
                    let diff = unique(0x4b8, dst.size);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntXor,
                        seq: seq(seq_base),
                        output: Some(diff),
                        inputs: SmallVec::from_slice(&[dst, src]),
                    });
                    seq_base += 1;
                    // masked = diff & mask
                    let masked = unique(0x4bc, dst.size);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntAnd,
                        seq: seq(seq_base),
                        output: Some(masked),
                        inputs: SmallVec::from_slice(&[diff, mask]),
                    });
                    seq_base += 1;
                    // dst = dst ^ masked
                    ops.push(PcodeOp {
                        opcode: OpCode::IntXor,
                        seq: seq(seq_base),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[dst, masked]),
                    });
                    seq_base += 1;
                    self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
                }
            }

            // Parity-flag jumps are not modelled (no PF tracking yet);
            // emit a CallOther so the emulator surfaces the gap instead
            // of silently branching on whatever was in ZF.
            Jp | Jnp => {
                ops.push(PcodeOp {
                    opcode: OpCode::CallOther,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(0, 4)]),
                });
            }

            Int3 => {
                ops.push(PcodeOp {
                    opcode: OpCode::CallOther,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(3, 4)]),
                });
            }

            _ => {
                ops.push(PcodeOp {
                    opcode: OpCode::CallOther,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(0, 4)]),
                });
            }
        }

        let _ = seq_base;
        Ok(ops)
    }

    /// Lift an SSE / scalar-float instruction to FLOAT_* p-code. Only reached
    /// when the instruction touches an XMM register. Unmodeled SSE mnemonics
    /// (shuffles, min/max, andn, …) fall through to an opaque CallOther so the
    /// caller never sees a decode error.
    fn lift_sse(
        &self,
        insn: &iced_x86::Instruction,
        address: u64,
    ) -> Result<Vec<PcodeOp>, LiftError> {
        use iced_x86::Mnemonic::*;
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let mut sb: u32 = 0;

        // Scalar element width for this mnemonic group (sd=8, ss=4, packed=16).
        let m = insn.mnemonic();
        let sz: u32 = match m {
            Addsd | Subsd | Mulsd | Divsd | Sqrtsd | Movsd | Comisd | Ucomisd | Cvtsd2ss
            | Minsd | Maxsd => 8,
            Addss | Subss | Mulss | Divss | Sqrtss | Movss | Comiss | Ucomiss | Cvtss2sd
            | Minss | Maxss => 4,
            // Packed ops act on the full 128-bit register. We model packed
            // arithmetic as a single FLOAT op over the whole varnode — not
            // bit-exact SIMD, but it keeps the vectorized noise math readable
            // and the dataflow connected (the BDS gradient loop is auto-
            // vectorized over the x/y/z lanes).
            Movaps | Movups | Movapd | Movupd | Movdqa | Movdqu | Addps | Subps | Mulps
            | Divps | Shufps | Shufpd | Unpcklps | Unpckhps | Unpcklpd | Unpckhpd
            | Movhlps | Movlhps | Pshufd => 16,
            Movq => 8,
            Movd => 4,
            _ => 8,
        };

        // Binary float arithmetic: dst (xmm) = dst OP src. Covers scalar
        // (sd/ss) and packed (ps) forms; packed runs at sz=16 (whole-register
        // approximation — see the sz note above).
        let float_bin = match m {
            Addsd | Addss | Addps => Some(OpCode::FloatAdd),
            Subsd | Subss | Subps => Some(OpCode::FloatSub),
            Mulsd | Mulss | Mulps => Some(OpCode::FloatMult),
            Divsd | Divss | Divps => Some(OpCode::FloatDiv),
            _ => None,
        };
        if let Some(opcode) = float_bin {
            let dst = self.sse_operand(insn, 0, sz, &mut ops, &mut sb, address)?;
            let src = self.sse_operand(insn, 1, sz, &mut ops, &mut sb, address)?;
            ops.push(PcodeOp {
                opcode,
                seq: seq(sb),
                output: Some(dst),
                inputs: SmallVec::from_slice(&[dst, src]),
            });
            return Ok(ops);
        }

        match m {
            // sqrt: dst (xmm) = sqrt(src)
            Sqrtsd | Sqrtss => {
                let dst = self.sse_operand(insn, 0, sz, &mut ops, &mut sb, address)?;
                let src = self.sse_operand(insn, 1, sz, &mut ops, &mut sb, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::FloatSqrt,
                    seq: seq(sb),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // Scalar / packed moves and gp<->xmm moves (movd/movq).
            Movsd | Movss | Movaps | Movups | Movapd | Movupd | Movdqa | Movdqu | Movd
            | Movq => {
                if insn.op_kind(0) == iced_x86::OpKind::Memory {
                    // store xmm/gp -> memory
                    let val = self.sse_operand(insn, 1, sz, &mut ops, &mut sb, address)?;
                    self.write_back_if_memory(insn, 0, val, &mut ops, &mut sb, address)?;
                } else {
                    let src = self.sse_operand(insn, 1, sz, &mut ops, &mut sb, address)?;
                    let dst = self.sse_operand(insn, 0, sz, &mut ops, &mut sb, address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::Copy,
                        seq: seq(sb),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[src]),
                    });
                }
            }

            // int -> float : dst (xmm) = (float)int_src
            Cvtsi2sd | Cvtsi2ss => {
                let src = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
                let dst = self.sse_operand(insn, 0, sz, &mut ops, &mut sb, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::FloatInt2Float,
                    seq: seq(sb),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // float -> int (truncating cvtt*, and rounding cvt* approximated as trunc)
            Cvttsd2si | Cvttss2si | Cvtsd2si | Cvtss2si => {
                let in_sz = if matches!(m, Cvttsd2si | Cvtsd2si) { 8 } else { 4 };
                let src = self.sse_operand(insn, 1, in_sz, &mut ops, &mut sb, address)?;
                let dst = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::FloatTrunc,
                    seq: seq(sb),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // float -> float resize (double<->single)
            Cvtsd2ss | Cvtss2sd => {
                let in_sz = if m == Cvtsd2ss { 8 } else { 4 };
                let out_sz = if m == Cvtsd2ss { 4 } else { 8 };
                let src = self.sse_operand(insn, 1, in_sz, &mut ops, &mut sb, address)?;
                let dst = self.sse_operand(insn, 0, out_sz, &mut ops, &mut sb, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::FloatFloat2Float,
                    seq: seq(sb),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // ordered/unordered compare: set ZF = (a==b), CF = (a<b), PF = 0.
            // Enables je/jne/jb/jae/ja/jbe after a float compare.
            Comisd | Comiss | Ucomisd | Ucomiss => {
                let a = self.sse_operand(insn, 0, sz, &mut ops, &mut sb, address)?;
                let b = self.sse_operand(insn, 1, sz, &mut ops, &mut sb, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::FloatEqual,
                    seq: seq(sb),
                    output: Some(reg(ZF_OFFSET, 1)),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
                sb += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::FloatLess,
                    seq: seq(sb),
                    output: Some(reg(CF_OFFSET, 1)),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
            }

            // xorps/pxor self-zero idiom -> 0; otherwise low-lane xor.
            Xorps | Xorpd | Pxor => {
                let dst = self.sse_operand(insn, 0, 8, &mut ops, &mut sb, address)?;
                if insn.op_kind(1) == iced_x86::OpKind::Register
                    && insn.op_register(0) == insn.op_register(1)
                {
                    ops.push(PcodeOp {
                        opcode: OpCode::Copy,
                        seq: seq(sb),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[constant(0, 8)]),
                    });
                } else {
                    let src = self.sse_operand(insn, 1, 8, &mut ops, &mut sb, address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::IntXor,
                        seq: seq(sb),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[dst, src]),
                    });
                }
            }

            // Shuffles / unpacks rearrange lanes between two registers. We
            // can't express the permute in scalar p-code, so we model the
            // result as a Copy of the source — lossy, but it keeps the
            // dataflow edge alive instead of emitting an opaque trap.
            Shufps | Shufpd | Unpcklps | Unpckhps | Unpcklpd | Unpckhpd | Movhlps
            | Movlhps | Pshufd => {
                let src = self.sse_operand(insn, 1, sz, &mut ops, &mut sb, address)?;
                let dst = self.sse_operand(insn, 0, sz, &mut ops, &mut sb, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(sb),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // and/or used for sign/abs masks — approximate on the low lane.
            Andps | Andpd | Orps | Orpd => {
                let dst = self.sse_operand(insn, 0, 8, &mut ops, &mut sb, address)?;
                let src = self.sse_operand(insn, 1, 8, &mut ops, &mut sb, address)?;
                let opcode = if matches!(m, Andps | Andpd) {
                    OpCode::IntAnd
                } else {
                    OpCode::IntOr
                };
                ops.push(PcodeOp {
                    opcode,
                    seq: seq(sb),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[dst, src]),
                });
            }

            // Unmodeled SSE (shuffles, min/max, andn, …): opaque, no decode error.
            _ => {
                ops.push(PcodeOp {
                    opcode: OpCode::CallOther,
                    seq: seq(sb),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(0, 4)]),
                });
            }
        }

        Ok(ops)
    }

    /// Resolve an SSE operand at the given element size. XMM registers map to
    /// the XMM register file (low lane); memory becomes a sized Load; GP
    /// registers (the integer side of cvt*) use the natural integer mapping.
    fn sse_operand(
        &self,
        insn: &iced_x86::Instruction,
        idx: u32,
        size: u32,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> Result<VarnodeData, LiftError> {
        use iced_x86::OpKind;
        match insn.op_kind(idx) {
            OpKind::Register => {
                let r = insn.op_register(idx);
                if let Some(off) = iced_xmm_offset(r) {
                    Ok(VarnodeData::new(REG_SPACE, off, size))
                } else {
                    iced_reg_to_varnode(r).ok_or_else(|| LiftError::Unsupported {
                        address: insn.ip(),
                        mnemonic: format!("unsupported sse register {:?}", r),
                    })
                }
            }
            OpKind::Memory => {
                let addr_vn = self.compute_memory_address(insn, ops, seq_base, address)?;
                let result = unique(*seq_base as u64 * 0x10 + 0x700, size);
                let seq = SeqNum::new(Address::new(RAM_SPACE, address), *seq_base);
                *seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::Load,
                    seq,
                    output: Some(result),
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr_vn]),
                });
                Ok(result)
            }
            _ => self.lift_operand(insn, idx, ops, seq_base, address),
        }
    }

    /// Set ZF/SF from a result varnode. Used by Add/Sub/Inc/Dec and by
    /// the logical ops, which (per Intel manual) clear CF/OF separately.
    fn emit_zf_sf_from(
        &self,
        result: VarnodeData,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) {
        let seq_at = |s: u32| SeqNum::new(Address::new(RAM_SPACE, address), s);
        let zero = constant(0, result.size);
        ops.push(PcodeOp {
            opcode: OpCode::IntEqual,
            seq: seq_at(*seq_base),
            output: Some(reg(ZF_OFFSET, 1)),
            inputs: SmallVec::from_slice(&[result, zero]),
        });
        *seq_base += 1;
        ops.push(PcodeOp {
            opcode: OpCode::IntSLess,
            seq: seq_at(*seq_base),
            output: Some(reg(SF_OFFSET, 1)),
            inputs: SmallVec::from_slice(&[result, zero]),
        });
        *seq_base += 1;
    }

    /// AND/OR/XOR clear CF and OF unconditionally.
    fn emit_clear_cf_of(
        &self,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) {
        let seq_at = |s: u32| SeqNum::new(Address::new(RAM_SPACE, address), s);
        ops.push(PcodeOp {
            opcode: OpCode::Copy,
            seq: seq_at(*seq_base),
            output: Some(reg(CF_OFFSET, 1)),
            inputs: SmallVec::from_slice(&[constant(0, 1)]),
        });
        *seq_base += 1;
        ops.push(PcodeOp {
            opcode: OpCode::Copy,
            seq: seq_at(*seq_base),
            output: Some(reg(OF_OFFSET, 1)),
            inputs: SmallVec::from_slice(&[constant(0, 1)]),
        });
        *seq_base += 1;
    }

    /// CF/OF for ADD computed from the pre-op operands.
    fn emit_add_carry_flags(
        &self,
        a: VarnodeData,
        b: VarnodeData,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) {
        let seq_at = |s: u32| SeqNum::new(Address::new(RAM_SPACE, address), s);
        ops.push(PcodeOp {
            opcode: OpCode::IntCarry,
            seq: seq_at(*seq_base),
            output: Some(reg(CF_OFFSET, 1)),
            inputs: SmallVec::from_slice(&[a, b]),
        });
        *seq_base += 1;
        ops.push(PcodeOp {
            opcode: OpCode::IntSCarry,
            seq: seq_at(*seq_base),
            output: Some(reg(OF_OFFSET, 1)),
            inputs: SmallVec::from_slice(&[a, b]),
        });
        *seq_base += 1;
    }

    /// CF/OF for SUB computed from the pre-op operands. CF is `a <u b`
    /// (unsigned borrow). OF is signed-borrow.
    fn emit_sub_carry_flags(
        &self,
        a: VarnodeData,
        b: VarnodeData,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) {
        let seq_at = |s: u32| SeqNum::new(Address::new(RAM_SPACE, address), s);
        ops.push(PcodeOp {
            opcode: OpCode::IntLess,
            seq: seq_at(*seq_base),
            output: Some(reg(CF_OFFSET, 1)),
            inputs: SmallVec::from_slice(&[a, b]),
        });
        *seq_base += 1;
        ops.push(PcodeOp {
            opcode: OpCode::IntSBorrow,
            seq: seq_at(*seq_base),
            output: Some(reg(OF_OFFSET, 1)),
            inputs: SmallVec::from_slice(&[a, b]),
        });
        *seq_base += 1;
    }

    /// Compute and return a fresh varnode holding `SF XOR OF` (the
    /// signed-less-than predicate). Each Jcc allocates its own unique
    /// to keep these from colliding within a single lifted instruction.
    fn emit_sf_xor_of(
        &self,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> VarnodeData {
        let out = unique(0x480, 1);
        ops.push(PcodeOp {
            opcode: OpCode::BoolXor,
            seq: SeqNum::new(Address::new(RAM_SPACE, address), *seq_base),
            output: Some(out),
            inputs: SmallVec::from_slice(&[reg(SF_OFFSET, 1), reg(OF_OFFSET, 1)]),
        });
        *seq_base += 1;
        out
    }

    /// Evaluate an instruction's x86 condition code into a 1-byte boolean
    /// varnode, reusing the same flag formulas as the Jcc arms. Returns None
    /// for parity conditions (PF is not modelled) and `None`/unknown codes —
    /// callers fall back (e.g. SETcc writes 0). Shared by SETcc/CMOVcc.
    fn cc_condition(
        &self,
        cc: iced_x86::ConditionCode,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> Option<VarnodeData> {
        use iced_x86::ConditionCode as C;
        let bool_or = |a: VarnodeData, b: VarnodeData, off: u64, ops: &mut Vec<PcodeOp>, seq_base: &mut u32| {
            let out = unique(off, 1);
            ops.push(PcodeOp {
                opcode: OpCode::BoolOr,
                seq: SeqNum::new(Address::new(RAM_SPACE, address), *seq_base),
                output: Some(out),
                inputs: SmallVec::from_slice(&[a, b]),
            });
            *seq_base += 1;
            out
        };
        let (zf, cf, sf, of) = (
            reg(ZF_OFFSET, 1),
            reg(CF_OFFSET, 1),
            reg(SF_OFFSET, 1),
            reg(OF_OFFSET, 1),
        );
        Some(match cc {
            C::e => zf,
            C::ne => self.emit_not(zf, 0x490, ops, seq_base, address),
            C::b => cf,
            C::ae => self.emit_not(cf, 0x492, ops, seq_base, address),
            C::s => sf,
            C::ns => self.emit_not(sf, 0x494, ops, seq_base, address),
            C::o => of,
            C::no => self.emit_not(of, 0x496, ops, seq_base, address),
            C::be => bool_or(cf, zf, 0x498, ops, seq_base),
            C::a => {
                let t = bool_or(cf, zf, 0x49a, ops, seq_base);
                self.emit_not(t, 0x49c, ops, seq_base, address)
            }
            C::l => self.emit_sf_xor_of(ops, seq_base, address),
            C::ge => {
                let x = self.emit_sf_xor_of(ops, seq_base, address);
                self.emit_not(x, 0x4a0, ops, seq_base, address)
            }
            C::le => {
                let x = self.emit_sf_xor_of(ops, seq_base, address);
                bool_or(zf, x, 0x4a2, ops, seq_base)
            }
            C::g => {
                let x = self.emit_sf_xor_of(ops, seq_base, address);
                let t = bool_or(zf, x, 0x4a4, ops, seq_base);
                self.emit_not(t, 0x4a6, ops, seq_base, address)
            }
            _ => return None, // p / np (PF unmodelled) and None
        })
    }

    /// BoolNegate helper: write `!src` into a unique at the given offset.
    fn emit_not(
        &self,
        src: VarnodeData,
        unique_offset: u64,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> VarnodeData {
        let out = unique(unique_offset, 1);
        ops.push(PcodeOp {
            opcode: OpCode::BoolNegate,
            seq: SeqNum::new(Address::new(RAM_SPACE, address), *seq_base),
            output: Some(out),
            inputs: SmallVec::from_slice(&[src]),
        });
        *seq_base += 1;
        out
    }

    fn lift_operand(
        &self,
        insn: &iced_x86::Instruction,
        idx: u32,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> Result<VarnodeData, LiftError> {
        use iced_x86::OpKind;
        let addr = insn.ip();
        match insn.op_kind(idx) {
            OpKind::Register => {
                iced_reg_to_varnode(insn.op_register(idx)).ok_or_else(|| LiftError::Unsupported {
                    address: addr,
                    mnemonic: format!("unsupported register {:?}", insn.op_register(idx)),
                })
            }
            OpKind::Immediate8 => Ok(constant(insn.immediate8() as u64, 1)),
            OpKind::Immediate16 => Ok(constant(insn.immediate16() as u64, 2)),
            OpKind::Immediate32 => Ok(constant(insn.immediate32() as u64, 4)),
            OpKind::Immediate64 => Ok(constant(insn.immediate64(), 8)),
            OpKind::Immediate8to16 => Ok(constant(insn.immediate8to16() as u16 as u64, 2)),
            OpKind::Immediate8to32 => Ok(constant(insn.immediate8to32() as u32 as u64, 4)),
            OpKind::Immediate8to64 => Ok(constant(insn.immediate8to64() as u64, 8)),
            OpKind::Immediate32to64 => Ok(constant(insn.immediate32to64() as u64, 8)),
            OpKind::Memory => {
                let size = insn.memory_size().size() as u32;
                if size == 0 {
                    return Ok(constant(0, self.ptr_size()));
                }
                let addr_vn = self.compute_memory_address(insn, ops, seq_base, address)?;
                let result = unique(*seq_base as u64 * 0x10 + 0x500, size);
                let seq = SeqNum::new(Address::new(RAM_SPACE, address), *seq_base);
                *seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::Load,
                    seq,
                    output: Some(result),
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr_vn]),
                });
                Ok(result)
            }
            OpKind::NearBranch16 => Ok(ram(insn.near_branch16() as u64, 2)),
            OpKind::NearBranch32 => Ok(ram(insn.near_branch32() as u64, 4)),
            OpKind::NearBranch64 => Ok(ram(insn.near_branch64(), 8)),
            _ => Err(LiftError::Unsupported {
                address: addr,
                mnemonic: format!("unsupported operand kind {:?}", insn.op_kind(idx)),
            }),
        }
    }

    fn lift_operand_no_load(
        &self,
        insn: &iced_x86::Instruction,
        idx: u32,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> Result<VarnodeData, LiftError> {
        use iced_x86::OpKind;
        match insn.op_kind(idx) {
            OpKind::Memory => {
                self.compute_memory_address(insn, ops, seq_base, address)
            }
            _ => self.lift_operand(insn, idx, ops, seq_base, address),
        }
    }

    fn compute_memory_address(
        &self,
        insn: &iced_x86::Instruction,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> Result<VarnodeData, LiftError> {
        let ps = self.ptr_size();
        let base_reg = insn.memory_base();
        let index_reg = insn.memory_index();
        let scale = insn.memory_index_scale() as u64;
        let disp = insn.memory_displacement64();

        if base_reg == iced_x86::Register::RIP || base_reg == iced_x86::Register::EIP {
            // iced_x86::Instruction::memory_displacement64() returns
            // the *effective* address for rip-relative operands --
            // i.e. it has already added `rip + insn.len()` to the
            // raw displacement bytes from the encoding. The previous
            // code added them again, so every `lea reg, [rip+disp]`
            // produced a constant that was `2 * rip + insn.len()` too
            // high; downstream the callsite resolver then matched
            // the wrong (or no) function address, breaking
            // `callsites --callbacks`.
            return Ok(constant(disp, ps));
        }

        let has_base = base_reg != iced_x86::Register::None;
        let has_index = index_reg != iced_x86::Register::None;
        let has_disp = disp != 0;

        if !has_base && !has_index {
            return Ok(constant(disp, ps));
        }

        let mut result = if has_base {
            iced_reg_to_varnode(base_reg).unwrap_or(constant(0, ps))
        } else {
            constant(0, ps)
        };

        if has_index {
            let idx_vn = iced_reg_to_varnode(index_reg).unwrap_or(constant(0, ps));
            if scale > 1 {
                let scaled = unique(*seq_base as u64 * 0x10 + 0x600, ps);
                let seq = SeqNum::new(Address::new(RAM_SPACE, address), *seq_base);
                *seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntMult,
                    seq,
                    output: Some(scaled),
                    inputs: SmallVec::from_slice(&[idx_vn, constant(scale, ps)]),
                });
                let added = unique(*seq_base as u64 * 0x10 + 0x600, ps);
                let seq2 = SeqNum::new(Address::new(RAM_SPACE, address), *seq_base);
                *seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq: seq2,
                    output: Some(added),
                    inputs: SmallVec::from_slice(&[result, scaled]),
                });
                result = added;
            } else {
                let added = unique(*seq_base as u64 * 0x10 + 0x600, ps);
                let seq = SeqNum::new(Address::new(RAM_SPACE, address), *seq_base);
                *seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq,
                    output: Some(added),
                    inputs: SmallVec::from_slice(&[result, idx_vn]),
                });
                result = added;
            }
        }

        if has_disp {
            let with_disp = unique(*seq_base as u64 * 0x10 + 0x600, ps);
            let seq = SeqNum::new(Address::new(RAM_SPACE, address), *seq_base);
            *seq_base += 1;
            ops.push(PcodeOp {
                opcode: OpCode::IntAdd,
                seq,
                output: Some(with_disp),
                inputs: SmallVec::from_slice(&[result, constant(disp, ps)]),
            });
            result = with_disp;
        }

        Ok(result)
    }

    fn lift_two_operands(
        &self,
        insn: &iced_x86::Instruction,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> Result<(VarnodeData, VarnodeData), LiftError> {
        let dst = self.lift_operand(insn, 0, ops, seq_base, address)?;
        let src_raw = self.lift_operand(insn, 1, ops, seq_base, address)?;
        let src = if src_raw.size != dst.size && src_raw.space == CONST_SPACE {
            constant(src_raw.offset, dst.size)
        } else {
            src_raw
        };
        Ok((dst, src))
    }

    fn write_back_if_memory(
        &self,
        insn: &iced_x86::Instruction,
        idx: u32,
        value: VarnodeData,
        ops: &mut Vec<PcodeOp>,
        seq_base: &mut u32,
        address: u64,
    ) -> Result<(), LiftError> {
        if insn.op_kind(idx) == iced_x86::OpKind::Memory {
            let addr_vn = self.compute_memory_address(insn, ops, seq_base, address)?;
            let seq = SeqNum::new(Address::new(RAM_SPACE, address), *seq_base);
            *seq_base += 1;
            ops.push(PcodeOp {
                opcode: OpCode::Store,
                seq,
                output: None,
                inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr_vn, value]),
            });
        }
        Ok(())
    }
}

impl PcodeLift for X86Lifter {
    fn lift_instruction(
        &self,
        memory: &Memory,
        address: u64,
    ) -> Result<LiftedInstruction, LiftError> {
        let mut buf = [0u8; 15];
        let read_len = memory.read_instruction_bytes(address, &mut buf);
        if read_len == 0 {
            return Err(LiftError::UnreadableAddress(address));
        }

        let bitness = if self.is_64 { 64 } else { 32 };
        let mut decoder =
            iced_x86::Decoder::with_ip(bitness, &buf[..read_len], address, iced_x86::DecoderOptions::NONE);
        let mut insn = iced_x86::Instruction::default();
        decoder.decode_out(&mut insn);

        if insn.is_invalid() {
            return Err(LiftError::DecodeFailed {
                address,
                reason: "invalid instruction".into(),
            });
        }

        let mnemonic = {
            use std::cell::RefCell;
            thread_local! {
                static FMT: RefCell<(iced_x86::IntelFormatter, String)> =
                    RefCell::new((iced_x86::IntelFormatter::new(), String::with_capacity(32)));
            }
            FMT.with(|cell| {
                let (fmt, buf) = &mut *cell.borrow_mut();
                buf.clear();
                fmt.format(&insn, buf);
                buf.clone()
            })
        };

        let pcode_ops = self.lift_iced(&insn, address)?;

        Ok(LiftedInstruction {
            address,
            length: insn.len() as u32,
            mnemonic,
            ops: pcode_ops,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Endian;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn make_memory(data: &[u8], addr: u64) -> Memory {
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: addr,
            size: data.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(data)),
        });
        mem
    }

    #[test]
    fn lift_nop() {
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x90], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 1);
        assert!(lifted.ops.is_empty());
    }

    #[test]
    fn lift_push_rbp() {
        let lifter = X86Lifter::new_64();
        // push rbp = 0x55
        let mem = make_memory(&[0x55], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 2);
        assert_eq!(lifted.ops[0].opcode, OpCode::IntSub);
        assert_eq!(lifted.ops[1].opcode, OpCode::Store);
    }

    #[test]
    fn lift_pop_rbp() {
        let lifter = X86Lifter::new_64();
        // pop rbp = 0x5d
        let mem = make_memory(&[0x5d], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 3);
        assert_eq!(lifted.ops[0].opcode, OpCode::Load);
        assert_eq!(lifted.ops[1].opcode, OpCode::Copy);
        assert_eq!(lifted.ops[2].opcode, OpCode::IntAdd);
    }

    #[test]
    fn lift_indirect_call_reg() {
        // call rax = ff d0  -> CallInd with the register target (not Call 0x0)
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0xff, 0xd0], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let call = lifted.ops.iter().find(|o| o.opcode == OpCode::CallInd).unwrap();
        assert_eq!(call.inputs[0].offset, 0x00); // rax
        assert!(!lifted.ops.iter().any(|o| o.opcode == OpCode::Call));
    }

    #[test]
    fn lift_indirect_call_mem_vtable() {
        // call [rax+0x10] = ff 50 10  -> CallInd through a Load of the slot
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0xff, 0x50, 0x10], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::Load));
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::CallInd));
    }

    #[test]
    fn lift_direct_call_still_call() {
        // e8 rel32 stays a direct Call to the resolved target
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0xe8, 0x00, 0x01, 0x00, 0x00], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::Call));
        assert!(!lifted.ops.iter().any(|o| o.opcode == OpCode::CallInd));
    }

    #[test]
    fn lift_mulsd_xmm() {
        // mulsd xmm0, xmm1 = f2 0f 59 c1
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0xf2, 0x0f, 0x59, 0xc1], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::FloatMult);
        // dst = xmm0 (offset 0x1200, size 8 low lane)
        let out = lifted.ops[0].output.unwrap();
        assert_eq!(out.offset, 0x1200);
        assert_eq!(out.size, 8);
        // inputs: [xmm0, xmm1]
        assert_eq!(lifted.ops[0].inputs[0].offset, 0x1200);
        assert_eq!(lifted.ops[0].inputs[1].offset, 0x1210);
    }

    #[test]
    fn lift_addsd_mem() {
        // addsd xmm2, [rip+0x10] = f2 0f 58 15 10 00 00 00
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0xf2, 0x0f, 0x58, 0x15, 0x10, 0x00, 0x00, 0x00], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // a Load (mem operand) then FLOAT_ADD
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::Load));
        let add = lifted.ops.iter().find(|o| o.opcode == OpCode::FloatAdd).unwrap();
        assert_eq!(add.output.unwrap().offset, 0x1220); // xmm2
    }

    #[test]
    fn lift_cvtsi2sd() {
        // cvtsi2sd xmm0, eax = f2 0f 2a c0
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0xf2, 0x0f, 0x2a, 0xc0], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let cvt = lifted.ops.iter().find(|o| o.opcode == OpCode::FloatInt2Float).unwrap();
        assert_eq!(cvt.output.unwrap().offset, 0x1200);
        assert_eq!(cvt.output.unwrap().size, 8);
    }

    #[test]
    fn lift_xorps_self_zeroes() {
        // xorps xmm0, xmm0 = 0f 57 c0
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x0f, 0x57, 0xc0], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::Copy);
        assert_eq!(lifted.ops[0].inputs[0].space, CONST_SPACE);
        assert_eq!(lifted.ops[0].inputs[0].offset, 0);
    }

    #[test]
    fn lift_ucomisd_sets_flags() {
        // ucomisd xmm0, xmm1 = 66 0f 2e c1
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x66, 0x0f, 0x2e, 0xc1], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::FloatEqual
            && o.output.unwrap().offset == ZF_OFFSET));
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::FloatLess
            && o.output.unwrap().offset == CF_OFFSET));
    }

    #[test]
    fn string_movsd_not_treated_as_sse() {
        // movsd (string, a5) has no xmm operand -> must NOT hit SSE path
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0xa5], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // falls to integer default (CallOther), never the SSE float path
        assert!(!lifted.ops.iter().any(|o| matches!(
            o.opcode,
            OpCode::FloatAdd | OpCode::FloatMult | OpCode::FloatSub | OpCode::FloatDiv
        )));
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::CallOther));
    }

    #[test]
    fn lift_mov_reg_reg() {
        let lifter = X86Lifter::new_64();
        // mov rbp, rsp = 48 89 e5
        let mem = make_memory(&[0x48, 0x89, 0xe5], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::Copy);
    }

    #[test]
    fn lift_mov_mem_dest_is_address_plus_store_no_dead_load() {
        // mov byte ptr [rbx+8], 1 = c6 43 08 01
        // A write-only memory destination must lift to exactly one address
        // computation + one Store — NO LOAD of the destination (it would be
        // dead) and NO duplicate address computation. The old path lifted the
        // dest as a value (dead LOAD + 1st address) then wrote back (2nd
        // address); CSE merged the two address temps and the merged unique
        // offset collided with an unrelated earlier use, making the store look
        // like it targeted a stale address in decompile output.
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0xc6, 0x43, 0x08, 0x01], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(
            !lifted.ops.iter().any(|o| o.opcode == OpCode::Load),
            "write-only mov destination must not emit a LOAD: {:?}",
            lifted.ops
        );
        let adds = lifted.ops.iter().filter(|o| o.opcode == OpCode::IntAdd).count();
        let stores = lifted.ops.iter().filter(|o| o.opcode == OpCode::Store).count();
        assert_eq!(adds, 1, "exactly one address computation: {:?}", lifted.ops);
        assert_eq!(stores, 1, "exactly one store: {:?}", lifted.ops);
        // The Store's address input is the IntAdd output (rbx+8), and the
        // stored value is the 1-byte constant 1.
        let add = lifted.ops.iter().find(|o| o.opcode == OpCode::IntAdd).unwrap();
        let store = lifted.ops.iter().find(|o| o.opcode == OpCode::Store).unwrap();
        assert_eq!(store.inputs[1].offset, add.output.unwrap().offset);
        assert_eq!(store.inputs[2].space, CONST_SPACE);
        assert_eq!(store.inputs[2].offset, 1);
        assert_eq!(store.inputs[2].size, 1, "byte store width");
    }

    #[test]
    fn lift_cdqe_is_sign_extend_not_trap() {
        // cdqe = 48 98  -> RAX = sext(EAX); must not be an opaque CallOther.
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x48, 0x98], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(!lifted.ops.iter().any(|o| o.opcode == OpCode::CallOther),
            "cdqe must be lifted, not dropped to CallOther: {:?}", lifted.ops);
        let sx = lifted.ops.iter().find(|o| o.opcode == OpCode::IntSExt).expect("IntSExt");
        assert_eq!(sx.output.unwrap().size, 8, "dest RAX is 8 bytes");
        assert_eq!(sx.inputs[0].size, 4, "src EAX is 4 bytes");
    }

    #[test]
    fn lift_ror_is_shift_or_no_trap() {
        let lifter = X86Lifter::new_64();
        // ror eax, 1 = d1 c8
        let l = lifter.lift_instruction(&make_memory(&[0xd1, 0xc8], 0x1000), 0x1000).unwrap();
        assert!(!l.ops.iter().any(|o| o.opcode == OpCode::CallOther));
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::IntRight));
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::IntLeft));
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::IntOr));
    }

    #[test]
    fn lift_ror_byte_count_masked_to_width_minus_1() {
        let lifter = X86Lifter::new_64();
        // ror al, 9 = c0 c8 09 — a byte rotate count masks to 9 & 0x7 = 1, not
        // the 5-bit shift mask 0x1f (which would shift the 8-bit value to 0).
        let l = lifter.lift_instruction(&make_memory(&[0xc0, 0xc8, 0x09], 0x1000), 0x1000).unwrap();
        let and = l.ops.iter().find(|o| o.opcode == OpCode::IntAnd).expect("count mask");
        assert_eq!(and.inputs[1].offset, 0x7, "byte rotate count masks to width-1");
    }

    #[test]
    fn lift_adc_adds_carry_and_sets_cf() {
        let lifter = X86Lifter::new_64();
        // adc eax, ecx = 11 c8
        let l = lifter.lift_instruction(&make_memory(&[0x11, 0xc8], 0x1000), 0x1000).unwrap();
        assert!(!l.ops.iter().any(|o| o.opcode == OpCode::CallOther));
        // carry chained in (zext of CF) and CF written back.
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::IntZExt));
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::IntCarry));
        assert!(l.ops.iter().any(|o|
            o.opcode == OpCode::BoolOr && o.output.is_some_and(|v| v.offset == CF_OFFSET)),
            "adc writes CF: {:?}", l.ops);
    }

    #[test]
    fn lift_cmovcc_branchless_select_no_trap() {
        // cmove rax, rcx = 48 0f 44 c1 -> rax = ZF ? rcx : rax
        let lifter = X86Lifter::new_64();
        let l = lifter.lift_instruction(&make_memory(&[0x48, 0x0f, 0x44, 0xc1], 0x1000), 0x1000).unwrap();
        assert!(!l.ops.iter().any(|o| o.opcode == OpCode::CallOther),
            "cmovcc must be lifted, not CallOther: {:?}", l.ops);
        // Branchless select shape: a 2COMP mask, an AND, and two XORs.
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::Int2Comp), "mask = -cond");
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::IntAnd));
        assert_eq!(l.ops.iter().filter(|o| o.opcode == OpCode::IntXor).count(), 2);
        // Final op writes RAX (offset 0).
        let last = l.ops.last().unwrap();
        assert_eq!(last.opcode, OpCode::IntXor);
        assert_eq!(last.output.unwrap().offset, 0x0, "result -> RAX");
    }

    #[test]
    fn lift_setcc_writes_condition_byte() {
        let lifter = X86Lifter::new_64();
        // sete al = 0f 94 c0  -> AL = ZF
        let l = lifter.lift_instruction(&make_memory(&[0x0f, 0x94, 0xc0], 0x1000), 0x1000).unwrap();
        assert!(!l.ops.iter().any(|o| o.opcode == OpCode::CallOther));
        let cp = l.ops.iter().find(|o| o.opcode == OpCode::Copy).expect("Copy");
        assert_eq!(cp.inputs[0].offset, ZF_OFFSET, "sete copies ZF");
        assert_eq!(cp.output.unwrap().offset, 0x0, "into AL");
        // setne al = 0f 95 c0  -> AL = !ZF (a BoolNegate appears)
        let l = lifter.lift_instruction(&make_memory(&[0x0f, 0x95, 0xc0], 0x1000), 0x1000).unwrap();
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::BoolNegate));
        // setbe al = 0f 96 c0  -> AL = CF | ZF (a BoolOr appears)
        let l = lifter.lift_instruction(&make_memory(&[0x0f, 0x96, 0xc0], 0x1000), 0x1000).unwrap();
        assert!(l.ops.iter().any(|o| o.opcode == OpCode::BoolOr));
    }

    #[test]
    fn lift_div_idiv_quotient_eax_remainder_edx() {
        let lifter = X86Lifter::new_64();
        // div ecx = f7 f1  -> EAX = EAX / ECX (unsigned), EDX = EAX % ECX
        let lifted = lifter.lift_instruction(&make_memory(&[0xf7, 0xf1], 0x1000), 0x1000).unwrap();
        assert!(!lifted.ops.iter().any(|o| o.opcode == OpCode::CallOther));
        let q = lifted.ops.iter().find(|o| o.opcode == OpCode::IntDiv).expect("IntDiv");
        let r = lifted.ops.iter().find(|o| o.opcode == OpCode::IntRem).expect("IntRem");
        assert_eq!(q.output.unwrap().offset, 0x0, "quotient -> EAX");
        assert_eq!(r.output.unwrap().offset, 0x10, "remainder -> EDX");
        // quotient and remainder both derive from the SAME saved-old dividend.
        assert_eq!(q.inputs[0].offset, r.inputs[0].offset);

        // idiv ecx = f7 f9  -> signed variants.
        let lifted = lifter.lift_instruction(&make_memory(&[0xf7, 0xf9], 0x1000), 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::IntSDiv));
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::IntSRem));
    }

    #[test]
    fn lift_xadd_reg_swaps_and_adds_no_trap() {
        // xadd ecx, eax = 0f c1 c1  (dst=ecx, src=eax)
        // old = ecx; ecx = ecx + eax; eax = old. Must not be a CallOther.
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x0f, 0xc1, 0xc1], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(!lifted.ops.iter().any(|o| o.opcode == OpCode::CallOther),
            "xadd must be lifted, not CallOther: {:?}", lifted.ops);
        assert_eq!(lifted.ops.iter().filter(|o| o.opcode == OpCode::IntAdd).count(), 1);
        // The sum and the saved-old both flow through Copies; at least the
        // src-writeback (eax = old) and old-save Copies are present.
        assert!(lifted.ops.iter().filter(|o| o.opcode == OpCode::Copy).count() >= 2,
            "xadd needs old-save + src writeback: {:?}", lifted.ops);
        // ZF is set from the sum.
        assert!(lifted.ops.iter().any(|o|
            o.opcode == OpCode::IntEqual && o.output.is_some_and(|v| v.offset == ZF_OFFSET)));
    }

    #[test]
    fn lift_cqo_fills_rdx_with_sign() {
        // cqo = 48 99  -> RDX = RAX >>s 63 (broadcast sign bit).
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x48, 0x99], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let sr = lifted.ops.iter().find(|o| o.opcode == OpCode::IntSRight).expect("IntSRight");
        assert_eq!(sr.inputs[1].space, CONST_SPACE);
        assert_eq!(sr.inputs[1].offset, 63);
    }

    #[test]
    fn lift_shr_sets_zf_from_result() {
        // shr rcx, 0x20 = 48 c1 e9 20 -> the shift result must drive ZF so a
        // following `je` tests the shifted value, not a stale earlier flag.
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x48, 0xc1, 0xe9, 0x20], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let zf = lifted.ops.iter().find(|o| {
            o.opcode == OpCode::IntEqual && o.output.is_some_and(|v| v.offset == ZF_OFFSET)
        });
        assert!(zf.is_some(), "shr must set ZF from its result: {:?}", lifted.ops);
    }

    #[test]
    fn lift_lea_rip_relative_uses_effective_address_once() {
        // Regression for the rip-relative LEA double-count: iced's
        // memory_displacement64() already folds in rip+len, so the
        // lifter must NOT add them again. The classic gcc callback
        // idiom `lea rdi, [rip + func]` has to resolve to the exact
        // function address or `callsites --callbacks` can't match it.
        let lifter = X86Lifter::new_64();
        // lea rax, [rip+0x100]  =  48 8d 05 00 01 00 00
        // ip 0x1000, len 7, disp 0x100 -> effective 0x1000+7+0x100 = 0x1107
        let mem = make_memory(&[0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 7);
        assert_eq!(lifted.ops.len(), 1);
        let op = &lifted.ops[0];
        assert_eq!(op.opcode, OpCode::Copy);
        let src = &op.inputs[0];
        assert_eq!(
            src.space, CONST_SPACE,
            "lea rip-relative source should be a constant effective address"
        );
        assert_eq!(
            src.offset, 0x1107,
            "rip-relative effective address must be ip+len+disp counted exactly once"
        );
    }

    #[test]
    fn lift_mov_rip_relative_load_address_is_effective() {
        // The same effective-address path feeds rip-relative LOADs,
        // e.g. `mov rax, [rip + global]`. Confirm the Load's address
        // operand is the once-counted effective address, not double.
        let lifter = X86Lifter::new_64();
        // mov rax, [rip+0x100]  =  48 8b 05 00 01 00 00  (len 7)
        // effective 0x1000+7+0x100 = 0x1107
        let mem = make_memory(&[0x48, 0x8b, 0x05, 0x00, 0x01, 0x00, 0x00], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 7);
        let load = lifted
            .ops
            .iter()
            .find(|o| o.opcode == OpCode::Load)
            .expect("rip-relative mov should emit a Load");
        // LOAD inputs: [space-id-const, address]. The address operand
        // (index 1) carries the effective rip-relative address.
        let addr = &load.inputs[1];
        assert_eq!(addr.space, CONST_SPACE);
        assert_eq!(addr.offset, 0x1107);
    }

    #[test]
    fn lift_sub_rsp_imm() {
        let lifter = X86Lifter::new_64();
        // sub rsp, 0x28 = 48 83 ec 28
        let mem = make_memory(&[0x48, 0x83, 0xec, 0x28], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // Sub now emits CF, OF (pre-op), IntSub, ZF, SF (post-op).
        // The pre-op flags must use the original `rsp` value, not the
        // post-decrement one.
        assert!(lifted.ops.iter().any(|op| op.opcode == OpCode::IntSub));
        let writes_to = |off: u64| lifted.ops.iter().any(|op|
            op.output.map(|v| v.space == REG_SPACE && v.offset == off).unwrap_or(false)
        );
        assert!(writes_to(ZF_OFFSET), "sub must set ZF: {:?}", lifted.ops);
        assert!(writes_to(SF_OFFSET), "sub must set SF: {:?}", lifted.ops);
        assert!(writes_to(CF_OFFSET), "sub must set CF: {:?}", lifted.ops);
        assert!(writes_to(OF_OFFSET), "sub must set OF: {:?}", lifted.ops);
    }

    #[test]
    fn lift_xor_self() {
        let lifter = X86Lifter::new_64();
        // xor eax, eax = 31 c0
        let mem = make_memory(&[0x31, 0xc0], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // Logical ops set ZF/SF from the result and clear CF/OF.
        assert!(lifted.ops.iter().any(|op| op.opcode == OpCode::IntXor));
        let writes_to = |off: u64| lifted.ops.iter().any(|op|
            op.output.map(|v| v.space == REG_SPACE && v.offset == off).unwrap_or(false)
        );
        assert!(writes_to(ZF_OFFSET), "xor must set ZF: {:?}", lifted.ops);
        assert!(writes_to(SF_OFFSET));
        assert!(writes_to(CF_OFFSET), "xor must clear CF: {:?}", lifted.ops);
        assert!(writes_to(OF_OFFSET), "xor must clear OF: {:?}", lifted.ops);
    }

    #[test]
    fn lift_ret() {
        let lifter = X86Lifter::new_64();
        // ret = c3
        let mem = make_memory(&[0xc3], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 3);
        assert_eq!(lifted.ops[0].opcode, OpCode::Load);
        assert_eq!(lifted.ops[1].opcode, OpCode::IntAdd);
        assert_eq!(lifted.ops[2].opcode, OpCode::Return);
    }

    #[test]
    fn lift_call() {
        let lifter = X86Lifter::new_64();
        // call rel32 = e8 10 00 00 00
        let mem = make_memory(&[0xe8, 0x10, 0x00, 0x00, 0x00], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // Opaque call is net-zero on sp (no return-address push): just the Call.
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::Call);
        assert_eq!(lifted.ops[0].inputs[0].offset, 0x1015); // resolved target
        // sp must NOT be touched by the call (no IntSub/Store).
        assert!(!lifted.ops.iter().any(|o| o.opcode == OpCode::IntSub || o.opcode == OpCode::Store));
    }

    #[test]
    fn lift_cmp() {
        let lifter = X86Lifter::new_64();
        // cmp eax, 0 = 83 f8 00
        let mem = make_memory(&[0x83, 0xf8, 0x00], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // Cmp produces IntSub (to a unique), then ZF/SF/CF/OF.
        // Without OF (added in this round), JL/JGE silently
        // flipped on signed overflow of (left - right).
        assert_eq!(lifted.ops.len(), 5);
        assert_eq!(lifted.ops[0].opcode, OpCode::IntSub);
        assert_eq!(lifted.ops[1].opcode, OpCode::IntEqual);
        assert_eq!(lifted.ops[2].opcode, OpCode::IntSLess);
        assert_eq!(lifted.ops[3].opcode, OpCode::IntLess);
        assert_eq!(lifted.ops[4].opcode, OpCode::IntSBorrow);
        assert_eq!(lifted.ops[4].output.unwrap().offset, OF_OFFSET);
    }

    #[test]
    fn lift_je() {
        let lifter = X86Lifter::new_64();
        // je +0x10 = 74 10
        let mem = make_memory(&[0x74, 0x10], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::CBranch);
    }

    #[test]
    fn lift_prologue_sequence() {
        let lifter = X86Lifter::new_64();
        // push rbp; mov rbp, rsp; sub rsp, 0x28
        let code = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x28];
        let mem = make_memory(&code, 0x1000);
        let lifted = lifter.lift_range(&mem, 0x1000, 3).unwrap();
        assert_eq!(lifted.len(), 3);
        assert!(lifted[0].mnemonic.contains("push"));
        assert!(lifted[1].mnemonic.contains("mov"));
        assert!(lifted[2].mnemonic.contains("sub"));
    }

    /// Find the CBranch op and return the second input (the predicate).
    fn cbranch_predicate(lifted: &LiftedInstruction) -> &VarnodeData {
        let op = lifted.ops.iter().find(|o| o.opcode == OpCode::CBranch)
            .expect("CBranch op present");
        op.inputs.get(1).expect("CBranch has a predicate input")
    }

    /// Find the op whose output writes the given register offset.
    fn op_writing(lifted: &LiftedInstruction, off: u64) -> &PcodeOp {
        lifted.ops.iter().find(|o|
            o.output.map(|v| v.space == REG_SPACE && v.offset == off).unwrap_or(false)
        ).unwrap_or_else(|| panic!("no op writes reg offset 0x{:x} in {:?}", off, lifted.ops))
    }

    #[test]
    fn js_branches_on_sf_not_zf() {
        // 78 10 = js +0x10. Previously *every* non-Je/Jne/Jl/Jge/Jb/Jae
        // conditional jump fell into one match arm that read ZF —
        // including JS, which should test SF.
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x78, 0x10], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let pred = cbranch_predicate(&lifted);
        assert_eq!(pred.space, REG_SPACE);
        assert_eq!(pred.offset, SF_OFFSET, "JS must read SF, not ZF (was 0x{:x}): {:?}", pred.offset, lifted.ops);
    }

    #[test]
    fn jbe_branches_on_cf_or_zf() {
        // 76 10 = jbe +0x10. Semantics: CF | ZF.
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x76, 0x10], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // Must contain a BoolOr of CF and ZF feeding into CBranch.
        let bool_or = lifted.ops.iter().find(|o| o.opcode == OpCode::BoolOr)
            .expect("JBE must compute CF | ZF, not test ZF alone: {lifted.ops:?}");
        let in0 = bool_or.inputs[0];
        let in1 = bool_or.inputs[1];
        let touches_cf = (in0.space, in0.offset) == (REG_SPACE, CF_OFFSET)
            || (in1.space, in1.offset) == (REG_SPACE, CF_OFFSET);
        let touches_zf = (in0.space, in0.offset) == (REG_SPACE, ZF_OFFSET)
            || (in1.space, in1.offset) == (REG_SPACE, ZF_OFFSET);
        assert!(touches_cf && touches_zf, "JBE's BoolOr must combine CF and ZF: {:?}", lifted.ops);
    }

    #[test]
    fn sub_self_updates_zf_so_je_branches() {
        // 29 c0 = sub eax, eax. Without flag updates, the canonical
        // `sub r, r; je L` idiom would never branch (ZF stayed stale).
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x29, 0xc0], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let zf_op = op_writing(&lifted, ZF_OFFSET);
        assert_eq!(zf_op.opcode, OpCode::IntEqual);
    }

    #[test]
    fn jl_uses_sf_xor_of_not_plain_sf() {
        // 7c 10 = jl +0x10. Semantics: SF != OF. Before this fix the
        // CBranch read SF directly, so `cmp INT_MIN, 1; jl L` failed
        // to branch on signed overflow.
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&[0x7c, 0x10], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let bool_xor = lifted.ops.iter().find(|o| o.opcode == OpCode::BoolXor)
            .unwrap_or_else(|| panic!("JL must compute SF XOR OF: {:?}", lifted.ops));
        let in0 = bool_xor.inputs[0];
        let in1 = bool_xor.inputs[1];
        let touches_sf = (in0.space, in0.offset) == (REG_SPACE, SF_OFFSET)
            || (in1.space, in1.offset) == (REG_SPACE, SF_OFFSET);
        let touches_of = (in0.space, in0.offset) == (REG_SPACE, OF_OFFSET)
            || (in1.space, in1.offset) == (REG_SPACE, OF_OFFSET);
        assert!(touches_sf && touches_of, "JL's BoolXor must combine SF and OF: {:?}", lifted.ops);
    }
}
