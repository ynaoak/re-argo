use gr_core::address::{Address, SpaceId};
use iced_x86::Formatter as _;
use gr_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use gr_loader::Memory;
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

        match insn.mnemonic() {
            Nop | Endbr64 | Endbr32 => {}

            Mov => {
                let (dst, src) = self.lift_two_operands(insn, &mut ops, &mut seq_base, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_base),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
                seq_base += 1;
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
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
                        // CF/OF unconditionally (x86 manual). Shifts have
                        // CF/OF semantics that depend on the count and are
                        // intentionally not modelled here yet.
                        self.emit_zf_sf_from(dst, &mut ops, &mut seq_base, address);
                        self.emit_clear_cf_of(&mut ops, &mut seq_base, address);
                    }
                    _ => {}
                }
                self.write_back_if_memory(insn, 0, dst, &mut ops, &mut seq_base, address)?;
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

            Call => {
                let sp = self.sp();
                let ret_addr = address + insn.len() as u64;
                ops.push(PcodeOp {
                    opcode: OpCode::IntSub,
                    seq: seq(seq_base),
                    output: Some(sp),
                    inputs: SmallVec::from_slice(&[sp, constant(ps as u64, ps)]),
                });
                seq_base += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::Store,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[
                        constant(RAM_SPACE.0 as u64, 4),
                        sp,
                        constant(ret_addr, ps),
                    ]),
                });
                seq_base += 1;
                let target = insn.near_branch_target();
                ops.push(PcodeOp {
                    opcode: OpCode::Call,
                    seq: seq(seq_base),
                    output: None,
                    inputs: SmallVec::from_slice(&[ram(target, ps)]),
                });
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
            let effective = insn.ip().wrapping_add(insn.len() as u64).wrapping_add(disp);
            return Ok(constant(effective, ps));
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
    use gr_core::address::Endian;
    use gr_loader::memory::{MemoryBlock, MemoryFlags};
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
    fn lift_mov_reg_reg() {
        let lifter = X86Lifter::new_64();
        // mov rbp, rsp = 48 89 e5
        let mem = make_memory(&[0x48, 0x89, 0xe5], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::Copy);
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
        assert_eq!(lifted.ops.len(), 3);
        assert_eq!(lifted.ops[0].opcode, OpCode::IntSub);
        assert_eq!(lifted.ops[1].opcode, OpCode::Store);
        assert_eq!(lifted.ops[2].opcode, OpCode::Call);
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
