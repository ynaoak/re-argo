use capstone::arch::arm64::{
    Arm64InsnDetail, Arm64OpMem, Arm64Operand, Arm64OperandType, Arm64Shift,
};
use capstone::prelude::*;
use capstone::RegId;
use gr_core::address::{Address, SpaceId};
use gr_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use gr_loader::Memory;
use smallvec::SmallVec;

use crate::lift::{LiftError, LiftedInstruction, PcodeLift};

// ---------------------------------------------------------------------------
// Space constants
// ---------------------------------------------------------------------------
const CONST_SPACE: SpaceId = SpaceId::CONST;
const RAM_SPACE: SpaceId = SpaceId::RAM;
const REG_SPACE: SpaceId = SpaceId::REGISTER;
const UNIQUE_SPACE: SpaceId = SpaceId::UNIQUE;

// ---------------------------------------------------------------------------
// AArch64 register layout (matches gr-arch/src/arm.rs aarch64_registers)
//   x0-x30:  offset = i*8,  size = 8  (w0-w30: same offset, size = 4)
//   sp:      offset = 31*8, size = 8
//   pc:      offset = 32*8, size = 8
//   xzr:     offset = 33*8, size = 8
//   nzcv:    offset = 0x200, size = 4
// ---------------------------------------------------------------------------
const SP_OFFSET: u64 = 31 * 8;
const XZR_OFFSET: u64 = 33 * 8;
const NZCV_OFFSET: u64 = 0x200;

// ---------------------------------------------------------------------------
// Capstone ARM64 register IDs (from capstone-sys arm64_reg)
// ---------------------------------------------------------------------------
mod cs_reg {
    pub const INVALID: u16 = 0;
    pub const FP: u16 = 2;    // ARM64_REG_FP = ARM64_REG_X29
    pub const LR: u16 = 3;    // ARM64_REG_LR = ARM64_REG_X30
    pub const NZCV: u16 = 4;
    pub const SP: u16 = 5;
    pub const WSP: u16 = 6;
    pub const WZR: u16 = 7;
    pub const XZR: u16 = 8;
    pub const W0: u16 = 185;
    pub const W28: u16 = 213;
    pub const W29: u16 = 214;
    pub const W30: u16 = 215;
    pub const X0: u16 = 216;
    pub const X28: u16 = 244;
}

// ---------------------------------------------------------------------------
// Capstone ARM64 instruction IDs (from capstone-sys arm64_insn)
// ---------------------------------------------------------------------------
mod cs_insn {
    pub const ADD: u32 = 4;
    pub const ADDS: u32 = 9;
    pub const ADR: u32 = 12;
    pub const ADRP: u32 = 13;
    pub const AND: u32 = 18;
    pub const ASR: u32 = 21;
    pub const B: u32 = 39;
    pub const BL: u32 = 46;
    pub const BLR: u32 = 47;
    pub const BR: u32 = 52;
    pub const CBNZ: u32 = 85;
    pub const CBZ: u32 = 86;
    pub const CMP: u32 = 107;
    pub const EOR: u32 = 160;
    pub const LDP: u32 = 391;
    pub const LDR: u32 = 393;
    pub const LDRB: u32 = 396;
    pub const LDRH: u32 = 397;
    pub const LDRSB: u32 = 398;
    pub const LDRSH: u32 = 399;
    pub const LDRSW: u32 = 400;
    pub const LSL: u32 = 477;
    pub const LSR: u32 = 480;
    pub const MOV: u32 = 488;
    pub const MOVK: u32 = 490;
    pub const MOVN: u32 = 491;
    pub const MOVZ: u32 = 494;
    pub const MUL: u32 = 499;
    pub const NOP: u32 = 508;
    pub const ORR: u32 = 515;
    pub const RET: u32 = 558;
    pub const STP: u32 = 761;
    pub const STR: u32 = 762;
    pub const STRB: u32 = 763;
    pub const STRH: u32 = 764;
    pub const SUB: u32 = 805;
    pub const SUBS: u32 = 809;
    pub const SXTW: u32 = 830;
    pub const UXTW: u32 = 921;
}

// ---------------------------------------------------------------------------
// Capstone ARM64 condition codes (from capstone-sys arm64_cc)
// ---------------------------------------------------------------------------
mod cs_cc {
    pub const EQ: u32 = 1;
    pub const NE: u32 = 2;
    pub const AL: u32 = 15;
}

// ---------------------------------------------------------------------------
// Varnode helpers
// ---------------------------------------------------------------------------
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

fn sp() -> VarnodeData {
    reg(SP_OFFSET, 8)
}

fn nzcv() -> VarnodeData {
    reg(NZCV_OFFSET, 4)
}

/// Map a capstone `RegId` to a `VarnodeData` using the AArch64 register
/// layout defined in `gr-arch/src/arm.rs`.
fn cs_reg_to_varnode(r: RegId) -> Option<VarnodeData> {
    let id = r.0;
    match id {
        cs_reg::INVALID => None,
        cs_reg::FP => Some(reg(29 * 8, 8)),
        cs_reg::LR => Some(reg(30 * 8, 8)),
        cs_reg::NZCV => Some(nzcv()),
        cs_reg::SP => Some(sp()),
        cs_reg::WSP => Some(reg(SP_OFFSET, 4)),
        cs_reg::WZR => Some(reg(XZR_OFFSET, 4)),
        cs_reg::XZR => Some(reg(XZR_OFFSET, 8)),
        w if (cs_reg::W0..=cs_reg::W28).contains(&w) => {
            let idx = (w - cs_reg::W0) as u64;
            Some(reg(idx * 8, 4))
        }
        w if w == cs_reg::W29 => Some(reg(29 * 8, 4)),
        w if w == cs_reg::W30 => Some(reg(30 * 8, 4)),
        x if (cs_reg::X0..=cs_reg::X28).contains(&x) => {
            let idx = (x - cs_reg::X0) as u64;
            Some(reg(idx * 8, 8))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Aarch64Lifter
// ---------------------------------------------------------------------------
pub struct Aarch64Lifter {
    cs: capstone::Capstone,
}

// Capstone's C library is thread-safe for independent instances.
unsafe impl Send for Aarch64Lifter {}
unsafe impl Sync for Aarch64Lifter {}

impl Aarch64Lifter {
    pub fn new() -> Self {
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("failed to create AArch64 capstone");
        Self { cs }
    }

    // -------------------------------------------------------------------
    // Main lifting dispatch
    // -------------------------------------------------------------------
    fn lift_insn(
        &self,
        insn: &capstone::Insn<'_>,
        detail: &Arm64InsnDetail<'_>,
        operands: &[Arm64Operand],
        address: u64,
    ) -> Result<Vec<PcodeOp>, LiftError> {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let mut s: u32 = 0;
        let insn_id = insn.id().0;
        let insn_len = insn.len() as u64;

        match insn_id {
            // =============================================================
            // NOP
            // =============================================================
            cs_insn::NOP => {}

            // =============================================================
            // MOV Xd, Xn  -- register copy
            // =============================================================
            cs_insn::MOV => {
                let (dst, src) = self.two_operands(operands, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(s),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // =============================================================
            // MOVZ / MOVN  -- move wide with zero / NOT
            // =============================================================
            cs_insn::MOVZ | cs_insn::MOVN => {
                let (dst, src) = self.two_operands(operands, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(s),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // =============================================================
            // MOVK Xd, #imm{, LSL #shift}  -- move wide with keep
            //   Semantics: Rd[shift+15:shift] = imm16, other bits unchanged
            // =============================================================
            cs_insn::MOVK => {
                if operands.len() >= 2 {
                    let dst = self.resolve_operand(&operands[0], address)?;
                    let imm = self.resolve_operand(&operands[1], address)?;
                    let shift_amt = match operands[1].shift {
                        Arm64Shift::Lsl(amt) => amt as u64,
                        _ => 0,
                    };
                    // shifted_imm = imm << shift_amt
                    let shifted = unique(s as u64 * 0x10 + 0x800, dst.size);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntLeft,
                        seq: seq(s),
                        output: Some(shifted),
                        inputs: SmallVec::from_slice(&[imm, constant(shift_amt, 4)]),
                    });
                    s += 1;
                    // mask = ~(0xFFFF << shift_amt)
                    let mask_val = !(0xFFFF_u64 << shift_amt);
                    let masked = unique(s as u64 * 0x10 + 0x800, dst.size);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntAnd,
                        seq: seq(s),
                        output: Some(masked),
                        inputs: SmallVec::from_slice(&[dst, constant(mask_val, dst.size)]),
                    });
                    s += 1;
                    // Rd = masked | shifted
                    ops.push(PcodeOp {
                        opcode: OpCode::IntOr,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[masked, shifted]),
                    });
                }
            }

            // =============================================================
            // ADD / SUB  (no flag update)
            // =============================================================
            cs_insn::ADD | cs_insn::SUB => {
                let opcode = if insn_id == cs_insn::ADD {
                    OpCode::IntAdd
                } else {
                    OpCode::IntSub
                };
                if operands.len() >= 3 {
                    let dst = self.resolve_operand(&operands[0], address)?;
                    let lhs = self.resolve_operand(&operands[1], address)?;
                    let rhs = self.resolve_shifted_operand(
                        &operands[2], dst.size, &mut ops, &mut s, address,
                    )?;
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[lhs, rhs]),
                    });
                } else {
                    let (dst, src) = self.two_operands(operands, address)?;
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[dst, src]),
                    });
                }
            }

            // =============================================================
            // ADDS / SUBS  (with NZCV flag update)
            // =============================================================
            cs_insn::ADDS | cs_insn::SUBS => {
                let opcode = if insn_id == cs_insn::ADDS {
                    OpCode::IntAdd
                } else {
                    OpCode::IntSub
                };
                if operands.len() >= 3 {
                    let dst = self.resolve_operand(&operands[0], address)?;
                    let lhs = self.resolve_operand(&operands[1], address)?;
                    let rhs = self.resolve_shifted_operand(
                        &operands[2], dst.size, &mut ops, &mut s, address,
                    )?;
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[lhs, rhs]),
                    });
                    s += 1;
                    self.emit_nzcv_update(dst, &mut ops, &mut s, address);
                } else {
                    let (dst, src) = self.two_operands(operands, address)?;
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[dst, src]),
                    });
                    s += 1;
                    self.emit_nzcv_update(dst, &mut ops, &mut s, address);
                }
            }

            // =============================================================
            // CMP Xn, Xm   -- alias for SUBS XZR, Xn, Xm
            // =============================================================
            cs_insn::CMP => {
                let (left, right) = self.two_operands(operands, address)?;
                let tmp = unique(0x100, left.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntSub,
                    seq: seq(s),
                    output: Some(tmp),
                    inputs: SmallVec::from_slice(&[left, right]),
                });
                s += 1;
                self.emit_nzcv_update(tmp, &mut ops, &mut s, address);
            }

            // =============================================================
            // AND / ORR / EOR
            // =============================================================
            cs_insn::AND | cs_insn::ORR | cs_insn::EOR => {
                let opcode = match insn_id {
                    cs_insn::AND => OpCode::IntAnd,
                    cs_insn::ORR => OpCode::IntOr,
                    cs_insn::EOR => OpCode::IntXor,
                    _ => unreachable!(),
                };
                if operands.len() >= 3 {
                    let dst = self.resolve_operand(&operands[0], address)?;
                    let lhs = self.resolve_operand(&operands[1], address)?;
                    let rhs = self.resolve_shifted_operand(
                        &operands[2], dst.size, &mut ops, &mut s, address,
                    )?;
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[lhs, rhs]),
                    });
                } else {
                    let (dst, src) = self.two_operands(operands, address)?;
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[dst, src]),
                    });
                }
            }

            // =============================================================
            // LSL / LSR / ASR
            // =============================================================
            cs_insn::LSL | cs_insn::LSR | cs_insn::ASR => {
                let opcode = match insn_id {
                    cs_insn::LSL => OpCode::IntLeft,
                    cs_insn::LSR => OpCode::IntRight,
                    cs_insn::ASR => OpCode::IntSRight,
                    _ => unreachable!(),
                };
                if operands.len() >= 3 {
                    let dst = self.resolve_operand(&operands[0], address)?;
                    let lhs = self.resolve_operand(&operands[1], address)?;
                    let rhs = self.resolve_operand(&operands[2], address)?;
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[lhs, rhs]),
                    });
                } else {
                    let (dst, src) = self.two_operands(operands, address)?;
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[dst, src]),
                    });
                }
            }

            // =============================================================
            // MUL Xd, Xn, Xm
            // =============================================================
            cs_insn::MUL => {
                if operands.len() >= 3 {
                    let dst = self.resolve_operand(&operands[0], address)?;
                    let lhs = self.resolve_operand(&operands[1], address)?;
                    let rhs = self.resolve_operand(&operands[2], address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::IntMult,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[lhs, rhs]),
                    });
                }
            }

            // =============================================================
            // LDR / LDRB / LDRH / LDRSB / LDRSH / LDRSW
            // =============================================================
            cs_insn::LDR | cs_insn::LDRB | cs_insn::LDRH
            | cs_insn::LDRSB | cs_insn::LDRSH | cs_insn::LDRSW => {
                if operands.len() >= 2 {
                    let dst = self.resolve_operand(&operands[0], address)?;
                    let addr_vn = self.resolve_mem_address(
                        &operands[1], &mut ops, &mut s, address,
                    )?;
                    let load_size = match insn_id {
                        cs_insn::LDRB | cs_insn::LDRSB => 1,
                        cs_insn::LDRH | cs_insn::LDRSH => 2,
                        cs_insn::LDRSW => 4,
                        _ => dst.size,
                    };
                    let loaded = unique(s as u64 * 0x10 + 0x500, load_size);
                    ops.push(PcodeOp {
                        opcode: OpCode::Load,
                        seq: seq(s),
                        output: Some(loaded),
                        inputs: SmallVec::from_slice(&[
                            constant(RAM_SPACE.0 as u64, 4),
                            addr_vn,
                        ]),
                    });
                    s += 1;
                    // Sign/zero extend when load is narrower than destination.
                    let is_signed = matches!(
                        insn_id,
                        cs_insn::LDRSW | cs_insn::LDRSB | cs_insn::LDRSH
                    );
                    if load_size < dst.size {
                        let ext_op = if is_signed {
                            OpCode::IntSExt
                        } else {
                            OpCode::IntZExt
                        };
                        ops.push(PcodeOp {
                            opcode: ext_op,
                            seq: seq(s),
                            output: Some(dst),
                            inputs: SmallVec::from_slice(&[loaded]),
                        });
                    } else {
                        ops.push(PcodeOp {
                            opcode: OpCode::Copy,
                            seq: seq(s),
                            output: Some(dst),
                            inputs: SmallVec::from_slice(&[loaded]),
                        });
                    }
                    s += 1;
                    self.emit_writeback(detail, &operands[1], &mut ops, &mut s, address);
                }
            }

            // =============================================================
            // STR / STRB / STRH
            // =============================================================
            cs_insn::STR | cs_insn::STRB | cs_insn::STRH => {
                if operands.len() >= 2 {
                    let src = self.resolve_operand(&operands[0], address)?;
                    let addr_vn = self.resolve_mem_address(
                        &operands[1], &mut ops, &mut s, address,
                    )?;
                    ops.push(PcodeOp {
                        opcode: OpCode::Store,
                        seq: seq(s),
                        output: None,
                        inputs: SmallVec::from_slice(&[
                            constant(RAM_SPACE.0 as u64, 4),
                            addr_vn,
                            src,
                        ]),
                    });
                    s += 1;
                    self.emit_writeback(detail, &operands[1], &mut ops, &mut s, address);
                }
            }

            // =============================================================
            // LDP Xt1, Xt2, [Xn{, #imm}]
            // =============================================================
            cs_insn::LDP => {
                if operands.len() >= 3 {
                    let dst1 = self.resolve_operand(&operands[0], address)?;
                    let dst2 = self.resolve_operand(&operands[1], address)?;
                    let addr_vn = self.resolve_mem_address(
                        &operands[2], &mut ops, &mut s, address,
                    )?;
                    let reg_size = dst1.size;

                    // First load
                    let loaded1 = unique(s as u64 * 0x10 + 0x500, reg_size);
                    ops.push(PcodeOp {
                        opcode: OpCode::Load,
                        seq: seq(s),
                        output: Some(loaded1),
                        inputs: SmallVec::from_slice(&[
                            constant(RAM_SPACE.0 as u64, 4),
                            addr_vn,
                        ]),
                    });
                    s += 1;
                    ops.push(PcodeOp {
                        opcode: OpCode::Copy,
                        seq: seq(s),
                        output: Some(dst1),
                        inputs: SmallVec::from_slice(&[loaded1]),
                    });
                    s += 1;

                    // Address of second slot
                    let addr2 = unique(s as u64 * 0x10 + 0x600, 8);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntAdd,
                        seq: seq(s),
                        output: Some(addr2),
                        inputs: SmallVec::from_slice(&[
                            addr_vn,
                            constant(reg_size as u64, 8),
                        ]),
                    });
                    s += 1;

                    // Second load
                    let loaded2 = unique(s as u64 * 0x10 + 0x500, reg_size);
                    ops.push(PcodeOp {
                        opcode: OpCode::Load,
                        seq: seq(s),
                        output: Some(loaded2),
                        inputs: SmallVec::from_slice(&[
                            constant(RAM_SPACE.0 as u64, 4),
                            addr2,
                        ]),
                    });
                    s += 1;
                    ops.push(PcodeOp {
                        opcode: OpCode::Copy,
                        seq: seq(s),
                        output: Some(dst2),
                        inputs: SmallVec::from_slice(&[loaded2]),
                    });
                    s += 1;

                    self.emit_writeback(detail, &operands[2], &mut ops, &mut s, address);
                }
            }

            // =============================================================
            // STP Xt1, Xt2, [Xn{, #imm}]
            // =============================================================
            cs_insn::STP => {
                if operands.len() >= 3 {
                    let src1 = self.resolve_operand(&operands[0], address)?;
                    let src2 = self.resolve_operand(&operands[1], address)?;
                    let addr_vn = self.resolve_mem_address(
                        &operands[2], &mut ops, &mut s, address,
                    )?;
                    let reg_size = src1.size;

                    // First store
                    ops.push(PcodeOp {
                        opcode: OpCode::Store,
                        seq: seq(s),
                        output: None,
                        inputs: SmallVec::from_slice(&[
                            constant(RAM_SPACE.0 as u64, 4),
                            addr_vn,
                            src1,
                        ]),
                    });
                    s += 1;

                    // Address of second slot
                    let addr2 = unique(s as u64 * 0x10 + 0x600, 8);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntAdd,
                        seq: seq(s),
                        output: Some(addr2),
                        inputs: SmallVec::from_slice(&[
                            addr_vn,
                            constant(reg_size as u64, 8),
                        ]),
                    });
                    s += 1;

                    // Second store
                    ops.push(PcodeOp {
                        opcode: OpCode::Store,
                        seq: seq(s),
                        output: None,
                        inputs: SmallVec::from_slice(&[
                            constant(RAM_SPACE.0 as u64, 4),
                            addr2,
                            src2,
                        ]),
                    });
                    s += 1;

                    self.emit_writeback(detail, &operands[2], &mut ops, &mut s, address);
                }
            }

            // =============================================================
            // B <label>  (unconditional)  /  B.cond <label>  (conditional)
            //
            // Capstone uses the same insn ID for both; the condition code
            // field in the detail distinguishes them.
            // =============================================================
            cs_insn::B => {
                let cc = detail.cc() as u32;
                if cc != 0 && cc != cs_cc::AL {
                    // B.cond -- conditional branch
                    if let Some(target) = self.extract_branch_target(operands) {
                        let cond = unique(s as u64 * 0x10 + 0x900, 1);
                        self.emit_condition_check(cc, &mut ops, &mut s, address, cond);
                        ops.push(PcodeOp {
                            opcode: OpCode::CBranch,
                            seq: seq(s),
                            output: None,
                            inputs: SmallVec::from_slice(&[ram(target, 8), cond]),
                        });
                    }
                } else {
                    // Unconditional branch
                    if let Some(target) = self.extract_branch_target(operands) {
                        ops.push(PcodeOp {
                            opcode: OpCode::Branch,
                            seq: seq(s),
                            output: None,
                            inputs: SmallVec::from_slice(&[ram(target, 8)]),
                        });
                    }
                }
            }

            // =============================================================
            // BL <label>  -- call
            // =============================================================
            cs_insn::BL => {
                if let Some(target) = self.extract_branch_target(operands) {
                    ops.push(PcodeOp {
                        opcode: OpCode::Call,
                        seq: seq(s),
                        output: None,
                        inputs: SmallVec::from_slice(&[ram(target, 8)]),
                    });
                }
            }

            // =============================================================
            // BLR Xn  -- indirect call
            // =============================================================
            cs_insn::BLR => {
                if !operands.is_empty() {
                    let target = self.resolve_operand(&operands[0], address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::CallInd,
                        seq: seq(s),
                        output: None,
                        inputs: SmallVec::from_slice(&[target]),
                    });
                }
            }

            // =============================================================
            // BR Xn  -- indirect branch
            // =============================================================
            cs_insn::BR => {
                if !operands.is_empty() {
                    let target = self.resolve_operand(&operands[0], address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::BranchInd,
                        seq: seq(s),
                        output: None,
                        inputs: SmallVec::from_slice(&[target]),
                    });
                }
            }

            // =============================================================
            // RET {Xn}  -- defaults to X30 / LR. An explicit Xn (e.g.
            // `ret x16` from a PLT thunk) returns to that register; reading
            // LR there would feed the decompiler the wrong return target.
            // =============================================================
            cs_insn::RET => {
                let target = if operands.is_empty() {
                    reg(30 * 8, 8)
                } else {
                    self.resolve_operand(&operands[0], address).unwrap_or_else(|_| reg(30 * 8, 8))
                };
                ops.push(PcodeOp {
                    opcode: OpCode::Return,
                    seq: seq(s),
                    output: None,
                    inputs: SmallVec::from_slice(&[target]),
                });
            }

            // =============================================================
            // CBZ Xt, <label>  /  CBNZ Xt, <label>
            // =============================================================
            cs_insn::CBZ | cs_insn::CBNZ => {
                if operands.len() >= 2 {
                    let test_reg = self.resolve_operand(&operands[0], address)?;
                    let target = self
                        .extract_branch_target(&operands[1..])
                        .unwrap_or(address + insn_len);

                    let cmp_op = if insn_id == cs_insn::CBZ {
                        OpCode::IntEqual
                    } else {
                        OpCode::IntNotEqual
                    };
                    let cond = unique(s as u64 * 0x10 + 0x900, 1);
                    ops.push(PcodeOp {
                        opcode: cmp_op,
                        seq: seq(s),
                        output: Some(cond),
                        inputs: SmallVec::from_slice(&[
                            test_reg,
                            constant(0, test_reg.size),
                        ]),
                    });
                    s += 1;
                    ops.push(PcodeOp {
                        opcode: OpCode::CBranch,
                        seq: seq(s),
                        output: None,
                        inputs: SmallVec::from_slice(&[ram(target, 8), cond]),
                    });
                }
            }

            // =============================================================
            // ADRP / ADR  -- computed address into register
            // =============================================================
            cs_insn::ADRP | cs_insn::ADR => {
                if operands.len() >= 2 {
                    let dst = self.resolve_operand(&operands[0], address)?;
                    let addr_val = self.resolve_operand(&operands[1], address)?;
                    ops.push(PcodeOp {
                        opcode: OpCode::Copy,
                        seq: seq(s),
                        output: Some(dst),
                        inputs: SmallVec::from_slice(&[addr_val]),
                    });
                }
            }

            // =============================================================
            // SXTW Xd, Wn  -- sign-extend 32 -> 64
            // =============================================================
            cs_insn::SXTW => {
                let (dst, src) = self.two_operands(operands, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntSExt,
                    seq: seq(s),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // =============================================================
            // UXTW Xd, Wn  -- zero-extend 32 -> 64
            // =============================================================
            cs_insn::UXTW => {
                let (dst, src) = self.two_operands(operands, address)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntZExt,
                    seq: seq(s),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            // =============================================================
            // Fallback: TBZ / TBNZ aren't exposed as named cs_insn constants
            // in this binding; detect them by mnemonic so the CFG sees a real
            // branch (otherwise they fall through to CallOther and a switch's
            // jump-table dispatch silently chains into the next instruction).
            // TBZ  Rt, #imm, label  -> branch if Rt[imm] == 0
            // TBNZ Rt, #imm, label  -> branch if Rt[imm] != 0
            // =============================================================
            _ if matches!(insn.mnemonic(), Some("tbz") | Some("tbnz")) => {
                if operands.len() >= 3 {
                    let test_reg = self.resolve_operand(&operands[0], address)?;
                    let bit_pos = self.resolve_operand(&operands[1], address)?;
                    let target = self
                        .extract_branch_target(&operands[2..])
                        .unwrap_or(address + insn_len);
                    // bit = (Rt >> imm) & 1
                    let shifted = unique(s as u64 * 0x10 + 0x900, test_reg.size);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntRight,
                        seq: seq(s),
                        output: Some(shifted),
                        inputs: SmallVec::from_slice(&[test_reg, bit_pos]),
                    });
                    s += 1;
                    let masked = unique(s as u64 * 0x10 + 0x900, test_reg.size);
                    ops.push(PcodeOp {
                        opcode: OpCode::IntAnd,
                        seq: seq(s),
                        output: Some(masked),
                        inputs: SmallVec::from_slice(&[shifted, constant(1, test_reg.size)]),
                    });
                    s += 1;
                    let cond = unique(s as u64 * 0x10 + 0x900, 1);
                    let cmp = if insn.mnemonic() == Some("tbz") {
                        OpCode::IntEqual
                    } else {
                        OpCode::IntNotEqual
                    };
                    ops.push(PcodeOp {
                        opcode: cmp,
                        seq: seq(s),
                        output: Some(cond),
                        inputs: SmallVec::from_slice(&[masked, constant(0, test_reg.size)]),
                    });
                    s += 1;
                    ops.push(PcodeOp {
                        opcode: OpCode::CBranch,
                        seq: seq(s),
                        output: None,
                        inputs: SmallVec::from_slice(&[ram(target, 8), cond]),
                    });
                }
            }

            // =============================================================
            // Fallback: emit CallOther for unrecognised instructions
            // =============================================================
            _ => {
                ops.push(PcodeOp {
                    opcode: OpCode::CallOther,
                    seq: seq(s),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(insn_id as u64, 4)]),
                });
            }
        }

        let _ = s;
        Ok(ops)
    }

    // -------------------------------------------------------------------
    // Operand resolution using capstone structured detail API
    // -------------------------------------------------------------------

    /// Resolve a single capstone `Arm64Operand` to a `VarnodeData`.
    fn resolve_operand(
        &self,
        op: &Arm64Operand,
        address: u64,
    ) -> Result<VarnodeData, LiftError> {
        match &op.op_type {
            Arm64OperandType::Reg(r) => {
                cs_reg_to_varnode(*r).ok_or_else(|| LiftError::Unsupported {
                    address,
                    mnemonic: format!("unsupported register {:?}", r),
                })
            }
            Arm64OperandType::Imm(imm) => Ok(constant(*imm as u64, 8)),
            Arm64OperandType::Mem(mem) => {
                // When used as a bare operand (not a memory address), return
                // the base register.  Actual memory operations use
                // `resolve_mem_address` instead.
                cs_reg_to_varnode(mem.base()).ok_or_else(|| LiftError::Unsupported {
                    address,
                    mnemonic: "mem operand with unsupported base".into(),
                })
            }
            _ => Err(LiftError::Unsupported {
                address,
                mnemonic: "unsupported operand type".into(),
            }),
        }
    }

    /// Resolve an operand, applying any shift that capstone reports on it.
    fn resolve_shifted_operand(
        &self,
        op: &Arm64Operand,
        result_size: u32,
        ops: &mut Vec<PcodeOp>,
        s: &mut u32,
        address: u64,
    ) -> Result<VarnodeData, LiftError> {
        let base = self.resolve_operand(op, address)?;
        let base = if base.space == CONST_SPACE && base.size != result_size {
            constant(base.offset, result_size)
        } else {
            base
        };

        let (shift_op, amt) = match op.shift {
            Arm64Shift::Lsl(a) if a > 0 => (Some(OpCode::IntLeft), a),
            Arm64Shift::Lsr(a) if a > 0 => (Some(OpCode::IntRight), a),
            Arm64Shift::Asr(a) if a > 0 => (Some(OpCode::IntSRight), a),
            _ => (None, 0),
        };

        if let Some(opcode) = shift_op {
            let shifted = unique(*s as u64 * 0x10 + 0x700, result_size);
            let seq = SeqNum::new(Address::new(RAM_SPACE, address), *s);
            *s += 1;
            ops.push(PcodeOp {
                opcode,
                seq,
                output: Some(shifted),
                inputs: SmallVec::from_slice(&[base, constant(amt as u64, 4)]),
            });
            Ok(shifted)
        } else {
            Ok(base)
        }
    }

    /// Compute the effective address for a memory operand.
    fn resolve_mem_address(
        &self,
        op: &Arm64Operand,
        ops: &mut Vec<PcodeOp>,
        s: &mut u32,
        address: u64,
    ) -> Result<VarnodeData, LiftError> {
        match &op.op_type {
            Arm64OperandType::Mem(mem) => self.compute_mem_addr(mem, ops, s, address),
            _ => self.resolve_operand(op, address),
        }
    }

    /// Build pcode to compute `base + index + disp` from an `Arm64OpMem`.
    fn compute_mem_addr(
        &self,
        mem: &Arm64OpMem,
        ops: &mut Vec<PcodeOp>,
        s: &mut u32,
        address: u64,
    ) -> Result<VarnodeData, LiftError> {
        let base_id = mem.base();
        let index_id = mem.index();
        let disp = mem.disp() as i64;

        let has_base = base_id.0 != 0;
        let has_index = index_id.0 != 0;
        let has_disp = disp != 0;

        if !has_base && !has_index {
            return Ok(constant(disp as u64, 8));
        }

        let mut result = if has_base {
            cs_reg_to_varnode(base_id).unwrap_or(constant(0, 8))
        } else {
            constant(0, 8)
        };

        // Widen a 4-byte base register to 8-byte address width.
        if result.size < 8 && result.space == REG_SPACE {
            let ext = unique(*s as u64 * 0x10 + 0x650, 8);
            let seq = SeqNum::new(Address::new(RAM_SPACE, address), *s);
            *s += 1;
            ops.push(PcodeOp {
                opcode: OpCode::IntZExt,
                seq,
                output: Some(ext),
                inputs: SmallVec::from_slice(&[result]),
            });
            result = ext;
        }

        if has_index {
            let idx_vn = cs_reg_to_varnode(index_id).unwrap_or(constant(0, 8));
            let added = unique(*s as u64 * 0x10 + 0x600, 8);
            let seq = SeqNum::new(Address::new(RAM_SPACE, address), *s);
            *s += 1;
            ops.push(PcodeOp {
                opcode: OpCode::IntAdd,
                seq,
                output: Some(added),
                inputs: SmallVec::from_slice(&[result, idx_vn]),
            });
            result = added;
        }

        if has_disp {
            let with_disp = unique(*s as u64 * 0x10 + 0x600, 8);
            let seq = SeqNum::new(Address::new(RAM_SPACE, address), *s);
            *s += 1;
            ops.push(PcodeOp {
                opcode: OpCode::IntAdd,
                seq,
                output: Some(with_disp),
                inputs: SmallVec::from_slice(&[result, constant(disp as u64, 8)]),
            });
            result = with_disp;
        }

        Ok(result)
    }

    /// Convenience: resolve two operands (dst, src) from a slice.
    fn two_operands(
        &self,
        operands: &[Arm64Operand],
        address: u64,
    ) -> Result<(VarnodeData, VarnodeData), LiftError> {
        if operands.len() < 2 {
            return Err(LiftError::DecodeFailed {
                address,
                reason: "expected at least 2 operands".into(),
            });
        }
        let dst = self.resolve_operand(&operands[0], address)?;
        let src_raw = self.resolve_operand(&operands[1], address)?;
        let src = if src_raw.space == CONST_SPACE && src_raw.size != dst.size {
            constant(src_raw.offset, dst.size)
        } else {
            src_raw
        };
        Ok((dst, src))
    }

    /// Extract a branch target address from operands.
    fn extract_branch_target(&self, operands: &[Arm64Operand]) -> Option<u64> {
        for op in operands {
            if let Arm64OperandType::Imm(imm) = &op.op_type {
                return Some(*imm as u64);
            }
        }
        None
    }

    // -------------------------------------------------------------------
    // NZCV flag helpers
    // -------------------------------------------------------------------

    /// Emit a simplified NZCV update: write the architectural NZCV register
    /// (Z at bit 30, N at bit 31; C and V left as 0). Previously this wrote
    /// to local `unique` slots that nothing else read, so `emit_condition_check`
    /// (which reads the real NZCV register) saw stale flags and conditional
    /// branches after adds/subs took the wrong path.
    fn emit_nzcv_update(
        &self,
        result: VarnodeData,
        ops: &mut Vec<PcodeOp>,
        s: &mut u32,
        address: u64,
    ) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);

        // is_zero (1 byte): result == 0
        let zf = unique(0xA00, 1);
        ops.push(PcodeOp {
            opcode: OpCode::IntEqual,
            seq: seq(*s),
            output: Some(zf),
            inputs: SmallVec::from_slice(&[result, constant(0, result.size)]),
        });
        *s += 1;
        // is_neg (1 byte): result <s 0
        let nf = unique(0xA01, 1);
        ops.push(PcodeOp {
            opcode: OpCode::IntSLess,
            seq: seq(*s),
            output: Some(nf),
            inputs: SmallVec::from_slice(&[result, constant(0, result.size)]),
        });
        *s += 1;
        // Pack into NZCV at the correct bit positions: zext to 4 bytes, shift,
        // OR. emit_condition_check expects Z at bit 30 and N at bit 31.
        let z32 = unique(0xA04, 4);
        ops.push(PcodeOp {
            opcode: OpCode::IntZExt,
            seq: seq(*s),
            output: Some(z32),
            inputs: SmallVec::from_slice(&[zf]),
        });
        *s += 1;
        let z_shifted = unique(0xA08, 4);
        ops.push(PcodeOp {
            opcode: OpCode::IntLeft,
            seq: seq(*s),
            output: Some(z_shifted),
            inputs: SmallVec::from_slice(&[z32, constant(30, 4)]),
        });
        *s += 1;
        let n32 = unique(0xA0C, 4);
        ops.push(PcodeOp {
            opcode: OpCode::IntZExt,
            seq: seq(*s),
            output: Some(n32),
            inputs: SmallVec::from_slice(&[nf]),
        });
        *s += 1;
        let n_shifted = unique(0xA10, 4);
        ops.push(PcodeOp {
            opcode: OpCode::IntLeft,
            seq: seq(*s),
            output: Some(n_shifted),
            inputs: SmallVec::from_slice(&[n32, constant(31, 4)]),
        });
        *s += 1;
        ops.push(PcodeOp {
            opcode: OpCode::IntOr,
            seq: seq(*s),
            output: Some(nzcv()),
            inputs: SmallVec::from_slice(&[z_shifted, n_shifted]),
        });
        *s += 1;
    }

    /// Emit a condition-code check for B.cond, writing a 1-byte boolean.
    fn emit_condition_check(
        &self,
        cc: u32,
        ops: &mut Vec<PcodeOp>,
        s: &mut u32,
        address: u64,
        out: VarnodeData,
    ) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let nzcv_vn = nzcv();

        match cc {
            // EQ: Z == 1 -> bit 30 of NZCV
            cs_cc::EQ => {
                let shifted = unique(*s as u64 * 0x10 + 0xA00, 4);
                ops.push(PcodeOp {
                    opcode: OpCode::IntRight,
                    seq: seq(*s),
                    output: Some(shifted),
                    inputs: SmallVec::from_slice(&[nzcv_vn, constant(30, 4)]),
                });
                *s += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntAnd,
                    seq: seq(*s),
                    output: Some(out),
                    inputs: SmallVec::from_slice(&[shifted, constant(1, 4)]),
                });
                *s += 1;
            }
            // NE: Z == 0
            cs_cc::NE => {
                let shifted = unique(*s as u64 * 0x10 + 0xA00, 4);
                ops.push(PcodeOp {
                    opcode: OpCode::IntRight,
                    seq: seq(*s),
                    output: Some(shifted),
                    inputs: SmallVec::from_slice(&[nzcv_vn, constant(30, 4)]),
                });
                *s += 1;
                let z_bit = unique(*s as u64 * 0x10 + 0xA00, 1);
                ops.push(PcodeOp {
                    opcode: OpCode::IntAnd,
                    seq: seq(*s),
                    output: Some(z_bit),
                    inputs: SmallVec::from_slice(&[shifted, constant(1, 4)]),
                });
                *s += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::BoolNegate,
                    seq: seq(*s),
                    output: Some(out),
                    inputs: SmallVec::from_slice(&[z_bit]),
                });
                *s += 1;
            }
            // Other conditions: approximate with NZCV != 0
            _ => {
                ops.push(PcodeOp {
                    opcode: OpCode::IntNotEqual,
                    seq: seq(*s),
                    output: Some(out),
                    inputs: SmallVec::from_slice(&[nzcv_vn, constant(0, 4)]),
                });
                *s += 1;
            }
        }
    }

    /// Emit a base-register writeback for pre-index or post-index addressing
    /// (indicated by `detail.writeback()`).
    fn emit_writeback(
        &self,
        detail: &Arm64InsnDetail<'_>,
        mem_op: &Arm64Operand,
        ops: &mut Vec<PcodeOp>,
        s: &mut u32,
        address: u64,
    ) {
        if !detail.writeback() {
            return;
        }
        if let Arm64OperandType::Mem(mem) = &mem_op.op_type {
            let base_id = mem.base();
            if let Some(base_vn) = cs_reg_to_varnode(base_id) {
                let disp = mem.disp() as i64;
                if disp != 0 {
                    let seq = SeqNum::new(Address::new(RAM_SPACE, address), *s);
                    *s += 1;
                    ops.push(PcodeOp {
                        opcode: OpCode::IntAdd,
                        seq,
                        output: Some(base_vn),
                        inputs: SmallVec::from_slice(&[
                            base_vn,
                            constant(disp as u64, base_vn.size),
                        ]),
                    });
                }
            }
        }
    }
}

impl Default for Aarch64Lifter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PcodeLift implementation
// ---------------------------------------------------------------------------
impl PcodeLift for Aarch64Lifter {
    fn lift_instruction(
        &self,
        memory: &Memory,
        address: u64,
    ) -> Result<LiftedInstruction, LiftError> {
        // AArch64 instructions are always 4 bytes.
        let mut buf = [0u8; 4];
        memory
            .read_bytes(address, &mut buf)
            .map_err(|_| LiftError::UnreadableAddress(address))?;

        let insns = self
            .cs
            .disasm_count(&buf, address, 1)
            .map_err(|e| LiftError::DecodeFailed {
                address,
                reason: e.to_string(),
            })?;

        let insn = insns
            .iter()
            .next()
            .ok_or_else(|| LiftError::DecodeFailed {
                address,
                reason: "no instruction decoded".into(),
            })?;

        let mnemonic_str = insn.mnemonic().unwrap_or("???");
        let op_str = insn.op_str().unwrap_or("");
        let mnemonic = if op_str.is_empty() {
            mnemonic_str.to_string()
        } else {
            format!("{} {}", mnemonic_str, op_str)
        };

        // Obtain structured instruction detail from capstone.
        let detail = self
            .cs
            .insn_detail(insn)
            .map_err(|e| LiftError::DecodeFailed {
                address,
                reason: format!("cannot get detail: {}", e),
            })?;

        let arch_detail = detail.arch_detail();
        let arm64_detail =
            arch_detail
                .arm64()
                .ok_or_else(|| LiftError::DecodeFailed {
                    address,
                    reason: "not arm64 detail".into(),
                })?;

        let operands: Vec<Arm64Operand> = arm64_detail.operands().collect();
        let pcode_ops = self.lift_insn(insn, arm64_detail, &operands, address)?;

        Ok(LiftedInstruction {
            address,
            length: insn.len() as u32,
            mnemonic,
            ops: pcode_ops,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
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
        let lifter = Aarch64Lifter::new();
        // NOP = 0xD503201F (little-endian: 1f 20 03 d5)
        let mem = make_memory(&[0x1f, 0x20, 0x03, 0xd5], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert!(lifted.ops.is_empty(), "NOP should produce no pcode ops");
    }

    #[test]
    fn lift_mov_x0_x1() {
        let lifter = Aarch64Lifter::new();
        // MOV X0, X1 = 0xAA0103E0 (little-endian: e0 03 01 aa)
        let mem = make_memory(&[0xe0, 0x03, 0x01, 0xaa], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        // Capstone may decode as MOV (-> Copy) or ORR (-> IntOr).
        assert!(!lifted.ops.is_empty());
        let first = &lifted.ops[0];
        assert!(
            first.opcode == OpCode::Copy || first.opcode == OpCode::IntOr,
            "expected Copy or IntOr, got {:?}",
            first.opcode
        );
    }

    #[test]
    fn lift_add() {
        let lifter = Aarch64Lifter::new();
        // ADD X0, X1, X2 = 0x8B020020 (little-endian: 20 00 02 8b)
        let mem = make_memory(&[0x20, 0x00, 0x02, 0x8b], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert!(
            lifted.ops.iter().any(|op| op.opcode == OpCode::IntAdd),
            "ADD should produce IntAdd, got: {:?}",
            lifted.ops.iter().map(|op| op.opcode).collect::<Vec<_>>()
        );
    }

    #[test]
    fn lift_ret() {
        let lifter = Aarch64Lifter::new();
        // RET = 0xD65F03C0 (little-endian: c0 03 5f d6)
        let mem = make_memory(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::Return);
    }

    #[test]
    fn lift_function_prologue() {
        let lifter = Aarch64Lifter::new();
        // STP X29, X30, [SP, #-16]!  = 0xA9BF7BFD (fd 7b bf a9)
        // MOV X29, SP                = 0x910003FD (fd 03 00 91)
        let code = [
            0xfd, 0x7b, 0xbf, 0xa9, // stp x29, x30, [sp, #-16]!
            0xfd, 0x03, 0x00, 0x91, // mov x29, sp  (ADD x29, sp, #0)
        ];
        let mem = make_memory(&code, 0x1000);
        let lifted = lifter.lift_range(&mem, 0x1000, 2).unwrap();
        assert_eq!(lifted.len(), 2);

        // STP should produce Store ops
        assert!(
            lifted[0].ops.iter().any(|op| op.opcode == OpCode::Store),
            "STP should produce Store ops, got: {:?}",
            lifted[0]
                .ops
                .iter()
                .map(|op| op.opcode)
                .collect::<Vec<_>>()
        );

        // MOV x29, sp  (encoded as ADD x29, sp, #0)
        assert!(
            lifted[1]
                .ops
                .iter()
                .any(|op| op.opcode == OpCode::Copy || op.opcode == OpCode::IntAdd),
            "MOV X29, SP should produce Copy or IntAdd, got: {:?}",
            lifted[1]
                .ops
                .iter()
                .map(|op| op.opcode)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn lift_sub_imm() {
        let lifter = Aarch64Lifter::new();
        // SUB SP, SP, #0x20 = 0xD10083FF (little-endian: ff 83 00 d1)
        let mem = make_memory(&[0xff, 0x83, 0x00, 0xd1], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert!(
            lifted.ops.iter().any(|op| op.opcode == OpCode::IntSub),
            "SUB should produce IntSub"
        );
    }

    #[test]
    fn lift_bl() {
        let lifter = Aarch64Lifter::new();
        // BL #0x100 (from 0x1000) = 0x94000040 (40 00 00 94)
        let mem = make_memory(&[0x40, 0x00, 0x00, 0x94], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::Call);
    }

    #[test]
    fn lift_b_unconditional() {
        let lifter = Aarch64Lifter::new();
        // B #0x100 (from 0x1000) = 0x14000040 (40 00 00 14)
        let mem = make_memory(&[0x40, 0x00, 0x00, 0x14], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert!(
            lifted.ops.iter().any(|op| op.opcode == OpCode::Branch),
            "B should produce Branch"
        );
    }

    #[test]
    fn lift_cbz() {
        let lifter = Aarch64Lifter::new();
        // CBZ X0, +0x10 (from 0x1000) = 0xB4000080 (80 00 00 b4)
        let mem = make_memory(&[0x80, 0x00, 0x00, 0xb4], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert!(
            lifted.ops.iter().any(|op| op.opcode == OpCode::IntEqual),
            "CBZ should produce IntEqual"
        );
        assert!(
            lifted.ops.iter().any(|op| op.opcode == OpCode::CBranch),
            "CBZ should produce CBranch"
        );
    }

    #[test]
    fn lift_ldr_str_basic() {
        let lifter = Aarch64Lifter::new();
        // LDR X0, [X1] = 0xF9400020 (20 00 40 f9)
        let mem = make_memory(&[0x20, 0x00, 0x40, 0xf9], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert!(
            lifted.ops.iter().any(|op| op.opcode == OpCode::Load),
            "LDR should produce Load"
        );

        // STR X0, [X1] = 0xF9000020 (20 00 00 f9)
        let mem2 = make_memory(&[0x20, 0x00, 0x00, 0xf9], 0x2000);
        let lifted2 = lifter.lift_instruction(&mem2, 0x2000).unwrap();
        assert_eq!(lifted2.length, 4);
        assert!(
            lifted2.ops.iter().any(|op| op.opcode == OpCode::Store),
            "STR should produce Store"
        );
    }

    #[test]
    fn lift_cmp() {
        let lifter = Aarch64Lifter::new();
        // CMP X0, X1 = SUBS XZR, X0, X1 = 0xEB01001F (1f 00 01 eb)
        let mem = make_memory(&[0x1f, 0x00, 0x01, 0xeb], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert!(
            lifted.ops.iter().any(|op| op.opcode == OpCode::IntSub),
            "CMP should produce IntSub"
        );
        assert!(
            lifted.ops.iter().any(|op| op.opcode == OpCode::IntEqual),
            "CMP should produce IntEqual for Z flag"
        );
    }

    #[test]
    fn lift_cmp_writes_nzcv_register() {
        // Without the fix, emit_nzcv_update wrote to local unique slots that
        // emit_condition_check never read, so flags set by adds/cmp were
        // invisible to b.eq / b.ne and conditional branches took the wrong path.
        let lifter = Aarch64Lifter::new();
        // CMP X0, X1 = 0xEB01001F
        let mem = make_memory(&[0x1f, 0x00, 0x01, 0xeb], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // The final OR producing the packed NZCV must write the architectural
        // register at REG_SPACE offset 0x200, not a unique.
        let nzcv_writer = lifted.ops.iter().find(|op|
            op.opcode == OpCode::IntOr
                && op.output.map(|v| v.space == SpaceId::REGISTER && v.offset == 0x200).unwrap_or(false));
        assert!(nzcv_writer.is_some(),
            "CMP must commit Z/N into the NZCV register so B.cond sees them");
    }

    #[test]
    fn lift_tbz_emits_cbranch() {
        // TBZ W0, #3, +0x10 from 0x1000 = 0x36180080
        // (bit 11:5 = imm14 = 2 (target 0x1010 / 4 = 2 instructions ahead -> imm * 4 = 8))
        // Hand-assembled: TBZ Rt, #imm, label encoding 0011 0110 ...
        // TBZ x5 (Rt=5) bit #3, +8 bytes -> Capstone decodes from raw bytes.
        // Use a known TBZ encoding: TBZ w0, #0, .+0 = 0x36000000
        let lifter = Aarch64Lifter::new();
        let mem = make_memory(&[0x00, 0x00, 0x00, 0x36], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        // Must emit a CBranch (not CallOther). The previous code fell into the
        // fallback and silently produced CallOther, breaking the CFG split.
        assert!(lifted.ops.iter().any(|op| op.opcode == OpCode::CBranch),
            "TBZ should produce CBranch, got ops: {:?}",
            lifted.ops.iter().map(|o| o.opcode).collect::<Vec<_>>());
        assert!(!lifted.ops.iter().any(|op| op.opcode == OpCode::CallOther),
            "TBZ should no longer fall through to CallOther");
    }

    #[test]
    fn lift_ret_xn_uses_operand_not_lr() {
        // RET X16 = 0xD65F0200. Without the fix, RET hard-coded the LR (X30)
        // register, so a PLT thunk's `ret x16` would return to the wrong target.
        let lifter = Aarch64Lifter::new();
        let mem = make_memory(&[0x00, 0x02, 0x5f, 0xd6], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let ret = lifted.ops.iter().find(|op| op.opcode == OpCode::Return)
            .expect("expected Return");
        // Inputs[0] should be X16 (offset 16*8 = 128), not X30 (240).
        assert_eq!(ret.inputs[0].offset, 16 * 8,
            "RET X16 must read X16, not the default LR");
    }
}
