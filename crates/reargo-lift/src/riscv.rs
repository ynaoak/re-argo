//! RISC-V RV32IMC → P-code lifter.
//!
//! Decodes the RV32I base integer set, the M (mul/div) extension, and the
//! common C (compressed, 16-bit) instructions directly into P-code. Capstone
//! supplies disassembly text. Instruction length is detected from the low two
//! bits so that mixed 16/32-bit streams stay aligned even for compressed
//! instructions that are not lifted (those emit no P-code but a correct length).

use reargo_core::address::{Address, SpaceId};
use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use reargo_loader::Memory;
use smallvec::SmallVec;

use crate::lift::{LiftError, LiftedInstruction, PcodeLift};

const CONST_SPACE: SpaceId = SpaceId::CONST;
const RAM_SPACE: SpaceId = SpaceId::RAM;
const REG_SPACE: SpaceId = SpaceId::REGISTER;
const UNIQUE_SPACE: SpaceId = SpaceId::UNIQUE;

const RA_INDEX: u32 = 1; // x1 = ra
const SP_INDEX: u32 = 2; // x2 = sp

fn constant(value: u64, size: u32) -> VarnodeData {
    VarnodeData::new(CONST_SPACE, value, size)
}

fn ram(addr: u64) -> VarnodeData {
    VarnodeData::new(RAM_SPACE, addr, 4)
}

fn unique(offset: u64, size: u32) -> VarnodeData {
    VarnodeData::new(UNIQUE_SPACE, offset, size)
}

/// Source operand for register `n`: x0 reads as constant 0.
fn xin(n: u32) -> VarnodeData {
    if n == 0 {
        constant(0, 4)
    } else {
        VarnodeData::new(REG_SPACE, n as u64 * 4, 4)
    }
}

/// Destination operand for register `n`: writes to x0 are discarded.
fn xout(n: u32) -> Option<VarnodeData> {
    if n == 0 {
        None
    } else {
        Some(VarnodeData::new(REG_SPACE, n as u64 * 4, 4))
    }
}

/// Compressed 3-bit register field maps to x8..x15.
fn creg(n3: u32) -> u32 {
    8 + (n3 & 0x7)
}

fn sext(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

/// Extract bits [hi:lo] (inclusive) from `word`.
fn bits(word: u32, hi: u32, lo: u32) -> u32 {
    (word >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

pub struct RiscVLifter {
    cs: capstone::Capstone,
}

unsafe impl Send for RiscVLifter {}
unsafe impl Sync for RiscVLifter {}

impl RiscVLifter {
    pub fn new_rv32() -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .extra_mode(std::iter::once(arch::riscv::ArchExtraMode::RiscVC))
            .build()
            .expect("failed to create RISC-V 32 capstone");
        Self { cs }
    }

    /// Lift a 32-bit RV32I/M instruction.
    fn lift_32(&self, word: u32, address: u64) -> Vec<PcodeOp> {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let mut s = 0u32;

        let opcode = word & 0x7F;
        let rd = bits(word, 11, 7);
        let funct3 = bits(word, 14, 12);
        let rs1 = bits(word, 19, 15);
        let rs2 = bits(word, 24, 20);
        let funct7 = bits(word, 31, 25);

        let i_imm = sext((word >> 20) as u64, 12) & 0xFFFF_FFFF;
        let s_imm = sext((((funct7 << 5) | rd) as u64) & 0xFFF, 12) & 0xFFFF_FFFF;
        let u_imm = (word & 0xFFFF_F000) as u64;
        // B-type immediate: imm[12|10:5|4:1|11]
        let b_imm = {
            let imm = ((bits(word, 31, 31) << 12)
                | (bits(word, 7, 7) << 11)
                | (bits(word, 30, 25) << 5)
                | (bits(word, 11, 8) << 1)) as u64;
            sext(imm, 13)
        };
        // J-type immediate: imm[20|10:1|11|19:12]
        let j_imm = {
            let imm = ((bits(word, 31, 31) << 20)
                | (bits(word, 19, 12) << 12)
                | (bits(word, 20, 20) << 11)
                | (bits(word, 30, 21) << 1)) as u64;
            sext(imm, 21)
        };

        let push = |ops: &mut Vec<PcodeOp>, s: &mut u32, op: OpCode, out: Option<VarnodeData>, ins: &[VarnodeData]| {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: out, inputs: SmallVec::from_slice(ins) });
            *s += 1;
        };

        match opcode {
            0x37 => {
                // LUI
                if let Some(out) = xout(rd) {
                    push(&mut ops, &mut s, OpCode::Copy, Some(out), &[constant(u_imm, 4)]);
                }
            }
            0x17 => {
                // AUIPC: rd = pc + u_imm
                if let Some(out) = xout(rd) {
                    push(&mut ops, &mut s, OpCode::Copy, Some(out), &[constant(address.wrapping_add(u_imm) & 0xFFFF_FFFF, 4)]);
                }
            }
            0x6F => {
                // JAL: rd = PC + 4; branch to PC + j_imm. The link write
                // is what differentiates JAL from a plain branch -- if rd
                // is x0 the assembler form is `j`. Without it, every
                // callee's `ret` returned to a stale value.
                let target = address.wrapping_add(j_imm) & 0xFFFF_FFFF;
                if let Some(link) = xout(rd) {
                    push(&mut ops, &mut s, OpCode::Copy, Some(link),
                        &[constant((address + 4) & 0xFFFF_FFFF, 4)]);
                }
                if rd == 0 {
                    push(&mut ops, &mut s, OpCode::Branch, None, &[ram(target)]);
                } else {
                    push(&mut ops, &mut s, OpCode::Call, None, &[ram(target)]);
                }
            }
            0x67 => {
                // JALR rd, imm(rs1): target = (rs1 + imm) & ~1;
                //                    rd = PC + 4.
                // Always materialise the target into a unique BEFORE
                // writing the link so the rs1 == rd case (e.g.
                // `jalr ra, 0(ra)`) reads the pre-link value. The
                // previous code captured `xin(rs1)` directly when
                // imm == 0 and never linked, so a tail-call-style
                // `jalr` left rd stale.
                let target = unique(0x400, 4);
                if i_imm == 0 {
                    push(&mut ops, &mut s, OpCode::Copy, Some(target), &[xin(rs1)]);
                } else {
                    push(&mut ops, &mut s, OpCode::IntAdd, Some(target),
                        &[xin(rs1), constant(i_imm, 4)]);
                }
                if let Some(link) = xout(rd) {
                    push(&mut ops, &mut s, OpCode::Copy, Some(link),
                        &[constant((address + 4) & 0xFFFF_FFFF, 4)]);
                }
                if rd == 0 {
                    if rs1 == RA_INDEX && i_imm == 0 {
                        push(&mut ops, &mut s, OpCode::Return, None, &[target]);
                    } else {
                        push(&mut ops, &mut s, OpCode::BranchInd, None, &[target]);
                    }
                } else {
                    push(&mut ops, &mut s, OpCode::CallInd, None, &[target]);
                }
            }
            0x63 => {
                // BRANCH
                let target = address.wrapping_add(b_imm) & 0xFFFF_FFFF;
                let cond = unique(0x500, 1);
                let (op, a, b) = match funct3 {
                    0 => (OpCode::IntEqual, xin(rs1), xin(rs2)),        // beq
                    1 => (OpCode::IntNotEqual, xin(rs1), xin(rs2)),     // bne
                    4 => (OpCode::IntSLess, xin(rs1), xin(rs2)),        // blt
                    5 => (OpCode::IntSLessEqual, xin(rs2), xin(rs1)),   // bge: rs1>=rs2
                    6 => (OpCode::IntLess, xin(rs1), xin(rs2)),         // bltu
                    7 => (OpCode::IntLessEqual, xin(rs2), xin(rs1)),    // bgeu
                    _ => return ops,
                };
                push(&mut ops, &mut s, op, Some(cond), &[a, b]);
                push(&mut ops, &mut s, OpCode::CBranch, None, &[ram(target), cond]);
            }
            0x03 => {
                // LOAD
                let (load_size, signed) = match funct3 {
                    0 => (1, true),  // lb
                    1 => (2, true),  // lh
                    2 => (4, false), // lw
                    4 => (1, false), // lbu
                    5 => (2, false), // lhu
                    _ => return ops,
                };
                if let Some(out) = xout(rd) {
                    let addr = unique(0x600, 4);
                    push(&mut ops, &mut s, OpCode::IntAdd, Some(addr), &[xin(rs1), constant(i_imm, 4)]);
                    if load_size == 4 {
                        push(&mut ops, &mut s, OpCode::Load, Some(out), &[constant(RAM_SPACE.0 as u64, 4), addr]);
                    } else {
                        let loaded = unique(0x610, load_size);
                        push(&mut ops, &mut s, OpCode::Load, Some(loaded), &[constant(RAM_SPACE.0 as u64, 4), addr]);
                        let ext = if signed { OpCode::IntSExt } else { OpCode::IntZExt };
                        push(&mut ops, &mut s, ext, Some(out), &[loaded]);
                    }
                }
            }
            0x23 => {
                // STORE
                let store_size = match funct3 {
                    0 => 1, // sb
                    1 => 2, // sh
                    2 => 4, // sw
                    _ => return ops,
                };
                let addr = unique(0x600, 4);
                push(&mut ops, &mut s, OpCode::IntAdd, Some(addr), &[xin(rs1), constant(s_imm, 4)]);
                let value = if rs2 == 0 {
                    constant(0, store_size)
                } else {
                    VarnodeData::new(REG_SPACE, rs2 as u64 * 4, store_size)
                };
                push(&mut ops, &mut s, OpCode::Store, None, &[constant(RAM_SPACE.0 as u64, 4), addr, value]);
            }
            0x13 => {
                // OP-IMM
                if let Some(out) = xout(rd) {
                    let shamt = bits(word, 24, 20);
                    let (op, b) = match funct3 {
                        0 => (OpCode::IntAdd, constant(i_imm, 4)),     // addi
                        2 => (OpCode::IntSLess, constant(i_imm, 4)),   // slti
                        3 => (OpCode::IntLess, constant(i_imm, 4)),    // sltiu
                        4 => (OpCode::IntXor, constant(i_imm, 4)),     // xori
                        6 => (OpCode::IntOr, constant(i_imm, 4)),      // ori
                        7 => (OpCode::IntAnd, constant(i_imm, 4)),     // andi
                        1 => (OpCode::IntLeft, constant(shamt as u64, 4)), // slli
                        5 => {
                            let op = if funct7 == 0x20 { OpCode::IntSRight } else { OpCode::IntRight };
                            (op, constant(shamt as u64, 4))
                        }
                        _ => return ops,
                    };
                    push(&mut ops, &mut s, op, Some(out), &[xin(rs1), b]);
                }
            }
            0x33 => {
                // OP (register-register), incl. M extension
                if let Some(out) = xout(rd) {
                    let op = if funct7 == 0x01 {
                        // M extension
                        match funct3 {
                            0 => OpCode::IntMult,  // mul
                            4 => OpCode::IntSDiv,  // div
                            5 => OpCode::IntDiv,   // divu
                            6 => OpCode::IntSRem,  // rem
                            7 => OpCode::IntRem,   // remu
                            // mulh / mulhsu / mulhu need a high-half
                            // multiply that P-code doesn't model with a
                            // single op. Surface them as CallOther so the
                            // emulator can flag the gap instead of
                            // silently producing an empty op list.
                            _ => {
                                push(&mut ops, &mut s, OpCode::CallOther, None,
                                    &[constant(0x3300 | (funct3 as u64), 4)]);
                                return ops;
                            }
                        }
                    } else {
                        match funct3 {
                            0 => if funct7 == 0x20 { OpCode::IntSub } else { OpCode::IntAdd },
                            1 => OpCode::IntLeft,   // sll
                            2 => OpCode::IntSLess,  // slt
                            3 => OpCode::IntLess,   // sltu
                            4 => OpCode::IntXor,    // xor
                            5 => if funct7 == 0x20 { OpCode::IntSRight } else { OpCode::IntRight },
                            6 => OpCode::IntOr,     // or
                            7 => OpCode::IntAnd,    // and
                            _ => return ops,
                        }
                    };
                    // Variable shifts (sll/srl/sra) use only rs2's low 5 bits;
                    // mask so a shift amount >= 32 doesn't collapse to 0 under
                    // P-code's at-width shift semantics. The M-extension ops
                    // (funct7 == 0x01) reuse funct3 1/5 for mulh/divu, so only
                    // mask for the base integer shifts.
                    let is_shift = funct7 != 0x01 && matches!(funct3, 1 | 5);
                    if is_shift {
                        let amt = unique(0x108, 4);
                        push(&mut ops, &mut s, OpCode::IntAnd, Some(amt), &[xin(rs2), constant(0x1F, 4)]);
                        push(&mut ops, &mut s, op, Some(out), &[xin(rs1), amt]);
                    } else {
                        push(&mut ops, &mut s, op, Some(out), &[xin(rs1), xin(rs2)]);
                    }
                }
            }
            // FENCE (0x0F) is a memory-ordering barrier; SYSTEM (0x73)
            // covers ECALL / EBREAK / CSR*. None of these have ordinary
            // data-flow semantics, but silently dropping them hid every
            // ecall site from analysis. Emit CallOther so the emulator
            // and downstream passes see the boundary.
            0x0F => {
                push(&mut ops, &mut s, OpCode::CallOther, None,
                    &[constant(0x0F, 4)]);
            }
            0x73 => {
                push(&mut ops, &mut s, OpCode::CallOther, None,
                    &[constant(0x73_00 | (funct3 as u64), 4)]);
            }
            _ => {
                // Truly unrecognised opcode bits. Same rationale --
                // surface, don't swallow.
                push(&mut ops, &mut s, OpCode::CallOther, None,
                    &[constant(opcode as u64, 4)]);
            }
        }

        let _ = s;
        ops
    }

    /// Lift a 16-bit compressed (RVC) instruction.
    fn lift_16(&self, half: u16, address: u64) -> Vec<PcodeOp> {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let w = half as u32;
        let mut ops: Vec<PcodeOp> = Vec::new();
        let mut s = 0u32;
        let quadrant = w & 0x3;
        let funct3 = bits(w, 15, 13);

        let push = |ops: &mut Vec<PcodeOp>, s: &mut u32, op: OpCode, out: Option<VarnodeData>, ins: &[VarnodeData]| {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: out, inputs: SmallVec::from_slice(ins) });
            *s += 1;
        };

        match (quadrant, funct3) {
            (0, 0) => {
                // c.addi4spn: rd' = sp + nzuimm
                let rd = creg(bits(w, 4, 2));
                let imm = ((bits(w, 10, 7) << 6) | (bits(w, 12, 11) << 4) | (bits(w, 5, 5) << 3) | (bits(w, 6, 6) << 2)) as u64;
                if imm != 0 && let Some(out) = xout(rd) {
                    push(&mut ops, &mut s, OpCode::IntAdd, Some(out), &[xin(SP_INDEX), constant(imm, 4)]);
                }
            }
            (0, 2) => {
                // c.lw: rd' = load(rs1' + uimm)
                let rd = creg(bits(w, 4, 2));
                let rs1 = creg(bits(w, 9, 7));
                let imm = ((bits(w, 5, 5) << 6) | (bits(w, 12, 10) << 3) | (bits(w, 6, 6) << 2)) as u64;
                if let Some(out) = xout(rd) {
                    let addr = unique(0x600, 4);
                    push(&mut ops, &mut s, OpCode::IntAdd, Some(addr), &[xin(rs1), constant(imm, 4)]);
                    push(&mut ops, &mut s, OpCode::Load, Some(out), &[constant(RAM_SPACE.0 as u64, 4), addr]);
                }
            }
            (0, 6) => {
                // c.sw: store(rs1' + uimm, rs2')
                let rs2 = creg(bits(w, 4, 2));
                let rs1 = creg(bits(w, 9, 7));
                let imm = ((bits(w, 5, 5) << 6) | (bits(w, 12, 10) << 3) | (bits(w, 6, 6) << 2)) as u64;
                let addr = unique(0x600, 4);
                push(&mut ops, &mut s, OpCode::IntAdd, Some(addr), &[xin(rs1), constant(imm, 4)]);
                push(&mut ops, &mut s, OpCode::Store, None, &[constant(RAM_SPACE.0 as u64, 4), addr, xin(rs2)]);
            }
            (1, 0) => {
                // c.addi / c.nop: rd += sext(imm)
                let rd = bits(w, 11, 7);
                let imm = sext(((bits(w, 12, 12) << 5) | bits(w, 6, 2)) as u64, 6) & 0xFFFF_FFFF;
                if rd != 0 && let Some(out) = xout(rd) {
                    push(&mut ops, &mut s, OpCode::IntAdd, Some(out), &[xin(rd), constant(imm, 4)]);
                }
            }
            (1, 1) => {
                // c.jal (RV32): ra = PC + 2; call address + imm.
                // Compressed instructions are 2 bytes, so the link is
                // PC + 2 (not PC + 4 as for the 32-bit JAL).
                let imm = cj_imm(w);
                let target = address.wrapping_add(imm) & 0xFFFF_FFFF;
                if let Some(link) = xout(RA_INDEX) {
                    push(&mut ops, &mut s, OpCode::Copy, Some(link),
                        &[constant((address + 2) & 0xFFFF_FFFF, 4)]);
                }
                push(&mut ops, &mut s, OpCode::Call, None, &[ram(target)]);
            }
            (1, 2) => {
                // c.li: rd = sext(imm)
                let rd = bits(w, 11, 7);
                let imm = sext(((bits(w, 12, 12) << 5) | bits(w, 6, 2)) as u64, 6) & 0xFFFF_FFFF;
                if let Some(out) = xout(rd) {
                    push(&mut ops, &mut s, OpCode::Copy, Some(out), &[constant(imm, 4)]);
                }
            }
            (1, 3) => {
                let rd = bits(w, 11, 7);
                if rd == SP_INDEX {
                    // c.addi16sp
                    let imm = sext(
                        ((bits(w, 12, 12) << 9) | (bits(w, 4, 3) << 7) | (bits(w, 5, 5) << 6) | (bits(w, 2, 2) << 5) | (bits(w, 6, 6) << 4)) as u64,
                        10,
                    ) & 0xFFFF_FFFF;
                    push(&mut ops, &mut s, OpCode::IntAdd, Some(VarnodeData::new(REG_SPACE, SP_INDEX as u64 * 4, 4)), &[xin(SP_INDEX), constant(imm, 4)]);
                } else if let Some(out) = xout(rd) {
                    // c.lui: rd = sext(imm) << 12
                    let imm = sext(((bits(w, 12, 12) << 17) | (bits(w, 6, 2) << 12)) as u64, 18) & 0xFFFF_FFFF;
                    push(&mut ops, &mut s, OpCode::Copy, Some(out), &[constant(imm, 4)]);
                }
            }
            (1, 4) => {
                // MISC-ALU (CB/CA forms)
                let rd = creg(bits(w, 9, 7));
                let sub = bits(w, 11, 10);
                match sub {
                    0 | 1 => {
                        // c.srli / c.srai
                        let shamt = ((bits(w, 12, 12) << 5) | bits(w, 6, 2)) as u64;
                        let op = if sub == 0 { OpCode::IntRight } else { OpCode::IntSRight };
                        if let Some(out) = xout(rd) {
                            push(&mut ops, &mut s, op, Some(out), &[xin(rd), constant(shamt, 4)]);
                        }
                    }
                    2 => {
                        // c.andi
                        let imm = sext(((bits(w, 12, 12) << 5) | bits(w, 6, 2)) as u64, 6) & 0xFFFF_FFFF;
                        if let Some(out) = xout(rd) {
                            push(&mut ops, &mut s, OpCode::IntAnd, Some(out), &[xin(rd), constant(imm, 4)]);
                        }
                    }
                    3 => {
                        // c.sub/c.xor/c.or/c.and
                        let rs2 = creg(bits(w, 4, 2));
                        let op = match bits(w, 6, 5) {
                            0 => OpCode::IntSub,
                            1 => OpCode::IntXor,
                            2 => OpCode::IntOr,
                            _ => OpCode::IntAnd,
                        };
                        if let Some(out) = xout(rd) {
                            push(&mut ops, &mut s, op, Some(out), &[xin(rd), xin(rs2)]);
                        }
                    }
                    _ => {}
                }
            }
            (1, 5) => {
                // c.j: branch address + imm
                let imm = cj_imm(w);
                let target = address.wrapping_add(imm) & 0xFFFF_FFFF;
                push(&mut ops, &mut s, OpCode::Branch, None, &[ram(target)]);
            }
            (1, 6) | (1, 7) => {
                // c.beqz / c.bnez: rs1' vs 0
                let rs1 = creg(bits(w, 9, 7));
                let imm = sext(
                    ((bits(w, 12, 12) << 8) | (bits(w, 6, 5) << 6) | (bits(w, 2, 2) << 5) | (bits(w, 11, 10) << 3) | (bits(w, 4, 3) << 1)) as u64,
                    9,
                ) & 0xFFFF_FFFF;
                let target = address.wrapping_add(imm) & 0xFFFF_FFFF;
                let cond = unique(0x500, 1);
                let op = if funct3 == 6 { OpCode::IntEqual } else { OpCode::IntNotEqual };
                push(&mut ops, &mut s, op, Some(cond), &[xin(rs1), constant(0, 4)]);
                push(&mut ops, &mut s, OpCode::CBranch, None, &[ram(target), cond]);
            }
            (2, 0) => {
                // c.slli
                let rd = bits(w, 11, 7);
                let shamt = ((bits(w, 12, 12) << 5) | bits(w, 6, 2)) as u64;
                if let Some(out) = xout(rd) {
                    push(&mut ops, &mut s, OpCode::IntLeft, Some(out), &[xin(rd), constant(shamt, 4)]);
                }
            }
            (2, 2) => {
                // c.lwsp: rd = load(sp + uimm)
                let rd = bits(w, 11, 7);
                let imm = ((bits(w, 3, 2) << 6) | (bits(w, 12, 12) << 5) | (bits(w, 6, 4) << 2)) as u64;
                if let Some(out) = xout(rd) {
                    let addr = unique(0x600, 4);
                    push(&mut ops, &mut s, OpCode::IntAdd, Some(addr), &[xin(SP_INDEX), constant(imm, 4)]);
                    push(&mut ops, &mut s, OpCode::Load, Some(out), &[constant(RAM_SPACE.0 as u64, 4), addr]);
                }
            }
            (2, 4) => {
                // c.jr / c.mv / c.jalr / c.add / c.ebreak
                let rd = bits(w, 11, 7);
                let rs2 = bits(w, 6, 2);
                let bit12 = bits(w, 12, 12);
                if bit12 == 0 {
                    if rs2 == 0 {
                        // c.jr rd
                        if rd == RA_INDEX {
                            push(&mut ops, &mut s, OpCode::Return, None, &[xin(rd)]);
                        } else if rd != 0 {
                            push(&mut ops, &mut s, OpCode::BranchInd, None, &[xin(rd)]);
                        }
                    } else if let Some(out) = xout(rd) {
                        // c.mv rd = rs2
                        push(&mut ops, &mut s, OpCode::Copy, Some(out), &[xin(rs2)]);
                    }
                } else if rs2 == 0 {
                    if rd != 0 {
                        // c.jalr rd: ra = PC + 2; CallInd via rd-register.
                        // Snapshot the indirect target first so the link
                        // write (ra = PC + 2) can't clobber it when the
                        // source register IS ra. The previous code
                        // produced CallInd without any link, so a callee
                        // returning via `ret` jumped to a stale ra.
                        let target = unique(0x420, 4);
                        push(&mut ops, &mut s, OpCode::Copy, Some(target), &[xin(rd)]);
                        if let Some(link) = xout(RA_INDEX) {
                            push(&mut ops, &mut s, OpCode::Copy, Some(link),
                                &[constant((address + 2) & 0xFFFF_FFFF, 4)]);
                        }
                        push(&mut ops, &mut s, OpCode::CallInd, None, &[target]);
                    } else {
                        // rd == 0 with bit12=1 and rs2=0 is c.ebreak --
                        // surface it as CallOther so the boundary is
                        // visible.
                        push(&mut ops, &mut s, OpCode::CallOther, None,
                            &[constant(0x9002, 4)]);
                    }
                } else if let Some(out) = xout(rd) {
                    // c.add rd += rs2
                    push(&mut ops, &mut s, OpCode::IntAdd, Some(out), &[xin(rd), xin(rs2)]);
                }
            }
            (2, 6) => {
                // c.swsp: store(sp + uimm, rs2)
                let rs2 = bits(w, 6, 2);
                let imm = ((bits(w, 8, 7) << 6) | (bits(w, 12, 9) << 2)) as u64;
                let addr = unique(0x600, 4);
                push(&mut ops, &mut s, OpCode::IntAdd, Some(addr), &[xin(SP_INDEX), constant(imm, 4)]);
                push(&mut ops, &mut s, OpCode::Store, None, &[constant(RAM_SPACE.0 as u64, 4), addr, xin(rs2)]);
            }
            _ => {}
        }

        let _ = s;
        ops
    }

    fn disasm_text(&self, bytes: &[u8], address: u64, fallback_word: u32) -> String {
        match self.cs.disasm_count(bytes, address, 1) {
            Ok(insns) => insns
                .iter()
                .next()
                .map(|insn| {
                    let m = insn.mnemonic().unwrap_or("???");
                    let o = insn.op_str().unwrap_or("");
                    if o.is_empty() { m.to_string() } else { format!("{} {}", m, o) }
                })
                .unwrap_or_else(|| format!(".word 0x{:08x}", fallback_word)),
            Err(_) => format!(".insn 0x{:x}", fallback_word),
        }
    }
}

/// CJ-format immediate (c.j / c.jal): imm[11|4|9:8|10|6|7|3:1|5].
fn cj_imm(w: u32) -> u64 {
    let imm = (bits(w, 12, 12) << 11)
        | (bits(w, 8, 8) << 10)
        | (bits(w, 10, 9) << 8)
        | (bits(w, 6, 6) << 7)
        | (bits(w, 7, 7) << 6)
        | (bits(w, 2, 2) << 5)
        | (bits(w, 11, 11) << 4)
        | (bits(w, 5, 3) << 1);
    sext(imm as u64, 12) & 0xFFFF_FFFF
}

impl PcodeLift for RiscVLifter {
    fn lift_instruction(&self, memory: &Memory, address: u64) -> Result<LiftedInstruction, LiftError> {
        let b0 = memory.read_byte(address).ok_or(LiftError::UnreadableAddress(address))?;
        let b1 = memory.read_byte(address + 1).ok_or(LiftError::UnreadableAddress(address))?;
        let half = (b0 as u16) | ((b1 as u16) << 8);

        if half & 0x3 == 0x3 {
            // 32-bit instruction
            let b2 = memory.read_byte(address + 2).ok_or(LiftError::UnreadableAddress(address))?;
            let b3 = memory.read_byte(address + 3).ok_or(LiftError::UnreadableAddress(address))?;
            let word = (half as u32) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
            let ops = self.lift_32(word, address);
            let mnemonic = self.disasm_text(&[b0, b1, b2, b3], address, word);
            Ok(LiftedInstruction { address, length: 4, mnemonic, ops })
        } else {
            // 16-bit compressed instruction
            let ops = self.lift_16(half, address);
            let mnemonic = self.disasm_text(&[b0, b1], address, half as u32);
            Ok(LiftedInstruction { address, length: 2, mnemonic, ops })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::{Endian, SpaceId as CoreSpace};
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn make_memory(bytes: &[u8], addr: u64) -> Memory {
        let mut mem = Memory::new(CoreSpace(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: addr,
            size: bytes.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(bytes)),
        });
        mem
    }

    fn le32(w: u32) -> [u8; 4] {
        w.to_le_bytes()
    }

    #[test]
    fn lift_addi() {
        // addi a0, a1, 5 => rd=10 rs1=11 funct3=0 opcode=0x13 imm=5
        let word = (5 << 20) | (11 << 15) | (10 << 7) | 0x13;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 4);
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::IntAdd);
        assert_eq!(lifted.ops[0].output.unwrap().offset, 10 * 4); // a0
        assert_eq!(lifted.ops[0].inputs[1].offset, 5); // imm
    }

    #[test]
    fn lift_sll_masks_shift_amount() {
        // sll a0, a1, a2 => opcode=0x33 rd=10 rs1=11 rs2=12 funct3=1 funct7=0
        // (rd = rs1 << (rs2 & 0x1F))
        let word = (12 << 20) | (11 << 15) | (1 << 12) | (10 << 7) | 0x33;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // First op masks rs2 to 5 bits; second shifts.
        assert_eq!(lifted.ops[0].opcode, OpCode::IntAnd);
        assert_eq!(lifted.ops[0].inputs[0].offset, 12 * 4); // rs2 = a2
        assert_eq!(lifted.ops[0].inputs[1].offset, 0x1F);
        assert_eq!(lifted.ops[1].opcode, OpCode::IntLeft);
        assert_eq!(lifted.ops[1].inputs[0].offset, 11 * 4); // rs1 = a1
        assert_eq!(lifted.ops[1].inputs[1].space, CoreSpace::UNIQUE); // masked amt
    }

    #[test]
    fn lift_sra_masks_but_mulh_does_not() {
        // mulh (M-ext, funct7=1, funct3=1) must NOT be treated as a shift.
        let word = (1 << 25) | (12 << 20) | (11 << 15) | (1 << 12) | (10 << 7) | 0x33;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(!lifted.ops.iter().any(|o| o.opcode == OpCode::IntAnd
            && o.inputs.get(1).map(|v| v.offset == 0x1F).unwrap_or(false)),
            "mulh must not get the shift-amount mask");
    }

    #[test]
    fn lift_add() {
        // add a0, a1, a2 => opcode=0x33 rd=10 rs1=11 rs2=12 funct3=0 funct7=0
        let word = (12 << 20) | (11 << 15) | (10 << 7) | 0x33;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops[0].opcode, OpCode::IntAdd);
    }

    #[test]
    fn lift_sub() {
        // sub a0, a1, a2 => funct7=0x20
        let word = (0x20 << 25) | (12 << 20) | (11 << 15) | (10 << 7) | 0x33;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops[0].opcode, OpCode::IntSub);
    }

    #[test]
    fn lift_lw() {
        // lw a0, 0(sp) => opcode=0x03 funct3=2 rd=10 rs1=2
        let word = (2 << 15) | (2 << 12) | (10 << 7) | 0x03;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::Load));
    }

    #[test]
    fn lift_sw() {
        // sw a0, 4(sp) => opcode=0x23 funct3=2 rs1=2 rs2=10 imm=4
        // s_imm: imm[11:5]=funct7, imm[4:0]=rd field. For imm=4: rd-field=4, funct7=0.
        let word = (10 << 20) | (2 << 15) | (2 << 12) | (4 << 7) | 0x23;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::Store));
    }

    #[test]
    fn lift_jalr_ret() {
        // ret = jalr x0, 0(ra) => opcode=0x67 rd=0 rs1=1 imm=0
        // JALR now snapshots the target into a unique before any link,
        // so the Return op is no longer the first op of the lift.
        let word = (1 << 15) | 0x67;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::Return),
            "ret must produce a Return op: {:?}", lifted.ops);
    }

    #[test]
    fn lift_jal_call() {
        // jal ra, +8 => opcode=0x6F rd=1, j_imm=8
        // j_imm layout imm[20|10:1|11|19:12]; imm[10:1] maps to word[30:21],
        // so imm[3] (value 8) sits at word bit 23.
        let word = (1 << 23) | (1 << 7) | 0x6F;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let call = lifted.ops.iter().find(|o| o.opcode == OpCode::Call)
            .expect("jal must emit Call");
        assert_eq!(call.inputs[0].offset, 0x1008);
    }

    #[test]
    fn lift_beq() {
        // beq a0, a1, +8 => opcode=0x63 funct3=0 rs1=10 rs2=11, b_imm=8
        // b_imm: imm[12|10:5|4:1|11]; imm=8 -> imm[3]=1 -> in word bits[11:8] (imm[4:1]) bit3 => word bit10.
        let word = (1 << 10) | (11 << 20) | (10 << 15) | 0x63;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::IntEqual));
        let cbr = lifted.ops.iter().find(|o| o.opcode == OpCode::CBranch).unwrap();
        assert_eq!(cbr.inputs[0].offset, 0x1008);
    }

    #[test]
    fn lift_lui() {
        // lui a0, 0x12345 => opcode=0x37 rd=10
        let word = (0x12345 << 12) | (10 << 7) | 0x37;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops[0].opcode, OpCode::Copy);
        assert_eq!(lifted.ops[0].inputs[0].offset, 0x12345000);
    }

    #[test]
    fn compressed_length_and_cmv() {
        // c.mv a0, a1 => quadrant=2 funct3=4 bit12=0 rd=10 rs2=11
        // encoding: funct3(100) << 13 | rd << 7 | rs2 << 2 | 0b10
        let half: u16 = (0b100 << 13) | (10 << 7) | (11 << 2) | 0b10;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&half.to_le_bytes(), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 2, "compressed instruction is 2 bytes");
        assert_eq!(lifted.ops[0].opcode, OpCode::Copy);
        assert_eq!(lifted.ops[0].output.unwrap().offset, 10 * 4);
    }

    #[test]
    fn compressed_c_addi() {
        // c.addi a0, 1 => quadrant=1 funct3=000 rd=10 imm=1
        // imm[5]=inst[12], imm[4:0]=inst[6:2]; imm=1 => inst[2]=1
        let half: u16 = (10 << 7) | (1 << 2) | 0b01; // funct3=000
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&half.to_le_bytes(), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.length, 2);
        assert_eq!(lifted.ops[0].opcode, OpCode::IntAdd);
        assert_eq!(lifted.ops[0].inputs[1].offset, 1);
    }

    #[test]
    fn compressed_c_jr_ra_is_return() {
        // c.jr ra => quadrant=2 funct3=100 bit12=0 rd=1 rs2=0
        let half: u16 = (0b100 << 13) | (1 << 7) | 0b10;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&half.to_le_bytes(), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops[0].opcode, OpCode::Return);
    }

    #[test]
    fn write_to_zero_discarded() {
        // addi x0, x1, 5 => writing x0 produces no op
        let word = (5 << 20) | (1 << 15) | 0x13;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.is_empty());
    }

    /// JAL must link rd = PC + 4 before transferring control. Without
    /// the link, every callee's `ret` returned to a stale ra.
    #[test]
    fn lift_jal_links_rd() {
        // jal ra, +8: rd=1, j_imm=8
        let word = (1 << 23) | (1 << 7) | 0x6F;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let ra_off = RA_INDEX as u64 * 4;
        let link = lifted.ops.iter().find(|o| o.opcode == OpCode::Copy
            && o.output.map(|v| v.offset == ra_off && v.space == CoreSpace::REGISTER).unwrap_or(false))
            .expect("jal must link ra");
        assert_eq!(link.inputs[0].offset, 0x1004);
    }

    /// JALR must link rd = PC + 4 and the indirect target must come
    /// from a unique snapshot taken BEFORE the link write (so that
    /// `jalr ra, 0(ra)` reads the pre-link ra).
    #[test]
    fn lift_jalr_links_rd_via_unique_target() {
        // jalr ra, 0(ra): rd=1 rs1=1 imm=0  (self-jalr edge case)
        let word = (1 << 15) | (1 << 7) | 0x67;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        // Indirect target must be a UNIQUE, not REGISTER ra (which would
        // be the linked value).
        let callind = lifted.ops.iter().find(|o| o.opcode == OpCode::CallInd)
            .expect("CallInd present");
        assert_eq!(callind.inputs[0].space, CoreSpace::UNIQUE,
            "JALR target must be a snapshot UNIQUE, not the just-linked ra: {:?}", lifted.ops);
        // The link copy must precede the CallInd.
        let link_pos = lifted.ops.iter().position(|o| o.opcode == OpCode::Copy
            && o.output.map(|v| v.offset == RA_INDEX as u64 * 4 && v.space == CoreSpace::REGISTER).unwrap_or(false))
            .expect("link Copy present");
        let snapshot_pos = lifted.ops.iter().position(|o| o.opcode == OpCode::Copy
            && o.output.map(|v| v.space == CoreSpace::UNIQUE).unwrap_or(false))
            .expect("target snapshot Copy present");
        assert!(snapshot_pos < link_pos,
            "target snapshot must run before the link write: {:?}", lifted.ops);
    }

    /// c.jal (RV32 compressed) must link ra = PC + 2.
    #[test]
    fn lift_c_jal_links_ra_pc_plus_2() {
        // c.jal +0x100 ; quadrant=1, funct3=001
        let half: u16 = (1 << 13) | (1 << 9) | 0b01;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&half.to_le_bytes(), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        let link = lifted.ops.iter().find(|o| o.opcode == OpCode::Copy
            && o.output.map(|v| v.offset == RA_INDEX as u64 * 4 && v.space == CoreSpace::REGISTER).unwrap_or(false))
            .expect("c.jal must link ra");
        assert_eq!(link.inputs[0].offset, 0x1002);
    }

    /// ECALL must surface as CallOther so the syscall site is visible
    /// instead of disappearing as an empty op list.
    #[test]
    fn lift_ecall_emits_call_other() {
        let word = 0x73u32;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::CallOther);
    }

    /// MULH (M-ext high-half multiply) is not directly modellable as a
    /// single P-code op, but it must not silently disappear.
    #[test]
    fn lift_mulh_emits_call_other() {
        // mulh a0, a1, a2: funct7=1 funct3=1
        let word = (1u32 << 25) | (12 << 20) | (11 << 15) | (1 << 12) | (10 << 7) | 0x33;
        let lifter = RiscVLifter::new_rv32();
        let mem = make_memory(&le32(word), 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| o.opcode == OpCode::CallOther),
            "mulh must emit CallOther: {:?}", lifted.ops);
    }
}
