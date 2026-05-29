//! ARM32 (A32) → P-code lifter.
//!
//! Decodes the common A32 encodings directly into P-code: data processing
//! (immediate and simple shifted-register operand2), single load/store,
//! block load/store (push/pop), multiply, and branches. Capstone supplies the
//! disassembly text. Condition codes are honoured for branches (via NZCV flags
//! computed by cmp/cmn/tst/teq); conditional data-processing is lifted
//! unconditionally (a documented simplification).

use gr_core::address::{Address, Endian, SpaceId};
use gr_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use gr_loader::Memory;
use smallvec::SmallVec;

use crate::lift::{LiftError, LiftedInstruction, PcodeLift};

const CONST_SPACE: SpaceId = SpaceId::CONST;
const RAM_SPACE: SpaceId = SpaceId::RAM;
const REG_SPACE: SpaceId = SpaceId::REGISTER;
const UNIQUE_SPACE: SpaceId = SpaceId::UNIQUE;

const LR_INDEX: u32 = 14;
const PC_INDEX: u32 = 15;

// NZCV flags stored in dedicated register-space slots (1 byte each).
const N_FLAG: u64 = 0x120;
const Z_FLAG: u64 = 0x121;
const C_FLAG: u64 = 0x122;
const V_FLAG: u64 = 0x123;

// ARM condition codes (bits 31:28).
const COND_AL: u32 = 0xE;

fn constant(value: u64, size: u32) -> VarnodeData {
    VarnodeData::new(CONST_SPACE, value, size)
}

fn ram(addr: u64) -> VarnodeData {
    VarnodeData::new(RAM_SPACE, addr, 4)
}

fn unique(offset: u64, size: u32) -> VarnodeData {
    VarnodeData::new(UNIQUE_SPACE, offset, size)
}

fn reg(index: u32) -> VarnodeData {
    VarnodeData::new(REG_SPACE, index as u64 * 4, 4)
}

fn flag(offset: u64) -> VarnodeData {
    VarnodeData::new(REG_SPACE, offset, 1)
}

pub struct Arm32Lifter {
    cs: capstone::Capstone,
    big_endian: bool,
    thumb: bool,
}

unsafe impl Send for Arm32Lifter {}
unsafe impl Sync for Arm32Lifter {}

impl Arm32Lifter {
    pub fn new(endian: Endian) -> Self {
        Self::new_arm(endian)
    }

    /// A32 (ARM) mode lifter.
    pub fn new_arm(endian: Endian) -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(false)
            .build()
            .expect("failed to create ARM capstone");
        Self {
            cs,
            big_endian: matches!(endian, Endian::Big),
            thumb: false,
        }
    }

    /// T16/T32 (Thumb) mode lifter.
    pub fn new_thumb(endian: Endian) -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .detail(false)
            .build()
            .expect("failed to create Thumb capstone");
        Self {
            cs,
            big_endian: matches!(endian, Endian::Big),
            thumb: true,
        }
    }

    fn read_word(&self, buf: &[u8; 4]) -> u32 {
        if self.big_endian {
            u32::from_be_bytes(*buf)
        } else {
            u32::from_le_bytes(*buf)
        }
    }

    fn read_half(&self, b0: u8, b1: u8) -> u16 {
        if self.big_endian {
            ((b0 as u16) << 8) | b1 as u16
        } else {
            (b0 as u16) | ((b1 as u16) << 8)
        }
    }

    /// A 16-bit halfword starts a 32-bit Thumb-2 instruction when its top five
    /// bits are 0b11101, 0b11110, or 0b11111.
    fn is_thumb32(half: u16) -> bool {
        (half >> 11) >= 0x1D
    }

    /// Decode a 16-bit Thumb (T16) instruction into P-code.
    fn lift_thumb16(&self, h: u16, address: u64) -> Vec<PcodeOp> {
        let h = h as u32;
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let mut s = 0u32;
        let top5 = h >> 11;
        let pc_next = address + 4;

        let emit = |ops: &mut Vec<PcodeOp>, s: &mut u32, op: OpCode, out: Option<VarnodeData>, ins: &[VarnodeData]| {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: out, inputs: SmallVec::from_slice(ins) });
            *s += 1;
        };

        match top5 {
            0x00..=0x02 => {
                // LSL / LSR / ASR by immediate
                let rd = h & 7;
                let rm = (h >> 3) & 7;
                let imm5 = (h >> 6) & 0x1F;
                if top5 == 0x00 && imm5 == 0 {
                    emit(&mut ops, &mut s, OpCode::Copy, Some(reg(rd)), &[reg(rm)]);
                } else {
                    let op = match top5 { 0x00 => OpCode::IntLeft, 0x01 => OpCode::IntRight, _ => OpCode::IntSRight };
                    emit(&mut ops, &mut s, op, Some(reg(rd)), &[reg(rm), constant(imm5 as u64, 4)]);
                }
            }
            0x03 => {
                // ADD/SUB register or 3-bit immediate
                let rd = h & 7;
                let rn = (h >> 3) & 7;
                let m = (h >> 6) & 7;
                let opc = (h >> 9) & 3;
                let (op, rhs) = match opc {
                    0 => (OpCode::IntAdd, reg(m)),
                    1 => (OpCode::IntSub, reg(m)),
                    2 => (OpCode::IntAdd, constant(m as u64, 4)),
                    _ => (OpCode::IntSub, constant(m as u64, 4)),
                };
                emit(&mut ops, &mut s, op, Some(reg(rd)), &[reg(rn), rhs]);
            }
            0x04 => {
                // MOV Rd, #imm8
                let rd = (h >> 8) & 7;
                emit(&mut ops, &mut s, OpCode::Copy, Some(reg(rd)), &[constant((h & 0xFF) as u64, 4)]);
            }
            0x05 => {
                // CMP Rn, #imm8
                let rn = (h >> 8) & 7;
                self.emit_cmp_flags(false, reg(rn), constant((h & 0xFF) as u64, 4), &mut ops, &mut s, address);
            }
            0x06 => {
                // ADD Rd, #imm8
                let rd = (h >> 8) & 7;
                emit(&mut ops, &mut s, OpCode::IntAdd, Some(reg(rd)), &[reg(rd), constant((h & 0xFF) as u64, 4)]);
            }
            0x07 => {
                // SUB Rd, #imm8
                let rd = (h >> 8) & 7;
                emit(&mut ops, &mut s, OpCode::IntSub, Some(reg(rd)), &[reg(rd), constant((h & 0xFF) as u64, 4)]);
            }
            _ => {
                self.lift_thumb16_wide(h, address, pc_next, &mut ops, &mut s);
            }
        }
        let _ = s;
        ops
    }

    fn lift_thumb16_wide(&self, h: u32, address: u64, pc_next: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);

        // ALU register operations: bits[15:10] = 0b010000
        if (h & 0xFC00) == 0x4000 {
            let rd = h & 7;
            let rm = (h >> 3) & 7;
            let op4 = (h >> 6) & 0xF;
            match op4 {
                0x0 => ops.push(PcodeOp { opcode: OpCode::IntAnd, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rd), reg(rm)]) }),
                0x1 => ops.push(PcodeOp { opcode: OpCode::IntXor, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rd), reg(rm)]) }),
                0x2 => ops.push(PcodeOp { opcode: OpCode::IntLeft, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rd), reg(rm)]) }),
                0x3 => ops.push(PcodeOp { opcode: OpCode::IntRight, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rd), reg(rm)]) }),
                0x4 => ops.push(PcodeOp { opcode: OpCode::IntSRight, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rd), reg(rm)]) }),
                0x8 => { self.emit_cmp_flags(true, reg(rd), reg(rm), ops, s, address); return; }   // TST
                0xA => { self.emit_cmp_flags(false, reg(rd), reg(rm), ops, s, address); return; }  // CMP
                0xB => { self.emit_cmn_flags(reg(rd), reg(rm), ops, s, address); return; }         // CMN
                0xC => ops.push(PcodeOp { opcode: OpCode::IntOr, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rd), reg(rm)]) }),
                0xD => ops.push(PcodeOp { opcode: OpCode::IntMult, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rd), reg(rm)]) }),
                0xF => ops.push(PcodeOp { opcode: OpCode::IntNegate, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rm)]) }),
                0x9 => ops.push(PcodeOp { opcode: OpCode::Int2Comp, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rm)]) }), // NEG
                _ => {}
            }
            *s += 1;
            return;
        }

        // Hi register operations / BX: bits[15:10] = 0b010001
        if (h & 0xFC00) == 0x4400 {
            let op = (h >> 8) & 3;
            let h1 = (h >> 7) & 1;
            let h2 = (h >> 6) & 1;
            let rd = (h & 7) | (h1 << 3);
            let rm = ((h >> 3) & 7) | (h2 << 3);
            match op {
                0 => ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rd), reg(rm)]) }),
                1 => { self.emit_cmp_flags(false, reg(rd), reg(rm), ops, s, address); return; }
                2 => ops.push(PcodeOp { opcode: OpCode::Copy, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rm)]) }),
                _ => {
                    // BX / BLX Rm
                    if h1 == 1 {
                        ops.push(PcodeOp { opcode: OpCode::CallInd, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[reg(rm)]) });
                    } else if rm == LR_INDEX {
                        ops.push(PcodeOp { opcode: OpCode::Return, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[reg(rm)]) });
                    } else {
                        ops.push(PcodeOp { opcode: OpCode::BranchInd, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[reg(rm)]) });
                    }
                }
            }
            *s += 1;
            return;
        }

        // PC-relative load: bits[15:11] = 0b01001
        if (h >> 11) == 0x09 {
            let rd = (h >> 8) & 7;
            let imm8 = h & 0xFF;
            let addr = (pc_next & !3).wrapping_add(imm8 as u64 * 4);
            ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), constant(addr & 0xFFFF_FFFF, 4)]) });
            *s += 1;
            return;
        }

        // Load/store with immediate offset (word/byte): bits[15:13] = 0b011
        if (h >> 13) == 0x03 {
            let byte = (h >> 12) & 1 == 1;
            let load = (h >> 11) & 1 == 1;
            let rd = h & 7;
            let rn = (h >> 3) & 7;
            let imm5 = (h >> 6) & 0x1F;
            let offset = if byte { imm5 } else { imm5 * 4 };
            let addr = unique(0x600, 4);
            ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(addr), inputs: SmallVec::from_slice(&[reg(rn), constant(offset as u64, 4)]) });
            *s += 1;
            if load {
                if byte {
                    let loaded = unique(0x610, 1);
                    ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(loaded), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
                    *s += 1;
                    ops.push(PcodeOp { opcode: OpCode::IntZExt, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[loaded]) });
                    *s += 1;
                } else {
                    ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
                    *s += 1;
                }
            } else {
                let value = if byte { VarnodeData::new(REG_SPACE, rd as u64 * 4, 1) } else { reg(rd) };
                ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr, value]) });
                *s += 1;
            }
            return;
        }

        // SP-relative load/store: bits[15:12] = 0b1001
        if (h >> 12) == 0x09 {
            let load = (h >> 11) & 1 == 1;
            let rd = (h >> 8) & 7;
            let imm8 = h & 0xFF;
            let addr = unique(0x600, 4);
            ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(addr), inputs: SmallVec::from_slice(&[reg(13), constant(imm8 as u64 * 4, 4)]) });
            *s += 1;
            if load {
                ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
            } else {
                ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr, reg(rd)]) });
            }
            *s += 1;
            return;
        }

        // ADD SP, #imm7*4 / SUB SP, #imm7*4: bits[15:8] = 0b10110000
        if (h & 0xFF00) == 0xB000 {
            let sub = (h >> 7) & 1 == 1;
            let imm7 = (h & 0x7F) * 4;
            let op = if sub { OpCode::IntSub } else { OpCode::IntAdd };
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: Some(reg(13)), inputs: SmallVec::from_slice(&[reg(13), constant(imm7 as u64, 4)]) });
            *s += 1;
            return;
        }

        // PUSH / POP: bits[15:12] = 0b1011, bit10 = 1
        if (h & 0xF600) == 0xB400 {
            let load = (h >> 11) & 1 == 1; // 1 = POP
            let extra = (h >> 8) & 1 == 1;  // LR (push) / PC (pop)
            let reg_list = h & 0xFF;
            let mut count = reg_list.count_ones();
            if extra { count += 1; }
            let sp = reg(13);
            if load {
                // POP: load r0..r7 then optionally PC, sp += 4*count
                let mut offset = 0u64;
                for i in 0..8u32 {
                    if reg_list & (1 << i) == 0 { continue; }
                    let ea = unique(0x680 + *s as u64, 4);
                    ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(ea), inputs: SmallVec::from_slice(&[sp, constant(offset, 4)]) });
                    *s += 1;
                    ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(reg(i)), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), ea]) });
                    *s += 1;
                    offset += 4;
                }
                if extra {
                    // pop pc => return
                    let ea = unique(0x680 + *s as u64, 4);
                    ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(ea), inputs: SmallVec::from_slice(&[sp, constant(offset, 4)]) });
                    *s += 1;
                    let loaded = unique(0x690 + *s as u64, 4);
                    ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(loaded), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), ea]) });
                    *s += 1;
                    ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(sp), inputs: SmallVec::from_slice(&[sp, constant(4 * count as u64, 4)]) });
                    *s += 1;
                    ops.push(PcodeOp { opcode: OpCode::Return, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[loaded]) });
                    *s += 1;
                    return;
                }
                ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(sp), inputs: SmallVec::from_slice(&[sp, constant(4 * count as u64, 4)]) });
                *s += 1;
            } else {
                // PUSH: sp -= 4*count, store r0..r7 (and LR) ascending
                ops.push(PcodeOp { opcode: OpCode::IntSub, seq: seq(*s), output: Some(sp), inputs: SmallVec::from_slice(&[sp, constant(4 * count as u64, 4)]) });
                *s += 1;
                let mut offset = 0u64;
                for i in 0..8u32 {
                    if reg_list & (1 << i) == 0 { continue; }
                    let ea = unique(0x680 + *s as u64, 4);
                    ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(ea), inputs: SmallVec::from_slice(&[sp, constant(offset, 4)]) });
                    *s += 1;
                    ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), ea, reg(i)]) });
                    *s += 1;
                    offset += 4;
                }
                if extra {
                    let ea = unique(0x680 + *s as u64, 4);
                    ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(ea), inputs: SmallVec::from_slice(&[sp, constant(offset, 4)]) });
                    *s += 1;
                    ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), ea, reg(LR_INDEX)]) });
                    *s += 1;
                }
            }
            return;
        }

        // Conditional branch: bits[15:12] = 0b1101
        if (h >> 12) == 0x0D {
            let cond = (h >> 8) & 0xF;
            if cond == 0xE || cond == 0xF {
                return; // permanently undefined / SVC
            }
            let off = ((h & 0xFF) as u8 as i8 as i64) << 1;
            let target = pc_next.wrapping_add(off as u64) & 0xFFFF_FFFF;
            let c = self.emit_cond(cond, ops, s, address);
            ops.push(PcodeOp { opcode: OpCode::CBranch, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[ram(target), c]) });
            *s += 1;
            return;
        }

        // Unconditional branch: bits[15:11] = 0b11100
        if (h >> 11) == 0x1C {
            let off = (((h & 0x7FF) << 21) as i32 >> 20) as i64; // sign-extend 11 bits, <<1
            let target = pc_next.wrapping_add(off as u64) & 0xFFFF_FFFF;
            ops.push(PcodeOp { opcode: OpCode::Branch, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[ram(target)]) });
            *s += 1;
        }
    }

    /// Decode a 32-bit Thumb-2 (T32) instruction. Handles the common BL/B.W
    /// branch forms; other T32 encodings produce no P-code (length stays 4).
    fn lift_thumb32(&self, hw1: u16, hw2: u16, address: u64) -> Vec<PcodeOp> {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let hw1 = hw1 as u32;
        let hw2 = hw2 as u32;

        // BL / B.W : hw1[15:11] = 0b11110, hw2[15:14] = 0b11 (BL) or 0b10 (B.W)
        if (hw1 >> 11) == 0x1E && (hw2 >> 14) == 0b11 {
            let s_bit = (hw1 >> 10) & 1;
            let imm10 = hw1 & 0x3FF;
            let j1 = (hw2 >> 13) & 1;
            let j2 = (hw2 >> 11) & 1;
            let imm11 = hw2 & 0x7FF;
            let i1 = 1 ^ (j1 ^ s_bit);
            let i2 = 1 ^ (j2 ^ s_bit);
            let imm = (s_bit << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
            let off = ((imm << 7) as i32 >> 7) as i64; // sign-extend 25 bits
            let target = (address.wrapping_add(4).wrapping_add(off as u64)) & 0xFFFF_FFFF;
            let is_bl = (hw2 >> 12) & 1 == 1;
            if is_bl {
                ops.push(PcodeOp { opcode: OpCode::Call, seq: seq(0), output: None, inputs: SmallVec::from_slice(&[ram(target)]) });
            } else {
                ops.push(PcodeOp { opcode: OpCode::CallInd, seq: seq(0), output: None, inputs: SmallVec::from_slice(&[ram(target)]) }); // BLX to ARM
            }
            return ops;
        }

        // B.W unconditional: hw1[15:11] = 0b11110, hw2[15:14] = 0b10, hw2[12] = 1
        if (hw1 >> 11) == 0x1E && (hw2 >> 14) == 0b10 && (hw2 >> 12) & 1 == 1 {
            let s_bit = (hw1 >> 10) & 1;
            let imm10 = hw1 & 0x3FF;
            let j1 = (hw2 >> 13) & 1;
            let j2 = (hw2 >> 11) & 1;
            let imm11 = hw2 & 0x7FF;
            let i1 = 1 ^ (j1 ^ s_bit);
            let i2 = 1 ^ (j2 ^ s_bit);
            let imm = (s_bit << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
            let off = ((imm << 7) as i32 >> 7) as i64;
            let target = (address.wrapping_add(4).wrapping_add(off as u64)) & 0xFFFF_FFFF;
            ops.push(PcodeOp { opcode: OpCode::Branch, seq: seq(0), output: None, inputs: SmallVec::from_slice(&[ram(target)]) });
            return ops;
        }

        let mut s = 0u32;

        // MOVW (move wide) / MOVT (move top): plain 16-bit immediate.
        if (hw1 & 0xFBF0) == 0xF240 || (hw1 & 0xFBF0) == 0xF2C0 {
            let movt = (hw1 & 0xFBF0) == 0xF2C0;
            let imm4 = hw1 & 0xF;
            let i = (hw1 >> 10) & 1;
            let imm3 = (hw2 >> 12) & 7;
            let imm8 = hw2 & 0xFF;
            let rd = (hw2 >> 8) & 0xF;
            let imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;
            if movt {
                // Rd = (Rd & 0x0000FFFF) | (imm16 << 16)
                let low = unique(0x730, 4);
                ops.push(PcodeOp { opcode: OpCode::IntAnd, seq: seq(s), output: Some(low), inputs: SmallVec::from_slice(&[reg(rd), constant(0xFFFF, 4)]) });
                s += 1;
                ops.push(PcodeOp { opcode: OpCode::IntOr, seq: seq(s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[low, constant((imm16 << 16) as u64, 4)]) });
            } else {
                ops.push(PcodeOp { opcode: OpCode::Copy, seq: seq(s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[constant(imm16 as u64, 4)]) });
            }
            return ops;
        }

        // Data processing (modified immediate): hw1[15:11]=11110, hw1[9]=0, hw2[15]=0.
        if (hw1 >> 11) == 0x1E && (hw1 >> 9) & 1 == 0 && (hw2 >> 15) == 0 {
            let opc = (hw1 >> 5) & 0xF;
            let set_flags = (hw1 >> 4) & 1 == 1;
            let rn = hw1 & 0xF;
            let rd = (hw2 >> 8) & 0xF;
            let imm12 = ((hw1 >> 10) & 1) << 11 | ((hw2 >> 12) & 7) << 8 | (hw2 & 0xFF);
            let imm = constant(Self::thumb_expand_imm(imm12) as u64, 4);
            self.thumb32_dp(opc, set_flags, rd, rn, imm, &mut ops, &mut s, address);
            return ops;
        }

        // Data processing (shifted register): hw1[15:9] = 1110101.
        if (hw1 >> 9) == 0x75 {
            let opc = (hw1 >> 5) & 0xF;
            let set_flags = (hw1 >> 4) & 1 == 1;
            let rn = hw1 & 0xF;
            let rd = (hw2 >> 8) & 0xF;
            let rm = hw2 & 0xF;
            let imm5 = ((hw2 >> 12) & 7) << 2 | ((hw2 >> 6) & 3);
            let shift_type = (hw2 >> 4) & 3;
            let op2 = if imm5 == 0 {
                reg(rm)
            } else {
                let shop = match shift_type {
                    0 => OpCode::IntLeft,
                    1 => OpCode::IntRight,
                    2 => OpCode::IntSRight,
                    _ => OpCode::IntRight,
                };
                let t = unique(0x738, 4);
                ops.push(PcodeOp { opcode: shop, seq: seq(s), output: Some(t), inputs: SmallVec::from_slice(&[reg(rm), constant(imm5 as u64, 4)]) });
                s += 1;
                t
            };
            self.thumb32_dp(opc, set_flags, rd, rn, op2, &mut ops, &mut s, address);
            return ops;
        }

        // Load/store single data item (T2/T3 imm12 positive-offset forms).
        let lsq = hw1 & 0xFFF0;
        let ls = match lsq {
            0xF8D0 => Some((true, 4u32, false)),
            0xF8C0 => Some((false, 4, false)),
            0xF890 => Some((true, 1, false)),
            0xF880 => Some((false, 1, false)),
            0xF8B0 => Some((true, 2, false)),
            0xF8A0 => Some((false, 2, false)),
            0xF990 => Some((true, 1, true)),
            0xF9B0 => Some((true, 2, true)),
            _ => None,
        };
        if let Some((load, size, signed)) = ls {
            let rn = hw1 & 0xF;
            let rt = (hw2 >> 12) & 0xF;
            let imm12 = hw2 & 0xFFF;
            if !(load && rt == PC_INDEX) {
                let addr = unique(0x600, 4);
                ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(s), output: Some(addr), inputs: SmallVec::from_slice(&[reg(rn), constant(imm12 as u64, 4)]) });
                s += 1;
                if load {
                    if size == 4 {
                        ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(s), output: Some(reg(rt)), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
                    } else {
                        let loaded = unique(0x610, size);
                        ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(s), output: Some(loaded), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
                        s += 1;
                        let ext = if signed { OpCode::IntSExt } else { OpCode::IntZExt };
                        ops.push(PcodeOp { opcode: ext, seq: seq(s), output: Some(reg(rt)), inputs: SmallVec::from_slice(&[loaded]) });
                    }
                } else {
                    let value = if size == 4 { reg(rt) } else { VarnodeData::new(REG_SPACE, rt as u64 * 4, size) };
                    ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr, value]) });
                }
                return ops;
            }
        }

        ops
    }

    /// ARM's ThumbExpandImm: decode a 12-bit modified immediate to its 32-bit
    /// value. All inputs are known at lift time, so this folds to a constant.
    fn thumb_expand_imm(imm12: u32) -> u32 {
        if (imm12 >> 10) & 3 == 0 {
            let imm8 = imm12 & 0xFF;
            match (imm12 >> 8) & 3 {
                0 => imm8,
                1 => (imm8 << 16) | imm8,
                2 => (imm8 << 24) | (imm8 << 8),
                _ => (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8,
            }
        } else {
            let unrotated = 0x80 | (imm12 & 0x7F);
            unrotated.rotate_right((imm12 >> 7) & 0x1F)
        }
    }

    /// Shared T32 data-processing dispatch for the modified-immediate and
    /// shifted-register encodings. `op2` is the already-resolved operand.
    #[allow(clippy::too_many_arguments)]
    fn thumb32_dp(&self, opc: u32, set_flags: bool, rd: u32, rn: u32, op2: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let rn_v = reg(rn);
        let push = |ops: &mut Vec<PcodeOp>, s: &mut u32, op: OpCode, out: Option<VarnodeData>, ins: &[VarnodeData]| {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: out, inputs: SmallVec::from_slice(ins) });
            *s += 1;
        };
        match opc {
            0x0 => {
                if rd == PC_INDEX && set_flags { self.emit_cmp_flags(true, rn_v, op2, ops, s, address); }
                else { push(ops, s, OpCode::IntAnd, Some(reg(rd)), &[rn_v, op2]); }
            }
            0x1 => { // BIC: rn & ~op2
                let n = unique(0x740, 4);
                push(ops, s, OpCode::IntNegate, Some(n), &[op2]);
                push(ops, s, OpCode::IntAnd, Some(reg(rd)), &[rn_v, n]);
            }
            0x2 => {
                if rn == PC_INDEX { push(ops, s, OpCode::Copy, Some(reg(rd)), &[op2]); }       // MOV
                else { push(ops, s, OpCode::IntOr, Some(reg(rd)), &[rn_v, op2]); }             // ORR
            }
            0x3 => { // ORN / MVN
                let n = unique(0x740, 4);
                push(ops, s, OpCode::IntNegate, Some(n), &[op2]);
                if rn == PC_INDEX { push(ops, s, OpCode::Copy, Some(reg(rd)), &[n]); }
                else { push(ops, s, OpCode::IntOr, Some(reg(rd)), &[rn_v, n]); }
            }
            0x4 => {
                if rd == PC_INDEX && set_flags { self.emit_cmp_flags(true, rn_v, op2, ops, s, address); } // TEQ
                else { push(ops, s, OpCode::IntXor, Some(reg(rd)), &[rn_v, op2]); }
            }
            0x8 => {
                if rd == PC_INDEX && set_flags { self.emit_cmn_flags(rn_v, op2, ops, s, address); }       // CMN
                else { push(ops, s, OpCode::IntAdd, Some(reg(rd)), &[rn_v, op2]); }
            }
            0xA => push(ops, s, OpCode::IntAdd, Some(reg(rd)), &[rn_v, op2]), // ADC (carry ignored)
            0xB => push(ops, s, OpCode::IntSub, Some(reg(rd)), &[rn_v, op2]), // SBC (carry ignored)
            0xD => {
                if rd == PC_INDEX && set_flags { self.emit_cmp_flags(false, rn_v, op2, ops, s, address); } // CMP
                else { push(ops, s, OpCode::IntSub, Some(reg(rd)), &[rn_v, op2]); }
            }
            0xE => push(ops, s, OpCode::IntSub, Some(reg(rd)), &[op2, rn_v]), // RSB: op2 - rn
            _ => {}
        }
    }

    fn lift_word(&self, word: u32, address: u64) -> Vec<PcodeOp> {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let mut ops: Vec<PcodeOp> = Vec::new();
        let mut s = 0u32;
        let cond = word >> 28;

        // BX / BLX (register): 0x012FFF1x / 0x012FFF3x
        if (word & 0x0FFF_FFF0) == 0x012F_FF10 {
            let rm = word & 0xF;
            if rm == LR_INDEX {
                ops.push(PcodeOp { opcode: OpCode::Return, seq: seq(s), output: None, inputs: SmallVec::from_slice(&[reg(LR_INDEX)]) });
            } else {
                ops.push(PcodeOp { opcode: OpCode::BranchInd, seq: seq(s), output: None, inputs: SmallVec::from_slice(&[reg(rm)]) });
            }
            return ops;
        }
        if (word & 0x0FFF_FFF0) == 0x012F_FF30 {
            let rm = word & 0xF;
            ops.push(PcodeOp { opcode: OpCode::CallInd, seq: seq(s), output: None, inputs: SmallVec::from_slice(&[reg(rm)]) });
            return ops;
        }

        // Branch / Branch-with-link: bits 27:25 = 101
        if (word & 0x0E00_0000) == 0x0A00_0000 {
            let link = (word >> 24) & 1 == 1;
            let imm24 = word & 0x00FF_FFFF;
            let offset = ((imm24 << 8) as i32 >> 6) as i64; // sign-extend 24 bits, <<2
            let target = (address.wrapping_add(8).wrapping_add(offset as u64)) & 0xFFFF_FFFF;

            if link {
                // BL is a call (condition rarely used; treat as unconditional call)
                ops.push(PcodeOp { opcode: OpCode::Call, seq: seq(s), output: None, inputs: SmallVec::from_slice(&[ram(target)]) });
            } else if cond == COND_AL {
                ops.push(PcodeOp { opcode: OpCode::Branch, seq: seq(s), output: None, inputs: SmallVec::from_slice(&[ram(target)]) });
            } else {
                let c = self.emit_cond(cond, &mut ops, &mut s, address);
                ops.push(PcodeOp { opcode: OpCode::CBranch, seq: seq(s), output: None, inputs: SmallVec::from_slice(&[ram(target), c]) });
            }
            return ops;
        }

        // Block data transfer (push/pop and friends): bits 27:25 = 100
        if (word & 0x0E00_0000) == 0x0800_0000 {
            self.lift_block_transfer(word, address, &mut ops, &mut s);
            return ops;
        }

        // Multiply: bits 27:22 = 000000, bits 7:4 = 1001
        if (word & 0x0FC0_00F0) == 0x0000_0090 {
            let rd = (word >> 16) & 0xF; // Rd is in Rn position for MUL
            let rs = (word >> 8) & 0xF;
            let rm = word & 0xF;
            ops.push(PcodeOp { opcode: OpCode::IntMult, seq: seq(s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[reg(rm), reg(rs)]) });
            return ops;
        }

        // Extra load/store (halfword / signed byte / signed halfword):
        // bits 27:25 = 000, bit7 = bit4 = 1, and SH (bits 6:5) != 00.
        if (word & 0x0E00_0090) == 0x0000_0090 && (word & 0x60) != 0 {
            self.lift_extra_load_store(word, address, &mut ops, &mut s);
            return ops;
        }

        // Single data transfer (load/store): bits 27:26 = 01
        if (word & 0x0C00_0000) == 0x0400_0000 {
            self.lift_load_store(word, address, &mut ops, &mut s);
            return ops;
        }

        // Data processing: bits 27:26 = 00
        if (word & 0x0C00_0000) == 0x0000_0000 {
            self.lift_data_processing(word, address, &mut ops, &mut s);
            return ops;
        }

        ops
    }

    fn lift_data_processing(&self, word: u32, address: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let i_bit = (word >> 25) & 1 == 1;
        let opcode = (word >> 21) & 0xF;
        let set_flags = (word >> 20) & 1 == 1;
        let rn = (word >> 16) & 0xF;
        let rd = (word >> 12) & 0xF;

        // Resolve operand2.
        let op2 = if i_bit {
            let imm8 = word & 0xFF;
            let rot = ((word >> 8) & 0xF) * 2;
            constant(imm8.rotate_right(rot) as u64, 4)
        } else {
            let rm = word & 0xF;
            let shift_amt = (word >> 7) & 0x1F;
            let shift_type = (word >> 5) & 0x3;
            let reg_shift = (word >> 4) & 1 == 1;
            if reg_shift || (shift_type == 0 && shift_amt == 0) {
                reg(rm)
            } else if shift_type == 3 {
                // ROR #n  ==  (Rm >> n) | (Rm << (32 - n))
                let hi = unique(0x700, 4);
                ops.push(PcodeOp { opcode: OpCode::IntRight, seq: seq(*s), output: Some(hi), inputs: SmallVec::from_slice(&[reg(rm), constant(shift_amt as u64, 4)]) });
                *s += 1;
                let lo = unique(0x708, 4);
                ops.push(PcodeOp { opcode: OpCode::IntLeft, seq: seq(*s), output: Some(lo), inputs: SmallVec::from_slice(&[reg(rm), constant((32 - shift_amt) as u64, 4)]) });
                *s += 1;
                let t = unique(0x710, 4);
                ops.push(PcodeOp { opcode: OpCode::IntOr, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[hi, lo]) });
                *s += 1;
                t
            } else {
                let op = match shift_type {
                    0 => OpCode::IntLeft,
                    1 => OpCode::IntRight,
                    _ => OpCode::IntSRight,
                };
                let t = unique(0x700, 4);
                ops.push(PcodeOp { opcode: op, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[reg(rm), constant(shift_amt as u64, 4)]) });
                *s += 1;
                t
            }
        };

        let rn_v = reg(rn);
        match opcode {
            0x0 => self.dp_binop(OpCode::IntAnd, rd, rn_v, op2, ops, s, address),       // AND
            0x1 => self.dp_binop(OpCode::IntXor, rd, rn_v, op2, ops, s, address),       // EOR
            0x2 => self.dp_binop(OpCode::IntSub, rd, rn_v, op2, ops, s, address),       // SUB
            0x3 => self.dp_binop_rev(OpCode::IntSub, rd, op2, rn_v, ops, s, address),   // RSB
            0x4 => self.dp_binop(OpCode::IntAdd, rd, rn_v, op2, ops, s, address),       // ADD
            0x5 => self.dp_binop(OpCode::IntAdd, rd, rn_v, op2, ops, s, address),       // ADC (carry ignored)
            0x6 => self.dp_binop(OpCode::IntSub, rd, rn_v, op2, ops, s, address),       // SBC (carry ignored)
            0x8 if set_flags => self.emit_cmp_flags(true, rn_v, op2, ops, s, address), // TST (AND flags)
            0x9 if set_flags => self.emit_cmp_flags(true, rn_v, op2, ops, s, address), // TEQ (EOR flags)
            0xA => self.emit_cmp_flags(false, rn_v, op2, ops, s, address),              // CMP
            0xB => self.emit_cmn_flags(rn_v, op2, ops, s, address),                     // CMN
            0xC => self.dp_binop(OpCode::IntOr, rd, rn_v, op2, ops, s, address),        // ORR
            0xD => { // MOV
                if let Some(out) = self.rd_out(rd) {
                    ops.push(PcodeOp { opcode: OpCode::Copy, seq: seq(*s), output: Some(out), inputs: SmallVec::from_slice(&[op2]) });
                    *s += 1;
                }
            }
            0xE => { // BIC: rd = rn & ~op2
                if let Some(out) = self.rd_out(rd) {
                    let notop2 = unique(0x718, 4);
                    ops.push(PcodeOp { opcode: OpCode::IntNegate, seq: seq(*s), output: Some(notop2), inputs: SmallVec::from_slice(&[op2]) });
                    *s += 1;
                    ops.push(PcodeOp { opcode: OpCode::IntAnd, seq: seq(*s), output: Some(out), inputs: SmallVec::from_slice(&[rn_v, notop2]) });
                    *s += 1;
                }
            }
            0xF => { // MVN
                if let Some(out) = self.rd_out(rd) {
                    ops.push(PcodeOp { opcode: OpCode::IntNegate, seq: seq(*s), output: Some(out), inputs: SmallVec::from_slice(&[op2]) });
                    *s += 1;
                }
            }
            _ => {}
        }
    }

    fn rd_out(&self, rd: u32) -> Option<VarnodeData> {
        // Writes to PC become control flow; not modelled as a data write here.
        if rd == PC_INDEX { None } else { Some(reg(rd)) }
    }

    #[allow(clippy::too_many_arguments)]
    fn dp_binop(&self, op: OpCode, rd: u32, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        if let Some(out) = self.rd_out(rd) {
            let seq = SeqNum::new(Address::new(RAM_SPACE, address), *s);
            ops.push(PcodeOp { opcode: op, seq, output: Some(out), inputs: SmallVec::from_slice(&[a, b]) });
            *s += 1;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dp_binop_rev(&self, op: OpCode, rd: u32, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        self.dp_binop(op, rd, a, b, ops, s, address);
    }

    fn emit_cmp_flags(&self, logical: bool, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let res = unique(0x720, 4);
        if logical {
            ops.push(PcodeOp { opcode: OpCode::IntAnd, seq: seq(*s), output: Some(res), inputs: SmallVec::from_slice(&[a, b]) });
            *s += 1;
        } else {
            ops.push(PcodeOp { opcode: OpCode::IntSub, seq: seq(*s), output: Some(res), inputs: SmallVec::from_slice(&[a, b]) });
            *s += 1;
        }
        // Z = res == 0
        ops.push(PcodeOp { opcode: OpCode::IntEqual, seq: seq(*s), output: Some(flag(Z_FLAG)), inputs: SmallVec::from_slice(&[res, constant(0, 4)]) });
        *s += 1;
        // N = res <s 0
        ops.push(PcodeOp { opcode: OpCode::IntSLess, seq: seq(*s), output: Some(flag(N_FLAG)), inputs: SmallVec::from_slice(&[res, constant(0, 4)]) });
        *s += 1;
        if !logical {
            // C = a >=u b  (no borrow)  == b <=u a
            ops.push(PcodeOp { opcode: OpCode::IntLessEqual, seq: seq(*s), output: Some(flag(C_FLAG)), inputs: SmallVec::from_slice(&[b, a]) });
            *s += 1;
            // V = signed borrow
            ops.push(PcodeOp { opcode: OpCode::IntSBorrow, seq: seq(*s), output: Some(flag(V_FLAG)), inputs: SmallVec::from_slice(&[a, b]) });
            *s += 1;
        }
    }

    fn emit_cmn_flags(&self, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let res = unique(0x720, 4);
        ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(res), inputs: SmallVec::from_slice(&[a, b]) });
        *s += 1;
        ops.push(PcodeOp { opcode: OpCode::IntEqual, seq: seq(*s), output: Some(flag(Z_FLAG)), inputs: SmallVec::from_slice(&[res, constant(0, 4)]) });
        *s += 1;
        ops.push(PcodeOp { opcode: OpCode::IntSLess, seq: seq(*s), output: Some(flag(N_FLAG)), inputs: SmallVec::from_slice(&[res, constant(0, 4)]) });
        *s += 1;
        ops.push(PcodeOp { opcode: OpCode::IntCarry, seq: seq(*s), output: Some(flag(C_FLAG)), inputs: SmallVec::from_slice(&[a, b]) });
        *s += 1;
        ops.push(PcodeOp { opcode: OpCode::IntSCarry, seq: seq(*s), output: Some(flag(V_FLAG)), inputs: SmallVec::from_slice(&[a, b]) });
        *s += 1;
    }

    /// Evaluate an ARM condition code into a 1-byte boolean varnode.
    fn emit_cond(&self, cond: u32, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) -> VarnodeData {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let n = flag(N_FLAG);
        let z = flag(Z_FLAG);
        let c = flag(C_FLAG);
        let v = flag(V_FLAG);

        let not = |ops: &mut Vec<PcodeOp>, s: &mut u32, x: VarnodeData| -> VarnodeData {
            let t = unique(0x740 + *s as u64 * 2, 1);
            ops.push(PcodeOp { opcode: OpCode::BoolNegate, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[x]) });
            *s += 1;
            t
        };

        match cond {
            0x0 => z,                                   // EQ
            0x1 => not(ops, s, z),                      // NE
            0x2 => c,                                   // CS/HS
            0x3 => not(ops, s, c),                      // CC/LO
            0x4 => n,                                   // MI
            0x5 => not(ops, s, n),                      // PL
            0x6 => v,                                   // VS
            0x7 => not(ops, s, v),                      // VC
            0x8 => {
                // HI: C && !Z
                let nz = not(ops, s, z);
                let t = unique(0x760, 1);
                ops.push(PcodeOp { opcode: OpCode::BoolAnd, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[c, nz]) });
                *s += 1;
                t
            }
            0x9 => {
                // LS: !C || Z
                let nc = not(ops, s, c);
                let t = unique(0x760, 1);
                ops.push(PcodeOp { opcode: OpCode::BoolOr, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[nc, z]) });
                *s += 1;
                t
            }
            0xA => {
                // GE: N == V
                let t = unique(0x760, 1);
                ops.push(PcodeOp { opcode: OpCode::IntEqual, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[n, v]) });
                *s += 1;
                t
            }
            0xB => {
                // LT: N != V
                let t = unique(0x760, 1);
                ops.push(PcodeOp { opcode: OpCode::IntNotEqual, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[n, v]) });
                *s += 1;
                t
            }
            0xC => {
                // GT: !Z && (N == V)
                let nz = not(ops, s, z);
                let nv = unique(0x760, 1);
                ops.push(PcodeOp { opcode: OpCode::IntEqual, seq: seq(*s), output: Some(nv), inputs: SmallVec::from_slice(&[n, v]) });
                *s += 1;
                let t = unique(0x768, 1);
                ops.push(PcodeOp { opcode: OpCode::BoolAnd, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[nz, nv]) });
                *s += 1;
                t
            }
            0xD => {
                // LE: Z || (N != V)
                let nev = unique(0x760, 1);
                ops.push(PcodeOp { opcode: OpCode::IntNotEqual, seq: seq(*s), output: Some(nev), inputs: SmallVec::from_slice(&[n, v]) });
                *s += 1;
                let t = unique(0x768, 1);
                ops.push(PcodeOp { opcode: OpCode::BoolOr, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[z, nev]) });
                *s += 1;
                t
            }
            _ => constant(1, 1), // AL or unhandled
        }
    }

    fn lift_load_store(&self, word: u32, address: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let i_bit = (word >> 25) & 1 == 1; // 0 = immediate offset
        let pre = (word >> 24) & 1 == 1;
        let up = (word >> 23) & 1 == 1;
        let byte = (word >> 22) & 1 == 1;
        let load = (word >> 20) & 1 == 1;
        let rn = (word >> 16) & 0xF;
        let rd = (word >> 12) & 0xF;

        // Offset
        let offset = if i_bit {
            // register offset (ignore shift for simplicity)
            reg(word & 0xF)
        } else {
            constant((word & 0xFFF) as u64, 4)
        };

        // Effective address (only pre-indexed offset addressing modelled).
        let addr = unique(0x600, 4);
        let op = if up { OpCode::IntAdd } else { OpCode::IntSub };
        if pre {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: Some(addr), inputs: SmallVec::from_slice(&[reg(rn), offset]) });
            *s += 1;
        } else {
            // post-indexed: use base directly
            ops.push(PcodeOp { opcode: OpCode::Copy, seq: seq(*s), output: Some(addr), inputs: SmallVec::from_slice(&[reg(rn)]) });
            *s += 1;
        }

        let size = if byte { 1 } else { 4 };
        if load {
            if rd == PC_INDEX {
                return; // load into PC = control flow, skip
            }
            if byte {
                let loaded = unique(0x610, 1);
                ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(loaded), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
                *s += 1;
                ops.push(PcodeOp { opcode: OpCode::IntZExt, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[loaded]) });
                *s += 1;
            } else {
                ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
                *s += 1;
            }
        } else {
            let value = if byte {
                VarnodeData::new(REG_SPACE, rd as u64 * 4, 1)
            } else {
                reg(rd)
            };
            ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr, value]) });
            *s += 1;
        }

        // Base writeback: pre-indexed with W bit, or any post-indexed form.
        let writeback = (word >> 21) & 1 == 1;
        if !pre || writeback {
            let off = if i_bit { reg(word & 0xF) } else { constant((word & 0xFFF) as u64, 4) };
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: Some(reg(rn)), inputs: SmallVec::from_slice(&[reg(rn), off]) });
            *s += 1;
        }
        let _ = size;
    }

    /// Extra load/store: halfword (LDRH/STRH) and signed byte/halfword
    /// (LDRSB/LDRSH). bits 6:5 (SH) select the variant.
    fn lift_extra_load_store(&self, word: u32, address: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let pre = (word >> 24) & 1 == 1;
        let up = (word >> 23) & 1 == 1;
        let imm_offset = (word >> 22) & 1 == 1; // I bit here: 1 = immediate
        let load = (word >> 20) & 1 == 1;
        let rn = (word >> 16) & 0xF;
        let rd = (word >> 12) & 0xF;
        let sh = (word >> 5) & 0x3;

        let offset = if imm_offset {
            let imm = ((word >> 4) & 0xF0) | (word & 0xF); // imm4H:imm4L
            constant(imm as u64, 4)
        } else {
            reg(word & 0xF)
        };

        let addr = unique(0x600, 4);
        let op = if up { OpCode::IntAdd } else { OpCode::IntSub };
        if pre {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: Some(addr), inputs: SmallVec::from_slice(&[reg(rn), offset]) });
            *s += 1;
        } else {
            ops.push(PcodeOp { opcode: OpCode::Copy, seq: seq(*s), output: Some(addr), inputs: SmallVec::from_slice(&[reg(rn)]) });
            *s += 1;
        }

        // SH: 01 = H (unsigned halfword), 10 = signed byte, 11 = signed halfword
        let (size, signed) = match sh {
            0b01 => (2u32, false),
            0b10 => (1, true),
            _ => (2, true), // 0b11
        };

        if load {
            let loaded = unique(0x610, size);
            ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(loaded), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
            *s += 1;
            let ext = if signed { OpCode::IntSExt } else { OpCode::IntZExt };
            ops.push(PcodeOp { opcode: ext, seq: seq(*s), output: Some(reg(rd)), inputs: SmallVec::from_slice(&[loaded]) });
            *s += 1;
        } else {
            // STRH stores the low halfword of Rd.
            let value = VarnodeData::new(REG_SPACE, rd as u64 * 4, size);
            ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr, value]) });
            *s += 1;
        }

        let writeback = (word >> 21) & 1 == 1;
        if !pre || writeback {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: Some(reg(rn)), inputs: SmallVec::from_slice(&[reg(rn), offset]) });
            *s += 1;
        }
    }

    fn lift_block_transfer(&self, word: u32, address: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let pre = (word >> 24) & 1 == 1;
        let up = (word >> 23) & 1 == 1;
        let load = (word >> 20) & 1 == 1;
        let rn = (word >> 16) & 0xF;
        let reg_list = word & 0xFFFF;
        let count = reg_list.count_ones();
        if count == 0 {
            return;
        }

        // Model the common push (STMDB sp!) / pop (LDMIA sp!) forms: registers
        // are stored/loaded in ascending order at ascending addresses, and sp
        // is adjusted by 4*count.
        let base = reg(rn);
        let mut offset: i64 = if up {
            if pre { 4 } else { 0 }
        } else {
            // descending: lowest address = base - 4*count (+4 if pre/DB)
            -(4 * count as i64) + if pre { 0 } else { 4 }
        };

        for i in 0..16u32 {
            if reg_list & (1 << i) == 0 {
                continue;
            }
            let ea = unique(0x680 + *s as u64, 4);
            if offset >= 0 {
                ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(ea), inputs: SmallVec::from_slice(&[base, constant(offset as u64, 4)]) });
            } else {
                ops.push(PcodeOp { opcode: OpCode::IntSub, seq: seq(*s), output: Some(ea), inputs: SmallVec::from_slice(&[base, constant((-offset) as u64, 4)]) });
            }
            *s += 1;
            if load {
                if i == PC_INDEX {
                    // pop pc => return
                    let loaded = unique(0x690 + *s as u64, 4);
                    ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(loaded), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), ea]) });
                    *s += 1;
                    ops.push(PcodeOp { opcode: OpCode::Return, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[loaded]) });
                    *s += 1;
                } else {
                    ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(reg(i)), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), ea]) });
                    *s += 1;
                }
            } else {
                ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), ea, reg(i)]) });
                *s += 1;
            }
            offset += 4;
        }

        // Writeback (W bit) — adjust base by ±4*count.
        if (word >> 21) & 1 == 1 {
            let delta = 4 * count as u64;
            let op = if up { OpCode::IntAdd } else { OpCode::IntSub };
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: Some(base), inputs: SmallVec::from_slice(&[base, constant(delta, 4)]) });
            *s += 1;
        }
    }

    fn disasm_text(&self, bytes: &[u8], address: u64, word: u32) -> String {
        match self.cs.disasm_count(bytes, address, 1) {
            Ok(insns) => insns
                .iter()
                .next()
                .map(|insn| {
                    let m = insn.mnemonic().unwrap_or("???");
                    let o = insn.op_str().unwrap_or("");
                    if o.is_empty() { m.to_string() } else { format!("{} {}", m, o) }
                })
                .unwrap_or_else(|| format!(".word 0x{:08x}", word)),
            Err(_) => format!(".word 0x{:08x}", word),
        }
    }
}

impl PcodeLift for Arm32Lifter {
    fn lift_instruction(&self, memory: &Memory, address: u64) -> Result<LiftedInstruction, LiftError> {
        if self.thumb {
            let b0 = memory.read_byte(address).ok_or(LiftError::UnreadableAddress(address))?;
            let b1 = memory.read_byte(address + 1).ok_or(LiftError::UnreadableAddress(address))?;
            let hw1 = self.read_half(b0, b1);
            if Self::is_thumb32(hw1) {
                let b2 = memory.read_byte(address + 2).ok_or(LiftError::UnreadableAddress(address))?;
                let b3 = memory.read_byte(address + 3).ok_or(LiftError::UnreadableAddress(address))?;
                let hw2 = self.read_half(b2, b3);
                let ops = self.lift_thumb32(hw1, hw2, address);
                let mnemonic = self.disasm_text(&[b0, b1, b2, b3], address, ((hw1 as u32) << 16) | hw2 as u32);
                Ok(LiftedInstruction { address, length: 4, mnemonic, ops })
            } else {
                let ops = self.lift_thumb16(hw1, address);
                let mnemonic = self.disasm_text(&[b0, b1], address, hw1 as u32);
                Ok(LiftedInstruction { address, length: 2, mnemonic, ops })
            }
        } else {
            let mut buf = [0u8; 4];
            memory
                .read_bytes(address, &mut buf)
                .map_err(|_| LiftError::UnreadableAddress(address))?;
            let word = self.read_word(&buf);
            let ops = self.lift_word(word, address);
            let mnemonic = self.disasm_text(&buf, address, word);
            Ok(LiftedInstruction { address, length: 4, mnemonic, ops })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gr_core::address::SpaceId as CoreSpace;
    use gr_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn make_memory(word: u32, addr: u64) -> Memory {
        let bytes = word.to_le_bytes();
        let mut mem = Memory::new(CoreSpace(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: addr,
            size: 4,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(bytes.as_slice())),
        });
        mem
    }

    fn lift(word: u32) -> Vec<PcodeOp> {
        let lifter = Arm32Lifter::new(Endian::Little);
        let mem = make_memory(word, 0x1000);
        lifter.lift_instruction(&mem, 0x1000).unwrap().ops
    }

    #[test]
    fn lift_mov_imm() {
        // mov r0, #1  => 0xE3A00001
        let ops = lift(0xE3A0_0001);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode, OpCode::Copy);
        assert_eq!(ops[0].output.unwrap().offset, 0); // r0
        assert_eq!(ops[0].inputs[0].offset, 1);
    }

    #[test]
    fn lift_add_imm() {
        // add r0, r1, #4 => 0xE2810004
        let ops = lift(0xE281_0004);
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
        assert_eq!(ops[0].output.unwrap().offset, 0); // r0
        assert_eq!(ops[0].inputs[0].offset, 4); // r1
        assert_eq!(ops[0].inputs[1].offset, 4); // imm 4
    }

    #[test]
    fn lift_add_reg() {
        // add r0, r1, r2 => 0xE0810002
        let ops = lift(0xE081_0002);
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
        assert_eq!(ops[0].inputs[1].space, CoreSpace::REGISTER);
        assert_eq!(ops[0].inputs[1].offset, 8); // r2
    }

    #[test]
    fn lift_sub_imm() {
        // sub r0, r0, #1 => 0xE2400001
        let ops = lift(0xE240_0001);
        assert_eq!(ops[0].opcode, OpCode::IntSub);
    }

    #[test]
    fn lift_branch() {
        // b +8 => offset imm24 such that target = 0x1000+8+(imm<<2)
        // For target 0x1010: offset = 0x1010 - 0x1008 = 8 => imm24 = 2
        let word = 0xEA00_0000 | 2;
        let lifter = Arm32Lifter::new(Endian::Little);
        let mem = make_memory(word, 0x1000);
        let ops = lifter.lift_instruction(&mem, 0x1000).unwrap().ops;
        assert_eq!(ops[0].opcode, OpCode::Branch);
        assert_eq!(ops[0].inputs[0].offset, 0x1010);
    }

    #[test]
    fn lift_bl_is_call() {
        // bl +0 => 0xEB000000, target = 0x1008
        let ops = lift(0xEB00_0000);
        assert_eq!(ops[0].opcode, OpCode::Call);
        assert_eq!(ops[0].inputs[0].offset, 0x1008);
    }

    #[test]
    fn lift_bx_lr_is_return() {
        // bx lr => 0xE12FFF1E
        let ops = lift(0xE12F_FF1E);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode, OpCode::Return);
    }

    #[test]
    fn lift_cmp_sets_flags() {
        // cmp r0, #0 => 0xE3500000
        let ops = lift(0xE350_0000);
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntSub));
        assert!(ops.iter().any(|o| o.output.map(|v| v.offset == Z_FLAG).unwrap_or(false)));
    }

    #[test]
    fn lift_conditional_branch() {
        // beq +0 => cond=0 (EQ), 0x0A000000, target=0x1008
        let ops = lift(0x0A00_0000);
        assert!(ops.iter().any(|o| o.opcode == OpCode::CBranch));
        let cbr = ops.iter().find(|o| o.opcode == OpCode::CBranch).unwrap();
        assert_eq!(cbr.inputs[0].offset, 0x1008);
        // condition is the Z flag
        assert_eq!(cbr.inputs[1].offset, Z_FLAG);
    }

    #[test]
    fn lift_ldr_imm() {
        // ldr r0, [r1, #4] => 0xE5910004
        let ops = lift(0xE591_0004);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Load));
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntAdd));
    }

    #[test]
    fn lift_str_imm() {
        // str r0, [r1, #4] => 0xE5810004
        let ops = lift(0xE581_0004);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Store));
    }

    #[test]
    fn lift_push_lr() {
        // push {lr} => stmdb sp!, {lr} => 0xE92D4000
        let ops = lift(0xE92D_4000);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Store));
    }

    #[test]
    fn lift_bic_is_and_not() {
        // bic r0, r1, r2 => 0xE1C10002  (rd=r0, rn=r1, op2=r2)
        let ops = lift(0xE1C1_0002);
        // expect IntNegate(op2) then IntAnd(rn, ~op2)
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntNegate));
        let and_op = ops.iter().find(|o| o.opcode == OpCode::IntAnd).unwrap();
        assert_eq!(and_op.output.unwrap().offset, 0); // r0
    }

    #[test]
    fn lift_ror_is_rotate() {
        // mov r0, r1, ror #8 => 0xE1A00461
        let ops = lift(0xE1A0_0461);
        // ROR expands to (>> n) | (<< 32-n): expect a right shift, left shift, and OR.
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntRight));
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntLeft));
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntOr));
    }

    #[test]
    fn lift_ldrh() {
        // ldrh r0, [r1, #4] => 0xE1D100B4
        let ops = lift(0xE1D1_00B4);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Load));
        // unsigned halfword -> zero extend
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntZExt));
    }

    #[test]
    fn lift_ldrsb() {
        // ldrsb r0, [r1, #0] => 0xE1D100D0
        let ops = lift(0xE1D1_00D0);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Load));
        // signed byte -> sign extend
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntSExt));
    }

    #[test]
    fn lift_ldr_post_index_writeback() {
        // ldr r0, [r1], #4 => post-indexed: 0xE4910004
        let ops = lift(0xE491_0004);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Load));
        // base r1 should be written back (IntAdd into r1)
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntAdd
            && o.output.map(|v| v.offset == 4).unwrap_or(false)));
    }

    // ---- Thumb (T16/T32) ----

    fn make_thumb_mem(halfwords: &[u16], addr: u64) -> Memory {
        let mut bytes = Vec::new();
        for h in halfwords {
            bytes.extend_from_slice(&h.to_le_bytes());
        }
        let mut mem = Memory::new(CoreSpace(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: addr,
            size: bytes.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(bytes.as_slice())),
        });
        mem
    }

    fn lift_thumb(halfwords: &[u16]) -> LiftedInstruction {
        let lifter = Arm32Lifter::new_thumb(Endian::Little);
        let mem = make_thumb_mem(halfwords, 0x1000);
        lifter.lift_instruction(&mem, 0x1000).unwrap()
    }

    #[test]
    fn thumb_mov_imm() {
        // movs r0, #5 => 0x2005
        let li = lift_thumb(&[0x2005]);
        assert_eq!(li.length, 2);
        assert_eq!(li.ops[0].opcode, OpCode::Copy);
        assert_eq!(li.ops[0].output.unwrap().offset, 0);
        assert_eq!(li.ops[0].inputs[0].offset, 5);
    }

    #[test]
    fn thumb_add_imm3() {
        // adds r0, r1, #2 => format1 opc=10: 0b0001110_010_001_000 = 0x1C88
        let li = lift_thumb(&[0x1C88]);
        assert_eq!(li.ops[0].opcode, OpCode::IntAdd);
        assert_eq!(li.ops[0].output.unwrap().offset, 0); // r0
        assert_eq!(li.ops[0].inputs[0].offset, 4); // r1
        assert_eq!(li.ops[0].inputs[1].offset, 2); // imm3
    }

    #[test]
    fn thumb_add_reg() {
        // adds r0, r1, r2 => opc=00: 0b0001100_010_001_000 = 0x1888
        let li = lift_thumb(&[0x1888]);
        assert_eq!(li.ops[0].opcode, OpCode::IntAdd);
        assert_eq!(li.ops[0].inputs[1].space, CoreSpace::REGISTER);
        assert_eq!(li.ops[0].inputs[1].offset, 8); // r2
    }

    #[test]
    fn thumb_cmp_imm_sets_flags() {
        // cmp r0, #0 => 0x2800
        let li = lift_thumb(&[0x2800]);
        assert!(li.ops.iter().any(|o| o.output.map(|v| v.offset == Z_FLAG).unwrap_or(false)));
    }

    #[test]
    fn thumb_bx_lr_is_return() {
        // bx lr => 0x4770
        let li = lift_thumb(&[0x4770]);
        assert_eq!(li.ops[0].opcode, OpCode::Return);
    }

    #[test]
    fn thumb_conditional_branch() {
        // beq #+4 => 0xD0xx ; cond=0 (EQ), offset8
        // target = pc(0x1004) + (offset<<1). offset=0 => 0x1004
        let li = lift_thumb(&[0xD000]);
        let cbr = li.ops.iter().find(|o| o.opcode == OpCode::CBranch).unwrap();
        assert_eq!(cbr.inputs[0].offset, 0x1004);
        assert_eq!(cbr.inputs[1].offset, Z_FLAG);
    }

    #[test]
    fn thumb_unconditional_branch() {
        // b #+4 => 0xE000 ; target = 0x1004 + 0 = 0x1004
        let li = lift_thumb(&[0xE000]);
        assert_eq!(li.ops[0].opcode, OpCode::Branch);
        assert_eq!(li.ops[0].inputs[0].offset, 0x1004);
    }

    #[test]
    fn thumb_bl_is_32bit_call() {
        // bl to a small positive offset.
        // hw1 = 0xF000 (S=0, imm10=0), hw2 = 0xF800 (J1=1,J2=1,imm11=0) => BL
        // imm = (i1<<23)|(i2<<22) with i1=i2=1, s=0 => off = 0x00C00000 sign? 25-bit value
        // Just verify it decodes as a 4-byte Call.
        let li = lift_thumb(&[0xF000, 0xF800]);
        assert_eq!(li.length, 4);
        assert_eq!(li.ops[0].opcode, OpCode::Call);
    }

    #[test]
    fn thumb_movw() {
        // movw r0, #0x1234 => [0xF241, 0x2034]
        let li = lift_thumb(&[0xF241, 0x2034]);
        assert_eq!(li.length, 4);
        assert_eq!(li.ops[0].opcode, OpCode::Copy);
        assert_eq!(li.ops[0].output.unwrap().offset, 0);
        assert_eq!(li.ops[0].inputs[0].offset, 0x1234);
    }

    #[test]
    fn thumb_movt() {
        // movt r0, #0xABCD => [0xF6CA, 0x30CD]
        let li = lift_thumb(&[0xF6CA, 0x30CD]);
        assert!(li.ops.iter().any(|o| o.opcode == OpCode::IntAnd));
        let or = li.ops.iter().find(|o| o.opcode == OpCode::IntOr).unwrap();
        assert_eq!(or.inputs[1].offset, 0xABCD << 16);
    }

    #[test]
    fn thumb_add_w_imm() {
        // add.w r0, r1, #0x10 => [0xF101, 0x0010]
        let li = lift_thumb(&[0xF101, 0x0010]);
        let add = li.ops.iter().find(|o| o.opcode == OpCode::IntAdd).unwrap();
        assert_eq!(add.output.unwrap().offset, 0);   // r0
        assert_eq!(add.inputs[0].offset, 4);          // r1
        assert_eq!(add.inputs[1].offset, 0x10);
    }

    #[test]
    fn thumb_add_w_reg() {
        // add.w r0, r1, r2 => [0xEB01, 0x0002]
        let li = lift_thumb(&[0xEB01, 0x0002]);
        let add = li.ops.iter().find(|o| o.opcode == OpCode::IntAdd).unwrap();
        assert_eq!(add.inputs[0].offset, 4); // r1
        assert_eq!(add.inputs[1].space, CoreSpace::REGISTER);
        assert_eq!(add.inputs[1].offset, 8); // r2
    }

    #[test]
    fn thumb_ldr_w() {
        // ldr.w r0, [r1, #8] => [0xF8D1, 0x0008]
        let li = lift_thumb(&[0xF8D1, 0x0008]);
        assert_eq!(li.length, 4);
        assert!(li.ops.iter().any(|o| o.opcode == OpCode::Load));
    }

    #[test]
    fn thumb_cmp_w_imm_sets_flags() {
        // cmp.w r1, #0 => data-proc modified imm, opc=1101(SUB/CMP), S=1, Rd=PC
        // hw1 = 0xF1B1 (opc=D, S=1, Rn=1), hw2 = 0x0F00 (Rd=PC=15, imm8=0)
        let li = lift_thumb(&[0xF1B1, 0x0F00]);
        assert!(li.ops.iter().any(|o| o.output.map(|v| v.offset == Z_FLAG).unwrap_or(false)));
    }

    #[test]
    fn thumb_expand_imm_values() {
        assert_eq!(Arm32Lifter::thumb_expand_imm(0x010), 0x10);          // plain imm8
        assert_eq!(Arm32Lifter::thumb_expand_imm(0x1FF), 0x00FF_00FF);   // pattern 01
        assert_eq!(Arm32Lifter::thumb_expand_imm(0x2FF), 0xFF00_FF00);   // pattern 10
        assert_eq!(Arm32Lifter::thumb_expand_imm(0x3FF), 0xFFFF_FFFF);   // pattern 11
    }

    #[test]
    fn thumb_push_pop() {
        // push {r4, lr} => 0xB510
        let push = lift_thumb(&[0xB510]);
        assert!(push.ops.iter().any(|o| o.opcode == OpCode::Store));
        assert!(push.ops.iter().any(|o| o.opcode == OpCode::IntSub)); // sp adjust
        // pop {r4, pc} => 0xBD10 => should return
        let pop = lift_thumb(&[0xBD10]);
        assert!(pop.ops.iter().any(|o| o.opcode == OpCode::Return));
    }

    #[test]
    fn thumb_ldr_imm() {
        // ldr r0, [r1, #4] => format9 word load: 0b01101_00001_001_000
        // L=1 B=0 imm5=1 (=>*4=4) rn=1 rd=0 => 0x6848
        let li = lift_thumb(&[0x6848]);
        assert!(li.ops.iter().any(|o| o.opcode == OpCode::Load));
    }

    #[test]
    fn thumb_length_detection() {
        // 0xBF00 (nop) is 16-bit; 0xF000.. is 32-bit
        assert!(!Arm32Lifter::is_thumb32(0xBF00));
        assert!(Arm32Lifter::is_thumb32(0xF000));
        assert!(Arm32Lifter::is_thumb32(0xE800));
        assert!(!Arm32Lifter::is_thumb32(0xE000)); // 16-bit unconditional B
    }
}
