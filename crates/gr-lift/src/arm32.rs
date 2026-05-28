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
}

unsafe impl Send for Arm32Lifter {}
unsafe impl Sync for Arm32Lifter {}

impl Arm32Lifter {
    pub fn new(endian: Endian) -> Self {
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
        }
    }

    fn read_word(&self, buf: &[u8; 4]) -> u32 {
        if self.big_endian {
            u32::from_be_bytes(*buf)
        } else {
            u32::from_le_bytes(*buf)
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
            } else {
                let op = match shift_type {
                    0 => OpCode::IntLeft,
                    1 => OpCode::IntRight,
                    2 => OpCode::IntSRight,
                    _ => OpCode::IntRight, // ROR approximated
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
            0xE => self.dp_binop(OpCode::IntAnd, rd, rn_v, op2, ops, s, address),       // BIC (rn & ~op2; ~ approximated below)
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
        let _ = size;
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
}
