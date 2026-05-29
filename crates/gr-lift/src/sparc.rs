//! SPARC V8 (32-bit) → P-code lifter.
//!
//! Decodes the common SPARC formats directly into P-code: SETHI, integer
//! arithmetic/logical (register and simm13), shifts, multiply/divide,
//! load/store, integer compares/cc into a simplified icc, CALL, Bicc
//! conditional branches, and JMPL (call/return/indirect). Capstone supplies the
//! disassembly text. SPARC is big-endian with fixed 4-byte instructions; `%g0`
//! reads as 0 and discards writes.
//!
//! ADDX/SUBX use the icc carry. Branch delay slots are honoured via a
//! `LiftContext`: a CALL/JMPL/Bicc defers its control transfer past the
//! following (delay-slot) instruction, whose effects run first, and the branch
//! condition is snapshotted before the slot. For an annulling conditional
//! branch the delay slot runs only when taken, so its register writes are
//! predicated on the condition and a store is guarded by writing back the
//! loaded value when not taken; `ba,a` stays inline and `bn,a` jumps over its
//! squashed slot. The stateless `lift_instruction` path still emits the
//! transfer inline. The remaining simplification is SAVE/RESTORE, which model
//! only the pointer arithmetic, not the register-window rotation.

use gr_core::address::{Address, SpaceId};
use gr_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use gr_loader::Memory;
use smallvec::SmallVec;

use crate::lift::{DelaySlot, LiftContext, LiftError, LiftedInstruction, PcodeLift};

const CONST_SPACE: SpaceId = SpaceId::CONST;
const RAM_SPACE: SpaceId = SpaceId::RAM;
const REG_SPACE: SpaceId = SpaceId::REGISTER;
const UNIQUE_SPACE: SpaceId = SpaceId::UNIQUE;

const O7_INDEX: u32 = 15; // link register for calls
const I7_INDEX: u32 = 31; // return address register

// Simplified integer condition codes (icc), one byte each.
const ICC_N: u64 = 0x200;
const ICC_Z: u64 = 0x201;
const ICC_V: u64 = 0x202;
const ICC_C: u64 = 0x203;

fn constant(value: u64, size: u32) -> VarnodeData {
    VarnodeData::new(CONST_SPACE, value, size)
}

fn ram(addr: u64) -> VarnodeData {
    VarnodeData::new(RAM_SPACE, addr, 4)
}

fn unique(offset: u64, size: u32) -> VarnodeData {
    VarnodeData::new(UNIQUE_SPACE, offset, size)
}

fn reg(n: u32) -> VarnodeData {
    VarnodeData::new(REG_SPACE, n as u64 * 4, 4)
}

fn flag(off: u64) -> VarnodeData {
    VarnodeData::new(REG_SPACE, off, 1)
}

/// Source operand: `%g0` (r0) reads as the literal 0.
fn rs(n: u32) -> VarnodeData {
    if n == 0 { constant(0, 4) } else { reg(n) }
}

/// Destination: writes to `%g0` (r0) are discarded.
fn rd_out(n: u32) -> Option<VarnodeData> {
    if n == 0 { None } else { Some(reg(n)) }
}

pub struct SparcLifter {
    cs: capstone::Capstone,
}

unsafe impl Send for SparcLifter {}
unsafe impl Sync for SparcLifter {}

impl SparcLifter {
    pub fn new_32() -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .sparc()
            .mode(arch::sparc::ArchMode::Default)
            .build()
            .expect("failed to create SPARC capstone");
        Self { cs }
    }

    fn lift_word(&self, word: u32, address: u64) -> Vec<PcodeOp> {
        let mut ops: Vec<PcodeOp> = Vec::new();
        let mut s = 0u32;
        let op = word >> 30;

        match op {
            1 => {
                // CALL: target = pc + disp30*4; %o7 = pc (return address).
                let disp30 = word & 0x3FFF_FFFF;
                let target = address.wrapping_add((disp30 << 2) as u64) & 0xFFFF_FFFF;
                self.push(&mut ops, &mut s, OpCode::Copy, Some(reg(O7_INDEX)), &[constant(address & 0xFFFF_FFFF, 4)], address);
                self.push(&mut ops, &mut s, OpCode::Call, None, &[ram(target)], address);
            }
            0 => self.lift_format2(word, address, &mut ops, &mut s),
            2 => self.lift_format3_alu(word, address, &mut ops, &mut s),
            3 => self.lift_format3_mem(word, address, &mut ops, &mut s),
            _ => {}
        }
        ops
    }

    fn lift_format2(&self, word: u32, address: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let op2 = (word >> 22) & 0x7;
        match op2 {
            4 => {
                // SETHI rd, imm22 : rd = imm22 << 10  (sethi %g0,0 = nop)
                let rd = (word >> 25) & 0x1F;
                let imm22 = word & 0x3F_FFFF;
                if let Some(out) = rd_out(rd) {
                    self.push(ops, s, OpCode::Copy, Some(out), &[constant((imm22 << 10) as u64, 4)], address);
                }
            }
            2 => {
                // Bicc: integer conditional branch.
                let cond = (word >> 25) & 0xF;
                let disp22 = ((word & 0x3F_FFFF) << 10) as i32 >> 10; // sign-extend 22 bits
                let target = address.wrapping_add((disp22 << 2) as i64 as u64) & 0xFFFF_FFFF;
                match cond {
                    0x0 => {} // BN: branch never
                    0x8 => self.push(ops, s, OpCode::Branch, None, &[ram(target)], address), // BA
                    _ => {
                        if let Some(c) = self.emit_cond(cond, ops, s, address) {
                            self.push(ops, s, OpCode::CBranch, None, &[ram(target), c], address);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn lift_format3_alu(&self, word: u32, address: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let op3 = (word >> 19) & 0x3F;
        let rd = (word >> 25) & 0x1F;
        let rs1 = (word >> 14) & 0x1F;
        let i = (word >> 13) & 1 == 1;
        let b = if i {
            constant(((word & 0x1FFF) << 19) as i32 as i64 as u64 >> 19 & 0xFFFF_FFFF, 4)
        } else {
            rs(word & 0x1F)
        };
        let a = rs(rs1);

        match op3 {
            0x38 => {
                // JMPL: target = rs1 + b; rd = pc (link).
                let target = unique(0x500, 4);
                self.push(ops, s, OpCode::IntAdd, Some(target), &[a, b], address);
                if let Some(out) = rd_out(rd) {
                    self.push(ops, s, OpCode::Copy, Some(out), &[constant(address & 0xFFFF_FFFF, 4)], address);
                }
                if rd == 0 && (rs1 == I7_INDEX || rs1 == O7_INDEX) {
                    self.push(ops, s, OpCode::Return, None, &[target], address);
                } else if rd == O7_INDEX {
                    self.push(ops, s, OpCode::CallInd, None, &[target], address);
                } else {
                    self.push(ops, s, OpCode::BranchInd, None, &[target], address);
                }
            }
            0x3C | 0x3D => {
                // SAVE / RESTORE: model only rd = rs1 + b (ignore window rotation).
                if let Some(out) = rd_out(rd) {
                    self.push(ops, s, OpCode::IntAdd, Some(out), &[a, b], address);
                }
            }
            0x25 => self.alu_simple(OpCode::IntLeft, rd, a, b, ops, s, address),   // SLL
            0x26 => self.alu_simple(OpCode::IntRight, rd, a, b, ops, s, address),  // SRL
            0x27 => self.alu_simple(OpCode::IntSRight, rd, a, b, ops, s, address), // SRA
            _ if op3 < 0x20 => {
                let base = op3 & 0xF;
                let cc = op3 & 0x10 != 0;
                self.alu_base(base, cc, rd, a, b, ops, s, address);
            }
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn alu_base(&self, base: u32, cc: bool, rd: u32, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        // Compute the result into a temp so flags can read it even when rd=%g0.
        let res = unique(0x510, 4);
        match base {
            0x0 => self.push(ops, s, OpCode::IntAdd, Some(res), &[a, b], address),        // ADD
            0x4 => self.push(ops, s, OpCode::IntSub, Some(res), &[a, b], address),        // SUB
            0x8 => self.emit_addx(res, a, b, ops, s, address),                            // ADDX: a + b + C
            0xC => self.emit_subx(res, a, b, ops, s, address),                            // SUBX: a - b - C
            0x1 => self.push(ops, s, OpCode::IntAnd, Some(res), &[a, b], address),        // AND
            0x2 => self.push(ops, s, OpCode::IntOr, Some(res), &[a, b], address),         // OR
            0x3 => self.push(ops, s, OpCode::IntXor, Some(res), &[a, b], address),        // XOR
            0x5 => self.alu_with_not(OpCode::IntAnd, res, a, b, ops, s, address),         // ANDN
            0x6 => self.alu_with_not(OpCode::IntOr, res, a, b, ops, s, address),          // ORN
            0x7 => {                                                                       // XNOR
                let t = unique(0x518, 4);
                self.push(ops, s, OpCode::IntXor, Some(t), &[a, b], address);
                self.push(ops, s, OpCode::IntNegate, Some(res), &[t], address);
            }
            0xA | 0xB => self.push(ops, s, OpCode::IntMult, Some(res), &[a, b], address), // UMUL / SMUL
            0xE => self.push(ops, s, OpCode::IntDiv, Some(res), &[a, b], address),        // UDIV
            0xF => self.push(ops, s, OpCode::IntSDiv, Some(res), &[a, b], address),       // SDIV
            _ => return,
        }
        if cc {
            let is_add = matches!(base, 0x0 | 0x8);
            let is_sub = matches!(base, 0x4 | 0xC);
            self.set_flags(a, b, res, is_add, is_sub, ops, s, address);
        }
        if let Some(out) = rd_out(rd) {
            self.push(ops, s, OpCode::Copy, Some(out), &[res], address);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn alu_with_not(&self, op: OpCode, res: VarnodeData, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let nb = unique(0x520, 4);
        self.push(ops, s, OpCode::IntNegate, Some(nb), &[b], address);
        self.push(ops, s, op, Some(res), &[a, nb], address);
    }

    /// ADDX: `res = a + b + C` (icc carry).
    fn emit_addx(&self, res: VarnodeData, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let t = unique(0x528, 4);
        self.push(ops, s, OpCode::IntAdd, Some(t), &[a, b], address);
        let cin = unique(0x530, 4);
        self.push(ops, s, OpCode::IntZExt, Some(cin), &[flag(ICC_C)], address);
        self.push(ops, s, OpCode::IntAdd, Some(res), &[t, cin], address);
    }

    /// SUBX: `res = a - b - C` (icc carry).
    fn emit_subx(&self, res: VarnodeData, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let t = unique(0x528, 4);
        self.push(ops, s, OpCode::IntSub, Some(t), &[a, b], address);
        let cin = unique(0x530, 4);
        self.push(ops, s, OpCode::IntZExt, Some(cin), &[flag(ICC_C)], address);
        self.push(ops, s, OpCode::IntSub, Some(res), &[t, cin], address);
    }

    #[allow(clippy::too_many_arguments)]
    fn alu_simple(&self, op: OpCode, rd: u32, a: VarnodeData, b: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        if let Some(out) = rd_out(rd) {
            self.push(ops, s, op, Some(out), &[a, b], address);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn set_flags(&self, a: VarnodeData, b: VarnodeData, res: VarnodeData, is_add: bool, is_sub: bool, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        // Z = res == 0 ; N = res <s 0
        self.push(ops, s, OpCode::IntEqual, Some(flag(ICC_Z)), &[res, constant(0, 4)], address);
        self.push(ops, s, OpCode::IntSLess, Some(flag(ICC_N)), &[res, constant(0, 4)], address);
        if is_sub {
            // C = borrow = a <u b ; V = signed borrow
            self.push(ops, s, OpCode::IntLess, Some(flag(ICC_C)), &[a, b], address);
            self.push(ops, s, OpCode::IntSBorrow, Some(flag(ICC_V)), &[a, b], address);
        } else if is_add {
            // C = unsigned carry ; V = signed carry
            self.push(ops, s, OpCode::IntCarry, Some(flag(ICC_C)), &[a, b], address);
            self.push(ops, s, OpCode::IntSCarry, Some(flag(ICC_V)), &[a, b], address);
        } else {
            // Logical: C and V cleared.
            self.push(ops, s, OpCode::Copy, Some(flag(ICC_C)), &[constant(0, 1)], address);
            self.push(ops, s, OpCode::Copy, Some(flag(ICC_V)), &[constant(0, 1)], address);
        }
    }

    fn lift_format3_mem(&self, word: u32, address: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let op3 = (word >> 19) & 0x3F;
        let rd = (word >> 25) & 0x1F;
        let rs1 = (word >> 14) & 0x1F;
        let i = (word >> 13) & 1 == 1;
        let off = if i {
            constant(((word & 0x1FFF) << 19) as i32 as i64 as u64 >> 19 & 0xFFFF_FFFF, 4)
        } else {
            rs(word & 0x1F)
        };
        let ea = unique(0x600, 4);
        self.push(ops, s, OpCode::IntAdd, Some(ea), &[rs(rs1), off], address);

        match op3 {
            0x00 => self.emit_load(rd, ea, 4, false, ops, s, address), // LD
            0x01 => self.emit_load(rd, ea, 1, false, ops, s, address), // LDUB
            0x02 => self.emit_load(rd, ea, 2, false, ops, s, address), // LDUH
            0x09 => self.emit_load(rd, ea, 1, true, ops, s, address),  // LDSB
            0x0A => self.emit_load(rd, ea, 2, true, ops, s, address),  // LDSH
            0x04 => self.emit_store(rd, ea, 4, ops, s, address),       // ST
            0x05 => self.emit_store(rd, ea, 1, ops, s, address),       // STB
            0x06 => self.emit_store(rd, ea, 2, ops, s, address),       // STH
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_load(&self, rd: u32, ea: VarnodeData, size: u32, signed: bool, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let Some(out) = rd_out(rd) else { return };
        if size == 4 {
            self.push(ops, s, OpCode::Load, Some(out), &[constant(RAM_SPACE.0 as u64, 4), ea], address);
        } else {
            let loaded = unique(0x610, size);
            self.push(ops, s, OpCode::Load, Some(loaded), &[constant(RAM_SPACE.0 as u64, 4), ea], address);
            let ext = if signed { OpCode::IntSExt } else { OpCode::IntZExt };
            self.push(ops, s, ext, Some(out), &[loaded], address);
        }
    }

    fn emit_store(&self, rd: u32, ea: VarnodeData, size: u32, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let value = if size == 4 {
            rs(rd)
        } else if rd == 0 {
            constant(0, size)
        } else {
            VarnodeData::new(REG_SPACE, rd as u64 * 4, size)
        };
        self.push(ops, s, OpCode::Store, None, &[constant(RAM_SPACE.0 as u64, 4), ea, value], address);
    }

    /// Build the branch condition for a Bicc cond field (icc-based). Returns
    /// `None` for "branch never" (cond 0); "branch always" is handled by caller.
    fn emit_cond(&self, cond: u32, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) -> Option<VarnodeData> {
        let n = flag(ICC_N);
        let z = flag(ICC_Z);
        let v = flag(ICC_V);
        let c = flag(ICC_C);
        let not = |ops: &mut Vec<PcodeOp>, s: &mut u32, x: VarnodeData, addr: u64| -> VarnodeData {
            let t = unique(0x700 + *s as u64 * 2, 1);
            ops.push(PcodeOp { opcode: OpCode::BoolNegate, seq: SeqNum::new(Address::new(RAM_SPACE, addr), *s), output: Some(t), inputs: SmallVec::from_slice(&[x]) });
            *s += 1;
            t
        };
        let bin = |ops: &mut Vec<PcodeOp>, s: &mut u32, op: OpCode, x: VarnodeData, y: VarnodeData, addr: u64| -> VarnodeData {
            let t = unique(0x720 + *s as u64 * 2, 1);
            ops.push(PcodeOp { opcode: op, seq: SeqNum::new(Address::new(RAM_SPACE, addr), *s), output: Some(t), inputs: SmallVec::from_slice(&[x, y]) });
            *s += 1;
            t
        };
        let r = match cond {
            0x1 => z,                                              // BE
            0x9 => not(ops, s, z, address),                        // BNE
            0x5 => c,                                              // BCS / BLU
            0xD => not(ops, s, c, address),                        // BCC / BGEU
            0x6 => n,                                              // BNEG
            0xE => not(ops, s, n, address),                        // BPOS
            0x7 => v,                                              // BVS
            0xF => not(ops, s, v, address),                        // BVC
            0x3 => bin(ops, s, OpCode::IntXor, n, v, address),     // BL:  N^V
            0xB => { let nv = bin(ops, s, OpCode::IntXor, n, v, address); not(ops, s, nv, address) } // BGE
            0x2 => { let nv = bin(ops, s, OpCode::IntXor, n, v, address); bin(ops, s, OpCode::BoolOr, z, nv, address) } // BLE
            0xA => { let nv = bin(ops, s, OpCode::IntXor, n, v, address); let le = bin(ops, s, OpCode::BoolOr, z, nv, address); not(ops, s, le, address) } // BG
            0x4 => bin(ops, s, OpCode::BoolOr, c, z, address),     // BLEU: C|Z
            0xC => { let cz = bin(ops, s, OpCode::BoolOr, c, z, address); not(ops, s, cz, address) } // BGU
            _ => return None,
        };
        Some(r)
    }

    #[allow(clippy::too_many_arguments)]
    fn push(&self, ops: &mut Vec<PcodeOp>, s: &mut u32, op: OpCode, out: Option<VarnodeData>, ins: &[VarnodeData], address: u64) {
        ops.push(PcodeOp {
            opcode: op,
            seq: SeqNum::new(Address::new(RAM_SPACE, address), *s),
            output: out,
            inputs: SmallVec::from_slice(ins),
        });
        *s += 1;
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

/// Whether an opcode is a control transfer that ends a basic block.
fn is_control(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Branch | OpCode::CBranch | OpCode::Call | OpCode::CallInd | OpCode::BranchInd | OpCode::Return
    )
}

impl SparcLifter {
    /// Decide how `word`'s delay slot is handled: `(defer, predicate)`.
    /// `defer` = move the control transfer past the delay slot; `predicate` =
    /// the delay slot runs only when the branch is taken (annulling conditional)
    /// so its register writes are guarded by the condition.
    ///
    /// `ba,a` is left inline (the transfer skips the annulled delay slot), and
    /// `bn`/`bn,a` produce no transfer.
    fn cti_decision(word: u32) -> (bool, bool) {
        match word >> 30 {
            1 => (true, false),                                  // CALL
            2 if (word >> 19) & 0x3F == 0x38 => (true, false),   // JMPL
            0 if (word >> 22) & 7 == 2 => {
                let cond = (word >> 25) & 0xF;
                let annul = (word >> 29) & 1 == 1;
                match cond {
                    8 => (!annul, false), // BA: defer; BA,a stays inline (skips slot)
                    0 => (false, false),  // BN: no transfer
                    _ => (true, annul),   // conditional: defer; annulling predicates slot
                }
            }
            _ => (false, false),
        }
    }

    fn read_word_be(&self, memory: &Memory, address: u64) -> Option<u32> {
        let mut buf = [0u8; 4];
        memory.read_bytes(address, &mut buf).ok()?;
        Some(u32::from_be_bytes(buf))
    }

    /// Predicate a delay-slot instruction's effects on `cond` (branch-free),
    /// for annulling conditional branches. Register writes are committed via a
    /// select; a store is guarded by writing back the loaded value when the
    /// branch is not taken (`store(ea, cond ? value : *ea)`).
    fn predicate_delay_slot(&self, ops: Vec<PcodeOp>, cond: VarnodeData, address: u64) -> Vec<PcodeOp> {
        let mut regs: Vec<VarnodeData> = Vec::new();
        let mut has_store = false;
        for op in &ops {
            if op.opcode == OpCode::Store {
                has_store = true;
            }
            if let Some(out) = op.output
                && out.space == REG_SPACE
                && !regs.iter().any(|r| r.offset == out.offset && r.size == out.size)
            {
                regs.push(out);
            }
        }
        if regs.is_empty() && !has_store {
            return ops;
        }
        let mut out: Vec<PcodeOp> = Vec::new();
        let mut s = 0u32;
        let mut olds = Vec::new();
        for (i, r) in regs.iter().enumerate() {
            let o = unique(0x800 + i as u64 * 8, r.size);
            self.push(&mut out, &mut s, OpCode::Copy, Some(o), &[*r], address);
            olds.push(o);
        }
        for op in ops {
            if op.opcode == OpCode::Store && op.inputs.len() == 3 {
                // store(space, ea, value) => only commit when taken:
                //   cur = load(space, ea); sel = cond ? value : cur; store(space, ea, sel)
                let space = op.inputs[0];
                let ea = op.inputs[1];
                let value = op.inputs[2];
                let size = value.size;
                let cur = unique(0x820, size);
                self.push(&mut out, &mut s, OpCode::Load, Some(cur), &[space, ea], address);
                let sel = unique(0x828, size);
                self.push(&mut out, &mut s, OpCode::Copy, Some(sel), &[value], address);
                self.emit_select(cond, sel, cur, &mut out, &mut s, address);
                self.push(&mut out, &mut s, OpCode::Store, None, &[space, ea, sel], address);
            } else {
                let mut op = op;
                op.seq = SeqNum::new(Address::new(RAM_SPACE, address), s);
                s += 1;
                out.push(op);
            }
        }
        for (r, old) in regs.iter().zip(olds.iter()) {
            self.emit_select(cond, *r, *old, &mut out, &mut s, address);
        }
        out
    }

    /// Branch-free `dst = cond ? dst : old` for an arbitrary-size register.
    fn emit_select(&self, cond: VarnodeData, dst: VarnodeData, old: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let size = dst.size;
        let cz = unique(0x780, size);
        if size == 1 {
            self.push(ops, s, OpCode::Copy, Some(cz), &[cond], address);
        } else {
            self.push(ops, s, OpCode::IntZExt, Some(cz), &[cond], address);
        }
        let mask = unique(0x788, size);
        self.push(ops, s, OpCode::Int2Comp, Some(mask), &[cz], address);
        let a = unique(0x790, size);
        self.push(ops, s, OpCode::IntAnd, Some(a), &[dst, mask], address);
        let nmask = unique(0x798, size);
        self.push(ops, s, OpCode::IntNegate, Some(nmask), &[mask], address);
        let b = unique(0x7A0, size);
        self.push(ops, s, OpCode::IntAnd, Some(b), &[old, nmask], address);
        self.push(ops, s, OpCode::IntOr, Some(dst), &[a, b], address);
    }
}

impl PcodeLift for SparcLifter {
    fn lift_instruction(&self, memory: &Memory, address: u64) -> Result<LiftedInstruction, LiftError> {
        let mut buf = [0u8; 4];
        memory
            .read_bytes(address, &mut buf)
            .map_err(|_| LiftError::UnreadableAddress(address))?;
        let word = u32::from_be_bytes(buf); // SPARC is big-endian
        let ops = self.lift_word(word, address);
        let mnemonic = self.disasm_text(&buf, address, word);
        Ok(LiftedInstruction { address, length: 4, mnemonic, ops })
    }

    fn lift_instruction_ctx(&self, memory: &Memory, address: u64, ctx: &mut LiftContext) -> Result<LiftedInstruction, LiftError> {
        // A transfer pending for this address means this instruction is the
        // delay slot: lift it normally, then append the deferred transfer so the
        // delay slot's effects happen before control leaves. A stale pending
        // (address mismatch from a diverged stream) is simply dropped.
        let pending = ctx.delay.take().filter(|d| d.addr == address);

        let mut li = self.lift_instruction(memory, address)?;

        if let Some(d) = pending {
            // Annulling conditional branch: the delay slot runs only when taken,
            // so guard its register writes on the branch condition.
            if d.annul
                && let Some(cond) = d.op.inputs.get(1).copied()
            {
                li.ops = self.predicate_delay_slot(li.ops, cond, address);
            }
            let mut op = d.op;
            op.seq = SeqNum::new(Address::new(RAM_SPACE, address), li.ops.len() as u32);
            li.ops.push(op);
            return Ok(li);
        }

        // A control-transfer instruction defers its trailing op past the delay
        // slot (see cti_decision).
        if let Some(word) = self.read_word_be(memory, address) {
            // bn,a (branch never, annul) squashes its delay slot: model it as a
            // jump over the slot to the next instruction.
            if word >> 30 == 0
                && (word >> 22) & 7 == 2
                && (word >> 25) & 0xF == 0
                && (word >> 29) & 1 == 1
            {
                let target = address.wrapping_add(8) & 0xFFFF_FFFF;
                let seq = SeqNum::new(Address::new(RAM_SPACE, address), li.ops.len() as u32);
                li.ops.push(PcodeOp { opcode: OpCode::Branch, seq, output: None, inputs: SmallVec::from_slice(&[ram(target)]) });
                return Ok(li);
            }
            let (defer, annul) = Self::cti_decision(word);
            if defer && li.ops.last().map(|o| is_control(o.opcode)).unwrap_or(false) {
                let mut ctrl = li.ops.pop().unwrap();
                // SPARC evaluates a branch condition before the delay slot.
                // Snapshot it into a stable temp at the branch so neither the
                // deferred CBranch nor the delay-slot predication is affected by
                // a delay slot that updates the icc flags.
                if ctrl.opcode == OpCode::CBranch
                    && let Some(cond) = ctrl.inputs.get(1).copied()
                {
                    let snap = unique(0x540, cond.size);
                    let seq = SeqNum::new(Address::new(RAM_SPACE, address), li.ops.len() as u32);
                    li.ops.push(PcodeOp { opcode: OpCode::Copy, seq, output: Some(snap), inputs: SmallVec::from_slice(&[cond]) });
                    ctrl.inputs[1] = snap;
                }
                ctx.delay = Some(DelaySlot { op: ctrl, addr: address + 4, annul });
            }
        }
        Ok(li)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gr_core::address::Endian;
    use gr_core::address::SpaceId as CoreSpace;
    use gr_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn make_memory(word: u32, addr: u64) -> Memory {
        let bytes = word.to_be_bytes();
        let mut mem = Memory::new(CoreSpace(1), Endian::Big);
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
        let lifter = SparcLifter::new_32();
        let mem = make_memory(word, 0x1000);
        lifter.lift_instruction(&mem, 0x1000).unwrap().ops
    }

    /// Lift two words at 0x1000/0x1004 sharing a LiftContext (delay-slot path).
    fn lift_ctx_two(w0: u32, w1: u32) -> (Vec<PcodeOp>, Vec<PcodeOp>) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&w0.to_be_bytes());
        bytes.extend_from_slice(&w1.to_be_bytes());
        let mut mem = Memory::new(CoreSpace(1), Endian::Big);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: 0x1000,
            size: 8,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(bytes.as_slice())),
        });
        let lifter = SparcLifter::new_32();
        let mut ctx = LiftContext::default();
        let a = lifter.lift_instruction_ctx(&mem, 0x1000, &mut ctx).unwrap().ops;
        let b = lifter.lift_instruction_ctx(&mem, 0x1004, &mut ctx).unwrap().ops;
        (a, b)
    }

    // Format-3 ALU encoder: op=2, op3, rd, rs1, i, rs2/simm13.
    fn f3(op3: u32, rd: u32, rs1: u32, rs2: u32) -> u32 {
        (2 << 30) | (rd << 25) | (op3 << 19) | (rs1 << 14) | rs2
    }
    fn f3i(op3: u32, rd: u32, rs1: u32, simm13: u32) -> u32 {
        (2 << 30) | (rd << 25) | (op3 << 19) | (rs1 << 14) | (1 << 13) | (simm13 & 0x1FFF)
    }

    #[test]
    fn lift_add_reg() {
        // add %o0, %o1, %o2  -> rd=o2(10), rs1=o0(8), rs2=o1(9), op3=0
        let ops = lift(f3(0x00, 10, 8, 9));
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
        assert_eq!(ops[0].inputs[0].offset, 8 * 4);
        assert_eq!(ops[0].inputs[1].offset, 9 * 4);
        // result copied to o2
        let last = ops.last().unwrap();
        assert_eq!(last.output.unwrap().offset, 10 * 4);
    }

    #[test]
    fn lift_add_imm() {
        // add %o0, 1, %o0  (inc)  rd=8 rs1=8 simm=1
        let ops = lift(f3i(0x00, 8, 8, 1));
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
        assert_eq!(ops[0].inputs[1].space, CoreSpace::CONST);
        assert_eq!(ops[0].inputs[1].offset, 1);
    }

    #[test]
    fn lift_add_imm_negative() {
        // add %o0, -1, %o0  : simm13 = 0x1FFF (-1)
        let ops = lift(f3i(0x00, 8, 8, 0x1FFF));
        assert_eq!(ops[0].inputs[1].offset, 0xFFFF_FFFF);
    }

    #[test]
    fn lift_g0_write_discarded() {
        // add %o0, %o1, %g0 : rd=0 -> no register written
        let ops = lift(f3(0x00, 0, 8, 9));
        // add computes into a temp but nothing copies to a register
        assert!(!ops.iter().any(|o| o.output.map(|v| v.space == CoreSpace::REGISTER && v.offset < 0x200).unwrap_or(false)));
    }

    #[test]
    fn lift_or_g0_is_mov() {
        // or %g0, %o1, %o0  (mov %o1, %o0): rs1=0 reads as const 0
        let ops = lift(f3(0x02, 8, 0, 9));
        assert_eq!(ops[0].opcode, OpCode::IntOr);
        assert_eq!(ops[0].inputs[0].space, CoreSpace::CONST);
        assert_eq!(ops[0].inputs[0].offset, 0);
    }

    #[test]
    fn lift_andn() {
        // andn %o0, %o1, %o2 : op3=0x05 -> negate then and
        let ops = lift(f3(0x05, 10, 8, 9));
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntNegate));
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntAnd));
    }

    #[test]
    fn lift_subcc_sets_flags() {
        // subcc %o0, %o1, %g0  (cmp %o0,%o1): op3=0x14, rd=0
        let ops = lift(f3(0x14, 0, 8, 9));
        assert!(ops.iter().any(|o| o.output.map(|v| v.offset == ICC_Z).unwrap_or(false)));
        assert!(ops.iter().any(|o| o.output.map(|v| v.offset == ICC_C).unwrap_or(false)));
    }

    #[test]
    fn lift_addx_uses_carry() {
        // addx %o0, %o1, %o2 : op3=0x08
        let ops = lift(f3(0x08, 10, 8, 9));
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntZExt && o.inputs[0].offset == ICC_C));
        // a+b then +carry => two IntAdd
        assert!(ops.iter().filter(|o| o.opcode == OpCode::IntAdd).count() >= 2);
    }

    #[test]
    fn lift_subx_uses_carry() {
        // subx %o0, %o1, %o2 : op3=0x0C
        let ops = lift(f3(0x0C, 10, 8, 9));
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntZExt && o.inputs[0].offset == ICC_C));
        assert!(ops.iter().filter(|o| o.opcode == OpCode::IntSub).count() >= 2);
    }

    #[test]
    fn lift_sll() {
        // sll %o0, 2, %o1 : op3=0x25
        let ops = lift(f3i(0x25, 9, 8, 2));
        assert_eq!(ops[0].opcode, OpCode::IntLeft);
        assert_eq!(ops[0].output.unwrap().offset, 9 * 4);
    }

    #[test]
    fn lift_sethi() {
        // sethi 0x3FFFFF, %o0 : op=0, op2=4, rd=8
        let word = (8 << 25) | (4 << 22) | 0x3F_FFFF;
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::Copy);
        assert_eq!(ops[0].inputs[0].offset, (0x3F_FFFF << 10) & 0xFFFF_FFFF);
    }

    #[test]
    fn lift_nop_is_empty() {
        // nop = sethi %g0, 0  (rd=0) -> discarded
        let word = 4 << 22;
        let ops = lift(word);
        assert!(ops.is_empty());
    }

    #[test]
    fn lift_ld() {
        // ld [%o0 + 4], %o1 : op=3 op3=0x00 rd=9 rs1=8 simm=4
        let word = (3 << 30) | (9 << 25) | (8 << 14) | (1 << 13) | 4;
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntAdd)); // ea
        assert!(ops.iter().any(|o| o.opcode == OpCode::Load));
    }

    #[test]
    fn lift_ldub_zero_extends() {
        // ldub [%o0], %o1 : op=3 op3=0x01
        let word = (3 << 30) | (9 << 25) | (0x01 << 19) | (8 << 14);
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntZExt));
    }

    #[test]
    fn lift_st() {
        // st %o1, [%o0] : op=3 op3=0x04 rd=9(src) rs1=8
        let word = (3 << 30) | (9 << 25) | (0x04 << 19) | (8 << 14);
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Store));
    }

    #[test]
    fn lift_call() {
        // call +0x40 : op=1 disp30=0x10  -> target = 0x1000 + 0x40
        let word = (1 << 30) | 0x10;
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Copy && o.output.map(|v| v.offset == O7_INDEX as u64 * 4).unwrap_or(false)));
        let call = ops.iter().find(|o| o.opcode == OpCode::Call).unwrap();
        assert_eq!(call.inputs[0].offset, 0x1040);
    }

    #[test]
    fn lift_ba() {
        // ba +8 : op=0 op2=2 cond=8 disp22=2
        let word = (8 << 25) | (2 << 22) | 2;
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::Branch);
        assert_eq!(ops[0].inputs[0].offset, 0x1008);
    }

    #[test]
    fn lift_be_conditional() {
        // be +8 : op=0 op2=2 cond=1(BE) disp22=2
        let word = (1 << 25) | (2 << 22) | 2;
        let ops = lift(word);
        let cbr = ops.iter().find(|o| o.opcode == OpCode::CBranch).unwrap();
        assert_eq!(cbr.inputs[0].offset, 0x1008);
        assert_eq!(cbr.inputs[1].offset, ICC_Z);
    }

    #[test]
    fn lift_jmpl_ret() {
        // ret = jmpl %i7 + 8, %g0 : op=2 op3=0x38 rd=0 rs1=31 simm=8
        let ops = lift(f3i(0x38, 0, I7_INDEX, 8));
        assert_eq!(ops.last().unwrap().opcode, OpCode::Return);
    }

    #[test]
    fn lift_jmpl_indirect_call() {
        // jmpl %o0, %o7 : op=2 op3=0x38 rd=15(o7) rs1=8
        let ops = lift(f3(0x38, O7_INDEX, 8, 0));
        assert!(ops.iter().any(|o| o.opcode == OpCode::CallInd));
    }

    // ---- Delay slots (Stage 1: non-annulling) ----

    #[test]
    fn delay_slot_call_defers_transfer() {
        // call +0x40 (delay slot: add %o0,1,%o0)
        let call = (1 << 30) | 0x10;
        let add = f3i(0x00, 8, 8, 1);
        let (a, b) = lift_ctx_two(call, add);
        // The branch instruction keeps the %o7 link write but NOT the Call.
        assert!(!a.iter().any(|o| o.opcode == OpCode::Call));
        assert!(a.iter().any(|o| o.opcode == OpCode::Copy && o.output.map(|v| v.offset == O7_INDEX as u64 * 4).unwrap_or(false)));
        // The delay slot runs its own add, then the deferred Call last.
        assert!(b.iter().any(|o| o.opcode == OpCode::IntAdd));
        assert_eq!(b.last().unwrap().opcode, OpCode::Call);
        assert_eq!(b.last().unwrap().inputs[0].offset, 0x1040);
    }

    #[test]
    fn delay_slot_jmpl_ret_defers_return() {
        // ret = jmpl %i7+8,%g0 ; delay slot: restore (modelled as add)
        let ret = f3i(0x38, 0, I7_INDEX, 8);
        let restore = f3(0x3D, 8, 8, 9); // restore %o0,%o1,%o0 (pointer add)
        let (a, b) = lift_ctx_two(ret, restore);
        // Target is computed at the branch; Return is deferred.
        assert!(!a.iter().any(|o| o.opcode == OpCode::Return));
        assert!(a.iter().any(|o| o.opcode == OpCode::IntAdd)); // target = i7 + 8
        assert_eq!(b.last().unwrap().opcode, OpCode::Return);
    }

    #[test]
    fn delay_slot_bicc_defers_cbranch() {
        // be +8 ; delay slot: add
        let be = (1 << 25) | (2 << 22) | 2;
        let add = f3i(0x00, 8, 8, 1);
        let (a, b) = lift_ctx_two(be, add);
        assert!(!a.iter().any(|o| o.opcode == OpCode::CBranch));
        // The condition (Z flag) is snapshotted into a temp at the branch...
        let snap = a.iter().find(|o| o.opcode == OpCode::Copy && o.output.map(|v| v.space == CoreSpace::UNIQUE).unwrap_or(false)).unwrap();
        assert_eq!(snap.inputs[0].offset, ICC_Z);
        let snap_vn = snap.output.unwrap();
        // delay slot's add runs, then the conditional branch last...
        assert!(b.iter().any(|o| o.opcode == OpCode::IntAdd));
        let cbr = b.last().unwrap();
        assert_eq!(cbr.opcode, OpCode::CBranch);
        assert_eq!(cbr.inputs[0].offset, 0x1008);
        // ...reading the pre-delay-slot snapshot, not the live flag.
        assert_eq!(cbr.inputs[1].space, CoreSpace::UNIQUE);
        assert_eq!(cbr.inputs[1].offset, snap_vn.offset);
    }

    #[test]
    fn delay_slot_stale_pending_dropped() {
        // A pending transfer for a different address must not be applied.
        let lifter = SparcLifter::new_32();
        let mem = make_memory(f3i(0x00, 8, 8, 1), 0x2000); // a plain add
        let mut ctx = LiftContext {
            it: None,
            delay: Some(DelaySlot {
                op: PcodeOp {
                    opcode: OpCode::Return,
                    seq: SeqNum::new(Address::new(RAM_SPACE, 0x1004), 0),
                    output: None,
                    inputs: SmallVec::from_slice(&[reg(I7_INDEX)]),
                },
                addr: 0x1004,
                annul: false,
            }),
        };
        let ops = lifter.lift_instruction_ctx(&mem, 0x2000, &mut ctx).unwrap().ops;
        // The stale Return is not appended; only the add's own op is present.
        assert!(!ops.iter().any(|o| o.opcode == OpCode::Return));
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
    }

    #[test]
    fn delay_slot_only_in_ctx_path() {
        // The stateless lift still emits the transfer inline (no delay slot).
        let call = (1 << 30) | 0x10;
        let ops = lift(call);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Call));
    }

    #[test]
    fn delay_slot_annulling_predicates_slot() {
        // be,a +8 ; delay slot: add %o0,1,%o0 (executes only if taken)
        let bea = (1 << 29) | (1 << 25) | (2 << 22) | 2;
        let add = f3i(0x00, 8, 8, 1);
        let (a, b) = lift_ctx_two(bea, add);
        // Condition snapshotted at the branch; CBranch deferred.
        assert!(!a.iter().any(|o| o.opcode == OpCode::CBranch));
        // Delay slot's write is predicated (mask + select) then the branch.
        assert!(b.iter().any(|o| o.opcode == OpCode::Int2Comp));
        assert!(b.iter().any(|o| o.opcode == OpCode::IntOr && o.output.map(|v| v.offset == 8 * 4).unwrap_or(false)));
        assert_eq!(b.last().unwrap().opcode, OpCode::CBranch);
        assert_eq!(b.last().unwrap().inputs[0].offset, 0x1008);
    }

    #[test]
    fn delay_slot_ba_annul_stays_inline() {
        // ba,a +8 : annulled delay slot -> branch stays inline, slot skipped.
        let baa = (1 << 29) | (8 << 25) | (2 << 22) | 2;
        let add = f3i(0x00, 8, 8, 1);
        let (a, b) = lift_ctx_two(baa, add);
        assert_eq!(a.last().unwrap().opcode, OpCode::Branch);
        // No transfer is appended to the following instruction.
        assert!(!b.iter().any(|o| matches!(o.opcode, OpCode::Branch | OpCode::CBranch)));
    }

    #[test]
    fn bn_annul_skips_delay_slot() {
        // bn,a +8 : delay slot squashed -> modelled as a jump to A+8.
        // (cond field = 0 = BN)
        let bna = (1 << 29) | (2 << 22) | 2;
        let add = f3i(0x00, 8, 8, 1);
        let (a, _b) = lift_ctx_two(bna, add);
        let br = a.last().unwrap();
        assert_eq!(br.opcode, OpCode::Branch);
        assert_eq!(br.inputs[0].offset, 0x1008); // 0x1000 + 8, over the slot
    }

    #[test]
    fn delay_slot_annulling_guards_store() {
        // be,a +8 ; delay slot: st %o1, [%o0]  (store only commits if taken)
        let bea = (1 << 29) | (1 << 25) | (2 << 22) | 2;
        let st = (3 << 30) | (9 << 25) | (0x04 << 19) | (8 << 14);
        let (_a, b) = lift_ctx_two(bea, st);
        // The store is guarded: load current, select, store; plus the branch.
        assert!(b.iter().any(|o| o.opcode == OpCode::Load));   // read-back of *ea
        assert!(b.iter().any(|o| o.opcode == OpCode::Int2Comp)); // select mask
        assert!(b.iter().any(|o| o.opcode == OpCode::Store));
        assert_eq!(b.last().unwrap().opcode, OpCode::CBranch);
        // The store now writes the selected value (a unique), not %o1 directly.
        let store = b.iter().find(|o| o.opcode == OpCode::Store).unwrap();
        assert_eq!(store.inputs[2].space, CoreSpace::UNIQUE);
    }
}
