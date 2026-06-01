//! PowerPC (32-bit) → P-code lifter.
//!
//! Decodes the common PPC32 D/X/I/B-form instructions directly into P-code:
//! integer arithmetic/logical (immediate and register), load/store, compares
//! (into a simplified CR0), and branches (b/bl/bc/blr/bctr). Capstone supplies
//! the disassembly text. PowerPC numbers bits MSB-first and is big-endian by
//! default; the configured endianness controls instruction-word reading.

use gr_core::address::{Address, Endian, SpaceId};
use gr_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use gr_loader::Memory;
use smallvec::SmallVec;

use crate::lift::{LiftError, LiftedInstruction, PcodeLift};

const CONST_SPACE: SpaceId = SpaceId::CONST;
const RAM_SPACE: SpaceId = SpaceId::RAM;
const REG_SPACE: SpaceId = SpaceId::REGISTER;
const UNIQUE_SPACE: SpaceId = SpaceId::UNIQUE;

const LR_OFFSET: u64 = 32 * 4;
const CTR_OFFSET: u64 = 33 * 4;

// Simplified CR0 condition bits (1 byte each).
const CR0_LT: u64 = 0x140;
const CR0_GT: u64 = 0x141;
const CR0_EQ: u64 = 0x142;

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

fn lr() -> VarnodeData {
    VarnodeData::new(REG_SPACE, LR_OFFSET, 4)
}

fn ctr() -> VarnodeData {
    VarnodeData::new(REG_SPACE, CTR_OFFSET, 4)
}

fn flag(off: u64) -> VarnodeData {
    VarnodeData::new(REG_SPACE, off, 1)
}

/// `ra` operand that reads as literal 0 when the field is r0 (PPC addressing).
fn ra_or_zero(ra: u32) -> VarnodeData {
    if ra == 0 {
        constant(0, 4)
    } else {
        reg(ra)
    }
}

pub struct PpcLifter {
    cs: capstone::Capstone,
    big_endian: bool,
}

unsafe impl Send for PpcLifter {}
unsafe impl Sync for PpcLifter {}

impl PpcLifter {
    pub fn new_32(endian: Endian) -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode32)
            .build()
            .expect("failed to create PPC capstone");
        Self {
            cs,
            big_endian: !matches!(endian, Endian::Little),
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

        let opcd = (word >> 26) & 0x3F;
        let rt = (word >> 21) & 0x1F; // also rs for stores / logical-imm
        let ra = (word >> 16) & 0x1F;
        let simm = ((word & 0xFFFF) as i16 as i64 as u64) & 0xFFFF_FFFF;
        let uimm = (word & 0xFFFF) as u64;

        let push = |ops: &mut Vec<PcodeOp>, s: &mut u32, op: OpCode, out: Option<VarnodeData>, ins: &[VarnodeData]| {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: out, inputs: SmallVec::from_slice(ins) });
            *s += 1;
        };

        match opcd {
            14 => {
                // addi rt, ra, simm  (li = addi rt, 0, simm)
                push(&mut ops, &mut s, OpCode::IntAdd, Some(reg(rt)), &[ra_or_zero(ra), constant(simm, 4)]);
            }
            15 => {
                // addis rt, ra, simm  (lis); value = ra + (simm << 16)
                let v = (((word & 0xFFFF) as u64) << 16) & 0xFFFF_FFFF;
                push(&mut ops, &mut s, OpCode::IntAdd, Some(reg(rt)), &[ra_or_zero(ra), constant(v, 4)]);
            }
            // ori ra, rs, uimm  (nop = ori 0,0,0); dest = ra, src = rt(=rs)
            24 if !(rt == 0 && ra == 0 && uimm == 0) => {
                push(&mut ops, &mut s, OpCode::IntOr, Some(reg(ra)), &[reg(rt), constant(uimm, 4)]);
            }
            25 => {
                let v = (uimm << 16) & 0xFFFF_FFFF;
                push(&mut ops, &mut s, OpCode::IntOr, Some(reg(ra)), &[reg(rt), constant(v, 4)]);
            }
            26 => push(&mut ops, &mut s, OpCode::IntXor, Some(reg(ra)), &[reg(rt), constant(uimm, 4)]),
            27 => {
                let v = (uimm << 16) & 0xFFFF_FFFF;
                push(&mut ops, &mut s, OpCode::IntXor, Some(reg(ra)), &[reg(rt), constant(v, 4)]);
            }
            28 => {
                // andi. -- the `.` is implicit in the mnemonic; the
                // instruction *always* records the result into CR0.
                // Previously the CR0 update was missing, so a following
                // `beq cr0` would branch on the previous compare.
                push(&mut ops, &mut s, OpCode::IntAnd, Some(reg(ra)), &[reg(rt), constant(uimm, 4)]);
                self.emit_cr0_record(reg(ra), &mut ops, &mut s, address);
            }
            29 => {
                // andis. -- same Rc=1 implicit semantics as andi.
                let v = (uimm << 16) & 0xFFFF_FFFF;
                push(&mut ops, &mut s, OpCode::IntAnd, Some(reg(ra)), &[reg(rt), constant(v, 4)]);
                self.emit_cr0_record(reg(ra), &mut ops, &mut s, address);
            }
            11 => self.emit_cmp(ra, constant(simm, 4), true, &mut ops, &mut s, address),  // cmpwi
            10 => self.emit_cmp(ra, constant(uimm, 4), false, &mut ops, &mut s, address), // cmplwi
            32 => self.emit_load(rt, ra, constant(simm, 4), 4, false, &mut ops, &mut s, address), // lwz
            34 => self.emit_load(rt, ra, constant(simm, 4), 1, false, &mut ops, &mut s, address), // lbz
            40 => self.emit_load(rt, ra, constant(simm, 4), 2, false, &mut ops, &mut s, address), // lhz
            36 => self.emit_store(rt, ra, constant(simm, 4), 4, &mut ops, &mut s, address), // stw
            38 => self.emit_store(rt, ra, constant(simm, 4), 1, &mut ops, &mut s, address), // stb
            44 => self.emit_store(rt, ra, constant(simm, 4), 2, &mut ops, &mut s, address), // sth
            33 => self.emit_load(rt, ra, constant(simm, 4), 4, false, &mut ops, &mut s, address), // lwzu (update not modelled)
            37 => self.emit_store(rt, ra, constant(simm, 4), 4, &mut ops, &mut s, address), // stwu
            18 => {
                // b / bl / ba / bla  (I-form)
                let aa = (word >> 1) & 1 == 1;
                let lk = word & 1 == 1;
                let d = (((word & 0x03FF_FFFC) << 6) as i32 >> 6) as i64;
                let target = if aa { (d as u64) & 0xFFFF_FFFF } else { address.wrapping_add(d as u64) & 0xFFFF_FFFF };
                if lk {
                    self.emit_link_lr(&mut ops, &mut s, address);
                    push(&mut ops, &mut s, OpCode::Call, None, &[ram(target)]);
                } else {
                    push(&mut ops, &mut s, OpCode::Branch, None, &[ram(target)]);
                }
            }
            16 => {
                // bc  (B-form conditional)
                let aa = (word >> 1) & 1 == 1;
                let lk = word & 1 == 1;
                let bo = (word >> 21) & 0x1F;
                let bi = (word >> 16) & 0x1F;
                let d = (((word & 0x0000_FFFC) << 16) as i32 >> 16) as i64;
                let target = if aa { (d as u64) & 0xFFFF_FFFF } else { address.wrapping_add(d as u64) & 0xFFFF_FFFF };
                // bcl always writes LR = PC + 4 (linkage happens regardless
                // of whether the branch is taken). Previously the lk bit
                // was ignored entirely, so `bcl` lifted as plain bc and
                // every later `blr` returned to a stale LR.
                if lk {
                    self.emit_link_lr(&mut ops, &mut s, address);
                }
                if let Some(cond) = self.emit_bc_condition(bo, bi, &mut ops, &mut s, address) {
                    push(&mut ops, &mut s, OpCode::CBranch, None, &[ram(target), cond]);
                } else {
                    // "branch always" form
                    push(&mut ops, &mut s, OpCode::Branch, None, &[ram(target)]);
                }
            }
            19 => {
                // bclr / bcctr
                let xo = (word >> 1) & 0x3FF;
                let lk = word & 1 == 1;
                match xo {
                    16 => {
                        // bclr (blr = return). blrl is bclr with LK=1 --
                        // we need to overwrite LR with PC+4 *after*
                        // capturing the old LR as the indirect target,
                        // otherwise the CallInd reads the freshly-linked
                        // value and loops back to PC+4.
                        if lk {
                            let saved = unique(0x780, 4);
                            ops.push(PcodeOp { opcode: OpCode::Copy, seq: seq(s), output: Some(saved), inputs: SmallVec::from_slice(&[lr()]) });
                            s += 1;
                            self.emit_link_lr(&mut ops, &mut s, address);
                            push(&mut ops, &mut s, OpCode::CallInd, None, &[saved]);
                        } else {
                            push(&mut ops, &mut s, OpCode::Return, None, &[lr()]);
                        }
                    }
                    528 => {
                        // bcctr (bctr / bctrl). bctrl links LR = PC+4
                        // before the indirect call.
                        if lk {
                            self.emit_link_lr(&mut ops, &mut s, address);
                            push(&mut ops, &mut s, OpCode::CallInd, None, &[ctr()]);
                        } else {
                            push(&mut ops, &mut s, OpCode::BranchInd, None, &[ctr()]);
                        }
                    }
                    _ => {}
                }
            }
            31 => self.lift_xform(word, address, &mut ops, &mut s),
            _ => {}
        }

        let _ = s;
        ops
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_load(&self, rt: u32, ra: u32, off: VarnodeData, size: u32, signed: bool, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let seq = |o: u32| SeqNum::new(Address::new(RAM_SPACE, address), o);
        let addr = unique(0x600, 4);
        ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(addr), inputs: SmallVec::from_slice(&[ra_or_zero(ra), off]) });
        *s += 1;
        if size == 4 {
            ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(reg(rt)), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
            *s += 1;
        } else {
            let loaded = unique(0x610, size);
            ops.push(PcodeOp { opcode: OpCode::Load, seq: seq(*s), output: Some(loaded), inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr]) });
            *s += 1;
            let ext = if signed { OpCode::IntSExt } else { OpCode::IntZExt };
            ops.push(PcodeOp { opcode: ext, seq: seq(*s), output: Some(reg(rt)), inputs: SmallVec::from_slice(&[loaded]) });
            *s += 1;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_store(&self, rs: u32, ra: u32, off: VarnodeData, size: u32, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let seq = |o: u32| SeqNum::new(Address::new(RAM_SPACE, address), o);
        let addr = unique(0x600, 4);
        ops.push(PcodeOp { opcode: OpCode::IntAdd, seq: seq(*s), output: Some(addr), inputs: SmallVec::from_slice(&[ra_or_zero(ra), off]) });
        *s += 1;
        let value = if size == 4 {
            reg(rs)
        } else {
            VarnodeData::new(REG_SPACE, rs as u64 * 4, size)
        };
        ops.push(PcodeOp { opcode: OpCode::Store, seq: seq(*s), output: None, inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr, value]) });
        *s += 1;
    }

    fn emit_cmp(&self, ra: u32, b: VarnodeData, signed: bool, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let seq = |o: u32| SeqNum::new(Address::new(RAM_SPACE, address), o);
        let a = reg(ra);
        let (lt_op, gt_op) = if signed {
            (OpCode::IntSLess, OpCode::IntSLess)
        } else {
            (OpCode::IntLess, OpCode::IntLess)
        };
        // LT = a < b ; GT = b < a ; EQ = a == b
        ops.push(PcodeOp { opcode: lt_op, seq: seq(*s), output: Some(flag(CR0_LT)), inputs: SmallVec::from_slice(&[a, b]) });
        *s += 1;
        ops.push(PcodeOp { opcode: gt_op, seq: seq(*s), output: Some(flag(CR0_GT)), inputs: SmallVec::from_slice(&[b, a]) });
        *s += 1;
        ops.push(PcodeOp { opcode: OpCode::IntEqual, seq: seq(*s), output: Some(flag(CR0_EQ)), inputs: SmallVec::from_slice(&[a, b]) });
        *s += 1;
    }

    /// Build the condition for a `bc` from BO/BI (CR0 only). Returns `None` for
    /// the unconditional ("branch always") form.
    fn emit_bc_condition(&self, bo: u32, bi: u32, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) -> Option<VarnodeData> {
        let seq = |o: u32| SeqNum::new(Address::new(RAM_SPACE, address), o);
        // BO=20 (0b10100) => branch always.
        if bo & 0x14 == 0x14 {
            return None;
        }
        // Only CR0 (BI < 4) is modelled.
        let crbit = bi & 0x3;
        let flagv = match crbit {
            0 => flag(CR0_LT),
            1 => flag(CR0_GT),
            2 => flag(CR0_EQ),
            _ => return None,
        };
        // BO bit 0x8 set => branch if true; clear => branch if false.
        if bo & 0x8 != 0 {
            Some(flagv)
        } else {
            let t = unique(0x760, 1);
            ops.push(PcodeOp { opcode: OpCode::BoolNegate, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[flagv]) });
            *s += 1;
            Some(t)
        }
    }

    fn lift_xform(&self, word: u32, address: u64, ops: &mut Vec<PcodeOp>, s: &mut u32) {
        let seq = |o: u32| SeqNum::new(Address::new(RAM_SPACE, address), o);
        let rt = (word >> 21) & 0x1F; // rt (arith dest) or rs (logical src)
        let ra = (word >> 16) & 0x1F;
        let rb = (word >> 11) & 0x1F;
        let xo = (word >> 1) & 0x3FF;
        // Rc (record condition) is bit 31 (LSB) of the instruction word.
        // When set, the result is reflected into CR0 -- without this every
        // `add.` / `or.` / `subf.` etc. left CR0 holding the previous
        // compare's bits and a following `beq cr0` branched on stale data.
        let rc = (word & 1) == 1;

        let push = |ops: &mut Vec<PcodeOp>, s: &mut u32, op: OpCode, out: VarnodeData, a: VarnodeData, b: VarnodeData| {
            ops.push(PcodeOp { opcode: op, seq: seq(*s), output: Some(out), inputs: SmallVec::from_slice(&[a, b]) });
            *s += 1;
        };

        // For ops whose Rc-record dest is `rt` (arithmetic dest).
        let record_rt = |this: &Self, ops: &mut Vec<PcodeOp>, s: &mut u32| {
            if rc {
                this.emit_cr0_record(reg(rt), ops, s, address);
            }
        };
        // For ops whose Rc-record dest is `ra` (logical dest).
        let record_ra = |this: &Self, ops: &mut Vec<PcodeOp>, s: &mut u32| {
            if rc {
                this.emit_cr0_record(reg(ra), ops, s, address);
            }
        };

        match xo {
            266 => { push(ops, s, OpCode::IntAdd, reg(rt), reg(ra), reg(rb)); record_rt(self, ops, s); }
            40 => { push(ops, s, OpCode::IntSub, reg(rt), reg(rb), reg(ra)); record_rt(self, ops, s); } // subf
            235 => { push(ops, s, OpCode::IntMult, reg(rt), reg(ra), reg(rb)); record_rt(self, ops, s); } // mullw
            491 => { push(ops, s, OpCode::IntSDiv, reg(rt), reg(ra), reg(rb)); record_rt(self, ops, s); } // divw
            459 => { push(ops, s, OpCode::IntDiv, reg(rt), reg(ra), reg(rb)); record_rt(self, ops, s); }  // divwu
            // logical X-form: dest = ra, sources rt(=rs) and rb
            28 => { push(ops, s, OpCode::IntAnd, reg(ra), reg(rt), reg(rb)); record_ra(self, ops, s); }
            444 => { push(ops, s, OpCode::IntOr, reg(ra), reg(rt), reg(rb)); record_ra(self, ops, s); } // or / mr
            316 => { push(ops, s, OpCode::IntXor, reg(ra), reg(rt), reg(rb)); record_ra(self, ops, s); }
            24 => { push(ops, s, OpCode::IntLeft, reg(ra), reg(rt), reg(rb)); record_ra(self, ops, s); }
            536 => { push(ops, s, OpCode::IntRight, reg(ra), reg(rt), reg(rb)); record_ra(self, ops, s); }
            792 => { push(ops, s, OpCode::IntSRight, reg(ra), reg(rt), reg(rb)); record_ra(self, ops, s); }
            124 => {
                // nor: ra = ~(rt | rb)
                let t = unique(0x720, 4);
                ops.push(PcodeOp { opcode: OpCode::IntOr, seq: seq(*s), output: Some(t), inputs: SmallVec::from_slice(&[reg(rt), reg(rb)]) });
                *s += 1;
                ops.push(PcodeOp { opcode: OpCode::IntNegate, seq: seq(*s), output: Some(reg(ra)), inputs: SmallVec::from_slice(&[t]) });
                *s += 1;
                record_ra(self, ops, s);
            }
            0 => self.emit_cmp(ra, reg(rb), true, ops, s, address),   // cmpw
            32 => self.emit_cmp(ra, reg(rb), false, ops, s, address), // cmplw
            339 => {
                // mfspr rt, spr
                let sprn = (((word >> 16) & 0x1F) << 5) | ((word >> 11) & 0x1F);
                let src = match sprn { 8 => Some(lr()), 9 => Some(ctr()), _ => None };
                if let Some(src) = src {
                    ops.push(PcodeOp { opcode: OpCode::Copy, seq: seq(*s), output: Some(reg(rt)), inputs: SmallVec::from_slice(&[src]) });
                    *s += 1;
                }
            }
            467 => {
                // mtspr spr, rs
                let sprn = (((word >> 16) & 0x1F) << 5) | ((word >> 11) & 0x1F);
                let dst = match sprn { 8 => Some(lr()), 9 => Some(ctr()), _ => None };
                if let Some(dst) = dst {
                    ops.push(PcodeOp { opcode: OpCode::Copy, seq: seq(*s), output: Some(dst), inputs: SmallVec::from_slice(&[reg(rt)]) });
                    *s += 1;
                }
            }
            _ => {}
        }
    }

    /// Write LR = PC + 4, used by every link-form branch.
    fn emit_link_lr(&self, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let seq = SeqNum::new(Address::new(RAM_SPACE, address), *s);
        ops.push(PcodeOp {
            opcode: OpCode::Copy,
            seq,
            output: Some(lr()),
            inputs: SmallVec::from_slice(&[constant((address + 4) & 0xFFFF_FFFF, 4)]),
        });
        *s += 1;
    }

    /// Reflect a 32-bit result into CR0 by recomputing LT/GT/EQ against 0.
    /// This is the Rc=1 / `andi.` / `andis.` semantics.
    fn emit_cr0_record(&self, result: VarnodeData, ops: &mut Vec<PcodeOp>, s: &mut u32, address: u64) {
        let seq = |o: u32| SeqNum::new(Address::new(RAM_SPACE, address), o);
        let zero = constant(0, result.size);
        ops.push(PcodeOp { opcode: OpCode::IntSLess, seq: seq(*s), output: Some(flag(CR0_LT)), inputs: SmallVec::from_slice(&[result, zero]) });
        *s += 1;
        ops.push(PcodeOp { opcode: OpCode::IntSLess, seq: seq(*s), output: Some(flag(CR0_GT)), inputs: SmallVec::from_slice(&[zero, result]) });
        *s += 1;
        ops.push(PcodeOp { opcode: OpCode::IntEqual, seq: seq(*s), output: Some(flag(CR0_EQ)), inputs: SmallVec::from_slice(&[result, zero]) });
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
                .unwrap_or_else(|| format!(".long 0x{:08x}", word)),
            Err(_) => format!(".long 0x{:08x}", word),
        }
    }
}

impl PcodeLift for PpcLifter {
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
        let lifter = PpcLifter::new_32(Endian::Big);
        let mem = make_memory(word, 0x1000);
        lifter.lift_instruction(&mem, 0x1000).unwrap().ops
    }

    #[test]
    fn lift_addi() {
        // addi r3, r4, 8 => opcd=14 rt=3 ra=4 simm=8
        let word = (14 << 26) | (3 << 21) | (4 << 16) | 8;
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
        assert_eq!(ops[0].output.unwrap().offset, 3 * 4);
        assert_eq!(ops[0].inputs[0].offset, 4 * 4);
        assert_eq!(ops[0].inputs[1].offset, 8);
    }

    #[test]
    fn lift_li() {
        // li r3, 5 = addi r3, 0, 5 => ra=0 reads as constant 0
        let word = (14 << 26) | (3 << 21) | 5;
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
        assert_eq!(ops[0].inputs[0].space, CoreSpace::CONST); // ra=0 -> const
        assert_eq!(ops[0].inputs[0].offset, 0);
    }

    #[test]
    fn lift_add_xform() {
        // add r3, r4, r5 => opcd=31 rt=3 ra=4 rb=5 xo=266
        let word = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (266 << 1);
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
        assert_eq!(ops[0].output.unwrap().offset, 3 * 4);
    }

    #[test]
    fn lift_or_dest_is_ra() {
        // or r3, r4, r5 => opcd=31 rs=4(rt field) ra=3 rb=5 xo=444
        // dest is ra (field bits 11-15) = 3, sources rt=4 and rb=5
        let word = (31 << 26) | (4 << 21) | (3 << 16) | (5 << 11) | (444 << 1);
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::IntOr);
        assert_eq!(ops[0].output.unwrap().offset, 3 * 4); // ra = dest
        assert_eq!(ops[0].inputs[0].offset, 4 * 4); // rs
        assert_eq!(ops[0].inputs[1].offset, 5 * 4); // rb
    }

    #[test]
    fn lift_subf() {
        // subf r3, r4, r5 => rt=3 ra=4 rb=5 xo=40 ; rt = rb - ra
        let word = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (40 << 1);
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::IntSub);
        assert_eq!(ops[0].inputs[0].offset, 5 * 4); // rb
        assert_eq!(ops[0].inputs[1].offset, 4 * 4); // ra
    }

    #[test]
    fn lift_lwz() {
        // lwz r3, 0(r4) => opcd=32 rt=3 ra=4 d=0
        let word = (32 << 26) | (3 << 21) | (4 << 16);
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Load));
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntAdd));
    }

    #[test]
    fn lift_stw() {
        // stw r3, 4(r1) => opcd=36 rs=3 ra=1 d=4
        let word = (36 << 26) | (3 << 21) | (1 << 16) | 4;
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.opcode == OpCode::Store));
    }

    #[test]
    fn lift_b_and_bl() {
        // b +0x100 => opcd=18, d=0x100, AA=0, LK=0
        let word = (18 << 26) | 0x100;
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::Branch);
        assert_eq!(ops[0].inputs[0].offset, 0x1100);

        // bl +0x100 => LK=1. bl now also writes LR = PC + 4 before
        // transferring control, so the Call is no longer the first op.
        let word_bl = (18 << 26) | 0x100 | 1;
        let ops_bl = lift(word_bl);
        let call = ops_bl.iter().find(|o| o.opcode == OpCode::Call)
            .expect("bl must emit a Call");
        assert_eq!(call.inputs[0].offset, 0x1100);
        let link = ops_bl.iter().find(|o| o.opcode == OpCode::Copy
            && o.output.map(|v| v.offset == LR_OFFSET).unwrap_or(false))
            .expect("bl must link LR = PC + 4");
        assert_eq!(link.inputs[0].offset, 0x1004);
    }

    #[test]
    fn lift_blr_is_return() {
        // blr => opcd=19 xo=16 BO=20 => 0x4E800020
        let word = 0x4E80_0020;
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::Return);
    }

    #[test]
    fn lift_bctr_indirect() {
        // bctr => opcd=19 xo=528 BO=20 => 0x4E800420
        let word = 0x4E80_0420;
        let ops = lift(word);
        assert_eq!(ops[0].opcode, OpCode::BranchInd);
        assert_eq!(ops[0].inputs[0].offset, CTR_OFFSET);
    }

    #[test]
    fn lift_cmpwi_sets_cr0() {
        // cmpwi r3, 0 => opcd=11 ra=3 (bf=0)
        let word = (11 << 26) | (3 << 16);
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.output.map(|v| v.offset == CR0_EQ).unwrap_or(false)));
    }

    #[test]
    fn lift_conditional_branch() {
        // beq cr0, +8 => bc 12, 2, +8 : opcd=16 BO=12 BI=2 d=8
        let word = (16 << 26) | (12 << 21) | (2 << 16) | 8;
        let ops = lift(word);
        let cbr = ops.iter().find(|o| o.opcode == OpCode::CBranch).unwrap();
        assert_eq!(cbr.inputs[0].offset, 0x1008);
        assert_eq!(cbr.inputs[1].offset, CR0_EQ);
    }

    #[test]
    fn lift_nop() {
        // nop = ori 0,0,0 => opcd=24 all-zero fields
        let word = 24 << 26;
        let ops = lift(word);
        assert!(ops.is_empty());
    }

    /// bctrl links LR = PC + 4 before the indirect call through CTR.
    /// Pre-fix the link was missing entirely, so any callee using `blr`
    /// after `bctrl` returned to the wrong address.
    #[test]
    fn lift_bctrl_links_lr() {
        let word = 0x4E80_0421u32; // bctrl
        let ops = lift(word);
        let link = ops.iter().find(|o| o.opcode == OpCode::Copy
            && o.output.map(|v| v.offset == LR_OFFSET).unwrap_or(false))
            .expect("bctrl must link LR");
        assert_eq!(link.inputs[0].offset, 0x1004);
        assert!(ops.iter().any(|o| o.opcode == OpCode::CallInd));
    }

    /// blrl (bclr with LK=1) must overwrite LR with PC + 4 *after*
    /// reading the old LR as the indirect target. Without saving the
    /// old LR first, the CallInd would jump to the freshly-linked PC+4.
    #[test]
    fn lift_blrl_saves_old_lr_before_link() {
        // blrl = bclr BO=20 LK=1 => 0x4E80_0021
        let word = 0x4E80_0021u32;
        let ops = lift(word);
        let link = ops.iter().find(|o| o.opcode == OpCode::Copy
            && o.output.map(|v| v.offset == LR_OFFSET).unwrap_or(false))
            .expect("blrl must link LR");
        let saved_copy = ops.iter().find(|o| o.opcode == OpCode::Copy
            && o.output.map(|v| v.space == CoreSpace::UNIQUE).unwrap_or(false)
            && o.inputs.first().map(|v| v.space == CoreSpace::REGISTER && v.offset == LR_OFFSET).unwrap_or(false))
            .expect("blrl must save old LR to a unique before overwriting it");
        // Saved-LR copy must come before the LR overwrite to avoid the
        // CallInd reading the freshly-linked value.
        let saved_pos = ops.iter().position(|o| std::ptr::eq(o, saved_copy)).unwrap();
        let link_pos = ops.iter().position(|o| std::ptr::eq(o, link)).unwrap();
        assert!(saved_pos < link_pos,
            "old-LR save must precede the new LR write: {:?}", ops);
        // CallInd reads the saved unique, not LR.
        let callind = ops.iter().find(|o| o.opcode == OpCode::CallInd)
            .expect("blrl must end with CallInd");
        assert_eq!(callind.inputs[0].space, CoreSpace::UNIQUE);
    }

    /// `andi.` always records its result into CR0. Pre-fix the CR0
    /// flags weren't touched, so `andi. r3, r4, mask; beq cr0, L`
    /// branched on whatever was in CR0 from a previous compare.
    #[test]
    fn lift_andi_updates_cr0() {
        // andi. r3, r4, 0xFF => opcd=28 rs=4 ra=3 uimm=0xFF
        let word = (28u32 << 26) | (4 << 21) | (3 << 16) | 0xFF;
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.output.map(|v| v.offset == CR0_LT).unwrap_or(false)));
        assert!(ops.iter().any(|o| o.output.map(|v| v.offset == CR0_GT).unwrap_or(false)));
        assert!(ops.iter().any(|o| o.output.map(|v| v.offset == CR0_EQ).unwrap_or(false)));
    }

    /// X-form ops with Rc=1 (e.g. `add.`) must record CR0. Pre-fix the
    /// Rc bit was ignored everywhere in the X-form decoder.
    #[test]
    fn lift_add_dot_updates_cr0() {
        // add. r3, r4, r5 => opcd=31 rt=3 ra=4 rb=5 xo=266 Rc=1
        let word = (31u32 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (266 << 1) | 1;
        let ops = lift(word);
        assert!(ops.iter().any(|o| o.opcode == OpCode::IntAdd));
        assert!(ops.iter().any(|o| o.output.map(|v| v.offset == CR0_EQ).unwrap_or(false)),
            "add. must record CR0_EQ: {:?}", ops);
    }

    /// X-form with Rc=0 must NOT update CR0 -- the pre-fix code would
    /// have always emitted the same op set regardless. Pin the behavior.
    #[test]
    fn lift_plain_add_does_not_update_cr0() {
        // add r3, r4, r5 (Rc=0)
        let word = (31u32 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (266 << 1);
        let ops = lift(word);
        assert!(!ops.iter().any(|o| o.output.map(|v| matches!(v.offset, CR0_LT | CR0_GT | CR0_EQ)).unwrap_or(false)),
            "plain add must not touch CR0: {:?}", ops);
    }
}
