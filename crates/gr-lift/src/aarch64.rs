use gr_core::address::{Address, SpaceId};
use gr_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use gr_loader::Memory;
use smallvec::SmallVec;

use crate::lift::{LiftError, LiftedInstruction, PcodeLift};

const CONST_SPACE: SpaceId = SpaceId::CONST;
const RAM_SPACE: SpaceId = SpaceId::RAM;
const REG_SPACE: SpaceId = SpaceId::REGISTER;
const UNIQUE_SPACE: SpaceId = SpaceId::UNIQUE;

const NZCV_OFFSET: u64 = 0x200;

fn xreg(n: u32) -> VarnodeData {
    VarnodeData::new(REG_SPACE, n as u64 * 8, 8)
}

fn wreg(n: u32) -> VarnodeData {
    VarnodeData::new(REG_SPACE, n as u64 * 8, 4)
}

fn sp() -> VarnodeData {
    VarnodeData::new(REG_SPACE, 31 * 8, 8)
}

fn constant(value: u64, size: u32) -> VarnodeData {
    VarnodeData::new(CONST_SPACE, value, size)
}

fn unique(offset: u64, size: u32) -> VarnodeData {
    VarnodeData::new(UNIQUE_SPACE, offset, size)
}

fn nzcv() -> VarnodeData {
    VarnodeData::new(REG_SPACE, NZCV_OFFSET, 4)
}

pub struct Aarch64Lifter {
    cs: capstone::Capstone,
}

unsafe impl Send for Aarch64Lifter {}
unsafe impl Sync for Aarch64Lifter {}

impl Aarch64Lifter {
    pub fn new() -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("failed to create AArch64 capstone");
        Self { cs }
    }

    fn parse_reg(&self, reg_name: &str) -> Option<VarnodeData> {
        let name = reg_name.to_lowercase();
        if name == "sp" || name == "wsp" {
            return Some(sp());
        }
        if name == "xzr" || name == "wzr" {
            return Some(constant(0, if name.starts_with('x') { 8 } else { 4 }));
        }
        if let Some(num_str) = name.strip_prefix('x')
            && let Ok(n) = num_str.parse::<u32>()
            && n <= 30 {
                return Some(xreg(n));
            }
        if let Some(num_str) = name.strip_prefix('w')
            && let Ok(n) = num_str.parse::<u32>()
            && n <= 30 {
                return Some(wreg(n));
            }
        None
    }

    fn lift_insn(
        &self,
        mnemonic: &str,
        operands: &str,
        address: u64,
    ) -> Result<Vec<PcodeOp>, LiftError> {
        let mn = mnemonic.to_lowercase();
        let seq = |order: u32| SeqNum::new(Address::new(RAM_SPACE, address), order);
        let mut ops = Vec::new();
        let mut seq_n: u32 = 0;

        let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();

        match mn.as_str() {
            "nop" => {}

            "ret" => {
                let lr = xreg(30);
                ops.push(PcodeOp {
                    opcode: OpCode::Return,
                    seq: seq(seq_n),
                    output: None,
                    inputs: SmallVec::from_slice(&[lr]),
                });
            }

            "mov" => {
                let dst = self.parse_operand(&parts, 0)?;
                let src = self.parse_operand(&parts, 1)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            "movz" | "movk" => {
                let dst = self.parse_operand(&parts, 0)?;
                let imm = self.parse_operand(&parts, 1)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[imm]),
                });
            }

            "add" | "sub" | "adds" | "subs" => {
                let opcode = if mn.starts_with("add") { OpCode::IntAdd } else { OpCode::IntSub };
                let dst = self.parse_operand(&parts, 0)?;
                let a = self.parse_operand(&parts, 1)?;
                let b = self.parse_operand(&parts, 2)?;
                ops.push(PcodeOp {
                    opcode,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
                if mn.ends_with('s') {
                    seq_n += 1;
                    ops.push(PcodeOp {
                        opcode: OpCode::IntEqual,
                        seq: seq(seq_n),
                        output: Some(nzcv()),
                        inputs: SmallVec::from_slice(&[dst, constant(0, dst.size)]),
                    });
                }
            }

            "and" | "orr" | "eor" | "ands" => {
                let opcode = match mn.as_str() {
                    "and" | "ands" => OpCode::IntAnd,
                    "orr" => OpCode::IntOr,
                    "eor" => OpCode::IntXor,
                    _ => unreachable!(),
                };
                let dst = self.parse_operand(&parts, 0)?;
                let a = self.parse_operand(&parts, 1)?;
                let b = self.parse_operand(&parts, 2)?;
                ops.push(PcodeOp {
                    opcode,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
            }

            "lsl" | "lsr" | "asr" => {
                let opcode = match mn.as_str() {
                    "lsl" => OpCode::IntLeft,
                    "lsr" => OpCode::IntRight,
                    "asr" => OpCode::IntSRight,
                    _ => unreachable!(),
                };
                let dst = self.parse_operand(&parts, 0)?;
                let a = self.parse_operand(&parts, 1)?;
                let b = self.parse_operand(&parts, 2)?;
                ops.push(PcodeOp {
                    opcode,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
            }

            "mul" | "madd" => {
                let dst = self.parse_operand(&parts, 0)?;
                let a = self.parse_operand(&parts, 1)?;
                let b = self.parse_operand(&parts, 2)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntMult,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
            }

            "neg" => {
                let dst = self.parse_operand(&parts, 0)?;
                let src = self.parse_operand(&parts, 1)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Int2Comp,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            "mvn" => {
                let dst = self.parse_operand(&parts, 0)?;
                let src = self.parse_operand(&parts, 1)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntNegate,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            "cmp" | "cmn" => {
                let a = self.parse_operand(&parts, 0)?;
                let b = self.parse_operand(&parts, 1)?;
                let opcode = if mn == "cmp" { OpCode::IntSub } else { OpCode::IntAdd };
                let tmp = unique(seq_n as u64 * 0x10, a.size);
                ops.push(PcodeOp {
                    opcode,
                    seq: seq(seq_n),
                    output: Some(tmp),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
                seq_n += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntEqual,
                    seq: seq(seq_n),
                    output: Some(nzcv()),
                    inputs: SmallVec::from_slice(&[tmp, constant(0, tmp.size)]),
                });
            }

            "tst" => {
                let a = self.parse_operand(&parts, 0)?;
                let b = self.parse_operand(&parts, 1)?;
                let tmp = unique(seq_n as u64 * 0x10, a.size);
                ops.push(PcodeOp {
                    opcode: OpCode::IntAnd,
                    seq: seq(seq_n),
                    output: Some(tmp),
                    inputs: SmallVec::from_slice(&[a, b]),
                });
                seq_n += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::IntEqual,
                    seq: seq(seq_n),
                    output: Some(nzcv()),
                    inputs: SmallVec::from_slice(&[tmp, constant(0, tmp.size)]),
                });
            }

            "ldr" => {
                let dst = self.parse_operand(&parts, 0)?;
                let addr_vn = self.parse_mem_operand(operands)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Load,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr_vn]),
                });
            }

            "ldp" => {
                let rt1 = self.parse_operand(&parts, 0)?;
                let rt2 = self.parse_operand(&parts, 1)?;
                let base_addr = self.parse_mem_operand(operands)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Load,
                    seq: seq(seq_n),
                    output: Some(rt1),
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), base_addr]),
                });
                seq_n += 1;
                let addr2 = unique(seq_n as u64 * 0x10, 8);
                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq: seq(seq_n),
                    output: Some(addr2),
                    inputs: SmallVec::from_slice(&[base_addr, constant(rt1.size as u64, 8)]),
                });
                seq_n += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::Load,
                    seq: seq(seq_n),
                    output: Some(rt2),
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr2]),
                });
            }

            "str" => {
                let src = self.parse_operand(&parts, 0)?;
                let addr_vn = self.parse_mem_operand(operands)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Store,
                    seq: seq(seq_n),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr_vn, src]),
                });
            }

            "stp" => {
                let rt1 = self.parse_operand(&parts, 0)?;
                let rt2 = self.parse_operand(&parts, 1)?;
                let base_addr = self.parse_mem_operand(operands)?;

                let has_pre_index = operands.contains("]!");
                if has_pre_index
                    && let Some(offset) = self.extract_bracket_offset(operands) {
                        ops.push(PcodeOp {
                            opcode: OpCode::IntAdd,
                            seq: seq(seq_n),
                            output: Some(sp()),
                            inputs: SmallVec::from_slice(&[sp(), constant(offset as u64, 8)]),
                        });
                        seq_n += 1;
                    }

                ops.push(PcodeOp {
                    opcode: OpCode::Store,
                    seq: seq(seq_n),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), base_addr, rt1]),
                });
                seq_n += 1;
                let addr2 = unique(seq_n as u64 * 0x10, 8);
                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq: seq(seq_n),
                    output: Some(addr2),
                    inputs: SmallVec::from_slice(&[base_addr, constant(rt1.size as u64, 8)]),
                });
                seq_n += 1;
                ops.push(PcodeOp {
                    opcode: OpCode::Store,
                    seq: seq(seq_n),
                    output: None,
                    inputs: SmallVec::from_slice(&[constant(RAM_SPACE.0 as u64, 4), addr2, rt2]),
                });
            }

            "b" => {
                if let Some(target) = parse_branch_target(operands) {
                    ops.push(PcodeOp {
                        opcode: OpCode::Branch,
                        seq: seq(seq_n),
                        output: None,
                        inputs: SmallVec::from_slice(&[VarnodeData::new(RAM_SPACE, target, 8)]),
                    });
                }
            }

            "bl" | "blr" => {
                let target = if mn == "blr" {
                    self.parse_operand(&parts, 0)?
                } else {
                    let target_addr = parse_branch_target(operands)
                        .ok_or_else(|| LiftError::DecodeFailed { address, reason: "no branch target".into() })?;
                    VarnodeData::new(RAM_SPACE, target_addr, 8)
                };
                ops.push(PcodeOp {
                    opcode: OpCode::Call,
                    seq: seq(seq_n),
                    output: None,
                    inputs: SmallVec::from_slice(&[target]),
                });
            }

            s if s.starts_with("b.") || s == "cbz" || s == "cbnz" => {
                let cond_vn = if s == "cbz" || s == "cbnz" {
                    let reg = self.parse_operand(&parts, 0)?;
                    let tmp = unique(seq_n as u64 * 0x10 + 0x100, 1);
                    let opcode = if s == "cbz" { OpCode::IntEqual } else { OpCode::IntNotEqual };
                    ops.push(PcodeOp {
                        opcode,
                        seq: seq(seq_n),
                        output: Some(tmp),
                        inputs: SmallVec::from_slice(&[reg, constant(0, reg.size)]),
                    });
                    seq_n += 1;
                    tmp
                } else {
                    nzcv()
                };

                let target_str = parts.last()
                    .ok_or_else(|| LiftError::DecodeFailed { address, reason: "no branch target".into() })?;
                if let Some(target) = parse_imm(target_str) {
                    let target_vn = VarnodeData::new(RAM_SPACE, target, 8);
                    ops.push(PcodeOp {
                        opcode: OpCode::CBranch,
                        seq: seq(seq_n),
                        output: None,
                        inputs: SmallVec::from_slice(&[target_vn, cond_vn]),
                    });
                }
            }

            "adrp" | "adr" => {
                let dst = self.parse_operand(&parts, 0)?;
                let imm = self.parse_operand(&parts, 1)?;
                ops.push(PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[imm]),
                });
            }

            "sxtw" => {
                let dst = self.parse_operand(&parts, 0)?;
                let src = self.parse_operand(&parts, 1)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntSExt,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            "uxtw" | "uxtb" | "uxth" => {
                let dst = self.parse_operand(&parts, 0)?;
                let src = self.parse_operand(&parts, 1)?;
                ops.push(PcodeOp {
                    opcode: OpCode::IntZExt,
                    seq: seq(seq_n),
                    output: Some(dst),
                    inputs: SmallVec::from_slice(&[src]),
                });
            }

            _ => {
                return Err(LiftError::Unsupported { address, mnemonic: mnemonic.to_string() });
            }
        }

        let _ = seq_n;
        Ok(ops)
    }

    fn parse_operand(&self, parts: &[&str], idx: usize) -> Result<VarnodeData, LiftError> {
        let s = parts.get(idx).unwrap_or(&"").trim();
        let s = s.trim_start_matches('[').trim_end_matches(']').trim_end_matches('!');
        if let Some(vn) = self.parse_reg(s) {
            return Ok(vn);
        }
        if let Some(val) = parse_imm(s) {
            return Ok(constant(val, 8));
        }
        Ok(constant(0, 8))
    }

    fn parse_mem_operand(&self, operands: &str) -> Result<VarnodeData, LiftError> {
        if let Some(start) = operands.find('[') {
            let inner = &operands[start + 1..];
            if let Some(end) = inner.find(']') {
                let bracket = &inner[..end];
                let mem_parts: Vec<&str> = bracket.split(',').map(|s| s.trim()).collect();
                let base = self.parse_reg(mem_parts[0]).unwrap_or(sp());
                if mem_parts.len() > 1
                    && let Some(offset) = parse_imm(mem_parts[1]) {
                        return Ok(VarnodeData::new(UNIQUE_SPACE, base.offset + offset, 8));
                    }
                return Ok(base);
            }
        }
        Ok(sp())
    }

    fn extract_bracket_offset(&self, operands: &str) -> Option<i64> {
        if let Some(start) = operands.find('[') {
            let inner = &operands[start + 1..];
            if let Some(end) = inner.find(']') {
                let bracket = &inner[..end];
                let parts: Vec<&str> = bracket.split(',').map(|s| s.trim()).collect();
                if parts.len() > 1 {
                    let s = parts[1].trim_start_matches('#');
                    if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
                        return i64::from_str_radix(hex, 16).ok().map(|v| -v);
                    }
                    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        return i64::from_str_radix(hex, 16).ok();
                    }
                    return s.parse::<i64>().ok();
                }
            }
        }
        None
    }
}

impl Default for Aarch64Lifter {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_imm(s: &str) -> Option<u64> {
    let s = s.trim().trim_start_matches('#');
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn parse_branch_target(operands: &str) -> Option<u64> {
    let s = operands.split(',').next_back()?.trim().trim_start_matches('#');
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

impl PcodeLift for Aarch64Lifter {
    fn lift_instruction(
        &self,
        memory: &Memory,
        address: u64,
    ) -> Result<LiftedInstruction, LiftError> {
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

        let insn = insns.iter().next().ok_or_else(|| LiftError::DecodeFailed {
            address,
            reason: "no instruction decoded".into(),
        })?;

        let mnemonic = insn.mnemonic().unwrap_or("???");
        let operands = insn.op_str().unwrap_or("");
        let length = insn.bytes().len() as u32;

        let ops = self.lift_insn(mnemonic, operands, address)?;

        let mut fmt = String::new();
        fmt.push_str(mnemonic);
        if !operands.is_empty() {
            fmt.push(' ');
            fmt.push_str(operands);
        }

        Ok(LiftedInstruction {
            address,
            length,
            mnemonic: fmt,
            ops,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gr_core::address::{Endian, SpaceId as CoreSpaceId};
    use gr_loader::memory::{Memory as LoaderMemory, MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn make_memory(data: &[u8], addr: u64) -> LoaderMemory {
        let mut mem = LoaderMemory::new(CoreSpaceId(1), Endian::Little);
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
        // NOP = 0xD503201F
        let mem = make_memory(&[0x1f, 0x20, 0x03, 0xd5], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.mnemonic.contains("nop"));
        assert!(lifted.ops.is_empty());
        assert_eq!(lifted.length, 4);
    }

    #[test]
    fn lift_ret() {
        let lifter = Aarch64Lifter::new();
        // RET = 0xD65F03C0
        let mem = make_memory(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.mnemonic.contains("ret"));
        assert_eq!(lifted.ops.len(), 1);
        assert_eq!(lifted.ops[0].opcode, OpCode::Return);
    }

    #[test]
    fn lift_mov_reg() {
        let lifter = Aarch64Lifter::new();
        // MOV X0, X1 = 0xAA0103E0
        let mem = make_memory(&[0xe0, 0x03, 0x01, 0xaa], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.mnemonic.contains("mov"));
        assert!(!lifted.ops.is_empty());
    }

    #[test]
    fn lift_add() {
        let lifter = Aarch64Lifter::new();
        // ADD X0, X1, X2 = 0x8B020020
        let mem = make_memory(&[0x20, 0x00, 0x02, 0x8b], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.mnemonic.contains("add"));
        assert!(!lifted.ops.is_empty());
        assert_eq!(lifted.ops[0].opcode, OpCode::IntAdd);
    }

    #[test]
    fn lift_sub() {
        let lifter = Aarch64Lifter::new();
        // SUB X0, X1, X2 = 0xCB020020
        let mem = make_memory(&[0x20, 0x00, 0x02, 0xcb], 0x1000);
        let lifted = lifter.lift_instruction(&mem, 0x1000).unwrap();
        assert!(lifted.mnemonic.contains("sub"));
        assert!(!lifted.ops.is_empty());
        assert_eq!(lifted.ops[0].opcode, OpCode::IntSub);
    }

    #[test]
    fn lift_range_prologue() {
        let lifter = Aarch64Lifter::new();
        // STP X29, X30, [SP, #-16]!  = 0xA9BF7BFD
        // MOV X29, SP                 = 0x910003FD
        let code = [
            0xfd, 0x7b, 0xbf, 0xa9,  // stp x29, x30, [sp, #-16]!
            0xfd, 0x03, 0x00, 0x91,  // mov x29, sp
        ];
        let mem = make_memory(&code, 0x1000);
        let lifted = lifter.lift_range(&mem, 0x1000, 2).unwrap();
        assert_eq!(lifted.len(), 2);
    }
}
