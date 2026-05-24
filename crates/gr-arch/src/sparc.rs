use gr_core::address::{Endian, SpaceId};
use gr_core::pcode::VarnodeData;
use gr_loader::Memory;

use crate::arch::{
    Architecture, CallingConvention, DecodedInstruction, FlowType, RegisterInfo,
};
use crate::error::DisasmError;

const REGISTER_SPACE: SpaceId = SpaceId::REGISTER;
const RAM_SPACE: SpaceId = SpaceId::RAM;

pub struct SparcArch {
    is_64: bool,
    registers: Vec<RegisterInfo>,
    calling_conventions: Vec<CallingConvention>,
    cs: capstone::Capstone,
}

unsafe impl Send for SparcArch {}
unsafe impl Sync for SparcArch {}

impl SparcArch {
    pub fn new(is_64: bool) -> Self {
        use capstone::prelude::*;
        let mode = if is_64 {
            arch::sparc::ArchMode::V9
        } else {
            arch::sparc::ArchMode::Default
        };
        let cs = Capstone::new()
            .sparc()
            .mode(mode)
            .build()
            .expect("failed to create SPARC capstone");
        let sz = if is_64 { 8u32 } else { 4 };
        let mut registers = Vec::new();
        for i in 0..8u64 {
            registers.push(RegisterInfo {
                name: format!("g{}", i),
                varnode: VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz),
                aliases: Vec::new(),
            });
        }
        for i in 0..8u64 {
            registers.push(RegisterInfo {
                name: format!("o{}", i),
                varnode: VarnodeData::new(REGISTER_SPACE, (8 + i) * sz as u64, sz),
                aliases: if i == 6 { vec!["sp".into()] } else { Vec::new() },
            });
        }
        for i in 0..8u64 {
            registers.push(RegisterInfo {
                name: format!("l{}", i),
                varnode: VarnodeData::new(REGISTER_SPACE, (16 + i) * sz as u64, sz),
                aliases: Vec::new(),
            });
        }
        for i in 0..8u64 {
            registers.push(RegisterInfo {
                name: format!("i{}", i),
                varnode: VarnodeData::new(REGISTER_SPACE, (24 + i) * sz as u64, sz),
                aliases: if i == 6 { vec!["fp".into()] } else { Vec::new() },
            });
        }
        registers.push(RegisterInfo {
            name: "pc".into(),
            varnode: VarnodeData::new(REGISTER_SPACE, 32 * sz as u64, sz),
            aliases: Vec::new(),
        });
        Self {
            is_64,
            registers,
            calling_conventions: vec![CallingConvention {
                name: "SPARC".into(),
                param_registers: (0..6).map(|i: u64| VarnodeData::new(REGISTER_SPACE, (8 + i) * sz as u64, sz)).collect(),
                return_register: Some(VarnodeData::new(REGISTER_SPACE, 8 * sz as u64, sz)),
                callee_saved: (16..32).map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz)).collect(),
                stack_pointer: VarnodeData::new(REGISTER_SPACE, 14 * sz as u64, sz),
            }],
            cs,
        }
    }
}

impl Architecture for SparcArch {
    fn name(&self) -> &str { if self.is_64 { "SPARC V9" } else { "SPARC" } }
    fn bits(&self) -> u32 { if self.is_64 { 64 } else { 32 } }
    fn endian(&self) -> Endian { Endian::Big }
    fn register_space(&self) -> SpaceId { REGISTER_SPACE }
    fn default_space(&self) -> SpaceId { RAM_SPACE }
    fn registers(&self) -> &[RegisterInfo] { &self.registers }
    fn register_by_name(&self, name: &str) -> Option<&RegisterInfo> {
        
        self.registers.iter().find(|r| r.name.eq_ignore_ascii_case(name) || r.aliases.iter().any(|a| a.eq_ignore_ascii_case(name)))
    }
    fn decode_instruction(&self, memory: &Memory, address: u64) -> Result<DecodedInstruction, DisasmError> {
        let mut buf = vec![0u8; 4];
        memory.read_bytes(address, &mut buf).map_err(|_| DisasmError::UnreadableAddress(address))?;
        let insns = self.cs.disasm_count(&buf, address, 1)
            .map_err(|e| DisasmError::DecodeError { address, reason: e.to_string() })?;
        let insn = insns.iter().next().ok_or(DisasmError::DecodeError { address, reason: "no instruction".into() })?;
        let mn = insn.mnemonic().unwrap_or("???").to_string();
        let ops = insn.op_str().unwrap_or("").to_string();
        let flow = match mn.as_str() {
            "call" => FlowType::Call,
            "ret" | "retl" => FlowType::Return,
            "ba" | "b" | "bra" => FlowType::UnconditionalJump,
            s if s.starts_with("b") => FlowType::ConditionalJump,
            "jmp" | "jmpl" => FlowType::IndirectJump,
            _ => FlowType::Fall,
        };
        Ok(DecodedInstruction {
            address, length: 4, mnemonic: mn, operands: ops,
            bytes: insn.bytes().into(), flow_type: flow, branch_target: None,
        })
    }
    fn calling_conventions(&self) -> &[CallingConvention] { &self.calling_conventions }
    fn default_calling_convention(&self) -> Option<&CallingConvention> { self.calling_conventions.first() }
    fn stack_pointer(&self) -> Option<&RegisterInfo> { self.register_by_name("sp") }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparc32_registers() {
        let arch = SparcArch::new(false);
        assert_eq!(arch.bits(), 32);
        assert!(arch.register_by_name("sp").is_some());
        assert!(arch.register_by_name("g0").is_some());
    }
}
