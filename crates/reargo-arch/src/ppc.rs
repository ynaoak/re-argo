use reargo_core::address::{Endian, SpaceId};
use reargo_core::pcode::VarnodeData;
use reargo_loader::Memory;
use crate::arch::{
    Architecture, CallingConvention, DecodedInstruction, FlowType, RegisterInfo,
};
use crate::error::DisasmError;

const REGISTER_SPACE: SpaceId = SpaceId::REGISTER;
const RAM_SPACE: SpaceId = SpaceId::RAM;

fn ppc_registers(is_64: bool) -> Vec<RegisterInfo> {
    let sz = if is_64 { 8u32 } else { 4 };
    let mut regs = Vec::new();
    for i in 0..=31u64 {
        regs.push(RegisterInfo {
            name: format!("r{}", i),
            varnode: VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz),
            aliases: Vec::new(),
        });
    }
    regs.push(RegisterInfo {
        name: "lr".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 32 * sz as u64, sz),
        aliases: Vec::new(),
    });
    regs.push(RegisterInfo {
        name: "ctr".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 33 * sz as u64, sz),
        aliases: Vec::new(),
    });
    regs.push(RegisterInfo {
        name: "cr".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 34 * sz as u64, 4),
        aliases: Vec::new(),
    });
    regs
}

pub struct PpcArch {
    is_64: bool,
    registers: Vec<RegisterInfo>,
    calling_conventions: Vec<CallingConvention>,
    cs: crate::capstone_wrapper::SafeCapstone,
}

impl PpcArch {
    pub fn new(is_64: bool) -> Result<Self, DisasmError> {
        use capstone::prelude::*;
        let mode = if is_64 {
            arch::ppc::ArchMode::Mode64
        } else {
            arch::ppc::ArchMode::Mode32
        };
        let cs = Capstone::new()
            .ppc()
            .mode(mode)
            .endian(capstone::Endian::Big)
            .detail(true)
            .build()
            .map_err(|e| DisasmError::EngineError(format!("PPC capstone init: {}", e)))?;
        let sz = if is_64 { 8u32 } else { 4 };
        Ok(Self {
            is_64,
            registers: ppc_registers(is_64),
            calling_conventions: vec![CallingConvention {
                name: "SysV PPC".to_string(),
                param_registers: (3..=10)
                    .map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz))
                    .collect(),
                return_register: Some(VarnodeData::new(REGISTER_SPACE, 3 * sz as u64, sz)),
                callee_saved: (14..=31)
                    .map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz))
                    .collect(),
                stack_pointer: VarnodeData::new(REGISTER_SPACE, sz as u64, sz),
            }],
            cs: crate::capstone_wrapper::SafeCapstone::new(cs),
        })
    }
}

impl Architecture for PpcArch {
    fn name(&self) -> &str { if self.is_64 { "PowerPC64" } else { "PowerPC" } }
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
        let insns = self.cs.disasm_count(&buf, address, 1)?;
        let insn = insns.iter().next().ok_or(DisasmError::DecodeError { address, reason: "no instruction".into() })?;
        let mn = insn.mnemonic().unwrap_or("???").to_string();
        let ops = insn.op_str().unwrap_or("").to_string();
        let flow = match mn.as_str() {
            "b" | "ba" => FlowType::UnconditionalJump,
            "bl" | "bla" => FlowType::Call,
            "blr" => FlowType::Return,
            "bctr" => FlowType::IndirectJump,
            "bctrl" => FlowType::IndirectCall,
            s if s.starts_with("b") && (s.contains("eq") || s.contains("ne") || s.contains("lt") || s.contains("gt")) => FlowType::ConditionalJump,
            _ => FlowType::Fall,
        };
        Ok(DecodedInstruction {
            address, length: 4, mnemonic: mn, operands: ops,
            bytes: insn.bytes().into(), flow_type: flow, branch_target: None,
        })
    }
    fn calling_conventions(&self) -> &[CallingConvention] { &self.calling_conventions }
    fn default_calling_convention(&self) -> Option<&CallingConvention> { self.calling_conventions.first() }
    fn stack_pointer(&self) -> Option<&RegisterInfo> { self.register_by_name("r1") }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ppc32_registers() {
        let arch = PpcArch::new(false).unwrap();
        assert_eq!(arch.bits(), 32);
        let r1 = arch.register_by_name("r1").unwrap();
        assert_eq!(r1.varnode.size, 4);
    }
}
