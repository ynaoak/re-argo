use gr_core::address::{Endian, SpaceId};
use gr_core::pcode::VarnodeData;
use gr_loader::Memory;
use smallvec::SmallVec;

use crate::arch::{
    Architecture, CallingConvention, DecodedInstruction, FlowType, RegisterInfo,
};
use crate::error::DisasmError;

const REGISTER_SPACE: SpaceId = SpaceId::REGISTER;
const RAM_SPACE: SpaceId = SpaceId::RAM;

fn riscv_registers(is_64: bool) -> Vec<RegisterInfo> {
    let sz = if is_64 { 8u32 } else { 4 };
    let names = [
        "zero", "ra", "sp", "gp", "tp",
        "t0", "t1", "t2",
        "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
        "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
        "t3", "t4", "t5", "t6",
    ];
    let mut regs = Vec::new();
    for (i, name) in names.iter().enumerate() {
        regs.push(RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, (i as u64) * sz as u64, sz),
            aliases: vec![format!("x{}", i)],
        });
    }
    regs.push(RegisterInfo {
        name: "pc".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 32 * sz as u64, sz),
        aliases: Vec::new(),
    });
    regs
}

fn riscv_calling_convention(is_64: bool) -> Vec<CallingConvention> {
    let sz = if is_64 { 8u32 } else { 4 };
    vec![CallingConvention {
        name: "RISC-V ILP32/LP64".to_string(),
        param_registers: (10..=17)
            .map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz))
            .collect(),
        return_register: Some(VarnodeData::new(REGISTER_SPACE, 10 * sz as u64, sz)),
        callee_saved: (8..=9)
            .chain(18..=27)
            .map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz))
            .collect(),
        stack_pointer: VarnodeData::new(REGISTER_SPACE, 2 * sz as u64, sz),
    }]
}

pub struct RiscVArch {
    is_64: bool,
    registers: Vec<RegisterInfo>,
    calling_conventions: Vec<CallingConvention>,
    cs: crate::capstone_wrapper::SafeCapstone,
}

impl RiscVArch {
    pub fn new_rv32() -> Result<Self, DisasmError> {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .extra_mode(std::iter::once(arch::riscv::ArchExtraMode::RiscVC))
            .detail(true)
            .build()
            .map_err(|e| DisasmError::EngineError(format!("RISC-V 32 capstone init: {}", e)))?;
        Ok(Self {
            is_64: false,
            registers: riscv_registers(false),
            calling_conventions: riscv_calling_convention(false),
            cs: crate::capstone_wrapper::SafeCapstone::new(cs),
        })
    }

    pub fn new_rv64() -> Result<Self, DisasmError> {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .extra_mode(std::iter::once(arch::riscv::ArchExtraMode::RiscVC))
            .detail(true)
            .build()
            .map_err(|e| DisasmError::EngineError(format!("RISC-V 64 capstone init: {}", e)))?;
        Ok(Self {
            is_64: true,
            registers: riscv_registers(true),
            calling_conventions: riscv_calling_convention(true),
            cs: crate::capstone_wrapper::SafeCapstone::new(cs),
        })
    }
}

impl Architecture for RiscVArch {
    fn name(&self) -> &str {
        if self.is_64 { "RISC-V 64" } else { "RISC-V 32" }
    }

    fn bits(&self) -> u32 {
        if self.is_64 { 64 } else { 32 }
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn register_space(&self) -> SpaceId {
        REGISTER_SPACE
    }

    fn default_space(&self) -> SpaceId {
        RAM_SPACE
    }

    fn registers(&self) -> &[RegisterInfo] {
        &self.registers
    }

    fn register_by_name(&self, name: &str) -> Option<&RegisterInfo> {
        
        self.registers.iter().find(|r| {
            r.name.eq_ignore_ascii_case(name)
                || r.aliases.iter().any(|a| a.eq_ignore_ascii_case(name))
        })
    }

    fn decode_instruction(
        &self,
        memory: &Memory,
        address: u64,
    ) -> Result<DecodedInstruction, DisasmError> {
        let mut buf = vec![0u8; 4];
        memory
            .read_bytes(address, &mut buf)
            .map_err(|_| DisasmError::UnreadableAddress(address))?;

        let insns = self.cs.disasm_count(&buf, address, 1)?;

        let insn = insns.iter().next().ok_or_else(|| DisasmError::DecodeError {
            address,
            reason: "no instruction decoded".into(),
        })?;

        let mnemonic = insn.mnemonic().unwrap_or("???").to_string();
        let operands = insn.op_str().unwrap_or("").to_string();
        let bytes: SmallVec<[u8; 16]> = insn.bytes().into();
        let length = insn.bytes().len() as u32;

        let flow_type = classify_riscv_flow(&mnemonic, &operands);
        let branch_target = extract_riscv_target(&operands, &flow_type);

        Ok(DecodedInstruction {
            address,
            length,
            mnemonic,
            operands,
            bytes,
            flow_type,
            branch_target,
        })
    }

    fn calling_conventions(&self) -> &[CallingConvention] {
        &self.calling_conventions
    }

    fn default_calling_convention(&self) -> Option<&CallingConvention> {
        self.calling_conventions.first()
    }

    fn stack_pointer(&self) -> Option<&RegisterInfo> {
        self.register_by_name("sp")
    }
}

fn classify_riscv_flow(mnemonic: &str, operands: &str) -> FlowType {
    match mnemonic {
        "jal" => {
            if operands.starts_with("ra,") || operands.contains("ra") {
                FlowType::Call
            } else {
                FlowType::UnconditionalJump
            }
        }
        "jalr" => {
            if operands.contains("ra") && !operands.starts_with("zero") {
                FlowType::Call
            } else {
                FlowType::IndirectJump
            }
        }
        "j" => FlowType::UnconditionalJump,
        "jr" => {
            if operands.contains("ra") {
                FlowType::Return
            } else {
                FlowType::IndirectJump
            }
        }
        "ret" | "mret" | "sret" | "uret" => FlowType::Return,
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => FlowType::ConditionalJump,
        "call" => FlowType::Call,
        "tail" => FlowType::UnconditionalJump,
        "ecall" | "ebreak" => FlowType::Call,
        _ => FlowType::Fall,
    }
}

fn extract_riscv_target(operands: &str, flow: &FlowType) -> Option<u64> {
    match flow {
        FlowType::UnconditionalJump | FlowType::ConditionalJump | FlowType::Call => {
            let last = operands.split(',').next_back()?.trim();
            let hex = last.strip_prefix("0x")?;
            u64::from_str_radix(hex, 16).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn riscv64_registers() {
        let arch = RiscVArch::new_rv64().unwrap();
        assert_eq!(arch.bits(), 64);
        let sp = arch.register_by_name("sp").unwrap();
        assert_eq!(sp.varnode.size, 8);
        let x2 = arch.register_by_name("x2").unwrap();
        assert_eq!(x2.name, "sp");
    }

    #[test]
    fn riscv32_registers() {
        let arch = RiscVArch::new_rv32().unwrap();
        assert_eq!(arch.bits(), 32);
        let a0 = arch.register_by_name("a0").unwrap();
        assert_eq!(a0.varnode.size, 4);
    }

    #[test]
    fn riscv_flow_classification() {
        assert_eq!(classify_riscv_flow("ret", ""), FlowType::Return);
        assert_eq!(classify_riscv_flow("beq", "a0, a1, 0x1000"), FlowType::ConditionalJump);
        assert_eq!(classify_riscv_flow("j", "0x2000"), FlowType::UnconditionalJump);
        assert_eq!(classify_riscv_flow("jal", "ra, 0x3000"), FlowType::Call);
        assert_eq!(classify_riscv_flow("addi", "a0, a0, 1"), FlowType::Fall);
    }
}
