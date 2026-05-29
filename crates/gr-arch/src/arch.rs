use gr_core::address::{Endian, SpaceId};
use gr_core::pcode::VarnodeData;
use gr_loader::Memory;
use smallvec::SmallVec;

use crate::error::DisasmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowType {
    Fall,
    UnconditionalJump,
    ConditionalJump,
    Call,
    IndirectCall,
    IndirectJump,
    Return,
}

#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub address: u64,
    pub length: u32,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: SmallVec<[u8; 16]>,
    pub flow_type: FlowType,
    pub branch_target: Option<u64>,
}

impl DecodedInstruction {
    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }

    pub fn is_branch(&self) -> bool {
        !matches!(self.flow_type, FlowType::Fall)
    }

    pub fn is_call(&self) -> bool {
        matches!(self.flow_type, FlowType::Call | FlowType::IndirectCall)
    }

    pub fn is_return(&self) -> bool {
        self.flow_type == FlowType::Return
    }

    pub fn is_unconditional_jump(&self) -> bool {
        matches!(
            self.flow_type,
            FlowType::UnconditionalJump | FlowType::IndirectJump
        )
    }
}

impl std::fmt::Display for DecodedInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}  ", self.address)?;
        for b in &self.bytes {
            write!(f, "{:02x} ", b)?;
        }
        let hex_width = 36;
        let hex_len = self.bytes.len() * 3;
        if hex_len < hex_width {
            for _ in 0..(hex_width - hex_len) {
                write!(f, " ")?;
            }
        }
        if self.operands.is_empty() {
            write!(f, "{}", self.mnemonic)
        } else {
            write!(f, "{:<8} {}", self.mnemonic, self.operands)
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub name: String,
    pub varnode: VarnodeData,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamLocation {
    Register(VarnodeData),
    Stack { offset: i64, size: u32 },
}

#[derive(Debug, Clone)]
pub struct CallingConvention {
    pub name: String,
    pub param_registers: Vec<VarnodeData>,
    pub return_register: Option<VarnodeData>,
    pub callee_saved: Vec<VarnodeData>,
    pub stack_pointer: VarnodeData,
}

pub trait Architecture: Send + Sync {
    fn name(&self) -> &str;
    fn bits(&self) -> u32;
    fn endian(&self) -> Endian;
    fn register_space(&self) -> SpaceId;
    fn default_space(&self) -> SpaceId;

    fn registers(&self) -> &[RegisterInfo];
    fn register_by_name(&self, name: &str) -> Option<&RegisterInfo>;

    fn decode_instruction(
        &self,
        memory: &Memory,
        address: u64,
    ) -> Result<DecodedInstruction, DisasmError>;

    fn decode_block(
        &self,
        memory: &Memory,
        start: u64,
        max_count: usize,
    ) -> Result<Vec<DecodedInstruction>, DisasmError> {
        let mut instructions = Vec::new();
        let mut addr = start;
        for _ in 0..max_count {
            match self.decode_instruction(memory, addr) {
                Ok(insn) => {
                    let next = insn.end_address();
                    let is_term = insn.is_return() || insn.is_unconditional_jump();
                    instructions.push(insn);
                    if is_term {
                        break;
                    }
                    addr = next;
                }
                Err(_) => break,
            }
        }
        Ok(instructions)
    }

    fn decode_linear(
        &self,
        memory: &Memory,
        start: u64,
        count: usize,
    ) -> Result<Vec<DecodedInstruction>, DisasmError> {
        let mut instructions = Vec::new();
        let mut addr = start;
        for _ in 0..count {
            match self.decode_instruction(memory, addr) {
                Ok(insn) => {
                    addr = insn.end_address();
                    instructions.push(insn);
                }
                Err(_) => break,
            }
        }
        Ok(instructions)
    }

    fn calling_conventions(&self) -> &[CallingConvention];
    fn default_calling_convention(&self) -> Option<&CallingConvention>;
    fn stack_pointer(&self) -> Option<&RegisterInfo>;
}

pub fn create_architecture(
    arch: gr_loader::Architecture,
) -> Result<Box<dyn Architecture>, DisasmError> {
    create_architecture_with_options(arch, false)
}

/// Like [`create_architecture`], but `thumb` selects Thumb (T16/T32) decoding
/// for the ARM architecture. The flag is ignored for non-ARM targets.
pub fn create_architecture_with_options(
    arch: gr_loader::Architecture,
    thumb: bool,
) -> Result<Box<dyn Architecture>, DisasmError> {
    match arch {
        #[cfg(feature = "x86")]
        gr_loader::Architecture::X86 => Ok(Box::new(crate::x86::X86Arch::new_32())),
        #[cfg(feature = "x86")]
        gr_loader::Architecture::X86_64 => Ok(Box::new(crate::x86::X86Arch::new_64())),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::Arm => Ok(Box::new(if thumb {
            crate::arm::ArmArch::new_arm32_thumb()
        } else {
            crate::arm::ArmArch::new_arm32()
        })),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::Arm64 => Ok(Box::new(crate::arm::ArmArch::new_aarch64())),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::Riscv32 => Ok(Box::new(crate::riscv::RiscVArch::new_rv32())),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::Riscv64 => Ok(Box::new(crate::riscv::RiscVArch::new_rv64())),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::Mips => Ok(Box::new(crate::mips::MipsArch::new(false, gr_core::address::Endian::Big))),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::Mips64 => Ok(Box::new(crate::mips::MipsArch::new(true, gr_core::address::Endian::Big))),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::PowerPc => Ok(Box::new(crate::ppc::PpcArch::new(false))),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::PowerPc64 => Ok(Box::new(crate::ppc::PpcArch::new(true))),
        #[cfg(feature = "arm")]
        gr_loader::Architecture::Sparc => Ok(Box::new(crate::sparc::SparcArch::new(false))),
        other => Err(DisasmError::UnsupportedArch(format!("{}", other))),
    }
}
