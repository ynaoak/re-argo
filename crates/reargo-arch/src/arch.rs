use reargo_core::address::{Endian, SpaceId};
use reargo_core::pcode::VarnodeData;
use reargo_loader::Memory;
use smallvec::SmallVec;

use crate::error::DisasmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FlowType {
    Fall,
    UnconditionalJump,
    ConditionalJump,
    Call,
    IndirectCall,
    IndirectJump,
    Return,
}

#[derive(Clone)]
pub struct DecodedInstruction {
    pub address: u64,
    pub length: u32,
    pub bytes: SmallVec<[u8; 16]>,
    pub flow_type: FlowType,
    pub branch_target: Option<u64>,
    /// The text (`mnemonic`, `operands`): given, or for x86 formatted from
    /// `bytes` on first use ([`DecodedInstruction::mnemonic`]) — most passes
    /// only read the flow, and formatting was a large part of decoding.
    text: DisasmText,
}

#[derive(Clone)]
struct DisasmText {
    // Boxed: most instructions never have their text formatted, and an
    // instruction is kept per address of the listing (a few hundred
    // thousand on a large binary): 8 bytes instead of 48 inline.
    cell: std::sync::OnceLock<std::sync::Arc<(String, String)>>,
    /// The x86 bitness to decode `bytes` with when the text is formatted
    /// lazily; 0 when the text was given.
    #[cfg_attr(not(feature = "x86"), allow(dead_code))]
    lazy_x86_bitness: u8,
}

impl DecodedInstruction {
    /// An instruction with its text given.
    pub fn new(
        address: u64,
        length: u32,
        mnemonic: String,
        operands: String,
        bytes: SmallVec<[u8; 16]>,
        flow_type: FlowType,
        branch_target: Option<u64>,
    ) -> Self {
        let cell = std::sync::OnceLock::new();
        let _ = cell.set(std::sync::Arc::new((mnemonic, operands)));
        Self { address, length, bytes, flow_type, branch_target, text: DisasmText { cell, lazy_x86_bitness: 0 } }
    }

    /// An x86 instruction whose text is formatted from `bytes` (exactly the
    /// instruction's bytes) when it is first read.
    #[cfg(feature = "x86")]
    pub(crate) fn new_x86_lazy(
        address: u64,
        length: u32,
        bytes: SmallVec<[u8; 16]>,
        flow_type: FlowType,
        branch_target: Option<u64>,
        bitness: u32,
    ) -> Self {
        let text = DisasmText { cell: std::sync::OnceLock::new(), lazy_x86_bitness: bitness as u8 };
        Self { address, length, bytes, flow_type, branch_target, text }
    }

    fn text(&self) -> &(String, String) {
        self.text.cell.get_or_init(|| {
            #[cfg(feature = "x86")]
            if self.text.lazy_x86_bitness != 0 {
                return std::sync::Arc::new(crate::x86::format_text(&self.bytes, self.address, self.text.lazy_x86_bitness as u32));
            }
            std::sync::Arc::new((String::new(), String::new()))
        })
    }

    /// The mnemonic (with its prefixes), e.g. `mov` / `rep movsb`.
    pub fn mnemonic(&self) -> &str {
        &self.text().0
    }

    /// The operands, `, `-separated.
    pub fn operands(&self) -> &str {
        &self.text().1
    }

    /// The instruction's text as the on-disk analysis cache stores it:
    /// the x86 bitness to format it with lazily (0 when the text was
    /// given), and the given text. An x86 text formatted on first use is
    /// not stored: it is formatted again from `bytes` after loading.
    pub fn cache_text(&self) -> (u8, Option<&(String, String)>) {
        let lazy = self.text.lazy_x86_bitness;
        (lazy, (lazy == 0).then(|| self.text()))
    }

    /// An instruction of the parts [`Self::cache_text`] and the public
    /// fields hold (the on-disk analysis cache).
    pub fn from_cache_parts(
        address: u64,
        length: u32,
        bytes: SmallVec<[u8; 16]>,
        flow_type: FlowType,
        branch_target: Option<u64>,
        lazy_x86_bitness: u8,
        text: Option<(String, String)>,
    ) -> Self {
        let cell = std::sync::OnceLock::new();
        if let Some(text) = text {
            let _ = cell.set(std::sync::Arc::new(text));
        }
        Self { address, length, bytes, flow_type, branch_target, text: DisasmText { cell, lazy_x86_bitness } }
    }

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

/// The serialised form of a [`DecodedInstruction`] (the on-disk analysis
/// cache): an x86 instruction whose text is formatted lazily stores only
/// its bitness — the text is formatted again from `bytes` on first use,
/// exactly as after decoding — any other its text.
#[derive(serde::Serialize, serde::Deserialize)]
struct DecodedInstructionRepr {
    address: u64,
    length: u32,
    bytes: SmallVec<[u8; 16]>,
    flow_type: FlowType,
    branch_target: Option<u64>,
    lazy_x86_bitness: u8,
    text: Option<(String, String)>,
}

impl serde::Serialize for DecodedInstruction {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (lazy, text) = self.cache_text();
        DecodedInstructionRepr {
            address: self.address,
            length: self.length,
            bytes: self.bytes.clone(),
            flow_type: self.flow_type,
            branch_target: self.branch_target,
            lazy_x86_bitness: lazy,
            text: text.cloned(),
        }
        .serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for DecodedInstruction {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = DecodedInstructionRepr::deserialize(d)?;
        Ok(Self::from_cache_parts(
            r.address,
            r.length,
            r.bytes,
            r.flow_type,
            r.branch_target,
            r.lazy_x86_bitness,
            r.text,
        ))
    }
}

impl std::fmt::Debug for DecodedInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedInstruction")
            .field("address", &self.address)
            .field("length", &self.length)
            .field("mnemonic", &self.mnemonic())
            .field("operands", &self.operands())
            .field("bytes", &self.bytes)
            .field("flow_type", &self.flow_type)
            .field("branch_target", &self.branch_target)
            .finish()
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
        if self.operands().is_empty() {
            write!(f, "{}", self.mnemonic())
        } else {
            write!(f, "{:<8} {}", self.mnemonic(), self.operands())
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

    /// A decoder of instructions of `memory`, one at a time, each exactly as
    /// [`Architecture::decode_instruction`] decodes it, for a pass decoding many: it may
    /// keep what one decode set up for the next (x86: one iced decoder over the memory
    /// block, instead of one built per instruction).
    fn instruction_decoder<'a>(&'a self, memory: &'a Memory) -> Box<dyn InstructionDecoder + 'a> {
        Box::new(EachDecoder { arch: self, memory })
    }

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

/// Decodes instructions one at a time ([`Architecture::instruction_decoder`]).
pub trait InstructionDecoder {
    /// The instruction at `address`, exactly as [`Architecture::decode_instruction`] gives
    /// it.
    fn decode(&mut self, address: u64) -> Result<DecodedInstruction, DisasmError>;

    /// The length, flow and branch target of [`Self::decode`]'s instruction
    /// (an error when it gives one), for a caller that reads only those.
    fn decode_flow(&mut self, address: u64) -> Result<(u32, FlowType, Option<u64>), DisasmError> {
        self.decode(address).map(|d| (d.length, d.flow_type, d.branch_target))
    }
}

/// [`InstructionDecoder`] calling [`Architecture::decode_instruction`] for each.
struct EachDecoder<'a, A: ?Sized> {
    arch: &'a A,
    memory: &'a Memory,
}

impl<A: Architecture + ?Sized> InstructionDecoder for EachDecoder<'_, A> {
    fn decode(&mut self, address: u64) -> Result<DecodedInstruction, DisasmError> {
        self.arch.decode_instruction(self.memory, address)
    }
}

pub fn create_architecture(
    arch: reargo_loader::Architecture,
) -> Result<Box<dyn Architecture>, DisasmError> {
    create_architecture_with_options(arch, false)
}

/// Like [`create_architecture`], but `thumb` selects Thumb (T16/T32) decoding
/// for the ARM architecture. The flag is ignored for non-ARM targets.
pub fn create_architecture_with_options(
    arch: reargo_loader::Architecture,
    thumb: bool,
) -> Result<Box<dyn Architecture>, DisasmError> {
    match arch {
        #[cfg(feature = "x86")]
        reargo_loader::Architecture::X86 => Ok(Box::new(crate::x86::X86Arch::new_32())),
        #[cfg(feature = "x86")]
        reargo_loader::Architecture::X86_64 => Ok(Box::new(crate::x86::X86Arch::new_64())),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::Arm => Ok(Box::new(if thumb {
            crate::arm::ArmArch::new_arm32_thumb()
        } else {
            crate::arm::ArmArch::new_arm32()?
        })),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::Arm64 => Ok(Box::new(crate::arm::ArmArch::new_aarch64()?)),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::Riscv32 => Ok(Box::new(crate::riscv::RiscVArch::new_rv32()?)),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::Riscv64 => Ok(Box::new(crate::riscv::RiscVArch::new_rv64()?)),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::Mips => Ok(Box::new(crate::mips::MipsArch::new(false, reargo_core::address::Endian::Big)?)),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::Mips64 => Ok(Box::new(crate::mips::MipsArch::new(true, reargo_core::address::Endian::Big)?)),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::PowerPc => Ok(Box::new(crate::ppc::PpcArch::new(false)?)),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::PowerPc64 => Ok(Box::new(crate::ppc::PpcArch::new(true)?)),
        #[cfg(feature = "arm")]
        reargo_loader::Architecture::Sparc => Ok(Box::new(crate::sparc::SparcArch::new(false)?)),
        other => Err(DisasmError::UnsupportedArch(format!("{}", other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listing keeps one per instruction (hundreds of thousands): the
    /// text is boxed so the struct stays small.
    #[test]
    fn decoded_instruction_stays_small() {
        assert!(std::mem::size_of::<DecodedInstruction>() <= 80, "{}", std::mem::size_of::<DecodedInstruction>());
    }
}
