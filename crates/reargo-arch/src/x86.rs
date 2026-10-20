use reargo_core::address::{Endian, SpaceId};
use reargo_core::pcode::VarnodeData;
use reargo_loader::Memory;
use smallvec::SmallVec;

use crate::arch::{
    Architecture, CallingConvention, DecodedInstruction, FlowType, RegisterInfo,
};
use crate::error::DisasmError;

const REGISTER_SPACE: SpaceId = SpaceId::REGISTER;
const RAM_SPACE: SpaceId = SpaceId::RAM;

fn x64_registers() -> Vec<RegisterInfo> {
    let mut regs = Vec::new();
    let gpr_names_64 = [
        ("RAX", 0x00u64),
        ("RCX", 0x08),
        ("RDX", 0x10),
        ("RBX", 0x18),
        ("RSP", 0x20),
        ("RBP", 0x28),
        ("RSI", 0x30),
        ("RDI", 0x38),
        ("R8", 0x80),
        ("R9", 0x88),
        ("R10", 0x90),
        ("R11", 0x98),
        ("R12", 0xA0),
        ("R13", 0xA8),
        ("R14", 0xB0),
        ("R15", 0xB8),
    ];

    for (name, offset) in &gpr_names_64 {
        regs.push(RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, *offset, 8),
            aliases: Vec::new(),
        });
    }

    let gpr_32 = [
        ("EAX", 0x00u64),
        ("ECX", 0x08),
        ("EDX", 0x10),
        ("EBX", 0x18),
        ("ESP", 0x20),
        ("EBP", 0x28),
        ("ESI", 0x30),
        ("EDI", 0x38),
    ];
    for (name, offset) in &gpr_32 {
        regs.push(RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, *offset, 4),
            aliases: Vec::new(),
        });
    }

    let gpr_16 = [
        ("AX", 0x00u64),
        ("CX", 0x08),
        ("DX", 0x10),
        ("BX", 0x18),
        ("SP", 0x20),
        ("BP", 0x28),
        ("SI", 0x30),
        ("DI", 0x38),
    ];
    for (name, offset) in &gpr_16 {
        regs.push(RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, *offset, 2),
            aliases: Vec::new(),
        });
    }

    let gpr_8l = [
        ("AL", 0x00u64),
        ("CL", 0x08),
        ("DL", 0x10),
        ("BL", 0x18),
    ];
    for (name, offset) in &gpr_8l {
        regs.push(RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, *offset, 1),
            aliases: Vec::new(),
        });
    }

    regs.push(RegisterInfo {
        name: "RIP".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 0x48, 8),
        aliases: vec!["EIP".to_string()],
    });

    regs.push(RegisterInfo {
        name: "rflags".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 0x200, 8),
        aliases: vec!["eflags".to_string()],
    });

    // XMM register file (base 0x1200, stride 0x10) — used by the SSE/scalar
    // float lifting. Full 16-byte view; scalar sd/ss ops alias the low lane.
    for i in 0..16u64 {
        regs.push(RegisterInfo {
            name: format!("XMM{}", i),
            varnode: VarnodeData::new(REGISTER_SPACE, 0x1200 + i * 0x10, 16),
            aliases: Vec::new(),
        });
    }

    regs
}

fn x86_registers() -> Vec<RegisterInfo> {
    let mut regs = Vec::new();
    let gpr_32 = [
        ("EAX", 0x00u64),
        ("ECX", 0x08),
        ("EDX", 0x10),
        ("EBX", 0x18),
        ("ESP", 0x20),
        ("EBP", 0x28),
        ("ESI", 0x30),
        ("EDI", 0x38),
    ];
    for (name, offset) in &gpr_32 {
        regs.push(RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, *offset, 4),
            aliases: Vec::new(),
        });
    }

    let gpr_16 = [
        ("AX", 0x00u64),
        ("CX", 0x08),
        ("DX", 0x10),
        ("BX", 0x18),
        ("SP", 0x20),
        ("BP", 0x28),
        ("SI", 0x30),
        ("DI", 0x38),
    ];
    for (name, offset) in &gpr_16 {
        regs.push(RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, *offset, 2),
            aliases: Vec::new(),
        });
    }

    let gpr_8l = [
        ("AL", 0x00u64),
        ("CL", 0x08),
        ("DL", 0x10),
        ("BL", 0x18),
    ];
    for (name, offset) in &gpr_8l {
        regs.push(RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, *offset, 1),
            aliases: Vec::new(),
        });
    }

    regs.push(RegisterInfo {
        name: "EIP".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 0x48, 4),
        aliases: Vec::new(),
    });

    regs.push(RegisterInfo {
        name: "eflags".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 0x200, 4),
        aliases: Vec::new(),
    });

    regs
}

fn x64_calling_conventions() -> Vec<CallingConvention> {
    vec![
        CallingConvention {
            name: "__fastcall".to_string(),
            param_registers: vec![
                VarnodeData::new(REGISTER_SPACE, 0x08, 8), // RCX
                VarnodeData::new(REGISTER_SPACE, 0x10, 8), // RDX
                VarnodeData::new(REGISTER_SPACE, 0x80, 8), // R8
                VarnodeData::new(REGISTER_SPACE, 0x88, 8), // R9
            ],
            return_register: Some(VarnodeData::new(REGISTER_SPACE, 0x00, 8)), // RAX
            callee_saved: vec![
                VarnodeData::new(REGISTER_SPACE, 0x18, 8), // RBX
                VarnodeData::new(REGISTER_SPACE, 0x28, 8), // RBP
                VarnodeData::new(REGISTER_SPACE, 0x30, 8), // RSI
                VarnodeData::new(REGISTER_SPACE, 0x38, 8), // RDI
                VarnodeData::new(REGISTER_SPACE, 0xA0, 8), // R12
                VarnodeData::new(REGISTER_SPACE, 0xA8, 8), // R13
                VarnodeData::new(REGISTER_SPACE, 0xB0, 8), // R14
                VarnodeData::new(REGISTER_SPACE, 0xB8, 8), // R15
            ],
            stack_pointer: VarnodeData::new(REGISTER_SPACE, 0x20, 8), // RSP
        },
        CallingConvention {
            name: "__cdecl (SysV)".to_string(),
            param_registers: vec![
                VarnodeData::new(REGISTER_SPACE, 0x38, 8), // RDI
                VarnodeData::new(REGISTER_SPACE, 0x30, 8), // RSI
                VarnodeData::new(REGISTER_SPACE, 0x10, 8), // RDX
                VarnodeData::new(REGISTER_SPACE, 0x08, 8), // RCX
                VarnodeData::new(REGISTER_SPACE, 0x80, 8), // R8
                VarnodeData::new(REGISTER_SPACE, 0x88, 8), // R9
            ],
            return_register: Some(VarnodeData::new(REGISTER_SPACE, 0x00, 8)), // RAX
            callee_saved: vec![
                VarnodeData::new(REGISTER_SPACE, 0x18, 8), // RBX
                VarnodeData::new(REGISTER_SPACE, 0x28, 8), // RBP
                VarnodeData::new(REGISTER_SPACE, 0xA0, 8), // R12
                VarnodeData::new(REGISTER_SPACE, 0xA8, 8), // R13
                VarnodeData::new(REGISTER_SPACE, 0xB0, 8), // R14
                VarnodeData::new(REGISTER_SPACE, 0xB8, 8), // R15
            ],
            stack_pointer: VarnodeData::new(REGISTER_SPACE, 0x20, 8), // RSP
        },
    ]
}

fn x86_calling_conventions() -> Vec<CallingConvention> {
    vec![CallingConvention {
        name: "__cdecl".to_string(),
        param_registers: Vec::new(),
        return_register: Some(VarnodeData::new(REGISTER_SPACE, 0x00, 4)), // EAX
        callee_saved: vec![
            VarnodeData::new(REGISTER_SPACE, 0x18, 4), // EBX
            VarnodeData::new(REGISTER_SPACE, 0x28, 4), // EBP
            VarnodeData::new(REGISTER_SPACE, 0x30, 4), // ESI
            VarnodeData::new(REGISTER_SPACE, 0x38, 4), // EDI
        ],
        stack_pointer: VarnodeData::new(REGISTER_SPACE, 0x20, 4), // ESP
    }]
}

pub struct X86Arch {
    is_64: bool,
    registers: Vec<RegisterInfo>,
    calling_conventions: Vec<CallingConvention>,
}

impl X86Arch {
    pub fn new_64() -> Self {
        Self {
            is_64: true,
            registers: x64_registers(),
            calling_conventions: x64_calling_conventions(),
        }
    }

    pub fn new_32() -> Self {
        Self {
            is_64: false,
            registers: x86_registers(),
            calling_conventions: x86_calling_conventions(),
        }
    }

    fn decode_with_iced(
        &self,
        data: &[u8],
        address: u64,
    ) -> Result<DecodedInstruction, DisasmError> {
        use iced_x86::{Decoder, DecoderOptions, Instruction};

        let bitness = self.bitness();
        let mut decoder = Decoder::with_ip(bitness, data, address, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);
        self.finish(&instruction, data, address)
    }

    fn bitness(&self) -> u32 {
        if self.is_64 { 64 } else { 32 }
    }

    /// The instruction `instruction` decoded from `data` (its bytes first) at `address`.
    fn finish(
        &self,
        instruction: &iced_x86::Instruction,
        data: &[u8],
        address: u64,
    ) -> Result<DecodedInstruction, DisasmError> {
        if instruction.is_invalid() {
            return Err(DisasmError::DecodeError {
                address,
                reason: "invalid instruction".into(),
            });
        }

        let len = instruction.len() as u32;
        let bytes: SmallVec<[u8; 16]> = SmallVec::from_slice(&data[..len as usize]);

        let flow_type = classify_flow(instruction);
        let branch_target = extract_branch_target(instruction);

        // The text is formatted from `bytes` when first read (`format_text`).
        Ok(DecodedInstruction::new_x86_lazy(address, len, bytes, flow_type, branch_target, self.bitness()))
    }
}

/// The x86 [`InstructionDecoder`]: one iced decoder over the bytes of the memory block
/// the last instruction was in, positioned at each address, instead of one built per
/// instruction ([`X86Arch::decode_instruction`] reads the bytes of the address's block
/// into a buffer and decodes them with a decoder of its own).
struct X86Decoder<'a> {
    arch: &'a X86Arch,
    memory: &'a Memory,
    block: Option<BlockDecoder<'a>>,
    instruction: iced_x86::Instruction,
}

/// An iced decoder over the data of one memory block.
struct BlockDecoder<'a> {
    start: u64,
    size: u64,
    /// The addresses `start .. start + end` read from this block ([`Memory::find_block`]:
    /// no other block starts before `start + end`).
    end: u64,
    /// The block's data (all of it).
    data: &'a [u8],
    /// Over `data[..min(size, data.len())]`.
    decoder: iced_x86::Decoder<'a>,
}

impl<'a> BlockDecoder<'a> {
    /// A decoder over the block `address` reads from, when it has data.
    fn new(memory: &'a Memory, address: u64, bitness: u32) -> Option<Self> {
        let block = memory.find_block(address)?;
        let data: &'a [u8] = block.data.as_deref()?;
        let next = memory.blocks().map(|b| b.start).filter(|&s| s > block.start).min();
        let end = next.map_or(block.size, |n| (n - block.start).min(block.size));
        let limit = usize::try_from(block.size.min(data.len() as u64)).ok()?;
        let decoder = iced_x86::Decoder::try_with_ip(bitness, &data[..limit], block.start, iced_x86::DecoderOptions::NONE).ok()?;
        Some(Self { start: block.start, size: block.size, end, data, decoder })
    }

    fn holds(&self, address: u64) -> bool {
        address >= self.start && address - self.start < self.end
    }
}

impl crate::arch::InstructionDecoder for X86Decoder<'_> {
    fn decode(&mut self, address: u64) -> Result<DecodedInstruction, DisasmError> {
        if !self.block.as_ref().is_some_and(|b| b.holds(address)) {
            self.block = BlockDecoder::new(self.memory, address, self.arch.bitness());
        }
        if let Some(b) = &mut self.block
            && b.holds(address)
        {
            // `decode_instruction` decodes the `min(15, size - offset)` bytes from the
            // offset, read from the data when it has them all: these same bytes are the
            // first of the decoder's from there (it reads at most 15).
            let offset = address - b.start;
            let read = 15.min(b.size - offset);
            if let Ok(offset) = usize::try_from(offset)
                && offset as u64 + read <= b.data.len() as u64
                && b.decoder.set_position(offset).is_ok()
            {
                b.decoder.set_ip(address);
                b.decoder.decode_out(&mut self.instruction);
                return self.arch.finish(&self.instruction, &b.data[offset..], address);
            }
        }
        self.arch.decode_instruction(self.memory, address)
    }
}

/// The Intel-syntax text `(mnemonic, operands)` of the x86 instruction
/// `bytes` (exactly its bytes) at `address`, as [`DecodedInstruction`]
/// prints it.
pub(crate) fn format_text(bytes: &[u8], address: u64, bitness: u32) -> (String, String) {
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Instruction};

    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    decoder.decode_out(&mut instruction);

    // One formatter per thread (building one per instruction was a
    // large share of the decode); its output does not depend on
    // earlier calls.
    thread_local! {
        static FORMATTER: std::cell::RefCell<IntelFormatter> = std::cell::RefCell::new(IntelFormatter::new());
    }
    FORMATTER.with(|cell| {
        let formatter = &mut *cell.borrow_mut();
        let mut mnemonic_output = String::new();
        formatter.format_mnemonic(&instruction, &mut mnemonic_output);

        let mut operand_output = String::new();
        // Use the *formatter's* operand count: it differs from
        // `instruction.op_count()` for pseudo-ops (`cmpltss` hides the
        // predicate imm) and for 3-operand `imul r, r, imm` with dst == src,
        // which iced prints in its 2-operand short form. Iterating the raw
        // count printed `imul eax, 93h, ` / `cmpltss xmm3, xmm0, ` with a
        // dangling separator and an empty operand.
        let operand_count = formatter.operand_count(&instruction);
        for i in 0..operand_count {
            if i > 0 {
                operand_output.push_str(", ");
            }
            let _ = formatter.format_operand(&instruction, &mut operand_output, i);
        }
        (mnemonic_output, operand_output)
    })
}

fn classify_flow(insn: &iced_x86::Instruction) -> FlowType {
    use iced_x86::FlowControl;
    match insn.flow_control() {
        FlowControl::Next | FlowControl::Exception => FlowType::Fall,
        FlowControl::UnconditionalBranch => FlowType::UnconditionalJump,
        FlowControl::ConditionalBranch => FlowType::ConditionalJump,
        FlowControl::Call => FlowType::Call,
        FlowControl::IndirectCall => FlowType::IndirectCall,
        FlowControl::IndirectBranch => FlowType::IndirectJump,
        FlowControl::Return => FlowType::Return,
        FlowControl::XbeginXabortXend | FlowControl::Interrupt => FlowType::Fall,
    }
}

fn extract_branch_target(insn: &iced_x86::Instruction) -> Option<u64> {
    use iced_x86::FlowControl;
    match insn.flow_control() {
        FlowControl::UnconditionalBranch
        | FlowControl::ConditionalBranch
        | FlowControl::Call => {
            let target = insn.near_branch_target();
            if target != 0 {
                Some(target)
            } else {
                None
            }
        }
        _ => None,
    }
}

impl Architecture for X86Arch {
    fn name(&self) -> &str {
        if self.is_64 {
            "x86_64"
        } else {
            "x86"
        }
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
        let mut buf = [0u8; 15];
        let read_len = memory.read_instruction_bytes(address, &mut buf);
        if read_len == 0 {
            return Err(DisasmError::UnreadableAddress(address));
        }
        self.decode_with_iced(&buf[..read_len], address)
    }

    fn instruction_decoder<'a>(&'a self, memory: &'a Memory) -> Box<dyn crate::arch::InstructionDecoder + 'a> {
        Box::new(X86Decoder { arch: self, memory, block: None, instruction: iced_x86::Instruction::default() })
    }

    fn calling_conventions(&self) -> &[CallingConvention] {
        &self.calling_conventions
    }

    fn default_calling_convention(&self) -> Option<&CallingConvention> {
        self.calling_conventions.first()
    }

    fn stack_pointer(&self) -> Option<&RegisterInfo> {
        self.register_by_name(if self.is_64 { "RSP" } else { "ESP" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::SpaceId;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn make_memory(data: &[u8], addr: u64) -> Memory {
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
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
    fn decode_nop() {
        let arch = X86Arch::new_64();
        let mem = make_memory(&[0x90], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "nop");
        assert_eq!(insn.length, 1);
        assert_eq!(insn.flow_type, FlowType::Fall);
    }

    #[test]
    fn decode_operands_have_no_dangling_separator() {
        let arch = X86Arch::new_64();
        // imul eax, eax, 93h = 69 c0 93 00 00 00
        let mem = make_memory(&[0x69, 0xc0, 0x93, 0x00, 0x00, 0x00], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert!(!insn.operands().trim_end().ends_with(','), "got {:?}", insn.operands());
        assert!(insn.operands().contains("93h"), "got {:?}", insn.operands());
        // cmpltss xmm3, xmm0 = f3 0f c2 d8 01
        let mem = make_memory(&[0xf3, 0x0f, 0xc2, 0xd8, 0x01], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "cmpltss");
        assert_eq!(insn.operands(), "xmm3, xmm0");
    }

    #[test]
    fn decode_ret() {
        let arch = X86Arch::new_64();
        let mem = make_memory(&[0xc3], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "ret");
        assert!(insn.is_return());
    }

    #[test]
    fn decode_call() {
        let arch = X86Arch::new_64();
        // CALL rel32 (e8 XX XX XX XX)
        let mem = make_memory(&[0xe8, 0x10, 0x00, 0x00, 0x00], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "call");
        assert!(insn.is_call());
        assert_eq!(insn.branch_target, Some(0x1015));
    }

    #[test]
    fn decode_jmp() {
        let arch = X86Arch::new_64();
        // JMP rel8 (eb XX)
        let mem = make_memory(&[0xeb, 0x10], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "jmp");
        assert!(insn.is_unconditional_jump());
        assert_eq!(insn.branch_target, Some(0x1012));
    }

    #[test]
    fn decode_conditional_branch() {
        let arch = X86Arch::new_64();
        // JE rel8 (74 XX)
        let mem = make_memory(&[0x74, 0x10], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.flow_type, FlowType::ConditionalJump);
        assert_eq!(insn.branch_target, Some(0x1012));
    }

    #[test]
    fn decode_mov_rax() {
        let arch = X86Arch::new_64();
        // MOV RAX, 0x1234567890ABCDEF
        let mem = make_memory(
            &[0x48, 0xb8, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12],
            0x1000,
        );
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "mov");
        assert_eq!(insn.length, 10);
    }

    #[test]
    fn decode_linear_sequence() {
        let arch = X86Arch::new_64();
        // push rbp; mov rbp, rsp; nop; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xe5, 0x90, 0x5d, 0xc3];
        let mem = make_memory(&code, 0x1000);
        let insns = arch.decode_linear(&mem, 0x1000, 10).unwrap();
        assert_eq!(insns.len(), 5);
        assert_eq!(insns[0].mnemonic(), "push");
        assert_eq!(insns[1].mnemonic(), "mov");
        assert_eq!(insns[2].mnemonic(), "nop");
        assert_eq!(insns[3].mnemonic(), "pop");
        assert_eq!(insns[4].mnemonic(), "ret");
    }

    #[test]
    fn decode_block_stops_at_ret() {
        let arch = X86Arch::new_64();
        // nop; ret; nop (block should stop after ret)
        let code = [0x90, 0xc3, 0x90];
        let mem = make_memory(&code, 0x1000);
        let insns = arch.decode_block(&mem, 0x1000, 100).unwrap();
        assert_eq!(insns.len(), 2);
    }

    /// [`Architecture::instruction_decoder`] gives what [`Architecture::decode_instruction`]
    /// gives at every address, in any order: across block ends, overlapping blocks, data
    /// shorter than its block, a block without data, unmapped addresses.
    #[test]
    fn instruction_decoder_matches_decode_instruction() {
        // (a fixed pseudo-random byte mix with common opcodes)
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut bytes = |n: usize| -> Vec<u8> {
            const COMMON: [u8; 12] = [0x48, 0x89, 0x8b, 0xe8, 0xc3, 0x0f, 0x66, 0xf3, 0x74, 0xeb, 0xff, 0x90];
            (0..n)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    if seed % 3 == 0 { COMMON[(seed >> 8) as usize % COMMON.len()] } else { (seed >> 16) as u8 }
                })
                .collect()
        };
        let block = |name: &str, start: u64, size: u64, data: Option<Vec<u8>>| MemoryBlock {
            name: name.into(),
            start,
            size,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: data.map(Arc::from),
        };
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(block("a", 0x1000, 0x200, Some(bytes(0x200))));
        // right after `a`
        mem.add_block(block("b", 0x1200, 0x40, Some(bytes(0x40))));
        // starting inside `c`, which goes on past it
        mem.add_block(block("c", 0x2000, 0x100, Some(bytes(0x100))));
        mem.add_block(block("d", 0x2080, 0x10, Some(bytes(0x10))));
        // data shorter than the block
        mem.add_block(block("e", 0x3000, 0x80, Some(bytes(0x40))));
        // no data
        mem.add_block(block("f", 0x4000, 0x20, None));
        for arch in [X86Arch::new_64(), X86Arch::new_32()] {
            let key = |d: Result<DecodedInstruction, DisasmError>| {
                d.map(|d| (d.address, d.length, d.bytes.clone(), d.flow_type, d.branch_target, d.mnemonic().to_string(), d.operands().to_string()))
                    .map_err(|e| e.to_string())
            };
            let addrs: Vec<u64> = [(0xff0u64, 0x1260u64), (0x1ff0, 0x2110), (0x2ff0, 0x3090), (0x3ff0, 0x4030)]
                .into_iter()
                .flat_map(|(lo, hi)| lo..hi)
                .collect();
            let mut decoder = arch.instruction_decoder(&mem);
            // in order, backwards, and jumping between the blocks
            let mixed = addrs.iter().copied().step_by(7).chain(addrs.iter().rev().copied().step_by(3));
            for a in addrs.iter().copied().chain(mixed) {
                assert_eq!(key(decoder.decode(a)), key(arch.decode_instruction(&mem, a)), "at {a:#x}");
            }
        }
    }

    #[test]
    fn register_lookup() {
        let arch = X86Arch::new_64();
        let rax = arch.register_by_name("RAX").unwrap();
        assert_eq!(rax.varnode.size, 8);
        let eax = arch.register_by_name("eax").unwrap();
        assert_eq!(eax.varnode.size, 4);
    }

    #[test]
    fn stack_pointer() {
        let arch = X86Arch::new_64();
        let sp = arch.stack_pointer().unwrap();
        assert_eq!(sp.name, "RSP");
    }

    #[test]
    fn x86_32_basics() {
        let arch = X86Arch::new_32();
        assert_eq!(arch.bits(), 32);
        let sp = arch.stack_pointer().unwrap();
        assert_eq!(sp.name, "ESP");
        assert_eq!(sp.varnode.size, 4);
    }
}
