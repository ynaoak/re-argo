use gr_core::address::{Endian, SpaceId};
use gr_core::pcode::VarnodeData;
use gr_loader::Memory;
use smallvec::SmallVec;

use crate::arch::{
    Architecture, CallingConvention, DecodedInstruction, FlowType, RegisterInfo,
};
use crate::error::DisasmError;

const REGISTER_SPACE: SpaceId = SpaceId(2);
const RAM_SPACE: SpaceId = SpaceId(1);

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
        use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Instruction};

        let bitness = if self.is_64 { 64 } else { 32 };
        let mut decoder = Decoder::with_ip(bitness, data, address, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);

        if instruction.is_invalid() {
            return Err(DisasmError::DecodeError {
                address,
                reason: "invalid instruction".into(),
            });
        }

        let len = instruction.len() as u32;
        let bytes: SmallVec<[u8; 16]> = data[..len as usize].into();

        let mut formatter = IntelFormatter::new();
        let mut mnemonic_output = String::new();
        formatter.format_mnemonic(&instruction, &mut mnemonic_output);

        let mut operand_output = String::new();
        let operand_count = instruction.op_count();
        for i in 0..operand_count {
            if i > 0 {
                operand_output.push_str(", ");
            }
            let _ = formatter.format_operand(&instruction, &mut operand_output, i);
        }

        let flow_type = classify_flow(&instruction);
        let branch_target = extract_branch_target(&instruction);

        Ok(DecodedInstruction {
            address,
            length: len,
            mnemonic: mnemonic_output,
            operands: operand_output,
            bytes,
            flow_type,
            branch_target,
        })
    }
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
        let upper = name.to_uppercase();
        self.registers.iter().find(|r| {
            r.name.to_uppercase() == upper
                || r.aliases.iter().any(|a| a.to_uppercase() == upper)
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
    use gr_core::address::SpaceId;
    use gr_loader::memory::{MemoryBlock, MemoryFlags};
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
        assert_eq!(insn.mnemonic, "nop");
        assert_eq!(insn.length, 1);
        assert_eq!(insn.flow_type, FlowType::Fall);
    }

    #[test]
    fn decode_ret() {
        let arch = X86Arch::new_64();
        let mem = make_memory(&[0xc3], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "ret");
        assert!(insn.is_return());
    }

    #[test]
    fn decode_call() {
        let arch = X86Arch::new_64();
        // CALL rel32 (e8 XX XX XX XX)
        let mem = make_memory(&[0xe8, 0x10, 0x00, 0x00, 0x00], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "call");
        assert!(insn.is_call());
        assert_eq!(insn.branch_target, Some(0x1015));
    }

    #[test]
    fn decode_jmp() {
        let arch = X86Arch::new_64();
        // JMP rel8 (eb XX)
        let mem = make_memory(&[0xeb, 0x10], 0x1000);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "jmp");
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
        assert_eq!(insn.mnemonic, "mov");
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
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[1].mnemonic, "mov");
        assert_eq!(insns[2].mnemonic, "nop");
        assert_eq!(insns[3].mnemonic, "pop");
        assert_eq!(insns[4].mnemonic, "ret");
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
