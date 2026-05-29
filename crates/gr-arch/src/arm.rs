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

fn arm32_registers() -> Vec<RegisterInfo> {
    let mut regs = Vec::new();
    for i in 0..=12 {
        regs.push(RegisterInfo {
            name: format!("r{}", i),
            varnode: VarnodeData::new(REGISTER_SPACE, i * 4, 4),
            aliases: Vec::new(),
        });
    }
    regs.push(RegisterInfo {
        name: "sp".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 13 * 4, 4),
        aliases: vec!["r13".to_string()],
    });
    regs.push(RegisterInfo {
        name: "lr".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 14 * 4, 4),
        aliases: vec!["r14".to_string()],
    });
    regs.push(RegisterInfo {
        name: "pc".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 15 * 4, 4),
        aliases: vec!["r15".to_string()],
    });
    regs.push(RegisterInfo {
        name: "cpsr".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 0x100, 4),
        aliases: Vec::new(),
    });
    regs
}

fn aarch64_registers() -> Vec<RegisterInfo> {
    let mut regs = Vec::new();
    for i in 0..=30 {
        regs.push(RegisterInfo {
            name: format!("x{}", i),
            varnode: VarnodeData::new(REGISTER_SPACE, i * 8, 8),
            aliases: vec![format!("w{}", i)],
        });
    }
    regs.push(RegisterInfo {
        name: "sp".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 31 * 8, 8),
        aliases: Vec::new(),
    });
    regs.push(RegisterInfo {
        name: "pc".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 32 * 8, 8),
        aliases: Vec::new(),
    });
    regs.push(RegisterInfo {
        name: "xzr".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 33 * 8, 8),
        aliases: vec!["wzr".to_string()],
    });
    regs.push(RegisterInfo {
        name: "nzcv".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 0x200, 4),
        aliases: Vec::new(),
    });
    regs
}

fn arm32_calling_conventions() -> Vec<CallingConvention> {
    vec![CallingConvention {
        name: "AAPCS".to_string(),
        param_registers: (0..4)
            .map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * 4, 4))
            .collect(),
        return_register: Some(VarnodeData::new(REGISTER_SPACE, 0, 4)),
        callee_saved: (4..=11)
            .map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * 4, 4))
            .collect(),
        stack_pointer: VarnodeData::new(REGISTER_SPACE, 13 * 4, 4),
    }]
}

fn aarch64_calling_conventions() -> Vec<CallingConvention> {
    vec![CallingConvention {
        name: "AAPCS64".to_string(),
        param_registers: (0..8)
            .map(|i| VarnodeData::new(REGISTER_SPACE, i * 8, 8))
            .collect(),
        return_register: Some(VarnodeData::new(REGISTER_SPACE, 0, 8)), // x0
        callee_saved: (19..=28)
            .map(|i| VarnodeData::new(REGISTER_SPACE, i * 8, 8))
            .chain(std::iter::once(VarnodeData::new(REGISTER_SPACE, 29 * 8, 8))) // x29 (fp)
            .chain(std::iter::once(VarnodeData::new(REGISTER_SPACE, 30 * 8, 8))) // x30 (lr)
            .collect(),
        stack_pointer: VarnodeData::new(REGISTER_SPACE, 31 * 8, 8), // sp
    }]
}

pub struct ArmArch {
    is_64: bool,
    thumb: bool,
    registers: Vec<RegisterInfo>,
    calling_conventions: Vec<CallingConvention>,
    cs: capstone::Capstone,
}

// Capstone's C library is thread-safe for independent instances
unsafe impl Send for ArmArch {}
unsafe impl Sync for ArmArch {}

impl ArmArch {
    pub fn new_arm32() -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("failed to create ARM capstone");
        Self {
            is_64: false,
            thumb: false,
            registers: arm32_registers(),
            calling_conventions: arm32_calling_conventions(),
            cs,
        }
    }

    pub fn new_arm32_thumb() -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .detail(true)
            .build()
            .expect("failed to create Thumb capstone");
        Self {
            is_64: false,
            thumb: true,
            registers: arm32_registers(),
            calling_conventions: arm32_calling_conventions(),
            cs,
        }
    }

    pub fn new_aarch64() -> Self {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("failed to create AArch64 capstone");
        Self {
            is_64: true,
            thumb: false,
            registers: aarch64_registers(),
            calling_conventions: aarch64_calling_conventions(),
            cs,
        }
    }
}

impl Architecture for ArmArch {
    fn name(&self) -> &str {
        if self.is_64 {
            "AArch64"
        } else if self.thumb {
            "Thumb"
        } else {
            "ARM"
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
        let lower = name.to_lowercase();
        self.registers.iter().find(|r| {
            r.name.to_lowercase() == lower
                || r.aliases.iter().any(|a| a.to_lowercase() == lower)
        })
    }

    fn decode_instruction(
        &self,
        memory: &Memory,
        address: u64,
    ) -> Result<DecodedInstruction, DisasmError> {
        // Thumb instructions are 2 or 4 bytes; read up to 4 but tolerate a
        // 2-byte tail at the end of a section.
        let mut buf: Vec<u8> = Vec::with_capacity(4);
        for i in 0..4u64 {
            match memory.read_byte(address + i) {
                Some(b) => buf.push(b),
                None => break,
            }
        }
        let min_len = if self.thumb { 2 } else { 4 };
        if buf.len() < min_len {
            return Err(DisasmError::UnreadableAddress(address));
        }

        let insns = self.cs
            .disasm_count(&buf, address, 1)
            .map_err(|e| DisasmError::DecodeError {
                address,
                reason: e.to_string(),
            })?;

        let insn = insns.iter().next().ok_or_else(|| DisasmError::DecodeError {
            address,
            reason: "no instruction decoded".into(),
        })?;

        let mnemonic = insn.mnemonic().unwrap_or("???").to_string();
        let operands = insn.op_str().unwrap_or("").to_string();
        let bytes: SmallVec<[u8; 16]> = insn.bytes().into();
        let length = insn.bytes().len() as u32;

        let flow_type = classify_arm_flow(&mnemonic, &operands, self.is_64);
        let branch_target = extract_arm_branch_target(&operands, &flow_type);

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

fn classify_arm_flow(mnemonic: &str, operands: &str, _is_64: bool) -> FlowType {
    let mn = mnemonic.to_lowercase();
    if mn == "b" {
        return FlowType::UnconditionalJump;
    }
    if mn.starts_with("b.") || mn == "cbz" || mn == "cbnz" || mn == "tbz" || mn == "tbnz" {
        return FlowType::ConditionalJump;
    }
    if mn.starts_with("b") && mn.len() > 1 && mn != "bic" && mn != "bfi" && mn != "bfxil" && mn != "brk" && mn != "br" && mn != "bl" && mn != "blr" && mn != "blx" {
        return FlowType::ConditionalJump;
    }
    if mn == "bl" || mn == "blx" || mn == "blr" {
        return FlowType::Call;
    }
    if mn == "br" || mn == "bx" {
        let ops = operands.to_lowercase();
        if ops.contains("lr") || ops.contains("x30") || ops.contains("r14") {
            return FlowType::Return;
        }
        return FlowType::IndirectJump;
    }
    if mn == "ret" {
        return FlowType::Return;
    }
    if mn == "svc" || mn == "hvc" {
        return FlowType::Call;
    }
    FlowType::Fall
}

fn extract_arm_branch_target(operands: &str, flow: &FlowType) -> Option<u64> {
    match flow {
        FlowType::UnconditionalJump | FlowType::ConditionalJump | FlowType::Call => {
            let target_str = operands
                .split(',')
                .next_back()
                .unwrap_or(operands)
                .trim()
                .strip_prefix("#")
                .unwrap_or(operands.trim());
            if let Some(hex) = target_str.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else {
                target_str.parse::<u64>().ok()
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gr_core::address::SpaceId;
    use gr_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn make_memory(data: &[u8], addr: u64, endian: Endian) -> Memory {
        let mut mem = Memory::new(SpaceId(1), endian);
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
    fn aarch64_nop() {
        let arch = ArmArch::new_aarch64();
        // NOP = 0xD503201F (little-endian)
        let mem = make_memory(&[0x1f, 0x20, 0x03, 0xd5], 0x1000, Endian::Little);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "nop");
        assert_eq!(insn.length, 4);
    }

    #[test]
    fn aarch64_ret() {
        let arch = ArmArch::new_aarch64();
        // RET = 0xD65F03C0 (little-endian)
        let mem = make_memory(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000, Endian::Little);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "ret");
        assert!(insn.is_return());
    }

    #[test]
    fn arm32_mov() {
        let arch = ArmArch::new_arm32();
        // MOV R0, #0 = 0xE3A00000 (little-endian)
        let mem = make_memory(&[0x00, 0x00, 0xa0, 0xe3], 0x1000, Endian::Little);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "mov");
        assert_eq!(insn.length, 4);
    }

    #[test]
    fn thumb_decodes_16bit() {
        let arch = ArmArch::new_arm32_thumb();
        assert_eq!(arch.name(), "Thumb");
        // movs r0, #5 => 0x2005 (little-endian: 05 20)
        let mem = make_memory(&[0x05, 0x20], 0x1000, Endian::Little);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.length, 2);
        assert_eq!(insn.mnemonic, "movs");
    }

    #[test]
    fn thumb_linear_mixed_lengths() {
        let arch = ArmArch::new_arm32_thumb();
        // movs r0,#5 (2 bytes) ; bl #x (4 bytes, 0xF000 0xF800) ; bx lr (2 bytes, 0x4770)
        let mem = make_memory(
            &[0x05, 0x20, 0x00, 0xf0, 0x00, 0xf8, 0x70, 0x47],
            0x1000,
            Endian::Little,
        );
        let insns = arch.decode_linear(&mem, 0x1000, 3).unwrap();
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].length, 2);
        assert_eq!(insns[1].length, 4); // bl is 32-bit
        assert_eq!(insns[2].address, 0x1006);
    }

    #[test]
    fn register_lookup_arm32() {
        let arch = ArmArch::new_arm32();
        let sp = arch.register_by_name("sp").unwrap();
        assert_eq!(sp.varnode.size, 4);
        let r13 = arch.register_by_name("r13").unwrap();
        assert_eq!(r13.name, "sp");
    }

    #[test]
    fn register_lookup_aarch64() {
        let arch = ArmArch::new_aarch64();
        let x0 = arch.register_by_name("x0").unwrap();
        assert_eq!(x0.varnode.size, 8);
        let w0 = arch.register_by_name("w0").unwrap();
        assert_eq!(w0.name, "x0");
    }

    #[test]
    fn aarch64_stack_pointer() {
        let arch = ArmArch::new_aarch64();
        let sp = arch.stack_pointer().unwrap();
        assert_eq!(sp.name, "sp");
        assert_eq!(sp.varnode.size, 8);
    }
}
