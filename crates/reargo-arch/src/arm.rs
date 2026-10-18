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
    cs: crate::capstone_wrapper::SafeCapstone,
}

impl ArmArch {
    pub fn new_arm32() -> Result<Self, DisasmError> {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| DisasmError::EngineError(format!("ARM capstone init: {}", e)))?;
        Ok(Self {
            is_64: false,
            thumb: false,
            registers: arm32_registers(),
            calling_conventions: arm32_calling_conventions(),
            cs: crate::capstone_wrapper::SafeCapstone::new(cs),
        })
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
            cs: crate::capstone_wrapper::SafeCapstone::new(cs),
        }
    }

    pub fn new_aarch64() -> Result<Self, DisasmError> {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| DisasmError::EngineError(format!("AArch64 capstone init: {}", e)))?;
        Ok(Self {
            is_64: true,
            thumb: false,
            registers: aarch64_registers(),
            calling_conventions: aarch64_calling_conventions(),
            cs: crate::capstone_wrapper::SafeCapstone::new(cs),
        })
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
        // Thumb instructions are 2 or 4 bytes; read up to 4 but tolerate a
        // 2-byte tail at the end of a section.
        let mut bytes = [0u8; 4];
        let len = match memory.slice(address, 4) {
            // (the bytes `read_byte` reads, in one lookup)
            Some(s) => {
                bytes.copy_from_slice(s);
                4
            }
            None => {
                let mut n = 0;
                while n < 4 {
                    match memory.read_byte(address + n as u64) {
                        Some(b) => bytes[n] = b,
                        None => break,
                    }
                    n += 1;
                }
                n
            }
        };
        let buf = &bytes[..len];
        let min_len = if self.thumb { 2 } else { 4 };
        if buf.len() < min_len {
            return Err(DisasmError::UnreadableAddress(address));
        }

        // (an AArch64 instruction that does not read the PC decodes the same at every address:
        // the decode of the same word made before, moved to `address`)
        let word = (self.is_64 && buf.len() == 4).then(|| u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]));
        // (a PC-relative branch or address is decoded without Capstone)
        if let Some(w) = word
            && let Some(d) = decode_pc_relative(w, buf, address)
        {
            return Ok(d);
        }
        let word = word.filter(|&w| !aarch64_pc_relative(w));
        if let Some(w) = word
            && let Some(known) = A64_DECODES.with(|m| m.borrow().get(&w).cloned())
        {
            let mut d = known;
            d.address = address;
            return Ok(d);
        }
        let decoded = self.decode_with_capstone(buf, address)?;
        if let Some(w) = word {
            A64_DECODES.with(|m| {
                let mut m = m.borrow_mut();
                if m.len() >= A64_DECODES_CAP {
                    m.clear();
                }
                m.insert(w, decoded.clone());
            });
        }
        Ok(decoded)
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

/// Decodes a thread keeps by AArch64 instruction word at most (emptied when full).
const A64_DECODES_CAP: usize = 1 << 14;

thread_local! {
    /// The decode of each AArch64 instruction word that does not read the PC, at the address it
    /// was first decoded at.
    static A64_DECODES: std::cell::RefCell<rustc_hash::FxHashMap<u32, DecodedInstruction>> = std::cell::RefCell::new(rustc_hash::FxHashMap::default());
}

pub use reargo_core::aarch64::is_pc_relative as aarch64_pc_relative;

/// The decode of the AArch64 PC-relative branch or address-forming instruction `word` (its
/// bytes `buf`) at `address`, as Capstone's ([`reargo_core::aarch64::PcRelative`]).
fn decode_pc_relative(word: u32, buf: &[u8], address: u64) -> Option<DecodedInstruction> {
    let insn = reargo_core::aarch64::PcRelative::decode(word, address)?;
    let (mnemonic, operands) = insn.text();
    let flow_type = classify_arm_flow(&mnemonic, &operands, true);
    let branch_target = extract_arm_branch_target(&operands, &flow_type);
    Some(DecodedInstruction::new(address, 4, mnemonic, operands, SmallVec::from_slice(buf), flow_type, branch_target))
}

impl ArmArch {
    /// The instruction `buf` starts with, at `address`, decoded by Capstone.
    fn decode_with_capstone(&self, buf: &[u8], address: u64) -> Result<DecodedInstruction, DisasmError> {
        let insns = self.cs.disasm_count(buf, address, 1)?;

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

        Ok(DecodedInstruction::new(address, length, mnemonic, operands, bytes, flow_type, branch_target))
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
    use reargo_core::address::SpaceId;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    /// Every word `aarch64_pc_relative` leaves out decodes the same at any address (what the
    /// decode memo relies on).
    #[test]
    fn aarch64_non_pc_relative_words_decode_alike() {
        let arch = ArmArch::new_aarch64().unwrap();
        let at = |w: u32, a: u64| {
            arch.decode_with_capstone(&w.to_le_bytes(), a)
                .ok()
                .map(|d| (d.mnemonic().to_string(), d.operands().to_string(), d.flow_type, d.branch_target, d.length, d.bytes.clone()))
        };
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut checked = 0;
        for _ in 0..200_000 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let w = (x >> 32) as u32;
            if aarch64_pc_relative(w) {
                continue;
            }
            let a = at(w, 0x40_1000);
            assert_eq!(a, at(w, 0x7f_6543_2100), "word {w:08x}");
            checked += usize::from(a.is_some());
        }
        assert!(checked > 10_000);
    }

    /// The PC-relative branches and addresses decoded without Capstone are Capstone's decodes.
    #[test]
    fn aarch64_pc_relative_decodes_as_capstone() {
        let arch = ArmArch::new_aarch64().unwrap();
        let key = |d: &DecodedInstruction| (d.address, d.mnemonic().to_string(), d.operands().to_string(), d.flow_type, d.branch_target, d.length, d.bytes.clone());
        let mut x: u64 = 0x7a4d_9e3b_1c55_0f61;
        let mut native = 0;
        let addrs = [0u64, 4, 0x1000, 0x40_1ffc, 0x7f_6543_2100, 0xffff_ffff_ffff_f000, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_fffc];
        for i in 0..300_000u32 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let class = [(0xfc00_0000u32, 0x1400_0000u32), (0xfc00_0000, 0x9400_0000), (0x7e00_0000, 0x3400_0000), (0x7e00_0000, 0x3600_0000), (0xff00_0000, 0x5400_0000), (0x1f00_0000, 0x1000_0000), (0x3b00_0000, 0x1800_0000)][(i % 7) as usize];
            let w = ((x >> 32) as u32 & !class.0) | class.1;
            let a = addrs[((x >> 8) % 8) as usize].wrapping_add(((x >> 12) & 0xffff_fffc) * u64::from(i % 3 == 0)) & !3;
            let b = w.to_le_bytes();
            let cap = arch.decode_with_capstone(&b, a).ok().map(|d| key(&d));
            if let Some(d) = decode_pc_relative(w, &b, a) {
                assert_eq!(Some(key(&d)), cap, "word {w:08x} at {a:x}");
                native += 1;
            }
        }
        assert!(native > 200_000, "{native}");
    }

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
        let arch = ArmArch::new_aarch64().unwrap();
        // NOP = 0xD503201F (little-endian)
        let mem = make_memory(&[0x1f, 0x20, 0x03, 0xd5], 0x1000, Endian::Little);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "nop");
        assert_eq!(insn.length, 4);
    }

    #[test]
    fn aarch64_ret() {
        let arch = ArmArch::new_aarch64().unwrap();
        // RET = 0xD65F03C0 (little-endian)
        let mem = make_memory(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000, Endian::Little);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "ret");
        assert!(insn.is_return());
    }

    #[test]
    fn arm32_mov() {
        let arch = ArmArch::new_arm32().unwrap();
        // MOV R0, #0 = 0xE3A00000 (little-endian)
        let mem = make_memory(&[0x00, 0x00, 0xa0, 0xe3], 0x1000, Endian::Little);
        let insn = arch.decode_instruction(&mem, 0x1000).unwrap();
        assert_eq!(insn.mnemonic(), "mov");
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
        assert_eq!(insn.mnemonic(), "movs");
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
        let arch = ArmArch::new_arm32().unwrap();
        let sp = arch.register_by_name("sp").unwrap();
        assert_eq!(sp.varnode.size, 4);
        let r13 = arch.register_by_name("r13").unwrap();
        assert_eq!(r13.name, "sp");
    }

    #[test]
    fn register_lookup_aarch64() {
        let arch = ArmArch::new_aarch64().unwrap();
        let x0 = arch.register_by_name("x0").unwrap();
        assert_eq!(x0.varnode.size, 8);
        let w0 = arch.register_by_name("w0").unwrap();
        assert_eq!(w0.name, "x0");
    }

    #[test]
    fn aarch64_stack_pointer() {
        let arch = ArmArch::new_aarch64().unwrap();
        let sp = arch.stack_pointer().unwrap();
        assert_eq!(sp.name, "sp");
        assert_eq!(sp.varnode.size, 8);
    }
}
