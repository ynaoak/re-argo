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

fn capstone_arm32() -> capstone::CsResult<capstone::Capstone> {
    use capstone::prelude::*;
    Capstone::new().arm().mode(arch::arm::ArchMode::Arm).detail(true).build()
}

fn capstone_thumb() -> capstone::CsResult<capstone::Capstone> {
    use capstone::prelude::*;
    Capstone::new().arm().mode(arch::arm::ArchMode::Thumb).detail(true).build()
}

fn capstone_aarch64() -> capstone::CsResult<capstone::Capstone> {
    use capstone::prelude::*;
    Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).detail(true).build()
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
        let cs = capstone_arm32()
            .map_err(|e| DisasmError::EngineError(format!("ARM capstone init: {}", e)))?;
        Ok(Self {
            is_64: false,
            thumb: false,
            registers: arm32_registers(),
            calling_conventions: arm32_calling_conventions(),
            cs: crate::capstone_wrapper::SafeCapstone::with_builder(cs, || capstone_arm32().ok()),
        })
    }

    pub fn new_arm32_thumb() -> Self {
        let cs = capstone_thumb().expect("failed to create Thumb capstone");
        Self {
            is_64: false,
            thumb: true,
            registers: arm32_registers(),
            calling_conventions: arm32_calling_conventions(),
            cs: crate::capstone_wrapper::SafeCapstone::with_builder(cs, || capstone_thumb().ok()),
        }
    }

    pub fn new_aarch64() -> Result<Self, DisasmError> {
        let cs = capstone_aarch64()
            .map_err(|e| DisasmError::EngineError(format!("AArch64 capstone init: {}", e)))?;
        Ok(Self {
            is_64: true,
            thumb: false,
            registers: aarch64_registers(),
            calling_conventions: aarch64_calling_conventions(),
            cs: crate::capstone_wrapper::SafeCapstone::with_builder(cs, || capstone_aarch64().ok()),
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
        // (a Thumb instruction that does not read the PC decodes the same at every address,
        // [`thumb_pc_relative16`] / [`thumb_pc_relative32`]: Capstone's `cs_disasm` starts each
        // decode with an empty IT block, so a decode depends on the bytes and the address only)
        let thumb = (self.thumb && !self.is_64).then(|| thumb_keys(buf));
        if let Some((hw, w)) = thumb {
            if !thumb_pc_relative16(hw)
                && let Some(known) = T16_DECODES.with(|m| m.borrow().get(&u32::from(hw)).cloned())
            {
                let mut d = known;
                d.address = address;
                return Ok(d);
            }
            if let Some(w) = w.filter(|&w| !thumb_pc_relative32(w))
                && let Some(known) = T32_DECODES.with(|m| m.borrow().get(&w).cloned())
            {
                let mut d = known;
                d.address = address;
                return Ok(d);
            }
        }
        let decoded = self.decode_with_capstone(buf, address)?;
        if let Some((hw, w)) = thumb {
            // (a halfword decoded as a T16 instruction is that instruction whatever follows it;
            // a T32 one is decoded from both halfwords)
            let memo = match (decoded.length, w) {
                (2, _) if !thumb_pc_relative16(hw) => Some((&T16_DECODES, u32::from(hw))),
                (4, Some(w)) if !thumb_pc_relative32(w) => Some((&T32_DECODES, w)),
                _ => None,
            };
            if let Some((table, key)) = memo {
                table.with(|m| {
                    let mut m = m.borrow_mut();
                    if m.len() >= THUMB_DECODES_CAP {
                        m.clear();
                    }
                    m.insert(key, decoded.clone());
                });
            }
            return Ok(decoded);
        }
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

/// Decodes a thread keeps by Thumb halfword (T16) and by Thumb word (T32) at most, each
/// (emptied when full).
const THUMB_DECODES_CAP: usize = 1 << 14;

thread_local! {
    /// The decode of each T16 halfword that does not read the PC (key: the halfword), and of
    /// each T32 instruction that does not (key: [`thumb_keys`]' word), at the address it was
    /// first decoded at.
    static T16_DECODES: std::cell::RefCell<rustc_hash::FxHashMap<u32, DecodedInstruction>> = std::cell::RefCell::new(rustc_hash::FxHashMap::default());
    static T32_DECODES: std::cell::RefCell<rustc_hash::FxHashMap<u32, DecodedInstruction>> = std::cell::RefCell::new(rustc_hash::FxHashMap::default());
}

/// The first halfword of the Thumb bytes `buf` (little-endian, at least 2 bytes) and, when it
/// has 4 bytes, both halfwords as one word (`first << 16 | second`, as the T32 encodings are
/// written).
fn thumb_keys(buf: &[u8]) -> (u16, Option<u32>) {
    let hw = u16::from_le_bytes([buf[0], buf[1]]);
    let w = (buf.len() == 4).then(|| (u32::from(hw) << 16) | u32::from(u16::from_le_bytes([buf[2], buf[3]])));
    (hw, w)
}

/// May the T16 instruction `hw` decode differently at different addresses? Its conditional
/// and unconditional branches (`1101....`, `11100...`: Capstone prints their targets), CBZ /
/// CBNZ (`1011.0.1`), ADR (`10100...`) and the literal load (`01001...`).
fn thumb_pc_relative16(hw: u16) -> bool {
    hw & 0xf000 == 0xd000 || hw & 0xf800 == 0xe000 || hw & 0xf500 == 0xb100 || hw & 0xf800 == 0xa000 || hw & 0xf800 == 0x4800
}

/// May the T32 instruction `w` ([`thumb_keys`]) decode differently at different addresses?
/// Its branches and miscellaneous control (`11110...` then `1...`: B, BL, BLX and their
/// targets) and anything with the PC as its base register (`Rn` = `1111` in the first
/// halfword: ADR, the literal loads, TBB / TBH, ...).
fn thumb_pc_relative32(w: u32) -> bool {
    let (hw1, hw2) = (w >> 16, w & 0xffff);
    (hw1 & 0xf800 == 0xf000 && hw2 & 0x8000 != 0) || hw1 & 0xf == 0xf
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

    /// Every Thumb instruction `thumb_pc_relative16` / `thumb_pc_relative32` leave out decodes
    /// the same at any address (what the Thumb decode memo relies on), and a halfword decoded
    /// as a T16 instruction is that one whatever bytes follow it: every T16 halfword, every
    /// first halfword of a T32 instruction with 48 second halfwords, and 400k random words.
    #[test]
    fn thumb_non_pc_relative_decodes_alike() {
        let arch = ArmArch::new_arm32_thumb();
        let at = |b: &[u8], a: u64| {
            arch.decode_with_capstone(b, a)
                .ok()
                .map(|d| (d.mnemonic().to_string(), d.operands().to_string(), d.flow_type, d.branch_target, d.length, d.bytes.clone()))
        };
        let addrs = [0x1000u64, 0x1002, 0x3a2e5, 0x7fff_fffe, 0xffff_f000];
        let mut checked = 0;
        for hw in 0..=0xffffu16 {
            let h = hw.to_le_bytes();
            let alone = at(&h, 0x1000);
            if alone.as_ref().is_some_and(|d| d.4 == 2) {
                // (the same T16 instruction with any second halfword)
                assert_eq!(at(&[h[0], h[1], 0xff, 0xf7], 0x1000), alone, "{hw:04x}");
                assert_eq!(at(&[h[0], h[1], 0x00, 0x00], 0x1000), alone, "{hw:04x}");
            }
            if thumb_pc_relative16(hw) {
                continue;
            }
            for &a in &addrs[1..] {
                assert_eq!(at(&h, a), alone, "{hw:04x} at {a:x}");
            }
            checked += usize::from(alone.is_some());
        }
        assert!(checked > 40_000, "{checked}");
        let mut x: u64 = 0x3c6e_f372_fe94_f82b;
        let mut next = || {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 32) as u32
        };
        let mut words: Vec<u32> = Vec::new();
        for hw1 in 0xe800..=0xffffu32 {
            for k in 0..48 {
                let hw2 = if k < 16 { (k << 12) | (next() & 0x0fff) } else { next() & 0xffff };
                words.push((hw1 << 16) | hw2);
            }
        }
        words.extend((0..400_000).map(|_| next()));
        let mut checked = 0;
        for (i, w) in words.into_iter().enumerate() {
            if thumb_pc_relative32(w) {
                continue;
            }
            let b = [(w >> 16) as u8, (w >> 24) as u8, w as u8, (w >> 8) as u8];
            let d = at(&b, 0x1000);
            if d.as_ref().is_none_or(|d| d.4 != 4) {
                continue;
            }
            assert_eq!(thumb_keys(&b).1, Some(w));
            assert_eq!(at(&b, addrs[1 + i % 4]), d, "{w:08x}");
            checked += 1;
        }
        assert!(checked > 100_000, "{checked}");
    }

    /// The memo gives what Capstone does: a stream of Thumb code decoded twice (the second
    /// time mostly from the memo) at other addresses.
    #[test]
    fn thumb_decode_memo_matches_capstone() {
        let arch = ArmArch::new_arm32_thumb();
        let mut x: u64 = 0x1d8e_4e27_c47d_124f;
        let code: Vec<u8> = (0..20_000)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (x >> 40) as u8
            })
            .collect();
        let key = |d: &DecodedInstruction| (d.address, d.mnemonic().to_string(), d.operands().to_string(), d.flow_type, d.branch_target, d.length, d.bytes.clone());
        for base in [0x1_0000u64, 0x2_0002] {
            let mem = make_memory(&code, base, Endian::Little);
            let mut a = base;
            while a + 4 <= base + code.len() as u64 {
                let got = arch.decode_instruction(&mem, a).ok().map(|d| key(&d));
                let cap = arch.decode_with_capstone(&code[(a - base) as usize..(a - base) as usize + 4], a).ok().map(|d| key(&d));
                assert_eq!(got, cap, "at {a:x}");
                a += got.map_or(2, |g| u64::from(g.5));
            }
        }
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
