use gr_core::address::{Endian, SpaceId};
use gr_core::pcode::VarnodeData;
use gr_loader::Memory;
use crate::arch::{
    Architecture, CallingConvention, DecodedInstruction, FlowType, RegisterInfo,
};
use crate::error::DisasmError;

const REGISTER_SPACE: SpaceId = SpaceId::REGISTER;
const RAM_SPACE: SpaceId = SpaceId::RAM;

fn mips_registers(is_64: bool) -> Vec<RegisterInfo> {
    let sz = if is_64 { 8u32 } else { 4 };
    let names = [
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
    ];
    let mut regs: Vec<RegisterInfo> = names
        .iter()
        .enumerate()
        .map(|(i, name)| RegisterInfo {
            name: name.to_string(),
            varnode: VarnodeData::new(REGISTER_SPACE, (i as u64) * sz as u64, sz),
            aliases: vec![format!("${}", i)],
        })
        .collect();
    regs.push(RegisterInfo {
        name: "pc".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 32 * sz as u64, sz),
        aliases: Vec::new(),
    });
    regs.push(RegisterInfo {
        name: "hi".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 33 * sz as u64, sz),
        aliases: Vec::new(),
    });
    regs.push(RegisterInfo {
        name: "lo".to_string(),
        varnode: VarnodeData::new(REGISTER_SPACE, 34 * sz as u64, sz),
        aliases: Vec::new(),
    });
    regs
}

pub struct MipsArch {
    is_64: bool,
    endian: Endian,
    registers: Vec<RegisterInfo>,
    calling_conventions: Vec<CallingConvention>,
    cs: capstone::Capstone,
}

unsafe impl Send for MipsArch {}
unsafe impl Sync for MipsArch {}

impl MipsArch {
    pub fn new(is_64: bool, endian: Endian) -> Self {
        use capstone::prelude::*;
        let mode = if is_64 {
            arch::mips::ArchMode::Mips64
        } else {
            arch::mips::ArchMode::Mips32
        };
        let cs_endian = match endian {
            Endian::Big => capstone::Endian::Big,
            Endian::Little => capstone::Endian::Little,
        };
        let cs = Capstone::new_raw(capstone::Arch::MIPS, mode.into(), std::iter::empty(), Some(cs_endian))
            .expect("failed to create MIPS capstone");
        let sz = if is_64 { 8u32 } else { 4 };
        Self {
            is_64,
            endian,
            registers: mips_registers(is_64),
            calling_conventions: vec![CallingConvention {
                name: "o32/n64".to_string(),
                param_registers: (4..=7)
                    .map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz))
                    .collect(),
                return_register: Some(VarnodeData::new(REGISTER_SPACE, 2 * sz as u64, sz)),
                callee_saved: (16..=23)
                    .map(|i: u64| VarnodeData::new(REGISTER_SPACE, i * sz as u64, sz))
                    .collect(),
                stack_pointer: VarnodeData::new(REGISTER_SPACE, 29 * sz as u64, sz),
            }],
            cs,
        }
    }
}

impl Architecture for MipsArch {
    fn name(&self) -> &str {
        if self.is_64 { "MIPS64" } else { "MIPS" }
    }
    fn bits(&self) -> u32 {
        if self.is_64 { 64 } else { 32 }
    }
    fn endian(&self) -> Endian {
        self.endian
    }
    fn register_space(&self) -> SpaceId { REGISTER_SPACE }
    fn default_space(&self) -> SpaceId { RAM_SPACE }
    fn registers(&self) -> &[RegisterInfo] { &self.registers }
    fn register_by_name(&self, name: &str) -> Option<&RegisterInfo> {
        
        self.registers.iter().find(|r|
            r.name.eq_ignore_ascii_case(name) || r.aliases.iter().any(|a| a.eq_ignore_ascii_case(name)))
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
            "j" | "b" => FlowType::UnconditionalJump,
            "jal" | "jalr" | "bal" => FlowType::Call,
            "jr" => if ops.contains("ra") { FlowType::Return } else { FlowType::IndirectJump },
            "beq" | "bne" | "bgtz" | "blez" | "bgez" | "bltz" | "beqz" | "bnez" => FlowType::ConditionalJump,
            _ => FlowType::Fall,
        };
        Ok(DecodedInstruction {
            address, length: insn.bytes().len() as u32,
            mnemonic: mn, operands: ops,
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
    fn mips32_registers() {
        let arch = MipsArch::new(false, Endian::Little);
        assert_eq!(arch.bits(), 32);
        let sp = arch.register_by_name("sp").unwrap();
        assert_eq!(sp.varnode.size, 4);
        let ra = arch.register_by_name("ra").unwrap();
        assert_eq!(ra.varnode.offset, 31 * 4);
    }
    #[test]
    fn mips64_registers() {
        let arch = MipsArch::new(true, Endian::Little);
        assert_eq!(arch.bits(), 64);
        assert_eq!(arch.register_by_name("a0").unwrap().varnode.size, 8);
    }
}
