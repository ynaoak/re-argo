use reargo_core::pcode::PcodeOp;

#[derive(Debug, Clone)]
pub struct SleighInstruction {
    pub address: u64,
    pub length: u32,
    pub mnemonic: String,
    pub constructor_id: u32,
    pub operands: Vec<OperandValue>,
    pub pcode: Vec<PcodeOp>,
    pub delay_slot_length: u32,
}

#[derive(Debug, Clone)]
pub enum OperandValue {
    Register(String),
    Immediate(u64),
    Address(u64),
    Expression(String),
}

impl SleighInstruction {
    pub fn has_delay_slot(&self) -> bool {
        self.delay_slot_length > 0
    }

    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }

    pub fn is_branch(&self) -> bool {
        self.pcode.iter().any(|op| matches!(
            op.opcode,
            reargo_core::pcode::OpCode::Branch | reargo_core::pcode::OpCode::CBranch
            | reargo_core::pcode::OpCode::BranchInd
        ))
    }

    pub fn is_call(&self) -> bool {
        self.pcode.iter().any(|op| matches!(
            op.opcode,
            reargo_core::pcode::OpCode::Call | reargo_core::pcode::OpCode::CallInd
        ))
    }

    pub fn is_return(&self) -> bool {
        self.pcode.iter().any(|op| op.opcode == reargo_core::pcode::OpCode::Return)
    }
}

impl std::fmt::Display for SleighInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}: {} ({} bytes, {} p-code ops)",
            self.address, self.mnemonic, self.length, self.pcode.len())
    }
}

impl std::fmt::Display for OperandValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register(name) => write!(f, "{}", name),
            Self::Immediate(val) => write!(f, "0x{:x}", val),
            Self::Address(addr) => write!(f, "[0x{:x}]", addr),
            Self::Expression(expr) => write!(f, "{}", expr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleigh_instruction_basic() {
        let insn = SleighInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "MOV".into(),
            constructor_id: 1,
            operands: vec![
                OperandValue::Register("RAX".into()),
                OperandValue::Immediate(42),
            ],
            pcode: Vec::new(),
            delay_slot_length: 0,
        };
        assert_eq!(insn.end_address(), 0x1004);
        assert!(!insn.has_delay_slot());
        assert!(!insn.is_branch());
    }
}
