use crate::context::ContextDatabase;
use crate::decision::DecisionNode;
use crate::symbol::SymbolTable;

pub struct SleighDisassembler {
    pub symbol_table: SymbolTable,
    pub context: ContextDatabase,
    pub root_decision: DecisionNode,
    pub big_endian: bool,
    pub alignment: u32,
}

impl SleighDisassembler {
    pub fn new(big_endian: bool, alignment: u32) -> Self {
        Self {
            symbol_table: SymbolTable::new(),
            context: ContextDatabase::new(),
            root_decision: DecisionNode::empty(),
            big_endian,
            alignment,
        }
    }

    pub fn decode_at(&self, bytes: &[u8], address: u64) -> Option<DecodedSleigh> {
        let context = self.context.get_context(address);
        let constructor_id = self.root_decision.resolve(bytes, context)?;

        Some(DecodedSleigh {
            address,
            constructor_id,
            length: self.alignment.max(1),
            context,
        })
    }

    pub fn set_context(&mut self, address: u64, field: &str, value: u64) {
        self.context.set_field_at(address, field, value);
    }
}

#[derive(Debug, Clone)]
pub struct DecodedSleigh {
    pub address: u64,
    pub constructor_id: u32,
    pub length: u32,
    pub context: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{DecisionNode, PatternMatch};

    #[test]
    fn basic_decode() {
        let mut disasm = SleighDisassembler::new(false, 1);
        disasm.root_decision = DecisionNode {
            start_bit: 0,
            bit_size: 8,
            is_context: false,
            patterns: vec![
                PatternMatch { mask: 0xFF, value: 0x90, constructor_id: 1 },
                PatternMatch { mask: 0xFF, value: 0xC3, constructor_id: 2 },
            ],
            children: Vec::new(),
        };

        let nop = disasm.decode_at(&[0x90], 0x1000);
        assert_eq!(nop.unwrap().constructor_id, 1);

        let ret = disasm.decode_at(&[0xC3], 0x1000);
        assert_eq!(ret.unwrap().constructor_id, 2);
    }
}
