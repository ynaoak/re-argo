// SLEIGH ParserWalker: instruction tree traversal for P-code generation.


#[derive(Debug, Clone)]
pub struct ConstructState {
    pub constructor_id: u32,
    pub offset: u32,
    pub length: u32,
    pub operand_values: Vec<ResolvedOperand>,
    pub children: Vec<ConstructState>,
}

#[derive(Debug, Clone)]
pub struct ResolvedOperand {
    pub value: u64,
    pub is_register: bool,
    pub register_name: Option<String>,
    pub size: u32,
}

pub struct ParserWalker {
    pub instruction_bytes: Vec<u8>,
    pub address: u64,
    pub context: u64,
    pub root: Option<ConstructState>,
}

impl ParserWalker {
    pub fn new(bytes: &[u8], address: u64, context: u64) -> Self {
        Self {
            instruction_bytes: bytes.to_vec(),
            address,
            context,
            root: None,
        }
    }

    pub fn set_root(&mut self, state: ConstructState) {
        self.root = Some(state);
    }

    pub fn instruction_length(&self) -> u32 {
        self.root.as_ref().map(|r| r.length).unwrap_or(0)
    }

    pub fn get_byte(&self, offset: usize) -> u8 {
        self.instruction_bytes.get(offset).copied().unwrap_or(0)
    }

    pub fn get_bytes(&self, offset: usize, count: usize) -> &[u8] {
        let end = (offset + count).min(self.instruction_bytes.len());
        &self.instruction_bytes[offset..end]
    }

    pub fn extract_bits(&self, bit_start: u32, bit_size: u32) -> u64 {
        let mut val: u64 = 0;
        for i in 0..bit_size {
            let pos = bit_start + i;
            let byte_idx = (pos / 8) as usize;
            let bit_idx = 7 - (pos % 8);
            if byte_idx < self.instruction_bytes.len() {
                val = (val << 1) | ((self.instruction_bytes[byte_idx] >> bit_idx) as u64 & 1);
            }
        }
        val
    }

    pub fn next_address(&self) -> u64 {
        self.address + self.instruction_length() as u64
    }
}

impl ConstructState {
    pub fn leaf(constructor_id: u32, length: u32) -> Self {
        Self {
            constructor_id,
            offset: 0,
            length,
            operand_values: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn operand_count(&self) -> usize {
        self.operand_values.len()
    }

    pub fn total_length(&self) -> u32 {
        let child_len: u32 = self.children.iter().map(|c| c.total_length()).sum();
        self.length.max(child_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_walker_basic() {
        let walker = ParserWalker::new(&[0x55, 0x48, 0x89, 0xE5], 0x1000, 0);
        assert_eq!(walker.get_byte(0), 0x55);
        assert_eq!(walker.get_byte(3), 0xE5);
        assert_eq!(walker.get_byte(10), 0);
    }

    #[test]
    fn extract_bits() {
        let walker = ParserWalker::new(&[0b10110100, 0b01101001], 0x1000, 0);
        assert_eq!(walker.extract_bits(0, 4), 0b1011);
        assert_eq!(walker.extract_bits(0, 8), 0b10110100);
    }

    #[test]
    fn construct_state_tree() {
        let mut root = ConstructState::leaf(1, 4);
        root.children.push(ConstructState::leaf(2, 2));
        root.children.push(ConstructState::leaf(3, 1));
        assert_eq!(root.total_length(), 4);
        assert_eq!(root.children.len(), 2);
    }

    #[test]
    fn next_address() {
        let mut walker = ParserWalker::new(&[0x90], 0x1000, 0);
        walker.set_root(ConstructState::leaf(1, 1));
        assert_eq!(walker.next_address(), 0x1001);
    }
}
