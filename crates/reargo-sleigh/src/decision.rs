/// Decision tree for instruction pattern matching.
/// Each node examines specific bits from the instruction stream
/// and routes to child nodes or directly to constructors.

#[derive(Debug, Clone)]
pub struct DecisionNode {
    pub start_bit: u32,
    pub bit_size: u32,
    pub is_context: bool,
    pub patterns: Vec<PatternMatch>,
    pub children: Vec<DecisionNode>,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub mask: u64,
    pub value: u64,
    pub constructor_id: u32,
}

impl DecisionNode {
    pub fn leaf(constructor_id: u32) -> Self {
        Self {
            start_bit: 0,
            bit_size: 0,
            is_context: false,
            patterns: vec![PatternMatch {
                mask: 0,
                value: 0,
                constructor_id,
            }],
            children: Vec::new(),
        }
    }

    pub fn empty() -> Self {
        Self {
            start_bit: 0,
            bit_size: 0,
            is_context: false,
            patterns: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn resolve(&self, instruction_bytes: &[u8], _context: u64) -> Option<u32> {
        if self.bit_size == 0 {
            return self.patterns.first().map(|p| p.constructor_id);
        }

        let bits = extract_bits(instruction_bytes, self.start_bit, self.bit_size);

        for pattern in &self.patterns {
            if (bits & pattern.mask) == pattern.value {
                return Some(pattern.constructor_id);
            }
        }

        let child_index = bits as usize;
        if child_index < self.children.len() {
            return self.children[child_index].resolve(instruction_bytes, _context);
        }

        None
    }

    pub fn is_leaf(&self) -> bool {
        self.children.is_empty() && self.patterns.len() <= 1
    }

    pub fn pattern_count(&self) -> usize {
        let mut count = self.patterns.len();
        for child in &self.children {
            count += child.pattern_count();
        }
        count
    }
}

fn extract_bits(data: &[u8], start_bit: u32, size: u32) -> u64 {
    let mut result: u64 = 0;
    for i in 0..size {
        let bit_pos = start_bit + i;
        let byte_idx = (bit_pos / 8) as usize;
        let bit_idx = 7 - (bit_pos % 8);
        if byte_idx < data.len() {
            let bit = ((data[byte_idx] >> bit_idx) & 1) as u64;
            result = (result << 1) | bit;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bits_basic() {
        let data = [0b10110100u8, 0b01101001u8];
        assert_eq!(extract_bits(&data, 0, 4), 0b1011);
        assert_eq!(extract_bits(&data, 4, 4), 0b0100);
        assert_eq!(extract_bits(&data, 0, 8), 0b10110100);
    }

    #[test]
    fn leaf_node_resolves() {
        let node = DecisionNode::leaf(42);
        assert_eq!(node.resolve(&[0xFF], 0), Some(42));
    }

    #[test]
    fn pattern_match() {
        let node = DecisionNode {
            start_bit: 0,
            bit_size: 8,
            is_context: false,
            patterns: vec![
                PatternMatch { mask: 0xF0, value: 0x90, constructor_id: 1 },
                PatternMatch { mask: 0xFF, value: 0xC3, constructor_id: 2 },
            ],
            children: Vec::new(),
        };
        assert_eq!(node.resolve(&[0x90], 0), Some(1));
        assert_eq!(node.resolve(&[0xC3], 0), Some(2));
        assert_eq!(node.resolve(&[0x00], 0), None);
    }

    #[test]
    fn pattern_count() {
        let mut node = DecisionNode::empty();
        node.patterns.push(PatternMatch { mask: 0, value: 0, constructor_id: 1 });
        let child = DecisionNode::leaf(2);
        node.children.push(child);
        assert_eq!(node.pattern_count(), 2);
    }
}
