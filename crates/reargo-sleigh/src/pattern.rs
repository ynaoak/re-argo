// SLEIGH pattern matching: DisjointPattern, InstructionPattern.

#[derive(Debug, Clone)]
pub struct PatternBlock {
    pub offset: u32,
    pub mask: Vec<u8>,
    pub value: Vec<u8>,
}

impl PatternBlock {
    pub fn new(offset: u32, mask: Vec<u8>, value: Vec<u8>) -> Self {
        Self { offset, mask, value }
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        let start = self.offset as usize;
        for (i, (&m, &v)) in self.mask.iter().zip(self.value.iter()).enumerate() {
            let idx = start + i;
            if idx >= data.len() { return false; }
            if (data[idx] & m) != (v & m) { return false; }
        }
        true
    }

    pub fn byte_length(&self) -> usize {
        self.mask.len()
    }
}

#[derive(Debug, Clone)]
pub struct CombinedPattern {
    pub instruction_patterns: Vec<PatternBlock>,
    pub context_patterns: Vec<PatternBlock>,
}

impl CombinedPattern {
    pub fn empty() -> Self {
        Self { instruction_patterns: Vec::new(), context_patterns: Vec::new() }
    }

    pub fn matches_instruction(&self, bytes: &[u8]) -> bool {
        self.instruction_patterns.iter().all(|p| p.matches(bytes))
    }

    pub fn matches_context(&self, context_bytes: &[u8]) -> bool {
        self.context_patterns.iter().all(|p| p.matches(context_bytes))
    }

    pub fn matches(&self, inst_bytes: &[u8], ctx_bytes: &[u8]) -> bool {
        self.matches_instruction(inst_bytes) && self.matches_context(ctx_bytes)
    }

    pub fn minimum_length(&self) -> usize {
        self.instruction_patterns.iter()
            .map(|p| p.offset as usize + p.byte_length())
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct PatternEquation {
    pub token_field: String,
    pub value: u64,
    pub mask: u64,
}

impl PatternEquation {
    pub fn matches(&self, extracted: u64) -> bool {
        (extracted & self.mask) == (self.value & self.mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_block_matches() {
        let block = PatternBlock::new(0, vec![0xFF, 0xF0], vec![0x55, 0x40]);
        assert!(block.matches(&[0x55, 0x48, 0x89]));
        assert!(!block.matches(&[0x56, 0x48, 0x89]));
    }

    #[test]
    fn combined_pattern() {
        let mut pat = CombinedPattern::empty();
        pat.instruction_patterns.push(PatternBlock::new(0, vec![0xFF], vec![0x90]));
        assert!(pat.matches_instruction(&[0x90]));
        assert!(!pat.matches_instruction(&[0xC3]));
        assert_eq!(pat.minimum_length(), 1);
    }

    #[test]
    fn pattern_equation() {
        let eq = PatternEquation { token_field: "opcode".into(), value: 0x0F, mask: 0xFF };
        assert!(eq.matches(0x0F));
        assert!(!eq.matches(0x10));
    }
}
