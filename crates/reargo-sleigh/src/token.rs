/// SLEIGH token definitions - instruction bit fields.

#[derive(Debug, Clone)]
pub struct TokenField {
    pub name: String,
    pub token_index: u32,
    pub bit_start: u32,
    pub bit_end: u32,
    pub signed: bool,
    pub hex_display: bool,
}

impl TokenField {
    pub fn bit_size(&self) -> u32 {
        self.bit_end - self.bit_start + 1
    }

    pub fn extract(&self, data: &[u8]) -> u64 {
        let mut val: u64 = 0;
        for bit in self.bit_start..=self.bit_end {
            let byte_idx = (bit / 8) as usize;
            let bit_idx = 7 - (bit % 8);
            if byte_idx < data.len() {
                val = (val << 1) | ((data[byte_idx] >> bit_idx) as u64 & 1);
            }
        }
        if self.signed && val & (1u64 << (self.bit_size() - 1)) != 0 {
            val |= !((1u64 << self.bit_size()) - 1);
        }
        val
    }
}

#[derive(Debug, Clone)]
pub struct TokenDef {
    pub name: String,
    pub size: u32,
    pub big_endian: bool,
    pub fields: Vec<TokenField>,
}

impl TokenDef {
    pub fn byte_size(&self) -> u32 {
        self.size
    }

    pub fn get_field(&self, name: &str) -> Option<&TokenField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_field() {
        let field = TokenField {
            name: "opcode".into(),
            token_index: 0,
            bit_start: 0,
            bit_end: 7,
            signed: false,
            hex_display: true,
        };
        assert_eq!(field.bit_size(), 8);
        assert_eq!(field.extract(&[0x90]), 0x90);
    }

    #[test]
    fn extract_partial_field() {
        let field = TokenField {
            name: "reg".into(),
            token_index: 0,
            bit_start: 0,
            bit_end: 2,
            signed: false,
            hex_display: false,
        };
        assert_eq!(field.bit_size(), 3);
        assert_eq!(field.extract(&[0b10110000]), 0b101);
    }

    #[test]
    fn signed_field() {
        let field = TokenField {
            name: "imm".into(),
            token_index: 0,
            bit_start: 0,
            bit_end: 7,
            signed: true,
            hex_display: false,
        };
        let val = field.extract(&[0xFF]);
        assert_eq!(val as i64, -1);
    }
}
