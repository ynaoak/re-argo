// FLIRT (Fast Library Identification and Recognition Technology) pattern matching.

#[derive(Debug, Clone)]
pub struct FlirtPattern {
    pub bytes: Vec<u8>,
    pub mask: Vec<u8>,
    pub name: String,
    pub offset: u32,
    pub total_length: u32,
}

impl FlirtPattern {
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }
        for (i, (&pat, &mask)) in self.bytes.iter().zip(self.mask.iter()).enumerate() {
            if mask != 0 && (data[i] & mask) != (pat & mask) {
                return false;
            }
        }
        true
    }

    pub fn from_hex_pattern(hex: &str, name: &str) -> Option<Self> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        let chars: Vec<char> = hex.chars().collect();
        let mut i = 0;

        while i + 1 < chars.len() {
            if chars[i] == '.' && chars[i + 1] == '.' {
                bytes.push(0);
                mask.push(0);
            } else {
                let high = chars[i].to_digit(16)?;
                let low = chars[i + 1].to_digit(16)?;
                bytes.push((high * 16 + low) as u8);
                mask.push(0xFF);
            }
            i += 2;
        }

        Some(Self {
            bytes,
            mask,
            name: name.into(),
            offset: 0,
            total_length: 0,
        })
    }
}

#[derive(Debug, Default)]
pub struct FlirtDatabase {
    patterns: Vec<FlirtPattern>,
}

impl FlirtDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, pattern: FlirtPattern) {
        self.patterns.push(pattern);
    }

    pub fn scan(&self, data: &[u8], base_address: u64) -> Vec<(u64, &str)> {
        let mut matches = Vec::new();
        for offset in 0..data.len() {
            for pat in &self.patterns {
                if pat.matches(&data[offset..]) {
                    matches.push((base_address + offset as u64, pat.name.as_str()));
                }
            }
        }
        matches
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_match() {
        let pat = FlirtPattern::from_hex_pattern("554889E5", "prologue").unwrap();
        assert!(pat.matches(&[0x55, 0x48, 0x89, 0xE5]));
        assert!(!pat.matches(&[0x55, 0x48, 0x89, 0x00]));
    }

    #[test]
    fn pattern_wildcard() {
        let pat = FlirtPattern::from_hex_pattern("55..89E5", "prologue_wild").unwrap();
        assert!(pat.matches(&[0x55, 0xFF, 0x89, 0xE5]));
        assert!(pat.matches(&[0x55, 0x00, 0x89, 0xE5]));
    }

    #[test]
    fn scan_data() {
        let mut db = FlirtDatabase::new();
        db.add(FlirtPattern::from_hex_pattern("554889E5", "func_start").unwrap());
        let data = [0x90, 0x90, 0x55, 0x48, 0x89, 0xE5, 0x90];
        let matches = db.scan(&data, 0x1000);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, 0x1002);
        assert_eq!(matches[0].1, "func_start");
    }
}
