// COFF (Common Object File Format) support.

#[derive(Debug, Clone)]
pub struct CoffHeader {
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: u32,
    pub symbol_table_offset: u32,
    pub num_symbols: u32,
    pub optional_header_size: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone)]
pub struct CoffSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_offset: u32,
    pub characteristics: u32,
}

impl CoffSection {
    pub fn is_code(&self) -> bool { self.characteristics & 0x20 != 0 }
    pub fn is_data(&self) -> bool { self.characteristics & 0x40 != 0 }
    pub fn is_bss(&self) -> bool { self.characteristics & 0x80 != 0 }
    pub fn is_readable(&self) -> bool { self.characteristics & 0x40000000 != 0 }
    pub fn is_writable(&self) -> bool { self.characteristics & 0x80000000 != 0 }
    pub fn is_executable(&self) -> bool { self.characteristics & 0x20000000 != 0 }
}

impl CoffHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 { return None; }
        Some(Self {
            machine: u16::from_le_bytes([data[0], data[1]]),
            num_sections: u16::from_le_bytes([data[2], data[3]]),
            timestamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            symbol_table_offset: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            num_symbols: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            optional_header_size: u16::from_le_bytes([data[16], data[17]]),
            characteristics: u16::from_le_bytes([data[18], data[19]]),
        })
    }

    pub fn is_x86(&self) -> bool { self.machine == 0x14C }
    pub fn is_x64(&self) -> bool { self.machine == 0x8664 }
    pub fn is_arm(&self) -> bool { self.machine == 0x1C0 }
    pub fn is_arm64(&self) -> bool { self.machine == 0xAA64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_coff_header() {
        let mut data = vec![0u8; 20];
        data[0..2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
        data[2..4].copy_from_slice(&5u16.to_le_bytes()); // 5 sections
        let header = CoffHeader::parse(&data).unwrap();
        assert!(header.is_x64());
        assert_eq!(header.num_sections, 5);
    }

    #[test]
    fn section_flags() {
        let section = CoffSection {
            name: ".text".into(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            raw_data_size: 0x1000,
            raw_data_offset: 0x200,
            characteristics: 0x60000020, // code + readable + executable
        };
        assert!(section.is_code());
        assert!(section.is_readable());
        assert!(section.is_executable());
        assert!(!section.is_writable());
    }
}
