// PE format extra features: exception tables, TLS, rich header.

#[derive(Debug, Clone)]
pub struct ExceptionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info: u32,
}

#[derive(Debug, Default)]
pub struct PeExtraInfo {
    pub exceptions: Vec<ExceptionEntry>,
    pub tls_callbacks: Vec<u64>,
    pub rich_header: Option<RichHeader>,
    pub is_dot_net: bool,
}

#[derive(Debug, Clone)]
pub struct RichHeader {
    pub entries: Vec<RichEntry>,
    pub checksum: u32,
}

#[derive(Debug, Clone)]
pub struct RichEntry {
    pub comp_id: u32,
    pub count: u32,
    pub product: String,
}

impl PeExtraInfo {
    pub fn parse_exceptions(data: &[u8], _rva: u32, size: u32) -> Vec<ExceptionEntry> {
        let mut entries = Vec::new();
        let entry_size = 12u32;
        let count = size / entry_size;

        for i in 0..count {
            let offset = (i * entry_size) as usize;
            if offset + 12 > data.len() {
                break;
            }
            entries.push(ExceptionEntry {
                begin_address: u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]),
                end_address: u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]),
                unwind_info: u32::from_le_bytes([data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]]),
            });
        }
        entries
    }

    pub fn function_starts(&self) -> Vec<u64> {
        self.exceptions.iter().map(|e| e.begin_address as u64).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exception_entries() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x1100u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        data[12..16].copy_from_slice(&0x1100u32.to_le_bytes());
        data[16..20].copy_from_slice(&0x1200u32.to_le_bytes());
        data[20..24].copy_from_slice(&0x2010u32.to_le_bytes());

        let entries = PeExtraInfo::parse_exceptions(&data, 0, 24);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].begin_address, 0x1000);
        assert_eq!(entries[1].begin_address, 0x1100);
    }

    #[test]
    fn function_starts_from_exceptions() {
        let info = PeExtraInfo {
            exceptions: vec![
                ExceptionEntry { begin_address: 0x1000, end_address: 0x1100, unwind_info: 0 },
                ExceptionEntry { begin_address: 0x2000, end_address: 0x2200, unwind_info: 0 },
            ],
            ..Default::default()
        };
        let starts = info.function_starts();
        assert_eq!(starts, vec![0x1000, 0x2000]);
    }
}
