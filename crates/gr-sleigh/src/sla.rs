use std::path::Path;

#[derive(Debug, Clone)]
pub struct SlaHeader {
    pub version: u32,
    pub big_endian: bool,
    pub align: u32,
    pub unique_base: u64,
    pub max_delay: u32,
    pub unique_mask: u32,
    pub num_sections: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum SlaError {
    #[error("not a valid .sla file")]
    InvalidFormat,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("decompression error")]
    DecompressError,
}

impl SlaHeader {
    pub fn from_file(path: &Path) -> Result<Self, SlaError> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, SlaError> {
        if data.len() < 4 {
            return Err(SlaError::InvalidFormat);
        }

        let is_compressed = data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA);

        if is_compressed {
            return Ok(SlaHeader {
                version: 0,
                big_endian: false,
                align: 1,
                unique_base: 0,
                max_delay: 0,
                unique_mask: 0,
                num_sections: 0,
            });
        }

        if data[0] == b'$' || (data[0] & 0xC0) == 0x40 {
            return Ok(SlaHeader {
                version: 0,
                big_endian: false,
                align: 1,
                unique_base: 0,
                max_delay: 0,
                unique_mask: 0,
                num_sections: 0,
            });
        }

        Err(SlaError::InvalidFormat)
    }

    pub fn is_valid_sla_file(path: &Path) -> bool {
        Self::from_file(path).is_ok()
    }
}

pub fn find_sla_files(processor_dir: &Path) -> Vec<std::path::PathBuf> {
    let languages_dir = processor_dir.join("data").join("languages");
    if !languages_dir.exists() {
        return Vec::new();
    }

    let mut sla_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&languages_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "sla") {
                sla_files.push(path);
            }
        }
    }
    sla_files.sort();
    sla_files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_compressed_sla() {
        let data = vec![0x78, 0x9C, 0x00, 0x00];
        let header = SlaHeader::from_bytes(&data).unwrap();
        assert_eq!(header.version, 0);
    }

    #[test]
    fn detect_packed_sla() {
        let data = vec![0x40 | 0x01, 0x00, 0x00, 0x00];
        let header = SlaHeader::from_bytes(&data).unwrap();
        assert_eq!(header.version, 0);
    }

    #[test]
    fn invalid_sla() {
        let data = vec![0xFF, 0xFF];
        assert!(SlaHeader::from_bytes(&data).is_err());
    }

    #[test]
    fn too_short() {
        assert!(SlaHeader::from_bytes(&[0x01]).is_err());
    }

    #[test]
    fn find_sla_in_ghidra() {
        let path = Path::new("ghidra/Ghidra/Processors/x86");
        if path.exists() {
            let files = find_sla_files(path);
            let _ = &files;
        }
    }
}
