use std::path::Path;

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct PdbInfo {
    pub valid: bool,
    pub version: u32,
    pub age: u32,
    pub guid: Vec<u8>,
    pub functions: Vec<PdbFunction>,
    pub global_symbols: Vec<PdbSymbol>,
}

#[derive(Debug, Clone)]
pub struct PdbFunction {
    pub name: String,
    pub address: u64,
    pub size: u32,
    pub section: u16,
}

#[derive(Debug, Clone)]
pub struct PdbSymbol {
    pub name: String,
    pub address: u64,
    pub kind: PdbSymbolKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbSymbolKind {
    Function,
    Data,
    PublicSymbol,
    Label,
    Unknown,
}


const PDB_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

impl PdbInfo {
    pub fn probe(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("read: {}", e))?;
        Self::from_bytes(&data)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < PDB_MAGIC.len() + 4 {
            return Err("file too small for PDB".into());
        }

        if &data[..PDB_MAGIC.len()] != PDB_MAGIC {
            return Err("not a PDB 7.0 file".into());
        }

        let _page_size = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);

        Ok(PdbInfo {
            valid: true,
            version: 7,
            age: 0,
            guid: Vec::new(),
            functions: Vec::new(),
            global_symbols: Vec::new(),
        })
    }

    pub fn is_pdb_file(path: &Path) -> bool {
        if let Ok(data) = std::fs::read(path) {
            data.len() >= PDB_MAGIC.len() && &data[..PDB_MAGIC.len()] == PDB_MAGIC
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdb_magic_detection() {
        let mut data = PDB_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 100]);
        let info = PdbInfo::from_bytes(&data).unwrap();
        assert!(info.valid);
        assert_eq!(info.version, 7);
    }

    #[test]
    fn not_pdb() {
        let data = vec![0u8; 100];
        assert!(PdbInfo::from_bytes(&data).is_err());
    }
}
