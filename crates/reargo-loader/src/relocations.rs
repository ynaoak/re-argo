use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Relocation {
    pub address: u64,
    pub symbol_name: String,
    pub reloc_type: RelocationType,
    pub addend: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    Absolute,
    Relative,
    GotEntry,
    PltEntry,
    TlsOffset,
    Copy,
    JumpSlot,
    Other(u32),
}

impl std::fmt::Display for RelocationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absolute => write!(f, "ABS"),
            Self::Relative => write!(f, "REL"),
            Self::GotEntry => write!(f, "GOT"),
            Self::PltEntry => write!(f, "PLT"),
            Self::TlsOffset => write!(f, "TLS"),
            Self::Copy => write!(f, "COPY"),
            Self::JumpSlot => write!(f, "JMPSLOT"),
            Self::Other(n) => write!(f, "TYPE({})", n),
        }
    }
}

#[derive(Debug, Default)]
pub struct RelocationTable {
    relocations: BTreeMap<u64, Relocation>,
}

impl RelocationTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, reloc: Relocation) {
        self.relocations.insert(reloc.address, reloc);
    }

    pub fn get(&self, address: u64) -> Option<&Relocation> {
        self.relocations.get(&address)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Relocation> {
        self.relocations.values()
    }

    pub fn len(&self) -> usize {
        self.relocations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relocations.is_empty()
    }

    pub fn by_type(&self, rtype: RelocationType) -> Vec<&Relocation> {
        self.relocations.values().filter(|r| r.reloc_type == rtype).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relocation_table() {
        let mut table = RelocationTable::new();
        table.add(Relocation {
            address: 0x1000,
            symbol_name: "printf".into(),
            reloc_type: RelocationType::JumpSlot,
            addend: 0,
        });
        table.add(Relocation {
            address: 0x2000,
            symbol_name: "data".into(),
            reloc_type: RelocationType::Absolute,
            addend: 4,
        });
        assert_eq!(table.len(), 2);
        assert_eq!(table.get(0x1000).unwrap().symbol_name, "printf");
        assert_eq!(table.by_type(RelocationType::JumpSlot).len(), 1);
    }
}
