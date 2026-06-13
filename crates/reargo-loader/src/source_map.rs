// Source file mapping for debug info integration.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct SourceFileEntry {
    pub file_path: String,
    pub compilation_dir: String,
    pub language: SourceLanguage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    C,
    Cpp,
    Rust,
    Go,
    Swift,
    ObjectiveC,
    Assembly,
    Unknown,
}

impl SourceLanguage {
    pub fn from_dwarf_lang(lang: u64) -> Self {
        match lang {
            0x01 | 0x02 => Self::C,
            0x04 | 0x21 => Self::Cpp,
            0x1C => Self::Rust,
            0x16 => Self::Go,
            0x1E => Self::Swift,
            0x10 | 0x11 => Self::ObjectiveC,
            0x8001 => Self::Assembly,
            _ => Self::Unknown,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Rust => "Rust",
            Self::Go => "Go",
            Self::Swift => "Swift",
            Self::ObjectiveC => "Objective-C",
            Self::Assembly => "Assembly",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Default)]
pub struct SourceMap {
    files: BTreeMap<String, SourceFileEntry>,
    address_to_file: BTreeMap<u64, String>,
}

impl SourceMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, path: impl Into<String>, entry: SourceFileEntry) {
        let p: String = path.into();
        self.files.insert(p, entry);
    }

    pub fn map_address(&mut self, address: u64, file_path: impl Into<String>) {
        self.address_to_file.insert(address, file_path.into());
    }

    pub fn file_at(&self, address: u64) -> Option<&SourceFileEntry> {
        self.address_to_file.range(..=address).next_back()
            .and_then(|(_, path)| self.files.get(path))
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn files(&self) -> impl Iterator<Item = (&str, &SourceFileEntry)> {
        self.files.iter().map(|(k, v)| (k.as_str(), v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_language_detection() {
        assert_eq!(SourceLanguage::from_dwarf_lang(0x01), SourceLanguage::C);
        assert_eq!(SourceLanguage::from_dwarf_lang(0x04), SourceLanguage::Cpp);
        assert_eq!(SourceLanguage::from_dwarf_lang(0x1C), SourceLanguage::Rust);
        assert_eq!(SourceLanguage::from_dwarf_lang(0x16), SourceLanguage::Go);
    }

    #[test]
    fn source_map_basic() {
        let mut map = SourceMap::new();
        map.add_file("main.c", SourceFileEntry {
            file_path: "main.c".into(),
            compilation_dir: "/src".into(),
            language: SourceLanguage::C,
        });
        map.map_address(0x1000, "main.c");
        let entry = map.file_at(0x1000).unwrap();
        assert_eq!(entry.language, SourceLanguage::C);
        assert_eq!(map.file_count(), 1);
    }
}
