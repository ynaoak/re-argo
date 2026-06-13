// Program metadata: format info, analysis settings, user preferences.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramMetadata {
    pub original_file: String,
    pub file_size: u64,
    pub file_hash: String,
    pub creation_time: String,
    pub last_modified: String,
    pub analysis_version: String,
    pub properties: BTreeMap<String, String>,
}

impl ProgramMetadata {
    pub fn new(file: impl Into<String>, size: u64, hash: impl Into<String>) -> Self {
        Self {
            original_file: file.into(),
            file_size: size,
            file_hash: hash.into(),
            creation_time: String::new(),
            last_modified: String::new(),
            analysis_version: env!("CARGO_PKG_VERSION").into(),
            properties: BTreeMap::new(),
        }
    }

    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    pub fn set_compiler(&mut self, compiler: impl Into<String>) {
        self.set_property("compiler", compiler);
    }

    pub fn set_language(&mut self, language: impl Into<String>) {
        self.set_property("language", language);
    }
}

impl Default for ProgramMetadata {
    fn default() -> Self {
        Self::new("", 0, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_basic() {
        let mut meta = ProgramMetadata::new("test.exe", 1024, "abc123");
        meta.set_compiler("gcc 12.0");
        meta.set_language("C");
        assert_eq!(meta.get_property("compiler"), Some("gcc 12.0"));
        assert_eq!(meta.get_property("language"), Some("C"));
        assert_eq!(meta.file_size, 1024);
    }

    #[test]
    fn metadata_serialization() {
        let meta = ProgramMetadata::new("test.elf", 2048, "deadbeef");
        let json = serde_json::to_string(&meta).unwrap();
        let loaded: ProgramMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.original_file, "test.elf");
        assert_eq!(loaded.file_hash, "deadbeef");
    }
}
