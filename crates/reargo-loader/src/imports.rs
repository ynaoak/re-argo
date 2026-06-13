// Import/export table management for all binary formats.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ImportedFunction {
    pub name: String,
    pub library: String,
    pub ordinal: Option<u32>,
    pub address: u64,
    pub thunk_address: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ExportedFunction {
    pub name: String,
    pub ordinal: u32,
    pub address: u64,
    pub is_forwarder: bool,
    pub forwarder_name: Option<String>,
}

#[derive(Debug, Default)]
pub struct ImportExportTable {
    imports: BTreeMap<u64, ImportedFunction>,
    exports: BTreeMap<u64, ExportedFunction>,
    import_libs: Vec<String>,
}

impl ImportExportTable {
    pub fn new() -> Self { Self::default() }

    pub fn add_import(&mut self, func: ImportedFunction) {
        if !self.import_libs.contains(&func.library) {
            self.import_libs.push(func.library.clone());
        }
        self.imports.insert(func.address, func);
    }

    pub fn add_export(&mut self, func: ExportedFunction) {
        self.exports.insert(func.address, func);
    }

    pub fn import_at(&self, address: u64) -> Option<&ImportedFunction> {
        self.imports.get(&address)
    }

    pub fn export_at(&self, address: u64) -> Option<&ExportedFunction> {
        self.exports.get(&address)
    }

    pub fn import_by_name(&self, name: &str) -> Option<&ImportedFunction> {
        self.imports.values().find(|f| f.name == name)
    }

    pub fn imports(&self) -> impl Iterator<Item = &ImportedFunction> {
        self.imports.values()
    }

    pub fn exports(&self) -> impl Iterator<Item = &ExportedFunction> {
        self.exports.values()
    }

    pub fn import_count(&self) -> usize { self.imports.len() }
    pub fn export_count(&self) -> usize { self.exports.len() }
    pub fn imported_libraries(&self) -> &[String] { &self.import_libs }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_export_table() {
        let mut table = ImportExportTable::new();
        table.add_import(ImportedFunction {
            name: "printf".into(), library: "libc.so.6".into(),
            ordinal: None, address: 0x1000, thunk_address: Some(0x2000),
        });
        table.add_export(ExportedFunction {
            name: "main".into(), ordinal: 0, address: 0x3000,
            is_forwarder: false, forwarder_name: None,
        });
        assert_eq!(table.import_count(), 1);
        assert_eq!(table.export_count(), 1);
        assert_eq!(table.import_by_name("printf").unwrap().library, "libc.so.6");
        assert_eq!(table.imported_libraries(), &["libc.so.6"]);
    }
}
