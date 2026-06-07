use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Program;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectSummary {
    pub name: String,
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub entry_point: u64,
    pub functions: Vec<FunctionSummary>,
    pub symbols: Vec<SymbolSummary>,
    pub references: Vec<ReferenceSummary>,
    pub references_count: usize,
    pub instructions_count: usize,
    pub has_dwarf: bool,
    pub dwarf_functions: usize,
    pub analyzers_run: Vec<String>,
    pub version: String,
    pub dynamic_libs: Vec<String>,
    pub import_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceSummary {
    pub from: u64,
    pub to: u64,
    pub ref_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub address: u64,
    pub name: String,
    pub block_count: usize,
    pub call_count: usize,
    pub stack_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolSummary {
    pub address: u64,
    pub name: String,
    pub kind: String,
}

impl ProjectSummary {
    pub fn from_program(program: &Program) -> Self {
        let functions = program
            .listing
            .functions()
            .map(|f| FunctionSummary {
                address: f.entry_point,
                name: f.name.clone(),
                block_count: f.body.len(),
                call_count: f.call_targets.len(),
                stack_size: f.stack_frame.local_size,
            })
            .collect();

        let symbols = program
            .symbol_table
            .iter()
            .take(10000)
            .map(|s| SymbolSummary {
                address: s.address,
                name: s.name.clone(),
                kind: format!("{:?}", s.symbol_type),
            })
            .collect();

        let references = program
            .references
            .all_refs()
            .take(5000)
            .map(|r| ReferenceSummary {
                from: r.from,
                to: r.to,
                ref_type: format!("{}", r.ref_type),
            })
            .collect();

        Self {
            name: program.name.clone(),
            format: format!("{}", program.info.format),
            arch: format!("{}", program.info.arch),
            bits: program.info.bits,
            entry_point: program.entry_point(),
            functions,
            symbols,
            references,
            references_count: program.references.len(),
            instructions_count: program.listing.instruction_count(),
            has_dwarf: program.has_dwarf(),
            dwarf_functions: program.dwarf_function_count(),
            analyzers_run: Vec::new(),
            version: "0.1.0".into(),
            dynamic_libs: program.info.dynamic.needed_libs.clone(),
            import_count: program.info.imports.len(),
        }
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(path, json).map_err(|e| format!("write: {}", e))
    }

    pub fn save_compact(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string(self)
            .map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(path, json).map_err(|e| format!("write: {}", e))
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("read: {}", e))?;
        let json = std::str::from_utf8(&data).map_err(|e| format!("utf8: {}", e))?;
        serde_json::from_str(json).map_err(|e| format!("deserialize: {}", e))
    }

    pub fn merge(&mut self, other: &ProjectSummary) {
        let existing_funcs: std::collections::HashSet<u64> =
            self.functions.iter().map(|f| f.address).collect();
        for func in &other.functions {
            if !existing_funcs.contains(&func.address) {
                self.functions.push(func.clone());
            }
        }
        let existing_syms: std::collections::HashSet<u64> =
            self.symbols.iter().map(|s| s.address).collect();
        for sym in &other.symbols {
            if !existing_syms.contains(&sym.address) {
                self.symbols.push(sym.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_summary() {
        let summary = ProjectSummary {
            name: "test.exe".into(),
            format: "PE".into(),
            arch: "x86_64".into(),
            bits: 64,
            entry_point: 0x1000,
            functions: vec![FunctionSummary {
                address: 0x1000,
                name: "main".into(),
                block_count: 3,
                call_count: 2,
                stack_size: 0x28,
            }],
            symbols: vec![SymbolSummary {
                address: 0x2000,
                name: "printf".into(),
                kind: "ExternalFunction".into(),
            }],
            references: vec![ReferenceSummary {
                from: 0x1000,
                to: 0x2000,
                ref_type: "CALL".into(),
            }],
            references_count: 42,
            instructions_count: 100,
            has_dwarf: false,
            dwarf_functions: 0,
            analyzers_run: vec!["FunctionDiscovery".into()],
            version: "0.1.0".into(),
            dynamic_libs: vec!["libc.so.6".into()],
            import_count: 5,
        };

        let json = serde_json::to_string_pretty(&summary).unwrap();
        let loaded: ProjectSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.name, "test.exe");
        assert_eq!(loaded.functions.len(), 1);
        assert_eq!(loaded.functions[0].name, "main");
    }
}
