use std::collections::BTreeMap;

use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<(String, String)>,
    pub calling_convention: Option<String>,
    pub library: String,
}

#[derive(Debug, Default)]
pub struct SignatureDatabase {
    by_pattern: BTreeMap<Vec<u8>, FunctionSignature>,
    by_name: BTreeMap<String, FunctionSignature>,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        let mut db = Self::default();
        db.load_builtins();
        db
    }

    fn load_builtins(&mut self) {
        let libc_sigs = [
            ("printf", "int", &[("format", "const char*")][..], "libc"),
            ("puts", "int", &[("s", "const char*")], "libc"),
            ("malloc", "void*", &[("size", "size_t")], "libc"),
            ("free", "void", &[("ptr", "void*")], "libc"),
            ("memcpy", "void*", &[("dst", "void*"), ("src", "const void*"), ("n", "size_t")], "libc"),
            ("memset", "void*", &[("s", "void*"), ("c", "int"), ("n", "size_t")], "libc"),
            ("strlen", "size_t", &[("s", "const char*")], "libc"),
            ("strcmp", "int", &[("s1", "const char*"), ("s2", "const char*")], "libc"),
            ("strcpy", "char*", &[("dst", "char*"), ("src", "const char*")], "libc"),
            ("fopen", "FILE*", &[("path", "const char*"), ("mode", "const char*")], "libc"),
            ("fclose", "int", &[("fp", "FILE*")], "libc"),
            ("fread", "size_t", &[("buf", "void*"), ("size", "size_t"), ("count", "size_t"), ("fp", "FILE*")], "libc"),
            ("fwrite", "size_t", &[("buf", "const void*"), ("size", "size_t"), ("count", "size_t"), ("fp", "FILE*")], "libc"),
            ("exit", "void", &[("status", "int")], "libc"),
            ("abort", "void", &[], "libc"),
            ("atoi", "int", &[("s", "const char*")], "libc"),
            ("getenv", "char*", &[("name", "const char*")], "libc"),
        ];

        for (name, ret, params, lib) in &libc_sigs {
            let sig = FunctionSignature {
                name: name.to_string(),
                return_type: ret.to_string(),
                parameters: params.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect(),
                calling_convention: None,
                library: lib.to_string(),
            };
            self.by_name.insert(name.to_string(), sig);
        }
    }

    pub fn lookup_by_name(&self, name: &str) -> Option<&FunctionSignature> {
        let clean = name.strip_suffix("@plt").unwrap_or(name);
        self.by_name.get(clean)
    }

    pub fn add_pattern(&mut self, pattern: Vec<u8>, sig: FunctionSignature) {
        self.by_pattern.insert(pattern, sig);
    }

    pub fn signature_count(&self) -> usize {
        self.by_name.len() + self.by_pattern.len()
    }
}

pub struct SignatureApplierAnalyzer;

impl Analyzer for SignatureApplierAnalyzer {
    fn name(&self) -> &str {
        "Signature Applier"
    }
    fn description(&self) -> &str {
        "Applies known function signatures from the signature database"
    }
    fn priority(&self) -> u32 {
        700
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let db = SignatureDatabase::new();
        let mut applied = 0;

        let symbol_names: Vec<(u64, String)> = program
            .symbol_table
            .iter()
            .map(|s| (s.address, s.name.clone()))
            .collect();

        for (addr, name) in &symbol_names {
            if let Some(_sig) = db.lookup_by_name(name) {
                if program.symbol_table.get_at(*addr).iter().all(|s| s.symbol_type != SymbolType::Function) {
                    program.symbol_table.add(Symbol::new(
                        name.clone(),
                        *addr,
                        SymbolType::Function,
                        SourceType::Analysis,
                    ));
                }
                applied += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: applied,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_signatures() {
        let db = SignatureDatabase::new();
        let printf = db.lookup_by_name("printf").unwrap();
        assert_eq!(printf.return_type, "int");
        assert_eq!(printf.parameters.len(), 1);
        assert_eq!(printf.parameters[0].1, "const char*");
    }

    #[test]
    fn plt_suffix_strip() {
        let db = SignatureDatabase::new();
        assert!(db.lookup_by_name("printf@plt").is_some());
        assert!(db.lookup_by_name("unknown_func").is_none());
    }

    #[test]
    fn signature_count() {
        let db = SignatureDatabase::new();
        assert!(db.signature_count() >= 17);
    }
}
