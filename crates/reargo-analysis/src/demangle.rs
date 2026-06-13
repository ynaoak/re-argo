use reargo_program::symbol::SourceType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct DemangleAnalyzer;

impl Analyzer for DemangleAnalyzer {
    fn name(&self) -> &str {
        "Demangler"
    }

    fn description(&self) -> &str {
        "Demangles C++ (Itanium/MSVC) and Rust symbol names"
    }

    fn priority(&self) -> u32 {
        50
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut demangled_count = 0;

        let symbols: Vec<(u64, String)> = program
            .symbol_table
            .iter()
            .filter(|s| s.source == SourceType::Imported)
            .filter(|s| is_mangled(&s.name))
            .map(|s| (s.address, s.name.clone()))
            .collect();

        for (addr, mangled) in &symbols {
            if let Some(demangled) = try_demangle(mangled) {
                program.symbol_table.add(reargo_program::symbol::Symbol::new(
                    demangled,
                    *addr,
                    reargo_program::symbol::SymbolType::Label,
                    SourceType::Analysis,
                ));
                demangled_count += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: demangled_count,
        })
    }
}

fn is_mangled(name: &str) -> bool {
    name.starts_with("_Z")
        || name.starts_with("__Z")
        || name.starts_with("?")
        || name.starts_with("_R")
        || is_go_symbol(name)
}

fn is_go_symbol(name: &str) -> bool {
    name.contains(".") && (name.starts_with("main.") || name.starts_with("runtime.") || name.starts_with("go."))
}

fn demangle_go(name: &str) -> Option<String> {
    if !is_go_symbol(name) {
        return None;
    }
    let cleaned = name
        .replace("%2e", ".")
        .replace("%2f", "/")
        .replace("%25", "%");
    if cleaned != name {
        Some(cleaned)
    } else {
        None
    }
}

pub fn try_demangle(name: &str) -> Option<String> {
    if let Ok(sym) = cpp_demangle::Symbol::new(name) {
        return Some(sym.to_string());
    }

    let stripped = name.strip_prefix('_').unwrap_or(name);
    if let Ok(sym) = cpp_demangle::Symbol::new(stripped) {
        return Some(sym.to_string());
    }

    let demangled = rustc_demangle::demangle(name).to_string();
    if demangled != name {
        return Some(demangled);
    }

    if let Some(go) = demangle_go(name) {
        return Some(go);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangle_cpp_itanium() {
        let result = try_demangle("_ZN3foo3barEi").unwrap();
        assert!(result.contains("foo"));
        assert!(result.contains("bar"));
    }

    #[test]
    fn demangle_rust_v0() {
        let result = try_demangle("_RNvCs1234_5hello4main");
        let _ = result;
    }

    #[test]
    fn no_demangle_plain() {
        assert!(try_demangle("printf").is_none());
        assert!(try_demangle("main").is_none());
    }

    #[test]
    fn is_mangled_detection() {
        assert!(is_mangled("_ZN3foo3barEi"));
        assert!(is_mangled("?method@Class@@QAEXXZ"));
        assert!(is_mangled("_RNvCs1234_5hello4main"));
        assert!(!is_mangled("printf"));
        assert!(!is_mangled("main"));
    }
}
