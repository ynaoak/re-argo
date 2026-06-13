//! Mach-O `__TEXT,__cstring` + `__TEXT,__objc_methname` string
//! scanning.
//!
//! Mach-O parks its C strings in dedicated sections under the
//! `__TEXT` segment — `__cstring` for `const char *` literals,
//! `__objc_methname` for selectors, `__objc_classname` for class
//! names, `__objc_methtype` for ObjC type strings. Our
//! `StringSearchAnalyzer` walks every readable data section
//! generically, but the Mach-O ELF-shaped output uses `.rodata`-
//! style names; the actual Mach-O sections are reported with
//! `__SEGMENT,__section` names that won't match. This analyzer
//! scopes the walk to the canonical Mach-O string sections and
//! registers each NUL-terminated run as an `s_<addr>` Data symbol.
//!
//! Bonus: ObjC selector + class names get a dedicated naming
//! scheme so the symbol table makes it obvious which strings come
//! from the runtime metadata vs user literals:
//!
//!   __objc_methname  → `objc_sel_<name>` Data symbol
//!   __objc_classname → `objc_clsname_<name>` Data symbol
//!   __cstring        → `s_<addr>` Data symbol
//!
//! No-op on non-Mach-O binaries.

use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct MachoStringsAnalyzer;

impl Analyzer for MachoStringsAnalyzer {
    fn name(&self) -> &str {
        "Mach-O Strings"
    }
    fn description(&self) -> &str {
        "Scans Mach-O __cstring / __objc_methname / __objc_classname for symbols"
    }
    fn priority(&self) -> u32 {
        // Before Discovery so any selector / class-name string we
        // register lands in time for ObjC analyzer cross-reference.
        86
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if program.info.format != reargo_loader::BinaryFormat::MachO {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let mut added = 0usize;
        let sections: Vec<(String, u64, u64)> = program
            .info
            .sections
            .iter()
            .filter_map(|s| {
                let n = s.name.as_str();
                let name_match = n.ends_with("__cstring")
                    || n.ends_with("__objc_methname")
                    || n.ends_with("__objc_classname")
                    || n.ends_with("__objc_methtype");
                if name_match && s.size > 0 {
                    Some((s.name.clone(), s.address, s.size))
                } else {
                    None
                }
            })
            .collect();

        for (name, base, size) in &sections {
            let cap = (*size).min(1 << 20) as usize;
            let mut buf = vec![0u8; cap];
            if program.info.memory.read_bytes(*base, &mut buf).is_err() {
                continue;
            }
            let prefix = if name.ends_with("__objc_methname") {
                "objc_sel"
            } else if name.ends_with("__objc_classname") {
                "objc_clsname"
            } else if name.ends_with("__objc_methtype") {
                "objc_methtype"
            } else {
                "s"
            };
            let mut start = 0usize;
            for i in 0..buf.len() {
                if buf[i] != 0 {
                    continue;
                }
                if i == start {
                    // Empty string — skip but advance past it.
                    start = i + 1;
                    continue;
                }
                let slice = &buf[start..i];
                if !is_printable_run(slice) || slice.len() < 2 {
                    start = i + 1;
                    continue;
                }
                let addr = base + start as u64;
                if program.symbol_table.primary_at(addr).is_none() {
                    let label = sanitize(std::str::from_utf8(slice).unwrap_or(""));
                    let sym_name = if prefix == "s" {
                        format!("s_{:x}", addr)
                    } else if label.is_empty() {
                        format!("{}_{:x}", prefix, addr)
                    } else {
                        format!("{}_{}", prefix, label)
                    };
                    program.symbol_table.add(Symbol::new(
                        sym_name,
                        addr,
                        SymbolType::Data,
                        SourceType::Analysis,
                    ));
                    added += 1;
                }
                start = i + 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: added,
        })
    }
}

fn is_printable_run(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| (b' '..=b'~').contains(&b) || b == b'\n' || b == b'\t' || b == b'\r')
        .count();
    printable * 5 >= bytes.len() * 4
}

fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().take(32) {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_run_accepts_ascii() {
        assert!(is_printable_run(b"hello"));
        assert!(!is_printable_run(b"\x01\x02"));
    }

    #[test]
    fn sanitize_strips_punct() {
        assert_eq!(sanitize("hello:world"), "hello_world");
        assert_eq!(sanitize("foo"), "foo");
        assert_eq!(sanitize("[NSString stringWithUTF8String:]"), "NSString_stringWithUTF8String");
    }
}
