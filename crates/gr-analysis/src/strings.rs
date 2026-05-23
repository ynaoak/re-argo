use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

const MIN_STRING_LENGTH: usize = 4;
const MAX_STRING_LENGTH: usize = 4096;

pub struct StringSearchAnalyzer;

impl Analyzer for StringSearchAnalyzer {
    fn name(&self) -> &str {
        "String Search"
    }

    fn description(&self) -> &str {
        "Finds ASCII and UTF-8 strings in data sections"
    }

    fn priority(&self) -> u32 {
        200
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut strings_found = 0;

        let data_sections: Vec<(String, u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| is_data_section(&s.name))
            .map(|s| (s.name.clone(), s.address, s.size))
            .collect();

        for (section_name, addr, size) in &data_sections {
            let mut buf = vec![0u8; *size as usize];
            if program.info.memory.read_bytes(*addr, &mut buf).is_err() {
                continue;
            }

            let found = find_strings(&buf, *addr);
            for (string_addr, string_val) in &found {
                let label = sanitize_string_label(string_val);
                program.symbol_table.add(Symbol::new(
                    format!("s_{}_{:x}", label, string_addr),
                    *string_addr,
                    SymbolType::Data,
                    SourceType::Analysis,
                ));
                strings_found += 1;
            }

            if !found.is_empty() {
                eprintln!(
                    "  [{}] {} strings in {} ({} bytes)",
                    self.name(),
                    found.len(),
                    section_name,
                    size
                );
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: strings_found,
        })
    }
}

fn is_data_section(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains(".rodata")
        || n.contains(".rdata")
        || n.contains(".data")
        || n.contains("__cstring")
        || n.contains("__const")
        || n.contains("__TEXT.__cstring")
}

fn find_strings(data: &[u8], base_addr: u64) -> Vec<(u64, String)> {
    let mut results = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if is_printable_ascii(data[i]) {
            let start = i;
            while i < data.len() && is_printable_ascii(data[i]) {
                i += 1;
            }
            let is_null_term = i < data.len() && data[i] == 0;
            let len = i - start;

            if (MIN_STRING_LENGTH..=MAX_STRING_LENGTH).contains(&len) && is_null_term
                && let Ok(s) = std::str::from_utf8(&data[start..i]) {
                    results.push((base_addr + start as u64, s.to_string()));
                }
            if is_null_term {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    results
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

fn sanitize_string_label(s: &str) -> String {
    let truncated = if s.len() > 32 { &s[..32] } else { s };
    truncated
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_null_terminated_strings() {
        let mut data = Vec::new();
        data.extend_from_slice(b"Hello, World!\0");
        data.extend_from_slice(b"\0\0\0");
        data.extend_from_slice(b"Another string here\0");
        data.extend_from_slice(b"ab\0"); // too short

        let found = find_strings(&data, 0x1000);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, 0x1000);
        assert_eq!(found[0].1, "Hello, World!");
        assert_eq!(found[1].1, "Another string here");
    }

    #[test]
    fn no_strings_in_binary() {
        let data = vec![0u8; 100];
        let found = find_strings(&data, 0x1000);
        assert!(found.is_empty());
    }

    #[test]
    fn sanitize_label() {
        assert_eq!(sanitize_string_label("Hello World!"), "Hello_World_");
        assert_eq!(sanitize_string_label("foo_bar"), "foo_bar");
    }

    #[test]
    fn data_section_detection() {
        assert!(is_data_section(".rodata"));
        assert!(is_data_section(".rdata"));
        assert!(is_data_section(".data"));
        assert!(is_data_section("__TEXT.__cstring"));
        assert!(!is_data_section(".text"));
        assert!(!is_data_section(".bss"));
    }
}
