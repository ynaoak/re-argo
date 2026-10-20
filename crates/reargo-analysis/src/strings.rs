use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, State};

const MIN_STRING_LENGTH: usize = 4;
const MAX_STRING_LENGTH: usize = 4096;

pub struct StringSearchAnalyzer;

impl Analyzer for StringSearchAnalyzer {
    fn writes(&self) -> State {
        State::SYMBOLS
    }
    fn name(&self) -> &str {
        "String Search"
    }

    fn description(&self) -> &str {
        "Finds ASCII and UTF-8 strings in data sections"
    }

    fn priority(&self) -> u32 {
        200
    }

    fn start_early(&self, program: &mut Program) {
        // the data sections' bytes are fixed for the run
        // the bytes are read on that thread (a clone of the memory
        // shares them)
        let (sections, memory) = (program.info.sections.clone(), program.info.memory.clone());
        crate::analyzer::Early::<StringSearchAnalyzer, Vec<SectionStrings>>::start(program, move || {
            data_section_bytes(&sections, &memory).into_par_iter().map(section_strings).collect()
        });
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let per_section = match crate::analyzer::Early::<StringSearchAnalyzer, Vec<SectionStrings>>::take(program) {
            Some(per_section) => per_section,
            None => data_section_bytes(&program.info.sections, &program.info.memory).into_par_iter().map(section_strings).collect(),
        };

        let mut strings_found = 0;
        for (section_name, size, found) in per_section {
            let count = found.len();
            for (string_addr, name) in found {
                program.symbol_table.add(Symbol::new(name, string_addr, SymbolType::Data, SourceType::Analysis));
                strings_found += 1;
            }
            if count > 0 {
                eprintln!(
                    "  [{}] {} strings in {} ({} bytes)",
                    self.name(),
                    count,
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

/// A data section's name and size, and the address and symbol name of
/// each string found in it.
type SectionStrings = (String, u64, Vec<(u64, String)>);

/// The name, address, size and bytes of each readable data section, in
/// section order.
fn data_section_bytes<'m>(
    sections: &[reargo_loader::Section],
    memory: &'m reargo_loader::memory::Memory,
) -> Vec<(String, u64, u64, std::borrow::Cow<'m, [u8]>)> {
    sections
        .iter()
        .filter(|s| is_data_section(&s.name))
        .filter_map(|s| {
            Some((s.name.clone(), s.address, s.size, memory.bytes(s.address, s.size as usize)?))
        })
        .collect()
}

fn section_strings((name, addr, size, buf): (String, u64, u64, std::borrow::Cow<'_, [u8]>)) -> SectionStrings {
    let found = find_strings(&buf, addr)
        .into_iter()
        .map(|(string_addr, string_val)| {
            let label = sanitize_string_label(&string_val);
            (string_addr, format!("s_{}_{:x}", label, string_addr))
        })
        .collect();
    (name, size, found)
}

pub fn is_data_section(name: &str) -> bool {
    let patterns = [".rodata", ".rdata", ".data", "__cstring", "__const", "__TEXT.__cstring"];
    patterns.iter().any(|p| {
        name.len() >= p.len()
            && name.as_bytes().windows(p.len()).any(|w|
                w.eq_ignore_ascii_case(p.as_bytes()))
    })
}

pub fn find_strings(data: &[u8], base_addr: u64) -> Vec<(u64, String)> {
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
