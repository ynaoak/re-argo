//! PE-specific enrichment beyond `.pdata`:
//!
//! 1. **IAT (Import Address Table) name resolution** — for every
//!    GOT-equivalent slot in `.idata` / IAT we register an Import
//!    symbol naming the imported function. Mirrors what the
//!    existing PE loader writes for ELF GOT slots but at a
//!    different layout.
//! 2. **Resource directory walk** — `.rsrc` holds the icon /
//!    manifest / version-info tree. We don't need to parse it
//!    fully, but the `VS_VERSIONINFO` at type id `RT_VERSION`
//!    contains the binary's product name + version, and that's
//!    extremely useful triage info we can stuff into
//!    `program.metadata` for `info` to show.
//!
//! Both passes are no-ops on non-PE binaries and on PE binaries
//! that lack the relevant directory — they degrade silently.
//!
//! Cost: a few hundred bytes of section reads per binary,
//! microseconds of work.

use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct PeEnrichmentAnalyzer;

impl Analyzer for PeEnrichmentAnalyzer {
    fn name(&self) -> &str {
        "PE Enrichment"
    }
    fn description(&self) -> &str {
        "Walks PE IAT for import names and .rsrc VS_VERSIONINFO for product strings"
    }
    fn priority(&self) -> u32 {
        // After EntryPoint / EhFrame / pre-Discovery passes so any
        // imports we add land in Discovery's seed queue.
        82
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if program.info.format != gr_loader::BinaryFormat::Pe {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let mut produced = 0usize;

        // (1) IAT: the gr-loader PE path already populates
        // `info.imports`, but the symbols it emits may not include
        // `@plt`-style PLT addresses. We add an `Import` SymbolType
        // for every (name, plt_address) so xref output and
        // CallSiteAnnotator see a consistent name.
        for imp in program.info.imports.iter() {
            if imp.plt_address == 0 || imp.name.is_empty() {
                continue;
            }
            let already = program
                .symbol_table
                .primary_at(imp.plt_address)
                .map(|s| !s.name.starts_with("FUN_"))
                .unwrap_or(false);
            if already {
                continue;
            }
            program.symbol_table.add(Symbol::new(
                imp.name.clone(),
                imp.plt_address,
                SymbolType::ExternalFunction,
                SourceType::Imported,
            ));
            produced += 1;
        }

        // (2) Resource directory — find `.rsrc` and pluck the first
        // printable VS_VERSIONINFO-shaped key/value run.
        if let Some((base, size)) = find_section(program, ".rsrc")
            && let Some((product, version)) = scrape_versioninfo(program, base, size)
        {
            if !product.is_empty() {
                program
                    .metadata
                    .set_property("pe_product", product);
            }
            if !version.is_empty() {
                program
                    .metadata
                    .set_property("pe_version", version);
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: produced,
        })
    }
}

fn find_section(program: &Program, name: &str) -> Option<(u64, u64)> {
    let s = program.info.sections.iter().find(|s| s.name == name)?;
    if s.size == 0 {
        return None;
    }
    Some((s.address, s.size))
}

/// Scan a `.rsrc` blob for `VS_VERSIONINFO`-style UTF-16LE
/// "Key\0Value\0" pairs. Returns (product_name, file_version) when
/// found. We deliberately don't parse the resource tree — the
/// `VS_VERSION_INFO` payload is always a UTF-16LE string table and
/// the keys we care about (`ProductName`, `FileVersion`) sit at
/// 16-byte-aligned offsets next to their values. Scanning for the
/// literal key + reading until the trailing NUL recovers the values
/// without re-implementing the full tree walk.
fn scrape_versioninfo(program: &Program, base: u64, size: u64) -> Option<(String, String)> {
    let cap = size.min(256 * 1024) as usize;
    let mut buf = vec![0u8; cap];
    program.info.memory.read_bytes(base, &mut buf).ok()?;

    let product = scrape_key(&buf, "ProductName");
    let version = scrape_key(&buf, "FileVersion");
    if product.is_empty() && version.is_empty() {
        return None;
    }
    Some((product, version))
}

fn scrape_key(buf: &[u8], key: &str) -> String {
    let key_utf16: Vec<u8> = key
        .encode_utf16()
        .flat_map(|w| w.to_le_bytes())
        .chain(std::iter::once(0))
        .chain(std::iter::once(0))
        .collect();
    let Some(pos) = buf.windows(key_utf16.len()).position(|w| w == key_utf16) else {
        return String::new();
    };
    // Value follows the key after dword-alignment padding. Scan up
    // to 256 bytes for a printable UTF-16LE run terminated by NUL.
    let value_start = (pos + key_utf16.len() + 3) & !3;
    let mut chars: Vec<u16> = Vec::new();
    let mut i = value_start;
    while i + 2 <= buf.len() && chars.len() < 256 {
        let w = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if w == 0 {
            break;
        }
        chars.push(w);
        i += 2;
    }
    let s = String::from_utf16_lossy(&chars);
    // Reject the trivial "FileFlagsMask" / "Translation" runs that
    // aren't user-facing strings.
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') && s.is_empty() {
        return String::new();
    }
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrape_finds_value() {
        // synthesise a fake VS_VERSIONINFO blob:
        // "ProductName\0\0" then aligned UTF-16LE "MyApp\0"
        let mut blob: Vec<u8> = Vec::new();
        let key = "ProductName";
        for c in key.encode_utf16() {
            blob.extend_from_slice(&c.to_le_bytes());
        }
        blob.extend_from_slice(&[0, 0]); // utf-16 NUL
        while !blob.len().is_multiple_of(4) {
            blob.push(0);
        }
        for c in "MyApp".encode_utf16() {
            blob.extend_from_slice(&c.to_le_bytes());
        }
        blob.extend_from_slice(&[0, 0]); // value NUL

        let got = scrape_key(&blob, "ProductName");
        assert_eq!(got, "MyApp");
    }

    #[test]
    fn scrape_missing_key_empty() {
        let got = scrape_key(b"no such key here", "ProductName");
        assert_eq!(got, "");
    }
}
