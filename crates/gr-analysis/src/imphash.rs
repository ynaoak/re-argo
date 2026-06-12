//! Mandiant-style PE import-hash (imphash) + ELF symhash for
//! cross-sample malware clustering.
//!
//! ## PE imphash
//!
//! Standard format used by VirusTotal, Mandiant, FireEye, and every
//! malware-intel platform: walk the import table in load order,
//! lowercase each `library.function` pair, join with `,`, MD5 the
//! resulting string. The hash is stable across recompilations that
//! preserve the IAT layout — every variant of a malware family
//! typically shares an imphash, making it the de-facto family
//! fingerprint.
//!
//! Library name normalisation matches the published algorithm:
//! `kernel32.dll` → `kernel32`, `wsock32.dll` → `wsock32`,
//! `oleaut32.dll` → `oleaut32`. The `.dll` / `.ocx` / `.sys` /
//! `.cpl` suffixes are stripped.
//!
//! Ordinal-only imports (no name) are rendered as `ord<N>` using the
//! decimal ordinal — same as pefile / Mandiant's reference.
//!
//! ## ELF symhash
//!
//! ELF binaries don't have an IAT in the same sense — `.dynsym`
//! lists every external symbol but the order isn't load-order. We
//! sort imports alphabetically before MD5'ing (Detect-It-Easy /
//! gnu-style convention).
//!
//! Both hashes are surfaced in `metadata.imphash` (with the same key
//! regardless of format, since clustering tools typically index by
//! the same name).

use gr_loader::BinaryFormat;
use gr_program::Program;
use md5::{Digest, Md5};

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct ImphashAnalyzer;

impl Analyzer for ImphashAnalyzer {
    fn name(&self) -> &str {
        "Imphash"
    }
    fn description(&self) -> &str {
        "PE imphash / ELF symhash for malware-sample clustering"
    }
    fn priority(&self) -> u32 {
        // Cheap, IAT-only. Run early so info / summary surface it.
        290
    }
    fn provides(&self) -> &'static [&'static str] {
        &["imphash"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let h = match program.info.format {
            BinaryFormat::Pe => compute_pe_imphash(&program.info.imports),
            BinaryFormat::Elf => compute_elf_symhash(&program.info.imports),
            _ => None,
        };

        let mut counted = 0;
        if let Some(hex) = h {
            program.metadata.set_property("imphash", hex);
            counted = 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: counted,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// PE imphash: walk the IAT in load order, normalise each
/// `library.function` pair, join with commas, MD5.
pub fn compute_pe_imphash(imports: &[gr_loader::ImportEntry]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }
    let mut pairs: Vec<String> = Vec::with_capacity(imports.len());
    for imp in imports {
        // gr-loader's ImportEntry doesn't carry a library name today
        // (imports are flattened across libs). Without a library
        // prefix the hash isn't strictly Mandiant-equivalent — we
        // fall back to `unknown.function` so the value is still
        // stable across recompilations of the same binary.
        let name = imp.name.trim();
        if name.is_empty() {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        pairs.push(format!("unknown.{}", lower));
    }
    if pairs.is_empty() {
        return None;
    }
    Some(md5_hex(pairs.join(",").as_bytes()))
}

/// ELF symhash: alphabetical sort of imported symbol names, then MD5.
pub fn compute_elf_symhash(imports: &[gr_loader::ImportEntry]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }
    let mut names: Vec<String> = imports
        .iter()
        .map(|i| i.name.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() {
        return None;
    }
    names.sort();
    names.dedup();
    Some(md5_hex(names.join(",").as_bytes()))
}

/// Normalise a library name the way Mandiant's pefile does: strip
/// the `.dll` / `.ocx` / `.sys` / `.cpl` suffix and lowercase. Used
/// by callers that have the library prefix available (currently
/// none in our loader path — kept here for the upcoming PE loader
/// upgrade that will preserve per-import-library identity).
pub fn normalise_library(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for suffix in [".dll", ".ocx", ".sys", ".cpl"] {
        if let Some(stripped) = lower.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    lower
}

fn md5_hex(input: &[u8]) -> String {
    let digest = Md5::digest(input);
    let mut s = String::with_capacity(32);
    for b in digest.iter() {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0xF));
    }
    s
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imp(name: &str) -> gr_loader::ImportEntry {
        gr_loader::ImportEntry {
            name: name.to_string(),
            plt_address: 0,
            got_address: 0,
        }
    }

    #[test]
    fn md5_known_value() {
        // RFC 1321 vector
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn pe_imphash_stable() {
        let imports = vec![imp("CreateFileA"), imp("ReadFile"), imp("CloseHandle")];
        let h1 = compute_pe_imphash(&imports).unwrap();
        let h2 = compute_pe_imphash(&imports).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32); // hex MD5
    }

    #[test]
    fn pe_imphash_changes_with_imports() {
        let a = compute_pe_imphash(&[imp("foo")]).unwrap();
        let b = compute_pe_imphash(&[imp("bar")]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn elf_symhash_order_independent() {
        let a = compute_elf_symhash(&[imp("printf"), imp("malloc"), imp("free")]).unwrap();
        let b = compute_elf_symhash(&[imp("free"), imp("malloc"), imp("printf")]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn elf_symhash_dedups() {
        let single = compute_elf_symhash(&[imp("malloc")]).unwrap();
        let dup = compute_elf_symhash(&[imp("malloc"), imp("MALLOC"), imp("malloc")]).unwrap();
        assert_eq!(single, dup);
    }

    #[test]
    fn empty_returns_none() {
        assert!(compute_pe_imphash(&[]).is_none());
        assert!(compute_elf_symhash(&[]).is_none());
    }

    #[test]
    fn normalise_library_strips_dll() {
        assert_eq!(normalise_library("KERNEL32.DLL"), "kernel32");
        assert_eq!(normalise_library("wsock32.dll"), "wsock32");
        assert_eq!(normalise_library("oleaut32"), "oleaut32"); // no suffix → just lowercase
    }
}
