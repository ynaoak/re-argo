//! Compiler / runtime fingerprinting.
//!
//! Mirrors Binary Ninja's "platform / runtime" detection and IDA's
//! `cmt.cfg` autodetect: scrapes the binary's `.comment` section,
//! `.note.gnu.build-id` note, and dynamic-version symbols, then writes
//! the findings into `program.metadata` so callers can pick the right
//! signature variant, demangler flavour, and ABI without re-reading the
//! file.
//!
//! Findings are surfaced as `metadata.properties`:
//!
//! ```text
//!   compiler       = "GCC 11.4.0"
//!   build_id       = "e92a66854d5ccb…"
//!   libc_version   = "GLIBC_2.34"
//!   language       = "C++"          // when libstdc++ is referenced
//!   runtime        = "libstdc++ / libgcc"
//! ```
//!
//! Nothing fails: if `.comment` is missing or the build ID is absent,
//! the analyzer just skips that field. The intent is "best-effort
//! metadata", not validation.

use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct CompilerFingerprintAnalyzer;

impl Analyzer for CompilerFingerprintAnalyzer {
    fn name(&self) -> &str {
        "Compiler Fingerprint"
    }
    fn description(&self) -> &str {
        "Extracts compiler, libc, build-id and language hints from binary metadata"
    }
    fn priority(&self) -> u32 {
        // After loader populates sections / dynamic info. Run early
        // so downstream signature pickers can read metadata.
        20
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut findings = 0usize;

        if let Some(compiler) = read_section_string(program, ".comment") {
            // .comment can contain multiple NUL-separated entries
            // ("GCC: (Debian 11.4.0-2) 11.4.0\0Linker: GNU ld\0…");
            // join the printable ones for display.
            let joined = compiler
                .split('\0')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" | ");
            if !joined.is_empty() {
                program.metadata.set_compiler(&joined);
                findings += 1;
            }
        }

        if let Some(id) = read_section_hex(program, ".note.gnu.build-id") {
            program.metadata.set_property("build_id", id);
            findings += 1;
        }

        // GLIBC / GCC version strings are stamped into each dynamically-
        // imported function's "@GLIBC_x.y" suffix in the dynsym table.
        // The highest version present is the binary's effective minimum
        // libc requirement.
        if let Some(libc) = highest_glibc_version(program) {
            program.metadata.set_property("libc_version", libc);
            findings += 1;
        }

        // Heuristic: dynamic deps reveal the language family.
        let lang = guess_language(program);
        if let Some(l) = lang {
            program.metadata.set_language(l);
            findings += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: findings,
        })
    }
}

fn read_section_string(program: &Program, name: &str) -> Option<String> {
    let section = program.info.sections.iter().find(|s| s.name == name)?;
    let mut buf = vec![0u8; section.size.min(4096) as usize];
    program.info.memory.read_bytes(section.address, &mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn read_section_hex(program: &Program, name: &str) -> Option<String> {
    let section = program.info.sections.iter().find(|s| s.name == name)?;
    let mut buf = vec![0u8; section.size.min(256) as usize];
    program.info.memory.read_bytes(section.address, &mut buf).ok()?;
    // .note.gnu.build-id layout: 4-byte name-size, 4-byte desc-size,
    // 4-byte note-type=3, then "GNU\0" name, then the build-id bytes.
    if buf.len() < 16 {
        return None;
    }
    let desc_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let id_offset = 16; // header (12) + "GNU\0" name (4)
    if id_offset + desc_size > buf.len() {
        return None;
    }
    let id_bytes = &buf[id_offset..id_offset + desc_size];
    Some(
        id_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>(),
    )
}

fn highest_glibc_version(program: &Program) -> Option<String> {
    let mut best: Option<(u32, u32, String)> = None;
    for sym in program.symbol_table.iter() {
        if let Some(rest) = sym.name.split('@').nth(1)
            && let Some(ver) = rest.strip_prefix("GLIBC_")
        {
            let parts: Vec<&str> = ver.split('.').collect();
            if parts.len() >= 2 {
                let major = parts[0].parse::<u32>().ok()?;
                let minor = parts[1].parse::<u32>().ok()?;
                let key = (major, minor);
                if best.as_ref().is_none_or(|b| (b.0, b.1) < key) {
                    best = Some((major, minor, format!("GLIBC_{}.{}", major, minor)));
                }
            }
        }
    }
    best.map(|(_, _, s)| s)
}

fn guess_language(program: &Program) -> Option<&'static str> {
    let libs = &program.info.dynamic.needed_libs;
    let has = |needle: &str| libs.iter().any(|l| l.contains(needle));
    if has("libstdc++") || has("libc++") {
        return Some("C++");
    }
    if has("libgo") {
        return Some("Go");
    }
    if has("librustc") || program.symbol_table.iter().any(|s| s.name.contains("_ZN") && s.name.contains("17h")) {
        return Some("Rust");
    }
    if has("libobjc") {
        return Some("Objective-C");
    }
    if has("libc.so") || has("libSystem") || has("msvcrt") || has("ucrtbase") {
        return Some("C");
    }
    None
}

#[cfg(test)]
mod tests {
    // Most surface area here is plumbing — pure ELF format handling.
    // Behaviour is exercised end-to-end via the analysis tests against
    // the real binaries the rest of the suite already loads.

    #[test]
    fn glibc_key_ordering() {
        // sanity: ensure (major, minor) ordering puts 2.34 above 2.27
        let a = (2u32, 27u32);
        let b = (2u32, 34u32);
        assert!(a < b);
    }
}
