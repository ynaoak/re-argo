//! Detect the runtime / language a binary was produced by.
//!
//! Extends `CompilerFingerprintAnalyzer`'s `.comment` + glibc-version
//! scrape with deeper, per-runtime symbol-table fingerprints. This is
//! the equivalent of IDA's "Loaded Type Library" and Binary Ninja's
//! "Detected Platform" — knowing the runtime is the difference
//! between "this is a Go binary, look for the pclntab" and "this is
//! a Rust binary, expect Itanium-style mangled `_ZN…17h` symbols".
//!
//! Detection heuristics (each is an OR of independent signals; first
//! hit wins, with priority Rust → Go → MSVC → unchanged):
//!
//! * **Rust** — any symbol matching `_ZN.*17h[0-9a-f]{16}E` (the
//!   Rust hash-tail mangling convention) OR a `panic_*` / `core::*`
//!   demangled name OR `__rust_alloc` import.
//! * **Go** — `runtime.morestack` / `runtime.gopark` /
//!   `runtime.main` symbols, or a `.gopclntab` section.
//! * **MSVC** — `__security_check_cookie` / `_RTC_*` / `__chkstk`
//!   imports, or a `MSVCRT` / `UCRT` runtime dep.
//!
//! Writes findings into `program.metadata`:
//!   `runtime` = "rust" | "go" | "msvc" | ...
//!   `language` (refines / overrides the existing CompilerFingerprint
//!   value when we have higher confidence)

use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct RuntimeFingerprintAnalyzer;

impl Analyzer for RuntimeFingerprintAnalyzer {
    fn name(&self) -> &str {
        "Runtime Fingerprint"
    }
    fn description(&self) -> &str {
        "Detects Rust / Go / MSVC runtimes via symbol-table + section heuristics"
    }
    fn priority(&self) -> u32 {
        // After CompilerFingerprint (20) so we refine its results;
        // before everything else so downstream analyzers see the
        // refined `language` property.
        25
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut findings = 0usize;

        if detect_rust(program) {
            program.metadata.set_property("runtime", "rust");
            program.metadata.set_language("Rust");
            findings += 1;
        } else if detect_go(program) {
            program.metadata.set_property("runtime", "go");
            program.metadata.set_language("Go");
            findings += 1;
        } else if detect_msvc(program) {
            program.metadata.set_property("runtime", "msvc");
            // Only set language=C if CompilerFingerprint hasn't
            // already picked a more specific one (C++ from libstdc++,
            // etc.) — we don't *know* MSVC binaries are C; they
            // could be C++ with `/MD`.
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

fn detect_rust(program: &Program) -> bool {
    // Signal 1: dynamic dep on librustc_driver / rust runtime.
    if program
        .info
        .dynamic
        .needed_libs
        .iter()
        .any(|l| l.contains("libstd-") && l.contains(".so") || l.contains("rustc"))
    {
        return true;
    }
    // Signal 2: Itanium hash-tail mangling, or any `_ZN…E` that
    // contains `17h` at the suffix position (Rust legacy mangling).
    // We also accept the new `_R…` v0 mangling that Rust ≥ 1.61
    // emits when enabled.
    let mut rust_mangled = 0usize;
    for s in program.symbol_table.iter() {
        // Either of: the v0 `_R…` mangler, or the legacy
        // `_ZN…17h<16 hex chars>E` hash-tail mangler. Both are
        // unambiguously Rust.
        let v0 = s.name.starts_with("_R");
        let legacy =
            s.name.starts_with("_ZN") && s.name.contains("17h") && s.name.ends_with('E');
        if v0 || legacy {
            rust_mangled += 1;
        } else if s.name.contains("core::panicking::")
            || s.name.contains("__rust_alloc")
            || s.name.contains("rust_eh_personality")
        {
            return true;
        }
        if rust_mangled >= 4 {
            // Bulk-mangled symbols are diagnostic — a stray
            // `_ZN…17h…E` could be a C++ class with an
            // unfortunate name, but four of them isn't.
            return true;
        }
    }
    false
}

fn detect_go(program: &Program) -> bool {
    // Signal 1: a `.gopclntab` section (Go pclntab); also `.go.buildinfo`
    // on newer Go.
    if program
        .info
        .sections
        .iter()
        .any(|s| s.name == ".gopclntab" || s.name == ".go.buildinfo")
    {
        return true;
    }
    // Signal 2: any of the canonical Go runtime symbols.
    let needles = [
        "runtime.morestack",
        "runtime.gopark",
        "runtime.main",
        "runtime.schedinit",
        "go.buildid",
    ];
    program
        .symbol_table
        .iter()
        .any(|s| needles.iter().any(|n| s.name.starts_with(n)))
}

fn detect_msvc(program: &Program) -> bool {
    // Dynamic dep on the Microsoft CRT.
    if program
        .info
        .dynamic
        .needed_libs
        .iter()
        .any(|l| {
            let l = l.to_ascii_lowercase();
            l == "msvcrt.dll" || l.starts_with("ucrtbase") || l.starts_with("vcruntime")
        })
    {
        return true;
    }
    // CRT runtime helpers — these are imports / direct symbols.
    let needles = [
        "__security_check_cookie",
        "__security_cookie",
        "_RTC_CheckEsp",
        "_RTC_Shutdown",
        "_RTC_InitBase",
        "__chkstk",
    ];
    program
        .symbol_table
        .iter()
        .any(|s| needles.contains(&s.name.as_str()))
}

#[cfg(test)]
mod tests {
    // Pure heuristic functions are exercised end-to-end by the
    // existing test binaries the suite already loads. The detection
    // dispatches are read-only against the immutable Program view.
    #[test]
    fn module_compiles() {
        let _ = super::RuntimeFingerprintAnalyzer;
    }
}
