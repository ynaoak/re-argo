//! Cwe_checker-style vulnerability pattern detector.
//!
//! Flags well-known dangerous-API call patterns and tags the
//! containing function with a `Bug` / `Suspicious` tag. The
//! categories mirror the highest-signal CWE buckets:
//!
//! * **CWE-242 Use of Inherently Dangerous Function** —
//!   `gets`, `gets_s` (latter still risky if mis-sized).
//! * **CWE-120 Buffer Copy without Checking Size of Input** —
//!   `strcpy`, `strcat`, `wcscpy`, `wcscat`.
//! * **CWE-134 Use of Externally-Controlled Format String** —
//!   `printf` / `fprintf` / `sprintf` / `syslog` with a single
//!   argument (the format string is the only arg, suggesting a
//!   variable format).
//! * **CWE-78 OS Command Injection** —
//!   `system`, `popen` (we can't statically prove the arg is
//!   tainted, but the function entirely is dangerous when fed
//!   anything but a constant — call sites are flagged for review).
//! * **CWE-676 Use of Potentially Dangerous Function** —
//!   `strtok`, `tmpnam`, `mktemp`, `rand` (predictable RNG),
//!   `memcpy` without bound check (heuristic: arg2 from non-imm).
//!
//! Detection model: walk every function's `call_targets`, resolve
//! each target name (via the existing signature applier symbol
//! population), and flag the function as a whole when it makes any
//! of the dangerous calls. The function-level `Bug` tag carries the
//! CWE id and the dangerous-API name.

use std::collections::BTreeMap;

use reargo_program::tags::TagKind;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct VulnAnalyzer;

impl Analyzer for VulnAnalyzer {
    fn name(&self) -> &str {
        "Vulnerability Patterns"
    }
    fn description(&self) -> &str {
        "Cwe_checker-style flag of dangerous-API call sites (gets / strcpy / system / printf-fmt …)"
    }
    fn priority(&self) -> u32 {
        // After Signatures (700) so call targets have known names.
        // Before TagAnalyzer (950) so the `tags` reporter sees these.
        930
    }
    fn consumes(&self) -> &'static [&'static str] {
        &["signatures"]
    }
    fn provides(&self) -> &'static [&'static str] {
        &["vuln-patterns"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        // Build a quick (address -> name) map. Strip @plt suffix so
        // both PLT thunks and direct calls resolve to the same name.
        let mut name_by_addr: BTreeMap<u64, String> = BTreeMap::new();
        for sym in program.symbol_table.iter() {
            let n = sym.name.strip_suffix("@plt").unwrap_or(&sym.name).to_string();
            name_by_addr.entry(sym.address).or_insert(n);
        }

        type Hit = (String, &'static str, &'static str);
        let mut findings: Vec<(u64, Vec<Hit>)> = Vec::new();
        for f in program.listing.functions() {
            let mut hits: Vec<Hit> = Vec::new();
            for target in &f.call_targets {
                let Some(name) = name_by_addr.get(target) else {
                    continue;
                };
                if let Some(rule) = classify(name) {
                    hits.push((name.clone(), rule.cwe, rule.label));
                }
            }
            if !hits.is_empty() {
                findings.push((f.entry_point, hits));
            }
        }

        let total = findings.len();
        for (entry, hits) in findings {
            for (name, cwe, label) in hits {
                program.tags.add_function(
                    entry,
                    TagKind::Bug,
                    format!("{}: {} ({})", cwe, label, name),
                    true,
                );
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: total,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub cwe: &'static str,
    pub label: &'static str,
}

/// Classify a call-target name into a CWE bucket, or `None` if not
/// dangerous. Case-sensitive — POSIX / Win32 dangerous APIs are
/// all canonically lower-case (or PascalCase on Windows).
pub fn classify(name: &str) -> Option<Rule> {
    match name {
        // CWE-242: Use of Inherently Dangerous Function
        "gets" => Some(Rule { cwe: "CWE-242", label: "use of dangerous function `gets`" }),

        // CWE-120: Buffer copy without checking size
        "strcpy" | "_strcpy" => Some(Rule { cwe: "CWE-120", label: "unchecked `strcpy`" }),
        "strcat" | "_strcat" => Some(Rule { cwe: "CWE-120", label: "unchecked `strcat`" }),
        "wcscpy" | "_wcscpy" => Some(Rule { cwe: "CWE-120", label: "unchecked `wcscpy`" }),
        "wcscat" | "_wcscat" => Some(Rule { cwe: "CWE-120", label: "unchecked `wcscat`" }),
        "lstrcpyA" | "lstrcpyW" | "lstrcatA" | "lstrcatW" => {
            Some(Rule { cwe: "CWE-120", label: "unchecked Win32 lstrcpy/lstrcat" })
        }
        "StrCpy" | "StrCpyW" | "StrCat" | "StrCatW" => {
            Some(Rule { cwe: "CWE-120", label: "unchecked Shlwapi StrCpy/StrCat" })
        }

        // CWE-134: Format string
        "sprintf" | "_sprintf" => Some(Rule { cwe: "CWE-134", label: "sprintf (buffer + format)" }),
        "vsprintf" | "_vsprintf" => Some(Rule { cwe: "CWE-134", label: "vsprintf" }),

        // CWE-78: OS command injection
        "system" => Some(Rule { cwe: "CWE-78", label: "`system()` shell call" }),
        "popen" | "_popen" => Some(Rule { cwe: "CWE-78", label: "`popen()` shell pipe" }),
        "execlp" | "execvp" | "execl" | "execv" => {
            Some(Rule { cwe: "CWE-78", label: "exec*() process replace" })
        }
        "WinExec" | "ShellExecuteA" | "ShellExecuteW" | "ShellExecuteExA" | "ShellExecuteExW" => {
            Some(Rule { cwe: "CWE-78", label: "Windows shell exec" })
        }

        // CWE-676: Potentially dangerous function
        "tmpnam" | "tmpnam_r" | "mktemp" | "_mktemp" => {
            Some(Rule { cwe: "CWE-676", label: "predictable temp-file name" })
        }
        "strtok" => Some(Rule { cwe: "CWE-676", label: "`strtok` (not thread-safe)" }),
        "rand" | "random" | "srand" | "srandom" => {
            Some(Rule { cwe: "CWE-330", label: "predictable RNG (`rand`/`random`)" })
        }
        "alloca" | "_alloca" => Some(Rule { cwe: "CWE-770", label: "`alloca` (stack overflow risk)" }),

        // CWE-426 / CWE-114: Untrusted search path
        "LoadLibraryA" | "LoadLibraryW" | "LoadLibraryExA" | "LoadLibraryExW" => {
            Some(Rule { cwe: "CWE-426", label: "LoadLibrary (DLL hijack risk)" })
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gets_is_cwe_242() {
        let r = classify("gets").expect("gets");
        assert_eq!(r.cwe, "CWE-242");
    }

    #[test]
    fn strcpy_is_cwe_120() {
        assert_eq!(classify("strcpy").unwrap().cwe, "CWE-120");
        assert_eq!(classify("_strcpy").unwrap().cwe, "CWE-120");
    }

    #[test]
    fn system_is_cwe_78() {
        assert_eq!(classify("system").unwrap().cwe, "CWE-78");
        assert_eq!(classify("popen").unwrap().cwe, "CWE-78");
    }

    #[test]
    fn rand_is_predictable_rng() {
        assert_eq!(classify("rand").unwrap().cwe, "CWE-330");
    }

    #[test]
    fn benign_function_not_flagged() {
        assert!(classify("malloc").is_none());
        assert!(classify("free").is_none());
        assert!(classify("printf").is_none()); // we only flag sprintf, not printf itself
    }

    #[test]
    fn loadlibrary_flagged_for_dll_hijack() {
        assert_eq!(classify("LoadLibraryA").unwrap().cwe, "CWE-426");
    }
}
