//! Capa-style capability rule engine.
//!
//! Capa (Mandiant) extracts a binary's *capabilities* — high-level
//! verbs like "encrypt data using AES" or "captures keyboard input"
//! — by matching rules against features (strings, imports, mnemonics,
//! constants, …) discovered by earlier analysis. We layer the same
//! idea on top of the existing tag / symbol / string infrastructure
//! the rest of the pipeline already produces.
//!
//! Each rule is a small predicate over a `CapaContext`:
//!
//! * `imports_any_of(&["WriteFile", "fopen", …])` — true if any
//!   matching import is present.
//! * `strings_any_of(&["password", "regex"])` — case-insensitive
//!   substring match against discovered strings.
//! * `tag_present(TagKind::Crypto)` — true if any analyzer set a
//!   crypto tag.
//!
//! Rules combine these primitives via `all_of` / `any_of` and emit
//! a `CapabilityFinding` with the rule name, namespace, and matched
//! evidence list. Findings are written to:
//!
//! * `program.tags` as `Important` function tags on each
//!   contributing function (so the existing `tags` CLI surfaces them).
//! * `program.metadata.capa_rules` as a `\n`-joined rule-name list
//!   for the `capa` CLI command to render.
//!
//! Built-in rule set: 20 entries covering the common "what does this
//! binary do?" questions — file I/O, networking, registry, crypto,
//! process injection, keylogging, anti-debug. Mirrors the highest-
//! signal subset of Capa's standard rules; we lean on existing
//! analyzers for the heavy lifting (the crypto / anti-debug tags are
//! already produced upstream).

use std::collections::BTreeSet;

use reargo_program::tags::TagKind;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: &'static str,
    pub namespace: &'static str,
    pub description: &'static str,
    pub predicate: Predicate,
}

#[derive(Debug, Clone)]
pub enum Predicate {
    /// Match if any of the listed imports is in the import table
    /// (case-insensitive substring).
    ImportsAnyOf(&'static [&'static str]),
    /// Match if any tag of this kind is present anywhere.
    TagPresent(TagKind),
    /// Match if any of the listed strings appears in a discovered
    /// string (case-insensitive substring).
    StringsAnyOf(&'static [&'static str]),
    /// Match if all sub-predicates match.
    AllOf(&'static [Predicate]),
    /// Match if any sub-predicate matches.
    AnyOf(&'static [Predicate]),
}

#[derive(Debug, Clone)]
pub struct CapabilityFinding {
    pub rule: &'static str,
    pub namespace: &'static str,
    pub evidence: Vec<String>,
}

pub struct CapaAnalyzer;

impl Analyzer for CapaAnalyzer {
    fn name(&self) -> &str {
        "Capa Rules"
    }
    fn description(&self) -> &str {
        "Match Capa-style capability rules against imports / strings / tags"
    }
    fn priority(&self) -> u32 {
        // Run very late so every upstream tag/string/import is in
        // place. Just below TagAnalyzer (950).
        960
    }
    fn consumes(&self) -> &'static [&'static str] {
        &["tags"]
    }
    fn provides(&self) -> &'static [&'static str] {
        &["capabilities"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let ctx = build_context(program);
        let mut findings = Vec::new();
        for rule in builtin_rules() {
            let mut evidence = Vec::new();
            if eval(&rule.predicate, &ctx, &mut evidence) {
                findings.push(CapabilityFinding {
                    rule: rule.name,
                    namespace: rule.namespace,
                    evidence,
                });
            }
        }

        if !findings.is_empty() {
            let names: Vec<String> = findings
                .iter()
                .map(|f| format!("{}/{}", f.namespace, f.rule))
                .collect();
            program
                .metadata
                .set_property("capa_rules", names.join("\n"));
        }

        let mut tag_count = 0usize;
        let entry = program.entry_point();
        for f in &findings {
            program.tags.add_function(
                entry,
                TagKind::Important,
                format!(
                    "capability: {}/{} — {}",
                    f.namespace,
                    f.rule,
                    f.evidence.join(", ")
                ),
                true,
            );
            tag_count += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: tag_count,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

struct CapaContext {
    imports: BTreeSet<String>,
    imports_lower: BTreeSet<String>,
    strings_lower: Vec<String>,
    present_tags: BTreeSet<String>,
}

fn build_context(program: &Program) -> CapaContext {
    let mut imports: BTreeSet<String> = BTreeSet::new();
    for imp in &program.info.imports {
        imports.insert(imp.name.clone());
    }
    for sym in program.symbol_table.iter() {
        let n = sym.name.strip_suffix("@plt").unwrap_or(&sym.name);
        imports.insert(n.to_string());
    }
    let imports_lower: BTreeSet<String> =
        imports.iter().map(|s| s.to_ascii_lowercase()).collect();

    // Pull strings from inline comments / immediate-string annotations
    // (every string the analyzer cared about flows through these).
    let mut strings_lower: Vec<String> = Vec::new();
    for c in program.comments.iter() {
        strings_lower.push(c.text.to_ascii_lowercase());
    }

    let mut present_tags: BTreeSet<String> = BTreeSet::new();
    for (_, tag) in program.tags.iter_addresses() {
        present_tags.insert(tag.kind.as_str().to_string());
    }
    for (_, tag) in program.tags.iter_functions() {
        present_tags.insert(tag.kind.as_str().to_string());
    }

    CapaContext {
        imports,
        imports_lower,
        strings_lower,
        present_tags,
    }
}

fn eval(p: &Predicate, ctx: &CapaContext, evidence: &mut Vec<String>) -> bool {
    match p {
        Predicate::ImportsAnyOf(needles) => {
            let mut hit = false;
            for needle in *needles {
                let nl = needle.to_ascii_lowercase();
                for imp in &ctx.imports_lower {
                    if imp.contains(&nl) {
                        // Find the original-cased name for the
                        // evidence list (use ctx.imports — there
                        // may be exact matches).
                        let original = ctx
                            .imports
                            .iter()
                            .find(|s| s.to_ascii_lowercase() == *imp)
                            .cloned()
                            .unwrap_or_else(|| (*needle).to_string());
                        evidence.push(format!("import {}", original));
                        hit = true;
                        break;
                    }
                }
            }
            hit
        }
        Predicate::TagPresent(kind) => {
            let slug = kind.as_str().to_string();
            if ctx.present_tags.contains(&slug) {
                evidence.push(format!("tag {}", slug));
                true
            } else {
                false
            }
        }
        Predicate::StringsAnyOf(needles) => {
            let mut hit = false;
            for needle in *needles {
                let nl = needle.to_ascii_lowercase();
                for s in &ctx.strings_lower {
                    if s.contains(&nl) {
                        evidence.push(format!("string {:?}", needle));
                        hit = true;
                        break;
                    }
                }
            }
            hit
        }
        Predicate::AllOf(parts) => parts.iter().all(|p| eval(p, ctx, evidence)),
        Predicate::AnyOf(parts) => parts.iter().any(|p| eval(p, ctx, evidence)),
    }
}

/// Built-in rule set, modelled on Capa's standard rules. Kept short
/// and conservative: each rule's predicate should be unambiguous,
/// otherwise we'd flood the report.
pub fn builtin_rules() -> &'static [Rule] {
    &BUILTIN_RULES
}

static BUILTIN_RULES: [Rule; 20] = [
    Rule {
        name: "read-file",
        namespace: "host-interaction/file-system",
        description: "Reads files from disk",
        predicate: Predicate::ImportsAnyOf(&[
            "ReadFile", "fread", "fopen", "open", "openat", "read",
        ]),
    },
    Rule {
        name: "write-file",
        namespace: "host-interaction/file-system",
        description: "Writes files to disk",
        predicate: Predicate::ImportsAnyOf(&[
            "WriteFile", "fwrite", "fputs", "write", "writev",
        ]),
    },
    Rule {
        name: "delete-file",
        namespace: "host-interaction/file-system",
        description: "Deletes files",
        predicate: Predicate::ImportsAnyOf(&[
            "DeleteFile", "unlink", "remove", "rmdir",
        ]),
    },
    Rule {
        name: "tcp-socket",
        namespace: "communication/tcp",
        description: "Uses TCP sockets",
        predicate: Predicate::ImportsAnyOf(&[
            "socket", "connect", "send", "recv", "WSASocket", "WSAConnect",
        ]),
    },
    Rule {
        name: "http-client",
        namespace: "communication/http",
        description: "Makes HTTP requests",
        predicate: Predicate::AnyOf(&[
            Predicate::ImportsAnyOf(&[
                "InternetOpen", "InternetConnect", "HttpOpenRequest",
                "WinHttpOpen", "curl_easy_init",
            ]),
            Predicate::StringsAnyOf(&["http://", "https://", "User-Agent:"]),
        ]),
    },
    Rule {
        name: "dns-resolution",
        namespace: "communication/dns",
        description: "Resolves DNS names",
        predicate: Predicate::ImportsAnyOf(&[
            "gethostbyname", "getaddrinfo", "DnsQuery",
        ]),
    },
    Rule {
        name: "registry-access",
        namespace: "host-interaction/registry",
        description: "Accesses the Windows registry",
        predicate: Predicate::ImportsAnyOf(&[
            "RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreateKey",
        ]),
    },
    Rule {
        name: "process-spawn",
        namespace: "host-interaction/process",
        description: "Spawns a process",
        predicate: Predicate::ImportsAnyOf(&[
            "CreateProcess", "ShellExecute", "WinExec",
            "fork", "vfork", "posix_spawn", "execve", "execvp", "system",
        ]),
    },
    Rule {
        name: "process-injection",
        namespace: "host-interaction/process",
        description: "Injects code into another process",
        predicate: Predicate::AllOf(&[
            Predicate::ImportsAnyOf(&[
                "OpenProcess", "VirtualAllocEx",
            ]),
            Predicate::ImportsAnyOf(&[
                "WriteProcessMemory", "CreateRemoteThread",
                "NtMapViewOfSection", "QueueUserAPC",
            ]),
        ]),
    },
    Rule {
        name: "keyboard-input",
        namespace: "collection/keylog",
        description: "Captures keyboard input",
        predicate: Predicate::ImportsAnyOf(&[
            "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
            "GetKeyboardState", "RegisterRawInputDevices",
        ]),
    },
    Rule {
        name: "clipboard-access",
        namespace: "collection/clipboard",
        description: "Reads or modifies the clipboard",
        predicate: Predicate::ImportsAnyOf(&[
            "OpenClipboard", "GetClipboardData", "SetClipboardData",
        ]),
    },
    Rule {
        name: "screenshot",
        namespace: "collection/screenshot",
        description: "Takes screenshots",
        predicate: Predicate::ImportsAnyOf(&[
            "BitBlt", "GetDesktopWindow", "PrintWindow", "CreateCompatibleBitmap",
        ]),
    },
    Rule {
        name: "encrypt-data",
        namespace: "data-manipulation/encryption",
        description: "Encrypts data using a known algorithm",
        predicate: Predicate::AnyOf(&[
            Predicate::TagPresent(TagKind::Crypto),
            Predicate::ImportsAnyOf(&[
                "EVP_EncryptInit", "AES_encrypt", "CryptEncrypt",
                "BCryptEncrypt", "RSA_public_encrypt",
            ]),
        ]),
    },
    Rule {
        name: "hash-data",
        namespace: "data-manipulation/hashing",
        description: "Hashes data with a known algorithm",
        predicate: Predicate::ImportsAnyOf(&[
            "MD5_Init", "SHA1_Init", "SHA256_Init", "EVP_DigestInit",
            "CryptHashData", "BCryptCreateHash",
        ]),
    },
    Rule {
        name: "anti-debugging",
        namespace: "anti-analysis/anti-debugging",
        description: "Implements anti-debugger checks",
        predicate: Predicate::AnyOf(&[
            Predicate::TagPresent(TagKind::AntiDebug),
            Predicate::ImportsAnyOf(&[
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "ptrace",
            ]),
        ]),
    },
    Rule {
        name: "packed-binary",
        namespace: "anti-analysis/packer",
        description: "Binary appears packed (high entropy + few imports)",
        predicate: Predicate::TagPresent(TagKind::Suspicious),
    },
    Rule {
        name: "persistence-registry-run-key",
        namespace: "persistence/registry",
        description: "Uses a Run / RunOnce key to persist",
        predicate: Predicate::AllOf(&[
            Predicate::ImportsAnyOf(&["RegSetValue", "RegCreateKey"]),
            Predicate::StringsAnyOf(&[
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ]),
        ]),
    },
    Rule {
        name: "service-install",
        namespace: "persistence/service",
        description: "Installs a service",
        predicate: Predicate::ImportsAnyOf(&[
            "OpenSCManager", "CreateService", "StartService",
        ]),
    },
    Rule {
        name: "shell-command",
        namespace: "execution/shell",
        description: "Runs a shell command",
        predicate: Predicate::AnyOf(&[
            Predicate::ImportsAnyOf(&["system", "popen", "WinExec"]),
            Predicate::StringsAnyOf(&["cmd.exe", "/bin/sh", "/bin/bash"]),
        ]),
    },
    Rule {
        name: "self-modify",
        namespace: "anti-analysis/self-modifying",
        description: "Modifies its own code at runtime",
        predicate: Predicate::ImportsAnyOf(&[
            "VirtualProtect", "mprotect",
        ]),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_imports(names: &[&str]) -> CapaContext {
        let imports: BTreeSet<String> = names.iter().map(|s| s.to_string()).collect();
        let imports_lower: BTreeSet<String> =
            imports.iter().map(|s| s.to_ascii_lowercase()).collect();
        CapaContext {
            imports,
            imports_lower,
            strings_lower: vec![],
            present_tags: BTreeSet::new(),
        }
    }

    #[test]
    fn imports_any_of_matches_case_insensitive() {
        let ctx = ctx_with_imports(&["readfile", "exit"]);
        let p = Predicate::ImportsAnyOf(&["ReadFile"]);
        let mut ev = Vec::new();
        assert!(eval(&p, &ctx, &mut ev));
        assert!(!ev.is_empty());
    }

    #[test]
    fn imports_any_of_misses_when_none_present() {
        let ctx = ctx_with_imports(&["exit"]);
        let p = Predicate::ImportsAnyOf(&["ReadFile"]);
        let mut ev = Vec::new();
        assert!(!eval(&p, &ctx, &mut ev));
    }

    #[test]
    fn all_of_requires_every_part() {
        let ctx = ctx_with_imports(&["OpenProcess"]);
        let p = Predicate::AllOf(&[
            Predicate::ImportsAnyOf(&["OpenProcess"]),
            Predicate::ImportsAnyOf(&["VirtualAllocEx"]),
        ]);
        let mut ev = Vec::new();
        assert!(!eval(&p, &ctx, &mut ev));

        let ctx2 = ctx_with_imports(&["OpenProcess", "VirtualAllocEx"]);
        let mut ev2 = Vec::new();
        assert!(eval(&p, &ctx2, &mut ev2));
    }

    #[test]
    fn any_of_short_circuit() {
        let ctx = ctx_with_imports(&["ReadFile"]);
        let p = Predicate::AnyOf(&[
            Predicate::ImportsAnyOf(&["ReadFile"]),
            Predicate::ImportsAnyOf(&["never-going-to-match"]),
        ]);
        let mut ev = Vec::new();
        assert!(eval(&p, &ctx, &mut ev));
    }

    #[test]
    fn builtin_rules_non_empty() {
        let rules = builtin_rules();
        assert!(rules.len() >= 20);
        // Every rule should have a namespace AND a name.
        for r in rules {
            assert!(!r.name.is_empty());
            assert!(!r.namespace.is_empty());
        }
    }

    #[test]
    fn tag_present_matches_existing_tag() {
        let mut ctx = ctx_with_imports(&[]);
        ctx.present_tags.insert("crypto".into());
        let p = Predicate::TagPresent(TagKind::Crypto);
        let mut ev = Vec::new();
        assert!(eval(&p, &ctx, &mut ev));
    }
}
