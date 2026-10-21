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

use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

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
    fn prepare_reads(&self) -> Option<State> {
        Some(State::SYMBOLS.union(State::COMMENTS))
    }
    fn writes(&self) -> State {
        State::TAGS.union(State::METADATA)
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    /// The import and string predicates of every rule evaluated: they
    /// do not depend on the tags (which the Tagger, right before, adds).
    fn prepare(&self, program: &Program) -> Prepared {
        let ctx = build_context(program, BTreeSet::new());
        let mut found: Vec<&'static Predicate> = Vec::new();
        for rule in builtin_rules() {
            collect_leaves(&rule.predicate, &mut found);
        }
        let leaves: Leaves = found
            .par_iter()
            .map(|&p| {
                let mut evidence = Vec::new();
                let hit = eval(p, &ctx, &mut evidence);
                (leaf_key(p), (hit, evidence))
            })
            .collect();
        Box::new(leaves)
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let leaves: Leaves = crate::analyzer::prepared(prepared);
        let present_tags = present_tags(program);
        let mut findings = Vec::new();
        for rule in builtin_rules() {
            let mut evidence = Vec::new();
            if eval_with(&rule.predicate, &present_tags, &leaves, &mut evidence) {
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
    /// The lower-cased import / symbol names, sorted and distinct.
    imports_lower: Haystack,
    /// For each of `imports_lower`, the first import (in sorted order)
    /// that lower-cases to it.
    original_import: Vec<String>,
    /// The comments, lower-cased.
    strings_lower: Haystack,
    present_tags: BTreeSet<String>,
}

/// Strings searched for the first one holding a needle: kept joined,
/// each followed by a NUL, so one search over all of them finds it
/// (a match holds no NUL, so it lies in one string, and the first
/// match is in the first string holding one).
#[derive(Default)]
struct Haystack {
    joined: Vec<u8>,
    /// Where each string starts in `joined`.
    starts: Vec<usize>,
    /// Whether a string holds a NUL itself (then each is searched alone).
    has_nul: bool,
}

impl Haystack {
    fn push(&mut self, s: &[u8]) {
        self.has_nul |= memchr::memchr(0, s).is_some();
        self.starts.push(self.joined.len());
        self.joined.extend_from_slice(s);
        self.joined.push(0);
    }

    /// The haystack of the strings of `parts`, in order.
    fn concat(parts: Vec<Haystack>) -> Self {
        let mut all = Haystack {
            joined: Vec::with_capacity(parts.iter().map(|p| p.joined.len()).sum()),
            starts: Vec::with_capacity(parts.iter().map(|p| p.starts.len()).sum()),
            has_nul: false,
        };
        for part in parts {
            let base = all.joined.len();
            all.has_nul |= part.has_nul;
            all.starts.extend(part.starts.iter().map(|&s| s + base));
            all.joined.extend_from_slice(&part.joined);
        }
        all
    }

    fn get(&self, i: usize) -> &[u8] {
        let end = self.starts.get(i + 1).map_or(self.joined.len(), |&e| e) - 1;
        &self.joined[self.starts[i]..end]
    }

    /// The index of the first string that contains `needle`, as testing
    /// each in order finds it.
    fn first_containing(&self, needle: &[u8]) -> Option<usize> {
        let finder = memchr::memmem::Finder::new(needle);
        if self.has_nul || needle.contains(&0) || needle.is_empty() {
            return (0..self.starts.len()).find(|&i| finder.find(self.get(i)).is_some());
        }
        // A large haystack is searched in parts in parallel, each part
        // whole strings (a match holds no NUL: it lies in one part), the
        // first part with a match giving the first one.
        const PART: usize = 1 << 18;
        let at = if self.joined.len() > 2 * PART {
            let parts = self.joined.len().div_ceil(PART);
            // (each part from the start of the first string at or past its
            // share)
            let bound = |k: usize| {
                if k == parts {
                    return self.joined.len();
                }
                let i = self.starts.partition_point(|&s| s < k * PART);
                self.starts.get(i).copied().unwrap_or(self.joined.len())
            };
            (0..parts).into_par_iter().find_map_first(|k| {
                let (lo, hi) = (bound(k), bound(k + 1));
                (lo < hi).then(|| finder.find(&self.joined[lo..hi]).map(|at| lo + at)).flatten()
            })?
        } else {
            finder.find(&self.joined)?
        };
        Some(self.starts.partition_point(|&s| s <= at) - 1)
    }
}

/// The result and evidence of each import / string predicate, by
/// [`leaf_key`].
type Leaves = rustc_hash::FxHashMap<(bool, usize), (bool, Vec<String>)>;

/// An import / string predicate's key: its kind and the address of its
/// (static) needle list.
fn leaf_key(p: &Predicate) -> (bool, usize) {
    match p {
        Predicate::ImportsAnyOf(needles) => (true, needles.as_ptr() as usize),
        Predicate::StringsAnyOf(needles) => (false, needles.as_ptr() as usize),
        _ => unreachable!("not an import / string predicate"),
    }
}

/// The import and string predicates in `p`, in [`eval`] order.
fn collect_leaves(p: &'static Predicate, out: &mut Vec<&'static Predicate>) {
    match p {
        Predicate::ImportsAnyOf(_) | Predicate::StringsAnyOf(_) => out.push(p),
        Predicate::TagPresent(_) => {}
        Predicate::AllOf(parts) | Predicate::AnyOf(parts) => {
            for part in *parts {
                collect_leaves(part, out);
            }
        }
    }
}

/// [`eval`] with the tags present and the import / string predicates
/// already evaluated (`leaves`): the same result and evidence.
fn eval_with(p: &Predicate, present_tags: &BTreeSet<String>, leaves: &Leaves, evidence: &mut Vec<String>) -> bool {
    match p {
        Predicate::ImportsAnyOf(_) | Predicate::StringsAnyOf(_) => {
            let (hit, found) = &leaves[&leaf_key(p)];
            evidence.extend(found.iter().cloned());
            *hit
        }
        Predicate::TagPresent(kind) => {
            let slug = kind.as_str().to_string();
            if present_tags.contains(&slug) {
                evidence.push(format!("tag {}", slug));
                true
            } else {
                false
            }
        }
        Predicate::AllOf(parts) => parts.iter().all(|p| eval_with(p, present_tags, leaves, evidence)),
        Predicate::AnyOf(parts) => parts.iter().any(|p| eval_with(p, present_tags, leaves, evidence)),
    }
}

/// The kinds of the tags on the program, as slugs.
fn present_tags(program: &Program) -> BTreeSet<String> {
    // (the distinct kinds borrowed first: a tag per address or function,
    // a handful of kinds)
    let mut kinds: BTreeSet<&str> = BTreeSet::new();
    let mut last: Option<&TagKind> = None;
    for (_, tag) in program.tags.iter_addresses().chain(program.tags.iter_functions()) {
        if last != Some(&tag.kind) {
            kinds.insert(tag.kind.as_str());
            last = Some(&tag.kind);
        }
    }
    kinds.into_iter().map(str::to_string).collect()
}

fn build_context(program: &Program, present_tags: BTreeSet<String>) -> CapaContext {
    // Every import name and symbol name (without `@plt`), sorted and
    // deduplicated.
    let mut imports: Vec<&str> = program.info.imports.iter().map(|imp| imp.name.as_str()).collect();
    imports.extend(program.symbol_table.iter().map(|sym| sym.name.strip_suffix("@plt").unwrap_or(&sym.name)));
    imports.par_sort_unstable();
    imports.dedup();
    // For each lower-cased name, the first name (in sorted order) that
    // lower-cases to it: a stable sort by the lower-cased name keeps
    // that one first.
    let mut lowered: Vec<(String, &str)> = imports.par_iter().map(|s| (s.to_ascii_lowercase(), *s)).collect();
    lowered.par_sort_by(|a, b| a.0.cmp(&b.0));
    lowered.dedup_by(|later, first| later.0 == first.0);
    // (sorted by the lower-cased name: the order of a set of them)
    let mut imports_lower = Haystack::default();
    let mut original_import: Vec<String> = Vec::with_capacity(lowered.len());
    for (lower, s) in lowered {
        imports_lower.push(lower.as_bytes());
        original_import.push(s.to_string());
    }

    // Pull strings from inline comments / immediate-string annotations
    // (every string the analyzer cared about flows through these).
    // (lower-cased in parts in parallel, then joined in order)
    let texts: Vec<&str> = program.comments.iter_refs().map(|(_, _, text)| text).collect();
    let parts: Vec<Haystack> = texts
        .par_chunks(4096)
        .map(|texts| {
            let mut part = Haystack::default();
            for text in texts {
                let at = part.joined.len();
                part.push(text.as_bytes());
                part.joined[at..].make_ascii_lowercase();
            }
            part
        })
        .collect();
    let strings_lower = Haystack::concat(parts);

    CapaContext {
        imports_lower,
        original_import,
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
                // the first import holding it, by its original-cased
                // name for the evidence list
                if let Some(i) = ctx.imports_lower.first_containing(nl.as_bytes()) {
                    evidence.push(format!("import {}", ctx.original_import[i]));
                    hit = true;
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
                if ctx.strings_lower.first_containing(nl.as_bytes()).is_some() {
                    evidence.push(format!("string {:?}", needle));
                    hit = true;
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

    /// The joined search finds the first string holding a needle, as a
    /// search of each string in order does (NULs in the strings or the
    /// needle, empty ones, repeats).
    #[test]
    fn haystack_finds_the_first_holder() {
        let sets: [&[&str]; 4] = [&["abc", "", "xbcd", "bc", "zzz"], &["a\0b", "b", "ab"], &[], &["", "only"]];
        let needles = ["bc", "b", "", "a\0b", "zz", "abcx", "\0", "c\0x", "only", "d"];
        for set in sets {
            let mut h = Haystack::default();
            for s in set {
                h.push(s.as_bytes());
            }
            for n in needles {
                let expected = set.iter().position(|s| s.contains(n));
                assert_eq!(h.first_containing(n.as_bytes()), expected, "{set:?} {n:?}");
            }
        }
    }

    /// A haystack searched in parts (large) or built from parts finds
    /// the same first holder as a test of each string in order.
    #[test]
    fn large_haystack_finds_the_first_holder() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // (many strings of letters, a few long ones spanning parts)
        let strings: Vec<String> = (0..40_000)
            .map(|i| {
                let len = if i % 9973 == 0 { 300_000 } else { (next() % 40) as usize };
                (0..len).map(|_| (b'a' + (next() % 6) as u8) as char).collect()
            })
            .collect();
        let mut whole = Haystack::default();
        for s in &strings {
            whole.push(s.as_bytes());
        }
        let parts: Vec<Haystack> = strings
            .chunks(777)
            .map(|c| {
                let mut h = Haystack::default();
                for s in c {
                    h.push(s.as_bytes());
                }
                h
            })
            .collect();
        let joined = Haystack::concat(parts);
        assert_eq!((&joined.joined, &joined.starts), (&whole.joined, &whole.starts));
        assert!(whole.joined.len() > 1 << 20);
        for needle in ["abcdef", "fedcba", "aaaaaaa", "ffffffff", "abcabcabc", "zz", "a", "eeeeeeeeeeee"] {
            let expected = strings.iter().position(|s| s.contains(needle));
            assert_eq!(whole.first_containing(needle.as_bytes()), expected, "{needle}");
        }
    }

    fn ctx_with_imports(names: &[&str]) -> CapaContext {
        let imports: BTreeSet<String> = names.iter().map(|s| s.to_string()).collect();
        let mut by_lower = std::collections::BTreeMap::new();
        for s in &imports {
            by_lower.entry(s.to_ascii_lowercase()).or_insert_with(|| s.clone());
        }
        let mut imports_lower = Haystack::default();
        let mut original_import = Vec::new();
        for (lower, s) in by_lower {
            imports_lower.push(lower.as_bytes());
            original_import.push(s);
        }
        CapaContext {
            imports_lower,
            original_import,
            strings_lower: Haystack::default(),
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
