//! Re-categorise the existing plate / pre / EOL comment stream into
//! BN-style tags so the `tags` CLI and `summary` report can filter
//! findings by category.
//!
//! This analyzer is intentionally a pure re-classifier: it doesn't
//! invent new findings, it walks `program.comments` + a few other
//! analyzer-populated structures (`function.no_return`,
//! `function.is_thunk`, `metadata.varargs_*_max`,
//! `metadata.scc_*_funcs`) and slots each into one or more tag
//! categories. That keeps the analyzer pipeline acyclic and lets the
//! tag set evolve without touching every individual analyzer.
//!
//! Why re-categorise instead of having each analyzer emit a tag
//! directly?
//!
//! * Single point of taxonomy maintenance — if we want to merge
//!   `noreturn` + `panic` into one category, we change one file.
//! * The CommentManager output is what users see in the listing;
//!   tags are the report-friendly view. Both must agree, and
//!   deriving tags from comments is the cheapest way to enforce that.
//! * User-written sidecar comments automatically flow into tags
//!   when their text matches a known pattern, so override workflows
//!   get tagging for free.

use reargo_program::tags::TagKind;
use rayon::prelude::*;
use reargo_program::Program;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

pub struct TagAnalyzer;

impl Analyzer for TagAnalyzer {
    fn name(&self) -> &str {
        "Tagger"
    }
    fn description(&self) -> &str {
        "Categorises analyzer findings (comments + metadata) into Binary-Ninja-style tags"
    }
    fn priority(&self) -> u32 {
        // Last in the pipeline so every other analyzer has already
        // written its comments / metadata.
        950
    }
    fn prepare_reads(&self) -> Option<State> {
        Some(
            State::COMMENTS
                .union(State::CODE)
                .union(State::FUNC_NAME)
                .union(State::FUNC_NO_RETURN)
                .union(State::METADATA)
                .union(State::SYMBOLS),
        )
    }
    fn writes(&self) -> State {
        State::TAGS
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    /// The address tags, then the function tags, in the order they are
    /// added.
    fn prepare(&self, program: &Program) -> Prepared {
        // The tags of every comment, derived in parallel (in comment
        // order), then added in that order.
        let derived: Vec<(u64, TagKind, String)> = {
            let comments: Vec<(u64, &str)> = program.comments.iter_refs().map(|(a, _, t)| (a, t)).collect();
            comments
                .par_iter()
                .flat_map_iter(|&(addr, text)| {
                    derive_tags(text)
                        .into_iter()
                        .map(move |(cat, derived_text)| (addr, cat, derived_text.unwrap_or_else(|| text.to_string())))
                })
                .collect()
        };

        let mut function_tags: Vec<(u64, TagKind, String)> = Vec::new();

        // Function-scope tags from Function flags.
        let func_facts: Vec<(u64, bool, bool, String)> = program
            .listing
            .functions()
            .map(|f| (f.entry_point, f.no_return, f.is_thunk, f.name.clone()))
            .collect();
        for (entry, no_return, is_thunk, name) in func_facts {
            if no_return {
                function_tags.push((entry, TagKind::NoReturn, format!("{}: no-return", name)));
            }
            if is_thunk {
                function_tags.push((entry, TagKind::Library, format!("{}: thunk", name)));
            }
            // Standard library names get a `library` tag so users can
            // filter their report to "what touches libc?"
            if name.contains("@plt") || name.contains("@GLIBC") || name.contains("@GOT") {
                function_tags.push((entry, TagKind::Library, format!("{}: import", name)));
            }
        }

        // Metadata-derived: SCC cluster members get `recursive`.
        let scc_keys: Vec<String> = program
            .metadata
            .properties
            .keys()
            .filter(|k| k.starts_with("scc_") && k.ends_with("_funcs"))
            .cloned()
            .collect();
        // The address of the first symbol (in symbol-table order)
        // carrying each cluster member's name, found in one pass over
        // the symbols instead of one scan per name.
        let wanted: FxHashSet<&str> = scc_keys
            .iter()
            .filter_map(|k| program.metadata.properties.get(k))
            .flat_map(|v| v.split(", "))
            .collect();
        let mut first_by_name: FxHashMap<String, u64> = FxHashMap::default();
        if !wanted.is_empty() {
            for sym in program.symbol_table.iter() {
                if wanted.contains(sym.name.as_str()) && !first_by_name.contains_key(sym.name.as_str()) {
                    first_by_name.insert(sym.name.clone(), sym.address);
                }
            }
        }
        for k in scc_keys {
            // The value is a comma-separated function name list;
            // we tag each function name's entry address.
            let Some(value) = program.metadata.properties.get(&k).cloned() else {
                continue;
            };
            for name in value.split(", ") {
                if let Some(&address) = first_by_name.get(name) {
                    function_tags.push((address, TagKind::Recursive, format!("{}: cluster {}", name, k)));
                }
            }
        }
        Box::new((derived, function_tags))
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        type Tags = Vec<(u64, TagKind, String)>;
        let (derived, function_tags): (Tags, Tags) = crate::analyzer::prepared(prepared);
        let tag_count = derived.len() + function_tags.len();
        for (addr, cat, text) in derived {
            program.tags.add_address(addr, cat, text, true);
        }
        for (entry, cat, text) in function_tags {
            program.tags.add_function(entry, cat, text, true);
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: tag_count,
        })
    }
}

/// Inspect a comment string and decide which TagKind(s) it belongs
/// to. The same comment can produce multiple tags — a function
/// flagged both "stack-protected" and "wrapper" gets both tags.
/// Returns `(kind, optional_replacement_text)` pairs; when the
/// replacement is `None`, the original comment text is used.
fn derive_tags(text: &str) -> Vec<(TagKind, Option<String>)> {
    let mut out = Vec::new();

    // Direct prefix / keyword matches against the analyzer output
    // we already emit. Keep these in sync with the comment strings
    // in canary.rs / anti_debug.rs / crypto.rs / etc.
    //
    // The previous form allocated a `String` lowered copy of every
    // comment regardless of need. Most comments hit only `starts_with`
    // checks, so we now defer the lowering to the first
    // case-insensitive needle we test.
    if text.starts_with("crypto:") {
        out.push((TagKind::Crypto, None));
    }
    if text.starts_with("C++ EH:") {
        out.push((TagKind::Exception, None));
    }
    if text.starts_with("wrapper →") || text.starts_with("wrapper ->") {
        out.push((TagKind::Wrapper, None));
    }
    if text.starts_with("hot function:") {
        out.push((TagKind::Important, None));
    }
    if text.starts_with("recursive cluster:") {
        out.push((TagKind::Recursive, None));
    }
    if text.starts_with("loop header") || text.starts_with("loop back-edge") {
        out.push((TagKind::Loop, None));
    }
    if text.starts_with("no-return") || text.contains("noreturn") {
        out.push((TagKind::NoReturn, None));
    }
    if text.starts_with("CRT helper:") || text.starts_with("GOT slot ->") {
        out.push((TagKind::Library, None));
    }
    if text.starts_with("TLS callback") {
        // TLS callbacks are runtime hooks — flag as suspicious so
        // they're easy to find in malware triage.
        out.push((TagKind::Suspicious, None));
    }

    // Case-insensitive needles — only allocate the lowered copy when
    // at least one of these is reached.
    let lower = text.to_ascii_lowercase();
    if lower.contains("stack-protected") || lower.contains("canary load") {
        out.push((TagKind::StackProtected, None));
    }
    if lower.contains("anti-debug")
        || lower.contains("rdtsc")
        || lower.contains("int3")
        || lower.contains("ptrace")
        || lower.contains("isdebuggerpresent")
    {
        out.push((TagKind::AntiDebug, None));
    }
    if lower.contains("itanium abi") && !out.iter().any(|(k, _)| matches!(k, TagKind::Exception)) {
        out.push((TagKind::Exception, None));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_plate_recognised() {
        let t = derive_tags("crypto: AES S-box (forward)");
        assert!(t.iter().any(|(k, _)| matches!(k, TagKind::Crypto)));
    }

    #[test]
    fn stack_protected_recognised() {
        let t = derive_tags("stack-protected");
        assert!(t.iter().any(|(k, _)| matches!(k, TagKind::StackProtected)));
    }

    #[test]
    fn anti_debug_multiple_keywords() {
        let t = derive_tags("rdtsc — timing read (possible anti-debug)");
        assert!(t.iter().any(|(k, _)| matches!(k, TagKind::AntiDebug)));
    }

    #[test]
    fn wrapper_arrow_recognised() {
        let t = derive_tags("wrapper → f_fatal_s");
        assert!(t.iter().any(|(k, _)| matches!(k, TagKind::Wrapper)));
    }

    #[test]
    fn loop_header_recognised() {
        let t = derive_tags("loop header (back-edge from 0x401234)");
        assert!(t.iter().any(|(k, _)| matches!(k, TagKind::Loop)));
    }

    #[test]
    fn unknown_text_produces_no_tags() {
        assert!(derive_tags("totally unrelated message").is_empty());
    }
}
