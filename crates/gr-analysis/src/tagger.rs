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

use gr_program::comments::CommentType;
use gr_program::tags::TagKind;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

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
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        // Snapshot comments so the iteration borrow doesn't fight
        // the tag-manager mutation.
        let comments: Vec<(u64, CommentType, String)> = program
            .comments
            .iter()
            .map(|c| (c.address, c.comment_type, c.text))
            .collect();

        let mut tag_count = 0usize;
        for (addr, _kind, text) in &comments {
            for (cat, derived_text) in derive_tags(text) {
                program
                    .tags
                    .add_address(*addr, cat, derived_text.unwrap_or_else(|| text.clone()), true);
                tag_count += 1;
            }
        }

        // Function-scope tags from Function flags.
        let func_facts: Vec<(u64, bool, bool, String)> = program
            .listing
            .functions()
            .map(|f| (f.entry_point, f.no_return, f.is_thunk, f.name.clone()))
            .collect();
        for (entry, no_return, is_thunk, name) in func_facts {
            if no_return {
                program.tags.add_function(
                    entry,
                    TagKind::NoReturn,
                    format!("{}: no-return", name),
                    true,
                );
                tag_count += 1;
            }
            if is_thunk {
                program
                    .tags
                    .add_function(entry, TagKind::Library, format!("{}: thunk", name), true);
                tag_count += 1;
            }
            // Standard library names get a `library` tag so users can
            // filter their report to "what touches libc?"
            if name.contains("@plt") || name.contains("@GLIBC") || name.contains("@GOT") {
                program.tags.add_function(
                    entry,
                    TagKind::Library,
                    format!("{}: import", name),
                    true,
                );
                tag_count += 1;
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
        for k in scc_keys {
            // The value is a comma-separated function name list;
            // we tag each function name's entry address.
            let Some(value) = program.metadata.properties.get(&k).cloned() else {
                continue;
            };
            for name in value.split(", ") {
                if let Some(sym) = program
                    .symbol_table
                    .iter()
                    .find(|s| s.name == name)
                {
                    program.tags.add_function(
                        sym.address,
                        TagKind::Recursive,
                        format!("{}: cluster {}", name, k),
                        true,
                    );
                    tag_count += 1;
                }
            }
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
