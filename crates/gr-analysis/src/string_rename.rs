//! Rename anonymous functions based on the strings they reference.
//!
//! A stripped binary's `FUN_4012a0` is impossible to triage by eye.
//! But if that function is small and the only thing it does is
//! pass `"malloc failed: %s\n"` to `fprintf` before calling `exit`,
//! the string *is* the function name — that's what every reverse-
//! engineering plugin (IDA's "Heuristic Procedure Naming", BN's
//! "Auto-name from string") does to make stripped output readable.
//!
//! This analyzer:
//!
//! 1. Iterates every `FUN_*` (unnamed, non-thunk) function.
//! 2. Walks the references *out of* its body, looking for the most
//!    distinctive printable string the function loads.
//! 3. Sanitises the string into a C identifier and renames the
//!    function to `f_<slug>`.
//!
//! Constraints (keeps precision high, avoids name collisions):
//!
//! * String must be ≥ 6 chars long and contain at least one
//!   alphabetic character.
//! * Picks the *first* candidate by address — so two
//!   randomly-similar strings don't accidentally collide.
//! * Skips when another function in the listing already has the
//!   proposed name.
//! * Skips trivial / generic strings (single common word) — those
//!   make worse names than `FUN_*`.

use std::collections::BTreeSet;

use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct StringHintRenameAnalyzer;

impl Analyzer for StringHintRenameAnalyzer {
    fn name(&self) -> &str {
        "String-Hint Rename"
    }
    fn description(&self) -> &str {
        "Renames FUN_* functions using the most distinctive string they reference"
    }
    fn priority(&self) -> u32 {
        // After CrtAnalyzer (710) + LateDiscovery (730) + SignatureApplier
        // (700) so we only rename what's still truly anonymous, but
        // before CallSiteAnnotator (750) so its annotation uses the
        // new name.
        740
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        // Collect existing names so we don't propose a colliding rename.
        let mut taken: BTreeSet<String> = BTreeSet::new();
        for f in program.listing.functions() {
            taken.insert(f.name.clone());
        }
        for s in program.symbol_table.iter() {
            taken.insert(s.name.clone());
        }

        struct Candidate {
            entry: u64,
            ranges: Vec<(u64, u64)>,
        }
        let candidates: Vec<Candidate> = program
            .listing
            .functions()
            .filter(|f| f.name.starts_with("FUN_") && !f.is_thunk)
            .map(|f| Candidate {
                entry: f.entry_point,
                ranges: f
                    .body
                    .ranges()
                    .map(|r| (r.start.offset, r.start.offset + r.size))
                    .collect(),
            })
            .collect();

        let mut renames: Vec<(u64, String)> = Vec::new();
        for cand in &candidates {
            // References whose source is inside this function and
            // whose target dereferences to a printable string.
            let mut best: Option<(u64, String)> = None;
            for (start, end) in &cand.ranges {
                for from in *start..*end {
                    let refs = program.references.get_refs_from(from);
                    if refs.is_empty() {
                        continue;
                    }
                    for r in refs {
                        let Some(s) = read_c_string(program, r.to) else {
                            continue;
                        };
                        let Some(slug) = sanitize_slug(&s) else {
                            continue;
                        };
                        let proposed = format!("f_{}", slug);
                        if taken.contains(&proposed) {
                            continue;
                        }
                        // Prefer the lowest-address string — picks
                        // a stable "first" candidate so re-runs are
                        // deterministic.
                        match &best {
                            None => best = Some((r.to, proposed)),
                            Some((cur_addr, _)) if r.to < *cur_addr => {
                                best = Some((r.to, proposed));
                            }
                            _ => {}
                        }
                    }
                }
            }
            if let Some((_addr, name)) = best {
                taken.insert(name.clone());
                renames.push((cand.entry, name));
            }
        }

        let mut renamed = 0usize;
        for (entry, name) in renames {
            program.symbol_table.add(Symbol::new(
                name.clone(),
                entry,
                SymbolType::Function,
                SourceType::Analysis,
            ));
            if let Some(f) = program.listing.get_function_mut(entry)
                && f.name.starts_with("FUN_")
            {
                f.name = name;
                renamed += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: renamed,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

fn read_c_string(program: &Program, addr: u64) -> Option<String> {
    let mut buf = [0u8; 64];
    let n = [64, 32, 16, 8]
        .into_iter()
        .find(|&n| program.info.memory.read_bytes(addr, &mut buf[..n]).is_ok())?;
    let nul = buf[..n].iter().position(|&b| b == 0)?;
    if nul < 6 {
        return None;
    }
    let s = &buf[..nul];
    let printable = s
        .iter()
        .filter(|&&b| (b' '..=b'~').contains(&b) || b == b'\n' || b == b'\t')
        .count();
    if printable * 5 < s.len() * 4 {
        return None;
    }
    let has_alpha = s.iter().any(|&b| b.is_ascii_alphabetic());
    if !has_alpha {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Turn a free-form string into a C-identifier-shaped slug, capped
/// to 32 chars. Returns None when the slug is shorter than 4 chars
/// (which would yield uninformative `f_xx` style names) or when the
/// resulting word matches a generic stop-set we explicitly reject.
fn sanitize_slug(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut prev_underscore = false;
    for c in s.chars().take(48) {
        let ok = c.is_ascii_alphanumeric() || c == '_';
        if ok {
            out.push(c.to_ascii_lowercase());
            prev_underscore = false;
        } else if !prev_underscore && !out.is_empty() {
            out.push('_');
            prev_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    while out.starts_with(|c: char| c.is_ascii_digit() || c == '_') {
        out.remove(0);
    }
    if out.len() < 4 {
        return None;
    }
    if out.len() > 32 {
        out.truncate(32);
        while out.ends_with('_') {
            out.pop();
        }
    }
    // Reject one-word generic names that are worse than FUN_*.
    let stop: &[&str] = &[
        "true", "false", "null", "none", "true_", "yes", "ok", "okay",
        "error", "value", "data", "name", "item", "result",
    ];
    if stop.contains(&out.as_str()) {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_basic() {
        assert_eq!(sanitize_slug("hello world").as_deref(), Some("hello_world"));
        assert_eq!(
            sanitize_slug("malloc failed: %s\n").as_deref(),
            Some("malloc_failed_s")
        );
    }

    #[test]
    fn slug_truncates_long() {
        let s = "a".repeat(64);
        let out = sanitize_slug(&s).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn slug_rejects_short() {
        assert!(sanitize_slug("hi").is_none());
        assert!(sanitize_slug("   ").is_none());
        assert!(sanitize_slug("123").is_none()); // numeric only
    }

    #[test]
    fn slug_strips_leading_digits() {
        assert_eq!(sanitize_slug("404 not found").as_deref(), Some("not_found"));
    }

    #[test]
    fn slug_rejects_generic_word() {
        assert!(sanitize_slug("error").is_none());
        assert!(sanitize_slug("result").is_none());
    }

    #[test]
    fn slug_preserves_underscores() {
        assert_eq!(
            sanitize_slug("on_message_received").as_deref(),
            Some("on_message_received")
        );
    }
}
