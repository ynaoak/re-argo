//! Flag the "hot" functions — high fan-in or high incoming-reference
//! count.
//!
//! IDA's "Most Referenced" and Binary Ninja's "Importance" tags both
//! surface the same observation: most binaries have a long tail of
//! tiny helpers and a small number of nucleus functions that
//! everything touches. Naming and reverse-engineering should start
//! at those hot spots; we want them obvious in the listing.
//!
//! For each function we compute:
//!
//! * `fan_in` — number of *distinct* caller functions
//! * `xref_in` — total number of incoming references (call sites)
//!
//! Functions in the top decile by `fan_in` (or `xref_in ≥ 8`,
//! whichever is more lenient) get a plate annotation:
//!
//! ```text
//!   hot function: called by 47 functions, 96 references in
//! ```
//!
//! PLT / thunk entries are excluded — every libc primitive looks
//! hot through the GOT funnel, which isn't useful to flag here.

use std::collections::BTreeMap;

use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::callgraph::CallGraph;

pub struct HotFunctionAnalyzer;

impl Analyzer for HotFunctionAnalyzer {
    fn name(&self) -> &str {
        "Hot Function"
    }
    fn description(&self) -> &str {
        "Marks top-decile functions by call-graph fan-in / incoming xref count"
    }
    fn priority(&self) -> u32 {
        // After Complexity (900) + CallGraphSccAnalyzer (910).
        915
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let cg = CallGraph::build(program);
        // fan_in via call-graph (distinct callers).
        let mut fan_in: BTreeMap<u64, usize> = BTreeMap::new();
        for f in program.listing.functions() {
            fan_in.insert(f.entry_point, cg.callers_of(f.entry_point).len());
        }
        // xref_in via reference table.
        let mut xref_in: BTreeMap<u64, usize> = BTreeMap::new();
        for f in program.listing.functions() {
            xref_in.insert(f.entry_point, program.references.get_refs_to(f.entry_point).len());
        }

        // Filter out thunks / @plt entries — they're never the
        // user-interesting hot spot.
        struct Cand {
            entry: u64,
            fan_in: usize,
            xref_in: usize,
        }
        let mut cands: Vec<Cand> = program
            .listing
            .functions()
            .filter(|f| !f.is_thunk && !f.name.contains("@plt"))
            .map(|f| Cand {
                entry: f.entry_point,
                fan_in: *fan_in.get(&f.entry_point).unwrap_or(&0),
                xref_in: *xref_in.get(&f.entry_point).unwrap_or(&0),
            })
            .collect();

        if cands.is_empty() {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        // Determine the top-decile fan_in threshold and apply it
        // alongside the xref_in≥8 absolute floor.
        let mut fans: Vec<usize> = cands.iter().map(|c| c.fan_in).collect();
        fans.sort_unstable();
        let threshold_idx = (fans.len() * 9) / 10; // 90th percentile
        let fan_threshold = fans[threshold_idx.min(fans.len() - 1)].max(3);

        cands.retain(|c| c.fan_in >= fan_threshold || c.xref_in >= 8);

        let mut emitted = 0usize;
        for c in &cands {
            if program.comments.get(c.entry, CommentType::Plate).is_some() {
                continue;
            }
            program.comments.set(
                c.entry,
                CommentType::Plate,
                format!(
                    "hot function: called by {} function{}, {} reference{} in",
                    c.fan_in,
                    if c.fan_in == 1 { "" } else { "s" },
                    c.xref_in,
                    if c.xref_in == 1 { "" } else { "s" }
                ),
            );
            emitted += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: emitted,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_compiles() {
        let _ = HotFunctionAnalyzer;
    }
}
