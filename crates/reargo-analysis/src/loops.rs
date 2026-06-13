//! Detect intra-function loops by finding backward branches.
//!
//! IDA and Binary Ninja both visualise loops in their CFG view; the
//! analysis underneath is dominance-based (a back-edge is an edge
//! `A → B` where `B` dominates `A`). Computing dominator trees for
//! every function is expensive and Rust-side dominance code already
//! exists in `reargo-decompile`. For an annotation-grade pass we don't
//! need full dominance — a backward branch whose target lies inside
//! the same function's body is almost always a loop back-edge.
//!
//! False positives are limited to:
//! * `jmp .L1` over a `nop` slide (Rust-style retry blocks) — these
//!   are technically loops at the CFG level too, so the
//!   annotation is still correct.
//! * Branch-back-to-prologue-style call-into-itself, which is
//!   genuine recursion and we *don't* want to annotate; we exclude
//!   targets equal to the function's entry point to avoid this.
//!
//! For each detected back-edge we emit:
//!
//! ```text
//!   <branch addr>  Post   loop back-edge -> 0x<target>
//!   <target>       Plate  loop header (back-edge from 0x<branch>)
//! ```

use reargo_arch::FlowType;
use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct LoopAnalyzer;

impl Analyzer for LoopAnalyzer {
    fn name(&self) -> &str {
        "Loop Detection"
    }
    fn description(&self) -> &str {
        "Marks back-edges and loop headers from intra-function backward branches"
    }
    fn priority(&self) -> u32 {
        // Run after Switch/TailCall (which annotate branches with
        // semantic flow info) and after CallSiteAnnotator (we don't
        // want to fight Pre comments on a call insn that happens to
        // branch back).
        785
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        struct FuncSnap {
            entry: u64,
            ranges: Vec<(u64, u64)>,
        }
        let funcs: Vec<FuncSnap> = program
            .listing
            .functions()
            .map(|f| FuncSnap {
                entry: f.entry_point,
                ranges: f
                    .body
                    .ranges()
                    .map(|r| (r.start.offset, r.start.offset + r.size))
                    .collect(),
            })
            .collect();

        // (branch_addr, target_addr, function_entry) — emitted in
        // two passes so we can also write the header annotation
        // without re-iterating.
        let mut back_edges: Vec<(u64, u64, u64)> = Vec::new();
        for snap in &funcs {
            for (start, end) in &snap.ranges {
                for insn in program.listing.instructions_in_range(*start, *end) {
                    let is_branch = matches!(
                        insn.flow_type,
                        FlowType::ConditionalJump | FlowType::UnconditionalJump
                    );
                    if !is_branch {
                        continue;
                    }
                    let Some(target) = insn.branch_target else {
                        continue;
                    };
                    // Backward branch inside this function's body.
                    if target >= insn.address {
                        continue;
                    }
                    if target == snap.entry {
                        // recursion-to-entry — skip
                        continue;
                    }
                    let inside = snap
                        .ranges
                        .iter()
                        .any(|(s, e)| target >= *s && target < *e);
                    if !inside {
                        continue;
                    }
                    back_edges.push((insn.address, target, snap.entry));
                }
            }
        }

        let mut header_set: std::collections::BTreeSet<(u64, u64)> = std::collections::BTreeSet::new();
        let mut emitted = 0usize;

        for (branch, target, _entry) in &back_edges {
            if program.comments.get(*branch, CommentType::Post).is_none() {
                program.comments.set(
                    *branch,
                    CommentType::Post,
                    format!("loop back-edge -> 0x{:x}", target),
                );
                emitted += 1;
            }
            header_set.insert((*target, *branch));
        }

        // Group headers; if multiple back-edges land on the same
        // header (rare — irreducible loops), enumerate them.
        let mut by_header: std::collections::BTreeMap<u64, Vec<u64>> = std::collections::BTreeMap::new();
        for (target, branch) in &header_set {
            by_header.entry(*target).or_default().push(*branch);
        }
        for (target, branches) in by_header {
            if program.comments.get(target, CommentType::Plate).is_some() {
                continue;
            }
            let text = if branches.len() == 1 {
                format!("loop header (back-edge from 0x{:x})", branches[0])
            } else {
                let formatted: Vec<String> =
                    branches.iter().map(|b| format!("0x{:x}", b)).collect();
                format!("loop header (back-edges from {})", formatted.join(", "))
            };
            program.comments.set(target, CommentType::Plate, text);
            emitted += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: emitted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Loop detection is data-driven over the listing + flow_type
    // information from reargo-arch. Behaviour is exercised end-to-end
    // by the test binaries the harness already analyses.
    #[test]
    fn module_compiles() {
        let _ = LoopAnalyzer;
    }
}
