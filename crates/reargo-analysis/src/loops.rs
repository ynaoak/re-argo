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
use reargo_program::comments::{CommentBatch, CommentType};
use rayon::prelude::*;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

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
    fn prepare_reads(&self) -> Option<State> {
        Some(State::CODE)
    }
    fn writes(&self) -> State {
        State::COMMENTS
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    fn prepare(&self, program: &Program) -> Prepared {
        // (branch_addr, target_addr, function_entry) — emitted in
        // two passes so we can also write the header annotation
        // without re-iterating.
        // Functions are independent: walked in parallel, the edges kept
        // in function order.
        let funcs: Vec<&reargo_program::function::Function> = program.listing.functions().collect();
        let listing = &program.listing;
        // (the body walks read the instructions sorted: no instruction is
        // listed after this analyzer)
        listing.sorted_instructions();
        let back_edges: Vec<(u64, u64, u64)> = funcs
            .par_iter()
            .flat_map_iter(|f| {
                let mut edges: Vec<(u64, u64, u64)> = Vec::new();
                let entry = f.entry_point;
                // A body holds one range per instruction: test membership
                // by a binary search over the merged ranges (of its runs
                // of adjacent ranges, the same addresses).
                let merged = crate::deadcode::merge_ranges(&f.body.runs());
                let inside = |a: u64| {
                    let i = merged.partition_point(|&(s, _)| s <= a);
                    i > 0 && a < merged[i - 1].1
                };
                listing.for_each_body_instruction(&f.body, |_, insn| {
                    let is_branch = matches!(
                        insn.flow_type,
                        FlowType::ConditionalJump | FlowType::UnconditionalJump
                    );
                    if !is_branch {
                        return;
                    }
                    let Some(target) = insn.branch_target else {
                        return;
                    };
                    // Backward branch inside this function's body.
                    if target >= insn.address {
                        return;
                    }
                    if target == entry {
                        // recursion-to-entry — skip
                        return;
                    }
                    if !inside(target) {
                        return;
                    }
                    edges.push((insn.address, target, entry));
                });
                edges
            })
            .collect();
        // The comments, formatted here (each is set only where its slot
        // is still free when applied).
        let posts: Vec<(u64, String)> =
            back_edges.iter().map(|(branch, target, _)| (*branch, format!("loop back-edge -> 0x{:x}", target))).collect();
        let header_set: std::collections::BTreeSet<(u64, u64)> =
            back_edges.iter().map(|(branch, target, _)| (*target, *branch)).collect();

        // Group headers; if multiple back-edges land on the same
        // header (rare — irreducible loops), enumerate them.
        let mut by_header: std::collections::BTreeMap<u64, Vec<u64>> = std::collections::BTreeMap::new();
        for (target, branch) in &header_set {
            by_header.entry(*target).or_default().push(*branch);
        }
        let plates: Vec<(u64, String)> = by_header
            .into_iter()
            .map(|(target, branches)| {
                let text = if branches.len() == 1 {
                    format!("loop header (back-edge from 0x{:x})", branches[0])
                } else {
                    let formatted: Vec<String> =
                        branches.iter().map(|b| format!("0x{:x}", b)).collect();
                    format!("loop header (back-edges from {})", formatted.join(", "))
                };
                (target, text)
            })
            .collect();
        // (sorted into a map here, each set at `apply` where still free)
        Box::new(CommentBatch::new(
            posts
                .into_iter()
                .map(|(branch, text)| (branch, CommentType::Post, text))
                .chain(plates.into_iter().map(|(target, text)| (target, CommentType::Plate, text))),
        ))
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let comments: CommentBatch = crate::analyzer::prepared(prepared);
        let emitted = program.comments.set_batch_if_absent(comments);

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
