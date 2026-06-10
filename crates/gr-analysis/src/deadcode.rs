//! Detect basic blocks inside a function that the entry can't reach.
//!
//! Dead-code detection at the CFG level: build the reachability set
//! from the function entry by following fall-through and branch
//! edges, then flag any basic block whose start address is in the
//! function body but not in the reachable set.
//!
//! Reasons a block can be unreachable in practice:
//! * The compiler emitted an exception-cleanup pad we never enter
//!   from the normal flow (handled via landingpad metadata, not
//!   instruction-level edges).
//! * Hand-written assembly or obfuscated code with a non-fall-
//!   through jump pattern.
//! * Stale code that survived linker optimisation.
//!
//! For each unreachable block we set:
//!
//! ```text
//!   <block_start>  Plate  unreachable from function entry
//! ```
//!
//! The flag is *informational* — we don't drop the block from the
//! listing. Downstream coverage / xref consumers may want to know
//! the bytes exist even though no normal-flow caller reaches them.

use std::collections::{BTreeSet, VecDeque};

use gr_arch::FlowType;
use gr_program::comments::CommentType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct DeadCodeAnalyzer;

impl Analyzer for DeadCodeAnalyzer {
    fn name(&self) -> &str {
        "Dead Code"
    }
    fn description(&self) -> &str {
        "Flags basic blocks unreachable from the function entry by CFG walk"
    }
    fn priority(&self) -> u32 {
        // Same band as Complexity (900) — after every analyzer that
        // can add functions / refs.
        905
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        struct FuncSnap {
            entry: u64,
            ranges: Vec<(u64, u64)>,
        }
        let snaps: Vec<FuncSnap> = program
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

        let mut all_unreachable: Vec<u64> = Vec::new();
        for snap in &snaps {
            // Build the per-function block-start set by walking
            // instructions and noting:
            //   * the entry address
            //   * every branch target inside the body
            //   * the fall-through of every branch / return
            let mut block_starts: BTreeSet<u64> = BTreeSet::new();
            block_starts.insert(snap.entry);
            let in_body = |a: u64| snap.ranges.iter().any(|(s, e)| a >= *s && a < *e);

            // Snapshot insns in body, sorted.
            let mut insns: Vec<(u64, u32, FlowType, Option<u64>)> = Vec::new();
            for (s, e) in &snap.ranges {
                for i in program.listing.instructions_in_range(*s, *e) {
                    insns.push((i.address, i.length, i.flow_type, i.branch_target));
                }
            }
            insns.sort_by_key(|(a, _, _, _)| *a);

            let mut prev_was_terminator = false;
            for (addr, _len, ft, tgt) in &insns {
                if prev_was_terminator {
                    block_starts.insert(*addr);
                }
                prev_was_terminator = false;
                match ft {
                    FlowType::ConditionalJump | FlowType::UnconditionalJump => {
                        if let Some(t) = tgt
                            && in_body(*t)
                        {
                            block_starts.insert(*t);
                        }
                        prev_was_terminator = true;
                    }
                    FlowType::Return => prev_was_terminator = true,
                    _ => {}
                }
            }

            // Walk reachability from entry using fall-through +
            // branch edges.
            let mut reachable: BTreeSet<u64> = BTreeSet::new();
            let mut queue: VecDeque<u64> = VecDeque::new();
            queue.push_back(snap.entry);
            while let Some(b) = queue.pop_front() {
                if !reachable.insert(b) {
                    continue;
                }
                // Walk insns from b until we hit a terminator or
                // bump into the next block start.
                let mut cur = b;
                let next_start = block_starts
                    .range(b + 1..)
                    .next()
                    .copied()
                    .unwrap_or(u64::MAX);
                let mut idx = insns.binary_search_by_key(&cur, |(a, _, _, _)| *a);
                while let Ok(i) = idx {
                    let (addr, len, ft, tgt) = insns[i];
                    if addr >= next_start {
                        if in_body(addr) {
                            queue.push_back(addr);
                        }
                        break;
                    }
                    let after = addr + len as u64;
                    match ft {
                        FlowType::Return => break,
                        FlowType::UnconditionalJump => {
                            if let Some(t) = tgt
                                && in_body(t)
                            {
                                queue.push_back(t);
                            }
                            break;
                        }
                        FlowType::ConditionalJump => {
                            if let Some(t) = tgt
                                && in_body(t)
                            {
                                queue.push_back(t);
                            }
                            if in_body(after) {
                                queue.push_back(after);
                            }
                            break;
                        }
                        _ => {
                            cur = after;
                            idx = insns.binary_search_by_key(&cur, |(a, _, _, _)| *a);
                        }
                    }
                }
            }

            for &start in &block_starts {
                if !reachable.contains(&start) {
                    all_unreachable.push(start);
                }
            }
        }

        let mut emitted = 0usize;
        for addr in all_unreachable {
            if program.comments.get(addr, CommentType::Plate).is_some() {
                continue;
            }
            program
                .comments
                .set(addr, CommentType::Plate, "unreachable from function entry");
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

    #[test]
    fn module_compiles() {
        let _ = DeadCodeAnalyzer;
    }
}
