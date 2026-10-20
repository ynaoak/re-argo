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

use std::collections::VecDeque;

use rayon::prelude::*;
use reargo_arch::FlowType;
use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

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
        struct FuncSnap<'a> {
            entry: u64,
            body: &'a reargo_core::address::AddressSet,
        }
        let snaps: Vec<FuncSnap> =
            program.listing.functions().map(|f| FuncSnap { entry: f.entry_point, body: &f.body }).collect();

        // Functions are independent: walk them in parallel, keeping
        // the results in function order.
        let listing = &program.listing;
        let per_function: Vec<Vec<u64>> = snaps.par_iter().map(|snap| {
            let mut unreachable: Vec<u64> = Vec::new();
            // Build the per-function block-start set by walking
            // instructions and noting:
            //   * the entry address
            //   * every branch target inside the body
            //   * the fall-through of every branch / return
            // (sorted and deduplicated once all are in)
            let mut block_starts: Vec<u64> = vec![snap.entry];
            // A body holds one range per instruction: test membership
            // by a binary search over the merged ranges instead of a
            // scan of all of them.
            let merged = merge_body_ranges(snap.body);
            let in_body = |a: u64| {
                let i = merged.partition_point(|&(s, _)| s <= a);
                i > 0 && a < merged[i - 1].1
            };

            // Snapshot insns in body, sorted.
            let mut insns: Vec<(u64, u32, FlowType, Option<u64>)> = Vec::new();
            listing.for_each_body_instruction(snap.body, |_, i| {
                insns.push((i.address, i.length, i.flow_type, i.branch_target));
            });
            if !insns.is_sorted_by_key(|(a, _, _, _)| *a) {
                insns.sort_by_key(|(a, _, _, _)| *a);
            }

            let mut prev_was_terminator = false;
            for (addr, _len, ft, tgt) in &insns {
                if prev_was_terminator {
                    block_starts.push(*addr);
                }
                prev_was_terminator = false;
                match ft {
                    FlowType::ConditionalJump | FlowType::UnconditionalJump => {
                        if let Some(t) = tgt
                            && in_body(*t)
                        {
                            block_starts.push(*t);
                        }
                        prev_was_terminator = true;
                    }
                    FlowType::Return => prev_was_terminator = true,
                    _ => {}
                }
            }

            block_starts.sort_unstable();
            block_starts.dedup();

            // Walk reachability from entry using fall-through +
            // branch edges.
            let mut reachable: rustc_hash::FxHashSet<u64> = rustc_hash::FxHashSet::default();
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
                    .get(block_starts.partition_point(|&s| s <= b))
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
                            // mostly the next instruction
                            idx = match insns.get(i + 1) {
                                Some(next) if next.0 == cur => Ok(i + 1),
                                _ => insns.binary_search_by_key(&cur, |(a, _, _, _)| *a),
                            };
                        }
                    }
                }
            }

            for &start in &block_starts {
                if !reachable.contains(&start) {
                    unreachable.push(start);
                }
            }
            unreachable
        }).collect();
        Box::new(per_function.into_iter().flatten().collect::<Vec<u64>>())
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let all_unreachable: Vec<u64> = crate::analyzer::prepared(prepared);
        let mut emitted = 0usize;
        for addr in all_unreachable {
            if program.comments.set_if_absent(addr, CommentType::Plate, "unreachable from function entry") {
                emitted += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: emitted,
        })
    }
}

/// [`merge_ranges`] of the body's ranges `(start, start + size)`, in
/// one pass when they come sorted by `(start, end)` (a body in one
/// space: always).
fn merge_body_ranges(body: &reargo_core::address::AddressSet) -> Vec<(u64, u64)> {
    let mut merged: Vec<(u64, u64)> = Vec::new();
    let mut last: Option<(u64, u64)> = None;
    for r in body.ranges() {
        let (s, e) = (r.start.offset, r.start.offset + r.size);
        if s >= e {
            continue;
        }
        if last.is_some_and(|l| (s, e) < l) {
            let ranges: Vec<(u64, u64)> = body.ranges().map(|r| (r.start.offset, r.start.offset + r.size)).collect();
            return merge_ranges(&ranges);
        }
        last = Some((s, e));
        match merged.last_mut() {
            Some(m) if s <= m.1 => m.1 = m.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

/// `ranges` (half-open) sorted and merged where they overlap or touch:
/// an address is in one of them exactly when it is in one of these.
pub(crate) fn merge_ranges(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut raw: Vec<(u64, u64)> = ranges.iter().copied().filter(|(s, e)| s < e).collect();
    raw.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(raw.len());
    for (s, e) in raw {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_compiles() {
        let _ = DeadCodeAnalyzer;
    }

    /// The one-pass merge of a body equals the sorting one (ranges in
    /// two spaces, empty, nested, touching).
    #[test]
    fn body_merge_matches_merge_ranges() {
        use reargo_core::address::{Address, AddressRange, AddressSet, SpaceId};
        let r = |sp: SpaceId, off: u64, size: u64| AddressRange::new(Address::new(sp, off), size);
        let ram = SpaceId::RAM;
        let other = SpaceId(ram.0 + 1);
        let bodies: Vec<AddressSet> = vec![
            [r(ram, 0x10, 2), r(ram, 0x12, 3), r(ram, 0x20, 0), r(ram, 0x20, 8), r(ram, 0x21, 2), r(ram, 0x30, 1)].into_iter().collect(),
            [r(ram, 0x40, 4), r(other, 0x10, 2), r(other, 0x44, 1)].into_iter().collect(),
            AddressSet::new(),
        ];
        for body in &bodies {
            let ranges: Vec<(u64, u64)> = body.ranges().map(|r| (r.start.offset, r.start.offset + r.size)).collect();
            assert_eq!(merge_body_ranges(body), merge_ranges(&ranges), "{body:?}");
        }
    }

    #[test]
    fn merged_ranges_keep_membership() {
        let raw = [(0x10u64, 0x14u64), (0x14, 0x18), (0x30, 0x40), (0x32, 0x35), (0x3f, 0x50), (0x60, 0x60), (0x5, 0x8)];
        let merged = merge_ranges(&raw);
        assert_eq!(merged, vec![(0x5, 0x8), (0x10, 0x18), (0x30, 0x50)]);
        for a in 0..0x70u64 {
            let naive = raw.iter().any(|&(s, e)| a >= s && a < e);
            let i = merged.partition_point(|&(s, _)| s <= a);
            assert_eq!(i > 0 && a < merged[i - 1].1, naive, "{a:#x}");
        }
    }
}
