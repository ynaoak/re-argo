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
        // (the body walks read the instructions sorted: no instruction is
        // listed after this analyzer)
        listing.sorted_instructions();
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
            // (a body holds a range per instruction)
            let mut insns: Vec<(u64, u32, FlowType, Option<u64>)> = Vec::with_capacity(snap.body.len());
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
            // The instruction each block start is, found in one pass over
            // both sorted lists (`u32::MAX`: none starts there): what the
            // walk's search from a block start finds.
            let mut start_at: Vec<u32> = Vec::with_capacity(block_starts.len());
            let mut j = 0;
            for &s in &block_starts {
                while j < insns.len() && insns[j].0 < s {
                    j += 1;
                }
                start_at.push(if j < insns.len() && insns[j].0 == s { j as u32 } else { u32::MAX });
            }

            // Walk reachability from entry using fall-through +
            // branch edges (in any order: the set reached is the same).
            // A block start reached is marked by its index, any other
            // address in a set.
            let mut reached_start = vec![false; block_starts.len()];
            let mut reached_other: rustc_hash::FxHashSet<u64> = rustc_hash::FxHashSet::default();
            let mut queue: Vec<u64> = vec![snap.entry];
            while let Some(b) = queue.pop() {
                let p = block_starts.partition_point(|&s| s <= b);
                let is_start = p > 0 && block_starts[p - 1] == b;
                let fresh = if is_start {
                    !std::mem::replace(&mut reached_start[p - 1], true)
                } else {
                    reached_other.insert(b)
                };
                if !fresh {
                    continue;
                }
                // Walk insns from b until we hit a terminator or
                // bump into the next block start.
                let mut cur = b;
                let next_start = block_starts.get(p).copied().unwrap_or(u64::MAX);
                let mut idx = match is_start {
                    // (an instruction at `b` is found either way; the
                    // instructions of an address are alike)
                    true if start_at[p - 1] != u32::MAX => Ok(start_at[p - 1] as usize),
                    _ => insns.binary_search_by_key(&cur, |(a, _, _, _)| *a),
                };
                while let Ok(i) = idx {
                    let (addr, len, ft, tgt) = insns[i];
                    if addr >= next_start {
                        if in_body(addr) {
                            queue.push(addr);
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
                                queue.push(t);
                            }
                            break;
                        }
                        FlowType::ConditionalJump => {
                            if let Some(t) = tgt
                                && in_body(t)
                            {
                                queue.push(t);
                            }
                            if in_body(after) {
                                queue.push(after);
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

            for (&start, &reached) in block_starts.iter().zip(&reached_start) {
                if !reached {
                    unreachable.push(start);
                }
            }
            unreachable
        }).collect();
        Box::new(per_function.into_iter().flatten().collect::<Vec<u64>>())
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let all_unreachable: Vec<u64> = crate::analyzer::prepared(prepared);
        let emitted = program
            .comments
            .set_all_if_absent(all_unreachable.into_iter().map(|addr| (addr, CommentType::Plate, "unreachable from function entry")));

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
    // (merging ranges in order of their starts gives the merge; a start
    // before the one before — another space's — falls back to sorting)
    let mut last_start = 0;
    for r in body.ranges() {
        let (s, e) = (r.start.offset, r.start.offset + r.size);
        if s >= e {
            continue;
        }
        if s < last_start {
            let ranges: Vec<(u64, u64)> = body.ranges().map(|r| (r.start.offset, r.start.offset + r.size)).collect();
            return merge_ranges(&ranges);
        }
        last_start = s;
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
