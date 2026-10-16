//! Linear range lifts of many functions, shared between neighbours.
//!
//! Several passes lift every function linearly from its entry for a
//! budget of instructions well past its end (`lift_range(entry, n)`),
//! so the ranges of neighbouring functions overlap several times over.
//! [`map_lifted_ranges`] hands each job the same instructions
//! `lift_range` would, lifting each address once per chunk of
//! consecutive jobs ([`X86Lifter::lift_range_cached`]), and runs the
//! chunks in parallel with the results kept in job order.

use rayon::prelude::*;
use reargo_lift::x86::{LiftCache, X86Lifter};
use reargo_lift::LiftedInstruction;
use reargo_loader::Memory;

/// Consecutive jobs sharing one cache: large enough that the overlap
/// into the next chunk is small, small enough to spread over threads.
const CHUNK: usize = 64;

/// `f(entry, insns)` for every job `(entry, count)` in order, `insns`
/// being exactly `X86Lifter::new_64().lift_range(memory, entry, count)`.
pub fn map_lifted_ranges<T, F>(memory: &Memory, jobs: &[(u64, usize)], f: F) -> Vec<T>
where
    T: Send,
    F: Fn(u64, &[&LiftedInstruction]) -> T + Sync,
{
    let lifter = X86Lifter::new_64();
    jobs.par_chunks(CHUNK)
        .map(|chunk| {
            let mut cache = LiftCache::new();
            chunk
                .iter()
                .map(|&(entry, count)| {
                    let range = lifter.lift_range_cached(memory, entry, count, &mut cache);
                    f(entry, &range.insns())
                })
                .collect::<Vec<T>>()
        })
        .collect::<Vec<Vec<T>>>()
        .into_iter()
        .flatten()
        .collect()
}
