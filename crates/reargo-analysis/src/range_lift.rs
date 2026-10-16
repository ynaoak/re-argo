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
    map_with_lifter(memory, jobs, |&(entry, count), lifter| lifter.with(entry, count, |insns| f(entry, insns)))
}

/// `f(job, lifter)` for every job in order, where `lifter` lifts any
/// ranges the job needs ([`RangeLifter::with`]); consecutive jobs share
/// the lifted instructions.
pub fn map_with_lifter<J, T, F>(memory: &Memory, jobs: &[J], f: F) -> Vec<T>
where
    J: Sync,
    T: Send,
    F: Fn(&J, &mut RangeLifter) -> T + Sync,
{
    jobs.par_chunks(CHUNK)
        .map(|chunk| {
            let mut lifter = RangeLifter { lifter: X86Lifter::new_64(), memory, cache: LiftCache::new() };
            chunk.iter().map(|job| f(job, &mut lifter)).collect::<Vec<T>>()
        })
        .collect::<Vec<Vec<T>>>()
        .into_iter()
        .flatten()
        .collect()
}

/// Lifts ranges through one [`LiftCache`].
pub struct RangeLifter<'m> {
    lifter: X86Lifter,
    memory: &'m Memory,
    cache: LiftCache,
}

impl RangeLifter<'_> {
    /// `g(insns)`, `insns` being exactly
    /// `X86Lifter::new_64().lift_range(memory, entry, count)`.
    pub fn with<R>(&mut self, entry: u64, count: usize, g: impl FnOnce(&[&LiftedInstruction]) -> R) -> R {
        let range = self.lifter.lift_range_cached(self.memory, entry, count, &mut self.cache);
        g(&range.insns())
    }
}

/// Results computed ahead of an analyzer by `(entry, instruction
/// budget)`: what it computes itself from `lift_range(entry, budget)`
/// and inputs that do not change during a run.
pub type AheadMap<T> = rustc_hash::FxHashMap<(u64, usize), T>;

/// The result of every job in order: the one in `ahead` for the same
/// `(entry, budget)`, else computed by `compute` (given the jobs not in
/// `ahead`, in order, it returns their results in that order).
pub fn with_ahead<T>(
    jobs: &[(u64, usize)],
    ahead: Option<AheadMap<T>>,
    compute: impl FnOnce(&[(u64, usize)]) -> Vec<T>,
) -> Vec<T> {
    let mut ahead = ahead.unwrap_or_default();
    let found: Vec<Option<T>> = jobs.iter().map(|j| ahead.remove(j)).collect();
    drop(ahead);
    let missing: Vec<(u64, usize)> =
        jobs.iter().zip(&found).filter(|(_, f)| f.is_none()).map(|(j, _)| *j).collect();
    let mut computed = compute(&missing).into_iter();
    found
        .into_iter()
        .map(|f| f.unwrap_or_else(|| computed.next().expect("a result for every job not computed ahead")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_ahead_keeps_job_order() {
        let jobs = [(0x10u64, 5usize), (0x20, 5), (0x30, 7), (0x40, 5)];
        let mut ahead = AheadMap::default();
        ahead.insert((0x20, 5), "ahead 0x20");
        ahead.insert((0x30, 6), "other budget");
        ahead.insert((0x50, 5), "no such job");
        let mut asked = Vec::new();
        let got = with_ahead(&jobs, Some(ahead), |missing| {
            asked.extend_from_slice(missing);
            missing.iter().map(|_| "computed").collect()
        });
        assert_eq!(asked, [(0x10, 5), (0x30, 7), (0x40, 5)]);
        assert_eq!(got, ["computed", "ahead 0x20", "computed", "computed"]);
        assert_eq!(with_ahead(&jobs, None, |m| m.iter().map(|j| j.0).collect()), [0x10, 0x20, 0x30, 0x40]);
    }
}
