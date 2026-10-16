//! Linear range lifts of many functions, shared between neighbours.
//!
//! Several passes lift every function linearly from its entry for a
//! budget of instructions well past its end (`lift_range(entry, n)`),
//! so the ranges of neighbouring functions overlap several times over.
//! [`map_lifted_ranges`] hands each job the same instructions
//! `lift_range` would, lifting each address once per run of
//! consecutive jobs on one thread ([`X86Lifter::lift_range_cached`]),
//! and runs the runs in parallel with the results kept in job order.

use rayon::prelude::*;
use reargo_lift::x86::{LiftCache, X86Lifter};
use reargo_lift::{InsnShape, LiftedInstruction};
use reargo_loader::Memory;

/// Fewest consecutive jobs run on one thread with one cache: the
/// overlap into the next run of jobs is lifted again.
pub(crate) const CHUNK: usize = 64;

/// Instructions a cache holds before those below the range being lifted
/// are dropped ([`trim`]).
const RETAIN_AT: usize = 4096;

/// Bound `cache` before lifting from `start`: the jobs of a run lift in
/// ascending order of their starts, so what lies below `start` is not
/// read again (and would only be lifted again if it were).
pub(crate) fn trim(cache: &mut LiftCache, start: u64) {
    cache.trim(start, RETAIN_AT);
}

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
/// ranges the job needs ([`RangeLifter::with`]); the consecutive jobs a
/// thread runs (runs of at least [`CHUNK`]) share the lifted
/// instructions, the instructions below the job's ranges dropped as the
/// run moves on ([`trim`]).
pub fn map_with_lifter<J, T, F>(memory: &Memory, jobs: &[J], f: F) -> Vec<T>
where
    J: Sync,
    T: Send,
    F: Fn(&J, &mut RangeLifter) -> T + Sync,
{
    jobs.par_iter()
        .with_min_len(CHUNK)
        .map_init(
            || RangeLifter { lifter: X86Lifter::new_64(), memory, cache: LiftCache::new() },
            |lifter, job| f(job, lifter),
        )
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
        trim(&mut self.cache, entry);
        let range = self.lifter.lift_range_cached(self.memory, entry, count, &mut self.cache);
        g(&range.insns())
    }

    /// `g(k, insns, shapes)` for the `k`-th of `budgets`, `insns` being
    /// exactly `X86Lifter::new_64().lift_range(memory, entry, budgets[k])`
    /// and `shapes` their [`InsnShape`]s when the cache holds them: one
    /// walk of the largest range, the others its prefixes
    /// ([`X86Lifter::lift_prefixes_cached`]).
    pub fn with_budgets<R>(
        &mut self,
        entry: u64,
        budgets: &[usize],
        g: impl FnMut(usize, &[&LiftedInstruction], Option<&[InsnShape]>) -> R,
    ) -> Vec<R> {
        trim(&mut self.cache, entry);
        self.lifter.lift_prefixes_cached(self.memory, entry, budgets, true, &mut self.cache, g)
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
