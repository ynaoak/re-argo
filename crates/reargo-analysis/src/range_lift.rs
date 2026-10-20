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

/// Most consecutive jobs run on one thread with one cache
/// ([`cost_chunks`]): the overlap into the next run of jobs is lifted
/// again.
pub(crate) const CHUNK: usize = 64;

/// Runs of consecutive jobs (index ranges, in order) for jobs of the
/// given `costs`: each at most [`CHUNK`] jobs and, past its first job,
/// at most an even share of the total cost split many ways per thread.
/// A run of the costliest neighbours (one large function after another)
/// would otherwise be the last thing a run of jobs waits for.
/// On one thread there is nothing to balance: one run of every job.
pub(crate) fn cost_chunks(costs: &[usize]) -> Vec<std::ops::Range<usize>> {
    cost_chunks_for(costs, rayon::current_num_threads())
}

/// [`cost_chunks`] for `threads` threads.
fn cost_chunks_for(costs: &[usize], threads: usize) -> Vec<std::ops::Range<usize>> {
    if threads <= 1 {
        return if costs.is_empty() { Vec::new() } else { vec![0..costs.len()] };
    }
    let total: usize = costs.iter().sum();
    let cap = (total / (threads * 16)).max(1);
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut cost = 0;
    for (k, &c) in costs.iter().enumerate() {
        if k > start && (k - start >= CHUNK || cost + c > cap) {
            chunks.push(start..k);
            start = k;
            cost = 0;
        }
        cost += c;
    }
    if start < costs.len() {
        chunks.push(start..costs.len());
    }
    chunks
}

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
    map_with_lifter(
        memory,
        jobs,
        |&(_, count)| count,
        |&(entry, count), lifter| lifter.with(entry, count, |insns| f(entry, insns)),
    )
}

/// `f(job, lifter)` for every job in order, where `lifter` lifts any
/// ranges the job needs ([`RangeLifter::with`]); the consecutive jobs a
/// thread runs share the lifted instructions, the instructions below
/// the job's ranges dropped as the run moves on ([`trim`]). The runs
/// are bounded by the jobs' `cost` (the instructions a job lifts,
/// [`cost_chunks`]), so no thread is left with a run of the largest
/// functions at the end.
pub fn map_with_lifter<J, T, F>(memory: &Memory, jobs: &[J], cost: impl Fn(&J) -> usize, f: F) -> Vec<T>
where
    J: Sync,
    T: Send,
    F: Fn(&J, &mut RangeLifter) -> T + Sync,
{
    let costs: Vec<usize> = jobs.iter().map(cost).collect();
    cost_chunks(&costs)
        .into_par_iter()
        .flat_map_iter(|run| {
            let mut lifter = RangeLifter { lifter: X86Lifter::new_64(), memory, cache: LiftCache::new() };
            let f = &f;
            jobs[run].iter().map(move |job| f(job, &mut lifter))
        })
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
    fn cost_chunks_cover_the_jobs_in_order() {
        let costs: Vec<usize> = (0..1000).map(|k| if k % 97 == 0 { 50_000 } else { 500 + k % 7 }).collect();
        for threads in [1, 2, 4, 8] {
            let chunks = cost_chunks_for(&costs, threads);
            let mut next = 0;
            for c in &chunks {
                assert_eq!(c.start, next);
                assert!(!c.is_empty() && c.len() <= if threads == 1 { costs.len() } else { CHUNK });
                next = c.end;
            }
            assert_eq!(next, costs.len());
            if threads > 1 {
                // a run of several jobs costs no more than its share
                let cap = costs.iter().sum::<usize>() / (threads * 16);
                assert!(chunks.iter().filter(|c| c.len() > 1).all(|c| costs[c.clone()].iter().sum::<usize>() <= cap));
                // so a large job runs alone
                assert!(chunks.iter().all(|c| c.len() == 1 || costs[c.clone()].iter().all(|&x| x < 50_000)));
            } else {
                assert_eq!(chunks.len(), 1);
            }
        }
        assert!(cost_chunks_for(&[], 4).is_empty());
        assert!(cost_chunks_for(&[], 1).is_empty());
    }

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
