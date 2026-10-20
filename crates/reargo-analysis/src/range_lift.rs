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

/// How many jobs past a full run [`span_chunks`] looks for the place to
/// end it.
pub(crate) const CHUNK: usize = 64;

/// One job of a run of jobs sharing a lift cache: it lifts `insns`
/// instructions linearly from `entry` and does `work` more with them
/// (in instructions lifted: a lift costs 1).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Span {
    pub entry: u64,
    pub insns: usize,
    pub work: usize,
}

/// Bytes an instruction is taken to span ([`span_chunks`] estimates
/// where a lift ends).
const INSN_BYTES: u64 = 4;

impl Span {
    fn end(&self) -> u64 {
        self.entry.saturating_add(self.insns as u64 * INSN_BYTES)
    }
    /// Its cost in a run whose jobs before it lifted up to `reach`.
    fn cost(&self, reach: u64) -> usize {
        (self.end().saturating_sub(reach.max(self.entry)) / INSN_BYTES) as usize + self.work
    }
}

/// Runs of consecutive jobs (index ranges, in order) of the jobs
/// `spans` (by ascending entry), each run on one thread with one lift
/// cache. A function's lift runs well past its end, over the next
/// functions, which a run lifts once: a job costs the instructions it
/// lifts that the jobs before it in its run did not, plus its own work.
/// Each run is filled to an even share of the total cost split many
/// ways per thread (so no thread is left with a run of large functions
/// at the end), then ended, among the next [`CHUNK`] jobs, before the
/// one whose lift the run covers least — the next run lifts again what
/// the run lifted from that job's entry on (the end of a large
/// function's lift, the functions after it read).
pub(crate) fn span_chunks(spans: &[Span]) -> Vec<std::ops::Range<usize>> {
    span_chunks_for(spans, rayon::current_num_threads())
}

/// [`span_chunks`] for `threads` threads.
fn span_chunks_for(spans: &[Span], threads: usize) -> Vec<std::ops::Range<usize>> {
    let total: usize = {
        let mut reach = 0;
        spans
            .iter()
            .map(|s| {
                let c = s.cost(reach);
                reach = reach.max(s.end());
                c
            })
            .sum()
    };
    let cap = (total / (threads * 16)).max(1);
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < spans.len() {
        // fill the run to its share
        let (mut reach, mut cost, mut k) = (0u64, 0usize, start);
        while k < spans.len() && (k == start || cost < cap) {
            cost += spans[k].cost(reach);
            reach = reach.max(spans[k].end());
            k += 1;
        }
        // then end it before the job (of the next ones) whose lift it
        // covers least, or with the last job
        let mut cut = (k, reach.saturating_sub(spans.get(k).map_or(u64::MAX, |s| s.entry)));
        let mut j = k;
        while j < spans.len() && j < k + CHUNK && cut.1 > 0 {
            reach = reach.max(spans[j].end());
            j += 1;
            let overlap = spans.get(j).map_or(0, |s| reach.saturating_sub(s.entry));
            if overlap < cut.1 {
                cut = (j, overlap);
            }
        }
        chunks.push(start..cut.0);
        start = cut.0;
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
        |&(entry, count)| Span { entry, insns: count, work: count / 4 },
        |&(entry, count), lifter| lifter.with(entry, count, |insns| f(entry, insns)),
    )
}

/// `f(job, lifter)` for every job in order, where `lifter` lifts any
/// ranges the job needs ([`RangeLifter::with`]); the consecutive jobs a
/// thread runs share the lifted instructions, the instructions below
/// the job's ranges dropped as the run moves on ([`trim`]). The runs
/// are cut by the lift and work of each job (its [`Span`],
/// [`span_chunks`]).
pub(crate) fn map_with_lifter<J, T, F>(memory: &Memory, jobs: &[J], span: impl Fn(&J) -> Span, f: F) -> Vec<T>
where
    J: Sync,
    T: Send,
    F: Fn(&J, &mut RangeLifter) -> T + Sync,
{
    let spans: Vec<Span> = jobs.iter().map(span).collect();
    span_chunks(&spans)
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
    fn span_chunks_cover_the_jobs_in_order() {
        // functions of 0x40 bytes lifting 500 instructions (well past
        // their ends), a large one every 97
        let spans: Vec<Span> = (0..1000u64)
            .map(|k| {
                let insns = if k % 97 == 0 { 50_000 } else { 500 };
                Span { entry: 0x1000 + k * 0x40, insns, work: insns / 4 }
            })
            .collect();
        for threads in [1, 2, 4, 8] {
            let chunks = span_chunks_for(&spans, threads);
            let mut next = 0;
            for c in &chunks {
                assert_eq!(c.start, next);
                assert!(!c.is_empty());
                next = c.end;
            }
            assert_eq!(next, spans.len());
            assert!(chunks.len() >= threads.min(spans.len()));
        }
        assert!(span_chunks_for(&[], 4).is_empty());
        // separate functions, each lifting only itself: one run each
        let apart: Vec<Span> = (0..3u64).map(|k| Span { entry: k * 0x10000, insns: 100, work: 100 }).collect();
        assert_eq!(span_chunks_for(&apart, 4), [0..1, 1..2, 2..3]);
    }

    #[test]
    fn span_chunks_end_a_run_where_the_next_relifts_least() {
        // a large function whose lift covers the next 20 small ones,
        // then small ones apart: the run of the large function keeps
        // the small ones its lift covers
        let mut spans = vec![Span { entry: 0, insns: 1000, work: 0 }];
        spans.extend((0..20u64).map(|k| Span { entry: 0x100 + k * 0x10, insns: 10, work: 0 }));
        spans.extend((0..40u64).map(|k| Span { entry: 0x10000 + k * 0x1000, insns: 100, work: 0 }));
        let chunks = span_chunks_for(&spans, 4);
        assert_eq!(chunks[0], 0..21);
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
