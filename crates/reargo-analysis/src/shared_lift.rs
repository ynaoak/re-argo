//! Per-function call-site results shared between analyzers.
//!
//! The Call Site Annotator (750) and Format Varargs (780) both need
//! every function's round-0 call sites (the walk of
//! [`crate::callsite`] with no parameter summaries); the annotator also
//! runs the CFG constant tracker and VSA on the same lift. [`compute`]
//! does that work and [`store`] leaves it on the program
//! ([`Program::analysis_cache`]), so the next analyzer redoes only the
//! functions whose results may differ on the program as it is by then.
//!
//! The annotator's lifts also give Argument Arity (780) and Calling
//! Convention (770) their per-function results ([`store_ahead`]): those
//! depend only on the function's own linear lift, which the lift cache
//! holds by then.
//!
//! CRT / main Recovery (710) keeps its own pass: Late Discovery and
//! Linear Sweep run between it and the annotator and change about half
//! of the functions (python3.12: 1723 of 3592 still valid at 750), so
//! computing the snapshots at 710 for the annotator cost more than the
//! annotator saved.
//!
//! What one function's results depend on, and how a cached result is
//! checked against it:
//!
//! * the lift: the bytes (fixed for the run), the entry and the
//!   instruction budget — the budget must match;
//! * [`crate::func_lift::external_entries`] of the lift: the lifted
//!   instructions that jump references reach from outside the lift
//!   (or through a jump table). References are only added, so the set
//!   stays the same while no jump reference added since the result was
//!   computed ([`reargo_program::ReferenceManager::jumps_since`]) makes
//!   a new lifted instruction such an entry — checked exactly against
//!   the lifted addresses and the entries the result was computed
//!   with;
//! * which function owns each call site the walk / the snapshots
//!   record (`function_containing`): every answer is kept and asked
//!   again;
//! * for the snapshots only, [`crate::func_lift::in_extent`]: the entry
//!   of the next function, kept and compared.
//!
//! A result failing any check is computed again, so the shared results
//! are always the ones a fresh pass would give.

use std::collections::BTreeSet;

use rayon::prelude::*;
use reargo_program::{Program, RefType, Reference};
use rustc_hash::FxHashMap;

use crate::callsite::{walk_function_shaped, walk_prefix, CallSite, ParamSummaries, WalkPrefix};
use crate::func_lift::function_jobs;

/// One function's results.
pub(crate) struct FunctionResults {
    /// Function entry.
    pub entry: u64,
    /// Instruction budget it was lifted with.
    pub max_insns: usize,
    /// Its round-0 call sites ([`crate::callsite::walk_function`] with
    /// no summaries), or `None` when the lift failed.
    pub walk: Option<Vec<CallSite>>,
    /// What the walk read of the lift (an increasing lift), for the
    /// resolver's rewalks.
    pub prefix: Option<WalkPrefix>,
    /// Its owned `cfg_const` and VSA call snapshots, when computed
    /// (empty for a failed lift).
    pub snapshots: Option<(crate::cfg_const::CallSnapshots, crate::vsa::CallSnapshots)>,
    /// The lifted instruction addresses, as offsets from `entry` (a
    /// lift runs forward from it); `None` for a failed lift, which
    /// depends on nothing the analyzers change. A lift whose offsets do
    /// not fit is not kept (`reusable` is false).
    lifted: Option<Box<[u32]>>,
    /// The lift's [`crate::func_lift::external_entries`], sorted.
    external: Box<[u64]>,
    /// Whether the result may be reused at all.
    reusable: bool,
    /// Entry of the next function when computed.
    next_entry: Option<u64>,
    /// Every address whose ownership the results depend on, with the
    /// answer of [`owns`] when computed.
    owned: Vec<(u64, bool)>,
}

/// The results of every function, in listing order, and the jump
/// reference mark they were computed at.
pub(crate) struct SharedLift {
    pub funcs: Vec<FunctionResults>,
    jump_mark: reargo_program::reference::JumpMark,
    /// With the snapshots: the Argument Arity and Calling Convention
    /// results of the functions lifted here, from the same lifts (see
    /// [`store_ahead`]).
    ahead: Option<AheadResults>,
}

/// Argument Arity and Calling Convention results, by `(entry, budget)`.
type AheadResults = (crate::range_lift::AheadMap<usize>, crate::range_lift::AheadMap<Option<(u64, &'static str)>>);

/// What [`store`] leaves on the program.
pub(crate) struct Cached {
    funcs: FxHashMap<u64, FunctionResults>,
    jump_mark: reargo_program::reference::JumpMark,
}

impl SharedLift {
    /// The round-0 call sites of the whole program, as
    /// [`crate::callsite::resolve_call_sites`] gives them.
    pub fn round0_sites(&self) -> Vec<&CallSite> {
        crate::callsite::dedup_site_refs(self.funcs.iter().filter_map(|f| f.walk.as_deref()))
    }
}

/// Results of every function of `program`, lifted with the x86-64
/// lifter (callers check the architecture), with the `cfg_const` / VSA snapshots too when
/// `with_snapshots`. Reuses each result [`store`]d earlier that still
/// holds; the cache is emptied (give the results back with [`store`]).
pub(crate) fn compute(program: &mut Program, with_snapshots: bool) -> SharedLift {
    let cached = program.analysis_cache.take::<Cached>();
    compute_from(program, cached, with_snapshots)
}

/// Whether results [`store`]d earlier are on the program (for
/// [`compute`] to reuse).
pub(crate) fn has_stored(program: &Program) -> bool {
    program.analysis_cache.contains::<Cached>()
}

/// [`compute`] reusing the results in `cached` (taken out of the
/// program's analysis cache) that still hold.
pub(crate) fn compute_from(program: &Program, cached: Option<Cached>, with_snapshots: bool) -> SharedLift {
    let jump_mark = program.references.jump_mark();
    // The jump references added since the cached results, by target.
    let (mut cached_funcs, changed): (FxHashMap<u64, FunctionResults>, Option<Vec<Reference>>) = match cached {
        Some(c) => {
            let changed = program.references.jumps_since(c.jump_mark).map(|j| {
                let mut j = j.to_vec();
                j.sort_unstable_by_key(|r| (r.to, r.from));
                j.dedup();
                j
            });
            (c.funcs, changed)
        }
        None => (FxHashMap::default(), None),
    };
    // With nothing cached every function is computed: the jump index
    // (below) is built meanwhile.
    let none_cached = cached_funcs.is_empty();
    let (early_jumps, (jobs, arity_budgets)) = rayon::join(
        || none_cached.then(|| crate::func_lift::JumpIndex::new(program)),
        || {
            let jobs: Vec<(u64, usize, Option<FunctionResults>)> = function_jobs(program)
                .into_iter()
                .map(|(entry, max)| (entry, max, cached_funcs.remove(&entry)))
                .collect();
            // Argument Arity's budget of each function, in the same order.
            let arity_budgets: Vec<usize> =
                if with_snapshots { program.listing.functions().map(crate::arity::budget).collect() } else { Vec::new() };
            (jobs, arity_budgets)
        },
    );
    drop(cached_funcs);
    // The cached results that still hold; the others are computed again.
    let jobs: Vec<(u64, usize, Option<FunctionResults>)> = jobs
        .into_par_iter()
        .map(|(entry, max_insns, old)| {
            let kept = old.filter(|old| {
                changed.as_ref().is_some_and(|changed| still_valid(old, program, max_insns, changed, with_snapshots))
            });
            (entry, max_insns, kept)
        })
        .collect();
    // Index the jump references when many functions are computed (else
    // a lookup per lifted instruction costs less than the index).
    let stale = jobs.iter().filter(|j| j.2.is_none()).count();
    let jumps = (stale > jobs.len() / 8).then(|| early_jumps.unwrap_or_else(|| crate::func_lift::JumpIndex::new(program)));
    // The consecutive functions a thread runs share a lift cache
    // ([`crate::range_lift::map_with_lifter`]): a function is lifted
    // linearly well past its end, over its neighbours
    // (`lift_range_cached` gives exactly what `lift_range` would).
    let x86 = reargo_lift::x86::X86Lifter::new_64();
    type Extra = Option<(u64, usize, usize, Option<(u64, &'static str)>)>;
    // (entry, max instructions, results kept, arity budget)
    type Job = (u64, usize, Option<FunctionResults>, usize);
    let jobs: Vec<Job> = if with_snapshots {
        jobs.into_iter().zip(arity_budgets).map(|((e, m, k), a)| (e, m, k, a)).collect()
    } else {
        jobs.into_iter().map(|(e, m, k)| (e, m, k, 0)).collect()
    };
    // Runs of consecutive jobs cut by their lifts and work (the budget
    // of each function computed, [`crate::range_lift::span_chunks`]),
    // so no run of large functions is left for one thread at the end.
    let spans: Vec<crate::range_lift::Span> = jobs
        .iter()
        .map(|j| match j.2 {
            Some(_) => crate::range_lift::Span { entry: j.0, insns: 0, work: 1 },
            None => crate::range_lift::Span { entry: j.0, insns: j.1.max(j.3), work: j.1 },
        })
        .collect();
    let mut jobs = jobs.into_iter();
    let chunks: Vec<Vec<Job>> = crate::range_lift::span_chunks(&spans)
        .into_iter()
        .map(|r| jobs.by_ref().take(r.len()).collect())
        .collect();
    // (the runs one rayon job takes, in order, share one cache: a run lifts again only what
    // the run before it did not)
    let computed: Vec<Vec<(FunctionResults, Extra)>> = chunks
        .into_par_iter()
        .map_init(reargo_lift::x86::LiftCache::new, |cache, chunk| {
            let (x86, jumps) = (&x86, jumps.as_ref());
            chunk
                .into_iter()
                .map(|(entry, max_insns, kept, arity_budget)| {
                    if let Some(kept) = kept {
                        return (kept, None);
                    }
                    crate::range_lift::trim(cache, entry);
                    let memory = &program.info.memory;
                    // The function's lift and, from the same walk (exactly
                    // their own linear lifts), Argument Arity's and Calling
                    // Convention's.
                    let mut results = None;
                    let mut arity = 0;
                    let mut convention = None;
                    let budgets: &[usize] = if with_snapshots {
                        &[max_insns, arity_budget, crate::callingconv::LIFT_BUDGET]
                    } else {
                        &[max_insns]
                    };
                    x86.lift_prefixes_cached(memory, entry, budgets, true, cache, |k, insns, shapes| match k {
                        0 => {
                            results = Some(compute_lifted(
                                program,
                                jumps,
                                entry,
                                max_insns,
                                insns,
                                shapes,
                                with_snapshots,
                            ))
                        }
                        1 => arity = crate::arity::infer_arity(insns),
                        _ => convention = crate::callingconv::convention_lifted(entry, insns),
                    });
                    let results = results.expect("the function's lift");
                    let extra = with_snapshots.then_some((entry, arity_budget, arity, convention));
                    (results, extra)
                    })
                .collect()
        })
        .collect();
    let mut ahead = with_snapshots.then(|| (crate::range_lift::AheadMap::default(), crate::range_lift::AheadMap::default()));
    let funcs: Vec<FunctionResults> = computed
        .into_iter()
        .flatten()
        .map(|(f, extra)| {
            if let (Some((arity, convention)), Some((entry, arity_budget, a, c))) = (ahead.as_mut(), extra) {
                arity.insert((entry, arity_budget), a);
                convention.insert((entry, crate::callingconv::LIFT_BUDGET), c);
            }
            f
        })
        .collect();
    SharedLift { funcs, jump_mark, ahead }
}

/// Leave the Argument Arity and Calling Convention results [`compute`]
/// took from its lifts on the program for those analyzers (beside the
/// ones computed ahead before).
pub(crate) fn store_ahead(program: &mut Program, shared: &mut SharedLift) {
    let Some((arity, convention)) = shared.ahead.take() else { return };
    let mut a = program.analysis_cache.take::<crate::arity::Ahead>().map(|a| a.0).unwrap_or_default();
    a.extend(arity);
    program.analysis_cache.insert(crate::arity::Ahead(a));
    let mut c = program.analysis_cache.take::<crate::callingconv::Ahead>().map(|c| c.0).unwrap_or_default();
    c.extend(convention);
    program.analysis_cache.insert(crate::callingconv::Ahead(c));
}

/// Leave `shared` on the program for the next [`compute`]. The
/// snapshots taken out of it are not kept.
pub(crate) fn store(program: &mut Program, shared: SharedLift) {
    let funcs = shared.funcs.into_iter().map(|f| (f.entry, f)).collect();
    program.analysis_cache.insert(Cached { funcs, jump_mark: shared.jump_mark });
}

fn still_valid(
    old: &FunctionResults,
    program: &Program,
    max_insns: usize,
    changed: &[Reference],
    with_snapshots: bool,
) -> bool {
    if !old.reusable || old.max_insns != max_insns {
        return false;
    }
    if with_snapshots
        && (old.snapshots.is_none()
            || program.listing.next_function_after(old.entry).map(|f| f.entry_point) != old.next_entry)
    {
        return false;
    }
    if let Some(lifted) = &old.lifted
        && gained_external_entry(old.entry, lifted, &old.external, changed)
    {
        return false;
    }
    let owner = crate::func_lift::Owner::new(program, old.entry);
    old.owned.iter().all(|&(addr, o)| owner.owns(addr) == o)
}

/// Whether one of the jump references `changed` (sorted by target)
/// makes [`crate::func_lift::external_entries`] of the lift `lifted` (offsets from
/// `entry`) differ from `external`: it reaches a lifted instruction
/// not in `external` through a jump table, or from outside the lift.
fn gained_external_entry(entry: u64, lifted: &[u32], external: &[u64], changed: &[Reference]) -> bool {
    let is_lifted = |a: u64| {
        a.checked_sub(entry)
            .and_then(|d| u32::try_from(d).ok())
            .is_some_and(|d| lifted.binary_search(&d).is_ok())
    };
    let (Some(&first), Some(&last)) = (lifted.first(), lifted.last()) else {
        return false;
    };
    let (first, last) = (entry + u64::from(first), entry + u64::from(last));
    let start = changed.partition_point(|r| r.to < first);
    changed[start..].iter().take_while(|r| r.to <= last).any(|r| {
        let enters = match r.ref_type {
            RefType::IndirectJump => true,
            RefType::UnconditionalJump | RefType::ConditionalJump => !is_lifted(r.from),
            _ => false,
        };
        enters && is_lifted(r.to) && external.binary_search(&r.to).is_err()
    })
}

/// The results of the function at `entry` from its lift (the x86
/// lift never fails: it stops at the first instruction it cannot lift).
fn compute_lifted<I: std::borrow::Borrow<reargo_lift::LiftedInstruction>>(
    program: &Program,
    jumps: Option<&crate::func_lift::JumpIndex>,
    entry: u64,
    max_insns: usize,
    insns: &[I],
    shapes: Option<&[reargo_lift::InsnShape]>,
    with_snapshots: bool,
) -> FunctionResults {
    let next_entry = program.listing.next_function_after(entry).map(|f| f.entry_point);
    let owner = crate::func_lift::Owner::new(program, entry);
    // What the walk and the blocks need of each instruction, read once
    // (or kept beside the lift).
    let shape = match shapes {
        Some(shapes) => crate::blockflow::LiftShape::from_shapes(insns, shapes),
        None => crate::blockflow::LiftShape::of(insns),
    };
    let external = match jumps {
        Some(jumps) => jumps.external_entries_ordered(program, &shape.addrs, shape.increasing),
        None => crate::func_lift::external_entries_at(program, &shape.addrs),
    };
    let in_body = |a: u64| a >= entry && next_entry.is_none_or(|n| a < n);
    // Of an increasing lift (all but a range wrapping around), what the
    // walk and the blocks both need, found in one pass: jump targets,
    // external entries, and who owns each call instruction (the walk,
    // the blocks the flows keep and the check of a cached result all
    // ask).
    let mut marks = shape
        .increasing
        .then(|| crate::blockflow::LiftMarks::new(&shape, &external, |i| owner.owns(shape.addrs[i])));
    let calls: Vec<(u64, bool)> = match &mut marks {
        Some(marks) => std::mem::take(&mut marks.calls),
        None => (0..shape.addrs.len())
            .filter(|&i| shape.has_call(i))
            .map(|i| (shape.addrs[i], owner.owns(shape.addrs[i])))
            .collect(),
    };
    let owns_call = |a: u64| match calls.binary_search_by_key(&a, |c| c.0) {
        Ok(k) => calls[k].1,
        Err(_) => owner.owns(a),
    };
    // (a lift through the cache is plain: lifted instruction by
    // instruction)
    let prefix = marks.as_ref().map(|marks| WalkPrefix::of_marks(&shape, marks, shapes.is_some()));
    let walk = match &prefix {
        Some(prefix) => walk_prefix(entry, insns, &prefix.flags, &ParamSummaries::default()),
        None => walk_function_shaped(entry, insns, &shape, &ParamSummaries::default(), &external, owns_call),
    };
    // The walk asks who owns each call instruction.
    let mut addrs: BTreeSet<u64> = calls.iter().map(|c| c.0).collect();
    let snapshots = with_snapshots.then(|| {
        // both flows walk the same blocks (`in_extent` with the next
        // entry looked up once), keeping only the snapshots of the
        // calls the function owns
        let blocks = match &marks {
            Some(marks) => {
                let mut blocks = crate::blockflow::Cfg::build_marked(&shape, marks, in_body);
                blocks.keep_owned_calls(marks);
                blocks
            }
            None => {
                let mut blocks = crate::blockflow::Cfg::build_shaped(&shape, &external, in_body);
                blocks.keep_calls_at(insns.len(), |i| shape.has_call(i) && owns_call(shape.addrs[i]));
                blocks
            }
        };
        let mut cfg = crate::cfg_const::function_snapshots_cfg(&blocks, insns);
        let mut vsa = crate::vsa::function_snapshots_cfg(&blocks, insns);
        addrs.extend(cfg.iter().map(|(a, _)| *a));
        addrs.extend(vsa.iter().map(|(a, _)| *a));
        cfg.retain(|(a, _)| owner.owns(*a));
        vsa.retain(|(a, _)| owner.owns(*a));
        (cfg, vsa)
    });
    let offsets: Option<Box<[u32]>> =
        shape.addrs.iter().map(|a| a.checked_sub(entry).and_then(|d| u32::try_from(d).ok())).collect();
    // offsets increase (a linear lift), so the list is sorted
    let reusable = offsets.as_ref().is_some_and(|o| o.is_sorted_by(|a, b| a < b));
    let lifted = Some(offsets.unwrap_or_default());
    FunctionResults {
        entry,
        max_insns,
        walk: Some(walk),
        prefix,
        snapshots,
        lifted,
        external: external.into_iter().collect(),
        reusable,
        next_entry,
        owned: addrs.into_iter().map(|a| (a, owns_call(a))).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_entry_gained_only_from_outside_or_a_table() {
        // a lift of 0x1000, 0x1002, 0x1005, 0x1008 with 0x1005 already
        // an external entry
        let lifted: [u32; 4] = [0, 2, 5, 8];
        let external = [0x1005];
        let gained = |r: Reference| gained_external_entry(0x1000, &lifted, &external, &[r]);
        // a jump inside the lift changes nothing
        assert!(!gained(Reference::new(0x1008, 0x1002, RefType::ConditionalJump)));
        // from outside the lift, or a misaligned source
        assert!(gained(Reference::new(0x2000, 0x1002, RefType::UnconditionalJump)));
        assert!(gained(Reference::new(0x1003, 0x1002, RefType::ConditionalJump)));
        // a jump table case
        assert!(gained(Reference::new(0x1008, 0x1002, RefType::IndirectJump)));
        // already an entry, not a lifted instruction, outside the lift,
        // or no jump
        assert!(!gained(Reference::new(0x2000, 0x1005, RefType::UnconditionalJump)));
        assert!(!gained(Reference::new(0x2000, 0x1003, RefType::UnconditionalJump)));
        assert!(!gained(Reference::new(0x2000, 0x1010, RefType::UnconditionalJump)));
        assert!(!gained(Reference::new(0x2000, 0x1002, RefType::DataRead)));
    }
}
