//! Resolve constant argument values at each Call site.
//!
//! For every Call instruction in the program, scan the preceding
//! P-code in the same function for the most-recent constant write
//! to each argument register. The result tells you "function X is
//! called with this argument set to this concrete value" -- the
//! foundational data needed to follow registry-style call chains
//! (e.g., `register_parser(callback, name, flags)` → who passes
//! what?).
//!
//! This is intentionally a simple intra-block constant-write
//! tracker, not a full SSA-level data-flow:
//!
//! * Walks each function's lifted P-code in instruction order.
//! * For each arg register, remembers the most recent `Copy reg =
//!   const` write.
//! * Any other write (arithmetic, load, call return value, etc.)
//!   *invalidates* the entry -- we only report values we can prove
//!   constant up to the call site.
//! * When a `Call` op is encountered, snapshot the current
//!   resolved-register map and record it as the call site's args.
//!
//! Cost: one pass per function over already-lifted instructions.
//! No SSA build, no optimization, no inter-procedural propagation
//! -- the kind of thing you can run as part of an `analyze` pass.

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_lift::PcodeLift;
use reargo_program::reference::RefType;
use reargo_program::Program;
use rustc_hash::FxHashMap;

use crate::analyzer::AnalysisError;
use crate::byteconst::{eval, is_unmodeled, is_view_refresh, ByteConst, ByteMem, RegFile};
use crate::func_lift::{function_jobs, lift_function};
use rayon::prelude::*;
use reargo_lift::LiftedInstruction;

/// Calling-convention argument-register offsets for x86_64 SysV in
/// declaration order: arg0..arg5 → RDI, RSI, RDX, RCX, R8, R9.
const X86_64_SYSV_ARG_REGS: [(u64, &str); 6] = [
    (0x38, "rdi"),
    (0x30, "rsi"),
    (0x10, "rdx"),
    (0x08, "rcx"),
    (0x80, "r8"),
    (0x88, "r9"),
];

/// One value resolved (or attempted) at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedArg {
    /// Register offset in REGISTER space.
    pub reg_offset: u64,
    /// Human-readable register name ("rdi", "rsi", ...).
    pub reg_name: &'static str,
    /// Concrete constant value at the call site, or `None` if the
    /// register was clobbered by a non-constant op before the call.
    pub value: Option<u64>,
}

/// One Call site with its resolved argument set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    /// Address of the Call instruction.
    pub call_site: u64,
    /// Address of the function the call was found inside.
    pub caller_function: u64,
    /// Static call target if the lifter resolved one (direct call).
    /// `None` for indirect calls.
    pub call_target: Option<u64>,
    /// Argument values resolved at this site, in calling-convention
    /// order. Entries with `value == None` could not be statically
    /// resolved by this simple tracker.
    pub args: Vec<ResolvedArg>,
}

/// Resolve call sites across every discovered function in the
/// program. Returns one `CallSite` entry per Call instruction.
///
/// Only x86_64 is supported in this initial implementation; other
/// architectures return an empty `Vec`. Adding a new calling
/// convention is a matter of swapping `X86_64_SYSV_ARG_REGS` for the
/// arch's argument-register table.
pub fn resolve_call_sites(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
) -> Result<Vec<CallSite>, AnalysisError> {
    resolve_inner(lifter, program, &ParamSummaries::default())
}

/// [`resolve_call_sites`] restricted to the functions whose entry is in
/// `entries`. A call site is recorded only by the function owning it
/// and a walk reads only its own lift, so the result is exactly the
/// sites of [`resolve_call_sites`] owned by those functions, in the
/// same order.
pub fn resolve_call_sites_in(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    entries: &rustc_hash::FxHashSet<u64>,
) -> Result<Vec<CallSite>, AnalysisError> {
    if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
        return Ok(Vec::new());
    }
    let summaries = ParamSummaries::default();
    let per_func: Vec<Option<Vec<CallSite>>> = function_jobs(program)
        .into_iter()
        .filter(|(entry, _)| entries.contains(entry))
        .collect::<Vec<_>>()
        .par_iter()
        .map(|&(entry, max)| {
            let insns = lift_function(lifter, program, entry, max)?;
            Some(walk_function(program, entry, &insns, &summaries))
        })
        .collect();
    Ok(dedup_sites(per_func.iter().flatten().map(Vec::as_slice)))
}

/// Per-function summary of values its parameter registers have ever
/// been called with. Indexed by argument position 0..5 in
/// calling-convention order (RDI, RSI, RDX, RCX, R8, R9 for SysV).
///
/// Built from a `Vec<CallSite>` by `build_param_summaries`: for
/// every call to function F with a resolved `args[i] = Some(v)`, the
/// value `v` is added to F's `params[i]` set; a call that passes an
/// unknown value makes `params[i]` `None`. When the set has exactly
/// one element, that parameter has that value at every call site we
/// observed -- the inter-procedural propagator below uses that to
/// extend the constant-tracking inside F.
///
/// A set stops growing at two values (only a single value pins the
/// parameter).
pub type ParamSummaries = FxHashMap<u64, Vec<Option<rustc_hash::FxHashSet<u64>>>>;

/// The value a summary pins a parameter to: the one value every
/// observed call passes.
fn pinned(param: &Option<rustc_hash::FxHashSet<u64>>) -> Option<u64> {
    match param {
        Some(set) if set.len() == 1 => set.iter().next().copied(),
        _ => None,
    }
}

/// Roll up `sites` into "for each function, what constants does each
/// of its parameter registers ever receive?"  Foundation for
/// inter-procedural propagation: a function whose param 0 is always
/// called with `&handler` can be analysed as if `handler` were a
/// compile-time constant in its body.
pub fn build_param_summaries(sites: &[CallSite]) -> ParamSummaries {
    param_summaries(sites.iter())
}

/// [`build_param_summaries`] of the sites `sites` gives.
fn param_summaries<'a>(sites: impl Iterator<Item = &'a CallSite>) -> ParamSummaries {
    let mut out: ParamSummaries = FxHashMap::default();
    for site in sites {
        let Some(target) = site.call_target else {
            continue;
        };
        let entry = out
            .entry(target)
            .or_insert_with(|| vec![Some(rustc_hash::FxHashSet::default()); X86_64_SYSV_ARG_REGS.len()]);
        for (i, arg) in site.args.iter().enumerate() {
            match (arg.value, &mut entry[i]) {
                (Some(v), Some(set)) => {
                    // (two values pin nothing, nor do more)
                    if set.len() < 2 {
                        set.insert(v);
                    }
                }
                (None, param) => *param = None,
                (Some(_), None) => {}
            }
        }
    }
    out
}

/// The summaries of [`param_summaries`] that seed something
/// ([`seeds_anything`]), each parameter pinned to one value a set of
/// it, the others `None` (the same walks: only a pinned parameter
/// seeds one).
fn seeding_summaries<'a>(sites: impl Iterator<Item = &'a CallSite>) -> ParamSummaries {
    /// What the calls pass to one parameter.
    #[derive(Clone, Copy)]
    enum Passed {
        Nothing,
        One(u64),
        /// Two values or more, or an unknown one.
        NotOne,
    }
    let mut passed: FxHashMap<u64, [Passed; X86_64_SYSV_ARG_REGS.len()]> = FxHashMap::default();
    for site in sites {
        let Some(target) = site.call_target else {
            continue;
        };
        let params = passed.entry(target).or_insert([Passed::Nothing; X86_64_SYSV_ARG_REGS.len()]);
        for (param, arg) in params.iter_mut().zip(&site.args) {
            *param = match (*param, arg.value) {
                (_, None) | (Passed::NotOne, _) => Passed::NotOne,
                (Passed::Nothing, Some(v)) => Passed::One(v),
                (Passed::One(w), Some(v)) if w == v => Passed::One(w),
                (Passed::One(_), Some(_)) => Passed::NotOne,
            };
        }
    }
    passed
        .into_iter()
        .filter(|(_, params)| params.iter().any(|p| matches!(p, Passed::One(_))))
        .map(|(target, params)| {
            let summary = params
                .iter()
                .map(|p| match *p {
                    Passed::One(v) => Some(std::iter::once(v).collect()),
                    _ => None,
                })
                .collect();
            (target, summary)
        })
        .collect()
}

/// Drop the summary of every function that may be entered other than
/// through the direct calls in `sites`: an exported one (other images
/// call it), one with a reference that is not such a call (a jump /
/// tail call, a data reference to its entry, a call from code no
/// walked function owns), or one whose entry is passed as an argument
/// (a callback). Its parameters can then take values no summary saw,
/// so they must not be seeded.
fn keep_closed_callers(program: &Program, sites: &[&CallSite], summaries: &mut ParamSummaries) {
    // (only the callers of the functions summarised, and the arguments
    // that are one of their entries, matter)
    let mut callers: FxHashMap<u64, rustc_hash::FxHashSet<u64>> = FxHashMap::default();
    let mut escaped: rustc_hash::FxHashSet<u64> = rustc_hash::FxHashSet::default();
    for site in sites {
        if let Some(t) = site.call_target
            && summaries.contains_key(&t)
        {
            callers.entry(t).or_default().insert(site.call_site);
        }
        escaped.extend(site.args.iter().filter_map(|a| a.value).filter(|v| summaries.contains_key(v)));
    }
    let pe_exports: rustc_hash::FxHashSet<u64> = program
        .info
        .symbols
        .iter()
        .filter(|s| s.kind == reargo_loader::SymbolKind::Export)
        .map(|s| s.address)
        .collect();
    let exported = |entry: u64| {
        program.info.dynamic.exported_functions.binary_search(&entry).is_ok() || pe_exports.contains(&entry)
    };
    summaries.retain(|entry, _| {
        if escaped.contains(entry) || exported(*entry) {
            return false;
        }
        let known = callers.get(entry);
        program.references.get_refs_to(*entry).iter().all(|r| {
            matches!(r.ref_type, RefType::UnconditionalCall | RefType::ConditionalCall)
                && known.is_some_and(|k| k.contains(&r.from))
        })
    });
}

/// Re-resolve call sites with the given parameter summaries seeded
/// into each function's initial register map. A parameter with a
/// *single* observed value is treated as a compile-time constant on
/// entry; parameters with multiple values (call site polymorphism)
/// are left unresolved.
///
/// This is the single-step inter-procedural propagator. Call it in
/// a fixpoint loop (via `resolve_call_sites_iterative`) to extend
/// reach across longer call chains: each round, newly-resolved
/// arguments at outer call sites feed back into the summary for the
/// next round, and chains like
///     register_parser(my_parser) -> list_add(my_parser) -> ...
/// surface end-to-end.
pub fn resolve_call_sites_with_summaries(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    summaries: &ParamSummaries,
) -> Result<Vec<CallSite>, AnalysisError> {
    resolve_inner(lifter, program, summaries)
}

/// Shared per-function walk that powers both `resolve_call_sites`
/// (intra-function only -- pass an empty `ParamSummaries`) and
/// `resolve_call_sites_with_summaries` (inter-procedural propagation
/// -- pass the rolled-up summaries from a previous round).
fn resolve_inner(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    summaries: &ParamSummaries,
) -> Result<Vec<CallSite>, AnalysisError> {
    if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
        return Ok(Vec::new());
    }
    // Lift + walk every function in parallel; a walk reads only its
    // own lift, so its call sites do not depend on the others.
    let per_func: Vec<Option<Vec<CallSite>>> = function_jobs(program)
        .par_iter()
        .map(|&(entry, max)| {
            let insns = lift_function(lifter, program, entry, max)?;
            Some(walk_function(program, entry, &insns, summaries))
        })
        .collect();
    Ok(dedup_sites(per_func.iter().flatten().map(Vec::as_slice)))
}

/// Keep each call site once, in listing order: the first function to
/// own a site keeps it.
pub(crate) fn dedup_sites<'a>(per_func: impl Iterator<Item = &'a [CallSite]>) -> Vec<CallSite> {
    dedup_site_refs(per_func).into_iter().cloned().collect()
}

/// [`dedup_sites`] without copying them.
pub(crate) fn dedup_site_refs<'a>(per_func: impl Iterator<Item = &'a [CallSite]>) -> Vec<&'a CallSite> {
    // (the sets sized for all of them at once: no growing)
    let per_func: Vec<&[CallSite]> = per_func.collect();
    let n = per_func.iter().map(|f| f.len()).sum();
    let mut seen: rustc_hash::FxHashSet<u64> = rustc_hash::FxHashSet::with_capacity_and_hasher(n, Default::default());
    let mut out: Vec<&CallSite> = Vec::with_capacity(n);
    for site in per_func.into_iter().flatten() {
        if seen.insert(site.call_site) {
            out.push(site);
        }
    }
    out
}

/// The call sites the function at `entry` owns, from its lifted
/// instructions, in instruction order. With an empty `summaries` this
/// is the intra-function (round 0) walk.
pub fn walk_function(
    program: &Program,
    entry: u64,
    insns: &[LiftedInstruction],
    summaries: &ParamSummaries,
) -> Vec<CallSite> {
    let external = crate::func_lift::external_entries(program, insns);
    walk_function_with(program, entry, insns, summaries, &external)
}

/// [`walk_function`] with the lift's
/// [`crate::func_lift::external_entries`] already computed.
pub(crate) fn walk_function_with<I: std::borrow::Borrow<LiftedInstruction>>(
    program: &Program,
    entry: u64,
    insns: &[I],
    summaries: &ParamSummaries,
    external: &std::collections::BTreeSet<u64>,
) -> Vec<CallSite> {
    let owner = crate::func_lift::Owner::new(program, entry);
    walk_function_owning(entry, insns, summaries, external, |a| owner.owns(a))
}

/// [`walk_function_with`] with whether the function owns the call
/// instruction at an address given by `owns_call`.
pub(crate) fn walk_function_owning<I: std::borrow::Borrow<LiftedInstruction>>(
    entry: u64,
    insns: &[I],
    summaries: &ParamSummaries,
    external: &std::collections::BTreeSet<u64>,
    owns_call: impl Fn(u64) -> bool,
) -> Vec<CallSite> {
    walk_function_shaped(entry, insns, &crate::blockflow::LiftShape::of(insns), summaries, external, owns_call)
}

/// [`walk_function_owning`] with the [`crate::blockflow::LiftShape`]
/// of `insns`.
pub(crate) fn walk_function_shaped<I: std::borrow::Borrow<LiftedInstruction>>(
    entry: u64,
    insns: &[I],
    shape: &crate::blockflow::LiftShape,
    summaries: &ParamSummaries,
    external: &std::collections::BTreeSet<u64>,
    owns_call: impl Fn(u64) -> bool,
) -> Vec<CallSite> {
    let mut out = Vec::new();
    let mut tracker = Tracker::new();
    if let Some(summary) = summaries.get(&entry) {
        tracker.seed_from_summary(summary);
    }

    // Only record a call site if we're actually walking the function
    // that *owns* it. Without this gate, an earlier function whose
    // lift_range bled past its own body would record the call with
    // *its* tracker state (e.g. all unresolved), and the dedup would
    // block the real owner from re-recording it with the correct
    // seeded state.
    let owned: Vec<bool> =
        (0..shape.addrs.len()).map(|i| shape.has_call(i) && owns_call(shape.addrs[i])).collect();
    // Nothing after the last owned call is recorded: the walk stops there.
    let Some(last) = owned.iter().rposition(|&o| o) else {
        return out;
    };
    let mut joins = join_points_shaped(shape);
    for (j, a) in joins.iter_mut().zip(shape.addrs.iter()) {
        *j |= external.contains(a);
    }
    for ((insn, &join), &owned) in insns[..=last].iter().map(std::borrow::Borrow::borrow).zip(&joins).zip(&owned) {
        if join {
            tracker.reset();
        }
        for op in &insn.ops {
            match op.opcode {
                OpCode::Call | OpCode::CallInd => {
                    if owned {
                        let target = direct_call_target(op);
                        let args = X86_64_SYSV_ARG_REGS
                            .iter()
                            .map(|&(offset, name)| ResolvedArg {
                                reg_offset: offset,
                                reg_name: name,
                                value: tracker.reg64(offset),
                            })
                            .collect();
                        out.push(CallSite {
                            call_site: insn.address,
                            caller_function: entry,
                            call_target: target,
                            args,
                        });
                    }
                    tracker.clear_for_call();
                }
                _ => tracker.apply(op),
            }
        }
    }
    out
}

/// What a walk of a function reads of its lift besides the P-code: for
/// each instruction up to the last call the function owns (where the
/// walk stops), whether the state reaching it along the previous one is
/// not the only one (a join point: [`WalkPrefix::JOIN`]) and whether it
/// is a call the function owns ([`WalkPrefix::OWNED`]). Kept from the
/// round-0 walk, so a rewalk lifts no more than that prefix (when
/// `plain`) and finds none of it again.
pub struct WalkPrefix {
    /// Per instruction of the prefix.
    pub flags: Box<[u8]>,
    /// The lift's instructions up to there are `lift_range` of that
    /// many instructions (the lift was made instruction by instruction:
    /// no x87 stack or parity flag read across instructions); otherwise
    /// a rewalk lifts the whole budget and keeps the prefix.
    pub plain: bool,
}

impl WalkPrefix {
    pub const JOIN: u8 = 1;
    pub const OWNED: u8 = 2;

    /// The prefix of an increasing lift from its marks.
    pub(crate) fn of_marks(shape: &crate::blockflow::LiftShape, marks: &crate::blockflow::LiftMarks, plain: bool) -> WalkPrefix {
        use crate::blockflow::LiftMarks;
        let n = marks.owned_calls.last().map_or(0, |&last| last + 1);
        let flags = (0..n)
            .map(|i| {
                let f = marks.flags[i];
                // a jump target, an external entry, or after an
                // instruction with no fall-through
                let join = f & (LiftMarks::TARGET | LiftMarks::EXTERNAL) != 0 || (i > 0 && shape.stops(i - 1));
                let owned = f & LiftMarks::OWNED_CALL != 0;
                (u8::from(join) * Self::JOIN) | (u8::from(owned) * Self::OWNED)
            })
            .collect();
        WalkPrefix { flags, plain }
    }
}

/// The walk of the first `flags.len()` instructions of a lift with
/// their [`WalkPrefix`] flags: [`walk_function_shaped`] when they are
/// the prefix of that lift.
pub(crate) fn walk_prefix<I: std::borrow::Borrow<LiftedInstruction>>(
    entry: u64,
    insns: &[I],
    flags: &[u8],
    summaries: &ParamSummaries,
) -> Vec<CallSite> {
    let mut out = Vec::new();
    let mut tracker = Tracker::new();
    if let Some(summary) = summaries.get(&entry) {
        tracker.seed_from_summary(summary);
    }
    let n = insns.len().min(flags.len());
    let mut i = 0;
    while i < n {
        let f = flags[i];
        if f & WalkPrefix::JOIN != 0 {
            tracker.reset();
            // A run up to the next join with no call the function owns
            // gives nothing when what a reset keeps is set already (it is
            // only ever set): the next join resets all the rest.
            if tracker.escaped && tracker.rbp_written {
                let end = flags[i + 1..n].iter().position(|&g| g & WalkPrefix::JOIN != 0).map_or(n, |k| i + 1 + k);
                if flags[i..end].iter().all(|&g| g & WalkPrefix::OWNED == 0) {
                    i = end;
                    continue;
                }
            }
        }
        let insn: &LiftedInstruction = insns[i].borrow();
        i += 1;
        let owned = f & WalkPrefix::OWNED != 0;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Call | OpCode::CallInd => {
                    if owned {
                        let target = direct_call_target(op);
                        let args = X86_64_SYSV_ARG_REGS
                            .iter()
                            .map(|&(offset, name)| ResolvedArg {
                                reg_offset: offset,
                                reg_name: name,
                                value: tracker.reg64(offset),
                            })
                            .collect();
                        out.push(CallSite {
                            call_site: insn.address,
                            caller_function: entry,
                            call_target: target,
                            args,
                        });
                    }
                    tracker.clear_for_call();
                }
                _ => tracker.apply(op),
            }
        }
    }
    out
}

/// Whether `summary` pins any parameter (seeds the tracker). A walk
/// with no seed is the round-0 walk.
fn seeds_anything(summary: Option<&Vec<Option<rustc_hash::FxHashSet<u64>>>>) -> bool {
    summary.is_some_and(|s| s.iter().any(|p| pinned(p).is_some()))
}

/// Round-0 result of one function for
/// [`resolve_call_sites_iterative_from`].
pub struct FunctionWalk {
    /// Function entry.
    pub entry: u64,
    /// Instruction budget it was lifted with.
    pub max_insns: usize,
    /// Its call sites from [`walk_function`] with no summaries, or
    /// `None` when its lift failed (the function is skipped).
    pub sites: Option<Vec<CallSite>>,
    /// What the walk read of the lift, when kept: a rewalk then lifts
    /// and walks only that prefix.
    pub prefix: Option<WalkPrefix>,
}

/// Iterate the propagator to fixpoint (or until `max_iters`). On
/// each round: rebuild parameter summaries from the previous
/// round's call sites, then re-resolve. Stops early when no new
/// per-param constants appear.
pub fn resolve_call_sites_iterative(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    max_iters: usize,
) -> Result<Vec<CallSite>, AnalysisError> {
    if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
        return Ok(Vec::new());
    }
    let empty = ParamSummaries::default();
    let jobs = function_jobs(program);
    let jumps = crate::func_lift::JumpIndex::new(program);
    let walks = map_function_lifts(lifter, program, &jobs, |entry, insns| {
        let external = jumps.external_entries(program, insns);
        walk_function_with(program, entry, insns, &empty, &external)
    });
    let round0: Vec<FunctionWalk> = jobs
        .iter()
        .zip(walks)
        .map(|(&(entry, max_insns), sites)| FunctionWalk { entry, max_insns, sites, prefix: None })
        .collect();
    resolve_call_sites_iterative_from(lifter, program, &round0, max_iters)
}

/// `f(entry, lift_function(lifter, program, entry, max))` for every job, in order (`None` where
/// the lift fails). An x86 lifter lifts the consecutive jobs a thread runs through one
/// [`reargo_lift::x86::LiftCache`] (`lift_range_cached` gives exactly what `lift_range` does):
/// the linear lifts of neighbouring functions overlap.
fn map_function_lifts<T, F>(lifter: &(dyn PcodeLift + Sync), program: &Program, jobs: &[(u64, usize)], f: F) -> Vec<Option<T>>
where
    T: Send,
    F: Fn(u64, &[&reargo_lift::LiftedInstruction]) -> T + Sync,
{
    let memory = &program.info.memory;
    match lifter.as_x86() {
        Some(x86) => {
            // runs of consecutive jobs cut by their lifts
            let spans: Vec<crate::range_lift::Span> = jobs
                .iter()
                .map(|&(entry, max_insns)| crate::range_lift::Span { entry, insns: max_insns, work: max_insns })
                .collect();
            // (the runs one rayon job takes, in order, share one cache)
            let runs: Vec<Vec<Option<T>>> = crate::range_lift::span_chunks(&spans)
                .into_par_iter()
                .map_init(reargo_lift::x86::LiftCache::new, |cache, run| {
                    jobs[run]
                        .iter()
                        .map(|&(entry, max_insns)| {
                            crate::range_lift::trim(cache, entry);
                            let range = x86.lift_range_cached(memory, entry, max_insns, cache);
                            Some(f(entry, &range.insns()))
                        })
                        .collect()
                })
                .collect();
            runs.into_iter().flatten().collect()
        }
        None => jobs
            .par_iter()
            .map(|&(entry, max_insns)| {
                let insns = lift_function(lifter, program, entry, max_insns)?;
                Some(f(entry, &insns.iter().collect::<Vec<_>>()))
            })
            .collect(),
    }
}

/// [`resolve_call_sites_iterative`] from round-0 walks already done
/// (one per function, in listing order). A later round re-lifts and
/// re-walks only the functions its summaries seed; the walk of any
/// other function is its round-0 walk.
pub fn resolve_call_sites_iterative_from(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    round0: &[FunctionWalk],
    max_iters: usize,
) -> Result<Vec<CallSite>, AnalysisError> {
    if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
        return Ok(Vec::new());
    }
    // each function's walk of the round: its rewalk, else round 0's
    let mut rewalked: Vec<Option<Vec<CallSite>>> = round0.iter().map(|_| None).collect();
    fn view<'a>(round0: &'a [FunctionWalk], rewalked: &'a [Option<Vec<CallSite>>]) -> Vec<&'a CallSite> {
        dedup_site_refs(round0.iter().zip(rewalked).filter_map(|(w, r)| r.as_deref().or(w.sites.as_deref())))
    }
    let summaries_of = |sites: &[&CallSite]| {
        // (only a summary that seeds something changes a walk)
        let mut summaries = seeding_summaries(sites.iter().copied());
        keep_closed_callers(program, sites, &mut summaries);
        summaries
    };
    let owned = |sites: &[&CallSite]| -> Vec<CallSite> { sites.par_iter().with_min_len(1024).map(|&s| s.clone()).collect() };
    // Each round's view of the call sites read once: its count, then the
    // next round's summaries (or the result).
    let first = view(round0, &rewalked);
    let mut prev_total_known = count_known_args(&first);
    let mut summaries = (max_iters > 0).then(|| summaries_of(&first));
    let mut sites = if max_iters == 0 { owned(&first) } else { Vec::new() };
    drop(first);
    // the lifts of the functions rewalked, for the next rounds (mostly
    // the same functions)
    let mut lifts = RewalkLifts::default();
    // the summaries of the round before (its walks are `rewalked`)
    let mut prev_summaries: Option<ParamSummaries> = None;
    for round in 0..max_iters {
        let Some(round_summaries) = summaries.take() else { break };
        let prev = prev_summaries.as_ref().map(|s| (s, std::mem::take(&mut rewalked)));
        rewalked = rewalk_functions(lifter, program, round0, &round_summaries, &mut lifts, prev);
        let current = view(round0, &rewalked);
        let next_known = count_known_args(&current);
        if next_known == prev_total_known || round + 1 == max_iters {
            sites = owned(&current);
            break;
        }
        prev_total_known = next_known;
        summaries = Some(summaries_of(&current));
        drop(current);
        prev_summaries = Some(round_summaries);
    }
    // (the lifts and walks are freed on another thread)
    rayon::spawn(move || drop((lifts, rewalked)));
    Ok(sites)
}

/// [`resolve_call_sites_with_summaries`] from round-0 walks: re-lifts
/// and re-walks only the functions `summaries` seeds.
pub fn rewalk_round(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    round0: &[FunctionWalk],
    summaries: &ParamSummaries,
) -> Vec<CallSite> {
    let rewalked = rewalk_functions(lifter, program, round0, summaries, &mut RewalkLifts::default(), None);
    dedup_sites(round0.iter().zip(&rewalked).filter_map(|(w, r)| r.as_deref().or(w.sites.as_deref())))
}

/// A function's lift (`None` when it failed) and its
/// [`crate::func_lift::external_entries`] (`None` for a function with a
/// [`WalkPrefix`], whose lift is cut to the prefix), by `(entry,
/// budget)`.
type RewalkLifts = FxHashMap<(u64, usize), Option<(RewalkInsns, Option<std::collections::BTreeSet<u64>>)>>;

/// A rewalk's lift: a plain prefix's instructions lifted when the walk
/// first reads them (it steps over some: [`walk_prefix`]), kept for the
/// next rounds.
enum RewalkInsns {
    Eager(Vec<LiftedInstruction>),
    Lazy(Vec<reargo_lift::x86::LazyInsn>),
}

/// The walk of each function of `round0` that `summaries` seeds (`None`
/// for the others), reusing (and adding to) the lifts in `lifts`; the
/// program must not change between the rounds that share them. `prev`:
/// the summaries of the round before and its walks (by function of
/// `round0`), taken for the functions whose summary is the same (a walk
/// reads only its own function's summary).
fn rewalk_functions(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    round0: &[FunctionWalk],
    summaries: &ParamSummaries,
    lifts: &mut RewalkLifts,
    prev: Option<(&ParamSummaries, Vec<Option<Vec<CallSite>>>)>,
) -> Vec<Option<Vec<CallSite>>> {
    let rewalk = |w: &FunctionWalk| w.sites.is_some() && seeds_anything(summaries.get(&w.entry));
    let (prev_summaries, mut prev_walks) = match prev {
        Some((s, walks)) => (Some(s), walks),
        None => (None, Vec::new()),
    };
    prev_walks.resize_with(round0.len(), || None);
    // (a walk of the round before with the same summary is this round's)
    let same = |w: &FunctionWalk, walked: &Option<Vec<CallSite>>| {
        walked.is_some() && prev_summaries.is_some_and(|p| p.get(&w.entry) == summaries.get(&w.entry))
    };
    let missing: Vec<(u64, usize, Option<&WalkPrefix>)> = round0
        .iter()
        .zip(&prev_walks)
        .filter(|(w, walked)| rewalk(w) && !same(w, walked) && !lifts.contains_key(&(w.entry, w.max_insns)))
        .map(|(w, _)| w)
        .map(|w| (w.entry, w.max_insns, w.prefix.as_ref()))
        .collect();
    let lifted: Vec<_> = missing
        .par_iter()
        .map(|&(entry, max_insns, prefix)| match prefix {
            // the walk reads only the prefix: lift that much (exactly the
            // whole lift's first instructions when it is plain)
            Some(p) => {
                let n = p.flags.len();
                if n == 0 {
                    return Some((RewalkInsns::Eager(Vec::new()), None));
                }
                if p.plain {
                    // (a prefix is of the x86-64 lift: the shared lift's)
                    let insns = match reargo_lift::x86::X86Lifter::new_64().lift_range_lazy(&program.info.memory, entry, n) {
                        reargo_lift::x86::LazyRange::Lazy(v) => RewalkInsns::Lazy(v),
                        reargo_lift::x86::LazyRange::Eager(v) => RewalkInsns::Eager(v),
                    };
                    return Some((insns, None));
                }
                let mut insns = lift_function(lifter, program, entry, max_insns)?;
                insns.truncate(n);
                Some((RewalkInsns::Eager(insns), None))
            }
            None => lift_function(lifter, program, entry, max_insns).map(|insns| {
                let external = crate::func_lift::external_entries(program, &insns);
                (RewalkInsns::Eager(insns), Some(external))
            }),
        })
        .collect();
    lifts.extend(missing.into_iter().map(|(e, m, _)| (e, m)).zip(lifted));
    let lifts = &*lifts;
    round0
        .par_iter()
        .zip(prev_walks)
        .map(|(w, walked)| {
            if !rewalk(w) {
                return None;
            }
            if same(w, &walked) {
                return walked;
            }
            let (insns, external) = lifts.get(&(w.entry, w.max_insns))?.as_ref()?;
            Some(match (&w.prefix, external, insns) {
                (Some(p), _, RewalkInsns::Lazy(insns)) => walk_prefix(w.entry, insns, &p.flags, summaries),
                (Some(p), _, RewalkInsns::Eager(insns)) => walk_prefix(w.entry, insns, &p.flags, summaries),
                (None, _, RewalkInsns::Lazy(_)) => unreachable!("only a prefix is lifted lazily"),
                (None, Some(external), RewalkInsns::Eager(insns)) => walk_function_with(program, w.entry, insns, summaries, external),
                (None, None, RewalkInsns::Eager(insns)) => {
                    walk_function_with(program, w.entry, insns, summaries, &crate::func_lift::external_entries(program, insns))
                }
            })
        })
        .collect()
}

fn count_known_args(sites: &[&CallSite]) -> usize {
    sites
        .iter()
        .map(|s| s.args.iter().filter(|a| a.value.is_some()).count())
        .sum()
}

/// REGISTER-space offset of `rbp` on x86_64. After the standard
/// `push rbp; mov rbp, rsp` prologue, this register is the
/// frame anchor for the rest of the function and stack slots are
/// addressed as `[rbp + signed_offset]`.
const X86_64_RBP_OFFSET: u64 = 0x28;
/// REGISTER-space offset of `rsp` on x86_64.
const X86_64_RSP_OFFSET: u64 = 0x20;

/// Mini abstract-interpreter that tracks enough state to thread
/// constants through gcc -O0's typical "spill to stack, reload"
/// pattern:
///
///   mov [rbp-8], rdi          ; param spill
///   ...
///   mov rax, [rbp-8]          ; reload to rax
///   mov rdi, rax              ; pass to next call
///
/// To follow the value across the spill/reload we have to track:
///
/// * `regs` -- known register bytes, with x86 sub-register
///   semantics (see [`crate::byteconst`]): `mov esi, 0x2a` and its
///   view refreshes leave `rsi = 0x2a`, `mov al, 5` changes only the
///   low byte of `rax`.
/// * `temps` -- known values of UNIQUE (and other non-register)
///   varnodes, keyed by offset with their size.
/// * `frame_offsets` -- UNIQUE varnodes that hold an `rbp + N`
///   effective address.
/// * `stack` -- known values stored to a stack slot (signed offset
///   from rbp, with the store's size).
/// * `rsp_temps` -- UNIQUE varnodes that hold an `rsp`-relative
///   address, and `escaped` -- whether a stack address has left the
///   frame-addressing ops (`lea rdi, [rbp-0x44]`, `push rax` of such
///   an address, a copy of rsp / rbp). Once it has, a call or a store
///   through an unknown pointer may write any slot, so they forget the
///   stack; a store through an rsp-relative address (which may alias
///   an rbp slot) always does.
///
/// This is deliberately NOT a full SSA / dataflow engine -- just
/// enough state to catch the typical -O0 call-argument flow. Loads
/// from memory not reachable from the frame pointer remain unknown.
/// The walk is linear, so the whole state is dropped at every
/// instruction another path can reach (a jump target, or the
/// instruction after an unconditional jump / return): a value set on
/// one path must not reach a call on another. Joins are
/// `cfg_const`'s job.
struct Tracker {
    regs: RegFile,
    temps: ByteMem<SpaceId>,
    frame_offsets: FxHashMap<u64, i64>,
    stack: ByteMem<()>,
    rsp_temps: rustc_hash::FxHashSet<u64>,
    escaped: bool,
    /// rbp was written in this function (before that it holds the
    /// caller's frame pointer, which `push rbp` saves harmlessly).
    rbp_written: bool,
}

impl Tracker {
    fn new() -> Self {
        Self {
            regs: RegFile::new(),
            temps: ByteMem::new(),
            frame_offsets: FxHashMap::default(),
            stack: ByteMem::new(),
            rsp_temps: rustc_hash::FxHashSet::default(),
            escaped: false,
            rbp_written: false,
        }
    }

    /// Wipe per-call caller-saved state but keep what survives a
    /// call. Conservatively: clear every register and every UNIQUE
    /// temp; stack slots persist because the callee can't write to
    /// the caller's frame -- unless a stack address escaped, then the
    /// callee may write through it. frame_offsets are also wiped --
    /// the lifter mints new UNIQUE addresses after each instruction.
    fn clear_for_call(&mut self) {
        self.regs.clear();
        self.temps.clear();
        self.frame_offsets.clear();
        self.rsp_temps.clear();
        if self.escaped {
            self.stack.clear();
        }
    }

    /// Whether `vn` holds a stack address (rsp, rbp, or a temporary
    /// computed from them).
    fn is_stack_address(&self, vn: &VarnodeData) -> bool {
        match vn.space {
            SpaceId::REGISTER => {
                vn.offset == X86_64_RSP_OFFSET || (vn.offset == X86_64_RBP_OFFSET && self.rbp_written)
            }
            SpaceId::UNIQUE => {
                self.frame_offsets.contains_key(&vn.offset) || self.rsp_temps.contains(&vn.offset)
            }
            _ => false,
        }
    }

    /// Forget everything: the next instruction is a control-flow join.
    fn reset(&mut self) {
        self.clear_for_call();
        self.stack.clear();
    }

    /// The known bytes of a varnode.
    fn read(&self, vn: &VarnodeData) -> ByteConst {
        match vn.space {
            SpaceId::CONST => ByteConst::konst(vn.offset, vn.size),
            SpaceId::REGISTER => self.regs.read(vn.offset, vn.size),
            s => self.temps.read(s, vn.offset as i64, vn.size),
        }
    }

    fn write(&mut self, out: &VarnodeData, v: ByteConst) {
        match out.space {
            SpaceId::REGISTER => self.regs.write(out.offset, out.size, v),
            s => self.temps.write(s, out.offset as i64, out.size, v),
        }
    }

    /// The full 8-byte value of the register at `offset`, if known.
    fn reg64(&self, offset: u64) -> Option<u64> {
        self.regs.get64(offset)
    }

    /// Apply one P-code op's effect to the tracker state (inlined: the ops that change
    /// nothing, a view refresh or an op without an output, return before a call).
    #[inline(always)]
    fn apply(&mut self, op: &reargo_core::pcode::PcodeOp) {
        if is_unmodeled(op) {
            // may write any register, and memory through them
            self.clear_for_call();
            return;
        }
        // Handle stores first -- they have no output but do mutate
        // tracked state (stack slots).
        if op.opcode == OpCode::Store {
            self.apply_store(op);
            return;
        }
        let Some(out) = op.output else { return };
        if is_view_refresh(op) {
            return;
        }
        self.apply_output(op, out);
    }

    /// [`Self::apply`] of a `STORE`.
    #[inline(never)]
    fn apply_store(&mut self, op: &reargo_core::pcode::PcodeOp) {
        {
            // STORE space, addr, value -- inputs[0]=space-id,
            // inputs[1]=address, inputs[2]=value.
            let (Some(addr), Some(value)) = (op.inputs.get(1), op.inputs.get(2)) else { return };
            if self.is_stack_address(value) {
                self.escaped = true;
            }
            let frame_slot = (addr.space == SpaceId::UNIQUE).then(|| self.frame_offsets.get(&addr.offset)).flatten();
            if let Some(&off) = frame_slot {
                let v = self.read(value);
                self.stack.write((), off, value.size, v);
            } else if self.escaped || self.is_stack_address(addr) {
                // rsp-relative (may alias an rbp slot), or through a
                // pointer that may point into the frame
                self.stack.clear();
            }
        }
    }

    /// [`Self::apply`] of an op (not a `STORE`, not a view refresh) that writes `out`.
    #[inline(never)]
    fn apply_output(&mut self, op: &reargo_core::pcode::PcodeOp, out: VarnodeData) {
        // a load's input is an address, not a value it passes on
        let reads_stack_address =
            op.opcode != OpCode::Load && op.inputs.iter().any(|vn| self.is_stack_address(vn));
        if out.space == SpaceId::REGISTER && out.offset & !7 == X86_64_RBP_OFFSET {
            self.rbp_written = true;
        }
        if out.space == SpaceId::UNIQUE {
            self.frame_offsets.remove(&out.offset);
            self.rsp_temps.remove(&out.offset);
            if let Some(off) = frame_address(op) {
                self.frame_offsets.insert(out.offset, off);
                self.write(&out, ByteConst::UNKNOWN);
                return;
            }
            if reads_stack_address {
                self.rsp_temps.insert(out.offset);
            }
        } else if out.space == SpaceId::REGISTER
            && reads_stack_address
            && out.offset < 0x200
            && !matches!(out.offset & !7, X86_64_RBP_OFFSET | X86_64_RSP_OFFSET)
        {
            // a stack address in a general register: it can be passed on
            self.escaped = true;
        }
        let v = if op.opcode == OpCode::Load {
            // LOAD space, addr -- inputs[0]=space-id, inputs[1]=address.
            match op.inputs.get(1) {
                Some(addr) if addr.space == SpaceId::UNIQUE => match self.frame_offsets.get(&addr.offset) {
                    Some(&off) => self.stack.read((), off, out.size),
                    None => ByteConst::UNKNOWN,
                },
                _ => ByteConst::UNKNOWN,
            }
        } else {
            eval(op, |vn| self.read(vn)).unwrap_or(ByteConst::UNKNOWN)
        };
        self.write(&out, v);
    }

    /// Pre-seed register state from a function-entry summary built
    /// by the inter-procedural propagator.
    fn seed_from_summary(&mut self, summary: &[Option<rustc_hash::FxHashSet<u64>>]) {
        for (i, param) in summary.iter().enumerate() {
            if let Some(v) = pinned(param) {
                self.regs.set64(X86_64_SYSV_ARG_REGS[i].0, v);
            }
        }
    }
}

/// `rbp + N` / `rbp - N` (a frame address): its signed offset `N`.
fn frame_address(op: &reargo_core::pcode::PcodeOp) -> Option<i64> {
    if !matches!(op.opcode, OpCode::IntAdd | OpCode::IntSub) || op.inputs.len() < 2 {
        return None;
    }
    let (a, b) = (&op.inputs[0], &op.inputs[1]);
    let frame_base =
        |vn: &VarnodeData| vn.space == SpaceId::REGISTER && vn.offset == X86_64_RBP_OFFSET && vn.size == 8;
    let signed = |vn: &VarnodeData| {
        let bits = vn.size.min(8) * 8;
        if bits == 0 || bits >= 64 {
            vn.offset as i64
        } else {
            ((vn.offset << (64 - bits)) as i64) >> (64 - bits)
        }
    };
    if frame_base(a) && b.space == SpaceId::CONST {
        let off = signed(b);
        Some(if op.opcode == OpCode::IntSub { off.wrapping_neg() } else { off })
    } else if frame_base(b) && a.space == SpaceId::CONST && op.opcode == OpCode::IntAdd {
        // Sub isn't commutative: (const - rbp) is no frame address.
        Some(signed(a))
    } else {
        None
    }
}

/// Indices of `insns` that start a new straight-line region: a jump
/// target inside the lift, or the instruction after an unconditional
/// jump / indirect jump / return. State reaching them along the
/// previous instruction is not the only state reaching them.
#[cfg(test)]
fn join_points<I: std::borrow::Borrow<LiftedInstruction>>(insns: &[I]) -> Vec<bool> {
    join_points_shaped(&crate::blockflow::LiftShape::of(insns))
}

/// [`join_points`] from the [`crate::blockflow::LiftShape`] of the
/// instructions: the targets of their `Branch` / `CBranch` ops, and
/// the instructions after a `Branch` / `BranchInd` / `Return`.
fn join_points_shaped(shape: &crate::blockflow::LiftShape) -> Vec<bool> {
    let mut out = vec![false; shape.addrs.len()];
    if shape.increasing {
        // (one address per instruction: each target is the address of at most one, found
        // by its place among the ascending addresses)
        for &(_, t) in &shape.branches {
            if let Ok(i) = shape.addrs.binary_search(&t) {
                out[i] = true;
            }
        }
        for (o, &f) in out.iter_mut().skip(1).zip(shape.flags.iter()) {
            *o |= f & reargo_lift::InsnShape::STOPS != 0;
        }
        return out;
    }
    join_points_hashed(shape)
}

/// [`join_points_shaped`] for any lift (the addresses need not increase).
fn join_points_hashed(shape: &crate::blockflow::LiftShape) -> Vec<bool> {
    let mut out = vec![false; shape.addrs.len()];
    let targets: rustc_hash::FxHashSet<u64> = shape.branches.iter().map(|&(_, t)| t).collect();
    let mut after_terminator = false;
    for (i, &a) in shape.addrs.iter().enumerate() {
        out[i] = after_terminator || targets.contains(&a);
        after_terminator = shape.stops(i);
    }
    out
}

/// Extract the direct call target from a Call op. Returns `None`
/// for indirect calls (target is not a CONST or RAM varnode).
fn direct_call_target(op: &reargo_core::pcode::PcodeOp) -> Option<u64> {
    let target_vn: &VarnodeData = op.inputs.first()?;
    if matches!(target_vn.space, SpaceId::RAM) || matches!(target_vn.space, SpaceId::CONST) {
        Some(target_vn.offset)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::pcode::{PcodeOp, SeqNum};

    /// The join points found by the ascending addresses are the ones the hashed targets
    /// give.
    #[test]
    fn join_points_increasing_match_hashed() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = |m: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % m
        };
        for _ in 0..200 {
            let n = next(60) as usize;
            let mut addrs = Vec::with_capacity(n);
            let mut a = 0x1000 + next(8);
            for _ in 0..n {
                addrs.push(a);
                a += 1 + next(7);
            }
            let branches = (0..next(12))
                .map(|_| (next(n.max(1) as u64) as usize, 0xff8 + next(a - 0xff0)))
                .collect::<Vec<_>>();
            let stops = (0..n).map(|_| next(4) == 0).collect::<Vec<_>>();
            let flags = stops
                .iter()
                .map(|&s| if s { reargo_lift::InsnShape::STOPS | reargo_lift::InsnShape::ENDS } else { 0 })
                .collect();
            let shape = crate::blockflow::LiftShape::from_parts(true, addrs, flags, branches);
            assert_eq!(join_points_shaped(&shape), join_points_hashed(&shape));
        }
    }
    use smallvec::SmallVec;

    fn const_vn(value: u64) -> VarnodeData {
        VarnodeData::new(SpaceId::CONST, value, 8)
    }
    fn k(value: u64, size: u32) -> VarnodeData {
        VarnodeData::new(SpaceId::CONST, value, size)
    }
    fn reg_vn(offset: u64) -> VarnodeData {
        VarnodeData::new(SpaceId::REGISTER, offset, 8)
    }
    fn reg(offset: u64, size: u32) -> VarnodeData {
        VarnodeData::new(SpaceId::REGISTER, offset, size)
    }
    fn uniq(offset: u64, size: u32) -> VarnodeData {
        VarnodeData::new(SpaceId::UNIQUE, offset, size)
    }
    fn seq(addr: u64) -> SeqNum {
        SeqNum::new(reargo_core::address::Address::new(SpaceId::RAM, addr), 0)
    }
    fn op(opcode: OpCode, output: Option<VarnodeData>, inputs: &[VarnodeData]) -> PcodeOp {
        PcodeOp { opcode, seq: seq(0x1000), output, inputs: SmallVec::from_slice(inputs) }
    }
    fn run(t: &mut Tracker, ops: &[PcodeOp]) {
        for o in ops {
            t.apply(o);
        }
    }
    use crate::byteconst::testseq::views;

    #[test]
    fn copy_const_to_register_is_tracked() {
        let mut t = Tracker::new();
        t.apply(&op(OpCode::Copy, Some(reg_vn(0x38)), &[const_vn(42)]));
        assert_eq!(t.reg64(0x38), Some(42));
    }

    #[test]
    fn non_const_write_invalidates() {
        let mut t = Tracker::new();
        t.regs.set64(0x38, 42);
        t.apply(&op(OpCode::IntAdd, Some(reg_vn(0x38)), &[reg_vn(0x30), const_vn(1)]));
        assert_eq!(t.reg64(0x38), None);
    }

    #[test]
    fn writes_to_other_registers_leave_target_alone() {
        let mut t = Tracker::new();
        t.regs.set64(0x38, 42);
        t.apply(&op(OpCode::Copy, Some(reg_vn(0x30)), &[const_vn(99)]));
        assert_eq!(t.reg64(0x38), Some(42));
        assert_eq!(t.reg64(0x30), Some(99));
    }

    /// `mov esi, 0x2a`: the ZEXT / SUBPIECE mirror writes must neither
    /// erase nor truncate the value.
    #[test]
    fn mov_esi_imm32() {
        let mut t = Tracker::new();
        let mut ops = vec![op(OpCode::Copy, Some(reg(0x30, 4)), &[k(0x2a, 4)])];
        ops.extend(views(0x30, 4));
        run(&mut t, &ops);
        assert_eq!(t.reg64(0x30), Some(0x2a));
    }

    /// `lea rax, [0x402004]; mov rdi, rax`: rdi is the full address,
    /// not its low byte.
    #[test]
    fn lea_then_mov_rdi_rax() {
        let mut t = Tracker::new();
        let mut ops = vec![op(OpCode::Copy, Some(reg(0, 8)), &[k(0x402004, 8)])];
        ops.extend(views(0, 8));
        ops.push(op(OpCode::Copy, Some(reg(0x38, 8)), &[reg(0, 8)]));
        ops.extend(views(0x38, 8));
        run(&mut t, &ops);
        assert_eq!(t.reg64(0), Some(0x402004));
        assert_eq!(t.reg64(0x38), Some(0x402004));
    }

    /// `mov al, 5` keeps the upper bytes of a known rax.
    #[test]
    fn mov_al_merges_into_known_rax() {
        let mut t = Tracker::new();
        t.regs.set64(0, 0x0000_7fff_1234_5678);
        let mut ops = vec![op(OpCode::Copy, Some(reg(0, 1)), &[k(5, 1)])];
        ops.extend(views(0, 1));
        run(&mut t, &ops);
        assert_eq!(t.reg64(0), Some(0x0000_7fff_1234_5605));
        // ...and into an unknown rax only the low byte is known.
        let mut t = Tracker::new();
        run(&mut t, &ops);
        assert_eq!(t.reg64(0), None);
        assert_eq!(t.regs.read(0, 1).get(1), Some(5));
    }

    /// `mov ah, 7` (the lifter writes byte 1 of rax, then rebuilds ax
    /// and rax) and `movzx ecx, ah`.
    #[test]
    fn ah_write_and_read() {
        let mut t = Tracker::new();
        t.regs.set64(0, 0x1111_2222_3333_4444);
        let hi = uniq(0x7e00, 6);
        run(
            &mut t,
            &[
                op(OpCode::Copy, Some(reg(1, 1)), &[k(7, 1)]),
                op(OpCode::Piece, Some(reg(0, 2)), &[reg(1, 1), reg(0, 1)]),
                op(OpCode::Subpiece, Some(hi), &[reg(0, 8), k(2, 4)]),
                op(OpCode::Piece, Some(reg(0, 8)), &[hi, reg(0, 2)]),
                op(OpCode::Subpiece, Some(reg(0, 4)), &[reg(0, 8), k(0, 4)]),
                // movzx ecx, ah: ah = SUBPIECE(rax, 1); ecx = ZEXT(ah); views
                op(OpCode::Subpiece, Some(reg(1, 1)), &[reg(0, 8), k(1, 4)]),
                op(OpCode::IntZExt, Some(reg(0x08, 4)), &[reg(1, 1)]),
            ],
        );
        run(&mut t, &views(0x08, 4));
        assert_eq!(t.reg64(0), Some(0x1111_2222_3333_0744));
        assert_eq!(t.reg64(0x08), Some(7));
    }

    /// `movsx edi, byte [const]`-style sign extension and `movzx`.
    #[test]
    fn movsx_movzx() {
        let mut t = Tracker::new();
        t.regs.write(0x10, 1, ByteConst::konst(0x80, 1)); // dl = 0x80
        let mut ops = vec![op(OpCode::IntSExt, Some(reg(0x38, 4)), &[reg(0x10, 1)])];
        ops.extend(views(0x38, 4));
        ops.push(op(OpCode::IntZExt, Some(reg(0x30, 4)), &[reg(0x10, 1)]));
        ops.extend(views(0x30, 4));
        // movsxd rcx, edi
        ops.push(op(OpCode::IntSExt, Some(reg(0x08, 8)), &[reg(0x38, 4)]));
        ops.extend(views(0x08, 8));
        run(&mut t, &ops);
        assert_eq!(t.reg64(0x38), Some(0xffff_ff80));
        assert_eq!(t.reg64(0x30), Some(0x80));
        assert_eq!(t.reg64(0x08), Some(0xffff_ffff_ffff_ff80));
    }

    /// `xor eax, eax` is 0 whatever eax held.
    #[test]
    fn xor_self_is_zero() {
        let mut t = Tracker::new();
        let mut ops = vec![op(OpCode::IntXor, Some(reg(0, 4)), &[reg(0, 4), reg(0, 4)])];
        ops.extend(views(0, 4));
        run(&mut t, &ops);
        assert_eq!(t.reg64(0), Some(0));
    }

    /// -O0 spill / reload through `[rbp-8]` with a 4-byte slot.
    #[test]
    fn stack_spill_reload() {
        let mut t = Tracker::new();
        let addr = uniq(0x100, 8);
        let mut ops = vec![
            op(OpCode::IntAdd, Some(addr), &[reg(0x28, 8), k(0xffff_ffff_ffff_fff8, 8)]),
            op(OpCode::Store, None, &[k(0, 8), addr, k(0x2a, 4)]),
        ];
        let addr2 = uniq(0x110, 8);
        let tmp = uniq(0x120, 4);
        ops.push(op(OpCode::IntSub, Some(addr2), &[reg(0x28, 8), k(8, 8)]));
        ops.push(op(OpCode::Load, Some(tmp), &[k(0, 8), addr2]));
        ops.push(op(OpCode::Copy, Some(reg(0x30, 4)), &[tmp]));
        ops.extend(views(0x30, 4));
        run(&mut t, &ops);
        assert_eq!(t.reg64(0x30), Some(0x2a));
        // an 8-byte reload of a 4-byte slot is unknown
        let tmp8 = uniq(0x130, 8);
        t.apply(&op(OpCode::Load, Some(tmp8), &[k(0, 8), addr2]));
        assert_eq!(t.read(&tmp8).get(8), None);
    }

    /// A slot whose address was taken (`lea rax, [rbp-0x44]`) may be
    /// written by a callee: it is forgotten at the next call. One whose
    /// address never left the frame survives the call.
    #[test]
    fn address_taken_slot_dies_at_call() {
        let run_case = |take_address: bool| {
            let mut t = Tracker::new();
            t.apply(&op(OpCode::Copy, Some(reg(0x28, 8)), &[reg(0x20, 8)])); // mov rbp, rsp
            let a = uniq(0x100, 8);
            t.apply(&op(OpCode::IntAdd, Some(a), &[reg(0x28, 8), k((-0x44i64) as u64, 8)]));
            t.apply(&op(OpCode::Store, None, &[k(0, 8), a, k(0, 4)]));
            if take_address {
                t.apply(&op(OpCode::IntAdd, Some(reg(0, 8)), &[reg(0x28, 8), k((-0x44i64) as u64, 8)]));
            }
            t.clear_for_call();
            let a2 = uniq(0x110, 8);
            t.apply(&op(OpCode::IntAdd, Some(a2), &[reg(0x28, 8), k((-0x44i64) as u64, 8)]));
            t.apply(&op(OpCode::Load, Some(reg(0x08, 4)), &[k(0, 8), a2]));
            t.regs.read(0x08, 4).get(4)
        };
        assert_eq!(run_case(false), Some(0));
        assert_eq!(run_case(true), None);
    }

    /// A jump target and the instruction after a `jmp` start a new
    /// straight-line region.
    #[test]
    fn join_points_at_targets_and_after_jumps() {
        let insn = |address: u64, ops: Vec<PcodeOp>| LiftedInstruction { address, length: 4, mnemonic: "x".into(), ops };
        let ram = |a: u64| VarnodeData::new(SpaceId::RAM, a, 8);
        let insns = vec![
            insn(0x1000, vec![op(OpCode::CBranch, None, &[ram(0x100c), reg(0x206, 1)])]),
            insn(0x1004, vec![op(OpCode::Copy, Some(reg_vn(0x38)), &[const_vn(1)])]),
            insn(0x1008, vec![op(OpCode::Branch, None, &[ram(0x1010)])]),
            insn(0x100c, vec![op(OpCode::Copy, Some(reg_vn(0x38)), &[const_vn(2)])]),
            insn(0x1010, vec![op(OpCode::Call, None, &[ram(0x2000)])]),
        ];
        assert_eq!(join_points(&insns), vec![false, false, false, true, true]);
    }
}
