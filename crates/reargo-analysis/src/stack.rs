use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use reargo_lift::PcodeLift;
use reargo_program::function::Function;
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, State};

const RSP_OFFSET: u64 = 0x20;
const RBP_OFFSET: u64 = 0x28;

pub struct StackFrameAnalyzer;

impl Analyzer for StackFrameAnalyzer {
    fn writes(&self) -> State {
        State::FUNC_OTHER.union(State::CACHE)
    }
    fn name(&self) -> &str {
        "Stack Frame"
    }

    fn description(&self) -> &str {
        "Analyzes stack accesses to identify local variables and parameters"
    }

    fn priority(&self) -> u32 {
        350
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let is_64 = program.info.bits == 64;
        if !matches!(
            program.info.arch,
            reargo_loader::Architecture::X86 | reargo_loader::Architecture::X86_64
        ) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let lifter: Box<dyn PcodeLift> = if is_64 {
            Box::new(reargo_lift::x86::X86Lifter::new_64())
        } else {
            Box::new(reargo_lift::x86::X86Lifter::new_32())
        };
        let lifter: &dyn PcodeLift = &*lifter;

        let func_entries: Vec<u64> = program
            .listing
            .functions()
            .map(|f| f.entry_point)
            .collect();

        // Phase 1: analyse each function in parallel against an
        // immutable view of `program`. The lift-and-scan loop is the
        // expensive part (lifting 200 instructions and walking each
        // op); doing it on a rayon thread pool gives near-linear
        // speed-up across cores because the analysis is pure
        // function-local with no shared mutable state.
        //
        // The 64-bit lift is shared between neighbouring functions
        // ([`crate::range_lift::map_with_lifter`]). Later analyzers lift
        // the same functions linearly again, and what they compute from
        // a lift depends on nothing that changes during the run (the
        // bytes, the sections, the imports): their results are computed
        // here on the same lifts and left for them, by `(entry, budget)`
        // ([`compute_ahead`]); each takes those whose budget still
        // matches and computes the others itself.
        let updates: Vec<FunctionStackInfo> = if is_64 {
            compute_ahead(program)
        } else {
            func_entries
                .par_iter()
                .map(|&entry| analyse_function_stack(lifter, program, entry))
                .collect()
        };

        // Phase 2: serialise the writes. PcodeLift's `&dyn` bound
        // doesn't enforce determinism, but each FunctionStackInfo
        // targets a *distinct* function entry, so the apply step
        // produces the same listing regardless of the parallel
        // analysis order.
        let mut total_vars = 0;
        for info in updates {
            if let Some(func) = program.listing.get_function_mut(info.entry) {
                func.stack_frame.local_size = info.stack_alloc.max(0) as u64;
                for (offset, size) in &info.variables {
                    func.stack_frame.add_variable(*offset, *size);
                }
            }
            total_vars += info.variables.len();
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: total_vars,
            instructions_decoded: 0,
        })
    }
}

/// The stack info of every function (in listing order), each from the
/// 64-bit `lift_range(entry, STACK_LIFT_BUDGET)`, and, from the same
/// lifts, the per-function results of the analyzers that lift every
/// function linearly later, stored for them in the analysis cache:
///
/// * Constant Propagation (400): the same lift
///   ([`crate::propagation::Precomputed`]);
/// * on x86-64, P-code Reference (510), Indirect Call Resolver (575,
///   when the program imports anything), Calling Convention (770) and
///   Argument Arity (780), each with its own budget
///   ([`crate::pcoderef::Ahead`], [`crate::indirect_resolve::Ahead`],
///   [`crate::callingconv::Ahead`], [`crate::arity::Ahead`]).
///
/// The largest range of a function is lifted first, the others mostly
/// read the instructions it lifted.
fn compute_ahead(program: &mut Program) -> Vec<FunctionStackInfo> {
    use crate::range_lift::AheadMap;
    struct Job {
        entry: u64,
        pcode: usize,
        indirect: usize,
        arity: usize,
    }
    struct Out {
        stack: FunctionStackInfo,
        propagation: Vec<(u64, u64)>,
        pcode: Vec<(u64, u64, reargo_program::RefType)>,
        indirect: Vec<(u64, u64)>,
        convention: Option<(u64, &'static str)>,
        arity: usize,
    }
    let x86_64 = matches!(program.info.arch, reargo_loader::Architecture::X86_64);
    // (each body's size summed once: the three budgets are made from it,
    // as `pcoderef::budget`, `indirect_resolve::budget`, `arity::budget`)
    let jobs: Vec<Job> = crate::func_lift::map_functions(program, |f| {
        let size = crate::func_lift::body_size(f);
        Job { entry: f.entry_point, pcode: size.max(500), indirect: size.max(200), arity: size.max(200) }
    });
    let (out, has_got): (Vec<Out>, bool) = {
        let program = &*program;
        let valid_ranges = crate::propagation::valid_ranges(program);
        let sections = crate::pcoderef::SectionMap::from(program);
        let got = crate::indirect_resolve::GotMap::new(program);
        let plt_of_got = |g: u64| got.as_ref().and_then(|got| got.plt_of_got(g));
        // a job lifts its largest budget and scans each prefix
        let span = |job: &Job| {
            let insns = if x86_64 {
                STACK_LIFT_BUDGET.max(job.pcode).max(job.indirect).max(job.arity).max(crate::callingconv::LIFT_BUDGET)
            } else {
                STACK_LIFT_BUDGET
            };
            crate::range_lift::Span { entry: job.entry, insns, work: insns / 4 }
        };
        // (a lazy cache: P-code Reference's scan, whose budget is the largest, lifts an
        // instruction only where its decode shows a constant in a section)
        let out = crate::range_lift::map_with_lazy_lifter(&program.info.memory, &jobs, span, |job, lifter| {
            let entry = job.entry;
            let mut stack = None;
            let mut propagation = Vec::new();
            let mut pcode = Vec::new();
            let mut indirect = Vec::new();
            let mut convention = None;
            let mut arity = 0;
            // the lifts of the analyzers, each exactly `lift_range(entry,
            // budget)`, from one walk of the largest
            const STACK: usize = 0;
            const PCODE: usize = 1;
            const INDIRECT: usize = 2;
            const ARITY: usize = 3;
            const CONVENTION: usize = 4;
            let budgets: &[usize] = if x86_64 {
                &[STACK_LIFT_BUDGET, job.pcode, job.indirect, job.arity, crate::callingconv::LIFT_BUDGET]
            } else {
                &[STACK_LIFT_BUDGET]
            };
            /// The instructions up to the first whose lift returns, lifted.
            fn lifted_to_return<'c>(insns: &[reargo_lift::x86::RangeInsn<'c>]) -> Vec<&'c reargo_lift::LiftedInstruction> {
                let mut out = Vec::with_capacity(insns.len());
                for i in insns {
                    let insn = i.get();
                    out.push(insn);
                    if insn.ops.iter().any(|op| op.opcode == OpCode::Return) {
                        break;
                    }
                }
                out
            }
            lifter.with_budgets_lazy(entry, budgets, |k, insns, shapes| match k {
                STACK => {
                    // (both stop after the first instruction that
                    // returns: the rest is not lifted for them)
                    let insns = lifted_to_return(insns);
                    stack = Some(stack_info_lifted(entry, &insns));
                    propagation = crate::propagation::analyse_lifted(&insns, &valid_ranges);
                }
                PCODE => pcode = crate::pcoderef::scan_range(insns, &sections),
                INDIRECT => {
                    if got.is_some() {
                        indirect = indirect_of(insns, shapes, &plt_of_got);
                    }
                }
                ARITY => arity = crate::arity::infer_arity(insns),
                CONVENTION => convention = crate::callingconv::convention_lifted(entry, insns),
                _ => unreachable!("one result per budget"),
            });
            let stack = stack.expect("the stack lift");
            Out { stack, propagation, pcode, indirect, convention, arity }
        });
        (out, got.is_some())
    };
    let mut propagation: AheadMap<Vec<(u64, u64)>> = AheadMap::default();
    let mut pcode: AheadMap<Vec<(u64, u64, reargo_program::RefType)>> = AheadMap::default();
    let mut indirect: AheadMap<Vec<(u64, u64)>> = AheadMap::default();
    let mut convention: AheadMap<Option<(u64, &'static str)>> = AheadMap::default();
    let mut arity: AheadMap<usize> = AheadMap::default();
    let mut stack = Vec::with_capacity(out.len());
    for (o, job) in out.into_iter().zip(&jobs) {
        let entry = job.entry;
        propagation.insert((entry, STACK_LIFT_BUDGET), o.propagation);
        if x86_64 {
            pcode.insert((entry, job.pcode), o.pcode);
            if has_got {
                indirect.insert((entry, job.indirect), o.indirect);
            }
            convention.insert((entry, crate::callingconv::LIFT_BUDGET), o.convention);
            arity.insert((entry, job.arity), o.arity);
        }
        stack.push(o.stack);
    }
    program.analysis_cache.insert(crate::propagation::Precomputed(propagation));
    if x86_64 {
        program.analysis_cache.insert(crate::pcoderef::Ahead(pcode));
        if has_got {
            program.analysis_cache.insert(crate::indirect_resolve::Ahead(indirect));
        }
        program.analysis_cache.insert(crate::callingconv::Ahead(convention));
        program.analysis_cache.insert(crate::arity::Ahead(arity));
    }
    stack
}

/// The Indirect Call Resolver's result of a lift (`resolve_lifted`):
/// only a `CallInd` gives one, and the walk runs forward, so what follows
/// the last one is not lifted for it.
fn indirect_of(
    insns: &[reargo_lift::x86::RangeInsn<'_>],
    shapes: Option<&reargo_lift::RangeShapes>,
    plt_of_got: &dyn Fn(u64) -> Option<u64>,
) -> Vec<(u64, u64)> {
    let last = match shapes {
        Some(shapes) => shapes.special().rev().find(|&i| shapes.flags[i] & reargo_lift::InsnShape::CALLIND != 0),
        None => insns.len().checked_sub(1),
    };
    let Some(last) = last else {
        return Vec::new();
    };
    let lifted: Vec<&reargo_lift::LiftedInstruction> = insns[..=last].iter().map(|i| i.get()).collect();
    crate::indirect_resolve::resolve_lifted(&lifted, plt_of_got)
}

/// P-code Reference's and the Indirect Call Resolver's results
/// ([`crate::pcoderef::Ahead`], [`crate::indirect_resolve::Ahead`]) for
/// functions with no body at `entries` (their budgets the floors, 500
/// and 200), from the same lifts as theirs: for functions an analyzer
/// adds after the Stack Frame analyzer computed the others (the CRT
/// Pattern analyzer's, in its `prepare`), each taken by `(entry, budget)`
/// like those. The second is `None` when the program imports nothing.
pub(crate) type NewAhead = (
    crate::range_lift::AheadMap<Vec<(u64, u64, reargo_program::RefType)>>,
    Option<crate::range_lift::AheadMap<Vec<(u64, u64)>>>,
);

pub(crate) fn ahead_for_new(program: &Program, entries: &[u64]) -> NewAhead {
    let empty = Function::new(0, String::new());
    let (pcode_budget, indirect_budget) = (crate::pcoderef::budget(&empty), crate::indirect_resolve::budget(&empty));
    let sections = crate::pcoderef::SectionMap::from(program);
    let got = crate::indirect_resolve::GotMap::new(program);
    let plt_of_got = |g: u64| got.as_ref().and_then(|got| got.plt_of_got(g));
    let scanner = reargo_lift::x86::X86Lifter::new_64();
    let insns = pcode_budget.max(indirect_budget);
    let span = |&entry: &u64| crate::range_lift::Span { entry, insns, work: insns / 4 };
    let out: Vec<(Vec<(u64, u64, reargo_program::RefType)>, Vec<(u64, u64)>)> =
        crate::range_lift::map_with_lazy_lifter(&program.info.memory, entries, span, |&entry, lifter| {
            // (as the analyzers do: P-code Reference's scan lifts an
            // instruction only where its decode shows a constant in a
            // section, the resolver lifts only a range with an indirect
            // `call`, found by a decode)
            let (mut pcode, mut indirect) = (Vec::new(), Vec::new());
            lifter.with_budgets_lazy(entry, &[pcode_budget], |_, insns, _| pcode = crate::pcoderef::scan_range(insns, &sections));
            if got.is_some() && scanner.range_has_indirect_call(&program.info.memory, entry, indirect_budget) {
                lifter.with_budgets_lazy(entry, &[indirect_budget], |_, insns, shapes| {
                    indirect = indirect_of(insns, shapes, &plt_of_got);
                });
            }
            (pcode, indirect)
        });
    let mut pcode = crate::range_lift::AheadMap::default();
    let mut indirect = crate::range_lift::AheadMap::default();
    for (&entry, (p, i)) in entries.iter().zip(out) {
        pcode.insert((entry, pcode_budget), p);
        indirect.insert((entry, indirect_budget), i);
    }
    (pcode, got.is_some().then_some(indirect))
}

/// Per-function analysis output. Carries only what `apply` needs to
/// write back, so the parallel phase can be `Send`.
struct FunctionStackInfo {
    entry: u64,
    stack_alloc: i64,
    variables: Vec<(i64, u32)>,
}

fn analyse_function_stack(
    lifter: &dyn PcodeLift,
    program: &Program,
    entry: u64,
) -> FunctionStackInfo {
    let lifted = match lifter.lift_range(&program.info.memory, entry, STACK_LIFT_BUDGET) {
        Ok(l) => l,
        Err(_) => {
            return FunctionStackInfo {
                entry,
                stack_alloc: 0,
                variables: Vec::new(),
            };
        }
    };
    stack_info_lifted(entry, &lifted.iter().collect::<Vec<_>>())
}

/// Instructions lifted from a function's entry; the same lift as
/// Constant Propagation's.
const STACK_LIFT_BUDGET: usize = crate::propagation::LIFT_BUDGET;

/// [`analyse_function_stack`] on the instructions `lifted` from `entry`.
fn stack_info_lifted(entry: u64, lifted: &[&reargo_lift::LiftedInstruction]) -> FunctionStackInfo {
    let mut stack_alloc: i64 = 0;
    let mut uses_frame_pointer = false;
    let mut variables: Vec<(i64, u32)> = Vec::new();

    for insn in lifted {
        for op in &insn.ops {
            if op.opcode == OpCode::IntSub
                && let (Some(out), Some(inp0)) = (&op.output, op.inputs.first())
                && out.space == SpaceId::REGISTER
                && out.offset == RSP_OFFSET
                && inp0.space == SpaceId::REGISTER
                && inp0.offset == RSP_OFFSET
                && let Some(inp1) = op.inputs.get(1)
                && inp1.space == SpaceId::CONST
            {
                stack_alloc = inp1.offset as i64;
            }

            if op.opcode == OpCode::Copy
                && let (Some(out), Some(inp)) = (&op.output, op.inputs.first())
                && out.space == SpaceId::REGISTER
                && out.offset == RBP_OFFSET
                && inp.space == SpaceId::REGISTER
                && inp.offset == RSP_OFFSET
            {
                uses_frame_pointer = true;
            }

            if matches!(op.opcode, OpCode::Load | OpCode::Store) {
                for input in &op.inputs {
                    if input.space == SpaceId::UNIQUE {
                        collect_stack_variables(
                            &insn.ops,
                            input,
                            uses_frame_pointer,
                            stack_alloc,
                            &mut variables,
                        );
                    }
                }
            }
        }

        if insn.ops.iter().any(|op| op.opcode == OpCode::Return) {
            break;
        }
    }

    FunctionStackInfo {
        entry,
        stack_alloc,
        variables,
    }
}

fn collect_stack_variables(
    ops: &[reargo_core::pcode::PcodeOp],
    addr_vn: &reargo_core::pcode::VarnodeData,
    _uses_fp: bool,
    _stack_alloc: i64,
    variables: &mut Vec<(i64, u32)>,
) {
    for op in ops {
        if op.opcode == OpCode::IntAdd
            && let Some(out) = &op.output
            && out.space == addr_vn.space
            && out.offset == addr_vn.offset
        {
            let base = op.inputs.first();
            let disp = op.inputs.get(1);
            if let (Some(b), Some(d)) = (base, disp)
                && b.space == SpaceId::REGISTER
                && (b.offset == RSP_OFFSET || b.offset == RBP_OFFSET)
                && d.space == SpaceId::CONST
            {
                let offset = if b.offset == RBP_OFFSET {
                    -(d.offset as i64)
                } else {
                    d.offset as i64
                };
                variables.push((offset, 8));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What [`ahead_for_new`] computes for functions with no body is what
    /// P-code Reference and the Indirect Call Resolver compute themselves
    /// for them (`lift_range` of their budgets).
    #[test]
    fn new_function_results_match_the_analyzers_own() {
        let (code_addr, data_addr) = (0x1000u64, 0x8000u64);
        let got = data_addr + 0x10;
        let mut code = Vec::new();
        for k in 0..40u64 {
            let at = code_addr + code.len() as u64;
            let rel = |insn_end: u64, target: u64| ((target as i64 - insn_end as i64) as i32).to_le_bytes();
            // lea rax, [rip+data]; mov rcx, [rip+got]; call rcx;
            // mov [rip+data+8], eax; ret (a call or two left out)
            code.extend([0x48, 0x8d, 0x05]);
            code.extend(rel(at + 7, data_addr + k));
            code.extend([0x48, 0x8b, 0x0d]);
            code.extend(rel(at + 14, got));
            if k % 3 != 0 {
                code.extend([0xff, 0xd1]);
            }
            let here = code_addr + code.len() as u64;
            code.extend([0x89, 0x05]);
            code.extend(rel(here + 6, data_addr + 8));
            code.push(0xc3);
            while code.len() % 16 != 0 {
                code.push(0xcc);
            }
        }
        let mut program = crate::testutil::helpers::make_x86_64_program_with_data(&code, &[0u8; 0x100], code_addr, data_addr);
        program.info.imports.push(reargo_loader::ImportEntry { name: "puts".into(), plt_address: 0x500, got_address: got });
        let entries: Vec<u64> = (0..code.len() as u64).step_by(16).map(|o| code_addr + o).collect();
        let (pcode, indirect) = ahead_for_new(&program, &entries);
        let indirect = indirect.expect("the program imports something");

        let empty = Function::new(0, String::new());
        let (pb, ib) = (crate::pcoderef::budget(&empty), crate::indirect_resolve::budget(&empty));
        let sections = crate::pcoderef::SectionMap::from(&program);
        let jobs: Vec<(u64, usize)> = entries.iter().map(|&e| (e, pb)).collect();
        let own_pcode = crate::range_lift::map_lifted_ranges(&program.info.memory, &jobs, |_, insns| {
            crate::pcoderef::scan_lifted(insns, &sections)
        });
        let gm = crate::indirect_resolve::GotMap::new(&program).expect("an import");
        let plt_of_got = |g: u64| gm.plt_of_got(g);
        let scanner = reargo_lift::x86::X86Lifter::new_64();
        let jobs: Vec<(u64, usize)> = entries.iter().map(|&e| (e, ib)).collect();
        let own_indirect = crate::range_lift::map_lifted_ranges(&program.info.memory, &jobs, |_, insns| {
            crate::indirect_resolve::resolve_lifted(insns, &plt_of_got)
        });
        let mut seen = (0, 0);
        for (k, &entry) in entries.iter().enumerate() {
            assert_eq!(pcode[&(entry, pb)], own_pcode[k], "P-code at {entry:#x}");
            let has_call = scanner.range_has_indirect_call(&program.info.memory, entry, ib);
            let own = if has_call { own_indirect[k].clone() } else { Vec::new() };
            assert_eq!(indirect[&(entry, ib)], own, "indirect at {entry:#x}");
            seen.0 += own_pcode[k].len();
            seen.1 += usize::from(has_call);
        }
        // (references found; ranges with an indirect call, which this
        // code's register writes leave unresolved)
        assert!(seen.0 > 0 && seen.1 > 0, "{seen:?}");
    }
}
