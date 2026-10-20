use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, State};

pub struct CallingConventionAnalyzer;

impl Analyzer for CallingConventionAnalyzer {
    fn writes(&self) -> State {
        State::FUNC_CC.union(State::CACHE)
    }
    fn name(&self) -> &str {
        "Calling Convention"
    }
    fn description(&self) -> &str {
        "Infers calling conventions from register usage patterns"
    }
    fn priority(&self) -> u32 {
        770
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let func_entries: Vec<u64> = program.listing.functions().map(|f| f.entry_point).collect();

        // Phase 1: infer convention for each function in parallel
        // against an immutable Program view. The lifts of neighbouring functions overlap: share them
        // ([`crate::range_lift::map_lifted_ranges`] gives each exactly
        // `lift_range(entry, 50)`).
        // Those the Stack Frame analyzer computed ahead from the same lift
        // ([`Ahead`]) are taken as they are.
        let jobs: Vec<(u64, usize)> = func_entries.iter().map(|&e| (e, LIFT_BUDGET)).collect();
        let ahead = program.analysis_cache.take::<Ahead>().map(|a| a.0);
        let inferences: Vec<Option<(u64, &'static str)>> = crate::range_lift::with_ahead(&jobs, ahead, |missing| {
            crate::range_lift::map_lifted_ranges(&program.info.memory, missing, |entry, insns| convention_lifted(entry, insns))
        });

        // Phase 2: apply serially. Each entry targets a distinct
        // function so ordering doesn't matter.
        let mut inferred = 0;
        for opt in inferences {
            if let Some((entry, convention)) = opt
                && let Some(func) = program.listing.get_function_mut(entry)
            {
                func.calling_convention = Some(convention.into());
                inferred += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: inferred,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// Instructions lifted from a function's entry.
pub(crate) const LIFT_BUDGET: usize = 50;

/// [`convention_lifted`] of functions, computed ahead of this analyzer
/// from the same lift, by `(entry, LIFT_BUDGET)`.
pub(crate) struct Ahead(pub crate::range_lift::AheadMap<Option<(u64, &'static str)>>);

/// Score `entry`'s body against Windows (RCX/RDX/R8/R9) vs System V
/// (RDI/RSI/RDX/RCX) argument register usage; return the winning
/// convention name, or `None` if neither set was touched. Pure
/// function-local work on the instructions `lifted` from `entry`.
pub(crate) fn convention_lifted<L: std::borrow::Borrow<reargo_lift::LiftedInstruction>>(entry: u64, lifted: &[L]) -> Option<(u64, &'static str)> {
    let win_regs = [0x08u64, 0x10, 0x80, 0x88]; // RCX, RDX, R8, R9
    let sysv_regs = [0x38u64, 0x30, 0x10, 0x08]; // RDI, RSI, RDX, RCX

    let mut win_score = 0;
    let mut sysv_score = 0;

    for insn in lifted {
        let insn = insn.borrow();
        for op in &insn.ops {
            for inp in &op.inputs {
                if inp.space == SpaceId::REGISTER {
                    if win_regs.contains(&inp.offset) {
                        win_score += 1;
                    }
                    if sysv_regs.contains(&inp.offset) {
                        sysv_score += 1;
                    }
                }
            }
        }
        if insn.ops.iter().any(|op| op.opcode == OpCode::Return) {
            break;
        }
    }

    if win_score > 0 || sysv_score > 0 {
        let convention = if win_score > sysv_score { "__fastcall" } else { "__cdecl" };
        Some((entry, convention))
    } else {
        None
    }
}
