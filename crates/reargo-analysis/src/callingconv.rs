use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use reargo_lift::PcodeLift;
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct CallingConventionAnalyzer;

impl Analyzer for CallingConventionAnalyzer {
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

        let lifter: Box<dyn PcodeLift> = Box::new(reargo_lift::x86::X86Lifter::new_64());
        let lifter: &dyn PcodeLift = &*lifter;

        let func_entries: Vec<u64> = program.listing.functions().map(|f| f.entry_point).collect();

        // Phase 1: infer convention for each function in parallel
        // against an immutable Program view.
        let inferences: Vec<Option<(u64, &'static str)>> = func_entries
            .par_iter()
            .map(|&entry| infer_convention(lifter, program, entry))
            .collect();

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

/// Score `entry`'s body against Windows (RCX/RDX/R8/R9) vs System V
/// (RDI/RSI/RDX/RCX) argument register usage; return the winning
/// convention name, or `None` if neither set was touched. Pure
/// function-local work -- no `&mut Program` is held.
fn infer_convention(
    lifter: &dyn PcodeLift,
    program: &reargo_program::Program,
    entry: u64,
) -> Option<(u64, &'static str)> {
    let lifted = lifter.lift_range(&program.info.memory, entry, 50).ok()?;

    let win_regs = [0x08u64, 0x10, 0x80, 0x88]; // RCX, RDX, R8, R9
    let sysv_regs = [0x38u64, 0x30, 0x10, 0x08]; // RDI, RSI, RDX, RCX

    let mut win_score = 0;
    let mut sysv_score = 0;

    for insn in &lifted {
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
