use gr_core::address::SpaceId;
use gr_core::pcode::OpCode;
use gr_lift::PcodeLift;
use gr_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

const RSP_OFFSET: u64 = 0x20;
const RBP_OFFSET: u64 = 0x28;

pub struct StackFrameAnalyzer;

impl Analyzer for StackFrameAnalyzer {
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
            gr_loader::Architecture::X86 | gr_loader::Architecture::X86_64
        ) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let lifter: Box<dyn PcodeLift> = if is_64 {
            Box::new(gr_lift::x86::X86Lifter::new_64())
        } else {
            Box::new(gr_lift::x86::X86Lifter::new_32())
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
        let updates: Vec<FunctionStackInfo> = func_entries
            .par_iter()
            .map(|&entry| analyse_function_stack(lifter, program, entry))
            .collect();

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
    let lifted = match lifter.lift_range(&program.info.memory, entry, 200) {
        Ok(l) => l,
        Err(_) => {
            return FunctionStackInfo {
                entry,
                stack_alloc: 0,
                variables: Vec::new(),
            };
        }
    };

    let mut stack_alloc: i64 = 0;
    let mut uses_frame_pointer = false;
    let mut variables: Vec<(i64, u32)> = Vec::new();

    for insn in &lifted {
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
    ops: &[gr_core::pcode::PcodeOp],
    addr_vn: &gr_core::pcode::VarnodeData,
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
