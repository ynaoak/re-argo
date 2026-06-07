use gr_core::address::SpaceId;
use gr_core::pcode::OpCode;
use gr_lift::PcodeLift;
use gr_program::reference::{RefType, Reference};
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct ConstantPropagationAnalyzer;

impl Analyzer for ConstantPropagationAnalyzer {
    fn name(&self) -> &str {
        "Constant Propagation"
    }

    fn description(&self) -> &str {
        "Tracks constant values through instructions to resolve computed addresses"
    }

    fn priority(&self) -> u32 {
        400
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

        let valid_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.address != 0 && s.size > 0)
            .map(|s| (s.address, s.address + s.size))
            .collect();

        let func_entries: Vec<u64> = program
            .listing
            .functions()
            .map(|f| f.entry_point)
            .collect();

        // Phase 1: per-function constant tracking in parallel against
        // an immutable view of `program`. Each thread emits the
        // candidate (from, to) reference pairs it discovers.
        let per_func: Vec<Vec<(u64, u64)>> = func_entries
            .par_iter()
            .map(|&entry| analyse_function(lifter, program, entry, &valid_ranges))
            .collect();

        // Phase 2: merge discovered references / symbols into the
        // shared Program serially. Dedup against existing refs as
        // before so re-running the analyzer is idempotent.
        let mut refs_found = 0;
        for candidates in per_func {
            for (from, val) in candidates {
                if !program
                    .references
                    .get_refs_from(from)
                    .iter()
                    .any(|r| r.to == val)
                {
                    program.references.add(Reference::new(from, val, RefType::DataRead));
                    refs_found += 1;
                }
                if program.symbol_table.primary_at(val).is_none() {
                    program.symbol_table.add(Symbol::new(
                        format!("DAT_{:x}", val),
                        val,
                        SymbolType::Data,
                        SourceType::Analysis,
                    ));
                }
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: refs_found,
            instructions_decoded: 0,
        })
    }
}

/// Track register constants forward through `entry`'s lifted body and
/// return every (insn_addr, computed_pointer_value) pair where the
/// pointer falls inside a loaded section. Pure function-local work --
/// no `&mut Program` is touched here so the analyzer can map this
/// over `func_entries` in parallel.
fn analyse_function(
    lifter: &dyn PcodeLift,
    program: &Program,
    entry: u64,
    valid_ranges: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    let lifted = match lifter.lift_range(&program.info.memory, entry, 200) {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };

    let mut reg_values: std::collections::BTreeMap<u64, u64> =
        std::collections::BTreeMap::new();
    let mut found = Vec::new();

    for insn in &lifted {
        for op in &insn.ops {
            if op.opcode == OpCode::Copy
                && let (Some(out), Some(inp)) = (&op.output, op.inputs.first())
                && out.space == SpaceId::REGISTER
                && inp.space == SpaceId::CONST
            {
                reg_values.insert(out.offset, inp.offset);
            }

            if op.opcode == OpCode::IntAdd
                && let (Some(out), Some(a), Some(b)) =
                    (&op.output, op.inputs.first(), op.inputs.get(1))
                && out.space == SpaceId::REGISTER
            {
                let val_a = if a.space == SpaceId::CONST {
                    Some(a.offset)
                } else if a.space == SpaceId::REGISTER {
                    reg_values.get(&a.offset).copied()
                } else {
                    None
                };
                let val_b = if b.space == SpaceId::CONST {
                    Some(b.offset)
                } else if b.space == SpaceId::REGISTER {
                    reg_values.get(&b.offset).copied()
                } else {
                    None
                };
                if let (Some(va), Some(vb)) = (val_a, val_b) {
                    reg_values.insert(out.offset, va.wrapping_add(vb));
                }
            }

            if matches!(op.opcode, OpCode::Load | OpCode::Store) {
                for inp in &op.inputs {
                    if inp.space == SpaceId::REGISTER
                        && let Some(&val) = reg_values.get(&inp.offset)
                        && crate::utils::is_valid_address(val, valid_ranges)
                    {
                        found.push((insn.address, val));
                    }
                }
            }

            if matches!(
                op.opcode,
                OpCode::Call
                    | OpCode::CallInd
                    | OpCode::Store
                    | OpCode::Branch
                    | OpCode::CBranch
            ) && op.output.as_ref().is_some_and(|o| o.space == SpaceId::REGISTER)
                && let Some(out) = &op.output
            {
                reg_values.remove(&out.offset);
            }
        }

        if insn.ops.iter().any(|op| op.opcode == OpCode::Return) {
            break;
        }
    }

    found
}
