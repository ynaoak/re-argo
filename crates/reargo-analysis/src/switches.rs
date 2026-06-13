use reargo_arch::FlowType;
use reargo_program::reference::{RefType, Reference};
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct SwitchTableAnalyzer;

impl Analyzer for SwitchTableAnalyzer {
    fn name(&self) -> &str {
        "Switch Table"
    }
    fn description(&self) -> &str {
        "Detects jump tables for switch statements and creates references"
    }
    fn priority(&self) -> u32 {
        550
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut refs_found = 0;
        let ptr_size = (program.info.bits / 8) as u64;

        let indirect_jumps: Vec<u64> = program
            .listing
            .instructions()
            .filter(|i| i.flow_type == FlowType::IndirectJump)
            .map(|i| i.address)
            .collect();

        let valid_code_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(reargo_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.address + s.size))
            .collect();

        let read_only_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(reargo_loader::SectionFlags::READ)
                && !s.flags.contains(reargo_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Phase 1: probe each indirect jump's putative table in
        // parallel against an immutable Program view (only memory
        // reads, no listing or reference mutation), producing
        // candidate (jmp_addr, target_addr) pairs. The previous loop
        // mutated `program.references` from inside the per-jump body
        // so it was serial; rayon now drives the memory-scan side
        // and the apply pass below stays sequential.
        let candidates: Vec<(u64, u64)> = indirect_jumps
            .par_iter()
            .flat_map_iter(|&jmp_addr| {
                // Locate the jump-table base: prefer a read-only section
                // that the jump's fall-through address lands in, else the
                // nearest read-only section starting after the jump.
                let insn_end = program
                    .listing
                    .instructions()
                    .find(|i| i.address == jmp_addr)
                    .map(|i| jmp_addr + i.bytes.len() as u64)
                    .unwrap_or(jmp_addr + 8);
                let table_base = if read_only_ranges
                    .iter()
                    .any(|&(s, e)| insn_end >= s && insn_end < e)
                {
                    insn_end
                } else {
                    read_only_ranges
                        .iter()
                        .filter(|&&(s, _)| s > jmp_addr)
                        .map(|&(s, _)| s)
                        .min()
                        .unwrap_or(insn_end)
                };
                let mut out: Vec<(u64, u64)> = Vec::new();
                for offset in 0..64u64 {
                    let table_entry = table_base.wrapping_add(offset * ptr_size);
                    let target = if ptr_size == 8 {
                        program.info.memory.read_u64(table_entry).ok()
                    } else {
                        program.info.memory.read_u32(table_entry).ok().map(|v| v as u64)
                    };
                    match target {
                        Some(target_addr) if crate::utils::is_valid_address(target_addr, &valid_code_ranges) => {
                            out.push((jmp_addr, target_addr));
                        }
                        _ => break,
                    }
                }
                out.into_iter()
            })
            .collect();

        for (jmp_addr, target_addr) in candidates {
            program.references.add(Reference::new(jmp_addr, target_addr, RefType::IndirectJump));
            refs_found += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: refs_found,
            instructions_decoded: 0,
        })
    }
}

pub struct TailCallAnalyzer;

impl Analyzer for TailCallAnalyzer {
    fn name(&self) -> &str {
        "Tail Call"
    }
    fn description(&self) -> &str {
        "Detects tail calls (unconditional jumps to other functions)"
    }
    fn priority(&self) -> u32 {
        560
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut tail_calls = 0;

        let jumps: Vec<(u64, Option<u64>)> = program
            .listing
            .instructions()
            .filter(|i| i.flow_type == FlowType::UnconditionalJump)
            .map(|i| (i.address, i.branch_target))
            .collect();

        // Phase 1: classify each jump in parallel against immutable
        // Program views (function_containing, has_function,
        // get_refs_from are all read-only). Each per-jump decision is
        // independent, so par_iter scales linearly with cores until
        // the apply step.
        let candidates: Vec<(u64, u64)> = jumps
            .par_iter()
            .filter_map(|(jmp_addr, target)| {
                let target_addr = (*target)?;
                let jmp_in_func = program.listing.function_containing(*jmp_addr);
                let target_is_func = program.listing.has_function(target_addr);
                let target_in_different_func = jmp_in_func
                    .map(|f| f.entry_point != target_addr)
                    .unwrap_or(true);
                if !(target_is_func && target_in_different_func) {
                    return None;
                }
                if program
                    .references
                    .get_refs_from(*jmp_addr)
                    .iter()
                    .any(|r| r.ref_type.is_call())
                {
                    return None;
                }
                Some((*jmp_addr, target_addr))
            })
            .collect();

        for (jmp_addr, target_addr) in candidates {
            program.references.add(Reference::new(jmp_addr, target_addr, RefType::UnconditionalCall));
            tail_calls += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: tail_calls,
            instructions_decoded: 0,
        })
    }
}
