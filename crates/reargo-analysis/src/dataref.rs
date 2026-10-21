use reargo_program::reference::{RefType, Reference};
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

pub struct DataReferenceAnalyzer;

impl Analyzer for DataReferenceAnalyzer {
    fn name(&self) -> &str {
        "Data Reference"
    }

    fn description(&self) -> &str {
        "Creates data references from instruction operand patterns"
    }

    fn priority(&self) -> u32 {
        500
    }

    fn prepare_reads(&self) -> Option<State> {
        Some(State::INSNS)
    }
    fn writes(&self) -> State {
        State::REFERENCES
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    fn prepare(&self, program: &Program) -> Prepared {
        let valid_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.address != 0 && s.size > 0)
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Snapshot per-instruction bytes once so the scan can run
        // against an immutable view in parallel. Same pattern as
        // ScalarReferenceAnalyzer (round 2) and
        // StringReferenceAnalyzer (round 9): per-window pointer
        // detection is read-only and embarrassingly parallel.
        let instructions: Vec<(u64, &[u8])> = program
            .listing
            .instructions()
            .map(|i| (i.address, &i.bytes[..]))
            .collect();

        // no section below `lowest` or at / above `highest`: most
        // windows are rejected by these two compares
        let lowest = valid_ranges.iter().map(|r| r.0).min().unwrap_or(0);
        let highest = valid_ranges.iter().map(|r| r.1).max().unwrap_or(0);

        // Phase 1: scan windows in parallel, collect candidate refs.
        let candidates: Vec<(u64, u64)> = instructions
            .par_iter()
            .flat_map_iter(|(addr, bytes)| {
                let mut out: Vec<(u64, u64)> = Vec::new();
                if bytes.len() >= 4 {
                    for window in bytes.windows(4) {
                        let val =
                            u32::from_le_bytes([window[0], window[1], window[2], window[3]])
                                as u64;
                        if val >= lowest && val < highest && crate::utils::is_valid_address(val, &valid_ranges) {
                            out.push((*addr, val));
                        }
                    }
                }
                out.into_iter()
            })
            .collect();
        drop(instructions);

        Box::new(candidates)
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let candidates: Vec<(u64, u64)> = crate::analyzer::prepared(prepared);
        // Phase 2: each unless a reference from its source to its target is
        // there (in bulk).
        let candidates = candidates.into_iter().map(|(addr, val)| Reference::new(addr, val, RefType::DataRead)).collect();
        let refs_found = crate::references::add_unless_keyed(&mut program.references, candidates, |r| r.to);

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: refs_found,
            instructions_decoded: 0,
        })
    }
}
