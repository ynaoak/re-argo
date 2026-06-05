use gr_program::reference::{RefType, Reference};
use gr_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

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

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
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
        let instructions: Vec<(u64, Vec<u8>)> = program
            .listing
            .instructions()
            .map(|i| (i.address, i.bytes.to_vec()))
            .collect();

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
                        if is_valid_data_addr(val, &valid_ranges) {
                            out.push((*addr, val));
                        }
                    }
                }
                out.into_iter()
            })
            .collect();

        // Phase 2: apply serially, deduplicating against existing refs.
        let mut refs_found = 0;
        for (addr, val) in candidates {
            if program
                .references
                .get_refs_from(addr)
                .iter()
                .any(|r| r.to == val)
            {
                continue;
            }
            program
                .references
                .add(Reference::new(addr, val, RefType::DataRead));
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

fn is_valid_data_addr(val: u64, ranges: &[(u64, u64)]) -> bool {
    if val < 0x1000 {
        return false;
    }
    ranges.iter().any(|&(start, end)| val >= start && val < end)
}
