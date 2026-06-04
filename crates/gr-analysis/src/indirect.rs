use gr_arch::FlowType;
use gr_program::reference::{RefType, Reference};
use gr_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct IndirectCallAnalyzer;

impl Analyzer for IndirectCallAnalyzer {
    fn name(&self) -> &str { "Indirect Call" }
    fn description(&self) -> &str { "Resolves indirect call targets from GOT/IAT entries" }
    fn priority(&self) -> u32 { 580 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let indirect_calls: Vec<u64> = program.listing.instructions()
            .filter(|i| i.flow_type == FlowType::IndirectCall)
            .map(|i| i.address)
            .collect();

        // Phase 1: per indirect-call site, find the first import
        // close enough to its address to plausibly be the target.
        // Pure immutable read against `program.info.imports` and
        // `program.references`, so the parallel scan runs without
        // contention.
        let candidates: Vec<(u64, u64)> = indirect_calls
            .par_iter()
            .filter_map(|&addr| {
                for import in &program.info.imports {
                    if program
                        .references
                        .get_refs_from(addr)
                        .iter()
                        .any(|r| r.to == import.plt_address)
                    {
                        continue;
                    }
                    let distance = import.got_address.abs_diff(addr);
                    if distance < 0x100000 {
                        return Some((addr, import.plt_address));
                    }
                }
                None
            })
            .collect();

        let mut resolved = 0;
        for (addr, plt) in candidates {
            program.references.add(Reference::new(addr, plt, RefType::IndirectCall));
            resolved += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: resolved,
            instructions_decoded: 0,
        })
    }
}

pub struct StringReferenceAnalyzer;

impl Analyzer for StringReferenceAnalyzer {
    fn name(&self) -> &str { "String Reference" }
    fn description(&self) -> &str { "Creates references from code to string data" }
    fn priority(&self) -> u32 { 590 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        use rustc_hash::FxHashMap;
        use rayon::prelude::*;

        // Index string addresses by their truncated u32 LE byte
        // pattern. The previous loop did O(N_insns * N_strings) per
        // run -- for a binary with 10k instructions and 1k strings
        // that's 10M nested-loop iterations even though each
        // instruction's bytes only contain a tiny constant set of
        // possible string addresses. Indexing them flips the inner
        // loop to a hash lookup, giving O(N_insns * insn_len) total.
        let string_addrs: Vec<u64> = program
            .symbol_table
            .iter()
            .filter(|s| s.name.starts_with("s_"))
            .map(|s| s.address)
            .collect();
        let by_low32: FxHashMap<[u8; 4], u64> = string_addrs
            .iter()
            .map(|&addr| ((addr as u32).to_le_bytes(), addr))
            .collect();

        // Snapshot per-instruction bytes once so the per-instruction
        // scan can run in parallel against an immutable view.
        // `Instruction::bytes` is a `SmallVec<[u8; 16]>` -- cheap to
        // clone when bytes fit inline.
        let insn_snapshot: Vec<(u64, smallvec::SmallVec<[u8; 16]>)> = program
            .listing
            .instructions()
            .map(|i| (i.address, i.bytes.clone()))
            .collect();

        // Phase 1: scan each instruction's bytes against the address
        // hash in parallel; report (insn_addr, string_addr) candidate
        // refs.
        let candidates: Vec<(u64, u64)> = insn_snapshot
            .par_iter()
            .flat_map_iter(|(insn_addr, bytes)| {
                let mut out: smallvec::SmallVec<[(u64, u64); 1]> = smallvec::SmallVec::new();
                if bytes.len() >= 4 {
                    for w in bytes.windows(4) {
                        let key = [w[0], w[1], w[2], w[3]];
                        if let Some(&str_addr) = by_low32.get(&key) {
                            out.push((*insn_addr, str_addr));
                        }
                    }
                }
                out.into_iter()
            })
            .collect();

        // Phase 2: apply serially -- dedup against existing refs and
        // add new ones.
        let mut refs_found = 0;
        for (insn_addr, str_addr) in candidates {
            if program.references.get_refs_from(insn_addr).iter().any(|r| r.to == str_addr) {
                continue;
            }
            program.references.add(Reference::new(insn_addr, str_addr, RefType::DataRead));
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
