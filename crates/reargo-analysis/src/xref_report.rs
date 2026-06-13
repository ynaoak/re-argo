use reargo_program::Program;
use rayon::prelude::*;
use rustc_hash::FxHashMap;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct CrossReferenceReportAnalyzer;

impl Analyzer for CrossReferenceReportAnalyzer {
    fn name(&self) -> &str { "XRef Report" }
    fn description(&self) -> &str { "Generates cross-reference statistics and identifies hot addresses" }
    fn priority(&self) -> u32 { 950 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        // Tally reference targets via FxHashMap rather than BTreeMap.
        // The keys are integer addresses with no need for ordered
        // iteration -- we only fold over `values()` to compute the
        // max and hot count -- so the BTreeMap's per-insert O(log N)
        // walk was pure overhead vs the FxHash table's amortised O(1)
        // insert.
        let mut target_counts: FxHashMap<u64, usize> =
            FxHashMap::with_capacity_and_hasher(1024, Default::default());
        for r in program.references.all_refs() {
            *target_counts.entry(r.to).or_default() += 1;
        }

        let mut max_refs_to = 0usize;
        let mut hot_addresses = 0;
        for &count in target_counts.values() {
            if count > max_refs_to {
                max_refs_to = count;
            }
            if count >= 5 {
                hot_addresses += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: hot_addresses,
            references_found: max_refs_to,
            instructions_decoded: 0,
        })
    }
}

pub struct UnreferencedFunctionAnalyzer;

impl Analyzer for UnreferencedFunctionAnalyzer {
    fn name(&self) -> &str { "Unreferenced Functions" }
    fn description(&self) -> &str { "Identifies functions with no incoming call references" }
    fn priority(&self) -> u32 { 960 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let entry = program.entry_point();
        let entries: Vec<u64> = program
            .listing
            .functions()
            .map(|f| f.entry_point)
            .collect();

        // Per-function `call_refs_to` lookup is read-only against an
        // immutable Program view and embarrassingly parallel; the
        // result is just a count so no apply phase is needed.
        let unreferenced: usize = entries
            .par_iter()
            .filter(|&&ep| ep != entry && program.references.call_refs_to(ep).is_empty())
            .count();

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: unreferenced,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}
