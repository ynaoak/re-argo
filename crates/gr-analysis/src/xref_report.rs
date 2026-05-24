use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct CrossReferenceReportAnalyzer;

impl Analyzer for CrossReferenceReportAnalyzer {
    fn name(&self) -> &str { "XRef Report" }
    fn description(&self) -> &str { "Generates cross-reference statistics and identifies hot addresses" }
    fn priority(&self) -> u32 { 950 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut max_refs_to = 0usize;
        let mut hot_addresses = 0;

        let all_targets: Vec<u64> = program.references.all_refs().map(|r| r.to).collect();
        let mut target_counts: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
        for addr in &all_targets {
            *target_counts.entry(*addr).or_default() += 1;
        }

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
        let mut unreferenced = 0;
        let entry = program.entry_point();

        for func in program.listing.functions() {
            if func.entry_point == entry {
                continue;
            }
            let refs_to = program.references.call_refs_to(func.entry_point);
            if refs_to.is_empty() {
                unreferenced += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: unreferenced,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}
