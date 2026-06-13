// Code coverage analysis.

use reargo_program::Program;
use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct CoverageAnalyzer;

impl Analyzer for CoverageAnalyzer {
    fn name(&self) -> &str { "Coverage" }
    fn description(&self) -> &str { "Computes analysis coverage statistics" }
    fn priority(&self) -> u32 { 999 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let total_code: u64 = program.info.sections.iter()
            .filter(|s| s.flags.contains(reargo_loader::SectionFlags::EXECUTE))
            .map(|s| s.size)
            .sum();

        let analyzed = program.listing.instruction_count() as u64;
        let coverage = if total_code > 0 { (analyzed as f64 / total_code as f64 * 100.0) as usize } else { 0 };

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: coverage,
            references_found: 0,
            instructions_decoded: analyzed as usize,
        })
    }
}
