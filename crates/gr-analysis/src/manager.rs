use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::discovery::FunctionDiscoveryAnalyzer;
use crate::strings::StringSearchAnalyzer;

pub struct AnalysisManager {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl Default for AnalysisManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisManager {
    pub fn new() -> Self {
        let mut analyzers: Vec<Box<dyn Analyzer>> = vec![
            Box::new(FunctionDiscoveryAnalyzer),
            Box::new(StringSearchAnalyzer),
        ];
        analyzers.sort_by_key(|a| a.priority());
        Self { analyzers }
    }

    pub fn run_all(&self, program: &mut Program) -> Result<Vec<AnalysisResult>, AnalysisError> {
        let mut results = Vec::new();
        for analyzer in &self.analyzers {
            let result = analyzer.analyze(program)?;
            results.push(result);
        }
        Ok(results)
    }
}
