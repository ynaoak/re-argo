use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::discovery::FunctionDiscoveryAnalyzer;
use crate::references::{NoReturnAnalyzer, ScalarReferenceAnalyzer};
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
            Box::new(NoReturnAnalyzer),
            Box::new(ScalarReferenceAnalyzer),
        ];
        analyzers.sort_by_key(|a| a.priority());
        Self { analyzers }
    }

    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        self.analyzers.push(analyzer);
        self.analyzers.sort_by_key(|a| a.priority());
    }

    pub fn run_all(&self, program: &mut Program) -> Vec<Result<AnalysisResult, AnalysisError>> {
        let mut results = Vec::new();
        for analyzer in &self.analyzers {
            results.push(analyzer.analyze(program));
        }
        results
    }

    pub fn run_all_or_fail(
        &self,
        program: &mut Program,
    ) -> Result<Vec<AnalysisResult>, AnalysisError> {
        self.run_all(program)
            .into_iter()
            .collect()
    }
}
