use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::dataref::DataReferenceAnalyzer;
use crate::demangle::DemangleAnalyzer;
use crate::discovery::FunctionDiscoveryAnalyzer;
use crate::ehframe::EhFrameAnalyzer;
use crate::filler::FillerBytesAnalyzer;
use crate::propagation::ConstantPropagationAnalyzer;
use crate::references::{NoReturnAnalyzer, ScalarReferenceAnalyzer};
use crate::stack::StackFrameAnalyzer;
use crate::strings::StringSearchAnalyzer;
use crate::switches::{SwitchTableAnalyzer, TailCallAnalyzer};
use crate::patterns::{PatternFunctionAnalyzer, StructLayoutAnalyzer};
use crate::signatures::SignatureApplierAnalyzer;
use crate::thunk::{EntryPointAnalyzer, ThunkDetectorAnalyzer};
use crate::vtable::VTableAnalyzer;

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
            Box::new(EntryPointAnalyzer),
            Box::new(DemangleAnalyzer),
            Box::new(EhFrameAnalyzer),
            Box::new(FunctionDiscoveryAnalyzer),
            Box::new(FillerBytesAnalyzer),
            Box::new(StringSearchAnalyzer),
            Box::new(NoReturnAnalyzer),
            Box::new(ScalarReferenceAnalyzer),
            Box::new(ConstantPropagationAnalyzer),
            Box::new(StackFrameAnalyzer),
            Box::new(ThunkDetectorAnalyzer),
            Box::new(DataReferenceAnalyzer),
            Box::new(SwitchTableAnalyzer),
            Box::new(TailCallAnalyzer),
            Box::new(VTableAnalyzer),
            Box::new(PatternFunctionAnalyzer),
            Box::new(SignatureApplierAnalyzer),
            Box::new(StructLayoutAnalyzer),
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
