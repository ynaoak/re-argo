use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::boundary::{FunctionBoundaryAnalyzer, VariadicFunctionAnalyzer};
use crate::callingconv::CallingConventionAnalyzer;
use crate::anti_debug::AntiDebugAnalyzer;
use crate::arity::ArgumentArityAnalyzer;
use crate::canary::StackCanaryAnalyzer;
use crate::complexity::ComplexityAnalyzer;
use crate::crt::CrtAnalyzer;
use crate::crt_patterns::CrtPatternAnalyzer;
use crate::crypto::CryptoConstantAnalyzer;
use crate::coverage::CoverageAnalyzer;
use crate::dataref::DataReferenceAnalyzer;
use crate::deadcode::DeadCodeAnalyzer;
use crate::demangle::DemangleAnalyzer;
use crate::discovery::{FunctionDiscoveryAnalyzer, LateDiscoveryAnalyzer};
use crate::ehframe::EhFrameAnalyzer;
use crate::exception::ExceptionFlowAnalyzer;
use crate::filler::FillerBytesAnalyzer;
use crate::fingerprint::CompilerFingerprintAnalyzer;
use crate::format_varargs::FormatVarargsAnalyzer;
use crate::got_annotate::GotAnnotator;
use crate::immstr::ImmediateStringAnnotator;
use crate::inline_mem::InlineMemAnalyzer;
use crate::loops::LoopAnalyzer;
use crate::indirect::{IndirectCallAnalyzer, StringReferenceAnalyzer};
use crate::propagation::ConstantPropagationAnalyzer;
use crate::rtti::RttiAnalyzer;
use crate::scc::CallGraphSccAnalyzer;
use crate::references::{NoReturnAnalyzer, ScalarReferenceAnalyzer};
use crate::stack::StackFrameAnalyzer;
use crate::stackstr::StackStringAnalyzer;
use crate::string_rename::StringHintRenameAnalyzer;
use crate::string_xref::StringXrefAnnotator;
use crate::strings::StringSearchAnalyzer;
use crate::switches::{SwitchTableAnalyzer, TailCallAnalyzer};
use crate::switches_v2::SwitchTableOffsetAnalyzer;
use crate::noreturn_prop::{DuplicateCodeAnalyzer, NoReturnPropagationAnalyzer};
use crate::panic_like::PanicLikeAnalyzer;
use crate::addrtable::AddressTableAnalyzer;
use crate::patterns::{PatternFunctionAnalyzer, StructLayoutAnalyzer};
use crate::pcoderef::PcodeReferenceAnalyzer;
use crate::signatures::SignatureApplierAnalyzer;
use crate::callsite_annotate::CallSiteAnnotator;
use crate::thunk::{EntryPointAnalyzer, ThunkDetectorAnalyzer};
use crate::tls::TlsVariableAnalyzer;
use crate::typerecovery::{DataTypeAnalyzer, TypeRecoveryAnalyzer};
use crate::vtable::VTableAnalyzer;
use crate::wrapper::WrapperFunctionAnalyzer;
use crate::xref_report::{CrossReferenceReportAnalyzer, UnreferencedFunctionAnalyzer};

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
            Box::new(CompilerFingerprintAnalyzer),
            Box::new(DemangleAnalyzer),
            Box::new(EhFrameAnalyzer),
            Box::new(FunctionDiscoveryAnalyzer),
            Box::new(FillerBytesAnalyzer),
            Box::new(StringSearchAnalyzer),
            Box::new(NoReturnAnalyzer),
            Box::new(CryptoConstantAnalyzer),
            Box::new(ScalarReferenceAnalyzer),
            Box::new(ConstantPropagationAnalyzer),
            Box::new(StackFrameAnalyzer),
            Box::new(StackStringAnalyzer),
            Box::new(ImmediateStringAnnotator),
            Box::new(InlineMemAnalyzer),
            Box::new(ThunkDetectorAnalyzer),
            Box::new(CrtPatternAnalyzer),
            Box::new(DataReferenceAnalyzer),
            Box::new(PcodeReferenceAnalyzer),
            Box::new(AddressTableAnalyzer),
            Box::new(SwitchTableAnalyzer),
            Box::new(SwitchTableOffsetAnalyzer),
            Box::new(TailCallAnalyzer),
            Box::new(VTableAnalyzer),
            Box::new(RttiAnalyzer),
            Box::new(PatternFunctionAnalyzer),
            Box::new(SignatureApplierAnalyzer),
            Box::new(CrtAnalyzer),
            Box::new(LateDiscoveryAnalyzer),
            Box::new(StringHintRenameAnalyzer),
            Box::new(StackCanaryAnalyzer),
            Box::new(TlsVariableAnalyzer),
            Box::new(CallSiteAnnotator),
            Box::new(StringXrefAnnotator),
            Box::new(GotAnnotator),
            Box::new(FormatVarargsAnalyzer),
            Box::new(LoopAnalyzer),
            Box::new(ExceptionFlowAnalyzer),
            Box::new(AntiDebugAnalyzer),
            Box::new(ArgumentArityAnalyzer),
            Box::new(WrapperFunctionAnalyzer),
            Box::new(ComplexityAnalyzer),
            Box::new(DeadCodeAnalyzer),
            Box::new(CallGraphSccAnalyzer),
            Box::new(StructLayoutAnalyzer),
            Box::new(NoReturnPropagationAnalyzer),
            Box::new(PanicLikeAnalyzer),
            Box::new(DuplicateCodeAnalyzer),
            Box::new(FunctionBoundaryAnalyzer),
            Box::new(VariadicFunctionAnalyzer),
            Box::new(CallingConventionAnalyzer),
            Box::new(CrossReferenceReportAnalyzer),
            Box::new(UnreferencedFunctionAnalyzer),
            Box::new(IndirectCallAnalyzer),
            Box::new(StringReferenceAnalyzer),
            Box::new(CoverageAnalyzer),
            Box::new(TypeRecoveryAnalyzer),
            Box::new(DataTypeAnalyzer),
        ];
        analyzers.sort_by_key(|a| a.priority());
        Self { analyzers }
    }

    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        self.analyzers.push(analyzer);
        self.analyzers.sort_by_key(|a| a.priority());
    }

    pub fn run_all(&self, program: &mut Program) -> Vec<Result<AnalysisResult, AnalysisError>> {
        let mut results = Vec::with_capacity(self.analyzers.len());
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
