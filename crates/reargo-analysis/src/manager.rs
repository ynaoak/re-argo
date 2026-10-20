use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};
use crate::boundary::{FunctionBoundaryAnalyzer, VariadicFunctionAnalyzer};
use crate::callingconv::CallingConventionAnalyzer;
use crate::anti_debug::AntiDebugAnalyzer;
use crate::arity::ArgumentArityAnalyzer;
use crate::authenticode::AuthenticodeAnalyzer;
use crate::canary::StackCanaryAnalyzer;
use crate::complexity::ComplexityAnalyzer;
use crate::crt::CrtAnalyzer;
use crate::crt_patterns::CrtPatternAnalyzer;
use crate::crypto::CryptoConstantAnalyzer;
use crate::coverage::CoverageAnalyzer;
use crate::dataref::DataReferenceAnalyzer;
use crate::deadcode::DeadCodeAnalyzer;
use crate::float_const::FloatConstantAnalyzer;
use crate::magic_div::MagicDivisionAnalyzer;
use crate::dwarf_enrich::DwarfEnrichmentAnalyzer;
use crate::demangle::DemangleAnalyzer;
use crate::discovery::{FunctionDiscoveryAnalyzer, LateDiscoveryAnalyzer};
use crate::ehframe::EhFrameAnalyzer;
use crate::exception::ExceptionFlowAnalyzer;
use crate::filler::FillerBytesAnalyzer;
use crate::fingerprint::CompilerFingerprintAnalyzer;
use crate::floss_lite::FlossLiteAnalyzer;
use crate::format_varargs::FormatVarargsAnalyzer;
use crate::got_annotate::GotAnnotator;
use crate::hot::HotFunctionAnalyzer;
use crate::immstr::ImmediateStringAnnotator;
use crate::imphash::ImphashAnalyzer;
use crate::inline_mem::InlineMemAnalyzer;
use crate::loops::LoopAnalyzer;
use crate::macho_objc::MachoObjCAnalyzer;
use crate::macho_strings::MachoStringsAnalyzer;
use crate::pe_enrich::PeEnrichmentAnalyzer;
use crate::pe_seh::PeSehAnalyzer;
use crate::indirect::{IndirectCallAnalyzer, StringReferenceAnalyzer};
use crate::indirect_resolve::IndirectCallResolver;
use crate::ioc::IocExtractor;
use crate::propagation::ConstantPropagationAnalyzer;
use crate::rtti::RttiAnalyzer;
use crate::runtime_fp::RuntimeFingerprintAnalyzer;
use crate::scc::CallGraphSccAnalyzer;
use crate::references::{NoReturnAnalyzer, ScalarReferenceAnalyzer};
use crate::stack::StackFrameAnalyzer;
use crate::linear_sweep::LinearSweepAnalyzer;
use crate::stackstr::StackStringAnalyzer;
use crate::tagger::TagAnalyzer;
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
use crate::capa::CapaAnalyzer;
use crate::entropy::EntropyAnalyzer;
use crate::packer::PackerAnalyzer;
use crate::rich_header::RichHeaderAnalyzer;
use crate::section_anomaly::SectionAnomalyAnalyzer;
use crate::thunk::{EntryPointAnalyzer, ThunkDetectorAnalyzer};
use crate::tlsh::TlshAnalyzer;
use crate::vuln::VulnAnalyzer;
use crate::tls::TlsVariableAnalyzer;
use crate::typerecovery::{DataTypeAnalyzer, TypeRecoveryAnalyzer};
use crate::vtable::VTableAnalyzer;
use crate::wrapper::WrapperFunctionAnalyzer;
use crate::xref_report::{CrossReferenceReportAnalyzer, UnreferencedFunctionAnalyzer};

/// A run of consecutive analyzers (indices into the pipeline) and the
/// ones among them that prepare at its start, in order.
struct Window {
    analyzers: std::ops::Range<usize>,
    prepared: Vec<usize>,
}

pub struct AnalysisManager {
    analyzers: Vec<Box<dyn Analyzer>>,
    /// Whether the split analyzers prepare ahead, overlapped (the
    /// default); without, each runs alone at its place.
    overlap: bool,
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
            Box::new(RuntimeFingerprintAnalyzer),
            Box::new(PeSehAnalyzer),
            Box::new(PeEnrichmentAnalyzer),
            Box::new(MachoObjCAnalyzer),
            Box::new(MachoStringsAnalyzer),
            Box::new(DemangleAnalyzer),
            Box::new(EhFrameAnalyzer),
            Box::new(FunctionDiscoveryAnalyzer),
            Box::new(FillerBytesAnalyzer),
            Box::new(StringSearchAnalyzer),
            Box::new(FlossLiteAnalyzer),
            Box::new(NoReturnAnalyzer),
            Box::new(CryptoConstantAnalyzer),
            Box::new(EntropyAnalyzer),
            Box::new(SectionAnomalyAnalyzer),
            Box::new(RichHeaderAnalyzer),
            Box::new(ImphashAnalyzer),
            Box::new(TlshAnalyzer),
            Box::new(AuthenticodeAnalyzer),
            Box::new(PackerAnalyzer),
            Box::new(ScalarReferenceAnalyzer),
            Box::new(ConstantPropagationAnalyzer),
            Box::new(StackFrameAnalyzer),
            Box::new(StackStringAnalyzer),
            Box::new(ImmediateStringAnnotator),
            Box::new(InlineMemAnalyzer),
            Box::new(ThunkDetectorAnalyzer),
            Box::new(CrtPatternAnalyzer),
            Box::new(LinearSweepAnalyzer),
            Box::new(DataReferenceAnalyzer),
            Box::new(FloatConstantAnalyzer),
            Box::new(MagicDivisionAnalyzer),
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
            Box::new(DwarfEnrichmentAnalyzer),
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
            Box::new(HotFunctionAnalyzer),
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
            Box::new(IndirectCallResolver),
            Box::new(StringReferenceAnalyzer),
            Box::new(CoverageAnalyzer),
            Box::new(TypeRecoveryAnalyzer),
            Box::new(DataTypeAnalyzer),
            Box::new(VulnAnalyzer),
            Box::new(IocExtractor),
            Box::new(TagAnalyzer),
            Box::new(CapaAnalyzer),
        ];
        analyzers.sort_by_key(|a| a.priority());
        Self { analyzers, overlap: true }
    }

    /// The same pipeline with every analyzer run alone at its place,
    /// nothing overlapped: the result is the same, slower. For checking
    /// the overlap.
    pub fn without_overlap(mut self) -> Self {
        self.overlap = false;
        self
    }

    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        self.analyzers.push(analyzer);
        self.analyzers.sort_by_key(|a| a.priority());
    }

    pub fn run_all(&self, program: &mut Program) -> Vec<Result<AnalysisResult, AnalysisError>> {
        self.run_all_timed(program)
            .into_iter()
            .map(|(_, _, r)| r)
            .collect()
    }

    /// Like [`run_all`](Self::run_all), but also reports each analyzer's
    /// name and wall-clock time. One entry per analyzer, in run
    /// (priority) order. Drives the per-analyzer table in `bench`.
    pub fn run_all_timed(
        &self,
        program: &mut Program,
    ) -> Vec<(&str, std::time::Duration, Result<AnalysisResult, AnalysisError>)> {
        for analyzer in &self.analyzers {
            analyzer.start_early(program);
        }
        let mut results = Vec::with_capacity(self.analyzers.len());
        // each split analyzer's prepared result, from the run it
        // prepared in to its place
        let mut ready: Vec<Option<(Prepared, std::time::Duration)>> = self.analyzers.iter().map(|_| None).collect();
        for window in self.windows() {
            // The prepares run at the same time, on the program as it is
            // here; each one's result is the same as at its analyzer's
            // own place (nothing in between writes what it reads).
            if window.prepared.len() >= 2 {
                let shared = &*program;
                let mut slots: Vec<(usize, Option<(Prepared, std::time::Duration)>)> =
                    window.prepared.iter().map(|&i| (i, None)).collect();
                rayon::scope(|s| {
                    for (i, slot) in slots.iter_mut() {
                        let analyzer = &*self.analyzers[*i];
                        s.spawn(move |_| {
                            let t = std::time::Instant::now();
                            *slot = Some((analyzer.prepare(shared), t.elapsed()));
                        });
                    }
                });
                for (i, slot) in slots {
                    ready[i] = slot;
                }
            }
            for i in window.analyzers {
                let analyzer = &self.analyzers[i];
                let t = std::time::Instant::now();
                // a prepared analyzer counts its prepare's time too
                let (r, extra) = match ready[i].take() {
                    Some((p, d)) => (analyzer.apply(program, p), d),
                    None => (analyzer.analyze(program), std::time::Duration::ZERO),
                };
                results.push((analyzer.name(), t.elapsed() + extra, r));
            }
        }
        results
    }

    /// The pipeline cut into runs of consecutive analyzers, each with
    /// the split analyzers ([`Analyzer::prepare_reads`]) that prepare at
    /// its start. A split analyzer that an analyzer of the run before it
    /// writes any of the state it reads of starts the next run; each
    /// split analyzer then prepares at the start of the earliest run
    /// from which no analyzer up to its own place writes any of that
    /// state (so its prepares fill the cores another run's leave idle).
    fn windows(&self) -> Vec<Window> {
        let mut windows = Vec::new();
        let mut current = Window { analyzers: 0..0, prepared: Vec::new() };
        let mut written = State::NONE;
        let mut split = Vec::new();
        for (i, analyzer) in self.analyzers.iter().enumerate() {
            if let Some(reads) = analyzer.prepare_reads().filter(|_| self.overlap) {
                if reads.intersects(written) {
                    let next = Window { analyzers: i..i, prepared: Vec::new() };
                    windows.push(std::mem::replace(&mut current, next));
                    written = State::NONE;
                }
                split.push((i, reads));
            }
            current.analyzers.end = i + 1;
            written = written | analyzer.writes();
        }
        windows.push(current);
        let homes: Vec<bool> = windows.iter().map(|w| split.iter().any(|(i, _)| w.analyzers.contains(i))).collect();
        for (i, reads) in split {
            // the run it is in, then earlier ones while nothing from
            // their start up to it writes what it reads
            let mut w = windows.iter().rposition(|w| w.analyzers.start <= i).expect("a run holds it");
            let mut written = self.analyzers[windows[w].analyzers.start..i]
                .iter()
                .fold(State::NONE, |acc, a| acc | a.writes());
            while w > 0 {
                let before = self.analyzers[windows[w - 1].analyzers.clone()]
                    .iter()
                    .fold(State::NONE, |acc, a| acc | a.writes());
                if reads.intersects(written | before) {
                    break;
                }
                written = written | before;
                w -= 1;
            }
            // only into a run that prepares anyway
            let home = windows.iter().rposition(|x| x.analyzers.start <= i).unwrap();
            while w < home && !homes[w] {
                w += 1;
            }
            debug_assert!(!reads.intersects(written));
            windows[w].prepared.push(i);
        }
        windows
    }

    /// Walk the priority-sorted analyzer list and report any
    /// consumer that runs before its producer — a BN-style
    /// "workflow validation" pass. Returns `(consumer, dep,
    /// problem)` tuples where `problem` is either
    /// `"runs_before_producer"` or `"missing_producer"`. Used by
    /// the `workflow` CLI subcommand to catch pipeline ordering
    /// regressions before they manifest as silent analyzer no-ops.
    pub fn validate_workflow(&self) -> Vec<(String, String, &'static str)> {
        let mut warnings = Vec::new();
        let mut seen_providers: std::collections::BTreeMap<&'static str, u32> =
            std::collections::BTreeMap::new();
        for a in &self.analyzers {
            for cap in a.consumes() {
                match seen_providers.get(cap) {
                    Some(producer_prio) if *producer_prio <= a.priority() => {}
                    Some(_) => warnings.push((
                        a.name().to_string(),
                        (*cap).to_string(),
                        "runs_before_producer",
                    )),
                    None => warnings.push((
                        a.name().to_string(),
                        (*cap).to_string(),
                        "missing_producer",
                    )),
                }
            }
            for cap in a.provides() {
                seen_providers.entry(cap).or_insert(a.priority());
            }
        }
        warnings
    }

    /// Iterate (name, priority, provides, consumes) for every
    /// analyzer in priority order — drives the `workflow` CLI
    /// listing.
    pub fn workflow_listing(
        &self,
    ) -> impl Iterator<
        Item = (&str, u32, &'static [&'static str], &'static [&'static str]),
    > {
        self.analyzers
            .iter()
            .map(|a| (a.name(), a.priority(), a.provides(), a.consumes()))
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
