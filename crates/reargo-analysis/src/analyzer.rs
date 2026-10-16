use reargo_program::Program;

pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn priority(&self) -> u32;
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError>;

    /// Names of *capabilities* this analyzer produces (BN-style
    /// Activity outputs). Examples: `"functions"`, `"signatures"`,
    /// `"call_renderings"`. The pipeline can validate that every
    /// `consumes()` entry has a producer earlier in priority order.
    /// Default empty so existing analyzers don't need updating in
    /// one go; new analyzers should declare their outputs.
    fn provides(&self) -> &'static [&'static str] {
        &[]
    }

    /// Names of capabilities this analyzer depends on. See
    /// `provides()`. The pipeline reports a warning if a consumer
    /// runs before its producer, or if a consumer's producer is
    /// missing entirely.
    fn consumes(&self) -> &'static [&'static str] {
        &[]
    }

    /// Called for every analyzer before the pipeline runs any. An
    /// analyzer whose result depends only on what no analyzer changes
    /// (the loaded bytes and sections) may start computing it here on
    /// another thread ([`Early::start`]) and leave the handle in
    /// `program.analysis_cache`; its `analyze` then takes the result
    /// (computing it itself when nothing was started) and applies it
    /// at its place in the pipeline, as before. The work overlaps the
    /// analyzers that leave cores idle.
    fn start_early(&self, _program: &mut Program) {}
}

/// A result computed on another thread from inputs fixed for the run
/// (see [`Analyzer::start_early`]); `K` tells apart the results of
/// different analyzers in `Program::analysis_cache`.
pub struct Early<K, T> {
    handle: std::sync::Mutex<Option<std::thread::JoinHandle<T>>>,
    _kind: std::marker::PhantomData<fn() -> K>,
}

impl<K: 'static, T: Send + 'static> Early<K, T> {
    /// Start `compute` on a new thread and leave it in `program`'s
    /// analysis cache.
    pub fn start(program: &mut Program, compute: impl FnOnce() -> T + Send + 'static) {
        let handle = std::thread::Builder::new().name("early-analysis".into()).spawn(compute).ok();
        program
            .analysis_cache
            .insert(Early::<K, T> { handle: std::sync::Mutex::new(handle), _kind: std::marker::PhantomData });
    }

    /// The result started for `program`, if any (a computation that
    /// panicked gives `None`, as if none was started).
    pub fn take(program: &mut Program) -> Option<T> {
        let early = program.analysis_cache.take::<Early<K, T>>()?;
        let handle = early.handle.into_inner().ok()??;
        handle.join().ok()
    }
}

#[derive(Debug)]
pub struct AnalysisResult {
    pub analyzer_name: String,
    pub functions_found: usize,
    pub references_found: usize,
    pub instructions_decoded: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("disassembly error: {0}")]
    Disassembly(String),
    #[error("analysis error: {0}")]
    Other(String),
}
