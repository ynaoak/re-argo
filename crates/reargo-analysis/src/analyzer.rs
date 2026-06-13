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
