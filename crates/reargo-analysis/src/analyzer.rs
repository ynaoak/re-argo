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

    /// The program state this analyzer may change (in `analyze` /
    /// `apply`). The default, everything, is always correct; a narrower
    /// set lets the pipeline prepare later analyzers before this one
    /// runs (see [`prepare_reads`](Self::prepare_reads)).
    fn writes(&self) -> State {
        State::ALL
    }

    /// For an analyzer split in two — a read-only [`prepare`]
    /// (Self::prepare) and an [`apply`](Self::apply) of its result —
    /// everything `prepare` reads of the program state (besides the
    /// loaded binary, which no analyzer changes). The pipeline may then
    /// run `prepare` earlier, at the same time as other analyzers'
    /// `prepare`, on the program as it is when no analyzer between
    /// there and this one has changed any of it (each declares what it
    /// changes with [`writes`](Self::writes)), and calls `apply` at the
    /// analyzer's own place. `None` (the default): not split.
    ///
    /// `prepare` cannot take an entry out of `program.analysis_cache`;
    /// it may look for one whose part of the state has a flag of its
    /// own ([`State::SHARED_LIFT`]), declared here and by the analyzers
    /// that store or take it.
    fn prepare_reads(&self) -> Option<State> {
        None
    }

    /// The read-only first part of a split analyzer (see
    /// [`prepare_reads`](Self::prepare_reads)).
    fn prepare(&self, _program: &Program) -> Prepared {
        unreachable!("{} is not split", self.name())
    }

    /// The second part of a split analyzer, given what its `prepare`
    /// returned. The default ignores it and runs `analyze`.
    fn apply(&self, program: &mut Program, _prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        self.analyze(program)
    }
}

/// What [`Analyzer::prepare`] hands to [`Analyzer::apply`].
pub type Prepared = Box<dyn std::any::Any + Send>;

/// The value of type `T` that a `prepare` returned.
pub(crate) fn prepared<T: 'static>(prepared: Prepared) -> T {
    *prepared.downcast::<T>().expect("the result of the analyzer's own prepare")
}

/// Parts of the program state, for what an analyzer reads
/// ([`Analyzer::prepare_reads`]) and writes ([`Analyzer::writes`]).
/// The loaded binary (`program.info`, `name`, `arch`) is not among
/// them: no analyzer changes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State(u32);

impl State {
    pub const NONE: State = State(0);
    /// The listing's instructions.
    pub const INSNS: State = State(1 << 0);
    /// The listing's set of functions and each function's entry, body
    /// and call targets.
    pub const FUNCS: State = State(1 << 1);
    /// Each function's `is_thunk` and `thunk_target`.
    pub const FUNC_THUNK: State = State(1 << 2);
    /// Each function's `name`.
    pub const FUNC_NAME: State = State(1 << 3);
    /// Each function's `calling_convention`.
    pub const FUNC_CC: State = State(1 << 4);
    /// Each function's `no_return`.
    pub const FUNC_NO_RETURN: State = State(1 << 5);
    /// The other function fields: `stack_frame`, `return_type`,
    /// `parameters`, `library`.
    pub const FUNC_OTHER: State = State(1 << 6);
    /// The symbol table, [`STRING_SYMBOLS`](Self::STRING_SYMBOLS)
    /// included.
    pub const SYMBOLS: State = State(1 << 7).union(Self::STRING_SYMBOLS);
    pub const REFERENCES: State = State(1 << 8);
    pub const COMMENTS: State = State(1 << 9);
    pub const TAGS: State = State(1 << 10);
    pub const METADATA: State = State(1 << 11);
    pub const CALL_RENDERINGS: State = State(1 << 12);
    pub const DATA_TYPES: State = State(1 << 13);
    /// `program.analysis_cache`: an analyzer that inserts or takes any
    /// entry writes it.
    pub const CACHE: State = State(1 << 14);
    /// The per-function call-site results stored in the analysis cache
    /// for the next analyzer that needs them
    /// ([`crate::shared_lift::store`]); an analyzer that stores or takes
    /// them writes it (besides [`CACHE`](Self::CACHE)). A `prepare`
    /// that looks for them reads it, so the pipeline never moves that
    /// `prepare` before an analyzer that stores or takes them.
    pub const SHARED_LIFT: State = State(1 << 15);
    /// The `s_<address>` data symbols the Call Site Annotator adds at
    /// the strings it read, each at an address that had no symbol (a
    /// part of [`SYMBOLS`](Self::SYMBOLS)). A reader that only looks
    /// for symbols by names of its own (none of the form `s_<hex>`), or
    /// by the first symbol of an address whose name it then matches so,
    /// does not read them: `SYMBOLS.difference(STRING_SYMBOLS)`.
    pub const STRING_SYMBOLS: State = State(1 << 16);
    /// The instructions and the functions' code: [`INSNS`](Self::INSNS),
    /// [`FUNCS`](Self::FUNCS) and [`FUNC_THUNK`](Self::FUNC_THUNK).
    pub const CODE: State = Self::INSNS.union(Self::FUNCS).union(Self::FUNC_THUNK);
    /// Every part of the functions: what adding or removing one
    /// changes (with [`FUNCS`](Self::FUNCS)).
    pub const FUNCTIONS: State = Self::FUNCS
        .union(Self::FUNC_THUNK)
        .union(Self::FUNC_NAME)
        .union(Self::FUNC_CC)
        .union(Self::FUNC_NO_RETURN)
        .union(Self::FUNC_OTHER);
    pub const ALL: State = State(u32::MAX);

    pub const fn union(self, other: State) -> State {
        State(self.0 | other.0)
    }

    /// The parts of `self` not in `other`.
    pub const fn difference(self, other: State) -> State {
        State(self.0 & !other.0)
    }

    pub const fn intersects(self, other: State) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for State {
    type Output = State;
    fn bitor(self, other: State) -> State {
        self.union(other)
    }
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
