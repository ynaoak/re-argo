use std::collections::{BTreeSet, VecDeque};

use reargo_arch::FlowType;
use reargo_core::address::{Address, AddressRange, AddressSet, SpaceId};
use reargo_program::function::Function;
use reargo_program::reference::{RefType, Reference};
use reargo_program::symbol::SymbolType;
use reargo_program::Program;
use reargo_program::listing::Listing;
use reargo_program::symbol::SymbolTable;
use reargo_arch::Architecture;
use reargo_loader::memory::Memory;
use rayon::prelude::*;
use reargo_arch::DecodedInstruction;
use rustc_hash::{FxHashMap, FxHashSet};
use reargo_loader::memory::MemoryFlags;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct FunctionDiscoveryAnalyzer;

/// Re-run function discovery after late analyzers (CrtAnalyzer,
/// CrtPatternAnalyzer) have added new function entries with empty
/// bodies. The body-filling re-entry inside the primary Discovery
/// pass handles existing zero-body functions; we just need that
/// pass to run *after* the late renamers have populated them.
pub struct LateDiscoveryAnalyzer;

impl Analyzer for LateDiscoveryAnalyzer {
    fn name(&self) -> &str {
        "Late Discovery"
    }
    fn description(&self) -> &str {
        "Re-runs function discovery to fill bodies for late-added functions (main, CRT helpers)"
    }
    fn priority(&self) -> u32 {
        // After CrtPatternAnalyzer (470) + CrtAnalyzer (710), before
        // CallSiteAnnotator (750) so the resolved arg values it
        // produces benefit from the now-discovered call_targets.
        730
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        FunctionDiscoveryAnalyzer.analyze(program).map(|r| AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: r.functions_found,
            references_found: r.references_found,
            instructions_decoded: r.instructions_decoded,
        })
    }
}

impl Analyzer for FunctionDiscoveryAnalyzer {
    fn name(&self) -> &str {
        "Function Discovery"
    }

    fn description(&self) -> &str {
        "Recursive descent disassembly to discover functions and build cross-references"
    }

    fn priority(&self) -> u32 {
        100
    }
    fn provides(&self) -> &'static [&'static str] {
        &["functions"]
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut work_queue: VecDeque<u64> = VecDeque::new();
        work_queue.push_back(program.entry_point());

        for sym in program.symbol_table.function_symbols() {
            if sym.address != 0 && matches!(sym.symbol_type, SymbolType::Function) {
                work_queue.push_back(sym.address);
            }
        }

        // `.init_array` / `.fini_array` / `.preinit_array` (and the
        // legacy `.ctors` / `.dtors`) hold pointer arrays the loader
        // calls before / after `main`. Discovery doesn't follow
        // these by default — they're populated by the linker and
        // referenced only from `.dynamic`, never from code — so
        // stripped binaries end up with `frame_dummy` and
        // `__do_global_dtors_aux` invisible to every downstream
        // analyzer that walks the function list. Seeding them here
        // costs almost nothing and unlocks the CRT-pattern recogniser.
        let pointer_width = if program.info.bits == 64 { 8 } else { 4 };
        for sec_name in [".init_array", ".fini_array", ".preinit_array", ".ctors", ".dtors"] {
            let Some(section) = program.info.sections.iter().find(|s| s.name == sec_name) else {
                continue;
            };
            if section.size == 0 {
                continue;
            }
            let mut buf = vec![0u8; section.size.min(4096) as usize];
            if program.info.memory.read_bytes(section.address, &mut buf).is_err() {
                continue;
            }
            for chunk in buf.chunks_exact(pointer_width) {
                let ptr = if pointer_width == 8 {
                    u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]))
                } else {
                    u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as u64
                };
                if ptr == 0 || ptr == u64::MAX {
                    continue;
                }
                work_queue.push_back(ptr);
            }
        }

        // With more than one thread, the pool decodes ahead of the walk
        // what it will read, while it walks ([`discover_parallel`]). The
        // result is the same either way.
        let (functions_found, references_found, instructions_decoded) = if rayon::current_num_threads() > 1 {
            discover_parallel(program, work_queue)
        } else {
            let mut found = Found::default();
            let Program { arch, info, listing, symbol_table, .. } = &mut *program;
            let (arch, memory) = (&**arch, &info.memory);
            let counts = discover(listing, symbol_table, work_queue, &mut Visited::default(), &mut found, |listing, entry, visited, references| {
                disassemble_function(entry, visited, &mut Listed { arch, memory, listing }, references)
            });
            found.apply(program, |_| ());
            counts
        };

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found,
            references_found,
            instructions_decoded,
        })
    }
}

/// What a discovery run adds to the program after its walk, in bulk:
/// the walk reads neither the references nor the bodies of the functions
/// it found (an entry of one is visited).
#[derive(Default)]
struct Found {
    references: Vec<Reference>,
    /// The ranges of the instructions of each function walked (one per
    /// instruction: re-walked block starts repeat).
    bodies: Vec<(u64, Vec<AddressRange>)>,
}

impl Found {
    /// Add the references and bodies to the program, and list the
    /// instructions `list` lists.
    fn apply(self, program: &mut Program, list: impl FnOnce(&mut Listing) + Send) {
        let Found { references, bodies } = self;
        let (listing, refs) = (&mut program.listing, &mut program.references);
        rayon::join(
            || refs.add_all(&references),
            || {
                let bodies: Vec<(u64, AddressSet)> =
                    bodies.into_par_iter().map(|(entry, body)| (entry, body.into_iter().collect())).collect();
                for (entry, body) in bodies {
                    if let Some(f) = listing.get_function_mut(entry) {
                        f.body = body;
                    }
                }
                list(listing);
            },
        );
    }
}

/// The discovery walk from the entries `work_queue` (and the calls it
/// finds), each function walked by `walk`, its results gathered in
/// `found`. Returns the functions, references and instructions found.
fn discover(
    listing: &mut Listing,
    symbols: &SymbolTable,
    mut work_queue: VecDeque<u64>,
    visited: &mut Visited,
    found: &mut Found,
    mut walk: impl FnMut(&mut Listing, u64, &mut Visited, &mut Vec<Reference>) -> Result<FunctionDiscovery, AnalysisError>,
) -> (usize, usize, usize) {
    let mut functions_found = 0;
    let mut references_found = 0;
    let mut instructions_decoded = 0;

    const MAX_FUNCTIONS: usize = 50_000;
    const MAX_INSTRUCTIONS: usize = 5_000_000;

    while let Some(func_entry) = work_queue.pop_front() {
        if functions_found >= MAX_FUNCTIONS || instructions_decoded >= MAX_INSTRUCTIONS {
            break;
        }
        if visited.contains(func_entry) {
            continue;
        }
        // A pre-existing function with an empty body (added by
        // EhFrameAnalyzer, EntryPointAnalyzer, or by Symbols
        // pre-seeding) still needs its body discovered — without
        // it `function_containing` rejects every address inside
        // and every downstream analyzer (callsite resolver,
        // boundary checker, coverage…) treats those bytes as
        // un-owned. Re-run discovery, then merge results in.
        let needs_body = listing
            .get_function(func_entry)
            .is_some_and(|f| f.body.is_empty());
        if listing.has_function(func_entry) && !needs_body {
            continue;
        }

        let result = walk(listing, func_entry, visited, &mut found.references);

        match result {
            Ok(discovery) => {
                instructions_decoded += discovery.instruction_count;
                references_found += discovery.reference_count;

                if needs_body {
                    if let Some(existing) = listing.get_function_mut(func_entry) {
                        existing.call_targets = discovery.call_targets.clone();
                        found.bodies.push((func_entry, discovery.body));
                    }
                } else {
                    let mut func =
                        if let Some(sym) = symbols.primary_at(func_entry) {
                            Function::new(func_entry, sym.name.clone())
                        } else {
                            Function::new(func_entry, format!("FUN_{:08x}", func_entry))
                        };
                    func.call_targets = discovery.call_targets.clone();
                    listing.add_function(func);
                    found.bodies.push((func_entry, discovery.body));
                    functions_found += 1;
                }

                for call_target in &discovery.call_targets {
                    if !visited.contains(*call_target)
                        && !listing.has_function(*call_target)
                    {
                        work_queue.push_back(*call_target);
                    }
                }
            }
            Err(_) => continue,
        }
    }
    (functions_found, references_found, instructions_decoded)
}

/// [`discover`] while the pool decodes ahead: the pool's threads take
/// the entries the walk may reach (the seeds, the calls, the functions
/// jumped or run into) and decode the code each one reaches
/// ([`speculate_one`]); the walk, on this thread and in its own order,
/// reads an instruction from those decodes when one is there, else
/// decodes it itself — it never waits for the pool, which may be busy
/// with other work. Decoding is a pure function of the bytes and the
/// address, so the result is the serial one, whatever the threads did.
fn discover_parallel(program: &mut Program, work_queue: VecDeque<u64>) -> (usize, usize, usize) {
    let Program { arch, info, listing, symbol_table, .. } = &mut *program;
    let shared = Shared {
        arch: &**arch,
        memory: &info.memory,
        listed: listing.functions().map(|f| f.entry_point).collect(),
        has_body: listing.functions().filter(|f| !f.body.is_empty()).map(|f| f.entry_point).collect(),
        claims: Claims::new(&info.memory),
        stop: AtomicBool::new(false),
        done: RwLock::new(Done::default()),
    };
    let mut visited = Visited::default();
    let mut found = Found::default();
    let shared = &shared;
    let counts = rayon::in_place_scope(|s| {
        let seeds: Vec<u64> =
            work_queue.iter().copied().filter(|&e| !shared.has_body.contains(&e) && shared.claims.claim(e)).collect();
        // (one task for the seeds, splitting as the pool takes them)
        s.spawn(move |s| {
            for entry in seeds {
                s.spawn(move |s| speculate_task(s, shared, entry));
            }
        });
        let counts = discover(listing, symbol_table, work_queue, &mut visited, &mut found, |listing, entry, visited, references| {
            let mut source = Ahead { shared, listing };
            disassemble_function(entry, visited, &mut source, references)
        });
        shared.stop.store(true, Ordering::Relaxed);
        counts
    });
    let done = std::mem::take(&mut *shared.done.write().unwrap_or_else(|e| e.into_inner()));
    let visited = &visited;
    found.apply(program, |listing| {
        // The instructions the walk read from the pool's decodes, listed:
        // the ones at the addresses it visited (it visits each one it
        // reads) not listed (it listed its own decodes), in address order
        // roughly (the specs by their first address).
        // (nothing else holds them now; were one held, its decodes copied)
        let mut specs: Vec<Spec> = done
            .specs
            .into_iter()
            .map(|spec| {
                Arc::try_unwrap(spec).unwrap_or_else(|spec| Spec {
                    insns: spec
                        .insns
                        .iter()
                        .map(|d| SpecInsn { addr: d.addr, facts: d.facts, dec: d.dec.clone() })
                        .collect(),
                })
            })
            .collect();
        specs.sort_unstable_by_key(|spec| spec.insns.first().map_or(u64::MAX, |d| d.addr));
        let decodes = specs.iter_mut().flat_map(|spec| {
            spec.insns.iter_mut().filter(|d| visited.contains(d.addr)).filter_map(|d| d.dec.take())
        });
        listing.add_unlisted_instructions(decodes);
        // (the decodes not read, freed in parallel)
        specs.into_par_iter().for_each(drop);
    });
    // (then what the threads freed, given back)
    crate::release_free_memory();
    counts
}

/// What the walk and the pool share in [`discover_parallel`].
struct Shared<'a> {
    arch: &'a dyn Architecture,
    memory: &'a Memory,
    /// The entries of the functions listed when the run started.
    listed: FxHashSet<u64>,
    /// The ones of them with a body: the walk never enters one as a
    /// function (only as another's code).
    has_body: FxHashSet<u64>,
    claims: Claims,
    /// Set when the walk is done: what the pool has not decoded yet, it
    /// leaves.
    stop: AtomicBool,
    done: RwLock<Done>,
}

/// The code the pool decoded so far.
#[derive(Default)]
struct Done {
    specs: Vec<Arc<Spec>>,
    /// The index in `specs` of each entry's.
    by_entry: FxHashMap<u64, u32>,
}

/// Decode the code reachable from `entry` ([`speculate_one`]), make it
/// the walk's to read, and take the entries it reaches.
fn speculate_task<'s>(s: &rayon::Scope<'s>, shared: &'s Shared<'s>, entry: u64) {
    if shared.stop.load(Ordering::Relaxed) {
        return;
    }
    let mut entries = Vec::new();
    let spec = speculate_one(shared, entry, &mut entries);
    if let Ok(mut done) = shared.done.write() {
        let index = done.specs.len() as u32;
        done.by_entry.insert(entry, index);
        done.specs.push(Arc::new(spec));
    }
    for (target, call) in entries {
        if (!call || !shared.has_body.contains(&target)) && shared.claims.claim(target) {
            s.spawn(move |s| speculate_task(s, shared, target));
        }
    }
}

/// The instruction addresses a discovery run visited: a bit per
/// address in pages of [`PAGE`] addresses. A run visits addresses
/// mostly in order, so this is much cheaper to probe than a hash set
/// of addresses.
#[derive(Default)]
struct Visited {
    pages: rustc_hash::FxHashMap<u64, Box<[u64; (PAGE / 64) as usize]>>,
}

/// Addresses per page of [`Visited`].
const PAGE: u64 = 4096;

impl Visited {
    fn contains(&self, addr: u64) -> bool {
        let bit = addr % PAGE;
        self.pages.get(&(addr / PAGE)).is_some_and(|p| p[(bit / 64) as usize] & (1 << (bit % 64)) != 0)
    }

    fn insert(&mut self, addr: u64) {
        let bit = addr % PAGE;
        self.pages.entry(addr / PAGE).or_insert_with(|| Box::new([0; (PAGE / 64) as usize]))[(bit / 64) as usize] |=
            1 << (bit % 64);
    }
}

/// What the walk reads of an instruction.
#[derive(Clone, Copy)]
struct Facts {
    target: u64,
    length: u32,
    flow: FlowType,
    has_target: bool,
}

impl Facts {
    fn of(insn: &DecodedInstruction) -> Self {
        Self {
            target: insn.branch_target.unwrap_or(0),
            length: insn.length,
            flow: insn.flow_type,
            has_target: insn.branch_target.is_some(),
        }
    }

    fn branch_target(&self) -> Option<u64> {
        self.has_target.then_some(self.target)
    }
}

/// Where the walk reads instructions from.
trait Source {
    /// Where the source last found an instruction, to look near it.
    type Hint: Clone + Default;
    /// The instruction at `addr` (`None`: there is none); `hint` is
    /// where the one before it on the walk was found, updated.
    fn fetch(&mut self, addr: u64, hint: &mut Self::Hint) -> Option<Facts>;
}

/// The listing: an instruction not listed is decoded and listed.
struct Listed<'a> {
    arch: &'a dyn Architecture,
    memory: &'a Memory,
    listing: &'a mut Listing,
}

impl Source for Listed<'_> {
    type Hint = ();
    fn fetch(&mut self, addr: u64, _: &mut ()) -> Option<Facts> {
        // Decoding is a pure function of the bytes, and only this
        // pass lists instructions: one listed at `addr` is the one
        // decoding gives (a block starting inside code decoded
        // before, or a later run of the pass).
        let (arch, memory) = (self.arch, self.memory);
        self.listing.instruction_or_insert_with(addr, || arch.decode_instruction(memory, addr).ok()).map(Facts::of)
    }
}

/// The pool's decodes (else [`Listed`]): read near the one the walk read
/// before, else in the code decoded from the entry at the address.
struct Ahead<'a, 'l> {
    shared: &'a Shared<'a>,
    listing: &'l mut Listing,
}

impl Source for Ahead<'_, '_> {
    type Hint = Option<(Arc<Spec>, u32)>;
    fn fetch(&mut self, addr: u64, hint: &mut Self::Hint) -> Option<Facts> {
        if let Some((spec, i)) = hint {
            let insns = &spec.insns;
            let at = if insns.get(*i as usize + 1).is_some_and(|d| d.addr == addr) {
                Some(*i as usize + 1)
            } else {
                insns.binary_search_by_key(&addr, |d| d.addr).ok()
            };
            if let Some(at) = at {
                *i = at as u32;
                return Some(insns[at].facts);
            }
        }
        let spec = self.shared.done.read().ok().and_then(|done| Some(done.specs[*done.by_entry.get(&addr)? as usize].clone()));
        if let Some(spec) = spec
            && let Ok(at) = spec.insns.binary_search_by_key(&addr, |d| d.addr)
        {
            let facts = spec.insns[at].facts;
            *hint = Some((spec, at as u32));
            return Some(facts);
        }
        *hint = None;
        Listed { arch: self.shared.arch, memory: self.shared.memory, listing: self.listing }.fetch(addr, &mut ())
    }
}

/// An instruction [`speculate_one`] decoded.
struct SpecInsn {
    addr: u64,
    facts: Facts,
    /// The decode (taken when listed).
    dec: Option<Box<DecodedInstruction>>,
}

/// The code reachable from one entry, decoded ahead of the walk.
struct Spec {
    /// By address, one per address.
    insns: Vec<SpecInsn>,
}

/// The entries the pool has taken (to decode from), shared by its
/// tasks: a bit per address of the executable code, else in a set.
struct Claims {
    base: u64,
    bits: Vec<AtomicU64>,
    others: Mutex<FxHashSet<u64>>,
}

impl Claims {
    fn new(memory: &Memory) -> Self {
        let exec = memory.blocks().filter(|b| b.flags.contains(MemoryFlags::EXECUTE));
        let (lo, hi) = exec.fold((u64::MAX, 0), |(lo, hi), b| (lo.min(b.start), hi.max(b.start.saturating_add(b.size))));
        // (up to 64 MiB of code: 8 MiB of bits at most)
        let span = if lo < hi && hi - lo <= 1 << 26 { hi - lo } else { 0 };
        let bits = (0..span.div_ceil(64)).map(|_| AtomicU64::new(0)).collect();
        Self { base: lo, bits, others: Mutex::new(FxHashSet::default()) }
    }

    /// The word and bit of `addr` in `bits`.
    fn slot(&self, addr: u64) -> Option<(&AtomicU64, u64)> {
        let i = addr.checked_sub(self.base)?;
        Some((self.bits.get((i / 64) as usize)?, 1 << (i % 64)))
    }

    /// Take `addr`: whether it was not taken before.
    fn claim(&self, addr: u64) -> bool {
        match self.slot(addr) {
            Some((word, bit)) => word.fetch_or(bit, Ordering::Relaxed) & bit == 0,
            None => self.others.lock().is_ok_and(|mut c| c.insert(addr)),
        }
    }

    /// Whether `addr` is taken (outside the code: assumed not).
    fn claimed(&self, addr: u64) -> bool {
        self.slot(addr).is_some_and(|(word, bit)| word.load(Ordering::Relaxed) & bit != 0)
    }
}

/// The instructions the flow from `entry` reaches, not entering the
/// functions listed when the run started nor the entries the pool has
/// taken (another task decodes from those); the entries it reaches are
/// added to `entries` (with whether by a call). The walk reads about
/// these (it stops where the run walked before, which depends on the
/// order); what is not here, it decodes itself.
fn speculate_one(shared: &Shared, entry: u64, entries: &mut Vec<(u64, bool)>) -> Spec {
    thread_local! {
        /// A thread's working sets, kept for its next entry.
        static SCRATCH: std::cell::RefCell<(Vec<SpecInsn>, FxHashSet<u64>, Vec<u64>)> = Default::default();
    }
    SCRATCH.with_borrow_mut(|(insns, seen, queue)| {
        insns.clear();
        seen.clear();
        queue.clear();
        queue.push(entry);
        while let Some(start) = queue.pop() {
            let mut addr = start;
            for _ in 0..10_000 {
                if addr != entry && (shared.claims.claimed(addr) || shared.listed.contains(&addr)) {
                    entries.push((addr, false));
                    break;
                }
                if !seen.insert(addr) {
                    break;
                }
                let Ok(d) = shared.arch.decode_instruction(shared.memory, addr) else {
                    break;
                };
                let facts = Facts::of(&d);
                insns.push(SpecInsn { addr, facts, dec: Some(Box::new(d)) });
                let next = addr + u64::from(facts.length);
                match facts.flow {
                    FlowType::Call => {
                        if let Some(target) = facts.branch_target() {
                            entries.push((target, true));
                        }
                        addr = next;
                    }
                    FlowType::IndirectCall | FlowType::Fall => addr = next,
                    FlowType::UnconditionalJump => {
                        queue.extend(facts.branch_target());
                        break;
                    }
                    FlowType::ConditionalJump => {
                        queue.extend(facts.branch_target());
                        queue.push(next);
                        break;
                    }
                    FlowType::IndirectJump | FlowType::Return => break,
                }
            }
        }
        insns.sort_unstable_by_key(|d| d.addr);
        Spec { insns: insns.drain(..).collect() }
    })
}

struct FunctionDiscovery {
    /// The body's ranges, one per instruction walked.
    body: Vec<AddressRange>,
    call_targets: BTreeSet<u64>,
    reference_count: usize,
    instruction_count: usize,
}

/// The references of the instruction at `insn_addr` the walk adds.
fn push_references(insn_addr: u64, insn: &Facts, references: &mut Vec<Reference>) {
    let fall_through = insn_addr + u64::from(insn.length);
    match insn.flow {
        FlowType::Call => {
            if let Some(target) = insn.branch_target() {
                references.push(Reference::new(insn_addr, target, RefType::UnconditionalCall));
            }
            references.push(Reference::new(insn_addr, fall_through, RefType::FallThrough));
        }
        FlowType::IndirectCall => references.push(Reference::new(insn_addr, 0, RefType::IndirectCall)),
        FlowType::UnconditionalJump => {
            if let Some(target) = insn.branch_target() {
                references.push(Reference::new(insn_addr, target, RefType::UnconditionalJump));
            }
        }
        FlowType::ConditionalJump => {
            if let Some(target) = insn.branch_target() {
                references.push(Reference::new(insn_addr, target, RefType::ConditionalJump));
            }
            references.push(Reference::new(insn_addr, fall_through, RefType::FallThrough));
        }
        FlowType::IndirectJump => references.push(Reference::new(insn_addr, 0, RefType::IndirectJump)),
        FlowType::Return | FlowType::Fall => {}
    }
}

/// Walk the function at `entry`, reading instructions from `source`,
/// adding its references to `references`; stops at code an earlier walk
/// of the run visited (`global_visited`).
fn disassemble_function<S: Source>(
    entry: u64,
    global_visited: &mut Visited,
    source: &mut S,
    references: &mut Vec<Reference>,
) -> Result<FunctionDiscovery, AnalysisError> {
    let mut block_queue: VecDeque<(u64, S::Hint)> = VecDeque::new();
    let mut block_visited: FxHashSet<u64> = FxHashSet::default();
    let mut body: Vec<AddressRange> = Vec::new();
    let mut call_targets: BTreeSet<u64> = BTreeSet::new();
    let references_before = references.len();
    let mut instruction_count = 0;

    block_queue.push_back((entry, S::Hint::default()));

    while let Some((block_start, mut hint)) = block_queue.pop_front() {
        if block_visited.contains(&block_start) {
            continue;
        }
        block_visited.insert(block_start);

        let mut addr = block_start;
        let max_insns = 10_000;

        for _ in 0..max_insns {
            if global_visited.contains(addr) && addr != block_start {
                break;
            }

            let Some(insn) = source.fetch(addr, &mut hint) else {
                break;
            };

            let insn_addr = addr;
            let insn_len = u64::from(insn.length);
            let branch_target = insn.branch_target();

            global_visited.insert(insn_addr);
            body.push(AddressRange::new(
                Address::new(SpaceId::RAM, insn_addr),
                insn_len,
            ));
            instruction_count += 1;

            push_references(insn_addr, &insn, references);
            match insn.flow {
                FlowType::Call => {
                    if let Some(target) = branch_target {
                        call_targets.insert(target);
                    }
                    addr = insn_addr + insn_len;
                }
                FlowType::IndirectCall => {
                    addr = insn_addr + insn_len;
                }
                FlowType::UnconditionalJump => {
                    if let Some(target) = branch_target
                        && !block_visited.contains(&target)
                    {
                        block_queue.push_back((target, hint.clone()));
                    }
                    break;
                }
                FlowType::ConditionalJump => {
                    if let Some(target) = branch_target
                        && !block_visited.contains(&target)
                    {
                        block_queue.push_back((target, hint.clone()));
                    }
                    let fall_through = insn_addr + insn_len;
                    if !block_visited.contains(&fall_through) {
                        block_queue.push_back((fall_through, hint.clone()));
                    }
                    break;
                }
                FlowType::IndirectJump | FlowType::Return => {
                    break;
                }
                FlowType::Fall => {
                    addr = insn_addr + insn_len;
                }
            }
        }
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    if instruction_count == 0 {
        return Err(AnalysisError::Disassembly(format!(
            "no instructions at 0x{:x}",
            entry
        )));
    }

    Ok(FunctionDiscovery {
        body,
        call_targets,
        reference_count: references.len() - references_before,
        instruction_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::helpers::make_x86_64_program;

    #[test]
    fn discover_simple_function() {
        // push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let mut program = make_x86_64_program(&code, 0x1000);
        let analyzer = FunctionDiscoveryAnalyzer;
        let result = analyzer.analyze(&mut program).unwrap();
        assert!(result.functions_found >= 1);
        assert!(result.instructions_decoded >= 4);
        assert!(program.listing.has_function(0x1000));
    }

    #[test]
    fn discover_with_call() {
        // func1: call +5; ret
        // func2: xor eax,eax; ret
        let code = [
            0xe8, 0x01, 0x00, 0x00, 0x00, // call 0x1006
            0xc3,                           // ret
            0x31, 0xc0,                     // xor eax,eax
            0xc3,                           // ret
        ];
        let mut program = make_x86_64_program(&code, 0x1001);
        let analyzer = FunctionDiscoveryAnalyzer;
        let result = analyzer.analyze(&mut program).unwrap();
        assert!(result.functions_found >= 1);
        assert!(result.references_found > 0);
    }

    #[test]
    fn empty_program_no_crash() {
        let code = [0x00u8; 0]; // empty
        let mut program = make_x86_64_program(&code, 0x1000);
        let analyzer = FunctionDiscoveryAnalyzer;
        let _result = analyzer.analyze(&mut program);
    }
}
