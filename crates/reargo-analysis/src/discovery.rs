use std::collections::{BTreeSet, VecDeque};

use reargo_arch::FlowType;
use reargo_core::address::{Address, AddressRange, AddressSet, SpaceId};
use reargo_program::function::Function;
use reargo_program::reference::{RefType, Reference};
use reargo_program::symbol::SymbolType;
use reargo_program::Program;
use reargo_program::listing::Listing;
use rayon::prelude::*;
use reargo_arch::DecodedInstruction;
use rustc_hash::{FxHashMap, FxHashSet};
use reargo_loader::memory::MemoryFlags;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

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

        // With more than one thread, the code the walk will read is
        // decoded and walked ahead, in parallel ([`discover_parallel`]).
        // The result is the same either way.
        let (functions_found, references_found, instructions_decoded) = if rayon::current_num_threads() > 1 {
            discover_parallel(program, work_queue)
        } else {
            let mut found = Found::default();
            let counts = discover(program, work_queue, &mut Visited::default(), &mut found, |program, entry, visited, references| {
                disassemble_function(entry, visited, &mut Listed(program), references, None)
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
/// it found (an entry of one is visited), nor (in parallel) the listing.
#[derive(Default)]
struct Found {
    references: Vec<Reference>,
    bodies: Vec<(u64, Body)>,
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
                    bodies.into_par_iter().map(|(entry, body)| (entry, body.into_set())).collect();
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
    program: &mut Program,
    mut work_queue: VecDeque<u64>,
    visited: &mut Visited,
    found: &mut Found,
    mut walk: impl FnMut(&mut Program, u64, &mut Visited, &mut Vec<Reference>) -> Result<FunctionDiscovery, AnalysisError>,
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
        let needs_body = program
            .listing
            .get_function(func_entry)
            .is_some_and(|f| f.body.is_empty());
        if program.listing.has_function(func_entry) && !needs_body {
            continue;
        }

        let result = walk(program, func_entry, visited, &mut found.references);

        match result {
            Ok(discovery) => {
                instructions_decoded += discovery.instruction_count;
                references_found += discovery.reference_count;

                if needs_body {
                    if let Some(existing) = program.listing.get_function_mut(func_entry) {
                        existing.call_targets = discovery.call_targets.clone();
                        found.bodies.push((func_entry, discovery.body));
                    }
                } else {
                    let mut func =
                        if let Some(sym) = program.symbol_table.primary_at(func_entry) {
                            Function::new(func_entry, sym.name.clone())
                        } else {
                            Function::new(func_entry, format!("FUN_{:08x}", func_entry))
                        };
                    func.call_targets = discovery.call_targets.clone();
                    program.listing.add_function(func);
                    found.bodies.push((func_entry, discovery.body));
                    functions_found += 1;
                }

                for call_target in &discovery.call_targets {
                    if !visited.contains(*call_target)
                        && !program.listing.has_function(*call_target)
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

/// [`discover`], its work done ahead in parallel:
///
/// 1. [`speculate`] decodes the code reachable from each entry the walk
///    may take (the seeds, the calls, the functions jumped to).
/// 2. Each of those entries is walked alone, reading those decodes,
///    with nothing visited before it ([`Ahead`]).
/// 3. The serial walk, in its order: an entry walked ahead whose walk
///    passed no address the run visited before it (where the walk checks
///    for one) is walked the same now — its walk is taken as it is; any
///    other is walked again, reading the decodes ([`Replay`]).
///
/// Decoding is a pure function of the bytes and the address, and a walk
/// one of the run's addresses does not stop is the walk alone, so the
/// result is the serial one, whatever the threads did.
fn discover_parallel(program: &mut Program, work_queue: VecDeque<u64>) -> (usize, usize, usize) {
    let seeds: Vec<u64> = work_queue.iter().copied().collect();
    let mut specs = speculate(program, &seeds);
    // (the threads' memos of decodes: the walk decodes little more)
    rayon::broadcast(|_| reargo_arch::arm::release_thread_decodes());
    let by_entry: FxHashMap<u64, u32> = specs.iter().enumerate().map(|(i, s)| (s.entry, i as u32)).collect();
    let mut state = ReplayState::default();
    let ahead: Vec<Option<Ahead>> = {
        let program = &*program;
        let (specs, by_entry) = (&specs, &by_entry);
        specs
            .par_iter()
            .map(|spec| {
                thread_local! {
                    /// A thread's working sets, kept for its next walk.
                    static SCRATCH: std::cell::RefCell<(Visited, Vec<Reference>, Vec<u64>)> = Default::default();
                }
                let mut local = ReplayState::default();
                let (mut walk, mut walked) = SCRATCH.with_borrow_mut(|(visited, references, walked)| {
                    visited.clear();
                    references.clear();
                    walked.clear();
                    let walk = disassemble_function(
                        spec.entry,
                        visited,
                        &mut Replay { program, specs, by_entry, state: &mut local },
                        references,
                        Some(walked),
                    )
                    .ok()?;
                    Some((walk, walked.as_slice().to_vec()))
                })?;
                // (one that needed a decode not made ahead is walked again,
                // and one with an address [`START`] would mark)
                if !local.fresh.is_empty()
                    || matches!(&walk.body, Body::Ranges(r) if r.iter().any(|r| r.start.offset & START != 0))
                {
                    return None;
                }
                walk.body = Body::Set(std::mem::replace(&mut walk.body, Body::Set(AddressSet::new())).into_set());
                walked.shrink_to_fit();
                Some(Ahead { walk, walked })
            })
            .collect()
    };
    let mut ahead = ahead;
    // (sized for the walks ahead: one allocation)
    let mut found = Found {
        references: Vec::with_capacity(ahead.iter().flatten().map(|a| a.walk.reference_count).sum::<usize>() * 9 / 8),
        bodies: Vec::with_capacity(specs.len()),
    };
    let mut visited = Visited::default();
    let counts = discover(program, work_queue, &mut visited, &mut found, |program, entry, visited, references| {
        if let Some(a) = by_entry.get(&entry).and_then(|&i| ahead[i as usize].take())
            && !a.walked.iter().any(|&addr| addr & START == 0 && visited.contains(addr))
        {
            // (its references again, from the decodes: as many as its walk)
            let mut replay = Replay { program, specs: &specs, by_entry: &by_entry, state: &mut state };
            let mut hint = None;
            for &addr in &a.walked {
                let addr = addr & !START;
                visited.insert(addr);
                if let Some(insn) = replay.fetch(addr, &mut hint) {
                    push_references(addr, &insn, references);
                }
            }
            return Ok(a.walk);
        }
        disassemble_function(
            entry,
            visited,
            &mut Replay { program, specs: &specs, by_entry: &by_entry, state: &mut state },
            references,
            None,
        )
    });
    drop(ahead);
    // The instructions the walk read that were not listed, to list: the
    // ones decoded at the addresses it visited (it visits each one it
    // reads), else decoded during the walk.
    found.apply(program, |listing| {
        // (in address order, roughly: the specs by their first address)
        specs.sort_unstable_by_key(|spec| spec.insns.first().map_or(u64::MAX, |d| d.addr));
        let from_specs = specs.iter_mut().flat_map(|spec| {
            spec.insns.iter_mut().filter(|d| visited.contains(d.addr)).filter_map(|d| d.dec.take())
        });
        listing.add_unlisted_instructions(from_specs);
        let mut fresh: Vec<Box<DecodedInstruction>> = state.fresh.into_values().filter_map(|(_, d)| d).collect();
        fresh.sort_unstable_by_key(|d| d.address);
        listing.add_unlisted_instructions(fresh);
    });
    // (the speculated decodes not read, freed in parallel; then what the
    // threads freed, given back)
    specs.into_par_iter().for_each(drop);
    crate::release_free_memory();
    counts
}

/// An entry walked ahead, alone (see [`discover_parallel`]).
struct Ahead {
    walk: FunctionDiscovery,
    /// The addresses of the instructions walked ([`disassemble_function`]).
    walked: Vec<u64>,
}

/// The instruction addresses a discovery run visited: a bit per
/// address in pages of [`PAGE`] addresses. A run visits addresses
/// mostly in order, so this is much cheaper to probe than a hash set
/// of addresses.
#[derive(Default)]
struct Visited {
    pages: rustc_hash::FxHashMap<u64, Box<[u64; (PAGE / 64) as usize]>>,
    /// Pages [`Self::clear`] emptied, for the next ones.
    spare: Vec<Box<[u64; (PAGE / 64) as usize]>>,
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
        let spare = &mut self.spare;
        self.pages.entry(addr / PAGE).or_insert_with(|| spare.pop().unwrap_or_else(|| Box::new([0; (PAGE / 64) as usize])))
            [(bit / 64) as usize] |= 1 << (bit % 64);
    }

    /// Empty it (keeping its memory).
    fn clear(&mut self) {
        for (_, mut page) in self.pages.drain() {
            page.fill(0);
            self.spare.push(page);
        }
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
    type Hint: Copy + Default;
    /// The instruction at `addr` (`None`: there is none); `hint` is
    /// where the one before it on the walk was found, updated.
    fn fetch(&mut self, addr: u64, hint: &mut Self::Hint) -> Option<Facts>;
}

/// The program's listing: an instruction not listed is decoded and
/// listed.
struct Listed<'a>(&'a mut Program);

impl Source for Listed<'_> {
    type Hint = ();
    fn fetch(&mut self, addr: u64, _: &mut ()) -> Option<Facts> {
        // Decoding is a pure function of the bytes, and only this
        // pass lists instructions: one listed at `addr` is the one
        // decoding gives (a block starting inside code decoded
        // before, or a later run of the pass).
        let program = &mut *self.0;
        let (arch, memory) = (&program.arch, &program.info.memory);
        program
            .listing
            .instruction_or_insert_with(addr, || arch.decode_instruction(memory, addr).ok())
            .map(Facts::of)
    }
}

/// What a [`Replay`] keeps between walks.
#[derive(Default)]
struct ReplayState {
    /// The instructions none was speculated for: decoded here (with
    /// the decode when not listed).
    fresh: FxHashMap<u64, (Option<Facts>, Option<Box<DecodedInstruction>>)>,
}

/// The instructions [`speculate`] decoded (else the listing's, else a
/// decode): the walk's own decodes, made ahead. The ones read that were
/// not listed are listed after the walk.
struct Replay<'a> {
    program: &'a Program,
    specs: &'a [Spec],
    /// The index in `specs` of each entry's.
    by_entry: &'a FxHashMap<u64, u32>,
    state: &'a mut ReplayState,
}

impl Replay<'_> {
    /// The (spec, index) of the speculated instruction at `addr`, looked
    /// up next to `hint`, else in the spec of the function at `addr`.
    fn find(&self, addr: u64, hint: Option<(u32, u32)>) -> Option<(u32, u32)> {
        if let Some((s, i)) = hint {
            let insns = &self.specs[s as usize].insns;
            if insns.get(i as usize + 1).is_some_and(|d| d.addr == addr) {
                return Some((s, i + 1));
            }
            if let Ok(j) = insns.binary_search_by_key(&addr, |d| d.addr) {
                return Some((s, j as u32));
            }
        }
        let s = *self.by_entry.get(&addr)?;
        let j = self.specs[s as usize].insns.binary_search_by_key(&addr, |d| d.addr).ok()?;
        Some((s, j as u32))
    }
}

impl Source for Replay<'_> {
    type Hint = Option<(u32, u32)>;
    fn fetch(&mut self, addr: u64, hint: &mut Self::Hint) -> Option<Facts> {
        if let Some((s, i)) = self.find(addr, *hint) {
            *hint = Some((s, i));
            return Some(self.specs[s as usize].insns[i as usize].facts);
        }
        let program = self.program;
        let entry = self.state.fresh.entry(addr).or_insert_with(|| match program.listing.get_instruction(addr) {
            Some(insn) => (Some(Facts::of(insn)), None),
            None => match program.arch.decode_instruction(&program.info.memory, addr) {
                Ok(d) => (Some(Facts::of(&d)), Some(Box::new(d))),
                Err(_) => (None, None),
            },
        });
        entry.0
    }
}

/// An instruction [`speculate`] decoded.
struct SpecInsn {
    addr: u64,
    facts: Facts,
    /// The decode, when the listing has none at `addr`.
    dec: Option<Box<DecodedInstruction>>,
}

/// The code reachable from one entry, decoded ahead of the walk.
struct Spec {
    entry: u64,
    /// By address, one per address.
    insns: Vec<SpecInsn>,
}

/// Decode ahead, in parallel, the code the discovery walk from `seeds`
/// will read: for each entry, the instructions its flow reaches up to
/// the code of the functions listed now (which are entries of their
/// own), and, as entries of their own, the calls it makes and the
/// functions it jumps or runs into. The walk itself may read a bit more
/// or less (it stops where the run walked before, which depends on the
/// order); what is not here, it decodes itself.
fn speculate(program: &Program, seeds: &[u64]) -> Vec<Spec> {
    struct Ctx<'a> {
        program: &'a Program,
        /// The entries of the functions listed now.
        listed: FxHashSet<u64>,
        claims: Claims,
        specs: Mutex<Vec<Spec>>,
    }
    impl Ctx<'_> {
        /// The walk never enters a listed function with a body as one
        /// (only as another's code).
        fn has_body(&self, entry: u64) -> bool {
            self.listed.contains(&entry)
                && self.program.listing.get_function(entry).is_some_and(|f| !f.body.is_empty())
        }
    }
    fn task<'s>(s: &rayon::Scope<'s>, ctx: &'s Ctx<'s>, entry: u64) {
        let mut entries = Vec::new();
        let spec = speculate_one(ctx.program, &ctx.listed, &ctx.claims, entry, &mut entries);
        for (target, call) in entries {
            if (!call || !ctx.has_body(target)) && ctx.claims.claim(target) {
                s.spawn(move |s| task(s, ctx, target));
            }
        }
        if let Ok(mut specs) = ctx.specs.lock() {
            specs.push(spec);
        }
    }
    let listed = program.listing.functions().map(|f| f.entry_point).collect();
    let ctx = Ctx { program, listed, claims: Claims::new(program), specs: Mutex::new(Vec::new()) };
    let ctx = &ctx;
    let seeds: Vec<u64> = seeds.iter().copied().filter(|&e| !ctx.has_body(e) && ctx.claims.claim(e)).collect();
    rayon::scope(|s| {
        for entry in seeds {
            s.spawn(move |s| task(s, ctx, entry));
        }
    });
    std::mem::take(&mut *ctx.specs.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The entries [`speculate`] has taken (to decode from), shared by its
/// tasks: a bit per address of the executable code, else in a set.
struct Claims {
    base: u64,
    bits: Vec<AtomicU64>,
    others: Mutex<FxHashSet<u64>>,
}

impl Claims {
    fn new(program: &Program) -> Self {
        let exec = program.info.memory.blocks().filter(|b| b.flags.contains(MemoryFlags::EXECUTE));
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

/// The instructions reachable from `entry` (see [`speculate`]), not
/// entering the functions in `listed` nor the entries taken in `claims`
/// (another task decodes from those); the entries it reaches are added
/// to `entries` (with whether by a call).
fn speculate_one(
    program: &Program,
    listed: &FxHashSet<u64>,
    claims: &Claims,
    entry: u64,
    entries: &mut Vec<(u64, bool)>,
) -> Spec {
    thread_local! {
        /// A thread's working sets, kept for its next entry.
        static SCRATCH: std::cell::RefCell<(Vec<SpecInsn>, FxHashSet<u64>, Vec<u64>)> = Default::default();
    }
    SCRATCH.with_borrow_mut(|(insns, seen, queue)| {
        insns.clear();
        seen.clear();
        queue.clear();
        speculate_into(program, listed, claims, entry, entries, insns, seen, queue);
        insns.sort_unstable_by_key(|d| d.addr);
        Spec { entry, insns: insns.drain(..).collect() }
    })
}

/// [`speculate_one`] into the working sets `insns`, `seen` and `queue`.
#[allow(clippy::too_many_arguments)]
fn speculate_into(
    program: &Program,
    listed: &FxHashSet<u64>,
    claims: &Claims,
    entry: u64,
    entries: &mut Vec<(u64, bool)>,
    insns: &mut Vec<SpecInsn>,
    seen: &mut FxHashSet<u64>,
    queue: &mut Vec<u64>,
) {
    queue.push(entry);
    while let Some(start) = queue.pop() {
        let mut addr = start;
        for _ in 0..10_000 {
            if addr != entry && (claims.claimed(addr) || listed.contains(&addr)) {
                entries.push((addr, false));
                break;
            }
            if !seen.insert(addr) {
                break;
            }
            let (facts, dec) = match program.listing.get_instruction(addr) {
                Some(insn) => (Facts::of(insn), None),
                None => match program.arch.decode_instruction(&program.info.memory, addr) {
                    Ok(d) => (Facts::of(&d), Some(Box::new(d))),
                    Err(_) => break,
                },
            };
            insns.push(SpecInsn { addr, facts, dec });
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
}

/// A function's body: the ranges of the instructions walked (one per
/// instruction), or their set.
enum Body {
    Ranges(Vec<AddressRange>),
    Set(AddressSet),
}

impl Body {
    fn into_set(self) -> AddressSet {
        match self {
            // (re-walked block starts repeat)
            Body::Ranges(ranges) => ranges.into_iter().collect(),
            Body::Set(set) => set,
        }
    }
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

/// Marks the first instruction of a block in a walk's `walked` list (no
/// address has the top bit).
const START: u64 = 1 << 63;

struct FunctionDiscovery {
    body: Body,
    call_targets: BTreeSet<u64>,
    reference_count: usize,
    instruction_count: usize,
}

/// Walk the function at `entry`, reading instructions from `source`,
/// adding its references to `references` (and to `walked` the addresses
/// of the instructions walked, [`START`] marking a block's first: the
/// others are the ones checked were not visited); stops at code an
/// earlier walk of the run visited (`global_visited`).
fn disassemble_function<S: Source>(
    entry: u64,
    global_visited: &mut Visited,
    source: &mut S,
    references: &mut Vec<Reference>,
    mut walked: Option<&mut Vec<u64>>,
) -> Result<FunctionDiscovery, AnalysisError> {
    let mut block_queue: VecDeque<(u64, S::Hint)> = VecDeque::new();
    thread_local! {
        /// A thread's blocks visited, kept for its next walk.
        static BLOCKS: std::cell::RefCell<FxHashSet<u64>> = Default::default();
    }
    let mut block_visited: FxHashSet<u64> = BLOCKS.with_borrow_mut(std::mem::take);
    block_visited.clear();
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
            if let Some(walked) = walked.as_deref_mut() {
                walked.push(if addr == block_start { addr | START } else { addr });
            }

            let insn_addr = addr;
            let insn_len = u64::from(insn.length);
            let flow = insn.flow;
            let branch_target = insn.branch_target();

            global_visited.insert(insn_addr);
            body.push(AddressRange::new(
                Address::new(SpaceId::RAM, insn_addr),
                insn_len,
            ));
            instruction_count += 1;

            push_references(insn_addr, &insn, references);
            match flow {
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
                        block_queue.push_back((target, hint));
                    }
                    break;
                }
                FlowType::ConditionalJump => {
                    if let Some(target) = branch_target
                        && !block_visited.contains(&target)
                    {
                        block_queue.push_back((target, hint));
                    }
                    let fall_through = insn_addr + insn_len;
                    if !block_visited.contains(&fall_through) {
                        block_queue.push_back((fall_through, hint));
                    }
                    break;
                }
                FlowType::IndirectJump => {
                    break;
                }
                FlowType::Return => {
                    break;
                }
                FlowType::Fall => {
                    addr = insn_addr + insn_len;
                }
            }
        }
    }

    BLOCKS.with_borrow_mut(|b| *b = block_visited);

    #[allow(clippy::absurd_extreme_comparisons)]
    if instruction_count == 0 {
        return Err(AnalysisError::Disassembly(format!(
            "no instructions at 0x{:x}",
            entry
        )));
    }

    Ok(FunctionDiscovery {
        body: Body::Ranges(body),
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
