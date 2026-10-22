use std::collections::{BTreeSet, VecDeque};

use reargo_arch::FlowType;
use reargo_core::address::{Address, AddressRange, AddressSet, SpaceId};
use reargo_program::function::Function;
use reargo_program::reference::{RefType, Reference};
use reargo_program::symbol::SymbolType;
use reargo_program::Program;
use reargo_program::listing::{InstructionRun, Listing};
use reargo_program::symbol::SymbolTable;
use reargo_program::reference::ReferenceManager;
use reargo_arch::{Architecture, InstructionDecoder};
use reargo_loader::memory::Memory;

use reargo_arch::DecodedInstruction;
use rustc_hash::{FxHashMap, FxHashSet};
use reargo_loader::memory::MemoryFlags;
use std::sync::{Arc, Condvar, Mutex, RwLock};
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

        // With more than one thread, other threads decode ahead of the
        // walk what it will read, while it walks ([`discover_parallel`]).
        // The result is the same either way.
        let (functions_found, references_found, instructions_decoded) = if rayon::current_num_threads() > 1 {
            discover_parallel(program, work_queue)
        } else {
            let mut found = Found::default();
            let Program { arch, info, listing, symbol_table, .. } = &mut *program;
            let (arch, memory) = (&**arch, &info.memory);
            let Found { references, bodies } = &mut found;
            let mut decoder = arch.instruction_decoder(memory);
            let mut decodes = Decodes::new(memory);
            let mut scratch = WalkScratch::default();
            let counts = discover(
                listing,
                symbol_table,
                work_queue,
                &mut Visited::new(memory),
                references,
                |walked| bodies.push(walked),
                |listing, _, entry, visited, references| {
                    let source = &mut Listed { decoder: &mut *decoder, listing, decodes: &mut decodes };
                    disassemble_function(entry, visited, source, references, &mut scratch)
                },
            );
            drop(decoder);
            listing.add_unlisted_instructions(vec![vec![decodes.into_sorted()]]);
            found.apply(program);
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
    /// The instructions of each function walked, and the calls it makes
    /// ([`Walked`]).
    bodies: Vec<Walked>,
}

/// A function walked: its entry, the address and length of each
/// instruction walked (in the walk's order, one per instruction:
/// re-walked block starts repeat; [`body_set`] makes the body) and the
/// targets of its calls (ascending, once each). Set on the function
/// after the walk: nothing reads them during it.
type Walked = (u64, BodyInsns, Vec<u64>);

/// The body and call targets of a function walked ([`Walked`]).
fn walked_sets((entry, body, calls): Walked) -> (u64, AddressSet, BTreeSet<u64>) {
    // (ascending: a bulk build)
    (entry, body.into_set(), calls.into_iter().collect())
}

/// The address and length of each instruction a walk visited, in its
/// order, packed: the runs of chained instructions (each starting where
/// the one before ends, its length not 0) as their first address and the
/// lengths of theirs (a byte each; ~1 byte an instruction against 16, made
/// on the walk's thread — its fresh memory costs page faults — and read on
/// another), or, should a length not fit in a byte, one by one.
#[derive(Default)]
struct BodyInsns {
    /// Each run's first address and the index of its first length.
    runs: Vec<(u64, u32)>,
    lens: Vec<u8>,
    /// Instead, when a length did not fit: every instruction.
    wide: Option<Vec<(u64, u32)>>,
    /// Where the instruction last added ends (`None`: nothing chains to
    /// it).
    end: Option<u64>,
}

impl BodyInsns {
    #[inline(always)]
    fn push(&mut self, addr: u64, length: u32) {
        match u8::try_from(length) {
            Ok(len) if self.wide.is_none() => {
                if self.end != Some(addr) {
                    self.runs.push((addr, self.lens.len() as u32));
                }
                self.lens.push(len);
                self.end = if len > 0 { addr.checked_add(u64::from(len)) } else { None };
            }
            _ => self.push_wide(addr, length),
        }
    }

    /// [`Self::push`] of a length past a byte, or once one was.
    #[cold]
    #[inline(never)]
    fn push_wide(&mut self, addr: u64, length: u32) {
        let mut wide = match self.wide.take() {
            Some(wide) => wide,
            None => self.take_vec(),
        };
        wide.push((addr, length));
        self.wide = Some(wide);
    }

    /// The instructions of run `k`, in order.
    fn run(&self, k: usize) -> impl Iterator<Item = (u64, u32)> + '_ {
        let (first, start) = self.runs[k];
        let stop = self.runs.get(k + 1).map_or(self.lens.len(), |r| r.1 as usize);
        self.lens[start as usize..stop].iter().scan(first, |a, &len| {
            let at = *a;
            *a = a.wrapping_add(u64::from(len));
            Some((at, u32::from(len)))
        })
    }

    /// The instructions packed so far, one by one (emptied).
    fn take_vec(&mut self) -> Vec<(u64, u32)> {
        let mut out = Vec::with_capacity(self.lens.len());
        for k in 0..self.runs.len() {
            out.extend(self.run(k));
        }
        self.runs.clear();
        self.lens.clear();
        out
    }

    /// The instructions, one by one, in the walk's order.
    fn into_vec(mut self) -> Vec<(u64, u32)> {
        match self.wide.take() {
            Some(wide) => wide,
            None => self.take_vec(),
        }
    }

    /// [`body_set`] of the instructions, read from the runs as packed:
    /// they are the runs `body_set` finds (each instruction starting where
    /// the one before ends, its length not 0).
    fn into_set(self) -> AddressSet {
        if self.wide.is_some() {
            return body_set(self.into_vec());
        }
        let range = |(a, len): (u64, u32)| AddressRange::new(Address::new(SpaceId::RAM, a), u64::from(len));
        if self.runs.len() <= 1 {
            // (one run: ascending)
            return self.into_vec().into_iter().map(range).collect();
        }
        // (first address, length, run), as `body_set` orders them
        let mut runs: Vec<(u64, u32, u32)> = (0..self.runs.len())
            .map(|k| {
                let stop = self.runs.get(k + 1).map_or(self.lens.len() as u32, |r| r.1);
                (self.runs[k].0, stop - self.runs[k].1, k as u32)
            })
            .collect();
        runs.sort_unstable();
        let mut sorted: Vec<(u64, u32)> = Vec::with_capacity(self.lens.len());
        let merged = runs.iter().all(|&(first, _, k)| {
            let mut run = self.run(k as usize);
            match sorted.last() {
                Some(&last) if last.0 >= first => {
                    if last == (first, u32::from(self.lens[self.runs[k as usize].1 as usize])) {
                        run.next();
                        sorted.extend(run);
                        true
                    } else {
                        run.all(|r| sorted.binary_search_by_key(&r.0, |s| s.0).is_ok_and(|i| sorted[i] == r))
                    }
                }
                _ => {
                    sorted.extend(run);
                    true
                }
            }
        });
        if merged {
            return sorted.into_iter().map(range).collect();
        }
        body_set(self.into_vec())
    }
}

/// Set the bodies and call targets of the functions walked.
fn set_walked(listing: &mut Listing, walked: impl IntoIterator<Item = (u64, AddressSet, BTreeSet<u64>)>) {
    for (entry, body, calls) in walked {
        if let Some(f) = listing.get_function_mut(entry) {
            f.body = body;
            f.call_targets = calls;
        }
    }
}

impl Found {
    /// Add the references and bodies to the program.
    fn apply(self, program: &mut Program) {
        program.references.add_all(&self.references);
        set_walked(&mut program.listing, self.bodies.into_iter().map(walked_sets));
    }
}

/// The discovery walk from the entries `work_queue` (and the calls it
/// finds), each function walked by `walk` (adding its references to
/// `references`), the instructions and calls of each one given to
/// `body_found` (the body and call targets are set later). Returns the
/// functions, references and instructions found.
#[allow(clippy::too_many_arguments)]
fn discover(
    listing: &mut Listing,
    symbols: &SymbolTable,
    mut work_queue: VecDeque<u64>,
    visited: &mut Visited,
    references: &mut Vec<Reference>,
    mut body_found: impl FnMut(Walked),
    mut walk: impl FnMut(&mut Listing, &VecDeque<u64>, u64, &mut Visited, &mut Vec<Reference>) -> Result<FunctionDiscovery, AnalysisError>,
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

        let result = walk(listing, &work_queue, func_entry, visited, references);

        match result {
            Ok(discovery) => {
                instructions_decoded += discovery.instruction_count;
                references_found += discovery.reference_count;

                if !needs_body {
                    let func =
                        if let Some(sym) = symbols.primary_at(func_entry) {
                            Function::new(func_entry, sym.name.clone())
                        } else {
                            Function::new(func_entry, format!("FUN_{:08x}", func_entry))
                        };
                    listing.add_function(func);
                    functions_found += 1;
                }

                for &call_target in &discovery.call_targets {
                    if !visited.contains(call_target)
                        && !listing.has_function(call_target)
                    {
                        work_queue.push_back(call_target);
                    }
                }
                body_found((func_entry, discovery.body, discovery.call_targets));
            }
            Err(_) => continue,
        }
    }
    (functions_found, references_found, instructions_decoded)
}

/// The set of the ranges of a function's instructions walked (the address
/// and length of each, in the walk's order: ascending within each block,
/// block starts walked again repeated). As collecting them into the set
/// does, sorted and deduplicated, by address alone: they are all in one
/// space, and the instruction at an address has one length. The blocks'
/// runs are taken in order by their first address (shorter first), each
/// appended or — a block start walked again — found among those before;
/// anything else (a block run into the middle of an instruction) is
/// sorted.
fn body_set(body: Vec<(u64, u32)>) -> AddressSet {
    let range = |(a, len): (u64, u32)| AddressRange::new(Address::new(SpaceId::RAM, a), u64::from(len));
    // the runs of instructions each starting where the one before ends
    // (a block's): (first address, length, start)
    let mut runs: Vec<(u64, u32, u32)> = Vec::new();
    for (i, r) in body.iter().enumerate() {
        match runs.last_mut() {
            Some(run) if body[i - 1].1 > 0 && body[i - 1].0.checked_add(u64::from(body[i - 1].1)) == Some(r.0) => run.1 += 1,
            _ => runs.push((r.0, 1, i as u32)),
        }
    }
    if runs.len() <= 1 {
        // (one run: ascending)
        return body.into_iter().map(range).collect();
    }
    runs.sort_unstable();
    let mut sorted: Vec<(u64, u32)> = Vec::with_capacity(body.len());
    let merged = runs.iter().all(|&(_, len, start)| {
        let run = &body[start as usize..(start + len) as usize];
        match sorted.last() {
            Some(last) if last.0 >= run[0].0 => {
                if *last == run[0] {
                    sorted.extend_from_slice(&run[1..]);
                    true
                } else {
                    run.iter().all(|r| sorted.binary_search_by_key(&r.0, |s| s.0).is_ok_and(|k| sorted[k] == *r))
                }
            }
            _ => {
                sorted.extend_from_slice(run);
                true
            }
        }
    });
    if merged {
        return sorted.into_iter().map(range).collect();
    }
    let mut body = body;
    body.sort_by_key(|r| r.0);
    body.dedup();
    body.into_iter().map(range).collect()
}

/// [`discover`] while other threads decode ahead of it: once the walk
/// has read [`HELP_AFTER`] instructions (a shorter one is done before
/// they would help), they take the entries the walk may reach (the calls
/// found, the functions jumped or run into) and decode the code each one
/// reaches ([`speculate_one`]); the walk, on this thread and in its own
/// order, reads an instruction from those decodes when one is there, else
/// decodes it itself — it never waits for them. Decoding is a pure
/// function of the bytes and the address, so the result is the serial
/// one, whatever the threads did. From then on the references and the
/// bodies' sets are made on threads too, while the walk goes on. When the
/// walk starts from many entries ([`SEED_START`]: Late Discovery, which
/// fills the bodies of the functions added since the first run), the
/// threads start at once, taking those entries in the walk's order. The
/// walk marks each decode it reads; at the end the threads hand over
/// those, by address (sorted while they wait for the walk, once out of
/// entries), cut into parts of the code that are listed on threads of
/// their own.
fn discover_parallel(program: &mut Program, work_queue: VecDeque<u64>) -> (usize, usize, usize) {
    let Program { arch, info, listing, symbol_table, references: reference_manager, .. } = &mut *program;
    let (arch, memory) = (&**arch, &info.memory);
    // (threads of their own, not the rayon pool's: the pool may be busy
    // with other work — the analyzers started early — and a scope on it
    // would wait for that)
    let helpers = rayon::current_num_threads() - 1;
    let shared: std::sync::OnceLock<Shared> = std::sync::OnceLock::new();
    let shared = &shared;
    let mut reference_manager = Some(reference_manager);
    // Many entries to walk from (a later run of the pass, which fills the
    // bodies of the functions added since): the threads start at once,
    // taking them in the walk's order.
    let seeded = work_queue
        .iter()
        .filter(|&&e| !listing.get_function(e).is_some_and(|f| !f.body.is_empty()))
        .take(SEED_START)
        .count()
        >= SEED_START;
    let (counts, bodies) = std::thread::scope(|s| {
        // what the walk found that is not handed to a thread yet
        let mut references = Vec::new();
        let mut bodies: Vec<Walked> = Vec::new();
        // the entries the walk may reach, for the threads to start with
        let mut calls: Vec<u64> = Vec::new();
        let mut walked = 0;
        // once the threads are started: the ways to them
        // (shared by the two hooks below: a cell)
        let started: std::cell::RefCell<Option<Started>> = std::cell::RefCell::new(None);
        // (should the walk panic: the threads let go, not waited for forever)
        let _release = ReleaseOnDrop(shared);
        let mut walk_visited = Visited::new(memory);
        // (the walk's own decodes)
        let mut decoder = arch.instruction_decoder(memory);
        let mut decodes = Decodes::new(memory);
        let (mut ahead_scratch, mut listed_scratch) = (WalkScratch::default(), WalkScratch::default());
        // (the decodes the walk read of each thread's)
        let mut reads = Reads { by_owner: vec![Vec::new(); helpers] };
        let counts = discover(
            listing,
            symbol_table,
            work_queue,
            &mut walk_visited,
            &mut references,
            |walked| {
                bodies.push(walked);
                if let Some(started) = &*started.borrow()
                    && bodies.len() >= BODY_BATCH
                {
                    let _ = started.bodies.send(std::mem::take(&mut bodies));
                }
            },
            |listing, queue, entry, visited, references| {
                if started.borrow().is_none() && (walked >= HELP_AFTER || seeded) {
                    let shared = shared.get_or_init(|| {
                        let cuts = part_cuts(listing, memory, rayon::current_num_threads());
                        Shared {
                            arch,
                            memory,
                            listed: listing.functions().map(|f| f.entry_point).collect(),
                            has_body: listing.functions().filter(|f| !f.body.is_empty()).map(|f| f.entry_point).collect(),
                            claims: Claims::new(memory),
                            cuts: cuts.0,
                            fixed: cuts.1,
                            walking: Claims::new(memory),
                            stop: AtomicBool::new(false),
                            queue: Mutex::new(Queue::default()),
                            wake: Condvar::new(),
                            done: RwLock::new(Done::default()),
                        }
                    });
                    // (the entries the walk takes next, in its order, then the
                    // calls it found)
                    let entries: Vec<u64> = queue
                        .iter()
                        .copied()
                        .chain(calls.drain(..))
                        .filter(|&e| e != entry && !visited.contains(e) && !shared.has_body.contains(&e) && shared.claims.claim(e))
                        .collect();
                    shared.queue.lock().unwrap_or_else(|e| e.into_inner()).entries.extend(entries);
                    if let Some(reference_manager) = reference_manager.take() {
                        *started.borrow_mut() = Some(Started::start(s, shared, helpers, reference_manager));
                    }
                }
                let is_started = started.borrow().is_some();
                if let Some(started) = &*started.borrow()
                    && references.len() >= REFERENCE_BATCH
                {
                    let refill = started.emptied.try_recv().unwrap_or_default();
                    let _ = started.references.send(std::mem::replace(references, refill));
                }
                let result = match shared.get().filter(|_| is_started) {
                    Some(shared) => {
                        shared.walking.claim(entry);
                        let source = &mut Ahead { shared, reads: &mut reads, listing, decoder: &mut *decoder, decodes: &mut decodes };
                        disassemble_function(entry, visited, source, references, &mut ahead_scratch)
                    }
                    // (before the threads start there is nothing decoded ahead)
                    None => {
                        let source = &mut Listed { decoder: &mut *decoder, listing, decodes: &mut decodes };
                        disassemble_function(entry, visited, source, references, &mut listed_scratch)
                    }
                };
                if let Ok(d) = &result {
                    walked += d.instruction_count;
                    match shared.get().filter(|_| is_started) {
                        Some(shared) => {
                            // (the calls it makes: entries for the threads too)
                            let mut queue = shared.queue.lock().unwrap_or_else(|e| e.into_inner());
                            let before = queue.entries.len();
                            for &target in &d.call_targets {
                                if !shared.has_body.contains(&target) && shared.claims.claim(target) {
                                    queue.entries.push_back(target);
                                }
                            }
                            if queue.entries.len() > before {
                                drop(queue);
                                shared.wake.notify_one();
                            }
                        }
                        None => calls.extend(&d.call_targets),
                    }
                }
                result
            },
        );
        drop(walk_visited);
        drop(decoder);
        // (holding no decodes made ahead)
        drop((ahead_scratch, listed_scratch));
        let own = decodes.into_sorted();
        let Some(started) = started.into_inner() else {
            // (a short walk: all on this thread)
            listing.add_unlisted_instructions(vec![vec![own]]);
            if let Some(reference_manager) = reference_manager.take() {
                reference_manager.add_all_unpooled(&references);
            }
            let bodies = bodies.into_iter().map(walked_sets).collect();
            return (counts, bodies);
        };
        let _ = started.references.send(references);
        let _ = started.bodies.send(bodies);
        let Started { references, bodies, adding, sets, read, decoding, emptied } = started;
        drop((references, bodies, emptied));
        // The decoding threads: stopped, then (the walk holding none of
        // their code now) each gives the decodes the walk read, to list.
        if let Some(shared) = shared.get() {
            drop(std::mem::take(&mut *shared.done.write().unwrap_or_else(|e| e.into_inner())));
        }
        if let Some(shared) = shared.get() {
            shared.queue.lock().unwrap_or_else(|e| e.into_inner()).reads = std::mem::take(&mut reads.by_owner);
            shared.release();
        }
        // (by part of the code, then by thread: each in the order read)
        let mut decodes: Vec<Vec<InstructionRun>> = Vec::new();
        for parts in read.iter().take(decoding) {
            decodes.resize_with(decodes.len().max(parts.len()), Vec::new);
            for (k, run) in parts.into_iter().enumerate() {
                decodes[k].push(run);
            }
        }
        // (and the walk's own, cut the same way)
        let cuts = shared.get().map_or(&[][..], |shared| &shared.cuts[..]);
        decodes.resize_with(decodes.len().max(cuts.len() + 1), Vec::new);
        let mut rest = own;
        for (k, &cut) in cuts.iter().enumerate().rev() {
            let at = rest.partition_point(|d| d.0 < cut);
            decodes[k + 1].push(rest.split_off(at));
        }
        decodes[0].push(rest);
        // (the fine parts grouped into as many as threads, of about as
        // many instructions each)
        let (cuts, decodes) = match shared.get() {
            Some(shared) if !shared.fixed => group_parts(cuts, decodes, rayon::current_num_threads()),
            _ => (cuts.to_vec(), decodes),
        };
        listing.add_unlisted_instructions_cut(&cuts, decodes);
        let bodies = sets.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        if let Err(e) = adding.join() {
            std::panic::resume_unwind(e);
        }
        (counts, bodies)
    });
    set_walked(listing, bodies);
    counts
}

/// The threads [`discover_parallel`] started, and the ways to them.
struct Started<'scope> {
    references: std::sync::mpsc::Sender<Vec<Reference>>,
    /// The batches added, emptied, for the walk to fill again (their
    /// memory is in use already: no page faults).
    emptied: std::sync::mpsc::Receiver<Vec<Reference>>,
    bodies: std::sync::mpsc::Sender<Vec<Walked>>,
    adding: std::thread::ScopedJoinHandle<'scope, ()>,
    sets: std::thread::ScopedJoinHandle<'scope, Vec<(u64, AddressSet, BTreeSet<u64>)>>,
    /// What each decoding thread gives back: the decodes the walk read, in
    /// the order decoded, cut into parts at [`Shared::cuts`].
    read: std::sync::mpsc::Receiver<Vec<InstructionRun>>,
    decoding: usize,
}

impl<'scope> Started<'scope> {
    /// Start the threads: `helpers` decoding ahead (reading the walk's
    /// `visited` once it is done), one adding the references to
    /// `reference_manager`, one making the bodies' sets.
    fn start<'env>(
        s: &'scope std::thread::Scope<'scope, 'env>,
        shared: &'env Shared<'env>,
        helpers: usize,
        reference_manager: &'env mut ReferenceManager,
    ) -> Self {
        // (the references in the order found)
        let (references, references_in) = std::sync::mpsc::channel::<Vec<Reference>>();
        let (emptied_out, emptied) = std::sync::mpsc::channel::<Vec<Reference>>();
        let adding = s.spawn(move || {
            while let Ok(batch) = references_in.recv() {
                // (lagging behind the walk — its batches waiting —, this
                // thread adds them with this one in one bulk add, the two
                // maps at the same time: it caught up later, and at the
                // walk's end it could still be adding ~20 ms after the
                // listing was built)
                let mut waiting = vec![batch];
                while let Ok(more) = references_in.try_recv() {
                    waiting.push(more);
                }
                if waiting.len() >= JOIN_WAITING {
                    reference_manager.add_all_unpooled(&waiting.concat());
                } else {
                    for batch in &waiting {
                        reference_manager.add_all_unpooled(batch);
                    }
                }
                for mut batch in waiting {
                    batch.clear();
                    let _ = emptied_out.send(batch);
                }
            }
        });
        let (bodies, bodies_in) = std::sync::mpsc::channel::<Vec<Walked>>();
        let sets = s.spawn(move || {
            // (re-walked block starts repeat)
            bodies_in
                .into_iter()
                .flatten()
                .map(walked_sets)
                .collect::<Vec<_>>()
        });
        let (read_out, read) = std::sync::mpsc::channel();
        for id in 0..helpers {
            let read_out = read_out.clone();
            s.spawn(move || speculate_loop(shared, id, read_out));
        }
        Self { references, emptied, bodies, adding, sets, read, decoding: helpers }
    }
}

impl Shared<'_> {
    /// Stop the threads decoding ahead and have them give what the walk
    /// read.
    fn release(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).collect = true;
        self.wake.notify_all();
    }
}

/// [`Shared::release`] when dropped (once made).
struct ReleaseOnDrop<'a>(&'a std::sync::OnceLock<Shared<'a>>);

impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        if let Some(shared) = self.0.get() {
            shared.release();
        }
    }
}

/// The references the walk gathers before they are added, in
/// [`discover_parallel`].
const REFERENCE_BATCH: usize = 1 << 13;

/// The reference batches waiting (with the one taken) from which the
/// thread adding them adds them together ([`discover_parallel`]): the
/// same lists in the same order either way.
const JOIN_WAITING: usize = 3;

/// The bodies the walk gathers before their sets are made, in
/// [`discover_parallel`].
const BODY_BATCH: usize = 256;

/// The instructions the walk reads before threads start decoding ahead
/// of it ([`discover_parallel`]).
const HELP_AFTER: usize = 1 << 16;

/// The entries to walk from (functions not listed or without a body) from
/// which the threads start decoding ahead at once ([`discover_parallel`]).
const SEED_START: usize = 512;

/// What the walk and the threads decoding ahead share in
/// [`discover_parallel`].
struct Shared<'a> {
    arch: &'a dyn Architecture,
    memory: &'a Memory,
    /// The entries of the functions listed when the threads started.
    listed: FxHashSet<u64>,
    /// The ones of them with a body: the walk never enters one as a
    /// function (only as another's code).
    has_body: FxHashSet<u64>,
    claims: Claims,
    /// Where the decodes handed over are cut into parts, listed on
    /// threads of their own ([`Listing::add_unlisted_instructions_cut`]):
    /// ascending addresses ([`part_cuts`]).
    cuts: Vec<u64>,
    /// Whether `cuts` are the listing's parts (else finer ones, grouped by
    /// their counts, [`group_parts`]).
    fixed: bool,
    /// The entries the walk has started on (its own decodes): left to it.
    walking: Claims,
    /// Set when the walk is done: what the threads have not decoded yet,
    /// they leave.
    stop: AtomicBool,
    /// The entries taken, not decoded yet.
    queue: Mutex<Queue>,
    /// Signalled when `queue` gains entries, or its last busy thread is
    /// done, or `stop` is set.
    wake: Condvar,
    done: RwLock<Done>,
}

/// [`Shared::queue`].
#[derive(Default)]
struct Queue {
    entries: VecDeque<u64>,
    /// The threads decoding from an entry (they may add more).
    busy: usize,
    /// Set when the walk is done and holds none of the code decoded.
    collect: bool,
    /// Then: what the walk read of each thread's decodes ([`Reads`]).
    reads: Vec<Vec<(u32, u32, u32)>>,
}

/// The code decoded ahead so far.
#[derive(Default)]
struct Done {
    specs: Vec<Arc<Spec>>,
    /// The index in `specs` of each entry's.
    by_entry: FxHashMap<u64, u32>,
}

/// A thread decoding ahead of the walk: take an entry, decode the code
/// reachable from it ([`speculate_one`]), make it the walk's to read,
/// take the entries it reaches; until the walk is done or there is
/// nothing left.
fn speculate_loop(
    shared: &Shared,
    id: usize,
    read_out: std::sync::mpsc::Sender<Vec<InstructionRun>>,
) {
    let mut entries = Vec::new();
    let mut decoder = shared.arch.instruction_decoder(shared.memory);
    // the code this thread decoded
    let mut own: Vec<Arc<Spec>> = Vec::new();
    'work: loop {
        let entry = {
            let mut queue = shared.queue.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if shared.stop.load(Ordering::Relaxed) {
                    break 'work;
                }
                if let Some(entry) = queue.entries.pop_front() {
                    if shared.walking.claimed(entry) {
                        continue;
                    }
                    queue.busy += 1;
                    break entry;
                }
                if queue.busy == 0 {
                    break 'work;
                }
                queue = shared.wake.wait(queue).unwrap_or_else(|e| e.into_inner());
            }
        };
        entries.clear();
        let mut spec = speculate_one(shared, &mut *decoder, entry, &mut entries);
        (spec.owner, spec.index) = (id as u32, own.len() as u32);
        let spec = Arc::new(spec);
        if let Ok(mut done) = shared.done.write() {
            let index = done.specs.len() as u32;
            done.by_entry.insert(entry, index);
            done.specs.push(spec.clone());
        }
        own.push(spec);
        let mut queue = shared.queue.lock().unwrap_or_else(|e| e.into_inner());
        for &(target, call) in &entries {
            if (!call || !shared.has_body.contains(&target)) && shared.claims.claim(target) {
                queue.entries.push_back(target);
            }
        }
        queue.busy -= 1;
        drop(queue);
        shared.wake.notify_all();
    }
    // Once the walk is done and holds none of the code decoded: the
    // decodes it read, for the listing; the others freed here, and what
    // this thread freed given back.
    let reads = {
        let mut queue = shared.queue.lock().unwrap_or_else(|e| e.into_inner());
        while !queue.collect {
            queue = shared.wake.wait(queue).unwrap_or_else(|e| e.into_inner());
        }
        queue.reads.get_mut(id).map(std::mem::take).unwrap_or_default()
    };
    // (were one still held: its decodes copied)
    let mut specs: Vec<Result<Spec, Arc<Spec>>> = own.into_iter().map(Arc::try_unwrap).collect();
    // (in the order read, cut into the parts at `shared.cuts`: the
    // listing puts them in order, part by part; a run ascends)
    let cuts = &shared.cuts[..];
    let mut parts: Vec<InstructionRun> = vec![Vec::new(); cuts.len() + 1];
    let mut k = 0;
    for (code, first, n) in reads {
        for at in first as usize..(first + n) as usize {
            let d = match &mut specs[code as usize] {
                Ok(spec) => {
                    let d = &mut spec.insns[at];
                    d.dec.take().map(|dec| (d.addr, dec))
                }
                Err(spec) => {
                    let d = &spec.insns[at];
                    d.dec.clone().map(|dec| (d.addr, dec))
                }
            };
            if let Some(d) = d {
                if (k > 0 && d.0 < cuts[k - 1]) || cuts.get(k).is_some_and(|&c| d.0 >= c) {
                    k = cuts.partition_point(|&c| c <= d.0);
                }
                parts[k].push(d);
            }
        }
    }
    let _ = read_out.send(parts);
    // (while the walk lists them)
    drop(specs);
    crate::release_free_memory();
}

/// The instruction addresses a discovery run visited: a bit per
/// address in pages of [`PAGE`] addresses, found by their index over the
/// executable code (else in a map). A run visits addresses mostly in
/// order, so this is much cheaper to probe than a hash set of addresses.
struct Visited {
    base: u64,
    pages: Vec<Option<VisitedPage>>,
    others: FxHashMap<u64, VisitedPage>,
}

/// Addresses per page of [`Visited`].
const PAGE: u64 = 4096;

/// A page of [`Visited`]: a bit per address.
type VisitedPage = Box<[u64; (PAGE / 64) as usize]>;

impl Visited {
    /// An empty set, indexed over the executable code of `memory`.
    fn new(memory: &Memory) -> Self {
        let (base, span) = code_span(memory);
        Self { base, pages: (0..span.div_ceil(PAGE)).map(|_| None).collect(), others: FxHashMap::default() }
    }

    fn contains(&self, addr: u64) -> bool {
        let bit = addr % PAGE;
        let page = match addr.checked_sub(self.base).and_then(|i| self.pages.get((i / PAGE) as usize)) {
            Some(page) => page.as_ref(),
            None => self.others.get(&(addr / PAGE)),
        };
        page.is_some_and(|p| p[(bit / 64) as usize] & (1 << (bit % 64)) != 0)
    }

    /// The word and bit of `addr` (set: in the set), its page made when
    /// new: one look-up to test an address and then add it.
    #[inline]
    fn slot(&mut self, addr: u64) -> (&mut u64, u64) {
        let bit = addr % PAGE;
        let new = || Box::new([0; (PAGE / 64) as usize]);
        let page = match addr.checked_sub(self.base).and_then(|i| self.pages.get_mut((i / PAGE) as usize)) {
            Some(page) => page.get_or_insert_with(new),
            None => self.others.entry(addr / PAGE).or_insert_with(new),
        };
        (&mut page[(bit / 64) as usize], 1 << (bit % 64))
    }
}

/// The parts per listing part ([`Shared::cuts`]) the decodes handed over
/// are cut into, to be grouped by their counts ([`group_parts`]).
const FINE_PARTS: usize = 16;

/// Where to cut the code for the listing ([`Shared::cuts`]), and whether
/// the parts are final: where its maps are cut when it has a map per part
/// and is large (its instructions are listed into them where they are),
/// else into [`FINE_PARTS`] equal spans per part, grouped later.
fn part_cuts(listing: &Listing, memory: &Memory, parts: usize) -> (Vec<u64>, bool) {
    let starts = listing.instruction_part_starts();
    if parts <= 1 || (starts.len() == parts && listing.instruction_count() >= 1 << 16) {
        return (starts[1..].iter().copied().take(parts.saturating_sub(1)).collect(), true);
    }
    let (base, span) = code_span(memory);
    let n = (parts * FINE_PARTS) as u64;
    ((1..n).map(|k| base + span / n * k).collect(), false)
}

/// The parts `fine` (cut at `cuts`, each a few runs) grouped into `groups`
/// consecutive ones of about as many instructions each (the runs of a
/// group in order: those of its first part, then the next's), with the
/// cuts between the groups.
fn group_parts(cuts: &[u64], fine: Vec<Vec<InstructionRun>>, groups: usize) -> (Vec<u64>, Vec<Vec<InstructionRun>>) {
    debug_assert_eq!(fine.len(), cuts.len() + 1);
    // (the instructions in the parts before each)
    let mut before = Vec::with_capacity(fine.len() + 1);
    let mut n = 0;
    for part in &fine {
        before.push(n);
        n += part.iter().map(Vec::len).sum::<usize>();
    }
    before.push(n);
    // each group's first part (the first group's 0), ascending
    let mut firsts = vec![0];
    for g in 1..groups.min(fine.len()) {
        let target = n * g / groups;
        let at = before.partition_point(|&b| b < target).clamp(firsts[g - 1] + 1, fine.len() - (groups.min(fine.len()) - g));
        firsts.push(at);
    }
    let cuts = firsts[1..].iter().map(|&f| cuts[f - 1]).collect();
    let mut grouped: Vec<Vec<InstructionRun>> = firsts.iter().map(|_| Vec::new()).collect();
    for (k, part) in fine.into_iter().enumerate() {
        grouped[firsts.partition_point(|&f| f <= k) - 1].extend(part);
    }
    (cuts, grouped)
}

/// The start and length of the span of `memory`'s executable blocks
/// (an empty one when there are none or it is over 4 GiB).
fn code_span(memory: &Memory) -> (u64, u64) {
    let exec = memory.blocks().filter(|b| b.flags.contains(MemoryFlags::EXECUTE));
    let (lo, hi) = exec.fold((u64::MAX, 0), |(lo, hi), b| (lo.min(b.start), hi.max(b.start.saturating_add(b.size))));
    // (up to 4 GiB of code)
    if lo < hi && hi - lo <= 1 << 32 { (lo, hi - lo) } else { (0, 0) }
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
    /// Where to look first for the branch target of the instruction just
    /// fetched with `hint`.
    fn target_hint(&self, hint: &Self::Hint) -> Self::Hint {
        hint.clone()
    }
}

/// The listing and the walk's own decodes ([`Decodes`]): an instruction
/// is decoded (with `decoder`), and kept to be listed when neither listed
/// nor decoded before in the run.
struct Listed<'a> {
    decoder: &'a mut dyn InstructionDecoder,
    listing: &'a Listing,
    decodes: &'a mut Decodes,
}

impl Source for Listed<'_> {
    type Hint = ();
    fn fetch(&mut self, addr: u64, _: &mut ()) -> Option<Facts> {
        // Decoding is a pure function of the bytes, and only this pass
        // lists instructions: one listed at `addr` (or decoded before in
        // the run) is the one decoding gives — decoding it again costs
        // about what looking it up did.
        let (word, bit, run) = self.decodes.slot(self.listing, addr);
        let known = *word & bit != 0;
        *word |= bit;
        if known {
            // (only its facts read)
            let (length, flow, target) = self.decoder.decode_flow(addr).ok()?;
            return Some(Facts { target: target.unwrap_or(0), length, flow, has_target: target.is_some() });
        }
        let d = self.decoder.decode(addr).ok()?;
        let facts = Facts::of(&d);
        run.push((addr, Box::new(d)));
        Some(facts)
    }
}

/// The instructions a discovery walk decoded itself, listed when it is
/// done ([`Self::into_sorted`]) instead of one by one into the listing's
/// map: the addresses listed or decoded so far, a bit per address in pages
/// of [`PAGE`] addresses (as [`Visited`]), a page's listed ones marked when
/// it is first used (the listing does not change during the walk), and the
/// decodes kept, by page.
struct Decodes {
    base: u64,
    pages: Vec<Option<(VisitedPage, InstructionRun)>>,
    others: FxHashMap<u64, (VisitedPage, InstructionRun)>,
}

impl Decodes {
    fn new(memory: &Memory) -> Self {
        let (base, span) = code_span(memory);
        Self { base, pages: (0..span.div_ceil(PAGE)).map(|_| None).collect(), others: FxHashMap::default() }
    }

    /// The word and bit of `addr` (set: listed or decoded before) and the
    /// decodes kept in its page.
    fn slot(&mut self, listing: &Listing, addr: u64) -> (&mut u64, u64, &mut InstructionRun) {
        let fill = |lo: u64| {
            let mut page: VisitedPage = Box::new([0; (PAGE / 64) as usize]);
            for a in listing.instruction_addresses_in_range(lo, lo.saturating_add(PAGE)) {
                let bit = a - lo;
                page[(bit / 64) as usize] |= 1 << (bit % 64);
            }
            (page, Vec::new())
        };
        let ((page, run), bit) = match addr.checked_sub(self.base).filter(|&i| ((i / PAGE) as usize) < self.pages.len()) {
            Some(i) => (self.pages[(i / PAGE) as usize].get_or_insert_with(|| fill(addr - i % PAGE)), i % PAGE),
            None => (self.others.entry(addr / PAGE).or_insert_with(|| fill(addr - addr % PAGE)), addr % PAGE),
        };
        (&mut page[(bit / 64) as usize], 1 << (bit % 64), run)
    }

    /// The decodes kept, by address: page by page (each in the walk's
    /// order, put in order through a table by the address in the page).
    fn into_sorted(self) -> InstructionRun {
        let mut all: InstructionRun =
            Vec::with_capacity(self.pages.iter().flatten().chain(self.others.values()).map(|p| p.1.len()).sum());
        // (the index in the page's run of each address in the page, and
        // which are set)
        let mut at = vec![0u32; PAGE as usize];
        let mut set = [0u64; (PAGE / 64) as usize];
        for (lo, run) in self.pages.into_iter().enumerate().filter_map(|(k, p)| Some((self.base + k as u64 * PAGE, p?.1))) {
            let mut run: Vec<Option<(u64, Box<DecodedInstruction>)>> = run.into_iter().map(Some).collect();
            for (i, d) in run.iter().enumerate() {
                if let Some(d) = d {
                    let off = (d.0 - lo) as usize;
                    at[off] = i as u32;
                    set[off / 64] |= 1 << (off % 64);
                }
            }
            for (w, word) in set.iter_mut().enumerate() {
                while *word != 0 {
                    let off = w * 64 + word.trailing_zeros() as usize;
                    *word &= *word - 1;
                    all.extend(run[at[off] as usize].take());
                }
            }
        }
        // (outside the code: by page; few)
        let mut others: Vec<_> = self.others.into_iter().flat_map(|(_, (_, run))| run).collect();
        others.sort_unstable_by_key(|d| d.0);
        // (code span pages hold every address from base up; the others are
        // below or above it)
        let below = others.partition_point(|d| d.0 < self.base);
        let above = others.split_off(below);
        others.extend(all);
        others.extend(above);
        others
    }
}

/// The decodes made ahead (else [`Listed`]): read at the place the hint
/// gives (the one after the instruction the walk read before, or that
/// one's branch target, both found when the code was decoded), else by
/// address in that code, else in the code decoded from the entry at the
/// address.
struct Ahead<'a, 'l> {
    shared: &'a Shared<'a>,
    reads: &'l mut Reads,
    listing: &'l Listing,
    decoder: &'l mut dyn InstructionDecoder,
    decodes: &'l mut Decodes,
}

impl Source for Ahead<'_, '_> {
    /// The code the instruction read before was in, and the place in it
    /// to look first (after that instruction).
    type Hint = Option<(Arc<Spec>, u32)>;
    fn fetch(&mut self, addr: u64, hint: &mut Self::Hint) -> Option<Facts> {
        if let Some((spec, i)) = hint {
            let insns = &spec.insns;
            let at = if insns.get(*i as usize).is_some_and(|d| d.addr == addr) {
                Some(*i as usize)
            } else {
                insns.binary_search_by_key(&addr, |d| d.addr).ok()
            };
            if let Some(at) = at {
                *i = at as u32 + 1;
                self.reads.read(spec, at);
                return Some(insns[at].facts());
            }
        }
        let spec = self.shared.done.read().ok().and_then(|done| Some(done.specs[*done.by_entry.get(&addr)? as usize].clone()));
        // (the code decoded from `addr`: its entry's place)
        if let Some(spec) = spec
            && let Some(at) = spec.entry_at
        {
            let at = at as usize;
            let facts = spec.insns[at].facts();
            self.reads.read(&spec, at);
            *hint = Some((spec, at as u32 + 1));
            return Some(facts);
        }
        *hint = None;
        Listed { decoder: &mut *self.decoder, listing: self.listing, decodes: &mut *self.decodes }.fetch(addr, &mut ())
    }

    fn target_hint(&self, hint: &Self::Hint) -> Self::Hint {
        // (the instruction just read is the one before the place; none
        // when its target is not in that code: then by entry)
        let (spec, i) = hint.as_ref()?;
        let target = spec.insns[*i as usize - 1].target_at;
        (target != NOT_DECODED).then(|| (spec.clone(), target))
    }
}

/// [`SpecInsn::target_at`] / [`Spec::entry_at`] of an address not decoded
/// in the code.
const NOT_DECODED: u32 = u32::MAX;

/// An instruction [`speculate_one`] decoded.
/// [`Facts`] by field, packed (32 bytes: the walk reads them from
/// another thread's memory).
struct SpecInsn {
    addr: u64,
    target: u64,
    /// The decode (taken when listed).
    dec: Option<Box<DecodedInstruction>>,
    /// For a jump: the index of its target in the same code
    /// ([`NOT_DECODED`] if it is not there, or no jump).
    target_at: u32,
    length: u16,
    flow: FlowType,
    has_target: bool,
}

impl SpecInsn {
    #[inline]
    fn facts(&self) -> Facts {
        Facts { target: self.target, length: u32::from(self.length), flow: self.flow, has_target: self.has_target }
    }
}

/// The code reachable from one entry, decoded ahead of the walk.
struct Spec {
    /// By address, one per address.
    insns: Vec<SpecInsn>,
    /// The index of the entry's instruction (`None`: it did not decode).
    entry_at: Option<u32>,
    /// The thread that decoded it, and its index in that thread's list.
    owner: u32,
    index: u32,
}

/// The decodes the walk read, by the thread decoding ahead that made them
/// ([`Spec::owner`]): runs of consecutive places in one code (its
/// [`Spec::index`], the first place, how many). The walk reads them from
/// those threads' memory and keeps this list in its own (no write to
/// theirs); at its end each thread takes its list and hands over those
/// decodes, without looking at the others.
struct Reads {
    by_owner: Vec<Vec<(u32, u32, u32)>>,
}

impl Reads {
    #[inline]
    fn read(&mut self, spec: &Spec, at: usize) {
        let runs = &mut self.by_owner[spec.owner as usize];
        let at = at as u32;
        match runs.last_mut() {
            Some((code, first, n)) if *code == spec.index && *first + *n == at => *n += 1,
            _ => runs.push((spec.index, at, 1)),
        }
    }
}

/// The entries the threads decoding ahead have taken (to decode from),
/// shared by them: a bit per address of the executable code, in pages
/// made on first use (else in a set).
struct Claims {
    base: u64,
    pages: Vec<std::sync::OnceLock<ClaimPage>>,
    others: Mutex<FxHashSet<u64>>,
}

/// Addresses per page of [`Claims`].
const CLAIM_PAGE: usize = 1 << 14;

/// A page of [`Claims`]: a bit per address.
type ClaimPage = Box<[AtomicU64; CLAIM_PAGE / 64]>;

impl Claims {
    fn new(memory: &Memory) -> Self {
        // (up to 4 GiB of code: 2 MiB of page pointers at most)
        let (lo, span) = code_span(memory);
        let pages = (0..span.div_ceil(CLAIM_PAGE as u64)).map(|_| std::sync::OnceLock::new()).collect();
        Self { base: lo, pages, others: Mutex::new(FxHashSet::default()) }
    }

    /// The page of `addr` (`None`: outside the code) and its word and bit
    /// there.
    fn slot(&self, addr: u64) -> Option<(&std::sync::OnceLock<ClaimPage>, usize, u64)> {
        let i = addr.checked_sub(self.base)?;
        let page = self.pages.get((i / CLAIM_PAGE as u64) as usize)?;
        let bit = i % CLAIM_PAGE as u64;
        Some((page, (bit / 64) as usize, 1 << (bit % 64)))
    }

    /// Take `addr`: whether it was not taken before.
    fn claim(&self, addr: u64) -> bool {
        match self.slot(addr) {
            Some((page, word, bit)) => {
                let page = page.get_or_init(|| Box::new(std::array::from_fn(|_| AtomicU64::new(0))));
                page[word].fetch_or(bit, Ordering::Relaxed) & bit == 0
            }
            None => self.others.lock().is_ok_and(|mut c| c.insert(addr)),
        }
    }

    /// Whether `addr` is taken (outside the code: assumed not).
    fn claimed(&self, addr: u64) -> bool {
        self.slot(addr)
            .is_some_and(|(page, word, bit)| page.get().is_some_and(|page| page[word].load(Ordering::Relaxed) & bit != 0))
    }
}

/// The instructions the flow from `entry` reaches, not entering the
/// functions listed when the threads started nor the entries the threads have
/// taken (another task decodes from those); the entries it reaches are
/// added to `entries` (with whether by a call). The walk reads about
/// these (it stops where the run walked before, which depends on the
/// order); what is not here, it decodes itself.
fn speculate_one(shared: &Shared, decoder: &mut dyn InstructionDecoder, entry: u64, entries: &mut Vec<(u64, bool)>) -> Spec {
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
            // (the walk may be done)
            if shared.stop.load(Ordering::Relaxed) {
                break;
            }
            let mut addr = start;
            for n in 0..10_000 {
                if n % 256 == 255 && shared.stop.load(Ordering::Relaxed) {
                    break;
                }
                if addr != entry && (shared.claims.claimed(addr) || shared.listed.contains(&addr)) {
                    entries.push((addr, false));
                    break;
                }
                if !seen.insert(addr) {
                    break;
                }
                let Ok(d) = decoder.decode(addr) else {
                    break;
                };
                let facts = Facts::of(&d);
                // (a length that does not fit: left to the walk)
                let Ok(length) = u16::try_from(facts.length) else {
                    break;
                };
                insns.push(SpecInsn {
                    addr,
                    target: facts.target,
                    dec: Some(Box::new(d)),
                    target_at: NOT_DECODED,
                    length,
                    flow: facts.flow,
                    has_target: facts.has_target,
                });
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
        // (where the walk will look for the jumps' targets: found here, off
        // its thread)
        for k in 0..insns.len() {
            if matches!(insns[k].flow, FlowType::UnconditionalJump | FlowType::ConditionalJump)
                && insns[k].has_target
                && let Ok(at) = insns.binary_search_by_key(&insns[k].target, |d| d.addr)
            {
                insns[k].target_at = at as u32;
            }
        }
        let entry_at = insns.binary_search_by_key(&entry, |d| d.addr).ok().map(|at| at as u32);
        // (exactly sized; the working set keeps its room)
        let mut own = Vec::with_capacity(insns.len());
        own.append(insns);
        Spec { insns: own, entry_at, owner: 0, index: 0 }
    })
}

struct FunctionDiscovery {
    /// The address and length of each instruction walked ([`Walked`]).
    body: BodyInsns,
    /// The targets of its calls, ascending, once each.
    call_targets: Vec<u64>,
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

/// What [`disassemble_function`] keeps from one function to the next (the
/// room of its block queue and set).
struct WalkScratch<H> {
    queue: VecDeque<(u64, H)>,
    blocks: FxHashSet<u64>,
}

impl<H> Default for WalkScratch<H> {
    fn default() -> Self {
        Self { queue: VecDeque::new(), blocks: FxHashSet::default() }
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
    scratch: &mut WalkScratch<S::Hint>,
) -> Result<FunctionDiscovery, AnalysisError> {
    let WalkScratch { queue: block_queue, blocks: block_visited } = scratch;
    block_queue.clear();
    block_visited.clear();
    // (a large function's room not kept: clearing it costs its size)
    if block_visited.capacity() > 1 << 12 {
        block_visited.shrink_to(1 << 8);
    }
    let mut body = BodyInsns::default();
    let mut call_targets: Vec<u64> = Vec::new();
    let references_before = references.len();
    let mut instruction_count = 0;

    block_queue.push_back((entry, S::Hint::default()));

    while let Some((block_start, mut hint)) = block_queue.pop_front() {
        if !block_visited.insert(block_start) {
            continue;
        }

        let mut addr = block_start;
        let max_insns = 10_000;

        for _ in 0..max_insns {
            let (word, bit) = global_visited.slot(addr);
            if *word & bit != 0 && addr != block_start {
                break;
            }

            let Some(insn) = source.fetch(addr, &mut hint) else {
                break;
            };

            let insn_addr = addr;
            let insn_len = u64::from(insn.length);
            let branch_target = insn.branch_target();

            *word |= bit;
            body.push(insn_addr, insn.length);
            instruction_count += 1;

            push_references(insn_addr, &insn, references);
            match insn.flow {
                FlowType::Call => {
                    if let Some(target) = branch_target {
                        call_targets.push(target);
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
                        block_queue.push_back((target, source.target_hint(&hint)));
                    }
                    break;
                }
                FlowType::ConditionalJump => {
                    if let Some(target) = branch_target
                        && !block_visited.contains(&target)
                    {
                        block_queue.push_back((target, source.target_hint(&hint)));
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

    // (as a set gives them)
    call_targets.sort_unstable();
    call_targets.dedup();
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

    /// Everything the pass leaves in the program, as text.
    fn discovery_state(program: &Program, mark: reargo_program::reference::JumpMark) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for i in program.listing.instructions() {
            let _ = writeln!(out, "insn {:x} {} {:?} {:?}", i.address, i.length, i.flow_type, i.branch_target);
        }
        for f in program.listing.functions() {
            let _ = writeln!(out, "fn {:x} {} {:?} {:?}", f.entry_point, f.name, f.body, f.call_targets);
        }
        let mut targets = BTreeSet::new();
        for r in program.references.all_refs() {
            let _ = writeln!(out, "ref {:?}", r);
            targets.insert(r.to);
        }
        for t in targets {
            let _ = writeln!(out, "to {:x} {:?}", t, program.references.get_refs_to(t));
        }
        let _ = writeln!(out, "jumps {:?}", program.references.jumps_since(mark));
        out
    }

    /// Discovery with threads decoding ahead (a walk long enough for them
    /// to start, functions jumping into each other and sharing code) gives
    /// what it gives on one thread.
    #[test]
    fn parallel_discovery_matches_serial() {
        parallel_matches_serial(false);
    }

    /// The same with the threads seeded from the start: every function an
    /// entry of the walk (a symbol), as in Late Discovery.
    #[test]
    fn seeded_parallel_discovery_matches_serial() {
        parallel_matches_serial(true);
    }

    fn parallel_matches_serial(seeded: bool) {
        // Function k at 64 * k: 40 nops, then a call to function k + 1
        // and a ret, a jump into the middle of function k + 3 (every 7th),
        // or a conditional jump back into function k - 1 then a ret
        // (every 5th); 2200 functions, ~95k instructions.
        let count = 2200u64;
        let base = 0x10000u64;
        let mut code = vec![0xccu8; (count * 64) as usize];
        for k in 0..count {
            let at = (k * 64) as usize;
            code[at..at + 40].fill(0x90);
            let mut p = at + 40;
            let rel = |from: usize, to: u64| ((to as i64) - (base as i64 + from as i64)) as i32;
            if k + 1 < count {
                // call rel32
                let r = rel(p + 5, base + (k + 1) * 64);
                code[p] = 0xe8;
                code[p + 1..p + 5].copy_from_slice(&r.to_le_bytes());
                p += 5;
            }
            if k % 7 == 3 && k + 3 < count {
                // jmp rel32 into the middle of function k + 3
                let r = rel(p + 5, base + (k + 3) * 64 + 20);
                code[p] = 0xe9;
                code[p + 1..p + 5].copy_from_slice(&r.to_le_bytes());
            } else if k % 5 == 2 && k > 0 {
                // jne rel32 into function k - 1, then ret
                let r = rel(p + 6, base + (k - 1) * 64 + 10);
                code[p] = 0x0f;
                code[p + 1] = 0x85;
                code[p + 2..p + 6].copy_from_slice(&r.to_le_bytes());
                code[p + 6] = 0xc3;
            } else {
                code[p] = 0xc3;
            }
        }
        let run = |threads: usize| {
            let mut program = make_x86_64_program(&code, base);
            if seeded {
                // (in reverse: the walk takes them in another order than the calls)
                for k in (1..count).rev() {
                    program.symbol_table.add(reargo_program::symbol::Symbol::new(
                        format!("f{k}"),
                        base + k * 64,
                        SymbolType::Function,
                        reargo_program::symbol::SourceType::Analysis,
                    ));
                }
            }
            let mark = program.references.jump_mark();
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            let result = pool.install(|| FunctionDiscoveryAnalyzer.analyze(&mut program)).unwrap();
            assert!(result.instructions_decoded > HELP_AFTER, "{}", result.instructions_decoded);
            (discovery_state(&program, mark), result.functions_found, result.references_found, result.instructions_decoded)
        };
        let serial = run(1);
        for threads in [2, 4] {
            let parallel = run(threads);
            assert_eq!((serial.1, serial.2, serial.3), (parallel.1, parallel.2, parallel.3));
            assert_eq!(serial.0.len(), parallel.0.len());
            if let Some((a, b)) = serial.0.lines().zip(parallel.0.lines()).find(|(a, b)| a != b) {
                panic!("{threads} threads: {a} != {b}");
            }
        }
    }

    /// `body_set` (runs merged) equals sorting and deduplicating, on
    /// random walks: blocks of chained instructions, block starts walked
    /// again, blocks run into the middle of an instruction.
    #[test]
    fn body_set_matches_sorting() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for _ in 0..3000 {
            // the instruction lengths at each address (fixed: one per address)
            let len: Vec<u32> = (0..400).map(|_| 1 + next(7) as u32).collect();
            let mut body: Vec<(u64, u32)> = Vec::new();
            for _ in 0..1 + next(12) {
                let mut a = next(300);
                if next(3) == 0 && !body.is_empty() {
                    // a block start walked again
                    a = body[next(body.len() as u64) as usize].0;
                }
                for _ in 0..1 + next(15) {
                    body.push((a, len[a as usize]));
                    a += u64::from(len[a as usize]);
                    if a >= 380 {
                        break;
                    }
                }
            }
            let mut expected: Vec<AddressRange> =
                body.iter().map(|&(a, len)| AddressRange::new(Address::new(SpaceId::RAM, a), u64::from(len))).collect();
            expected.sort_by_key(|r| r.start.offset);
            expected.dedup();
            let expected: AddressSet = expected.into_iter().collect();
            assert_eq!(format!("{:?}", body_set(body.clone())), format!("{expected:?}"), "{body:?}");
            // (the same from the packed runs)
            let mut packed = BodyInsns::default();
            for &(a, len) in &body {
                packed.push(a, len);
            }
            assert_eq!(format!("{:?}", packed.into_set()), format!("{expected:?}"), "{body:?}");
        }
    }

    /// A packed body gives back what was pushed, in order, and its set is
    /// `body_set`'s: chained runs, jumps back, zero lengths, lengths past a
    /// byte (from then on one by one), the end of the address space.
    #[test]
    fn packed_body_gives_back_what_was_pushed() {
        let mut seed = 0x51_7cc1_b727_220au64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for case in 0..2000 {
            let (mut body, mut again) = (BodyInsns::default(), BodyInsns::default());
            let mut pushed = Vec::new();
            let mut a = if case % 7 == 0 { u64::MAX - next(64) } else { next(1 << 20) };
            for _ in 0..next(200) {
                let len = match next(40) {
                    0 => 0,
                    1 if case % 5 == 0 => 256 + next(1000) as u32,
                    _ => 1 + next(15) as u32,
                };
                body.push(a, len);
                again.push(a, len);
                pushed.push((a, len));
                a = match next(6) {
                    // (a jump elsewhere, or back to the same address)
                    0 => next(1 << 20),
                    1 => a,
                    _ => a.wrapping_add(u64::from(len)),
                };
            }
            assert_eq!(format!("{:?}", again.into_set()), format!("{:?}", body_set(pushed.clone())));
            assert_eq!(body.into_vec(), pushed);
        }
    }

    /// Fine parts grouped by their counts: the runs in the same order
    /// (each address in its group's range, the runs of an address in the
    /// order they had), as many groups as asked (or parts), ascending cuts
    /// among the fine ones, the groups about even.
    #[test]
    fn fine_parts_grouped_by_count() {
        let code = vec![0x90u8; 64];
        let program = make_x86_64_program(&code, 0x10000);
        let mut decoder = program.arch.instruction_decoder(&program.info.memory);
        let nop = decoder.decode(0x10000).unwrap();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for (parts, groups) in [(64usize, 4usize), (64, 1), (3, 4), (16, 16), (64, 3)] {
            let cuts: Vec<u64> = (1..parts as u64).map(|k| k * 1000).collect();
            // (counts from none to many, a few runs each)
            let fine: Vec<Vec<InstructionRun>> = (0..parts as u64)
                .map(|k| {
                    let n = if next(4) == 0 { 0 } else { next(3000) };
                    (0..1 + next(3)).map(|_| (0..n / 2).map(|_| (k * 1000 + next(1000), Box::new(nop.clone()))).collect()).collect()
                })
                .collect();
            let flat = |p: &Vec<Vec<InstructionRun>>| p.iter().flatten().flatten().map(|d| d.0).collect::<Vec<_>>();
            let (group_cuts, grouped) = group_parts(&cuts, fine.clone(), groups);
            assert_eq!(grouped.len(), groups.min(parts));
            assert_eq!(group_cuts.len() + 1, grouped.len());
            assert!(group_cuts.windows(2).all(|w| w[0] < w[1]) && group_cuts.iter().all(|c| cuts.contains(c)));
            assert_eq!(flat(&grouped), flat(&fine));
            let total = flat(&fine).len();
            for (g, part) in grouped.iter().enumerate() {
                let (lo, hi) = (if g == 0 { 0 } else { group_cuts[g - 1] }, group_cuts.get(g).copied().unwrap_or(u64::MAX));
                assert!(part.iter().flatten().all(|d| lo <= d.0 && d.0 < hi));
                // (within a fine part of the even share)
                let n: usize = part.iter().map(Vec::len).sum();
                assert!(groups > parts || n <= total / groups + 3000, "{parts} {groups}: {n} of {total}");
            }
        }
    }

    /// The walk's own decodes come out by address, once each, the listed
    /// ones left out.
    #[test]
    fn decodes_sorted_by_address() {
        let code = vec![0x90u8; 3 * PAGE as usize];
        let program = make_x86_64_program(&code, 0x10000);
        let mut listing = Listing::new();
        let mut decoder = program.arch.instruction_decoder(&program.info.memory);
        for a in [0x10005u64, 0x11003] {
            listing.add_instruction(decoder.decode(a).unwrap());
        }
        let mut decodes = Decodes::new(&program.info.memory);
        let mut seed = 12345u64;
        let mut expected = BTreeSet::new();
        for _ in 0..5000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            // (some outside the code too)
            let a = 0x10000 - 64 + (seed >> 33) % (3 * PAGE + 128);
            let source = &mut Listed { decoder: &mut *decoder, listing: &listing, decodes: &mut decodes };
            if source.fetch(a, &mut ()).is_some() && !listing.has_instruction(a) {
                expected.insert(a);
            }
        }
        let got: Vec<u64> = decodes.into_sorted().into_iter().map(|d| d.0).collect();
        assert_eq!(got, expected.into_iter().collect::<Vec<_>>());
    }

    #[test]
    fn empty_program_no_crash() {
        let code = [0x00u8; 0]; // empty
        let mut program = make_x86_64_program(&code, 0x1000);
        let analyzer = FunctionDiscoveryAnalyzer;
        let _result = analyzer.analyze(&mut program);
    }
}
