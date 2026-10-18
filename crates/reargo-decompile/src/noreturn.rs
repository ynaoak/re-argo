//! Calls that never return (WS81).
//!
//! A call to `_Unwind_Resume`, `abort`, `__cxa_throw`, … does not come back, so the code
//! after it is not its continuation: compilers put the next block (a landing pad, a cold
//! path, or the next function) right behind it. Taken as a fall-through, that edge glues
//! unrelated code into the function and makes bogus joins for the structurer.
//!
//! [`NoReturn`] answers "does the function at `target` never return?":
//! * by name, for imports whose contract is `noreturn` ([`NORETURN_NAMES`], exact match of the
//!   symbol without its `@plt` / `@GLIBC_…` suffix);
//! * by its code: no path from `target` reaches a `ret`, an indirect jump, or code that
//!   cannot be lifted (or past the instruction budget) — every path ends in a trap (`int3` /
//!   `ud2` / `hlt`) or in a call to a function that never returns (decided the same way,
//!   depth-limited); a tail jump is followed as part of the path. An unknown answer counts as
//!   "returns", so a mistake can only leave a fall-through in, never cut real code out.
//!
//! The search is a 0-1 BFS over the instructions where passing a call costs 1: an exit
//! reachable with fewer calls is found first, and only the calls in front of it are looked
//! into. Instructions are lifted as the search reaches them. A question is answered from
//! scratch (its search memoises the functions it looks into, nothing is kept from an earlier
//! question), so the answer depends on the target alone and a batch shares it.
//!
//! [`mark_noreturn_calls`] appends a [`NORETURN_MARK`] op to each such call instruction;
//! [`crate::cfg::is_trap`] treats it like a trap (control does not fall through) and the
//! emitters print nothing for it.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use reargo_core::address::{Address, SpaceId};
use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_loader::Memory;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

/// `CALLOTHER` tag of the marker appended to a call that never returns.
pub const NORETURN_MARK: u64 = reargo_core::pcode::intrinsic::NORETURN;

/// Imports that never return (C, C++ runtime, unwinder).
pub const NORETURN_NAMES: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "pthread_exit",
    "thrd_exit",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "err",
    "errx",
    "verr",
    "verrx",
    "__stack_chk_fail",
    "__fortify_fail",
    "__chk_fail",
    "__assert_fail",
    "__assert_perror_fail",
    "__assert_rtn",
    "__libc_fatal",
    "_Unwind_Resume",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_pure_virtual",
    "__cxa_deleted_virtual",
    "__cxa_call_unexpected",
    "__cxa_throw_bad_array_new_length",
    "_ZSt9terminatev",
    "std::terminate()",
    "_ZSt17__throw_bad_allocv",
    "_ZSt20__throw_length_errorPKc",
    "_ZSt20__throw_out_of_rangePKc",
    "_ZSt24__throw_out_of_range_fmtPKcz",
    "_ZSt19__throw_logic_errorPKc",
    "_ZSt20__throw_bad_array_new_lengthv",
    "_ZSt25__throw_bad_function_callv",
    "_ZSt16__throw_bad_castv",
    "_ZSt21__throw_runtime_errorPKc",
    "_ZSt20__throw_system_errori",
    "_ZSt24__throw_invalid_argumentPKc",
];

/// Is `name` (a symbol, possibly `foo@plt` / `foo@GLIBC_2.2.5`) a function that never returns?
pub fn is_noreturn_name(name: &str) -> bool {
    let base = name.split('@').next().unwrap_or(name);
    NORETURN_NAMES.contains(&base)
}

/// Most instructions lifted per function looked into.
const MAX_INSNS: usize = 1024;
/// Call levels followed below the function asked about.
const MAX_DEPTH: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    NoReturn,
    Returns,
    /// The search was cut short (depth limit, recursion): treated as "returns".
    Unsure,
}

/// "Does this function never return?"; each question answered by a search from scratch.
pub struct NoReturn<'a> {
    lifter: &'a dyn PcodeLift,
    memory: &'a Memory,
    symbols: Option<&'a BTreeMap<u64, String>>,
    /// target -> verdict (and, for `Unsure`, the depth it was computed with), for the search
    /// of one question
    memo: Mutex<FxHashMap<u64, (Verdict, u32)>>,
    /// The cache shared by the searches of a batch ([`FlowCache`]): the answers and searches
    /// for every lifter, the control flow of each instruction lifted alone for x86.
    cache: Option<&'a FlowCache>,
    /// `symbols`' addresses that [`is_noreturn_name`], from `cache`.
    named: Option<&'a rustc_hash::FxHashSet<u64>>,
}

/// What [`search`] reads of an instruction: its extent and control flow. Shared by every
/// search of a batch: the same for an instruction lifted alone as lifted in a range (the PF
/// and the x87 stack a range lift adds change no control flow).
///
/// It also keeps the answers of [`NoReturn::is_noreturn`]: each is a pure function of the
/// target (a search from scratch, see there), so the functions of a batch share them.
/// `(memory, symbols, target)` -> the function at `target` never returns.
type Verdicts = FxHashMap<(usize, usize, u64), bool>;

/// What a search of a function's code ([`NoReturn::analyze`]) asked and found: the calls it
/// asked about, in order, with the answers it got, and whether control leaves (`None`: the
/// code at the target cannot be lifted). The search is a function of the code and of those
/// answers: given the same answers to the same questions it asks nothing else and finds the
/// same, so another search of the function replays it.
struct Trace {
    calls: Box<[(u64, bool)]>,
    exit: Option<bool>,
}

/// The last [`Trace`] of each function searched, by memory, symbols and target.
type Traces = FxHashMap<(usize, usize, u64), std::sync::Arc<Trace>>;

#[derive(Default)]
pub struct FlowCache {
    shards: Vec<Mutex<FlowShard>>,
    /// The flows of the other lifters' instructions, by address and the decode state they
    /// are lifted in ([`GenericFlows`]).
    generic: Vec<Mutex<GenericFlows>>,
    /// the answers of the questions asked, by memory, symbols and target
    verdicts: Vec<Mutex<Verdicts>>,
    traces: Vec<Mutex<Traces>>,
    /// The addresses whose symbol names a function that never returns, for the symbols (by
    /// address) of the batch.
    named: std::sync::OnceLock<(usize, rustc_hash::FxHashSet<u64>)>,
}

impl FlowCache {
    pub fn new() -> Self {
        Self {
            shards: (0..64).map(|_| Mutex::new(FlowShard::default())).collect(),
            generic: (0..64).map(|_| Mutex::new(GenericFlows::default())).collect(),
            verdicts: (0..16).map(|_| Mutex::new(FxHashMap::default())).collect(),
            traces: (0..16).map(|_| Mutex::new(FxHashMap::default())).collect(),
            named: std::sync::OnceLock::new(),
        }
    }

    fn trace_shard(&self, target: u64) -> Option<&Mutex<Traces>> {
        let n = self.traces.len() as u64;
        (n > 0).then(|| &self.traces[((target ^ (target >> 5)) % n) as usize])
    }

    fn verdict_shard(&self, target: u64) -> Option<&Mutex<Verdicts>> {
        let n = self.verdicts.len() as u64;
        (n > 0).then(|| &self.verdicts[((target ^ (target >> 5)) % n) as usize])
    }

    /// The flows of the instructions from `addr` on, each lifted alone, handed to `each` while
    /// it returns `true` (up to the first that cannot be lifted). The instructions of one
    /// 4 KB page share a shard, looked up under one lock.
    fn run(&self, x86: &reargo_lift::x86::X86Lifter, memory: &Memory, addr: u64, each: &mut dyn FnMut(Flow) -> bool) {
        let shard_of = |a: u64| ((a >> 12) % self.shards.len() as u64) as usize;
        let mut at = addr;
        let mut cursor = reargo_lift::x86::DecodeCursor::default();
        loop {
            let k = shard_of(at);
            let Ok(mut m) = self.shards[k].lock() else { return };
            while shard_of(at) == k {
                let f = match m.get(at) {
                    Some(f) => f,
                    None => {
                        let f = flow_alone(x86, memory, at, &mut cursor);
                        m.insert(at, &f);
                        f
                    }
                };
                let Some(f) = f else { return };
                at = f.address + u64::from(f.length);
                if !each(f) {
                    return;
                }
            }
        }
    }
}

impl FlowCache {
    /// `lifter.lift_range(memory, addr, ..)`'s instructions' flows (a lifter with the default
    /// `lift_range`: a stream from a fresh decode state, up to the first instruction that
    /// cannot be lifted), handed to `each` while it returns `true`. The lift of an instruction
    /// is a function of its address and of the decode state it is lifted in (a Thumb IT
    /// block), so its flow is kept by both: the searches of a batch lift each once.
    fn run_generic(&self, lifter: &dyn PcodeLift, memory: &Memory, addr: u64, each: &mut dyn FnMut(Flow) -> bool) {
        // (the instructions of one 4 KB page share a shard, looked up under one lock)
        let shard_of = |a: u64| ((a >> 12) % self.generic.len() as u64) as usize;
        let mut at = addr;
        let mut ctx = reargo_lift::LiftContext::default();
        loop {
            let k = shard_of(at);
            let Ok(mut m) = self.generic[k].lock() else { return };
            while shard_of(at) == k {
                // (a pending delay slot is not kept: lifted each time)
                let key = ctx.delay.is_none().then(|| (at, ctx.it.map(|it| (it.state, it.addr))));
                let (flow, after) = match key.and_then(|k| m.get(k)) {
                    Some(v) => v,
                    None => {
                        let lifted = lifter.lift_instruction_ctx(memory, at, &mut ctx).ok();
                        let flow = lifted.as_ref().map(Flow::of);
                        let after = ctx.it.map(|it| (it.state, it.addr));
                        if let Some(k) = key
                            && ctx.delay.is_none()
                        {
                            m.insert(k, &flow, after);
                        }
                        (flow, after)
                    }
                };
                let Some(f) = flow else { return };
                if ctx.delay.is_none() {
                    ctx.it = after.map(|(state, addr)| reargo_lift::ItBlock { state, addr });
                }
                at = f.address + u64::from(f.length);
                if !each(f) {
                    return;
                }
            }
        }
    }
}

/// An IT state (`(state, address)`).
type ItKey = Option<(u8, u64)>;

/// [`FlowCache::run_generic`]'s flows: `(address, IT state)` -> the flow (`None`: it cannot be
/// lifted) and the IT state after it; those outside IT blocks (no state before nor after) at
/// a 32-bit address packed in 32 bits ([`GenericFlows::pack`]) when they fit, the others as
/// they are.
#[derive(Default)]
struct GenericFlows {
    packed: FxHashMap<u32, u32>,
    other: FxHashMap<(u64, ItKey), (Option<Flow>, ItKey)>,
}

/// A flow packed in 32 bits: lifted (bit 0; else the instruction could not be lifted), the
/// length (bits 1..5), a trap (bit 5), the event count (bits 6..8), each event's kind (bits
/// 8..10 and 11..13: exit, jump, conditional jump, call) and whether it has a target (bits 10,
/// 13), and the one target relative to the address (bits 14..32, signed).
const PACKED32_LIFTED: u32 = 1;

impl GenericFlows {
    fn get(&self, (addr, it): (u64, ItKey)) -> Option<(Option<Flow>, ItKey)> {
        if it.is_none()
            && let Ok(a) = u32::try_from(addr)
            && let Some(&v) = self.packed.get(&a)
        {
            return Some((Self::unpack(addr, v), None));
        }
        self.other.get(&(addr, it)).cloned()
    }

    fn insert(&mut self, (addr, it): (u64, ItKey), flow: &Option<Flow>, after: ItKey) {
        if it.is_none()
            && after.is_none()
            && let Ok(a) = u32::try_from(addr)
            && let Some(v) = Self::pack(flow)
        {
            self.packed.insert(a, v);
        } else {
            self.other.insert((addr, it), (flow.clone(), after));
        }
    }

    fn pack(f: &Option<Flow>) -> Option<u32> {
        let Some(f) = f else { return Some(0) };
        if f.length > 15 || f.events.len() > 2 {
            return None;
        }
        let mut v = PACKED32_LIFTED | (f.length << 1) | (u32::from(f.trap) << 5) | ((f.events.len() as u32) << 6);
        let mut target = None;
        for (i, ev) in f.events.iter().enumerate() {
            let (kind, t) = match *ev {
                Event::Exit => (0u32, None),
                Event::Branch { uncond: true, target } => (1, target),
                Event::Branch { uncond: false, target } => (2, target),
                Event::Call(t) => (3, Some(t)),
            };
            v |= kind << (8 + 3 * i);
            if let Some(t) = t {
                if target.is_some() {
                    return None;
                }
                let rel = t.wrapping_sub(f.address) as i64;
                if !(-(1 << 17)..1 << 17).contains(&rel) {
                    return None;
                }
                target = Some(rel as i32);
                v |= 1 << (10 + 3 * i);
            }
        }
        Some(v | ((target.unwrap_or(0) as u32) << 14))
    }

    fn unpack(addr: u64, v: u32) -> Option<Flow> {
        if v & PACKED32_LIFTED == 0 {
            return None;
        }
        let target = addr.wrapping_add(((v as i32) >> 14) as i64 as u64);
        let events = (0..((v >> 6) & 3) as usize)
            .map(|i| {
                let has = v & (1 << (10 + 3 * i)) != 0;
                match (v >> (8 + 3 * i)) & 3 {
                    0 => Event::Exit,
                    1 => Event::Branch { uncond: true, target: has.then_some(target) },
                    2 => Event::Branch { uncond: false, target: has.then_some(target) },
                    _ => Event::Call(target),
                }
            })
            .collect();
        Some(Flow { address: addr, length: (v >> 1) & 0xf, trap: v & (1 << 5) != 0, events })
    }
}

/// What [`flow_alone`] knows of the instructions alike ([`reargo_lift::x86::X86Lifter::alike_key`])
/// of one it lifted: their flow (its targets those of their own branch), that they cannot
/// be lifted, or nothing (lifted each time).
#[derive(Clone)]
enum AlikeFlow {
    Flow(Flow),
    Fails,
    Lift,
}

/// [`AlikeFlow`]s a thread keeps at most (emptied when full).
const FLOW_MEMO_CAP: usize = 1 << 16;

thread_local! {
    static FLOW_MEMO: std::cell::RefCell<FxHashMap<(bool, iced_x86::Instruction), AlikeFlow>> = std::cell::RefCell::new(FxHashMap::default());
}

/// The direct branch target of `insn`, if it has one.
fn near_target(insn: &iced_x86::Instruction) -> Option<u64> {
    use iced_x86::OpKind;
    (0..insn.op_count())
        .any(|i| matches!(insn.op_kind(i), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64))
        .then(|| insn.near_branch_target())
}

/// `Flow::of` the lift alone of the instruction at `at` (`None` when it cannot be lifted): an
/// instruction alike one lifted before (but for its displacement / branch target) has its
/// flow with its own branch target, when that one's targets were its branch target — the
/// lift's control flow does not depend on those values.
fn flow_alone<'m>(x86: &reargo_lift::x86::X86Lifter, memory: &'m Memory, at: u64, cursor: &mut reargo_lift::x86::DecodeCursor<'m>) -> Option<Flow> {
    let insn = x86.decode_alone_with(memory, at, cursor).ok()?;
    let key = x86.alike_key(&insn);
    let near = near_target(&insn);
    let known = FLOW_MEMO.with(|m| m.borrow().get(&key).cloned());
    match known {
        Some(AlikeFlow::Flow(f)) => {
            let events = f.events.iter().map(|e| match *e {
                Event::Branch { uncond, target: Some(_) } => Event::Branch { uncond, target: near },
                Event::Call(_) => Event::Call(near.expect("a call alike one to its branch target")),
                other => other,
            });
            return Some(Flow { address: at, length: insn.len() as u32, trap: f.trap, events: events.collect() });
        }
        Some(AlikeFlow::Fails) => return None,
        Some(AlikeFlow::Lift) | None => {}
    }
    let f = x86.lift_decoded_alone(insn, at).ok().map(|i| Flow::of(&i));
    if known.is_none() {
        let alike = match &f {
            None => AlikeFlow::Fails,
            Some(f) if f.events.iter().all(|e| match *e {
                Event::Branch { target: Some(t), .. } | Event::Call(t) => near == Some(t),
                _ => true,
            }) => AlikeFlow::Flow(f.clone()),
            Some(_) => AlikeFlow::Lift,
        };
        FLOW_MEMO.with(|m| {
            let mut m = m.borrow_mut();
            if m.len() >= FLOW_MEMO_CAP {
                m.clear();
            }
            m.insert(key, alike);
        });
    }
    f
}

/// The flows of a [`FlowCache`] shard: packed in a `u64` (see [`FlowShard::pack`]), the
/// others (more events, or two with a target) as they are.
#[derive(Default)]
struct FlowShard {
    packed: FxHashMap<u64, u64>,
    other: FxHashMap<u64, Option<Flow>>,
}

/// A packed flow: lifted (else the instruction could not be lifted), the length (bits 0..4),
/// a trap (bit 4), the event count (bits 5..7), each event's kind (bits 7..9 and 10..12:
/// exit, jump, conditional jump, call) and whether it has a target (bits 9, 12), and the one
/// target, relative to the address (bits 32..64).
const PACKED_LIFTED: u64 = 1 << 15;

impl FlowShard {
    fn get(&self, addr: u64) -> Option<Option<Flow>> {
        if let Some(&v) = self.packed.get(&addr) {
            return Some(Self::unpack(addr, v));
        }
        self.other.get(&addr).cloned()
    }

    fn insert(&mut self, addr: u64, f: &Option<Flow>) {
        match Self::pack(f) {
            Some(v) => self.packed.insert(addr, v),
            None => self.other.insert(addr, f.clone()).map(|_| 0),
        };
    }

    fn pack(f: &Option<Flow>) -> Option<u64> {
        let Some(f) = f else { return Some(0) };
        if f.length > 15 || f.events.len() > 2 {
            return None;
        }
        let mut v = PACKED_LIFTED | u64::from(f.length) | (u64::from(f.trap) << 4) | ((f.events.len() as u64) << 5);
        let mut target = None;
        for (i, ev) in f.events.iter().enumerate() {
            let (kind, t) = match *ev {
                Event::Exit => (0u64, None),
                Event::Branch { uncond: true, target } => (1, target),
                Event::Branch { uncond: false, target } => (2, target),
                Event::Call(t) => (3, Some(t)),
            };
            v |= kind << (7 + 3 * i);
            if let Some(t) = t {
                if target.is_some() {
                    return None;
                }
                target = Some(i32::try_from(t.wrapping_sub(f.address) as i64).ok()?);
                v |= 1 << (9 + 3 * i);
            }
        }
        Some(v | (u64::from(target.unwrap_or(0) as u32) << 32))
    }

    fn unpack(addr: u64, v: u64) -> Option<Flow> {
        if v & PACKED_LIFTED == 0 {
            return None;
        }
        let target = addr.wrapping_add((v >> 32) as u32 as i32 as i64 as u64);
        let events = (0..((v >> 5) & 3) as usize)
            .map(|i| {
                let has = v & (1 << (9 + 3 * i)) != 0;
                match (v >> (7 + 3 * i)) & 3 {
                    0 => Event::Exit,
                    1 => Event::Branch { uncond: true, target: has.then_some(target) },
                    2 => Event::Branch { uncond: false, target: has.then_some(target) },
                    _ => Event::Call(target),
                }
            })
            .collect();
        Some(Flow { address: addr, length: (v & 0xf) as u32, trap: v & (1 << 4) != 0, events })
    }
}

/// The control flow of one instruction, in op order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    address: u64,
    length: u32,
    trap: bool,
    events: SmallVec<[Event; 2]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// `RETURN` / `BRANCHIND`: control leaves.
    Exit,
    /// `BRANCH` (`uncond`) / `CBRANCH`, with its target when it is an address.
    Branch { uncond: bool, target: Option<u64> },
    /// `CALL` of an address.
    Call(u64),
}

impl Flow {
    fn of(insn: &LiftedInstruction) -> Self {
        let ram = |op: &PcodeOp| op.inputs.first().filter(|t| t.space == SpaceId::RAM).map(|t| t.offset);
        let mut events = SmallVec::new();
        for op in &insn.ops {
            match op.opcode {
                OpCode::Return | OpCode::BranchInd => events.push(Event::Exit),
                OpCode::Branch | OpCode::CBranch => events.push(Event::Branch { uncond: op.opcode == OpCode::Branch, target: ram(op) }),
                OpCode::Call => {
                    if let Some(t) = ram(op) {
                        events.push(Event::Call(t));
                    }
                }
                _ => {}
            }
        }
        Self { address: insn.address, length: insn.length, trap: crate::cfg::is_trap(insn), events }
    }
}

impl<'a> NoReturn<'a> {
    pub fn new(lifter: &'a dyn PcodeLift, memory: &'a Memory, symbols: Option<&'a BTreeMap<u64, String>>) -> Self {
        Self { lifter, memory, symbols, memo: Mutex::new(FxHashMap::default()), cache: None, named: None }
    }

    /// The same oracle sharing its answers and searches with the batch through `cache` (and,
    /// for an x86 lifter, reading the instructions' control flow from it; the answers do not
    /// change).
    pub fn with_flow_cache(mut self, cache: Option<&'a FlowCache>) -> Self {
        self.cache = cache;
        // (the symbols that name such a function, collected once for the batch)
        if let (Some(cache), Some(symbols)) = (cache, self.symbols) {
            let id = std::ptr::from_ref(symbols) as usize;
            let (of, set) = cache.named.get_or_init(|| (id, symbols.iter().filter(|(_, n)| is_noreturn_name(n)).map(|(&a, _)| a).collect()));
            self.named = (*of == id).then_some(set);
        }
        self
    }

    /// Does the function at `target` never return?
    ///
    /// Each answer is a search from scratch (no memo of an earlier question), so it depends on
    /// `target` alone and an oracle with a flow cache shares it with the batch.
    pub fn is_noreturn(&self, target: u64) -> bool {
        if self.named(target) {
            return true;
        }
        let key = (std::ptr::from_ref(self.memory) as usize, self.symbols.map_or(0, |s| std::ptr::from_ref(s) as usize), target);
        let shard = self.cache.and_then(|cache| cache.verdict_shard(target));
        if let Some(&v) = shard.and_then(|m| m.lock().ok()).as_ref().and_then(|m| m.get(&key)) {
            return v;
        }
        if let Ok(mut m) = self.memo.lock() {
            m.clear();
        }
        let v = self.verdict(target, MAX_DEPTH, &mut Vec::new()) == Verdict::NoReturn;
        if let Some(mut m) = shard.and_then(|m| m.lock().ok()) {
            m.insert(key, v);
        }
        v
    }

    fn named(&self, target: u64) -> bool {
        match self.named {
            Some(set) => set.contains(&target),
            None => self.symbols.and_then(|s| s.get(&target)).is_some_and(|n| is_noreturn_name(n)),
        }
    }

    fn verdict(&self, target: u64, depth: u32, stack: &mut Vec<u64>) -> Verdict {
        if self.named(target) {
            return Verdict::NoReturn;
        }
        if let Some(&(v, d)) = self.memo.lock().ok().and_then(|m| m.get(&target).copied()).as_ref()
            && (v != Verdict::Unsure || d >= depth)
        {
            return v;
        }
        if depth == 0 || stack.contains(&target) {
            return Verdict::Unsure;
        }
        stack.push(target);
        let v = self.analyze(target, depth, stack);
        stack.pop();
        if let Ok(mut m) = self.memo.lock() {
            m.insert(target, (v, depth));
        }
        v
    }

    fn analyze(&self, target: u64, depth: u32, stack: &mut Vec<u64>) -> Verdict {
        let ask = |t: u64, s: &mut Vec<u64>, unsure: &mut bool| match self.verdict(t, depth - 1, s) {
            Verdict::NoReturn => true,
            Verdict::Returns => false,
            Verdict::Unsure => {
                *unsure = true;
                false
            }
        };
        let outcome = |exit: Option<bool>, unsure: bool| match (exit, unsure) {
            (None, _) => Verdict::Returns,
            (Some(false), _) => Verdict::NoReturn,
            (Some(true), false) => Verdict::Returns,
            (Some(true), true) => Verdict::Unsure,
        };
        // (a search of the function made before, by any question: the same questions asked in
        // its order get the same answers, and so it finds the same; at the first answer that
        // differs the search runs, asking those questions again — answered the same, from the
        // memo or as before, without changing it)
        let key = (std::ptr::from_ref(self.memory) as usize, self.symbols.map_or(0, |s| std::ptr::from_ref(s) as usize), target);
        let shard = self.cache.and_then(|cache| cache.trace_shard(target));
        if let Some(trace) = shard.and_then(|m| m.lock().ok().and_then(|m| m.get(&key).cloned())) {
            let mut unsure = false;
            if trace.calls.iter().all(|&(t, answer)| ask(t, stack, &mut unsure) == answer) {
                return outcome(trace.exit, unsure);
            }
        }
        let mut code = Code { lifter: self.lifter, memory: self.memory, flow: self.lifter.as_x86().zip(self.cache), shared: self.cache.filter(|_| self.lifter.as_x86().is_none()), insns: Vec::new(), index: FxHashMap::default() };
        code.take_buffers();
        let mut unsure = false;
        let mut calls = Vec::new();
        let exit = code.at(target).map(|entry| {
            let mut stops = |t: u64, s: &mut Vec<u64>| {
                let answer = ask(t, s, &mut unsure);
                if shard.is_some() {
                    calls.push((t, answer));
                }
                answer
            };
            search(&mut code, entry, &|t| self.named(t), &mut stops, stack)
        });
        if let Some(mut m) = shard.and_then(|m| m.lock().ok()) {
            m.insert(key, std::sync::Arc::new(Trace { calls: calls.into_boxed_slice(), exit }));
        }
        outcome(exit, unsure)
    }
}

/// The instructions of a function, lifted as the search reaches them.
struct Code<'a> {
    lifter: &'a dyn PcodeLift,
    memory: &'a Memory,
    flow: Option<(&'a reargo_lift::x86::X86Lifter, &'a FlowCache)>,
    /// The batch's cache, for a lifter other than x86 ([`FlowCache::run_generic`]).
    shared: Option<&'a FlowCache>,
    insns: Vec<Flow>,
    index: FxHashMap<u64, usize>,
}

/// Instructions lifted at a time.
const CHUNK: usize = 24;

thread_local! {
    /// The emptied buffers of the [`Code`]s a thread dropped (a search nests one per call
    /// level it looks into): a new one takes them instead of growing its own to the function's
    /// size again.
    static CODE_BUFFERS: std::cell::RefCell<Vec<CodeBuffers>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// A [`Code`]'s buffers: its flows and their index by address.
type CodeBuffers = (Vec<Flow>, FxHashMap<u64, usize>);

impl Code<'_> {
    /// Take a dropped `Code`'s buffers, else room for a chunk.
    fn take_buffers(&mut self) {
        match CODE_BUFFERS.with(|b| b.borrow_mut().pop()) {
            Some((insns, index)) => (self.insns, self.index) = (insns, index),
            None => {
                self.insns.reserve(CHUNK);
                self.index.reserve(CHUNK);
            }
        }
    }
}

impl Drop for Code<'_> {
    fn drop(&mut self) {
        let (mut insns, mut index) = (std::mem::take(&mut self.insns), std::mem::take(&mut self.index));
        insns.clear();
        index.clear();
        CODE_BUFFERS.with(|b| {
            let mut b = b.borrow_mut();
            if b.len() < 2 * MAX_DEPTH as usize {
                b.push((insns, index));
            }
        });
    }
}

impl Code<'_> {
    /// The instruction at `addr`, lifting from there when it is not lifted yet; `None` when it
    /// cannot be lifted or the budget ([`MAX_INSNS`]) is spent.
    fn at(&mut self, addr: u64) -> Option<usize> {
        if let Some(&i) = self.index.get(&addr) {
            return Some(i);
        }
        if self.insns.len() >= MAX_INSNS {
            return None;
        }
        match self.flow {
            // `lift_range(addr, CHUNK)`'s instructions, one at a time (it stops at the first
            // that cannot be lifted)
            Some((x86, cache)) => {
                let mut n = 0;
                cache.run(x86, self.memory, addr, &mut |f| {
                    match self.index.entry(f.address) {
                        std::collections::hash_map::Entry::Occupied(_) => return false, // runs into code lifted before
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert(self.insns.len());
                        }
                    }
                    self.insns.push(f);
                    n += 1;
                    n < CHUNK
                });
            }
            None if let Some(cache) = self.shared => {
                let mut n = 0;
                cache.run_generic(self.lifter, self.memory, addr, &mut |f| {
                    match self.index.entry(f.address) {
                        std::collections::hash_map::Entry::Occupied(_) => return false, // runs into code lifted before
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert(self.insns.len());
                        }
                    }
                    self.insns.push(f);
                    n += 1;
                    n < CHUNK
                });
            }
            None => {
                for insn in self.lifter.lift_range(self.memory, addr, CHUNK).ok()? {
                    if self.index.contains_key(&insn.address) {
                        break; // runs into code lifted before
                    }
                    self.index.insert(insn.address, self.insns.len());
                    self.insns.push(Flow::of(&insn));
                }
            }
        }
        self.index.get(&addr).copied()
    }
}

enum Item {
    Insn(usize),
    /// A direct call to `target`; `fall` = the address after it.
    Call { target: u64, fall: u64 },
}

/// Can control leave the function (see the module doc) from `entry`? `named(t)`: `t` is an
/// import that never returns; `stops(t)`: a call to `t` never returns. A jump to another
/// function (a tail call) is followed as part of this one.
fn search(
    code: &mut Code<'_>,
    entry: usize,
    named: &dyn Fn(u64) -> bool,
    stops: &mut dyn FnMut(u64, &mut Vec<u64>) -> bool,
    stack: &mut Vec<u64>,
) -> bool {
    // (by the instruction's position in `code`, which only grows)
    let mut seen: Vec<bool> = Vec::new();
    let mut queue: VecDeque<Item> = VecDeque::from([Item::Insn(entry)]);
    while let Some(item) = queue.pop_front() {
        let i = match item {
            Item::Insn(i) => i,
            Item::Call { target, fall } => {
                if stops(target, stack) {
                    continue;
                }
                match code.at(fall) {
                    Some(f) => {
                        queue.push_front(Item::Insn(f));
                        continue;
                    }
                    None => return true,
                }
            }
        };
        if seen.len() <= i {
            seen.resize(code.insns.len().max(i + 1), false);
        }
        if std::mem::replace(&mut seen[i], true) {
            continue;
        }
        let insn = &code.insns[i];
        if insn.trap {
            continue;
        }
        let next = insn.address + insn.length as u64;
        let mut falls = true;
        let mut targets: SmallVec<[u64; 2]> = SmallVec::new();
        for ev in &insn.events {
            match *ev {
                Event::Exit => return true,
                Event::Branch { uncond, target } => {
                    if uncond {
                        falls = false;
                    }
                    // (a branch inside the instruction's own p-code — rep, cmov — has none)
                    if let Some(t) = target {
                        targets.push(t);
                    }
                }
                Event::Call(t) => {
                    if !named(t) {
                        queue.push_back(Item::Call { target: t, fall: next });
                    }
                    falls = false;
                }
            }
        }
        if falls {
            targets.push(next);
        }
        for t in targets {
            if named(t) {
                continue; // a tail call to an import that never returns
            }
            match code.at(t) {
                Some(j) => queue.push_front(Item::Insn(j)),
                None => return true,
            }
        }
    }
    false
}

/// Append a [`NORETURN_MARK`] op to every direct call in `insns` whose callee never returns.
/// Returns how many calls were marked.
pub fn mark_noreturn_calls(insns: &mut [LiftedInstruction], oracle: &NoReturn<'_>) -> usize {
    let mut marked = 0;
    for insn in insns.iter_mut() {
        let target = insn
            .ops
            .iter()
            .find(|op| op.opcode == OpCode::Call)
            .and_then(|op| op.inputs.first())
            .filter(|t| t.space == SpaceId::RAM)
            .map(|t| t.offset);
        // (a trap is not marked; asked only of a call: its text may be formatted for it)
        if let Some(t) = target
            && !crate::cfg::is_trap(insn)
            && oracle.is_noreturn(t)
        {
            insn.ops.push(marker(insn.address, insn.ops.len() as u32));
            marked += 1;
        }
    }
    marked
}

fn marker(addr: u64, seq: u32) -> PcodeOp {
    PcodeOp {
        opcode: OpCode::CallOther,
        seq: SeqNum::new(Address::new(SpaceId::RAM, addr), seq),
        output: None,
        inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId::CONST, NORETURN_MARK, 4)]),
    }
}

/// Is `op` the marker of a call that never returns?
pub fn is_marker(op: &PcodeOp) -> bool {
    op.opcode == OpCode::CallOther
        && op.inputs.first().is_some_and(|c| c.space == SpaceId::CONST && c.offset == NORETURN_MARK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Endian;
    use reargo_lift::x86::X86Lifter;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    #[test]
    fn generic_flows_round_trip() {
        let at = 0x8_1000u64;
        let flows = [
            None,
            Some(Flow { address: at, length: 2, trap: false, events: SmallVec::new() }),
            Some(Flow { address: at, length: 4, trap: true, events: SmallVec::from_slice(&[Event::Exit]) }),
            Some(Flow { address: at, length: 4, trap: false, events: SmallVec::from_slice(&[Event::Call(at - 0x1_fff0)]) }),
            Some(Flow { address: at, length: 2, trap: false, events: SmallVec::from_slice(&[Event::Branch { uncond: false, target: Some(at + 0x1_fffe) }, Event::Exit]) }),
            Some(Flow { address: at, length: 4, trap: false, events: SmallVec::from_slice(&[Event::Branch { uncond: true, target: None }]) }),
            // (too far, two targets, an address past 32 bits: kept as they are)
            Some(Flow { address: at, length: 4, trap: false, events: SmallVec::from_slice(&[Event::Call(at + 0x2_0000)]) }),
            Some(Flow { address: at, length: 4, trap: false, events: SmallVec::from_slice(&[Event::Call(at + 8), Event::Branch { uncond: true, target: Some(at + 4) }]) }),
        ];
        for f in &flows {
            let mut g = GenericFlows::default();
            g.insert((at, None), f, None);
            assert_eq!(g.get((at, None)), Some((f.clone(), None)));
            assert_eq!(g.get((at, Some((0x18, at)))), None);
            let it = Some((0x18, at + 2));
            g.insert((at, Some((0x14, at))), f, it);
            assert_eq!(g.get((at, Some((0x14, at)))), Some((f.clone(), it)));
        }
        let far = 0x1_0000_1000u64;
        let f = Some(Flow { address: far, length: 4, trap: false, events: SmallVec::new() });
        let mut g = GenericFlows::default();
        g.insert((far, None), &f, None);
        assert_eq!(g.get((far, None)), Some((f, None)));
        assert!(g.packed.is_empty());
    }

    fn mem(parts: &[(u64, &[u8])]) -> Memory {
        let mut m = Memory::new(SpaceId(1), Endian::Little);
        for (i, (addr, data)) in parts.iter().enumerate() {
            m.add_block(MemoryBlock {
                name: format!(".text{i}"),
                start: *addr,
                size: data.len() as u64,
                flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
                data: Some(Arc::from(*data)),
            });
        }
        m
    }

    #[test]
    fn names() {
        assert!(is_noreturn_name("_Unwind_Resume@plt"));
        assert!(is_noreturn_name("abort@GLIBC_2.2.5"));
        assert!(is_noreturn_name("__cxa_throw"));
        assert!(!is_noreturn_name("abort_message"));
        assert!(!is_noreturn_name("malloc@plt"));
    }

    #[test]
    fn import_by_name() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[(0x2000, &[0xff, 0x25, 0, 0, 0, 0])]); // jmp [rip] (a PLT stub)
        let syms = BTreeMap::from([(0x2000u64, "abort@plt".to_string())]);
        assert!(NoReturn::new(&lifter, &m, Some(&syms)).is_noreturn(0x2000));
        assert!(!NoReturn::new(&lifter, &m, None).is_noreturn(0x2000), "a PLT stub is unknown");
    }

    /// The control flow of an instruction lifted alone is the one it has in a range lift that
    /// adds the integer PF and the x87 stack ([`FlowCache`]).
    #[test]
    fn flow_alone_equals_flow_in_a_range() {
        let lifter = X86Lifter::new_64();
        let code: &[u8] = &[
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x7a, 0x02, // jp +2 (reads the integer PF)
            0xd9, 0x07, // fld dword [rdi]
            0xde, 0xc1, // faddp st(1), st
            0xf3, 0xa4, // rep movsb (a branch inside its p-code)
            0xe8, 0x10, 0x00, 0x00, 0x00, // call +0x10
            0xdd, 0x1e, // fstp qword [rsi]
            0xff, 0xe0, // jmp rax
            0xcc, // int3
            0x0f, 0x0b, // ud2
            0xc3, // ret
        ];
        let m = mem(&[(0x1000, code)]);
        let x86 = lifter.as_x86().unwrap();
        for start in 0..code.len() as u64 {
            let range = lifter.lift_range(&m, 0x1000 + start, 40).unwrap();
            for insn in &range {
                let alone = x86.lift_alone(&m, insn.address).unwrap();
                assert_eq!(Flow::of(insn), Flow::of(&alone), "{:#x}", insn.address);
            }
        }
    }

    /// A packed flow unpacks to the same flow; one that does not fit stays as it is.
    #[test]
    fn packed_flows() {
        let lifter = X86Lifter::new_64();
        let code: &[u8] = &[
            0x74, 0x02, // je +2
            0xf3, 0xa4, // rep movsb (a branch inside its p-code)
            0xe8, 0x10, 0x00, 0x00, 0x00, // call +0x10
            0xe9, 0x00, 0x01, 0x00, 0x00, // jmp +0x100
            0xff, 0xe0, // jmp rax
            0xcc, // int3
            0x48, 0x89, 0xc3, // mov rbx, rax
            0xc3, // ret
        ];
        let m = mem(&[(0x1000, code)]);
        let x86 = lifter.as_x86().unwrap();
        let mut shard = FlowShard::default();
        let mut at = 0x1000;
        while at < 0x1000 + code.len() as u64 {
            let f = x86.lift_alone(&m, at).ok().map(|i| Flow::of(&i));
            shard.insert(at, &f);
            assert_eq!(shard.get(at), Some(f.clone()), "{at:#x}");
            if let Some(p) = FlowShard::pack(&f) {
                assert_eq!(FlowShard::unpack(at, p), f);
            }
            at += u64::from(f.unwrap().length);
        }
        assert_eq!(FlowShard::unpack(0x5000, FlowShard::pack(&None).unwrap()), None);
        let far = Flow { address: 0x9000, length: 5, trap: false, events: SmallVec::from_slice(&[Event::Call(0x1_0000_9000)]) };
        assert_eq!(FlowShard::pack(&Some(far.clone())), None);
        shard.insert(0x9000, &Some(far.clone()));
        assert_eq!(shard.get(0x9000), Some(Some(far)));
    }

    #[test]
    fn trap_and_returning_functions() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[
            // 0x2000: test edi, edi ; je 0x2006 ; ud2 ; 0x2006: ud2  (both paths trap)
            (0x2000, &[0x85, 0xff, 0x74, 0x02, 0x0f, 0x0b, 0x0f, 0x0b]),
            // 0x3000: test edi, edi ; je 0x3006 ; ud2 ; 0x3006: ret  (one path returns)
            (0x3000, &[0x85, 0xff, 0x74, 0x02, 0x0f, 0x0b, 0xc3]),
            // 0x4000: test edi, edi ; je 0x4006 ; ud2 ; (end of the code: nothing at 0x4006)
            (0x4000, &[0x85, 0xff, 0x74, 0x02, 0x0f, 0x0b]),
        ]);
        let o = NoReturn::new(&lifter, &m, None);
        assert!(o.is_noreturn(0x2000));
        assert!(!o.is_noreturn(0x3000));
        // a branch off the end of what could be lifted is not proof
        assert!(!o.is_noreturn(0x4000));
    }

    #[test]
    fn calls_into_noreturn_functions_propagate() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[
            // 0x2000: mov edi, 1 ; call 0x3000 ; 0x200a: ret (never reached)
            (0x2000, &[0xbf, 0x01, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0xc3]),
            // 0x3000: call 0x4000 ; 0x3005 ud2
            (0x3000, &[0xe8, 0xfb, 0x0f, 0, 0, 0x0f, 0x0b]),
            // 0x4000: ud2
            (0x4000, &[0x0f, 0x0b]),
            // 0x5000: call 0x6000 ; ret      0x6000: ret
            (0x5000, &[0xe8, 0xfb, 0x0f, 0, 0, 0xc3]),
            (0x6000, &[0xc3]),
        ]);
        let o = NoReturn::new(&lifter, &m, None);
        assert!(o.is_noreturn(0x4000));
        assert!(o.is_noreturn(0x3000));
        assert!(o.is_noreturn(0x2000));
        assert!(!o.is_noreturn(0x5000));
        assert!(!o.is_noreturn(0x6000));
    }

    #[test]
    fn tail_jumps_are_followed() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[
            (0x2000, &[0xe9, 0xfb, 0x0f, 0, 0]), // jmp 0x3000
            (0x3000, &[0x0f, 0x0b]),             // ud2
            (0x4000, &[0xe9, 0xfb, 0x0f, 0, 0]), // jmp 0x5000 (abort@plt)
            (0x5000, &[0xff, 0x25, 0, 0, 0, 0]),
            (0x6000, &[0xe9, 0xfb, 0x0f, 0, 0]), // jmp 0x7000
            (0x7000, &[0xc3]),
        ]);
        let syms = BTreeMap::from([(0x5000u64, "abort@plt".to_string())]);
        let o = NoReturn::new(&lifter, &m, Some(&syms));
        assert!(o.is_noreturn(0x2000));
        assert!(o.is_noreturn(0x4000));
        assert!(!o.is_noreturn(0x6000));
    }

    #[test]
    fn recursion() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[
            // 0x2000: call 0x2000 ; ud2  (recursion or a trap: never returns)
            (0x2000, &[0xe8, 0xfb, 0xff, 0xff, 0xff, 0x0f, 0x0b]),
            // 0x3000: test edi, edi ; je 0x300b ; call 0x3000 ; ud2 ; 0x300b: ret
            (0x3000, &[0x85, 0xff, 0x74, 0x07, 0xe8, 0xf7, 0xff, 0xff, 0xff, 0x0f, 0x0b, 0xc3]),
        ]);
        let o = NoReturn::new(&lifter, &m, None);
        assert!(o.is_noreturn(0x2000));
        assert!(!o.is_noreturn(0x3000));
    }
}
