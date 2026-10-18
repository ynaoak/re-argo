//! Which argument registers does a callee read? (WS78)
//!
//! The pipeline gives every call all of the calling convention's argument
//! registers and `optimize::prune_call_args` decides which of them are the
//! call's arguments. Looking only at the caller has two failure modes:
//!
//! * an argument the caller passes straight through from its own incoming
//!   registers (`f(this, 5)` with `this` still in `rdi`) has no setup
//!   instruction, so it looked like "not an argument";
//! * a register left over from earlier work (`rcx` of a loop counter,
//!   `xmm3..6` of an earlier computation) looked like one.
//!
//! For a direct call the callee's code answers the question: an argument
//! register the callee reads before writing it on some path from its entry is
//! a parameter. This module lifts the callee and runs that "read before
//! written" (must-defined) analysis over its CFG.
//!
//! Details that keep the answer honest on compiled x86-64:
//! * a register counts as read only when the read covers its low byte, so the
//!   lifter's view-sync ops (`SUBPIECE(xmm0, 8)` to rebuild the upper lanes
//!   after a scalar write, `SUBPIECE(rdi, 1)` after `mov dil, ..`) are not
//!   reads of a parameter;
//! * `xor esi, esi` / `sub esi, esi` (zero idioms) do not read `esi`;
//! * a call inside the callee clobbers every argument register; the
//!   arguments *it* passes through are the callee's reads too, found by
//!   analysing that inner callee (depth-limited). An inner call whose
//!   callee is unknown (indirect, past the depth limit, or itself only a
//!   lower bound such as a PLT stub) is assumed to take the contiguous
//!   prefix of each register class up to the highest register the callee
//!   has set up — the System V rule;
//! * a tail `jmp` out of the lifted body is treated as such a call;
//! * an indirect jump (jump table, PLT stub) or a body longer than the lift
//!   limit makes the answer a lower bound (`complete == false`): reads may
//!   be missing, so the caller must not drop arguments on its strength.

use std::sync::Mutex;

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, PcodeOp, VarnodeData};
use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_loader::Memory;
use rustc_hash::FxHashMap;

use crate::cfg::ControlFlowGraph;

/// Parameters of a callee as a bit set over the convention's argument
/// registers (`bit i` = `CallConvention::args[i]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParamInfo {
    pub mask: u32,
    /// `false` when the analysis could not see the whole body: `mask` is then
    /// a lower bound.
    pub complete: bool,
}

/// Instruction limit for one callee body.
const MAX_INSNS: usize = 3000;
/// How many call levels below the analysed callee are followed to find
/// pass-through arguments.
const MAX_DEPTH: u32 = 2;

/// Callee parameter oracle with a memo shared by every lookup (safe to share
/// across threads, e.g. by `decompile_all`).
pub struct CalleeParams<'a> {
    pub(crate) lifter: &'a dyn PcodeLift,
    pub(crate) memory: &'a Memory,
    pub(crate) args: Vec<VarnodeData>,
    /// Register class of each argument (index into `class_members`).
    class_of: Vec<usize>,
    /// Arguments of each class, in parameter order.
    class_members: Vec<Vec<usize>>,
    /// The space every argument is in, if they share one, and `(offset, 1 << arg)` of each
    /// argument by offset (for [`Self::covering`]).
    arg_space: Option<SpaceId>,
    arg_offsets: Vec<(u64, u32)>,
    /// When every argument's offset is a multiple of 8: per 8-byte step `g` up to the last
    /// argument, the index in `arg_offsets` of the first argument at or above `8 * g` (the
    /// [`Self::covering`] search of an offset, looked up).
    first_at: Vec<u8>,
    memo: Mutex<FxHashMap<(u64, u32), Option<ParamInfo>>>,
    /// The convention's return registers (`rax`, `xmm0`).
    pub(crate) returns: Vec<VarnodeData>,
    ret_memo: Mutex<FxHashMap<(u64, u32), ReturnKind>>,
    /// Registers a call may change (the convention's returns and clobbers).
    pub(crate) caller_saved: Vec<VarnodeData>,
    /// How a callee uses its pointer parameters (WS91), by callee.
    fields_memo: Mutex<FxHashMap<u64, std::sync::Arc<ParamUse>>>,
    /// The address of `.eh_frame_hdr` (the function covering an address), when known (WS92).
    pub(crate) unwind_table: Option<u64>,
    /// The classes of the objects a class's constructors store in its fields (WS92,
    /// `classfields`), by the class's vtable.
    pub(crate) class_fields_memo: Mutex<FxHashMap<u64, ClassFields>>,
    /// The lifted-once, depth-independent analysis of each body.
    summary_memo: Mutex<FxHashMap<u64, Option<std::sync::Arc<Summary>>>>,
    /// What [`Self::summarize_compact`] reads of each instruction lifted alone, shared by the
    /// bodies (x86, a batch with [`Self::with_entries`]): the bodies at addresses inside
    /// functions overlap (where `.cold` parts jump back to), each instruction is lifted once.
    compact: Option<CompactTable>,
    /// The functions' entries, in increasing order ([`Self::with_entries`]).
    entries: Vec<u64>,
    /// The lengths and flags of the instructions lifted alone, for the range walks (x86).
    facts: Option<reargo_lift::x86::InsnFacts>,
    /// The lifts of the ranges a walk cannot answer (x87 code, the integer PF), for
    /// [`reargo_lift::x86::X86Lifter::lift_range_cached`] (x86): the ranges from the entries
    /// of neighbouring functions and from the addresses `.cold` parts jump back to overlap
    /// over most of their 3000 instructions.
    range_cache: Option<Mutex<reargo_lift::x86::LiftCache>>,
    /// The direct call sites by target, when a batch built them ([`Self::with_call_index`]).
    call_index: Option<crate::callers::CallIndex>,
    /// [`crate::callers::return_hint`] by function.
    hint_memo: Mutex<FxHashMap<u64, Option<crate::callers::ReturnHint>>>,
    /// The control flow of the instructions the no-return searches read (x86).
    flow_cache: Option<crate::noreturn::FlowCache>,
    /// The RELATIVE relocations' slots by value, and the vtables of each function.
    reloc_slots: std::sync::OnceLock<Option<FxHashMap<u64, Vec<u64>>>>,
    vtables_memo: Mutex<FxHashMap<u64, Vec<u64>>>,
}

/// `(offset, vtable)`: the fields of a class holding objects of a known class (WS92,
/// `classfields`).
pub type ClassFields = std::sync::Arc<Vec<(u64, u64)>>;

/// How a function uses its pointer parameters (WS91).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParamUse {
    /// The memory it accesses through them.
    pub fields: Vec<ParamAccess>,
    /// Every `ret` returns the first argument's incoming value: a struct returned in memory
    /// (`rdi` is the result's address, so a method's `this` is the second argument).
    pub returns_first: bool,
    /// Constants it stores at offset 0 of a parameter, 8 bytes (WS92): the vtable a constructor
    /// or destructor puts into its `this` (`(arg, value)`; whether a value is a vtable is for
    /// the caller to check).
    pub vtable_stores: Vec<(usize, u64)>,
}

/// A memory access a function makes through one of its parameters (WS91): `*(T*)(param + off)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamAccess {
    /// the parameter (index into the convention's arguments)
    pub arg: usize,
    pub off: u64,
    pub size: u32,
}

/// Which return register a callee leaves its result in (WS79).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnKind {
    /// The integer register (`rax`).
    Int,
    /// The vector register (`xmm0`): a `float` / `double`.
    Float,
    /// Not known (no `ret` found, a `ret` straight after a call to an unknown function, or
    /// `ret`s that disagree).
    Unknown,
}

impl<'a> CalleeParams<'a> {
    /// `None` when the lifter has no calling convention.
    pub fn new(lifter: &'a dyn PcodeLift, memory: &'a Memory) -> Option<Self> {
        let cc = lifter.call_convention()?;
        let (class_of, class_members) = arg_classes(&cc.args);
        let arg_space = cc.args.first().map(|a| a.space).filter(|&sp| cc.args.iter().all(|a| a.space == sp));
        let mut arg_offsets: Vec<(u64, u32)> = cc.args.iter().enumerate().map(|(i, a)| (a.offset, 1u32 << i)).collect();
        arg_offsets.sort_unstable();
        let first_at = match arg_offsets.last() {
            Some(&(last, _)) if arg_offsets.iter().all(|&(o, _)| o % 8 == 0) && last < 1 << 16 && arg_offsets.len() < 256 => {
                (0..=last / 8).map(|g| arg_offsets.partition_point(|&(off, _)| off < 8 * g) as u8).collect()
            }
            _ => Vec::new(),
        };
        Some(Self {
            arg_space,
            arg_offsets,
            first_at,
            lifter,
            memory,
            args: cc.args,
            class_of,
            class_members,
            memo: Mutex::new(FxHashMap::default()),
            returns: cc.returns.iter().map(|(r, _)| *r).collect(),
            ret_memo: Mutex::new(FxHashMap::default()),
            caller_saved: cc.returns.iter().chain(cc.clobbers.iter()).map(|(r, _)| *r).collect(),
            fields_memo: Mutex::new(FxHashMap::default()),
            unwind_table: None,
            class_fields_memo: Mutex::new(FxHashMap::default()),
            summary_memo: Mutex::new(FxHashMap::default()),
            compact: None,
            entries: Vec::new(),
            facts: lifter.as_x86().map(|_| reargo_lift::x86::InsnFacts::new(memory)),
            range_cache: lifter.as_x86().map(|_| Mutex::new(reargo_lift::x86::LiftCache::new())),
            call_index: None,
            hint_memo: Mutex::new(FxHashMap::default()),
            flow_cache: lifter.as_x86().map(|_| crate::noreturn::FlowCache::new()),
            reloc_slots: std::sync::OnceLock::new(),
            vtables_memo: Mutex::new(FxHashMap::default()),
        })
    }

    /// The same oracle knowing the functions' entries (for a batch of decompiles): a body at
    /// another address (inside a function, where a `.cold` part jumps back to it; a stub) is
    /// summarised from the compact lifts of its instructions, shared by the bodies that
    /// overlap it, without its parameter accesses until they are asked for. A function's own
    /// body is lifted and analysed whole: its accesses are almost always asked for (it is
    /// called directly from some function decompiled).
    pub fn with_entries(mut self, mut entries: Vec<u64>) -> Self {
        entries.sort_unstable();
        entries.dedup();
        self.entries = entries;
        self.compact = self.lifter.as_x86().map(|_| CompactTable::new(self.memory));
        self
    }

    /// The same oracle with the direct call sites of the whole binary indexed once (for a batch
    /// of decompiles: each looks its callers up).
    pub fn with_call_index(mut self) -> Self {
        self.call_index = crate::callers::CallIndex::build(self.memory);
        self
    }

    /// [`crate::vcall::this_vtables`]`(memory, f)`, memoised, from an index of the relocations
    /// built once.
    pub(crate) fn this_vtables(&self, f: u64) -> Vec<u64> {
        let Some(slots) = self.reloc_slots.get_or_init(|| crate::vcall::relative_slots(self.memory)) else {
            return crate::vcall::this_vtables(self.memory, f);
        };
        if let Some(v) = self.vtables_memo.lock().ok().and_then(|m| m.get(&f).cloned()) {
            return v;
        }
        let v = crate::vcall::this_vtables_indexed(self.memory, slots, f);
        if let Ok(mut m) = self.vtables_memo.lock() {
            m.insert(f, v.clone());
        }
        v
    }

    /// [`crate::vcall::vtables_listing`]`(memory, targets)` through [`Self::this_vtables`].
    pub(crate) fn vtables_listing(&self, targets: &[u64]) -> FxHashMap<u64, Vec<u64>> {
        let mut out = FxHashMap::default();
        for &f in targets {
            let v = self.this_vtables(f);
            if !v.is_empty() {
                out.insert(f, v);
            }
        }
        out
    }

    /// The control-flow cache the no-return searches of this oracle's batch share.
    pub(crate) fn flow_cache(&self) -> Option<&crate::noreturn::FlowCache> {
        self.flow_cache.as_ref()
    }

    /// [`crate::callers::return_hint`]`(lifter, memory, target)`, memoised.
    pub fn return_hint(&self, target: u64) -> Option<crate::callers::ReturnHint> {
        if let Some(h) = self.hint_memo.lock().ok().and_then(|m| m.get(&target).copied()) {
            return h;
        }
        let h = match &self.call_index {
            Some(index) => crate::callers::return_hint_indexed(self.lifter, self.memory, target, index),
            None => crate::callers::return_hint(self.lifter, self.memory, target),
        };
        if let Ok(mut m) = self.hint_memo.lock() {
            m.insert(target, h);
        }
        h
    }

    /// The same oracle, finding the function that covers an address through the
    /// `.eh_frame_hdr` table at `hdr` (WS92, `classfields`).
    pub fn with_unwind_table(mut self, hdr: Option<u64>) -> Self {
        self.unwind_table = hdr;
        self
    }

    /// The memory the function at `target` accesses through its parameters (WS91): every
    /// load / store whose address is a parameter's incoming value plus a constant (followed
    /// through copies, constant adds and the registers a call keeps), found while its
    /// parameters are analysed. `None` when it cannot be lifted.
    pub fn param_use(&self, target: u64) -> Option<std::sync::Arc<ParamUse>> {
        self.params(target)?;
        if let Some(f) = self.fields_memo.lock().ok()?.get(&target).cloned() {
            return Some(f);
        }
        // (a body summarised without them, below a call: its accesses from its lift)
        let f = self.body(target).map(|(cfg, _)| std::sync::Arc::new(self.param_accesses_of(&cfg, &crate::dominator::reverse_post_order(&cfg)))).unwrap_or_default();
        Some(self.fields_memo.lock().ok()?.entry(target).or_insert(f).clone())
    }

    pub fn args(&self) -> &[VarnodeData] {
        &self.args
    }

    /// Parameters of the function at `target`, or `None` when it cannot be
    /// lifted.
    pub fn params(&self, target: u64) -> Option<ParamInfo> {
        self.params_at(target, MAX_DEPTH)
    }

    /// Which register the function at `target` returns its value in (WS79): at each `ret`,
    /// the return register it wrote last (looking back through straight-line predecessors);
    /// a `ret` right after a call returns what that callee returns (depth-limited).
    pub fn return_kind(&self, target: u64) -> ReturnKind {
        self.return_kind_at(target, MAX_DEPTH)
    }

    fn return_kind_at(&self, target: u64, depth_left: u32) -> ReturnKind {
        if self.returns.len() < 2 {
            return ReturnKind::Unknown;
        }
        let memo = |s: &Self| s.ret_memo.lock().ok().and_then(|m| m.get(&(target, depth_left)).copied());
        if let Some(r) = memo(self) {
            return r;
        }
        // the parameter analysis lifts the body once and answers this too
        self.params_at(target, depth_left);
        memo(self).unwrap_or(ReturnKind::Unknown)
    }

    /// What each `ret` of a lifted body returns (see `return_kind`): the return register it
    /// wrote last (looking back through straight-line predecessors), or the call right before
    /// it, whose callee's return kind is looked up at the depth asked.
    fn return_sites(&self, cfg: &ControlFlowGraph) -> Vec<RetSite> {
        let mut kinds = Vec::new();
        if self.returns.len() < 2 {
            return kinds;
        }
        let (int_reg, float_reg) = (self.returns[0], self.returns[1]);
        for b in 0..cfg.blocks.len() {
            if !cfg.blocks[b].is_return() {
                continue;
            }
            let mut cur = b;
            let mut steps = 0;
            let kind = 'search: loop {
                for insn in cfg.blocks[cur].instructions.iter().rev() {
                    for op in insn.ops.iter().rev() {
                        if matches!(op.opcode, OpCode::Call | OpCode::CallInd) {
                            let callee = (op.opcode == OpCode::Call)
                                .then(|| op.inputs.first())
                                .flatten()
                                .filter(|t| t.space == SpaceId::RAM);
                            break 'search RetSite::Call(callee.map(|t| t.offset));
                        }
                        let Some(out) = op.output else { continue };
                        if out.space != SpaceId::REGISTER {
                            continue;
                        }
                        if out.offset == int_reg.offset && out.size <= int_reg.size {
                            break 'search RetSite::Kind(ReturnKind::Int);
                        }
                        // a scalar float result (`xmm0_d` / `xmm0_q`, not the lifter's view sync),
                        // or a whole-register copy from another vector register
                        let scalar = out.offset == float_reg.offset
                            && (out.size == 4 || out.size == 8)
                            && !matches!(op.opcode, OpCode::Piece | OpCode::Subpiece);
                        let copy = out.offset == float_reg.offset
                            && out.size == float_reg.size
                            && op.opcode == OpCode::Copy
                            && op.inputs.first().is_some_and(|i| i.space == SpaceId::REGISTER && i.size == float_reg.size);
                        if scalar || copy {
                            break 'search RetSite::Kind(ReturnKind::Float);
                        }
                    }
                }
                let preds = &cfg.blocks[cur].predecessors;
                steps += 1;
                if preds.len() != 1 || steps > 8 {
                    break RetSite::Kind(ReturnKind::Unknown);
                }
                cur = preds[0];
            };
            kinds.push(kind);
        }
        kinds
    }

    /// The return register of a summarised body at `depth_left` (see `return_kind`).
    fn return_kind_of(&self, sites: &[RetSite], depth_left: u32) -> ReturnKind {
        if self.returns.len() < 2 {
            return ReturnKind::Unknown;
        }
        let mut kinds = Vec::with_capacity(sites.len());
        for s in sites {
            kinds.push(match *s {
                RetSite::Kind(k) => k,
                RetSite::Call(Some(t)) if depth_left > 0 => self.return_kind_at(t, depth_left - 1),
                RetSite::Call(_) => ReturnKind::Unknown,
            });
        }
        let any = |k| kinds.contains(&k);
        match (any(ReturnKind::Int), any(ReturnKind::Float)) {
            (true, false) => ReturnKind::Int,
            (false, true) => ReturnKind::Float,
            _ => ReturnKind::Unknown,
        }
    }

    fn params_at(&self, target: u64, depth_left: u32) -> Option<ParamInfo> {
        if let Some(r) = self.memo.lock().ok().and_then(|m| m.get(&(target, depth_left)).copied()) {
            return r;
        }
        // no "in progress" marker: the depth limit already bounds recursion
        // (f -> g -> f), and a marker would let a concurrent lookup see a
        // half-done answer
        let r = self.analyze(target, depth_left);
        if let Ok(mut m) = self.memo.lock() {
            m.insert((target, depth_left), r);
        }
        r
    }

    /// The body of the function at `target` as a CFG (up to its returns; `None` when it cannot
    /// be lifted).
    pub(crate) fn body_cfg(&self, target: u64) -> Option<ControlFlowGraph> {
        let lifted = self.lifter.lift_range(self.memory, target, MAX_INSNS).ok()?;
        if lifted.is_empty() || lifted[0].address != target {
            return None;
        }
        Some(ControlFlowGraph::build_owned(crate::pipeline::trim_to_return(lifted)))
    }

    /// `keep_fde_body(lift_range(start, count), lo, hi)` (the instructions in `[lo, hi)` and the
    /// `int3`s right after `hi`), lifting only those when the range is the lifts of its
    /// instructions alone; with whether the range was empty. `None` when it must be lifted as
    /// a whole.
    pub(crate) fn lift_fde_body(&self, start: u64, count: usize, lo: u64, hi: u64) -> Option<(bool, Vec<LiftedInstruction>)> {
        let x86 = self.lifter.as_x86()?;
        // (the range's instructions, stepping over the spans of other walks: only those up to
        // the body's end and the `int3`s after it are looked at)
        let walk = x86.plain_walk(self.memory, start, count, self.facts.as_ref()?, false)?;
        let mut out = Vec::new();
        let mut next = hi;
        let mut cursor = reargo_lift::x86::DecodeCursor::default();
        let mut failed = false;
        walk.each(|a| {
            if a >= lo && a < hi {
                match x86.lift_alone_with(self.memory, a, &mut cursor) {
                    Ok(insn) => out.push(insn),
                    Err(_) => failed = true,
                }
            } else if a == next {
                match x86.lift_alone_with(self.memory, a, &mut cursor) {
                    Ok(insn) if insn.mnemonic.trim() == "int3" => {
                        next += u64::from(insn.length);
                        out.push(insn);
                    }
                    Ok(_) => {}
                    Err(_) => failed = true,
                }
            } else if a > next && a >= hi {
                // (the addresses increase: none after it is in the body or the `int3`s)
                return false;
            }
            !failed
        });
        (!failed).then_some((!walk.is_empty(), out))
    }

    /// The depth-independent part of the analysis of the function at `target`, lifted once
    /// and shared by every depth (`None` when it cannot be lifted).
    ///
    /// A function's body (or any, without [`Self::with_entries`]) is lifted and analysed as
    /// a whole; another from the [`CompactTable`] when it can be, without the accesses
    /// ([`Self::param_use`] finds them when asked).
    fn summary(&self, target: u64) -> Option<std::sync::Arc<Summary>> {
        if let Some(s) = self.summary_memo.lock().ok().and_then(|m| m.get(&target).cloned()) {
            return s;
        }
        let light = self.compact.is_some() && self.entries.binary_search(&target).is_err();
        let s = if light { self.summarize_light(target) } else { self.summarize(target) }.map(std::sync::Arc::new);
        if let Ok(mut m) = self.summary_memo.lock() {
            m.insert(target, s.clone());
        }
        s
    }

    fn summarize(&self, target: u64) -> Option<Summary> {
        let (cfg, truncated) = self.body(target)?;
        Some(self.summarize_body(cfg, truncated))
    }

    /// [`Self::summarize`] without the parameter accesses, from the [`CompactTable`] when the
    /// body is the lifts of its instructions alone.
    fn summarize_light(&self, target: u64) -> Option<Summary> {
        if let (Some(x86), Some(facts), Some(table)) = (self.lifter.as_x86(), &self.facts, &self.compact)
            && let Some(walk) = x86.plain_walk(self.memory, target, MAX_INSNS, facts, true)
            && let Some(s) = self.summarize_compact(x86, table, target, &walk)
        {
            return Some(s);
        }
        self.summarize(target)
    }

    /// The body [`Self::summarize`] analyses: the CFG of the instructions of
    /// `trim_to_return(lift_range(target, MAX_INSNS))`, and whether it runs past the limit.
    fn body(&self, target: u64) -> Option<(ControlFlowGraph, bool)> {
        if let (Some(x86), Some(facts)) = (self.lifter.as_x86(), &self.facts)
            && let Some(walk) = x86.plain_walk(self.memory, target, MAX_INSNS, facts, true)
            && let Some(b) = self.body_plain(x86, target, &walk)
        {
            return Some(b);
        }
        let (insns, len, first, last) = match (self.lifter.as_x86(), self.range_cache.as_ref().and_then(|c| c.lock().ok())) {
            // (`trim_to_return(lift_range(…))` from the lifts of the range's instructions alone,
            // cloning those the trim keeps)
            (Some(x86), Some(mut cache)) => x86.lift_range_cached_kept(self.memory, target, MAX_INSNS, &mut cache, &mut |all| crate::pipeline::reachability(all)),
            _ => {
                let lifted = self.lifter.lift_range(self.memory, target, MAX_INSNS).ok()?;
                let (len, first, last) = (lifted.len(), lifted.first().map(|i| i.address), lifted.last().map(|i| i.address));
                (crate::pipeline::trim_to_return(lifted), len, first, last)
            }
        };
        if len == 0 || first != Some(target) {
            return None;
        }
        let hit_limit = len >= MAX_INSNS;
        // the body runs past the lift limit (its last lifted instruction is live)
        let truncated = hit_limit && insns.last().map(|i| i.address) == last;
        Some((ControlFlowGraph::build_owned(insns), truncated))
    }

    /// [`Self::body`] of a range that is the lifts of the walk's instructions alone
    /// ([`reargo_lift::x86::X86Lifter::plain_walk`]; with the integer PF when the walk needs
    /// it): only the instructions the trim keeps are lifted.
    fn body_plain(&self, x86: &reargo_lift::x86::X86Lifter, target: u64, walk: &reargo_lift::x86::PlainWalk<'_>) -> Option<(ControlFlowGraph, bool)> {
        if walk.first() != Some(target) {
            return None;
        }
        // (the stack holds addresses: those of a walk increase with their index)
        let idx_of = |a: u64| walk.index_of(a).map(|_| a as usize);
        // (the walk's instructions follow each other: the one after any but the last is in it)
        let last = walk.last();
        // (the addresses seen, by their offset from the target: every one is in the walk)
        let mut seen = vec![0u64; (last.map_or(0, |l| l - target) as usize + 1).div_ceil(64)];
        // (room for the whole walk: the instructions are large, and growing moved them)
        let mut lifted: Vec<(usize, LiftedInstruction)> = Vec::with_capacity(walk.len());
        let mut stack = vec![target as usize];
        let mut cursor = reargo_lift::x86::DecodeCursor::default();
        while let Some(a) = stack.pop() {
            let off = a - target as usize;
            if seen[off / 64] >> (off % 64) & 1 != 0 {
                continue;
            }
            seen[off / 64] |= 1 << (off % 64);
            // (the range lift with the integer PF: each instruction lifted alone with it)
            let insn = if walk.needs_pf {
                self.lifter.lift_instruction(self.memory, a as u64)
            } else {
                x86.lift_alone_with(self.memory, a as u64, &mut cursor)
            }
            .ok()?;
            let fall = insn.address + u64::from(insn.length);
            let next_in_walk = Some(insn.address) != last;
            crate::pipeline::reach_successors(&insn, |x| if x == fall && next_in_walk { Some(x as usize) } else { idx_of(x) }, &mut stack);
            lifted.push((a, insn));
        }
        lifted.sort_unstable_by_key(|(a, _)| *a);
        let insns: Vec<LiftedInstruction> = lifted.into_iter().map(|(_, i)| i).collect();
        let hit_limit = walk.len() >= MAX_INSNS;
        let truncated = hit_limit && insns.last().map(|i| i.address) == last;
        Some((ControlFlowGraph::build_owned(insns), truncated))
    }

    /// [`param_accesses`] of a body with this oracle's convention.
    fn param_accesses_of(&self, cfg: &ControlFlowGraph, rpo: &[usize]) -> ParamUse {
        param_accesses(cfg, rpo, &self.args, &self.caller_saved, self.returns.first())
    }

    fn summarize_body(&self, cfg: ControlFlowGraph, truncated: bool) -> Summary {
        let rpo = crate::dominator::reverse_post_order(&cfg);
        let fields = Some(std::sync::Arc::new(self.param_accesses_of(&cfg, &rpo)));
        let ret_sites = self.return_sites(&cfg);
        let n = cfg.blocks.len();

        // must-defined (by low byte) sets at block entry; None = not reached yet
        let mut inn: Vec<Option<u32>> = vec![None; n];
        inn[cfg.entry_block] = Some(0);
        let mut acc = Acc { reads: 0, complete: !truncated, calls: Vec::new() };
        // each block's transfer (`run_block` without `acc`): after a call every argument is
        // defined, else what it writes is added to what was defined on entry
        let all = (1u32 << self.args.len()) - 1;
        let transfer: Vec<Option<u32>> = (0..n).map(|b| self.block_writes(&cfg, b)).collect();
        loop {
            let mut changed = false;
            for &b in &rpo {
                let Some(state) = inn[b] else { continue };
                let out = transfer[b].map_or(all, |w| state | w);
                for &s in &cfg.blocks[b].successors {
                    let new = match inn[s] {
                        None => out,
                        Some(old) => old & out,
                    };
                    if s != cfg.entry_block && inn[s] != Some(new) {
                        inn[s] = Some(new);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        for &b in &rpo {
            if let Some(state) = inn[b] {
                self.run_block(&cfg, b, state, Some(&mut acc));
            }
        }
        Summary { reads: acc.reads, complete: acc.complete, calls: acc.calls, ret_sites, fields }
    }

    fn analyze(&self, target: u64, depth_left: u32) -> Option<ParamInfo> {
        let s = self.summary(target)?;
        if depth_left == MAX_DEPTH
            && let Some(fields) = &s.fields
            && let Ok(mut m) = self.fields_memo.lock()
        {
            m.entry(target).or_insert_with(|| fields.clone());
        }
        let kind = self.return_kind_of(&s.ret_sites, depth_left);
        if let Ok(mut m) = self.ret_memo.lock() {
            m.insert((target, depth_left), kind);
        }
        let mut reads = s.reads;
        for c in &s.calls {
            reads |= self.inner_call_reads(c.target, c.window, depth_left) & !c.defined;
        }
        Some(ParamInfo { mask: reads, complete: s.complete })
    }

    /// The argument registers block `b` writes (`None` when it calls: every argument is then
    /// defined at its end): [`Self::run_block`]'s result is `defined | writes`.
    fn block_writes(&self, cfg: &ControlFlowGraph, b: usize) -> Option<u32> {
        let mut w = 0u32;
        for op in cfg.blocks[b].instructions.iter().flat_map(|i| i.ops.iter()) {
            match op.opcode {
                OpCode::Call | OpCode::CallInd => return None,
                OpCode::Branch | OpCode::BranchInd => continue,
                _ => {}
            }
            if let Some(out) = &op.output {
                w |= self.covering(out.space, out.offset, out.offset + out.size as u64);
            }
        }
        Some(w)
    }

    /// Transfer function of one block; with `acc`, records the reads and the inner calls.
    fn run_block(&self, cfg: &ControlFlowGraph, b: usize, mut defined: u32, mut acc: Option<&mut Acc>) -> u32 {
        let all = (1u32 << self.args.len()) - 1;
        // registers written since the block start / the last call: the setup window an unknown
        // inner callee's argument prefix is judged by (a loop temporary written earlier is not
        // an argument setup)
        let mut window = 0u32;
        for insn in &cfg.blocks[b].instructions {
            // (found when an input is first asked about)
            let mut zeroed = None;
            for op in &insn.ops {
                match op.opcode {
                    OpCode::Call | OpCode::CallInd => {
                        if let Some(a) = acc.as_deref_mut() {
                            let direct = (op.opcode == OpCode::Call)
                                .then(|| op.inputs.first())
                                .flatten()
                                .filter(|t| t.space == SpaceId::RAM)
                                .map(|t| t.offset);
                            a.calls.push(InnerCall { target: direct, window, defined });
                        }
                        defined = all; // every argument register is caller-saved
                        window = 0;
                        continue;
                    }
                    OpCode::Branch => {
                        // a tail call out of the lifted body
                        if let Some(t) = op.inputs.first().filter(|t| t.space == SpaceId::RAM)
                            && cfg.block_at(t.offset).is_none()
                            && let Some(a) = acc.as_deref_mut()
                        {
                            a.calls.push(InnerCall { target: Some(t.offset), window, defined });
                        }
                        continue;
                    }
                    OpCode::BranchInd => {
                        if let Some(a) = acc.as_deref_mut() {
                            a.complete = false;
                        }
                        continue;
                    }
                    _ => {}
                }
                // (a read adds the arguments neither defined nor read yet: none once all are)
                if let Some(a) = acc.as_deref_mut()
                    && defined | a.reads != all
                {
                    for (k, inp) in op.inputs.iter().enumerate() {
                        if inp.space == SpaceId::CONST || zeroed.get_or_insert_with(|| zero_idiom_operands(insn)).contains(inp) {
                            continue;
                        }
                        let (lo, hi) = read_range(op, k, inp);
                        a.reads |= self.covering(inp.space, lo, hi) & !defined;
                    }
                }
                if let Some(out) = &op.output {
                    let w = self.covering(out.space, out.offset, out.offset + out.size as u64);
                    defined |= w;
                    window |= w;
                }
            }
        }
        defined
    }

    /// The argument registers an inner call reads (before masking by what the
    /// caller already defined); `window` = registers set up just before it.
    fn inner_call_reads(&self, target: Option<u64>, window: u32, depth_left: u32) -> u32 {
        if let Some(t) = target
            && depth_left > 0
            && let Some(info) = self.params_at(t, depth_left - 1)
        {
            if info.complete {
                return info.mask;
            }
            // a lower bound (e.g. a PLT stub): add the prefix rule rather than give up on
            // the whole answer
            return info.mask | self.prefix_reads(window);
        }
        self.prefix_reads(window)
    }

    /// Unknown callee: each class's prefix up to the highest register set up for it.
    fn prefix_reads(&self, window: u32) -> u32 {
        let mut reads = 0;
        for members in &self.class_members {
            if let Some(top) = members.iter().rposition(|&i| window & (1 << i) != 0) {
                for &i in &members[..=top] {
                    reads |= 1 << i;
                }
            }
        }
        reads
    }

    /// Arguments whose low byte lies in `[lo, hi)` of `space`.
    #[inline(always)]
    fn covering(&self, space: SpaceId, lo: u64, hi: u64) -> u32 {
        let mut m = 0;
        // (the arguments by offset; `arg_space`: the one space they are all in)
        if let Some(sp) = self.arg_space {
            if space != sp {
                return 0;
            }
            // (the offsets are multiples of 8: the first at or above `lo` is the first at or
            // above `lo` rounded up to one)
            let from = if self.first_at.is_empty() {
                self.arg_offsets.partition_point(|&(off, _)| off < lo)
            } else {
                self.first_at.get(lo.div_ceil(8) as usize).map_or(self.arg_offsets.len(), |&i| usize::from(i))
            };
            for &(off, bit) in &self.arg_offsets[from..] {
                if off >= hi {
                    break;
                }
                m |= bit;
            }
            return m;
        }
        for (i, a) in self.args.iter().enumerate() {
            if a.space == space && lo <= a.offset && a.offset < hi {
                m |= 1 << i;
            }
        }
        m
    }

    /// Register class (index) of argument `i`.
    pub fn class_of(&self, i: usize) -> usize {
        self.class_of[i]
    }
}

/// [`CInsn`]s by address and lift (with the integer PF or not), shared by the threads: per
/// address of the executable memory (in pages allocated when first used) the position of its
/// [`CInsn`] in an append-only arena (in chunks). A lookup reads two cells no other thread
/// writes once they are set, so the threads share the entries without moving cache lines
/// between their cores (as the locks of a shared map do).
struct CompactTable {
    base: u64,
    end: u64,
    /// Per page of addresses, the arena position + 1 of each address's entry (0: none yet),
    /// without and with the PF.
    pages: [Vec<std::sync::OnceLock<Box<[std::sync::atomic::AtomicU32]>>>; 2],
    chunks: Vec<std::sync::OnceLock<Box<[std::sync::OnceLock<CInsn>]>>>,
    next: std::sync::atomic::AtomicUsize,
}

const CT_PAGE_BITS: u32 = 8;
const CT_CHUNK_BITS: u32 = 14;
const CT_CHUNKS: usize = 1 << 12;

impl CompactTable {
    fn new(memory: &Memory) -> Self {
        let exec = memory.blocks().filter(|b| b.flags.contains(reargo_loader::memory::MemoryFlags::EXECUTE));
        let (mut base, mut end) = (u64::MAX, 0u64);
        for b in exec {
            base = base.min(b.start);
            end = end.max(b.start.saturating_add(b.size));
        }
        let n = if base < end { ((end - 1) >> CT_PAGE_BITS) as usize - (base >> CT_PAGE_BITS) as usize + 1 } else { 0 };
        let page = || (0..n).map(|_| std::sync::OnceLock::new()).collect();
        Self {
            base,
            end,
            pages: [page(), page()],
            chunks: (0..CT_CHUNKS).map(|_| std::sync::OnceLock::new()).collect(),
            next: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The cell of `addr` lifted with the PF or not (`None` outside the executable memory).
    fn cell(&self, addr: u64, pf: bool) -> Option<&std::sync::atomic::AtomicU32> {
        if addr < self.base || addr >= self.end {
            return None;
        }
        let k = ((addr >> CT_PAGE_BITS) - (self.base >> CT_PAGE_BITS)) as usize;
        let page = self.pages[usize::from(pf)][k].get_or_init(|| (0..1usize << CT_PAGE_BITS).map(|_| std::sync::atomic::AtomicU32::new(0)).collect());
        Some(&page[(addr & ((1 << CT_PAGE_BITS) - 1)) as usize])
    }

    fn get(&self, cell: &std::sync::atomic::AtomicU32) -> Option<CInsn> {
        let i = cell.load(std::sync::atomic::Ordering::Acquire).checked_sub(1)? as usize;
        self.chunks[i >> CT_CHUNK_BITS].get()?[i & ((1 << CT_CHUNK_BITS) - 1)].get().copied()
    }

    /// Adds `c` as the entry of `cell` (unless another thread did first).
    fn put(&self, cell: &std::sync::atomic::AtomicU32, c: CInsn) {
        let i = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(chunk) = self.chunks.get(i >> CT_CHUNK_BITS) else { return };
        let chunk = chunk.get_or_init(|| (0..1usize << CT_CHUNK_BITS).map(|_| std::sync::OnceLock::new()).collect());
        if chunk[i & ((1 << CT_CHUNK_BITS) - 1)].set(c).is_ok()
            && let Ok(v) = u32::try_from(i + 1)
        {
            let _ = cell.compare_exchange(0, v, std::sync::atomic::Ordering::Release, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// What a summary reads of one instruction lifted alone ([`CalleeParams::summarize_compact`]):
/// its flow (as `reachability`, the CFG's leaders and edges see it), its effect on the
/// argument registers (as `run_block` / `block_writes` see it: the ops before its one call /
/// jump, that event, the ops after it) and what a `ret` after it returns (as `return_sites`
/// sees it).
#[derive(Clone, Copy)]
struct CInsn {
    /// The one `RAM` address its jumps and calls name, relative to its own: the target of its
    /// `BRANCH` / `CBRANCH` ([`CI_TARGET`]), [`crate::cfg::BasicBlock::branch_target`] of a
    /// block it ends ([`CI_BT`]), the event's ([`EV_CALL`], [`EV_BRANCH`]) and the callee of
    /// [`RET_CALL`].
    rel: i32,
    /// Before the event: the arguments its ops read that they did not write first, and those
    /// they write; after it, the same (at most 16 arguments).
    pre_ue: u16,
    pre_w: u16,
    post_ue: u16,
    post_w: u16,
    flags: u16,
    len: u8,
    /// The event ([`EV_NONE`], …) and, shifted by 4, what `return_sites` finds scanning its ops
    /// backwards ([`RET_NONE`], …).
    kind: u8,
}

/// It has a `BRANCH`.
const CI_BRANCH: u16 = 1;
const CI_CBRANCH: u16 = 2;
const CI_RETURN: u16 = 4;
const CI_BRANCHIND: u16 = 8;
/// [`crate::cfg::is_trap`].
const CI_TRAP: u16 = 16;
/// The lift failed.
const CI_FAILED: u16 = 32;
const CI_TARGET: u16 = 64;
const CI_BT: u16 = 128;
/// `target` is set.
const CI_ADDR: u16 = 256;

/// The arguments of a mask in the compact form's 16 bits.
fn narrow(m: u32) -> Option<u16> {
    u16::try_from(m).ok()
}

const EV_NONE: u8 = 0;
/// A `CALL` to a `RAM` target.
const EV_CALL: u8 = 1;
/// Another call (`CALLIND`, or a `CALL` to no `RAM` address).
const EV_CALL_OTHER: u8 = 2;
/// A `BRANCH` to a `RAM` target (a tail call when no block starts there).
const EV_BRANCH: u8 = 3;
const EV_IND: u8 = 4;

const RET_NONE: u8 = 0;
const RET_INT: u8 = 1;
const RET_FLOAT: u8 = 2;
/// A call to `target`.
const RET_CALL: u8 = 3;
/// A call to no known address.
const RET_CALL_OTHER: u8 = 4;

impl CInsn {
    fn has(&self, f: u16) -> bool {
        self.flags & f != 0
    }

    /// `compute_leaders` takes its target and the address after it.
    fn leads(&self) -> bool {
        self.has(CI_BRANCH | CI_CBRANCH | CI_BRANCHIND | CI_RETURN | CI_TRAP)
    }

    /// `reach_successors` follows it to the next instruction.
    fn falls(&self) -> bool {
        !self.has(CI_BRANCH | CI_RETURN | CI_BRANCHIND | CI_TRAP)
    }

    fn ev(&self) -> u8 {
        self.kind & 0xf
    }

    fn ret(&self) -> u8 {
        self.kind >> 4
    }

    /// The address it names, for the instruction at `at`.
    fn addr(&self, at: u64) -> u64 {
        at.wrapping_add(self.rel as i64 as u64)
    }

    fn target(&self, at: u64) -> Option<u64> {
        self.has(CI_TARGET).then(|| self.addr(at))
    }

    fn branch_target(&self, at: u64) -> Option<u64> {
        self.has(CI_BT).then(|| self.addr(at))
    }

    fn ret_site(&self, at: u64) -> Option<RetSite> {
        match self.ret() {
            RET_INT => Some(RetSite::Kind(ReturnKind::Int)),
            RET_FLOAT => Some(RetSite::Kind(ReturnKind::Float)),
            RET_CALL => Some(RetSite::Call(Some(self.addr(at)))),
            RET_CALL_OTHER => Some(RetSite::Call(None)),
            _ => None,
        }
    }

    /// The argument registers a block of these writes (`block_writes`).
    fn writes(&self) -> Option<u32> {
        (!matches!(self.ev(), EV_CALL | EV_CALL_OTHER)).then_some(u32::from(self.pre_w | self.post_w))
    }

    /// Names `t` as its one `RAM` address, for the instruction at `at` (`false` when it names
    /// another, or one too far away).
    fn name(&mut self, at: u64, t: u64) -> bool {
        let Ok(rel) = i32::try_from(t.wrapping_sub(at) as i64) else { return false };
        if self.has(CI_ADDR) && self.rel != rel {
            return false;
        }
        self.flags |= CI_ADDR;
        self.rel = rel;
        true
    }

    fn set_ev(&mut self, ev: u8) {
        self.kind = self.kind & 0xf0 | ev;
    }

    fn set_ret(&mut self, ret: u8) {
        self.kind = self.kind & 0xf | ret << 4;
    }

    const FAILED: CInsn = CInsn { rel: 0, pre_ue: 0, pre_w: 0, post_ue: 0, post_w: 0, flags: CI_FAILED, len: 0, kind: EV_NONE | RET_NONE << 4 };
}

impl<'a> CalleeParams<'a> {
    /// The [`CInsn`] of `insn`; `None` for what the compact form does not hold (two jump
    /// targets or two calls / jumps, a recovered jump table's cases, a length past a byte).
    fn compact_insn(&self, insn: &LiftedInstruction) -> Option<CInsn> {
        let mut c = CInsn { flags: 0, len: u8::try_from(insn.length).ok()?, ..CInsn::FAILED };
        for op in &insn.ops {
            let ram = op.inputs.first().filter(|t| t.space == SpaceId::RAM).map(|t| t.offset);
            match op.opcode {
                OpCode::Branch | OpCode::CBranch => {
                    c.flags |= if op.opcode == OpCode::Branch { CI_BRANCH } else { CI_CBRANCH };
                    if let Some(t) = ram {
                        if c.has(CI_TARGET) || !c.name(insn.address, t) {
                            return None;
                        }
                        c.flags |= CI_TARGET;
                    }
                }
                OpCode::BranchInd => {
                    c.flags |= CI_BRANCHIND;
                    if op.inputs.iter().skip(1).any(|t| t.space == SpaceId::RAM) {
                        return None;
                    }
                }
                OpCode::Return => c.flags |= CI_RETURN,
                _ => {}
            }
        }
        if crate::cfg::is_trap(insn) {
            c.flags |= CI_TRAP;
        }
        if let Some(t) = insn.ops.iter().rev().find_map(|op| {
            if matches!(op.opcode, OpCode::Branch | OpCode::CBranch | OpCode::Call) {
                op.inputs.first().filter(|vn| vn.space == SpaceId::RAM).map(|vn| vn.offset)
            } else {
                None
            }
        }) {
            if !c.name(insn.address, t) {
                return None;
            }
            c.flags |= CI_BT;
        }
        // `return_sites`' backward scan
        if self.returns.len() >= 2 {
            let (int_reg, float_reg) = (self.returns[0], self.returns[1]);
            for op in insn.ops.iter().rev() {
                if matches!(op.opcode, OpCode::Call | OpCode::CallInd) {
                    match (op.opcode == OpCode::Call).then(|| op.inputs.first()).flatten().filter(|t| t.space == SpaceId::RAM) {
                        Some(t) if c.name(insn.address, t.offset) => c.set_ret(RET_CALL),
                        Some(_) => return None,
                        None => c.set_ret(RET_CALL_OTHER),
                    }
                    break;
                }
                let Some(out) = op.output else { continue };
                if out.space != SpaceId::REGISTER {
                    continue;
                }
                if out.offset == int_reg.offset && out.size <= int_reg.size {
                    c.set_ret(RET_INT);
                    break;
                }
                let scalar = out.offset == float_reg.offset && (out.size == 4 || out.size == 8) && !matches!(op.opcode, OpCode::Piece | OpCode::Subpiece);
                let copy = out.offset == float_reg.offset
                    && out.size == float_reg.size
                    && op.opcode == OpCode::Copy
                    && op.inputs.first().is_some_and(|i| i.space == SpaceId::REGISTER && i.size == float_reg.size);
                if scalar || copy {
                    c.set_ret(RET_FLOAT);
                    break;
                }
            }
        }
        // `run_block`'s steps
        let (mut ue, mut w) = (0u32, 0u32);
        let mut zeroed = None;
        for op in &insn.ops {
            let ram = op.inputs.first().filter(|t| t.space == SpaceId::RAM).map(|t| t.offset);
            let ev = match op.opcode {
                OpCode::Call => match ram {
                    Some(t) => (EV_CALL, t),
                    None => (EV_CALL_OTHER, 0),
                },
                OpCode::CallInd => (EV_CALL_OTHER, 0),
                OpCode::Branch => match ram {
                    Some(t) => (EV_BRANCH, t),
                    None => continue,
                },
                OpCode::BranchInd => (EV_IND, 0),
                _ => (EV_NONE, 0),
            };
            if ev.0 != EV_NONE {
                if c.ev() != EV_NONE || (matches!(ev.0, EV_CALL | EV_BRANCH) && !c.name(insn.address, ev.1)) {
                    return None;
                }
                c.set_ev(ev.0);
                (c.pre_ue, c.pre_w) = (narrow(ue)?, narrow(w)?);
                (ue, w) = (0, 0);
                continue;
            }
            for (k, inp) in op.inputs.iter().enumerate() {
                if inp.space == SpaceId::CONST || zeroed.get_or_insert_with(|| zero_idiom_operands(insn)).contains(inp) {
                    continue;
                }
                let (lo, hi) = read_range(op, k, inp);
                ue |= self.covering(inp.space, lo, hi) & !w;
            }
            if let Some(out) = &op.output {
                w |= self.covering(out.space, out.offset, out.offset + out.size as u64);
            }
        }
        if c.ev() == EV_NONE {
            (c.pre_ue, c.pre_w) = (narrow(ue)?, narrow(w)?);
        } else {
            (c.post_ue, c.post_w) = (narrow(ue)?, narrow(w)?);
        }
        Some(c)
    }

    /// The [`CInsn`] of the instruction at `addr` lifted alone (with the integer PF when
    /// `pf`), from `table` or lifted and added to it; `None` when its lift fails or the
    /// compact form does not hold it.
    fn compact_at<'m>(&self, x86: &reargo_lift::x86::X86Lifter, table: &CompactTable, addr: u64, pf: bool, cursor: &mut reargo_lift::x86::DecodeCursor<'m>) -> Option<CInsn>
    where
        'a: 'm,
    {
        let cell = table.cell(addr, pf);
        if let Some(c) = cell.and_then(|cell| table.get(cell)) {
            return (!c.has(CI_FAILED)).then_some(c);
        }
        let lifted = if pf { self.lifter.lift_instruction(self.memory, addr) } else { x86.lift_alone_with(self.memory, addr, cursor) };
        let c = match lifted {
            Ok(insn) => self.compact_insn(&insn).unwrap_or(CInsn::FAILED),
            Err(_) => CInsn::FAILED,
        };
        if let Some(cell) = cell {
            table.put(cell, c);
        }
        (!c.has(CI_FAILED)).then_some(c)
    }

    /// [`Self::summarize_body`] of [`Self::body_plain`]'s body without the parameter accesses,
    /// from the [`CInsn`]s of its instructions: the same reachability, blocks, edges and
    /// data flow over the compact form. `None` where the body has an instruction whose lift
    /// fails or that the compact form does not hold (then [`Self::summarize`] answers).
    fn summarize_compact(&self, x86: &reargo_lift::x86::X86Lifter, table: &CompactTable, target: u64, walk: &reargo_lift::x86::PlainWalk<'_>) -> Option<Summary> {
        if walk.first() != Some(target) {
            return None;
        }
        let idx_of = |a: u64| walk.index_of(a).map(|_| a);
        let last = walk.last();
        let mut seen = vec![0u64; (last.map_or(0, |l| l - target) as usize + 1).div_ceil(64)];
        let mut insns: Vec<(u64, CInsn)> = Vec::new();
        let mut stack = vec![target];
        let mut cursor = reargo_lift::x86::DecodeCursor::default();
        while let Some(a) = stack.pop() {
            let off = (a - target) as usize;
            if seen[off / 64] >> (off % 64) & 1 != 0 {
                continue;
            }
            seen[off / 64] |= 1 << (off % 64);
            let c = self.compact_at(x86, table, a, walk.needs_pf, &mut cursor)?;
            // (`reach_successors`; the instruction after any but the walk's last is in it)
            let fall = a + u64::from(c.len);
            let next_in_walk = Some(a) != last;
            let succ = |x: u64| if x == fall && next_in_walk { Some(x) } else { idx_of(x) };
            if let Some(t) = c.target(a) {
                stack.extend(succ(t));
            }
            if c.falls() {
                stack.extend(succ(fall));
            }
            insns.push((a, c));
        }
        insns.sort_unstable_by_key(|(a, _)| *a);
        let hit_limit = walk.len() >= MAX_INSNS;
        let truncated = hit_limit && insns.last().map(|i| i.0) == last;
        Some(self.compact_body(&insns, truncated))
    }

    /// The analysis of `summarize_body` over the [`CInsn`]s of a body's instructions (in
    /// increasing address order, the first its entry), building its blocks as
    /// `ControlFlowGraph::build_owned` does.
    fn compact_body(&self, insns: &[(u64, CInsn)], truncated: bool) -> Summary {
        // the leaders (`compute_leaders`)
        let mut leaders: Vec<u64> = vec![insns[0].0];
        for (a, c) in insns {
            if c.leads() {
                leaders.extend(c.target(*a));
                leaders.push(a + u64::from(c.len));
            }
        }
        leaders.sort_unstable();
        leaders.dedup();
        // each leader's run of instructions: the blocks, `(start, first, end)`
        let mut blocks: Vec<(u64, usize, usize)> = Vec::with_capacity(leaders.len());
        let mut at = 0;
        for (k, &leader) in leaders.iter().enumerate() {
            let next = leaders.get(k + 1).copied().unwrap_or(u64::MAX);
            while at < insns.len() && insns[at].0 < leader {
                at += 1;
            }
            let from = at;
            while at < insns.len() && insns[at].0 < next {
                at += 1;
            }
            if at > from {
                blocks.push((leader, from, at));
            }
        }
        let n = blocks.len();
        let block_at = |a: u64| blocks.binary_search_by_key(&a, |b| b.0).ok();
        // the edges (`finalize_cfg`), at most two per block
        let mut succs: Vec<[usize; 2]> = vec![[usize::MAX; 2]; n];
        for (i, &(_, _, end)) in blocks.iter().enumerate() {
            let (a, c) = &insns[end - 1];
            if c.has(CI_BRANCHIND) || c.has(CI_RETURN) || c.has(CI_TRAP) {
                continue;
            }
            let fall = a + u64::from(c.len);
            let (x, y) = if c.has(CI_BRANCH) && !c.has(CI_CBRANCH) {
                (c.branch_target(*a).and_then(block_at), None)
            } else if c.has(CI_CBRANCH) {
                (c.branch_target(*a).and_then(block_at), block_at(fall))
            } else {
                (block_at(fall), None)
            };
            for (k, s) in [x, y].into_iter().flatten().enumerate() {
                succs[i][k] = s;
            }
        }
        let succ_of = |b: usize| succs[b].iter().copied().filter(|&s| s != usize::MAX);
        // the number of distinct predecessors of each block and the first (`return_sites`
        // follows a block's only one)
        let mut preds: Vec<(u32, usize)> = vec![(0, usize::MAX); n];
        for (i, &[x, y]) in succs.iter().enumerate() {
            // (a block listed twice, a `CBRANCH` to the next instruction, is one predecessor)
            for s in [x, y].into_iter().take(if x == y { 1 } else { 2 }) {
                if s != usize::MAX {
                    if preds[s].0 == 0 {
                        preds[s].1 = i;
                    }
                    preds[s].0 += 1;
                }
            }
        }
        let entry = block_at(insns[0].0).unwrap_or(0);
        // `reverse_post_order`
        let rpo = {
            let mut seen = vec![false; n];
            let mut post: Vec<usize> = Vec::with_capacity(n);
            let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
            seen[entry] = true;
            while let Some(top) = stack.last_mut() {
                let (b, i) = *top;
                if let Some(s) = succ_of(b).nth(i) {
                    top.1 += 1;
                    if !seen[s] {
                        seen[s] = true;
                        stack.push((s, 0));
                    }
                } else {
                    post.push(b);
                    stack.pop();
                }
            }
            post.reverse();
            post
        };
        let block_insns = |b: usize| &insns[blocks[b].1..blocks[b].2];
        // `return_sites`
        let mut ret_sites = Vec::new();
        if self.returns.len() >= 2 {
            for b in 0..n {
                if !block_insns(b).last().is_some_and(|(_, c)| c.has(CI_RETURN)) {
                    continue;
                }
                let mut cur = b;
                let mut steps = 0;
                let kind = loop {
                    if let Some(r) = block_insns(cur).iter().rev().find_map(|(a, c)| c.ret_site(*a)) {
                        break r;
                    }
                    steps += 1;
                    if preds[cur].0 != 1 || steps > 8 {
                        break RetSite::Kind(ReturnKind::Unknown);
                    }
                    cur = preds[cur].1;
                };
                ret_sites.push(kind);
            }
        }
        // the must-defined data flow (`summarize_body`)
        let all = (1u32 << self.args.len()) - 1;
        let transfer: Vec<Option<u32>> = (0..n).map(|b| block_insns(b).iter().try_fold(0u32, |w, (_, c)| Some(w | c.writes()?))).collect();
        let mut inn: Vec<Option<u32>> = vec![None; n];
        inn[entry] = Some(0);
        loop {
            let mut changed = false;
            for &b in &rpo {
                let Some(state) = inn[b] else { continue };
                let out = transfer[b].map_or(all, |w| state | w);
                for s in succ_of(b) {
                    let new = match inn[s] {
                        None => out,
                        Some(old) => old & out,
                    };
                    if s != entry && inn[s] != Some(new) {
                        inn[s] = Some(new);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        // `run_block` with the accumulator
        let mut acc = Acc { reads: 0, complete: !truncated, calls: Vec::new() };
        for &b in &rpo {
            let Some(mut defined) = inn[b] else { continue };
            let mut window = 0u32;
            for &(a, c) in block_insns(b) {
                acc.reads |= u32::from(c.pre_ue) & !defined;
                defined |= u32::from(c.pre_w);
                window |= u32::from(c.pre_w);
                match c.ev() {
                    EV_NONE => continue,
                    EV_CALL | EV_CALL_OTHER => {
                        acc.calls.push(InnerCall { target: (c.ev() == EV_CALL).then(|| c.addr(a)), window, defined });
                        defined = all;
                        window = 0;
                    }
                    EV_BRANCH => {
                        if block_at(c.addr(a)).is_none() {
                            acc.calls.push(InnerCall { target: Some(c.addr(a)), window, defined });
                        }
                    }
                    _ => acc.complete = false,
                }
                acc.reads |= u32::from(c.post_ue) & !defined;
                defined |= u32::from(c.post_w);
                window |= u32::from(c.post_w);
            }
        }
        Summary { reads: acc.reads, complete: acc.complete, calls: acc.calls, ret_sites, fields: None }
    }
}

struct Acc {
    reads: u32,
    complete: bool,
    calls: Vec<InnerCall>,
}

/// A call (or tail jump) inside a summarised body: its direct target, the argument registers
/// set up right before it and those defined on every path to it.
#[derive(PartialEq, Eq, Debug)]
struct InnerCall {
    target: Option<u64>,
    window: u32,
    defined: u32,
}

/// What a `ret` returns: a known register, or what the call right before it returns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RetSite {
    Kind(ReturnKind),
    Call(Option<u64>),
}

/// The depth-independent analysis of one body: the argument registers read before written
/// outside the inner calls, the inner calls, the `ret`s and the parameter accesses.
struct Summary {
    reads: u32,
    complete: bool,
    calls: Vec<InnerCall>,
    ret_sites: Vec<RetSite>,
    /// The parameter accesses, when the body was lifted as a whole ([`CalleeParams::summary`]).
    fields: Option<std::sync::Arc<ParamUse>>,
}

/// Field offsets past this are no struct fields.
const MAX_FIELD: i64 = 0x10_0000;

/// What a storage location holds: an argument's incoming value plus a delta.
pub(crate) type Held = SmallMap<(SpaceId, u64, u32), (usize, i64)>;

pub(crate) fn kill<V: Copy>(state: &mut SmallMap<(SpaceId, u64, u32), V>, out: &VarnodeData) {
    let overlaps = |&(sp, off, sz): &(SpaceId, u64, u32)| sp == out.space && off < out.offset + u64::from(out.size) && out.offset < off + u64::from(sz);
    // (most writes overlap nothing held: looked for before rebuilding the map)
    if state.0.iter().any(|e| overlaps(&e.0)) {
        state.retain(|k, _| !overlaps(k));
    }
}

/// A map of few entries, kept sorted by key in a small vector: the data flows over a body's
/// storage locations hold a handful at a time, where a hash map's table costs more to clone,
/// scan and compare than the entries themselves. Equal maps hold the same entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SmallMap<K, V>(smallvec::SmallVec<[(K, V); 8]>);

impl<K, V> Default for SmallMap<K, V> {
    fn default() -> Self {
        Self(smallvec::SmallVec::new())
    }
}

impl<K: Ord + Copy, V: Copy> SmallMap<K, V> {
    pub(crate) fn get(&self, k: &K) -> Option<&V> {
        // (a handful of entries: a linear scan beats the binary search's branches)
        self.0.iter().find(|e| e.0 == *k).map(|e| &e.1)
    }

    pub(crate) fn insert(&mut self, k: K, v: V) {
        match self.0.binary_search_by(|e| e.0.cmp(&k)) {
            Ok(i) => self.0[i].1 = v,
            Err(i) => self.0.insert(i, (k, v)),
        }
    }

    pub(crate) fn remove(&mut self, k: &K) {
        if let Some(i) = self.0.iter().position(|e| e.0 == *k) {
            self.0.remove(i);
        }
    }

    pub(crate) fn retain(&mut self, mut f: impl FnMut(&K, &V) -> bool) {
        self.0.retain(|e| f(&e.0, &e.1));
    }

    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.0.iter().map(|e| (&e.0, &e.1))
    }
}

impl<K: Ord + Copy, V: Copy> FromIterator<(K, V)> for SmallMap<K, V> {
    /// (from entries in key order, as [`SmallMap::iter`] gives them, with distinct keys)
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let v: smallvec::SmallVec<[(K, V); 8]> = iter.into_iter().collect();
        debug_assert!(v.windows(2).all(|w| w[0].0 < w[1].0));
        Self(v)
    }
}

/// The loads / stores of a body whose address is an argument's incoming value plus a constant
/// (WS91): a forward data flow of "holds argument `i` + delta" over copies and constant adds,
/// meeting at joins where the predecessors agree; a call forgets the registers it may change.
fn param_accesses(cfg: &ControlFlowGraph, rpo: &[usize], args: &[VarnodeData], caller_saved: &[VarnodeData], ret: Option<&VarnodeData>) -> ParamUse {
    let n = cfg.blocks.len();
    let mut inn: Vec<Option<Held>> = vec![None; n];
    let mut entry = Held::default();
    for (i, a) in args.iter().enumerate().filter(|(_, a)| a.size == 8) {
        entry.insert((a.space, a.offset, a.size), (i, 0));
    }
    inn[cfg.entry_block] = Some(entry);
    let mut found: Vec<ParamAccess> = Vec::new();
    let mut vtable_stores: Vec<(usize, u64)> = Vec::new();
    // A block whose entry state did not change since it was last run gives the same accesses
    // (already recorded), `ret`s and states for its successors (already met into theirs, which
    // only shrank since): it is not run again. Its `ret`s are kept from that run.
    let mut dirty: Vec<bool> = vec![true; n];
    let mut block_returns: Vec<smallvec::SmallVec<[bool; 1]>> = vec![smallvec::SmallVec::new(); n];
    for pass in 0..8 {
        let mut changed = false;
        let last = pass == 7;
        for &b in rpo {
            if !dirty[b] {
                continue;
            }
            let Some(mut st) = inn[b].clone() else { continue };
            dirty[b] = false;
            let returns = &mut block_returns[b];
            returns.clear();
            // the constants the block wrote into registers (`lea rax, [vtable]`), for the stores
            let mut consts: SmallMap<(SpaceId, u64, u32), u64> = SmallMap::default();
            for insn in &cfg.blocks[b].instructions {
                for op in &insn.ops {
                    let held = |st: &Held, v: &VarnodeData| st.get(&(v.space, v.offset, v.size)).copied();
                    if op.opcode == OpCode::Store
                        && let (Some(a), Some(v)) = (op.inputs.get(1).and_then(|v| held(&st, v)), op.inputs.get(2))
                        && a.1 == 0
                        && v.size == 8
                    {
                        let k = if v.space == SpaceId::CONST { Some(v.offset) } else { consts.get(&(v.space, v.offset, v.size)).copied() };
                        if let Some(k) = k
                            && !vtable_stores.contains(&(a.0, k))
                        {
                            vtable_stores.push((a.0, k));
                        }
                    }
                    if let Some(out) = op.output {
                        let c = match (op.opcode, op.inputs.first()) {
                            (OpCode::Copy, Some(c)) if out.size == 8 && c.space == SpaceId::CONST => Some(c.offset),
                            (OpCode::Copy, Some(c)) if out.size == 8 => consts.get(&(c.space, c.offset, c.size)).copied(),
                            _ => None,
                        };
                        // (the lifter's view sync, `eax = SUBPIECE(rax, 0)`, leaves the register it reads)
                        let view_sync = op.opcode == OpCode::Subpiece && op.inputs.first().is_some_and(|r| r.space == out.space && r.offset == out.offset && r.size > out.size);
                        if !view_sync && !consts.0.is_empty() {
                            consts.retain(|r, _| !(r.0 == out.space && r.1 < out.offset + u64::from(out.size) && out.offset < r.1 + u64::from(r.2)));
                        }
                        if let Some(c) = c {
                            consts.insert((out.space, out.offset, out.size), c);
                        }
                    }
                    if matches!(op.opcode, OpCode::Call | OpCode::CallInd) {
                        consts.clear();
                    }
                    match op.opcode {
                        OpCode::Load | OpCode::Store => {
                            let size = match op.opcode {
                                OpCode::Load => op.output.map(|o| o.size),
                                _ => op.inputs.get(2).map(|v| v.size),
                            };
                            if let (Some(a), Some(size)) = (op.inputs.get(1).and_then(|v| held(&st, v)), size)
                                && (0..MAX_FIELD).contains(&a.1)
                            {
                                let acc = ParamAccess { arg: a.0, off: a.1 as u64, size };
                                if !found.contains(&acc) {
                                    found.push(acc);
                                }
                            }
                        }
                        OpCode::Call | OpCode::CallInd => {
                            for r in caller_saved {
                                kill(&mut st, r);
                            }
                            st.retain(|k, _| k.0 != SpaceId::UNIQUE);
                            continue;
                        }
                        OpCode::Return => {
                            returns.push(ret.is_some_and(|r| st.get(&(r.space, r.offset, r.size)) == Some(&(0, 0))));
                            continue;
                        }
                        _ => {}
                    }
                    let Some(out) = op.output else { continue };
                    let konst = |v: &VarnodeData| (v.space == SpaceId::CONST).then_some(v.offset as i64);
                    let v = match (op.opcode, op.inputs.as_slice()) {
                        (OpCode::Copy, [a]) => held(&st, a),
                        (OpCode::IntAdd, [a, b]) => held(&st, a).zip(konst(b)).or_else(|| held(&st, b).zip(konst(a))).map(|((i, d), k)| (i, d.wrapping_add(k))),
                        (OpCode::IntSub, [a, b]) => held(&st, a).zip(konst(b)).map(|((i, d), k)| (i, d.wrapping_sub(k))),
                        _ => None,
                    };
                    // (the lifter's view sync, `eax = SUBPIECE(rax, 0)`, leaves the register it reads)
                    let sync = op.opcode == OpCode::Subpiece && op.inputs.first().is_some_and(|r| r.space == out.space && r.offset == out.offset && r.size > out.size);
                    if sync {
                        st.remove(&(out.space, out.offset, out.size));
                    } else {
                        kill(&mut st, &out);
                    }
                    if let Some(v) = v.filter(|_| out.size == 8) {
                        st.insert((out.space, out.offset, out.size), v);
                    }
                }
            }
            for &succ in &cfg.blocks[b].successors {
                let new = match &inn[succ] {
                    None => st.clone(),
                    Some(old) => old.iter().filter(|(k, v)| st.get(k) == Some(v)).map(|(k, v)| (*k, *v)).collect(),
                };
                if succ != cfg.entry_block && inn[succ].as_ref() != Some(&new) {
                    inn[succ] = Some(new);
                    dirty[succ] = true;
                    changed = true;
                }
            }
        }
        if !changed || last {
            break;
        }
    }
    let mut returns = rpo.iter().filter(|&&b| inn[b].is_some()).flat_map(|&b| block_returns[b].iter().copied()).peekable();
    let returns_first = returns.peek().is_some() && returns.all(|r| r);
    ParamUse { fields: found, returns_first, vtable_stores }
}

/// Group the argument registers into classes (System V: integer, vector) by
/// their size; members keep parameter order.
pub fn arg_classes(args: &[VarnodeData]) -> (Vec<usize>, Vec<Vec<usize>>) {
    let mut sizes: Vec<u32> = Vec::new();
    let mut class_of = Vec::with_capacity(args.len());
    let mut members: Vec<Vec<usize>> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let c = match sizes.iter().position(|&s| s == a.size) {
            Some(c) => c,
            None => {
                sizes.push(a.size);
                members.push(Vec::new());
                sizes.len() - 1
            }
        };
        class_of.push(c);
        members[c].push(i);
    }
    (class_of, members)
}

/// Bytes `[lo, hi)` (in the input's space) that input `k` of `op` reads:
/// `SUBPIECE(x, c)` reads only the bytes it extracts.
fn read_range(op: &PcodeOp, k: usize, inp: &VarnodeData) -> (u64, u64) {
    if op.opcode == OpCode::Subpiece
        && k == 0
        && let (Some(c), Some(out)) = (op.inputs.get(1), op.output.as_ref())
        && c.space == SpaceId::CONST
    {
        let lo = inp.offset + c.offset;
        return (lo, (lo + out.size as u64).min(inp.offset + inp.size as u64));
    }
    (inp.offset, inp.offset + inp.size as u64)
}

/// Operands of `xor r, r` / `sub r, r` in this instruction: their old value is
/// not read.
fn zero_idiom_operands(insn: &LiftedInstruction) -> smallvec::SmallVec<[VarnodeData; 1]> {
    insn.ops
        .iter()
        .filter(|o| {
            matches!(o.opcode, OpCode::IntXor | OpCode::IntSub)
                && o.inputs.len() == 2
                && o.inputs[0] == o.inputs[1]
                && o.inputs[0].space != SpaceId::CONST
        })
        .map(|o| o.inputs[0])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Endian;
    use reargo_lift::x86::X86Lifter;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    /// Code blobs placed at their addresses inside one `0xcc`-filled block.
    fn memory(parts: &[(u64, &[u8])]) -> Memory {
        let base = parts.iter().map(|p| p.0).min().unwrap();
        let end = parts.iter().map(|p| p.0 + p.1.len() as u64).max().unwrap();
        let mut data = vec![0xccu8; (end - base) as usize + 16];
        for (a, bytes) in parts {
            let o = (a - base) as usize;
            data[o..o + bytes.len()].copy_from_slice(bytes);
        }
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: base,
            size: data.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(data.as_slice())),
        });
        mem
    }

    const RDI: u32 = 1 << 0;
    const RSI: u32 = 1 << 1;
    const RDX: u32 = 1 << 2;
    const XMM0: u32 = 1 << 6;
    const XMM1: u32 = 1 << 7;

    /// The parameters of the function at `at`, the same from its compact summary (no entry
    /// known: every body is summarised from the compact lifts).
    fn params(parts: &[(u64, &[u8])], at: u64) -> ParamInfo {
        let lifter = X86Lifter::new_64();
        let mem = memory(parts);
        let p = CalleeParams::new(&lifter, &mem).unwrap();
        let r = p.params(at).unwrap();
        let compact = CalleeParams::new(&lifter, &mem).unwrap().with_entries(Vec::new());
        assert_eq!(compact.params(at), Some(r), "compact summary at {at:#x}");
        assert_eq!(compact.param_use(at), p.param_use(at), "compact summary's accesses at {at:#x}");
        r
    }

    fn kind(parts: &[(u64, &[u8])], at: u64) -> ReturnKind {
        let lifter = X86Lifter::new_64();
        let mem = memory(parts);
        let k = CalleeParams::new(&lifter, &mem).unwrap().return_kind(at);
        assert_eq!(CalleeParams::new(&lifter, &mem).unwrap().with_entries(Vec::new()).return_kind(at), k, "compact summary at {at:#x}");
        k
    }

    #[test]
    fn return_kind_from_the_last_return_register_write() {
        // mov eax, 1 ; cvtsi2ss xmm0, edi ; ret  -> float
        assert_eq!(kind(&[(0x1000, &[0xb8, 1, 0, 0, 0, 0xf3, 0x0f, 0x2a, 0xc7, 0xc3])], 0x1000), ReturnKind::Float);
        // cvtsi2ss xmm0, edi ; mov eax, 1 ; ret  -> int
        assert_eq!(kind(&[(0x1000, &[0xf3, 0x0f, 0x2a, 0xc7, 0xb8, 1, 0, 0, 0, 0xc3])], 0x1000), ReturnKind::Int);
        // movaps xmm0, xmm1 ; ret  -> float (a whole-register copy from another vector register)
        assert_eq!(kind(&[(0x1000, &[0x0f, 0x28, 0xc1, 0xc3])], 0x1000), ReturnKind::Float);
        // ret alone -> unknown
        assert_eq!(kind(&[(0x1000, &[0xc3])], 0x1000), ReturnKind::Unknown);
        // mov eax, 1 ; test edi, edi ; je +0 ; ret  -> int (the `ret`'s block has one
        // predecessor, which the `je` names twice: as its target and as the next instruction)
        assert_eq!(kind(&[(0x1000, &[0xb8, 1, 0, 0, 0, 0x85, 0xff, 0x74, 0x00, 0xc3])], 0x1000), ReturnKind::Int);
    }

    #[test]
    fn return_kind_through_a_tail_call_result() {
        // f: call g ; ret     g: cvtsi2sd xmm0, edi ; ret
        let f: &[u8] = &[0xe8, 0xfb, 0x00, 0x00, 0x00, 0xc3]; // call 0x1100
        let g: &[u8] = &[0xf2, 0x0f, 0x2a, 0xc7, 0xc3];
        assert_eq!(kind(&[(0x1000, f), (0x1100, g)], 0x1000), ReturnKind::Float);
    }

    #[test]
    fn reads_before_writes_are_parameters() {
        // mov eax, edi ; add eax, esi ; mov edx, 1 ; add eax, edx ; ret
        let code = [0x89, 0xf8, 0x01, 0xf0, 0xba, 0x01, 0, 0, 0, 0x01, 0xd0, 0xc3];
        let p = params(&[(0x2000, &code)], 0x2000);
        assert_eq!(p, ParamInfo { mask: RDI | RSI, complete: true });
    }

    #[test]
    fn zero_idiom_is_not_a_read() {
        // xor esi, esi ; mov eax, esi ; ret
        let code = [0x31, 0xf6, 0x89, 0xf0, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, 0);
    }

    #[test]
    fn scalar_sse_write_does_not_read_the_upper_lanes() {
        // cvtsi2ss xmm0, edi ; addss xmm0, xmm1 ; ret
        let code = [0xf3, 0x0f, 0x2a, 0xc7, 0xf3, 0x0f, 0x58, 0xc1, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, RDI | XMM1);
        // movss xmm0, [rdi] ; ret  — reads rdi, writes xmm0
        let code = [0xf3, 0x0f, 0x10, 0x07, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, RDI);
        // addss xmm0, xmm0 ; ret — a real float parameter
        let code = [0xf3, 0x0f, 0x58, 0xc0, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, XMM0);
    }

    #[test]
    fn arguments_passed_through_to_an_inner_call_are_parameters() {
        // 0x2000: mov edx, 3 ; call 0x3000 ; ret      (rdi, rsi pass through)
        // 0x3000: mov eax, edi ; add eax, esi ; add eax, edx ; ret
        let outer = [0xba, 0x03, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0xc3];
        let inner = [0x89, 0xf8, 0x01, 0xf0, 0x01, 0xd0, 0xc3];
        let p = params(&[(0x2000, &outer), (0x3000, &inner)], 0x2000);
        assert_eq!(p, ParamInfo { mask: RDI | RSI, complete: true });
    }

    #[test]
    fn registers_read_after_an_inner_call_are_not_parameters() {
        // call 0x3000 ; mov eax, edi ; ret   (0x3000: ret)
        let outer = [0xe8, 0xfb, 0x0f, 0, 0, 0x89, 0xf8, 0xc3];
        let p = params(&[(0x2000, &outer), (0x3000, &[0xc3])], 0x2000);
        assert_eq!(p, ParamInfo { mask: 0, complete: true });
    }

    #[test]
    fn unknown_inner_call_takes_the_set_up_prefix() {
        // mov edx, 1 ; call rax ; ret  — rdx set up, so rdi/rsi pass through
        let code = [0xba, 0x01, 0, 0, 0, 0xff, 0xd0, 0xc3];
        let p = params(&[(0x2000, &code)], 0x2000);
        assert_eq!(p.mask, RDI | RSI, "rdx is set up here, rdi/rsi come from the caller");
        assert!(p.complete);
    }

    #[test]
    fn unknown_inner_call_prefix_ignores_earlier_temporaries() {
        // mov ecx, 3 ; test eax, eax ; je L ; L: mov edi, 1 ; call rax ; ret
        // rcx was written in an earlier block (a temporary), so it does not stretch the
        // inner call's argument prefix to rsi/rdx
        let code = [0xb9, 0x03, 0, 0, 0, 0x85, 0xc0, 0x74, 0x00, 0xbf, 0x01, 0, 0, 0, 0xff, 0xd0, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, 0);
    }

    #[test]
    fn indirect_jump_makes_the_answer_a_lower_bound() {
        // jmp [rip+0x1000]  (a PLT stub)
        let code = [0xff, 0x25, 0x00, 0x10, 0, 0];
        let p = params(&[(0x2000, &code)], 0x2000);
        assert_eq!(p, ParamInfo { mask: 0, complete: false });
    }

    #[test]
    fn read_on_one_path_only_is_a_parameter() {
        // test eax, eax ; je L ; mov esi, 1 ; L: mov eax, esi ; ret
        let code = [0x85, 0xc0, 0x74, 0x05, 0xbe, 0x01, 0, 0, 0, 0x89, 0xf0, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, RSI);
        let _ = RDX;
    }
}
