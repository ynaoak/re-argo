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
    /// The lengths and flags of the instructions lifted alone, for the range walks (x86).
    facts: Option<reargo_lift::x86::InsnFacts>,
    /// The direct call sites by target, when a batch built them ([`Self::with_call_index`]).
    call_index: Option<crate::callers::CallIndex>,
    /// [`crate::callers::return_hint`] by function.
    hint_memo: Mutex<FxHashMap<u64, Option<crate::callers::ReturnHint>>>,
    /// The control flow of the instructions the no-return searches read (x86).
    flow_cache: Option<crate::noreturn::FlowCache>,
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
        Some(Self {
            arg_space,
            arg_offsets,
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
            facts: lifter.as_x86().map(|_| reargo_lift::x86::InsnFacts::new(memory)),
            call_index: None,
            hint_memo: Mutex::new(FxHashMap::default()),
            flow_cache: lifter.as_x86().map(|_| crate::noreturn::FlowCache::new()),
        })
    }

    /// The same oracle with the direct call sites of the whole binary indexed once (for a batch
    /// of decompiles: each looks its callers up).
    pub fn with_call_index(mut self) -> Self {
        self.call_index = crate::callers::CallIndex::build(self.memory);
        self
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
        self.fields_memo.lock().ok()?.get(&target).cloned()
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
        let addrs = x86.plain_range(self.memory, start, count, self.facts.as_ref()?)?;
        let mut out = Vec::new();
        let mut next = hi;
        for &a in &addrs {
            if a >= lo && a < hi {
                out.push(x86.lift_alone(self.memory, a).ok()?);
            } else if a == next {
                let insn = x86.lift_alone(self.memory, a).ok()?;
                if insn.mnemonic.trim() == "int3" {
                    next += u64::from(insn.length);
                    out.push(insn);
                }
            }
        }
        Some((!addrs.is_empty(), out))
    }

    /// The depth-independent part of the analysis of the function at `target`, lifted once
    /// and shared by every depth (`None` when it cannot be lifted).
    fn summary(&self, target: u64) -> Option<std::sync::Arc<Summary>> {
        if let Some(s) = self.summary_memo.lock().ok().and_then(|m| m.get(&target).cloned()) {
            return s;
        }
        let s = self.summarize(target).map(std::sync::Arc::new);
        if let Ok(mut m) = self.summary_memo.lock() {
            m.insert(target, s.clone());
        }
        s
    }

    fn summarize(&self, target: u64) -> Option<Summary> {
        if let (Some(x86), Some(facts)) = (self.lifter.as_x86(), &self.facts)
            && let Some(addrs) = x86.plain_range(self.memory, target, MAX_INSNS, facts)
            && let Some(s) = self.summarize_plain(x86, target, &addrs)
        {
            return Some(s);
        }
        let lifted = self.lifter.lift_range(self.memory, target, MAX_INSNS).ok()?;
        if lifted.is_empty() || lifted[0].address != target {
            return None;
        }
        let last = lifted.last().map(|i| i.address);
        let hit_limit = lifted.len() >= MAX_INSNS;
        let insns = crate::pipeline::trim_to_return(lifted);
        // the body runs past the lift limit (its last lifted instruction is live)
        let truncated = hit_limit && insns.last().map(|i| i.address) == last;
        Some(self.summarize_body(ControlFlowGraph::build_owned(insns), truncated))
    }

    /// [`Self::summarize`] of a range that is the lifts of `addrs` alone
    /// ([`reargo_lift::x86::X86Lifter::plain_range`]): only the instructions the trim keeps
    /// are lifted.
    fn summarize_plain(&self, x86: &reargo_lift::x86::X86Lifter, target: u64, addrs: &[u64]) -> Option<Summary> {
        if addrs.first() != Some(&target) {
            return None;
        }
        let idx_of = |a: u64| addrs.binary_search(&a).ok();
        let mut seen = vec![false; addrs.len()];
        let mut lifted: Vec<(usize, LiftedInstruction)> = Vec::new();
        let mut stack = vec![0usize];
        while let Some(idx) = stack.pop() {
            if seen[idx] {
                continue;
            }
            seen[idx] = true;
            let insn = x86.lift_alone(self.memory, addrs[idx]).ok()?;
            crate::pipeline::reach_successors(&insn, idx_of, &mut stack);
            lifted.push((idx, insn));
        }
        lifted.sort_unstable_by_key(|(idx, _)| *idx);
        let insns: Vec<LiftedInstruction> = lifted.into_iter().map(|(_, i)| i).collect();
        let hit_limit = addrs.len() >= MAX_INSNS;
        let truncated = hit_limit && insns.last().map(|i| i.address) == addrs.last().copied();
        Some(self.summarize_body(ControlFlowGraph::build_owned(insns), truncated))
    }

    fn summarize_body(&self, cfg: ControlFlowGraph, truncated: bool) -> Summary {
        let fields = std::sync::Arc::new(param_accesses(&cfg, &self.args, &self.caller_saved, self.returns.first()));
        let ret_sites = self.return_sites(&cfg);
        let n = cfg.blocks.len();
        let rpo = crate::dominator::reverse_post_order(&cfg);

        // must-defined (by low byte) sets at block entry; None = not reached yet
        let mut inn: Vec<Option<u32>> = vec![None; n];
        inn[cfg.entry_block] = Some(0);
        let mut acc = Acc { reads: 0, complete: !truncated, calls: Vec::new() };
        loop {
            let mut changed = false;
            for &b in &rpo {
                let Some(state) = inn[b] else { continue };
                let out = self.run_block(&cfg, b, state, None);
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
            && let Ok(mut m) = self.fields_memo.lock()
        {
            m.entry(target).or_insert_with(|| s.fields.clone());
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

    /// Transfer function of one block; with `acc`, records the reads and the inner calls.
    fn run_block(&self, cfg: &ControlFlowGraph, b: usize, mut defined: u32, mut acc: Option<&mut Acc>) -> u32 {
        let all = (1u32 << self.args.len()) - 1;
        // registers written since the block start / the last call: the setup window an unknown
        // inner callee's argument prefix is judged by (a loop temporary written earlier is not
        // an argument setup)
        let mut window = 0u32;
        for insn in &cfg.blocks[b].instructions {
            let zeroed = zero_idiom_operands(insn);
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
                if let Some(a) = acc.as_deref_mut() {
                    for (k, inp) in op.inputs.iter().enumerate() {
                        if inp.space == SpaceId::CONST || zeroed.contains(inp) {
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
    fn covering(&self, space: SpaceId, lo: u64, hi: u64) -> u32 {
        let mut m = 0;
        // (the arguments by offset; `arg_space`: the one space they are all in)
        if let Some(sp) = self.arg_space {
            if space != sp {
                return 0;
            }
            let from = self.arg_offsets.partition_point(|&(off, _)| off < lo);
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

struct Acc {
    reads: u32,
    complete: bool,
    calls: Vec<InnerCall>,
}

/// A call (or tail jump) inside a summarised body: its direct target, the argument registers
/// set up right before it and those defined on every path to it.
struct InnerCall {
    target: Option<u64>,
    window: u32,
    defined: u32,
}

/// What a `ret` returns: a known register, or what the call right before it returns.
#[derive(Clone, Copy)]
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
    fields: std::sync::Arc<ParamUse>,
}

/// Field offsets past this are no struct fields.
const MAX_FIELD: i64 = 0x10_0000;

/// What a storage location holds: an argument's incoming value plus a delta.
pub(crate) type Held = FxHashMap<(SpaceId, u64, u32), (usize, i64)>;

pub(crate) fn kill(state: &mut Held, out: &VarnodeData) {
    state.retain(|&(sp, off, sz), _| !(sp == out.space && off < out.offset + u64::from(out.size) && out.offset < off + u64::from(sz)));
}

/// The loads / stores of a body whose address is an argument's incoming value plus a constant
/// (WS91): a forward data flow of "holds argument `i` + delta" over copies and constant adds,
/// meeting at joins where the predecessors agree; a call forgets the registers it may change.
fn param_accesses(cfg: &ControlFlowGraph, args: &[VarnodeData], caller_saved: &[VarnodeData], ret: Option<&VarnodeData>) -> ParamUse {
    let n = cfg.blocks.len();
    let mut inn: Vec<Option<Held>> = vec![None; n];
    let mut entry = Held::default();
    for (i, a) in args.iter().enumerate().filter(|(_, a)| a.size == 8) {
        entry.insert((a.space, a.offset, a.size), (i, 0));
    }
    inn[cfg.entry_block] = Some(entry);
    let rpo = crate::dominator::reverse_post_order(cfg);
    let mut found: Vec<ParamAccess> = Vec::new();
    let mut returns: Vec<bool> = Vec::new();
    let mut vtable_stores: Vec<(usize, u64)> = Vec::new();
    for pass in 0..8 {
        returns.clear();
        let mut changed = false;
        let last = pass == 7;
        for &b in &rpo {
            let Some(mut st) = inn[b].clone() else { continue };
            // the constants the block wrote into registers (`lea rax, [vtable]`), for the stores
            let mut consts: FxHashMap<(SpaceId, u64, u32), u64> = FxHashMap::default();
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
                        if !view_sync {
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
                    changed = true;
                }
            }
        }
        if !changed || last {
            break;
        }
    }
    ParamUse { fields: found, returns_first: !returns.is_empty() && returns.iter().all(|&r| r), vtable_stores }
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

    fn params(parts: &[(u64, &[u8])], at: u64) -> ParamInfo {
        let lifter = X86Lifter::new_64();
        let mem = memory(parts);
        CalleeParams::new(&lifter, &mem).unwrap().params(at).unwrap()
    }

    fn kind(parts: &[(u64, &[u8])], at: u64) -> ReturnKind {
        let lifter = X86Lifter::new_64();
        let mem = memory(parts);
        CalleeParams::new(&lifter, &mem).unwrap().return_kind(at)
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
