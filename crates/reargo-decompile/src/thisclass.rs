//! The classes of the objects a function is given (WS93): `this` of a non-virtual method in a
//! stripped binary, from what its callers pass.
//!
//! A whole-binary index, built once per binary (and cached, see [`load_or_build`]):
//!
//! * **Summaries.** Each function (an `.eh_frame` FDE range) is decoded linearly (x86-64) and
//!   followed with a forward data flow over its basic blocks: the 16 general registers, the
//!   stack pointer as an offset from its value on entry, and the 8-byte stack slots (spills).
//!   A value is unknown, a constant, or a pointer `source + k`, the source being an argument
//!   register on entry (`Arg(i)`), the result of a call (`Ret(c)`), a value loaded from a
//!   field of a pointer (`Ld(l)`: `[source + k]`) or the stack (an address in the frame). A
//!   block no jump reaches (a jump table's case, a landing pad) starts from the meet of the
//!   states after the calls and at the indirect jumps. A stack object is followed through the
//!   flow, as a slot may be reused for another object: it is the one the first call it is given
//!   to made (its constructor, when that callee is one; or the vtable an inlined constructor
//!   stored) until the slot is written again, and the objects a slot holds on two joined paths
//!   are one. The facts kept: the direct calls and
//!   tail jumps with the pointers passed in `rdi rsi rdx rcx r8 r9` (an argument that is no
//!   pointer — unknown, a constant other than 0 — makes the callee's parameter unknown), the
//!   vtables stored at `[p + 0]` (a constructor or destructor; a primary vtable at `[p + k]`:
//!   an embedded member object), the pointers stored into fields, the pointer left in `rax`
//!   at each `ret`, and the functions whose address is taken (`lea r, [rip + f]`).
//! * **Classes.** The polymorphic classes come from the RTTI: a vtable's address point is
//!   a run of code pointers behind a `type_info` pointer and an offset-to-top; the class's
//!   primary vtable has offset-to-top 0, its bases come from the `type_info`.
//! * **Seeds.** A method listed in primary vtables has the class all of them derive from as
//!   `this` (the second argument for a method returning a struct in memory); a function
//!   storing a vtable into its argument `i` (a constructor / destructor) has that class there
//!   (the most derived of several). The other parameters of a function listed in a vtable, and
//!   every parameter of a function whose address is taken or with no direct caller, are
//!   unknown (it can be called from anywhere).
//! * **Propagation.** The class of parameter `j` of `f` is the join of what every direct call
//!   of `f` passes there: the caller's own parameter's class, a local object's class (from the
//!   vtables stored into it and the seeds of the calls made on it — its constructor, destructor,
//!   virtual methods called directly; or the callee's return class for a call result), the
//!   class of a field of an object of a known class (the join of
//!   the objects stored there by any function of that class or its bases), an embedded member's
//!   class. The join of two classes is their nearest common base (unknown when there is none);
//!   one unknown caller makes the parameter unknown. The return class of a function is the
//!   join of what it returns. Rounds are repeated (from "nothing known") until nothing changes
//!   or the budget runs out.
//!
//! The index records, per function, the class (primary vtable) of each parameter known, the
//! return class, and the field / member classes by container class.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use rayon::prelude::*;
use reargo_loader::{Memory, MemoryFlags};
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;

/// Integer argument registers (System V): rdi rsi rdx rcx r8 r9 (iced GPR numbers).
const ARG_REGS: [usize; 6] = [7, 6, 2, 1, 8, 9];
/// Registers a call clobbers (rax is the result).
const CALLER_SAVED: [usize; 9] = [0, 1, 2, 6, 7, 8, 9, 10, 11];
const RAX: usize = 0;
const RSP: usize = 4;
const RBP: usize = 5;
/// Most instructions decoded per function.
const MAX_INSNS: usize = 200_000;
/// Most stack slots tracked per state.
const MAX_SLOTS: usize = 48;
/// Most loaded values named per function.
const MAX_LOADS: usize = 4096;
/// Rounds of the propagation.
pub const MAX_ROUNDS: usize = 40;

/// Where a pointer comes from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Src {
    /// argument register `i` on entry
    Arg(u8),
    /// the result of call `c` (an index into [`Summary::call_targets`])
    Ret(u32),
    /// the value loaded from `loads[l]`
    Ld(u32),
    /// the stack (the offset is from the stack pointer on entry)
    Stack,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Val {
    Unk,
    Const(u64),
    Ptr(Src, i32),
    /// (a stack slot only) the object here was first given to call `c` as argument `j` since
    /// the slot was last written: its constructor, when that callee is one
    Made(u32, u8),
}

/// A stack object, by the call it was first given to and the argument: `(call, argument)`.
pub type Instance = (u32, u8);

/// What says the class of a stack object passed to a call, at that call (WS93): the vtable
/// pointer it holds (an inlined constructor stored it), or the call it was first given to
/// (`(call, argument)`: its constructor, when that callee stores a vtable into it). A stack slot
/// is reused for several objects, so this is followed through the function's flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StackEv {
    Vtable(u64),
    Made(u32, u8),
}

/// What one function does with pointers (see the module documentation).
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Summary {
    /// by call id: the direct target, 0 for an indirect call
    pub call_targets: Vec<u64>,
    /// `(call, argument, source, offset)`: a pointer passed to a call
    pub args: Vec<(u32, u8, Src, i32)>,
    /// `(target, mask)`: the arguments a direct call passes that are no pointer
    pub top_args: Vec<(u64, u8)>,
    /// `(call, argument, evidence)`: the class evidence of a stack object passed to a call
    pub stack_ev: Vec<(u32, u8, StackEv)>,
    /// `(call, argument, vtable)`: a vtable stored into the stack object first given to that
    /// call (an inlined destructor or constructor of it)
    pub made_vt: Vec<(u32, u8, u64)>,
    /// two stack objects (by the call first given each) that are one after a join
    pub made_alias: Vec<(Instance, Instance)>,
    /// `(source, offset, vtable)`: a vtable stored at `source + offset`
    pub vt_stores: Vec<(Src, i32, u64)>,
    /// `(source, offset, value source, value offset)`: a pointer stored into a field
    pub field_stores: Vec<(Src, i32, Src, i32)>,
    /// the pointers returned in `rax`
    pub rets: Vec<(Src, i32)>,
    /// a `ret` returns something else
    pub ret_unknown: bool,
    /// `loads[l] = (source, offset)`: `Ld(l)` is the value at `source + offset`
    pub loads: Vec<(Src, i32)>,
    /// addresses taken in code (`lea r, [rip + x]`, `mov r, imm`)
    pub refs: Vec<u64>,
}

impl Summary {
    /// Every `ret` returns the first argument: a struct returned in memory (`this` is next).
    pub fn returns_first(&self) -> bool {
        !self.ret_unknown && !self.rets.is_empty() && self.rets.iter().all(|&r| r == (Src::Arg(0), 0))
    }
}

#[derive(Clone, PartialEq, Debug)]
struct St {
    r: [Val; 16],
    slots: SmallVec<[(i32, Val); 8]>,
}

impl St {
    fn entry() -> St {
        let mut r = [Val::Unk; 16];
        for (i, &a) in ARG_REGS.iter().enumerate() {
            r[a] = Val::Ptr(Src::Arg(i as u8), 0);
        }
        r[RSP] = Val::Ptr(Src::Stack, 0);
        St { r, slots: SmallVec::new() }
    }

    fn unknown() -> St {
        St { r: [Val::Unk; 16], slots: SmallVec::new() }
    }

    /// `self ∧= o`; whether `self` changed.
    fn meet(&mut self, o: &St) -> bool {
        self.meet_objects(o, &mut Vec::new())
    }

    /// [`St::meet`]; two objects a slot holds on two paths (two markers) are one object after
    /// the join: the slot keeps the first marker and `aliases` gets the pair.
    fn meet_objects(&mut self, o: &St, aliases: &mut Vec<(Instance, Instance)>) -> bool {
        let mut changed = false;
        for (a, b) in self.r.iter_mut().zip(o.r.iter()) {
            if *a != *b && *a != Val::Unk {
                *a = Val::Unk;
                changed = true;
            }
        }
        let before = self.slots.clone();
        self.slots.retain(|s| match (s.1, o.slot_raw(s.0)) {
            (Val::Made(a, i), Val::Made(b, j)) if (a, i) != (b, j) => {
                let pair = ((a, i).min((b, j)), (a, i).max((b, j)));
                if !aliases.contains(&pair) {
                    aliases.push(pair);
                }
                s.1 = Val::Made(pair.0 .0, pair.0 .1);
                true
            }
            (x, y) => x == y && o.slots.iter().any(|t| t.0 == s.0),
        });
        changed | (self.slots != before)
    }

    /// The value in the stack slot at `off` (a marker is no value).
    fn slot(&self, off: i32) -> Val {
        match self.slot_raw(off) {
            Val::Made(..) => Val::Unk,
            v => v,
        }
    }

    fn slot_raw(&self, off: i32) -> Val {
        self.slots.iter().find(|s| s.0 == off).map_or(Val::Unk, |s| s.1)
    }

    /// A store of `size` bytes at stack offset `off`.
    fn store_slot(&mut self, off: i32, size: u32, v: Val) {
        let end = i64::from(off) + i64::from(size.max(1));
        self.slots.retain(|s| i64::from(s.0) + 8 <= i64::from(off) || i64::from(s.0) >= end);
        if size == 8 && v != Val::Unk {
            if self.slots.len() >= MAX_SLOTS {
                self.slots.remove(0);
            }
            self.slots.push((off, v));
        }
    }
}

fn gpr(r: Register) -> Option<usize> {
    let f = r.full_register();
    f.is_gpr64().then(|| f as usize - Register::RAX as usize)
}

fn add(v: Val, k: i64) -> Val {
    match v {
        Val::Ptr(s, o) => i32::try_from(i64::from(o) + k).map_or(Val::Unk, |o| Val::Ptr(s, o)),
        Val::Const(c) => Val::Const(c.wrapping_add(k as u64)),
        Val::Unk | Val::Made(..) => Val::Unk,
    }
}

/// The interpretation of one function's instructions (see [`summarize`]).
struct Interp<'a> {
    vt_points: &'a FxHashSet<u64>,
    loads: FxHashMap<(Src, i32), u32>,
    out: Summary,
    info: InstructionInfoFactory,
    /// states after calls and at indirect jumps (the entry of the blocks no jump reaches)
    fallback: Option<St>,
}

impl Interp<'_> {
    fn addr(&self, st: &St, i: &Instruction) -> Val {
        if matches!(i.segment_prefix(), Register::FS | Register::GS) || i.memory_index() != Register::None {
            return Val::Unk;
        }
        let base = i.memory_base();
        if base == Register::RIP {
            return Val::Const(i.ip_rel_memory_address());
        }
        let disp = i.memory_displacement64() as i64;
        match base {
            Register::None => Val::Const(disp as u64),
            b => match gpr(b) {
                Some(g) if b.is_gpr64() => add(st.r[g], disp),
                _ => Val::Unk,
            },
        }
    }

    fn load(&mut self, st: &St, a: Val) -> Val {
        match a {
            Val::Ptr(Src::Stack, s) => st.slot(s),
            Val::Ptr(src, k) => {
                let n = self.loads.len() as u32;
                if let Some(&l) = self.loads.get(&(src, k)) {
                    return Val::Ptr(Src::Ld(l), 0);
                }
                if self.loads.len() >= MAX_LOADS {
                    return Val::Unk;
                }
                self.loads.insert((src, k), n);
                self.out.loads.push((src, k));
                Val::Ptr(Src::Ld(n), 0)
            }
            _ => Val::Unk,
        }
    }

    fn store(&mut self, st: &mut St, a: Val, size: u32, v: Val, emit: bool) {
        match a {
            Val::Ptr(Src::Stack, s) => {
                if emit
                    && size == 8
                    && let (Val::Made(c, j), Val::Const(vt)) = (st.slot_raw(s), v)
                    && self.vt_points.contains(&vt)
                {
                    self.out.made_vt.push((c, j, vt));
                }
                st.store_slot(s, size, v);
                if emit && size == 8
                    && let Val::Const(c) = v
                    && self.vt_points.contains(&c)
                {
                    self.out.vt_stores.push((Src::Stack, s, c));
                }
            }
            Val::Ptr(src, k) if emit && size == 8 => match v {
                Val::Const(c) if self.vt_points.contains(&c) => self.out.vt_stores.push((src, k, c)),
                Val::Ptr(vs, vo) if vs != Src::Stack => self.out.field_stores.push((src, k, vs, vo)),
                _ => {}
            },
            _ => {}
        }
    }

    fn fallback_with(&mut self, st: &St) {
        match &mut self.fallback {
            Some(f) => {
                f.meet(st);
            }
            None => self.fallback = Some(st.clone()),
        }
    }

    /// What the stack slot at `s` says of the object there (see [`StackEv`]).
    fn stack_ev(&self, st: &St, s: i32) -> Option<StackEv> {
        match st.slot_raw(s) {
            Val::Const(c) if self.vt_points.contains(&c) => Some(StackEv::Vtable(c)),
            Val::Made(c, j) => Some(StackEv::Made(c, j)),
            _ => None,
        }
    }

    /// The arguments of call `id` to `target` (0: indirect).
    fn call_args(&mut self, st: &St, id: u32, target: u64) {
        let mut mask = 0u8;
        for (j, &a) in ARG_REGS.iter().enumerate() {
            match st.r[a] {
                Val::Ptr(s, k) => {
                    self.out.args.push((id, j as u8, s, k));
                    if s == Src::Stack
                        && let Some(e) = self.stack_ev(st, k)
                    {
                        self.out.stack_ev.push((id, j as u8, e));
                    }
                }
                Val::Const(0) => {}
                _ => mask |= 1 << j,
            }
        }
        if target != 0 && mask != 0 {
            self.out.top_args.push((target, mask));
        }
    }

    /// One instruction; `call_id` names a call / tail jump, `outside` says a branch leaves
    /// the function.
    fn step(&mut self, st: &mut St, i: &Instruction, call_id: Option<u32>, emit: bool, inside: &dyn Fn(u64) -> bool) {
        let op0 = || (i.op_count() > 0).then(|| i.op0_kind());
        let reg64 = |r: Register| r.is_gpr64();
        match i.mnemonic() {
            Mnemonic::Mov if i.op_count() == 2 => {
                match (i.op0_kind(), i.op1_kind()) {
                    (OpKind::Register, OpKind::Register) => {
                        let (d, s) = (i.op0_register(), i.op1_register());
                        if let Some(g) = gpr(d) {
                            st.r[g] = if reg64(d) && reg64(s) { gpr(s).map_or(Val::Unk, |x| st.r[x]) } else { Val::Unk };
                        }
                    }
                    (OpKind::Register, OpKind::Memory) => {
                        let d = i.op0_register();
                        if let Some(g) = gpr(d) {
                            st.r[g] = if reg64(d) {
                                let a = self.addr(st, i);
                                self.load(st, a)
                            } else {
                                Val::Unk
                            };
                        }
                    }
                    (OpKind::Register, _) => {
                        let d = i.op0_register();
                        if let Some(g) = gpr(d) {
                            st.r[g] = match d.size() {
                                8 => Val::Const(i.immediate(1)),
                                4 => Val::Const(i.immediate(1) & 0xffff_ffff),
                                _ => Val::Unk,
                            };
                            if emit && let Val::Const(c) = st.r[g] {
                                self.out.refs.push(c);
                            }
                        }
                    }
                    (OpKind::Memory, OpKind::Register) => {
                        let s = i.op1_register();
                        let a = self.addr(st, i);
                        let v = if reg64(s) { gpr(s).map_or(Val::Unk, |x| st.r[x]) } else { Val::Unk };
                        self.store(st, a, s.size() as u32, v, emit);
                    }
                    (OpKind::Memory, _) => {
                        let a = self.addr(st, i);
                        let size = i.memory_size().size() as u32;
                        let v = if size == 8 { Val::Const(i.immediate(1)) } else { Val::Unk };
                        self.store(st, a, size, v, emit);
                    }
                    _ => self.generic(st, i),
                }
            }
            Mnemonic::Lea => {
                let d = i.op0_register();
                if let Some(g) = gpr(d) {
                    st.r[g] = if reg64(d) { self.addr(st, i) } else { Val::Unk };
                    if emit && i.memory_base() == Register::RIP {
                        self.out.refs.push(i.ip_rel_memory_address());
                    }
                }
            }
            Mnemonic::Add | Mnemonic::Sub if op0() == Some(OpKind::Register) && reg64(i.op0_register()) && matches!(i.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate8 | OpKind::Immediate32) => {
                let g = gpr(i.op0_register()).expect("gpr64");
                let k = i.immediate(1) as i64;
                st.r[g] = add(st.r[g], if i.mnemonic() == Mnemonic::Sub { k.wrapping_neg() } else { k });
            }
            Mnemonic::Xor | Mnemonic::Sub if i.op_count() == 2 && i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register && i.op0_register() == i.op1_register() => {
                if let Some(g) = gpr(i.op0_register()) {
                    st.r[g] = if i.op0_register().size() >= 4 { Val::Const(0) } else { Val::Unk };
                }
            }
            Mnemonic::Push if i.op_count() == 1 => {
                let v = match i.op0_kind() {
                    OpKind::Register if reg64(i.op0_register()) => gpr(i.op0_register()).map_or(Val::Unk, |g| st.r[g]),
                    OpKind::Immediate8to64 | OpKind::Immediate32to64 => Val::Const(i.immediate(0)),
                    _ => Val::Unk,
                };
                st.r[RSP] = add(st.r[RSP], -8);
                if let Val::Ptr(Src::Stack, s) = st.r[RSP] {
                    st.store_slot(s, 8, v);
                }
            }
            Mnemonic::Pop if i.op_count() == 1 && i.op0_kind() == OpKind::Register && reg64(i.op0_register()) && i.op0_register() != Register::RSP => {
                let v = match st.r[RSP] {
                    Val::Ptr(Src::Stack, s) => st.slot(s),
                    _ => Val::Unk,
                };
                st.r[RSP] = add(st.r[RSP], 8);
                st.r[gpr(i.op0_register()).expect("gpr64")] = v;
            }
            Mnemonic::Leave => {
                st.r[RSP] = st.r[RBP];
                st.r[RBP] = match st.r[RSP] {
                    Val::Ptr(Src::Stack, s) => st.slot(s),
                    _ => Val::Unk,
                };
                st.r[RSP] = add(st.r[RSP], 8);
            }
            Mnemonic::Call => {
                let id = call_id.unwrap_or(u32::MAX);
                let target = if i.op0_kind() == OpKind::NearBranch64 { i.near_branch64() } else { 0 };
                if emit && id != u32::MAX {
                    self.call_args(st, id, target);
                }
                // a stack object passed to the call may be written by it; it stays the object it
                // was (its vtable pointer, the call it was first given to), else this call made it
                let objects: SmallVec<[(i32, Val); 2]> = ARG_REGS
                    .iter()
                    .enumerate()
                    .filter_map(|(j, &a)| match st.r[a] {
                        Val::Ptr(Src::Stack, s) => Some((
                            s,
                            match self.stack_ev(st, s) {
                                Some(StackEv::Vtable(c)) => Val::Const(c),
                                Some(StackEv::Made(c, k)) => Val::Made(c, k),
                                None if id != u32::MAX => Val::Made(id, j as u8),
                                None => Val::Unk,
                            },
                        )),
                        _ => None,
                    })
                    .collect();
                // (what other objects in the frame are — a marker, a vtable pointer — stays)
                if let Some(low) = objects.iter().map(|o| o.0).min() {
                    let vt_points = self.vt_points;
                    st.slots.retain(|s| {
                        s.0 + 8 <= low
                            || (!objects.iter().any(|o| o.0 == s.0) && (matches!(s.1, Val::Made(..)) || matches!(s.1, Val::Const(c) if vt_points.contains(&c))))
                    });
                }
                for &(s, v) in objects.iter().rev() {
                    st.store_slot(s, 8, v);
                }
                for &c in &CALLER_SAVED {
                    st.r[c] = Val::Unk;
                }
                st.r[RAX] = if id != u32::MAX { Val::Ptr(Src::Ret(id), 0) } else { Val::Unk };
                let mut after = st.clone();
                after.r[RAX] = Val::Unk;
                after.r[2] = Val::Unk;
                self.fallback_with(&after);
            }
            Mnemonic::Ret => {
                if emit {
                    match st.r[RAX] {
                        Val::Ptr(s, k) if s != Src::Stack => self.out.rets.push((s, k)),
                        Val::Const(0) => {}
                        _ => self.out.ret_unknown = true,
                    }
                }
            }
            _ => match i.flow_control() {
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                    if i.op0_kind() == OpKind::NearBranch64 && !inside(i.near_branch64()) && emit {
                        // a tail call
                        if let Some(id) = call_id {
                            self.call_args(st, id, i.near_branch64());
                        }
                    }
                }
                FlowControl::IndirectBranch => {
                    let s = st.clone();
                    self.fallback_with(&s);
                }
                _ => self.generic(st, i),
            },
        }
    }

    /// Any other instruction: the registers it writes are unknown, the stack slots it writes
    /// are forgotten.
    fn generic(&mut self, st: &mut St, i: &Instruction) {
        let has_mem = (0..i.op_count()).any(|k| i.op_kind(k) == OpKind::Memory);
        let addr = if has_mem { self.addr(st, i) } else { Val::Unk };
        let info = self.info.info(i);
        for u in info.used_registers() {
            if matches!(u.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
                && let Some(g) = gpr(u.register())
            {
                st.r[g] = Val::Unk;
            }
        }
        let writes_memory = info
            .used_memory()
            .iter()
            .any(|m| matches!(m.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite) && m.base() != Register::RSP);
        if writes_memory {
            match addr {
                Val::Ptr(Src::Stack, s) => st.store_slot(s, i.memory_size().size().max(8) as u32, Val::Unk),
                // a string store through `rdi` into the frame (`rep stosq`): the slots are not known
                _ if !has_mem && matches!(st.r[7], Val::Ptr(Src::Stack, _)) => st.slots.clear(),
                _ => {}
            }
        }
    }
}

/// The summary of the function at `[start, start + len)` (x86-64); `vt_points` are the vtable
/// address points of the binary.
pub fn summarize(mem: &Memory, start: u64, len: u64, vt_points: &FxHashSet<u64>) -> Summary {
    let Some(block) = mem.find_block(start) else { return Summary::default() };
    let Some(data) = block.data.as_ref() else { return Summary::default() };
    let from = (start - block.start) as usize;
    let to = (from as u64 + len).min(data.len() as u64) as usize;
    if from >= to {
        return Summary::default();
    }
    let end = start + (to - from) as u64;
    let mut dec = Decoder::with_ip(64, &data[from..to], start, DecoderOptions::NONE);
    let mut insns: Vec<Instruction> = Vec::new();
    while dec.can_decode() && insns.len() < MAX_INSNS {
        let i = dec.decode();
        if i.is_invalid() {
            break;
        }
        insns.push(i);
    }
    if insns.is_empty() {
        return Summary::default();
    }
    let inside = |a: u64| a >= start && a < end;
    let index_of = |a: u64| insns.binary_search_by_key(&a, |i| i.ip()).ok();

    // call ids: every call, then every branch out of the function (a tail call)
    let mut call_id: Vec<Option<u32>> = vec![None; insns.len()];
    let mut n = 0u32;
    for (k, i) in insns.iter().enumerate() {
        if matches!(i.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            call_id[k] = Some(n);
            n += 1;
        }
    }
    let mut targets: Vec<u64> = insns
        .iter()
        .zip(&call_id)
        .filter(|(_, c)| c.is_some())
        .map(|(i, _)| if i.op0_kind() == OpKind::NearBranch64 { i.near_branch64() } else { 0 })
        .collect();
    for (k, i) in insns.iter().enumerate() {
        if matches!(i.flow_control(), FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch)
            && i.op0_kind() == OpKind::NearBranch64
            && !inside(i.near_branch64())
        {
            call_id[k] = Some(n);
            targets.push(i.near_branch64());
            n += 1;
        }
    }

    // basic blocks
    let mut leader = vec![false; insns.len()];
    leader[0] = true;
    for (k, i) in insns.iter().enumerate() {
        match i.flow_control() {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                if i.op0_kind() == OpKind::NearBranch64
                    && let Some(t) = index_of(i.near_branch64())
                {
                    leader[t] = true;
                }
                if k + 1 < insns.len() {
                    leader[k + 1] = true;
                }
            }
            FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => {
                if k + 1 < insns.len() {
                    leader[k + 1] = true;
                }
            }
            _ => {}
        }
    }
    let starts: Vec<usize> = (0..insns.len()).filter(|&k| leader[k]).collect();
    let block_of = |k: usize| starts.partition_point(|&s| s <= k) - 1;
    let nb = starts.len();
    let block_end = |b: usize| if b + 1 < nb { starts[b + 1] } else { insns.len() };
    let succs = |b: usize| -> SmallVec<[usize; 2]> {
        let last = &insns[block_end(b) - 1];
        let mut s = SmallVec::new();
        let next = (block_end(b) < insns.len()).then(|| b + 1);
        match last.flow_control() {
            FlowControl::UnconditionalBranch => {
                if last.op0_kind() == OpKind::NearBranch64
                    && let Some(t) = index_of(last.near_branch64())
                {
                    s.push(block_of(t));
                }
            }
            FlowControl::ConditionalBranch => {
                if last.op0_kind() == OpKind::NearBranch64
                    && let Some(t) = index_of(last.near_branch64())
                {
                    s.push(block_of(t));
                }
                s.extend(next);
            }
            FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => {}
            _ => s.extend(next),
        }
        s
    };

    let mut it = Interp { vt_points, loads: FxHashMap::default(), out: Summary::default(), info: InstructionInfoFactory::new(), fallback: None };
    let mut states: Vec<Option<St>> = vec![None; nb];
    states[0] = Some(St::entry());
    let mut work: Vec<usize> = vec![0];
    let mut queued = vec![false; nb];
    queued[0] = true;
    for _round in 0..8 {
        let mut steps = 0usize;
        while let Some(b) = work.pop() {
            queued[b] = false;
            steps += 1;
            if steps > nb * 24 + 64 {
                break;
            }
            let Some(mut st) = states[b].clone() else { continue };
            for k in starts[b]..block_end(b) {
                it.step(&mut st, &insns[k], call_id[k], false, &inside);
            }
            for s in succs(b) {
                let changed = match &mut states[s] {
                    Some(old) => old.meet_objects(&st, &mut it.out.made_alias),
                    None => {
                        states[s] = Some(st.clone());
                        true
                    }
                };
                if changed && !queued[s] {
                    queued[s] = true;
                    work.push(s);
                }
            }
        }
        // blocks no jump reaches: from the states after calls / at indirect jumps
        let unreached: Vec<usize> = (0..nb).filter(|&b| states[b].is_none()).collect();
        if unreached.is_empty() {
            break;
        }
        let fb = it.fallback.clone().unwrap_or_else(St::unknown);
        for b in unreached {
            states[b] = Some(fb.clone());
            queued[b] = true;
            work.push(b);
        }
    }
    // the facts, from the states found
    it.out.call_targets = targets;
    for b in 0..nb {
        let mut st = states[b].clone().unwrap_or_else(St::unknown);
        for k in starts[b]..block_end(b) {
            it.step(&mut st, &insns[k], call_id[k], true, &inside);
        }
    }
    let mut out = it.out;
    out.refs.retain(|&r| r != 0);
    out.refs.sort_unstable();
    out.refs.dedup();
    out
}

/// The polymorphic classes of a binary, from its RTTI.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Hierarchy {
    /// class -> its primary vtable (address point)
    pub vtables: Vec<u64>,
    /// class -> its bases at offset 0 (transitively; not itself): a pointer to an object is a
    /// pointer to each of them
    pub bases: Vec<Vec<u32>>,
}

impl Hierarchy {
    fn derives(&self, a: u32, b: u32) -> bool {
        a == b || self.bases[a as usize].contains(&b)
    }

    /// The nearest common base of two classes (one of them when it is a base of the other).
    pub fn join(&self, a: u32, b: u32) -> Option<u32> {
        if self.derives(a, b) {
            return Some(b);
        }
        if self.derives(b, a) {
            return Some(a);
        }
        let common: Vec<u32> = self.bases[a as usize].iter().copied().filter(|c| self.bases[b as usize].contains(c)).collect();
        common.iter().copied().find(|&c| common.iter().all(|&o| self.derives(c, o)))
    }

    /// The class deriving from all of `cs` (`None` when no one does).
    pub fn most_derived(&self, cs: &[u32]) -> Option<u32> {
        cs.iter().copied().find(|&c| cs.iter().all(|&o| self.derives(c, o)))
    }
}

/// The lattice of the propagation: nothing known yet, unknown (any class), or a class.
const BOT: u32 = 0;
const TOP: u32 = 1;
fn cls(c: u32) -> u32 {
    c + 2
}

/// The index of one binary (see the module documentation).
#[derive(Default, Debug, Clone, PartialEq)]
pub struct ThisIndex {
    pub hierarchy: Hierarchy,
    /// function -> the class of each integer parameter its callers give it (`u32::MAX`: not
    /// known) — not the classes a vtable listing the function or a vtable it stores into its
    /// argument gives (the decompiler finds those itself)
    pub params: FxHashMap<u64, [u32; 6]>,
    /// function -> the class of the pointer it returns
    pub rets: FxHashMap<u64, u32>,
    /// `(container class, offset)` -> the class of the pointer stored there (lattice value:
    /// class + 2)
    pub fields: FxHashMap<(u32, i32), u32>,
    /// `(container class, offset)` -> the class of the member object embedded there (class + 2)
    pub members: FxHashMap<(u32, i32), u32>,
    pub stats: IndexStats,
}

/// How the index was built.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct IndexStats {
    pub functions: u64,
    pub classes: u64,
    pub rounds: u64,
    pub converged: bool,
    /// functions whose `this` class a vtable gives (listing it, or stored into `this`)
    pub seeded_this: u64,
    pub summarize_ms: u64,
    pub solve_ms: u64,
}

impl ThisIndex {
    fn vt(&self, c: u32) -> Option<u64> {
        (c != u32::MAX).then(|| self.hierarchy.vtables.get(c as usize).copied()).flatten()
    }

    /// The class (primary vtable) of integer parameter `i` of `f`.
    pub fn param_class(&self, f: u64, i: usize) -> Option<u64> {
        self.params.get(&f).and_then(|p| self.vt(*p.get(i)?))
    }

    /// The class (primary vtable) of the pointer `f` returns.
    pub fn ret_class(&self, f: u64) -> Option<u64> {
        self.rets.get(&f).and_then(|&c| self.vt(c))
    }

    fn class_of_vtable(&self, vt: u64) -> Option<u32> {
        self.hierarchy.vtables.iter().position(|&v| v == vt).map(|c| c as u32)
    }

    /// The class (primary vtable) of the pointer stored at offset `off` of objects of the class
    /// whose primary vtable is `vt`: the join of what the functions of that class and of its
    /// bases store there.
    pub fn field_class(&self, vt: u64, off: i64) -> Option<u64> {
        let c = self.class_of_vtable(vt)?;
        let off = i32::try_from(off).ok()?;
        let l = lookup(&self.hierarchy, &self.fields, c, off);
        (l >= 2).then(|| self.vt(l - 2)).flatten()
    }

    /// The fields and member objects of known class of the class whose primary vtable is `vt`
    /// (its own and its bases'): `(offset, class vtable, member)` by offset.
    pub fn class_fields(&self, vt: u64) -> Vec<(i32, u64, bool)> {
        let Some(c) = self.class_of_vtable(vt) else { return Vec::new() };
        let mut offs: Vec<(i32, bool)> = Vec::new();
        for k in std::iter::once(c).chain(self.hierarchy.bases[c as usize].iter().copied()) {
            offs.extend(self.fields.keys().filter(|f| f.0 == k).map(|f| (f.1, false)));
            offs.extend(self.members.keys().filter(|f| f.0 == k).map(|f| (f.1, true)));
        }
        offs.sort_unstable();
        offs.dedup();
        offs.into_iter()
            .filter_map(|(off, m)| {
                let l = lookup(&self.hierarchy, if m { &self.members } else { &self.fields }, c, off);
                Some((off, self.vt((l >= 2).then(|| l - 2)?)?, m))
            })
            .collect()
    }

    /// The number of functions whose parameter `i` has a class from the callers.
    pub fn count_known(&self, i: usize) -> usize {
        self.params.values().filter(|p| p[i] != u32::MAX).count()
    }
}

/// The class at `(c, off)` in `map`, joined over `c` and its bases.
fn lookup(h: &Hierarchy, map: &FxHashMap<(u32, i32), u32>, c: u32, off: i32) -> u32 {
    let mut out = BOT;
    for k in std::iter::once(c).chain(h.bases[c as usize].iter().copied()) {
        if let Some(&v) = map.get(&(k, off)) {
            out = join(h, out, v);
        }
    }
    out
}

fn join(h: &Hierarchy, a: u32, b: u32) -> u32 {
    match (a, b) {
        (BOT, x) | (x, BOT) => x,
        (TOP, _) | (_, TOP) => TOP,
        (x, y) if x == y => x,
        (x, y) => h.join(x - 2, y - 2).map_or(TOP, cls),
    }
}

/// Pointer words of the data: `(address, value)` in address order — the relative relocations
/// of a PIE, else the aligned words of the non-executable blocks that point into code.
fn pointer_words(mem: &Memory) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    if let Some(t) = mem.dynamic_relocations() {
        for e in t.chunks_exact(24) {
            let w = |k: usize| u64::from_le_bytes(e[k * 8..k * 8 + 8].try_into().expect("8 bytes"));
            let ty = w(1) & 0xffff_ffff;
            if ty == 8 || ty == 1027 {
                out.push((w(0), w(2)));
            }
        }
    } else {
        for b in mem.blocks().filter(|b| !b.flags.contains(MemoryFlags::EXECUTE)) {
            let Some(data) = &b.data else { continue };
            let skip = ((8 - b.start % 8) % 8) as usize;
            for (k, w) in data.get(skip..).unwrap_or(&[]).chunks_exact(8).enumerate() {
                let v = u64::from_le_bytes(w.try_into().expect("8 bytes"));
                if v != 0 && crate::vcall::is_code(mem, v) {
                    out.push((b.start + skip as u64 + k as u64 * 8, v));
                }
            }
        }
    }
    out.sort_unstable();
    out
}

/// The vtables of the binary: `(address point, offset-to-top, type_info, slots)`.
fn vtables(mem: &Memory, words: &[(u64, u64)]) -> Vec<(u64, i64, u64, Vec<u64>)> {
    let exec: Vec<(u64, u64)> = mem.blocks().filter(|b| b.flags.contains(MemoryFlags::EXECUTE)).map(|b| (b.start, b.start + b.size)).collect();
    let is_code = |a: u64| exec.iter().any(|&(s, e)| a >= s && a < e);
    let mut ti_ok: FxHashMap<u64, bool> = FxHashMap::default();
    let mut out = Vec::new();
    let mut k = 1;
    while k < words.len() {
        let (p, f) = words[k];
        let (q, ti) = words[k - 1];
        if q + 8 != p || !is_code(f) || is_code(ti) {
            k += 1;
            continue;
        }
        let ok = *ti_ok.entry(ti).or_insert_with(|| crate::vcall::type_info_name(mem, ti).is_some());
        let ott = mem.read_u64(p - 16).ok().map(|v| v as i64).filter(|o| (-0x10_0000..=0).contains(o));
        let (true, Some(ott)) = (ok, ott) else {
            k += 1;
            continue;
        };
        let mut slots = Vec::new();
        let mut j = k;
        while j < words.len() && words[j].0 == p + 8 * (j - k) as u64 && is_code(words[j].1) {
            slots.push(words[j].1);
            j += 1;
        }
        out.push((p, ott, ti, slots));
        k = j.max(k + 1);
    }
    out
}

/// The direct bases at offset 0 of the class whose `type_info` is at `ti` (not virtual): the
/// one base of a `__si_class_type_info` (`ti+16`), the bases of a `__vmi_class_type_info` (a
/// count at `ti+20`, `{base, offset_flags}` pairs from `ti+24`; offset = flags >> 8, bit 0 =
/// virtual) whose offset is 0. A pointer to the object is a pointer to these bases; a base at
/// another offset is reached through `this + k`, another value.
fn zero_offset_bases(mem: &Memory, ti: u64) -> Vec<u64> {
    let is_ti = |b: u64| crate::vcall::type_info_name(mem, b).is_some();
    if let Some(b) = crate::vcall::pointer_at(mem, ti + 16).filter(|&b| is_ti(b)) {
        return vec![b];
    }
    let Some(n) = mem.read_u32(ti + 20).ok().filter(|n| (1..=64).contains(n)) else { return Vec::new() };
    (0..u64::from(n))
        .filter_map(|i| {
            let b = crate::vcall::pointer_at(mem, ti + 24 + 16 * i).filter(|&b| is_ti(b))?;
            let flags = mem.read_u64(ti + 32 + 16 * i).ok()? as i64;
            (flags & 1 == 0 && flags >> 8 == 0).then_some(b)
        })
        .collect()
}

/// What [`solve`] needs to know about the binary.
pub struct Universe {
    pub hierarchy: Hierarchy,
    /// every vtable address point (primary or not)
    pub vt_points: FxHashSet<u64>,
    /// a vtable address point -> its class, when it is a primary vtable
    pub primary: FxHashMap<u64, u32>,
    /// a function -> the primary vtables listing it (classes)
    pub listing: FxHashMap<u64, Vec<u32>>,
    /// functions whose address is in data (not a vtable slot) or in a non-primary vtable only
    pub taken: FxHashSet<u64>,
}

/// The classes, vtables and data references of a binary.
pub fn universe(mem: &Memory) -> Universe {
    let words = pointer_words(mem);
    let vts = vtables(mem, &words);
    let mut by_ti: FxHashMap<u64, u32> = FxHashMap::default();
    let mut hier = Hierarchy::default();
    let mut tis: Vec<u64> = Vec::new();
    for (p, ott, ti, _) in &vts {
        if *ott == 0 && !by_ti.contains_key(ti) {
            by_ti.insert(*ti, hier.vtables.len() as u32);
            hier.vtables.push(*p);
            tis.push(*ti);
        }
    }
    let direct: Vec<Vec<u64>> = tis.par_iter().map(|&ti| zero_offset_bases(mem, ti)).collect();
    let direct_of: FxHashMap<u64, &Vec<u64>> = tis.iter().copied().zip(direct.iter()).collect();
    for &ti in &tis {
        let mut seen: Vec<u64> = Vec::new();
        let mut work: Vec<u64> = direct_of.get(&ti).map(|v| v.to_vec()).unwrap_or_else(|| zero_offset_bases(mem, ti));
        while let Some(t) = work.pop() {
            if seen.contains(&t) || seen.len() > 64 {
                continue;
            }
            seen.push(t);
            match direct_of.get(&t) {
                Some(v) => work.extend(v.iter().copied()),
                None => work.extend(zero_offset_bases(mem, t)),
            }
        }
        hier.bases.push(seen.iter().filter_map(|t| by_ti.get(t).copied()).collect());
    }
    let mut listing: FxHashMap<u64, Vec<u32>> = FxHashMap::default();
    let mut in_vtables: FxHashSet<u64> = FxHashSet::default();
    let mut slot_words: FxHashSet<u64> = FxHashSet::default();
    let mut primary: FxHashMap<u64, u32> = FxHashMap::default();
    for (p, ott, ti, slots) in &vts {
        for (s, &f) in slots.iter().enumerate() {
            slot_words.insert(p + 8 * s as u64);
            in_vtables.insert(f);
        }
        if *ott == 0
            && let Some(&c) = by_ti.get(ti)
        {
            primary.insert(*p, c);
            for &f in slots {
                let e = listing.entry(f).or_default();
                if !e.contains(&c) {
                    e.push(c);
                }
            }
        }
    }
    let mut taken: FxHashSet<u64> = words.iter().filter(|w| !slot_words.contains(&w.0)).map(|w| w.1).collect();
    taken.extend(in_vtables.into_iter().filter(|f| !listing.contains_key(f)));
    Universe { hierarchy: hier, vt_points: vts.iter().map(|v| v.0).collect(), primary, listing, taken }
}

/// The classes known in a round, to evaluate the values of one function.
struct Ctx<'a> {
    h: &'a Hierarchy,
    starts: &'a [u64],
    sums: &'a [Summary],
    evidence: &'a [FxHashMap<(Src, i32), u32>],
    stack: &'a [FxHashMap<(u32, u8), u32>],
    p: &'a [[u32; 6]],
    r: &'a [u32],
    fields: &'a FxHashMap<(u32, i32), u32>,
    members: &'a FxHashMap<(u32, i32), u32>,
}

impl Ctx<'_> {
    fn fidx(&self, a: u64) -> Option<usize> {
        self.starts.binary_search(&a).ok()
    }

    /// The class of the object `src` points to in function `k` (`ld`: of its loaded values).
    fn base(&self, k: usize, src: Src, ld: &[u32]) -> u32 {
        let ev = &self.evidence[k];
        match src {
            Src::Arg(i) => self.p[k][i as usize],
            Src::Stack => TOP,
            Src::Ret(c) => ev.get(&(src, 0)).copied().unwrap_or_else(|| match self.fidx(self.sums[k].call_targets[c as usize]) {
                Some(t) => self.r[t],
                None => TOP,
            }),
            Src::Ld(l) => ev.get(&(src, 0)).copied().unwrap_or(ld[l as usize]),
        }
    }

    /// The class of argument `j` of call `c` of function `k`, the object at `src + off`.
    fn arg_value(&self, k: usize, c: u32, j: u8, src: Src, off: i32, ld: &[u32]) -> u32 {
        match src {
            Src::Stack => self.stack[k].get(&(c, j)).copied().unwrap_or(TOP),
            _ => self.value(k, src, off, ld),
        }
    }

    /// The class of the object at `src + off` (a member object when `off` is not 0).
    fn value(&self, k: usize, src: Src, off: i32, ld: &[u32]) -> u32 {
        if src == Src::Stack {
            return TOP;
        }
        let b = self.base(k, src, ld);
        if off == 0 || b < 2 {
            return b;
        }
        match lookup(self.h, self.members, b - 2, off) {
            BOT => TOP,
            m => m,
        }
    }

    /// The classes of the values function `k` loads (a field's class by its container's).
    fn loads(&self, k: usize) -> Vec<u32> {
        let s = &self.sums[k];
        let mut ld = vec![BOT; s.loads.len()];
        for l in 0..s.loads.len() {
            let (src, off) = s.loads[l];
            let c = self.base(k, src, &ld);
            ld[l] = if c >= 2 {
                match lookup(self.h, self.fields, c - 2, off) {
                    BOT => TOP,
                    v => v,
                }
            } else {
                c
            };
        }
        ld
    }
}

/// What one function contributes in a round: `(callee, parameter, class)`, its return class,
/// field classes and member classes by `(container class, offset)`.
type Contributions = (Vec<(u32, u8, u32)>, u32, Vec<((u32, i32), u32)>, Vec<((u32, i32), u32)>);

/// The propagation over the summaries of the functions `starts` (address order); `external`
/// functions (exported) may be called with anything.
pub fn solve(u: &Universe, starts: &[u64], sums: &[Summary], external: &FxHashSet<u64>, max_rounds: usize) -> ThisIndex {
    let h = &u.hierarchy;
    let n = starts.len();
    let fidx = |a: u64| starts.binary_search(&a).ok();
    let class_of_vt = |vt: u64| u.primary.get(&vt).copied();

    // seeds: a vtable listing the function, a vtable stored into an argument
    let mut fixed = vec![[false; 6]; n];
    let mut seed = vec![[BOT; 6]; n];
    let mut has_callers = vec![false; n];
    let mut taken = vec![false; n];
    for s in sums {
        for &t in &s.call_targets {
            if let Some(k) = fidx(t) {
                has_callers[k] = true;
            }
        }
        for &r in &s.refs {
            if let Some(k) = fidx(r) {
                taken[k] = true;
            }
        }
    }
    for (k, &f) in starts.iter().enumerate() {
        let s = &sums[k];
        for i in 0..6u8 {
            let cs: Vec<u32> = s.vt_stores.iter().filter(|v| v.0 == Src::Arg(i) && v.1 == 0).filter_map(|v| class_of_vt(v.2)).collect();
            if !cs.is_empty() {
                fixed[k][i as usize] = true;
                seed[k][i as usize] = h.most_derived(&cs).map_or(TOP, cls);
            }
        }
        let listed = u.listing.contains_key(&f);
        if let Some(cs) = u.listing.get(&f) {
            let this = usize::from(s.returns_first());
            let common = cs.iter().copied().find(|&c| cs.iter().all(|&o| h.derives(o, c)));
            if !fixed[k][this] {
                fixed[k][this] = true;
                seed[k][this] = common.map_or(TOP, cls);
            }
        }
        if listed || u.taken.contains(&f) || taken[k] || !has_callers[k] || external.contains(&f) {
            for i in 0..6 {
                if !fixed[k][i] {
                    fixed[k][i] = true;
                    seed[k][i] = TOP;
                }
            }
        }
    }
    // the arguments that are no pointer
    let mut static_top = vec![0u8; n];
    for s in sums {
        for &(t, m) in &s.top_args {
            if let Some(k) = fidx(t) {
                static_top[k] |= m;
            }
        }
    }
    let init: Vec<[u32; 6]> = (0..n)
        .map(|k| {
            let mut p = seed[k];
            for i in 0..6 {
                if !fixed[k][i] && static_top[k] & (1 << i) != 0 {
                    p[i] = TOP;
                }
            }
            p
        })
        .collect();

    // the objects whose class the seeds say (vtables stored into them, constructors called on
    // them), per function: (source, offset) -> class
    let evidence: Vec<FxHashMap<(Src, i32), u32>> = sums
        .par_iter()
        .map(|s| {
            let mut ev: FxHashMap<(Src, i32), Vec<u32>> = FxHashMap::default();
            for &(src, k, vt) in &s.vt_stores {
                let key = match src {
                    Src::Stack | Src::Arg(_) => continue,
                    _ if k == 0 => (src, 0),
                    _ => continue,
                };
                if let Some(c) = class_of_vt(vt) {
                    ev.entry(key).or_default().push(c);
                }
            }
            for &(c, j, src, k) in &s.args {
                let Some(t) = fidx(s.call_targets[c as usize]) else { continue };
                if !fixed[t][j as usize] || seed[t][j as usize] < 2 || matches!(src, Src::Arg(_) | Src::Stack) {
                    continue;
                }
                let key = match src {
                    _ if k == 0 => (src, 0),
                    _ => continue,
                };
                ev.entry(key).or_default().push(seed[t][j as usize] - 2);
            }
            ev.into_iter().map(|(key, cs)| (key, h.most_derived(&cs).map_or(TOP, cls))).collect()
        })
        .collect();
    // the stack objects passed to calls: the vtable they hold there, else the most derived of
    // the seeds of the calls made on that object — the one first given to call `c` as argument
    // `j` (its constructor, the destructor, the virtual methods called directly) — and of the
    // vtables stored into it (an inlined destructor)
    let stack: Vec<FxHashMap<(u32, u8), u32>> = sums
        .par_iter()
        .map(|s| {
            let seed_of = |c: u32, j: u8| match fidx(s.call_targets[c as usize]) {
                Some(t) if fixed[t][j as usize] && seed[t][j as usize] >= 2 => Some(seed[t][j as usize] - 2),
                _ => None,
            };
            // (objects joined at a merge of paths are one)
            let mut parent: FxHashMap<(u32, u8), (u32, u8)> = FxHashMap::default();
            fn root(parent: &FxHashMap<(u32, u8), (u32, u8)>, mut x: (u32, u8)) -> (u32, u8) {
                while let Some(&p) = parent.get(&x) {
                    if p == x {
                        break;
                    }
                    x = p;
                }
                x
            }
            for &(a, b) in &s.made_alias {
                let (ra, rb) = (root(&parent, a), root(&parent, b));
                if ra != rb {
                    parent.insert(ra.max(rb), ra.min(rb));
                }
            }
            let mut objects: FxHashMap<(u32, u8), Vec<u32>> = FxHashMap::default();
            for &(c, j, vt) in &s.made_vt {
                objects.entry(root(&parent, (c, j))).or_default().extend(class_of_vt(vt));
            }
            for &(c, j, e) in &s.stack_ev {
                if let StackEv::Made(c2, j2) = e {
                    let o = objects.entry(root(&parent, (c2, j2))).or_default();
                    o.extend(seed_of(c2, j2));
                    o.extend(seed_of(c, j));
                }
            }
            for &(a, b) in &s.made_alias {
                for x in [a, b] {
                    objects.entry(root(&parent, x)).or_default().extend(seed_of(x.0, x.1));
                }
            }
            // (a call given an object with no evidence yet made it: the object is that instance)
            let ev: FxHashMap<(u32, u8), StackEv> = s.stack_ev.iter().map(|&(c, j, e)| ((c, j), e)).collect();
            s.args
                .iter()
                .filter(|a| a.2 == Src::Stack)
                .map(|&(c, j, _, _)| {
                    let v = match ev.get(&(c, j)).copied().unwrap_or(StackEv::Made(c, j)) {
                        StackEv::Vtable(vt) => class_of_vt(vt).map_or(TOP, cls),
                        StackEv::Made(c2, j2) => {
                            let mut cs = objects.get(&root(&parent, (c2, j2))).cloned().unwrap_or_default();
                            cs.extend(seed_of(c2, j2));
                            if cs.is_empty() { TOP } else { h.most_derived(&cs).map_or(TOP, cls) }
                        }
                    };
                    ((c, j), v)
                })
                .collect()
        })
        .collect();
    let mut p = init.clone();
    let mut r = vec![BOT; n];
    let mut fields: FxHashMap<(u32, i32), u32> = FxHashMap::default();
    let mut members: FxHashMap<(u32, i32), u32> = FxHashMap::default();
    let mut rounds = 0;
    let mut converged = false;
    while rounds < max_rounds {
        rounds += 1;
        // per function: the class of each loaded value, then the contributions
        let per: Vec<Contributions> = (0..n)
            .into_par_iter()
            .map(|k| {
                let s = &sums[k];
                let cx = Ctx { h, starts, sums, evidence: &evidence, stack: &stack, p: &p, r: &r, fields: &fields, members: &members };
                let ld = cx.loads(k);
                let value = |src: Src, off: i32, ld: &[u32]| cx.value(k, src, off, ld);
                let base = |src: Src, ld: &[u32]| cx.base(k, src, ld);
                let mut contrib = Vec::new();
                for &(c, j, src, off) in &s.args {
                    let Some(t) = fidx(s.call_targets[c as usize]) else { continue };
                    if fixed[t][j as usize] {
                        continue;
                    }
                    contrib.push((t as u32, j, cx.arg_value(k, c, j, src, off, &ld)));
                }
                let mut ret = BOT;
                if s.ret_unknown {
                    ret = TOP;
                } else {
                    for &(src, off) in &s.rets {
                        ret = join(h, ret, value(src, off, &ld));
                    }
                }
                let mut fs = Vec::new();
                // (a field is past the vtable pointer; a negative offset is no field of this
                // class: `this` of a base class's method reaching the derived object around it)
                for &(src, off, vs, vo) in s.field_stores.iter().filter(|f| f.1 > 0) {
                    let b = base(src, &ld);
                    if b >= 2 {
                        fs.push(((b - 2, off), value(vs, vo, &ld)));
                    }
                }
                let mut ms = Vec::new();
                for &(src, off, vt) in &s.vt_stores {
                    if off <= 0 || src == Src::Stack {
                        continue;
                    }
                    let b = base(src, &ld);
                    if b >= 2
                        && let Some(c) = class_of_vt(vt)
                    {
                        ms.push(((b - 2, off), cls(c)));
                    }
                }
                (contrib, ret, fs, ms)
            })
            .collect();
        let mut np = init.clone();
        let mut nr = vec![BOT; n];
        let mut nf: FxHashMap<(u32, i32), u32> = FxHashMap::default();
        let mut nm: FxHashMap<(u32, i32), u32> = FxHashMap::default();
        for (k, (contrib, ret, fs, ms)) in per.into_iter().enumerate() {
            for (t, j, v) in contrib {
                let e = &mut np[t as usize][j as usize];
                *e = join(h, *e, v);
            }
            nr[k] = ret;
            for (key, v) in fs {
                let e = nf.entry(key).or_insert(BOT);
                *e = join(h, *e, v);
            }
            for (key, v) in ms {
                let e = nm.entry(key).or_insert(BOT);
                *e = join(h, *e, v);
            }
        }
        let same = np == p && nr == r && nf == fields && nm == members;
        p = np;
        r = nr;
        fields = nf;
        members = nm;
        if same {
            converged = true;
            break;
        }
    }

    // (development: `REARGO_THIS_EXPLAIN=0x…,0x…` prints why `this` of those functions is what it is)
    if let Some(list) = std::env::var_os("REARGO_THIS_EXPLAIN") {
        let cx = Ctx { h, starts, sums, evidence: &evidence, stack: &stack, p: &p, r: &r, fields: &fields, members: &members };
        let show = |v: u32| match v {
            BOT => "nothing".to_string(),
            TOP => "unknown".to_string(),
            c => format!("class vtable 0x{:x}", h.vtables[(c - 2) as usize]),
        };
        for t in list.to_string_lossy().split(',').filter_map(|a| u64::from_str_radix(a.trim().trim_start_matches("0x"), 16).ok()) {
            let Some(ti) = fidx(t) else {
                eprintln!("[explain] 0x{t:x}: no function");
                continue;
            };
            eprintln!(
                "[explain] 0x{t:x}: this = {} (fixed {}, listed {}, taken {}, callers {}, a caller passes no pointer {})",
                show(p[ti][0]),
                fixed[ti][0],
                u.listing.contains_key(&t),
                u.taken.contains(&t) || taken[ti] || external.contains(&t),
                has_callers[ti],
                static_top[ti] & 1 != 0
            );
            for (k, s) in sums.iter().enumerate() {
                if s.top_args.iter().any(|&(x, m)| x == t && m & 1 != 0) {
                    eprintln!("[explain]   0x{:x} passes no pointer", starts[k]);
                }
                let ld = cx.loads(k);
                for &(c, j, src, off) in &s.args {
                    if j == 0 && s.call_targets[c as usize] == t {
                        let detail = match src {
                            Src::Ld(l) => format!("{:?}", s.loads[l as usize]),
                            Src::Stack => {
                                let ev: Vec<_> = s.stack_ev.iter().filter(|e| e.0 == c && e.1 == j).collect();
                                let made: Vec<_> = s.made_vt.iter().collect();
                                let on: Vec<_> = s.stack_ev.iter().filter(|e| ev.iter().any(|x| x.2 == e.2)).map(|e| (format!("{:#x}", s.call_targets[e.0 as usize]), e.1)).collect();
                                format!("call {c} ev {ev:?} vtables {made:?} calls on it {on:?}")
                            }
                            _ => String::new(),
                        };
                        eprintln!("[explain]   0x{:x} passes {src:?}+{off:#x} {detail}: {}", starts[k], show(cx.arg_value(k, c, j, src, off, &ld)));
                    }
                }
            }
        }
    }
    let mut idx = ThisIndex { hierarchy: h.clone(), ..Default::default() };
    for k in 0..n {
        let mut q = [u32::MAX; 6];
        for i in 0..6 {
            if !fixed[k][i] && p[k][i] >= 2 {
                q[i] = p[k][i] - 2;
            }
        }
        if q.iter().any(|&v| v != u32::MAX) {
            idx.params.insert(starts[k], q);
        }
        if r[k] >= 2 {
            idx.rets.insert(starts[k], r[k] - 2);
        }
    }
    idx.fields = fields.into_iter().filter(|e| e.1 >= 2).collect();
    idx.members = members.into_iter().filter(|e| e.1 >= 2).collect();
    let seeded_this = (0..n).filter(|&k| seed[k][usize::from(sums[k].returns_first())] >= 2).count() as u64;
    idx.stats = IndexStats { functions: n as u64, classes: h.vtables.len() as u64, rounds: rounds as u64, converged, seeded_this, ..Default::default() };
    idx
}

/// The index of the functions `[start, start + len)` of `mem`; `external` are the functions
/// another module may call (exported).
pub fn build(mem: &Memory, functions: &[(u64, u64)], external: &[u64]) -> ThisIndex {
    let t0 = std::time::Instant::now();
    let u = universe(mem);
    let mut fs: Vec<(u64, u64)> = functions.to_vec();
    fs.sort_unstable();
    fs.dedup_by_key(|f| f.0);
    let sums: Vec<Summary> = fs.par_iter().map(|&(s, l)| summarize(mem, s, l, &u.vt_points)).collect();
    let t1 = std::time::Instant::now();
    let starts: Vec<u64> = fs.iter().map(|f| f.0).collect();
    let mut idx = solve(&u, &starts, &sums, &external.iter().copied().collect(), MAX_ROUNDS);
    idx.stats.summarize_ms = (t1 - t0).as_millis() as u64;
    idx.stats.solve_ms = t1.elapsed().as_millis() as u64;
    idx
}

/// The version of the index format and of the analysis behind it (a cached index of another
/// version is rebuilt).
const INDEX_VERSION: u8 = 8;
const MAGIC: &[u8; 7] = b"RATHIS\0";

impl ThisIndex {
    /// The index as bytes (little-endian; see [`ThisIndex::from_bytes`]).
    pub fn to_bytes(&self, key: u64) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        let u32_ = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
        let u64_ = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_le_bytes());
        b.extend_from_slice(MAGIC);
        b.push(INDEX_VERSION);
        u64_(&mut b, key);
        let s = &self.stats;
        for v in [s.functions, s.classes, s.rounds, u64::from(s.converged), s.summarize_ms, s.solve_ms, s.seeded_this] {
            u64_(&mut b, v);
        }
        u32_(&mut b, self.hierarchy.vtables.len() as u32);
        for (vt, bases) in self.hierarchy.vtables.iter().zip(&self.hierarchy.bases) {
            u64_(&mut b, *vt);
            u32_(&mut b, bases.len() as u32);
            for &c in bases {
                u32_(&mut b, c);
            }
        }
        let mut params: Vec<_> = self.params.iter().collect();
        params.sort_unstable_by_key(|p| p.0);
        u32_(&mut b, params.len() as u32);
        for (f, p) in params {
            u64_(&mut b, *f);
            for &c in p {
                u32_(&mut b, c);
            }
        }
        let mut rets: Vec<_> = self.rets.iter().collect();
        rets.sort_unstable();
        u32_(&mut b, rets.len() as u32);
        for (f, c) in rets {
            u64_(&mut b, *f);
            u32_(&mut b, *c);
        }
        for map in [&self.fields, &self.members] {
            let mut m: Vec<_> = map.iter().collect();
            m.sort_unstable();
            u32_(&mut b, m.len() as u32);
            for ((c, off), v) in m {
                u32_(&mut b, *c);
                u32_(&mut b, *off as u32);
                u32_(&mut b, *v);
            }
        }
        b
    }

    /// The index [`ThisIndex::to_bytes`] wrote, when its key is `key`.
    pub fn from_bytes(b: &[u8], key: u64) -> Option<ThisIndex> {
        struct R<'a>(&'a [u8], usize);
        impl R<'_> {
            fn take(&mut self, n: usize) -> Option<&[u8]> {
                let s = self.0.get(self.1..self.1 + n)?;
                self.1 += n;
                Some(s)
            }
            fn u32(&mut self) -> Option<u32> {
                Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
            }
            fn u64(&mut self) -> Option<u64> {
                Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
            }
        }
        let mut r = R(b, 0);
        if r.take(7)? != MAGIC || r.take(1)?[0] != INDEX_VERSION || r.u64()? != key {
            return None;
        }
        let mut idx = ThisIndex::default();
        let mut st = [0u64; 7];
        for v in st.iter_mut() {
            *v = r.u64()?;
        }
        idx.stats = IndexStats { functions: st[0], classes: st[1], rounds: st[2], converged: st[3] != 0, summarize_ms: st[4], solve_ms: st[5], seeded_this: st[6] };
        let n = r.u32()? as usize;
        for _ in 0..n {
            idx.hierarchy.vtables.push(r.u64()?);
            let k = r.u32()? as usize;
            let mut bases = Vec::with_capacity(k.min(64));
            for _ in 0..k {
                bases.push(r.u32()?);
            }
            idx.hierarchy.bases.push(bases);
        }
        for _ in 0..r.u32()? {
            let f = r.u64()?;
            let mut p = [0u32; 6];
            for c in p.iter_mut() {
                *c = r.u32()?;
            }
            idx.params.insert(f, p);
        }
        for _ in 0..r.u32()? {
            let f = r.u64()?;
            idx.rets.insert(f, r.u32()?);
        }
        for m in 0..2 {
            for _ in 0..r.u32()? {
                let (c, off, v) = (r.u32()?, r.u32()? as i32, r.u32()?);
                if m == 0 {
                    idx.fields.insert((c, off), v);
                } else {
                    idx.members.insert((c, off), v);
                }
            }
        }
        (r.1 == b.len()).then_some(idx)
    }
}

/// A fingerprint of the file at `path`: its size and 64 samples of 4 KiB spread over it.
pub fn file_key(path: &std::path::Path) -> std::io::Result<u64> {
    use std::hash::Hasher;
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut h = rustc_hash::FxHasher::default();
    h.write_u64(len);
    let mut buf = vec![0u8; 4096];
    for k in 0..64u64 {
        let at = if len > 4096 { (len - 4096) / 63 * k } else { 0 };
        f.seek(SeekFrom::Start(at))?;
        let n = f.read(&mut buf)?;
        h.write(&buf[..n]);
    }
    Ok(h.finish())
}

/// Where the index of `binary` is cached: `$REARGO_CACHE_DIR`, else the user's cache directory
/// (`%LOCALAPPDATA%\re-argo`, `$XDG_CACHE_HOME/re-argo`, `~/.cache/re-argo`), else the temp
/// directory; named after the binary and its fingerprint.
pub fn cache_path(binary: &std::path::Path, key: u64) -> std::path::PathBuf {
    let dir = std::env::var_os("REARGO_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(|d| std::path::Path::new(&d).join("re-argo")))
        .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(|d| std::path::Path::new(&d).join("re-argo")))
        .or_else(|| std::env::var_os("HOME").map(|d| std::path::Path::new(&d).join(".cache").join("re-argo")))
        .unwrap_or_else(std::env::temp_dir);
    let name = binary.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "binary".into());
    dir.join(format!("{name}-{key:016x}.this"))
}

/// The index of `binary` (loaded into `mem`, `.eh_frame_hdr` at `hdr`): read from the cache,
/// else built from the functions of the `.eh_frame_hdr` table and saved there (best effort).
/// `rebuild` ignores the cache. `None` when the binary has no such table.
pub fn load_or_build(binary: &std::path::Path, mem: &Memory, hdr: Option<u64>, rebuild: bool) -> Option<ThisIndex> {
    let key = file_key(binary).ok()?;
    let path = cache_path(binary, key);
    if !rebuild
        && let Ok(b) = std::fs::read(&path)
        && let Some(idx) = ThisIndex::from_bytes(&b, key)
    {
        return Some(idx);
    }
    let functions = reargo_loader::fde_functions(mem, hdr?);
    if functions.is_empty() {
        return None;
    }
    let external = std::fs::read(binary).map(|d| reargo_loader::elf_exported_functions(&d)).unwrap_or_default();
    let idx = build(mem, &functions, &external);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        if std::fs::write(&tmp, idx.to_bytes(key)).is_ok() && std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    Some(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Endian;
    use reargo_loader::memory::MemoryBlock;
    use std::sync::Arc;

    fn text(code: &[u8]) -> Memory {
        let mut mem = Memory::new(reargo_core::address::SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock { name: ".text".into(), start: 0x1000, size: code.len() as u64, flags: MemoryFlags::READ | MemoryFlags::EXECUTE, data: Some(Arc::from(code)) });
        mem
    }

    fn this_args(s: &Summary) -> Vec<(u64, Src, i32)> {
        s.args.iter().filter(|a| a.1 == 0).map(|a| (s.call_targets[a.0 as usize], a.2, a.3)).collect()
    }

    /// The pointers passed as the first argument: `this`, a member's address, a loaded field
    /// (also in a tail call), through a callee-saved register.
    #[test]
    fn a_summary_follows_this_through_registers_and_fields() {
        // push rbx ; mov rbx, rdi ; lea rdi, [rbx+0x10] ; call 0x1100 ; mov rdi, rbx ;
        // call 0x1100 ; mov rax, [rbx+8] ; mov rdi, rax ; pop rbx ; jmp 0x1200
        let code = [
            0x53, 0x48, 0x89, 0xfb, 0x48, 0x8d, 0x7b, 0x10, 0xe8, 0xf3, 0x00, 0x00, 0x00, 0x48, 0x89, 0xdf, 0xe8, 0xeb, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x43, 0x08,
            0x48, 0x89, 0xc7, 0x5b, 0xe9, 0xde, 0x01, 0x00, 0x00,
        ];
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &FxHashSet::default());
        assert_eq!(this_args(&s), [(0x1100, Src::Arg(0), 0x10), (0x1100, Src::Arg(0), 0), (0x1200, Src::Ld(0), 0)]);
        assert_eq!(s.loads, [(Src::Arg(0), 8)]);
        // after the first call `rsi` … `r9` are no pointers
        assert!(s.top_args.contains(&(0x1100, 0b11_1110)), "{:?}", s.top_args);
    }

    /// A spilled `this` comes back from its stack slot; two values joined at a branch are no
    /// one pointer; a vtable stored into `this` is a constructor's.
    #[test]
    fn a_summary_follows_spills_and_joins() {
        // sub rsp, 0x18 ; mov [rsp+8], rdi ; call 0x1100 ; mov rdi, [rsp+8] ; call 0x1100 ;
        // test eax, eax ; je L ; mov rdi, rsi ; L: call 0x1100 ; lea rax, [rip+0x2000] ;
        // mov rcx, [rsp+8] ; mov [rcx], rax ; add rsp, 0x18 ; ret
        let code = [
            0x48, 0x83, 0xec, 0x18, // sub rsp, 0x18
            0x48, 0x89, 0x7c, 0x24, 0x08, // mov [rsp+8], rdi
            0xe8, 0xf2, 0x00, 0x00, 0x00, // call 0x1100 (next 0x100e)
            0x48, 0x8b, 0x7c, 0x24, 0x08, // mov rdi, [rsp+8]
            0xe8, 0xe8, 0x00, 0x00, 0x00, // call 0x1100 (next 0x1018)
            0x85, 0xc0, // test eax, eax
            0x74, 0x03, // je +3
            0x48, 0x89, 0xf7, // mov rdi, rsi
            0xe8, 0xdc, 0x00, 0x00, 0x00, // call 0x1100 (next 0x1024)
            0x48, 0x8d, 0x05, 0xd5, 0x0f, 0x00, 0x00, // lea rax, [0x2000] (next 0x102b)
            0x48, 0x8b, 0x4c, 0x24, 0x08, // mov rcx, [rsp+8]
            0x48, 0x89, 0x01, // mov [rcx], rax
            0x48, 0x83, 0xc4, 0x18, // add rsp, 0x18
            0xc3,
        ];
        let vts: FxHashSet<u64> = [0x2000].into_iter().collect();
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &vts);
        // the first two calls get `this`, the third one an unknown value (`this` or `rsi`)
        assert_eq!(this_args(&s), [(0x1100, Src::Arg(0), 0), (0x1100, Src::Arg(0), 0)]);
        assert!(s.top_args.iter().any(|&(t, m)| t == 0x1100 && m & 1 != 0), "{:?}", s.top_args);
        assert_eq!(s.vt_stores, [(Src::Arg(0), 0, 0x2000)]);
        assert!(s.refs.contains(&0x2000));
    }

    /// A stack object is the one its first call made (its constructor, when that callee is
    /// one) until the slot is written again: a reused slot holds another object.
    #[test]
    fn a_stack_object_is_followed_through_the_reuse_of_its_slot() {
        // sub rsp, 0x28 ; mov rdi, rsp ; call 0x1100 ; mov rdi, rsp ; call 0x1200 ;
        // mov qword [rsp], 5 ; mov rdi, rsp ; call 0x1300 ; add rsp, 0x28 ; ret
        let code = [
            0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0xe7, 0xe8, 0xf4, 0x00, 0x00, 0x00, 0x48, 0x89, 0xe7, 0xe8, 0xec, 0x01, 0x00, 0x00, 0x48, 0xc7, 0x04, 0x24,
            0x05, 0x00, 0x00, 0x00, 0x48, 0x89, 0xe7, 0xe8, 0xdc, 0x02, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &FxHashSet::default());
        assert_eq!(this_args(&s), [(0x1100, Src::Stack, -0x28), (0x1200, Src::Stack, -0x28), (0x1300, Src::Stack, -0x28)]);
        // the second call gets the object the first one made; the third one another object
        assert_eq!(s.stack_ev, [(1, 0, StackEv::Made(0, 0))]);
    }

    /// Two objects a slot holds on two paths are one after the join: a vtable stored there
    /// afterwards (an inlined destructor) is the class of both.
    #[test]
    fn stack_objects_joined_at_a_merge_are_one() {
        // sub rsp, 0x28 ; test esi, esi ; je L ; mov rdi, rsp ; call 0x1100 ; jmp M ;
        // L: mov rdi, rsp ; call 0x1200 ; M: lea rax, [0x2000] ; mov [rsp], rax ; add rsp, 0x28 ; ret
        let code = [
            0x48, 0x83, 0xec, 0x28, 0x85, 0xf6, 0x74, 0x0a, 0x48, 0x89, 0xe7, 0xe8, 0xf0, 0x00, 0x00, 0x00, 0xeb, 0x08, 0x48, 0x89, 0xe7, 0xe8, 0xe6, 0x01,
            0x00, 0x00, 0x48, 0x8d, 0x05, 0xdf, 0x0f, 0x00, 0x00, 0x48, 0x89, 0x04, 0x24, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        let vts: FxHashSet<u64> = [0x2000].into_iter().collect();
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &vts);
        assert_eq!(s.made_alias, [((0, 0), (1, 0))]);
        assert_eq!(s.made_vt, [(0, 0, 0x2000)]);
    }

    /// The bases of a class with several (`__vmi_class_type_info`): only those at offset 0.
    #[test]
    fn only_bases_at_offset_zero_count() {
        let mut d = vec![0u8; 0x400];
        let mut w = |at: usize, v: u64| d[at..at + 8].copy_from_slice(&v.to_le_bytes());
        // 0x2000: D (vmi) — name 0x2300, flags 0 / 2 bases: 0x2100 at 0 (public), 0x2200 at +0x10
        w(0x08, 0x2300);
        w(0x10, 2 << 32);
        w(0x18, 0x2100);
        w(0x20, 2);
        w(0x28, 0x2200);
        w(0x30, (0x10 << 8) | 2);
        // 0x2100: B1, 0x2200: B2 (no bases)
        w(0x108, 0x2310);
        w(0x208, 0x2320);
        d[0x300..0x302].copy_from_slice(b"1D");
        d[0x310..0x313].copy_from_slice(b"2B1");
        d[0x320..0x323].copy_from_slice(b"2B2");
        let mut mem = Memory::new(reargo_core::address::SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock { name: ".data.rel.ro".into(), start: 0x2000, size: d.len() as u64, flags: MemoryFlags::READ, data: Some(Arc::from(d.as_slice())) });
        assert_eq!(zero_offset_bases(&mem, 0x2000), [0x2100]);
        assert_eq!(zero_offset_bases(&mem, 0x2100), Vec::<u64>::new());
    }

    /// The join of two classes is their nearest common base.
    #[test]
    fn classes_join_at_their_nearest_common_base() {
        // 0 Shape ; 1 Circle : Shape ; 2 Square : Shape ; 3 Holder ; 4 Disc : Circle
        let h = Hierarchy { vtables: vec![0x10, 0x20, 0x30, 0x40, 0x50], bases: vec![vec![], vec![0], vec![0], vec![], vec![1, 0]] };
        assert_eq!(h.join(1, 2), Some(0));
        assert_eq!(h.join(4, 2), Some(0));
        assert_eq!(h.join(4, 1), Some(1));
        assert_eq!(h.join(1, 3), None);
        assert_eq!(h.most_derived(&[0, 1, 4]), Some(4));
        assert_eq!(h.most_derived(&[1, 2]), None);
        assert_eq!(join(&h, BOT, cls(1)), cls(1));
        assert_eq!(join(&h, cls(1), cls(2)), cls(0));
        assert_eq!(join(&h, cls(1), cls(3)), TOP);
        assert_eq!(join(&h, cls(1), TOP), TOP);
    }

    #[test]
    fn an_index_reads_back_what_it_wrote() {
        let mut idx = ThisIndex { hierarchy: Hierarchy { vtables: vec![0x10, 0x20], bases: vec![vec![], vec![0]] }, ..Default::default() };
        idx.params.insert(0x1000, [1, u32::MAX, 0, u32::MAX, u32::MAX, u32::MAX]);
        idx.rets.insert(0x1100, 0);
        idx.fields.insert((0, 8), cls(1));
        idx.members.insert((1, 0x10), cls(0));
        idx.stats.rounds = 3;
        let b = idx.to_bytes(42);
        assert_eq!(ThisIndex::from_bytes(&b, 42), Some(idx.clone()));
        assert_eq!(ThisIndex::from_bytes(&b, 43), None, "another binary");
        assert_eq!(ThisIndex::from_bytes(&b[..b.len() - 1], 42), None, "truncated");
        assert_eq!(idx.param_class(0x1000, 0), Some(0x20));
        assert_eq!(idx.param_class(0x1000, 1), None);
        assert_eq!(idx.ret_class(0x1100), Some(0x10));
        // a field of a base class is a field of the derived class
        assert_eq!(idx.field_class(0x20, 8), Some(0x20));
        assert_eq!(idx.field_class(0x10, 0x10), None);
    }
}
