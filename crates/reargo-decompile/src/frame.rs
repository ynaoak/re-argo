//! Stack slots by name (WS87): `*(uint64_t*)(rsp + 0x28)` -> `local_30`.
//!
//! The stack pointer's SSA values are followed from the entry: `rsp` on entry is the address of
//! the return address (offset 0), `push` / `sub rsp, n` / `add rsp, n` move it by a constant,
//! and a copy (`mov rbp, rsp`) or an added constant (`lea rdi, [rsp+0x40]`) keeps a known
//! offset; where paths join, the offset is known when every path agrees. Anything else
//! (`and rsp, -32`, a load) is not followed, so an access is named only when its address is
//! provably `entry rsp + k`, whichever register holds it — the name is the same at every
//! access of the slot, also across pushes and different base registers.
//!
//! A slot below the return address (`k < 0`) is `local_<-k>` (hex, as Ghidra names them), its
//! type the widest access starting there. An access starting inside a wider slot prints
//! through that slot: the same start, narrower — `(uint32_t)local_30` to read,
//! `*(uint32_t*)&local_30 = v` to write; further in — `*(uint32_t*)((uint8_t*)&local_30 + 4)`.
//! A frame address taken (`lea rdi, [rsp+0x40]`) is `&local_48` (or inside a slot as above); a
//! region only addressed is an array up to the next slot (`uint8_t local_48[0x18]`). The stack
//! pointer's own updates are not printed when nothing but these reads them.
//!
//! WS88: the caller's frame above the return address holds the stack arguments (SysV: the
//! first is at `entry rsp + 8`): a slot there is `arg_<k>` and a parameter of the function,
//! printed after the register parameters; an address only taken there is an array of unknown
//! length (`uint8_t arg_8[]`, an aggregate passed in memory). The Rust output names the same
//! slots (`local_30 as u32`, `*(&raw mut local_30 as *mut u32) = v`).

use std::collections::BTreeMap;

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::condition::{value_key, ValueKey};
use crate::ssa::{OpIdx, SsaFunction, VarId};

const RSP: u64 = 0x20;

/// Most passes over the ops (offsets through phis settle in a few).
const MAX_PASSES: usize = 8;

/// A named slot: its start (an offset from the entry `rsp`: negative for a local, 8 or more
/// for a stack argument) and size; `array` when only its address is taken (a stack argument's
/// array has size 0: its length is unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    pub start: i64,
    pub size: u32,
    pub array: bool,
}

impl Slot {
    pub fn name(&self) -> String {
        if self.is_arg() {
            format!("arg_{:x}", self.start)
        } else {
            format!("local_{:x}", self.start.unsigned_abs())
        }
    }

    /// A stack argument (in the caller's frame, above the return address).
    pub fn is_arg(&self) -> bool {
        self.start >= ARGS
    }

    /// Its end (exclusive); an argument array of unknown length runs on.
    fn end(&self) -> i64 {
        if self.array && self.size == 0 { i64::MAX } else { self.start + i64::from(self.size) }
    }

    /// The C declaration (`uint64_t local_30`, `uint8_t local_48[0x18]`, `uint8_t arg_8[]`).
    pub fn c_declaration(&self) -> String {
        match (self.array, self.size) {
            (true, 0) => format!("uint8_t {}[]", self.name()),
            (true, n) => format!("uint8_t {}[0x{n:x}]", self.name()),
            (false, n) => format!("{} {}", crate::emit::size_to_type(n), self.name()),
        }
    }

    /// The Rust type (`u64`, `[u8; 0x18]`, `*mut u8` for an argument array of unknown length).
    pub fn rust_type(&self) -> String {
        match (self.array, self.size) {
            (true, 0) => "*mut u8".into(),
            (true, n) => format!("[u8; 0x{n:x}]"),
            (false, n) => crate::rust_emit::size_to_rust_type(n).into(),
        }
    }
}

/// Where the stack arguments start: past the return address.
const ARGS: i64 = 8;

/// Whether an access of `size` bytes at frame offset `k` can be a slot: a local below the
/// return address, or a stack argument above it.
fn slot_range(k: i64, size: u32) -> bool {
    (k < 0 && k.checked_add(i64::from(size)).is_some_and(|e| e <= 0)) || k >= ARGS
}

#[derive(Default)]
pub(crate) struct Frame {
    /// value -> its offset from the entry `rsp` (by value: CSE leaves several names of one)
    offsets: FxHashMap<ValueKey, i64>,
    /// slot start -> slot
    slots: BTreeMap<i64, Slot>,
    /// the entry's `rsp` (offset 0 in the body)
    entry: Option<ValueKey>,
    /// the landing pads' blocks, and the offset of `rsp` there when known (WS88)
    pads: FxHashSet<usize>,
    pad: Option<i64>,
}

fn is_rsp(func: &SsaFunction, v: VarId) -> bool {
    let d = &func.varnodes[v as usize].data;
    d.space == SpaceId::REGISTER && d.offset == RSP && d.size == 8
}

/// The blocks the function's entry does not reach: its exception landing pads and what only
/// they reach (WS88). They read the registers' incoming values — the SSA names them like the
/// entry's — but there the stack pointer is the one at the call that threw, not the entry's.
fn pad_blocks(func: &SsaFunction) -> FxHashSet<usize> {
    let n = func.cfg.blocks.len();
    let mut seen = vec![false; n];
    let mut work = vec![func.cfg.entry_block];
    while let Some(b) = work.pop() {
        if b >= n || std::mem::replace(&mut seen[b], true) {
            continue;
        }
        work.extend(func.cfg.blocks[b].successors.iter().copied());
    }
    (0..n).filter(|&b| !seen[b]).collect()
}

impl Frame {
    /// The offset of value `v` read in block `block` (the entry's `rsp` is 0 in the body, the
    /// landing pads' offset in a pad).
    fn offset_in(&self, func: &SsaFunction, v: VarId, block: usize) -> Option<i64> {
        let key = value_key(func, v);
        if Some(key) == self.entry {
            return if self.pads.contains(&block) { self.pad } else { Some(0) };
        }
        self.offsets.get(&key).copied()
    }

    /// Follow the offsets through copies, constant adds and phis (a few passes).
    fn propagate(&mut self, func: &SsaFunction) {
        let konst = |v: VarId| {
            let d = &func.varnodes[v as usize].data;
            (d.space == SpaceId::CONST).then_some(d.offset as i64)
        };
        for _ in 0..MAX_PASSES {
            let mut changed = false;
            for op in &func.ops {
                let Some(out) = op.output else { continue };
                let key = value_key(func, out);
                if op.dead || func.varnodes[out as usize].data.size != 8 || self.offsets.contains_key(&key) {
                    continue;
                }
                // (a phi's input is read at the end of its predecessor)
                let at = |i: usize| match op.opcode {
                    OpCode::MultiEqual => func.cfg.blocks[op.block].predecessors.get(i).copied().unwrap_or(op.block),
                    _ => op.block,
                };
                let off = |i: usize| op.inputs.get(i).and_then(|&v| self.offset_in(func, v, at(i)));
                let k = match op.opcode {
                    OpCode::Copy => off(0),
                    OpCode::IntAdd => match (off(0), off(1)) {
                        (Some(a), None) => op.inputs.get(1).and_then(|&v| konst(v)).map(|c| a.wrapping_add(c)),
                        (None, Some(b)) => op.inputs.first().and_then(|&v| konst(v)).map(|c| b.wrapping_add(c)),
                        _ => None,
                    },
                    OpCode::IntSub => off(0).and_then(|a| op.inputs.get(1).and_then(|&v| konst(v)).map(|c| a.wrapping_sub(c))),
                    OpCode::MultiEqual => {
                        let ks: Vec<Option<i64>> = (0..op.inputs.len()).map(off).collect();
                        // (a loop's phi reads itself: the other inputs decide)
                        let known: Vec<i64> = ks.iter().flatten().copied().collect();
                        let selfish = op.inputs.iter().zip(&ks).all(|(&v, k)| k.is_some() || value_key(func, v) == key);
                        (selfish && !known.is_empty() && known.iter().all(|&k| k == known[0])).then(|| known[0])
                    }
                    _ => None,
                };
                if let Some(k) = k {
                    self.offsets.insert(key, k);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// The stack pointer's offset at the body's calls, when every call where it is known
    /// agrees (WS88): a landing pad starts with the stack pointer of the call that threw.
    fn offset_at_calls(&self, func: &SsaFunction) -> Option<i64> {
        // the last stack pointer write of each block, and the value reaching each call
        let n = func.cfg.blocks.len();
        let mut last: Vec<Option<VarId>> = vec![None; n];
        let mut at_calls: Vec<(usize, Option<VarId>)> = Vec::new();
        for o in func.ops.iter().filter(|o| !o.dead && o.block < n) {
            if matches!(o.opcode, OpCode::Call | OpCode::CallInd) && !self.pads.contains(&o.block) {
                at_calls.push((o.block, last[o.block]));
            }
            if let Some(w) = o.output.filter(|&w| is_rsp(func, w)) {
                last[o.block] = Some(w);
            }
        }
        // at a block's start: up its single predecessors to a write (or the entry)
        let start = |mut b: usize| -> Option<i64> {
            for _ in 0..64 {
                match func.cfg.blocks[b].predecessors.as_slice() {
                    [] if b == func.cfg.entry_block => return Some(0),
                    [p] => match last[*p] {
                        Some(w) => return self.offset_in(func, w, *p),
                        None => b = *p,
                    },
                    _ => return None,
                }
            }
            None
        };
        let mut k = None;
        for (b, w) in at_calls {
            let x = match w {
                Some(w) => self.offset_in(func, w, b),
                None => start(b),
            };
            match (x, k) {
                (Some(x), None) => k = Some(x),
                (Some(x), Some(y)) if x != y => return None,
                _ => {}
            }
        }
        k
    }

    pub fn new(func: &SsaFunction, live: &dyn Fn(OpIdx) -> bool) -> Self {
        let Some(entry) = func.varnodes.iter().find(|v| v.def_op.is_none() && is_rsp(func, v.id)).map(|v| value_key(func, v.id)) else {
            return Frame::default();
        };
        let pads = pad_blocks(func);
        let mut frame = Frame { offsets: FxHashMap::default(), slots: BTreeMap::new(), entry: Some(entry), pads, pad: None };
        frame.propagate(func);
        if !frame.pads.is_empty() {
            frame.pad = frame.offset_at_calls(func);
            if frame.pad.is_some() {
                frame.propagate(func);
            }
        }

        // the slots: the widest access at each start below the return address
        let mut addressed: Vec<i64> = Vec::new();
        for op in func.ops.iter().filter(|o| !o.dead && live(o.index)) {
            match op.opcode {
                OpCode::Load | OpCode::Store => {
                    let Some(size) = access_size(func, op) else { continue };
                    let Some(k) = op.inputs.get(1).and_then(|&v| frame.offset_in(func, v, op.block)) else { continue };
                    if slot_range(k, size) {
                        let s = frame.slots.entry(k).or_insert(Slot { start: k, size, array: false });
                        s.size = s.size.max(size);
                    }
                }
                _ => {
                    if let Some(out) = op.output
                        && !is_rsp(func, out)
                        && func.varnodes[out as usize].data.space == SpaceId::REGISTER
                        && let Some(k) = frame.offset_of(func, out)
                        && !(0..ARGS).contains(&k)
                    {
                        addressed.push(k);
                    }
                }
            }
        }
        // a start inside a wider slot belongs to it
        let starts: Vec<(i64, Slot)> = frame.slots.iter().map(|(&k, &s)| (k, s)).collect();
        let mut end = i64::MIN;
        for (k, s) in starts {
            if k < end {
                frame.slots.remove(&k);
            } else {
                end = s.end();
            }
        }
        for k in addressed {
            if frame.containing(k).is_some() {
                continue;
            }
            // (a local array ends at the return address at most; an argument array of
            // unknown length runs up to the next slot, if any)
            let next = frame.slots.range(k + 1..).next().map(|(&n, _)| n);
            let size = match (k < 0, next) {
                (true, n) => u32::try_from(n.unwrap_or(0).min(0) - k).unwrap_or(0),
                (false, Some(n)) => u32::try_from(n - k).unwrap_or(0),
                (false, None) => 0,
            };
            if size > 0 || k >= ARGS {
                frame.slots.insert(k, Slot { start: k, size, array: true });
            }
        }
        frame
    }

    /// The slot containing frame offset `k`, and `k`'s distance into it.
    fn containing(&self, k: i64) -> Option<(Slot, u64)> {
        let (_, s) = self.slots.range(..=k).next_back()?;
        (k < s.end()).then(|| (*s, (k - s.start) as u64))
    }

    /// The frame offset value `v` holds, when known.
    pub fn offset_of(&self, func: &SsaFunction, v: VarId) -> Option<i64> {
        self.offsets.get(&value_key(func, v)).copied()
    }

    /// The named slots, by start.
    pub fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.slots.values()
    }

    /// The memory a `size`-byte access at address `v` names, for a load (`as_lvalue` false) or
    /// the left-hand side of a store; in Rust syntax when `rust` (a place: the caller wraps a
    /// dereference in `unsafe`).
    pub fn access(&self, func: &SsaFunction, block: usize, v: VarId, size: u32, as_lvalue: bool, rust: bool) -> Option<String> {
        let k = self.offset_in(func, v, block)?;
        let (s, d) = self.containing(k)?;
        let whole = !s.array && d == 0;
        Some(match (whole, size.cmp(&s.size), rust) {
            (true, std::cmp::Ordering::Equal, _) => s.name(),
            (true, std::cmp::Ordering::Less, false) if as_lvalue => format!("*({}*)&{}", crate::emit::size_to_type(size), s.name()),
            (true, std::cmp::Ordering::Less, false) => format!("({}){}", crate::emit::size_to_type(size), s.name()),
            (true, std::cmp::Ordering::Less, true) if !as_lvalue => format!("({} as {})", s.name(), crate::rust_emit::size_to_rust_type(size)),
            // elsewhere: through the slot's address
            (_, _, false) => format!("*({}*){}", crate::emit::size_to_type(size), self.address_text(s, d, true, false)),
            (_, _, true) => {
                let ptr = if as_lvalue { "*mut" } else { "*const" };
                format!("*({} as {ptr} {})", self.address_text(s, d, true, true), crate::rust_emit::size_to_rust_type(size))
            }
        })
    }

    /// The address `d` bytes into slot `s` (`&local_48`, `(uint8_t*)&local_48 + 0x8`; an array
    /// is its own address), parenthesised when `operand`. In Rust: `&raw mut local_48`,
    /// `(&raw mut local_48 as *mut u8).add(0x8)`, `local_48.as_mut_ptr()`.
    fn address_text(&self, s: Slot, d: u64, operand: bool, rust: bool) -> String {
        if rust {
            let base = match (s.array, s.size) {
                (true, 0) => s.name(),
                (true, _) => format!("{}.as_mut_ptr()", s.name()),
                (false, _) => format!("&raw mut {}", s.name()),
            };
            // (`&raw mut x as *mut u32` casts the reference: no parentheses needed)
            return match (d, s.array) {
                (0, _) => base,
                (_, true) => format!("{base}.add(0x{d:x})"),
                (_, false) => format!("({base} as *mut u8).add(0x{d:x})"),
            };
        }
        let base = if s.array { s.name() } else { format!("&{}", s.name()) };
        match (d, operand) {
            (0, _) => base,
            (_, false) => format!("(uint8_t*){base} + 0x{d:x}"),
            (_, true) => format!("((uint8_t*){base} + 0x{d:x})"),
        }
    }

    /// The address value `v` holds as a slot's address: `&local_48`, inside one
    /// `(uint8_t*)&local_48 + 0x8`.
    pub fn address(&self, func: &SsaFunction, v: VarId, rust: bool) -> Option<String> {
        let k = self.offset_of(func, v)?;
        let (s, d) = self.containing(k)?;
        Some(self.address_text(s, d, false, rust))
    }

    /// The stack pointer updates and stack addresses nothing prints by name: every live reader
    /// is a named access through it, another such op, an address printed as a slot's, or not
    /// printed itself (`noise`: the frame restore before a `ret`).
    pub fn hidden(&self, func: &SsaFunction, noise: &FxHashSet<OpIdx>) -> FxHashSet<OpIdx> {
        let mut hidden: FxHashSet<OpIdx> = FxHashSet::default();
        if self.slots.is_empty() {
            return hidden;
        }
        let readers = crate::condition::Readers::new(func);
        // candidates: ops computing a stack address (`rsp` updates, `rsp + c` temporaries)
        hidden.extend(
            func.ops
                .iter()
                .filter(|o| {
                    !o.dead
                        && matches!(o.opcode, OpCode::IntAdd | OpCode::IntSub | OpCode::Copy)
                        && o.output.is_some_and(|v| {
                            let d = &func.varnodes[v as usize].data;
                            self.offset_of(func, v).is_some() && (is_rsp(func, v) || d.space == SpaceId::UNIQUE)
                        })
                })
                .map(|o| o.index),
        );
        // drop those read by something else, until none is
        loop {
            let before = hidden.len();
            let cur = hidden.clone();
            hidden.retain(|&d| {
                let v = func.ops[d].output.expect("filtered");
                let key = value_key(func, v);
                readers.of(func, v).iter().all(|&u| {
                    let r = &func.ops[u];
                    if cur.contains(&u) || noise.contains(&u) {
                        return true;
                    }
                    let at: Vec<usize> = r.inputs.iter().enumerate().filter(|&(_, &i)| value_key(func, i) == key).map(|(j, _)| j).collect();
                    match r.opcode {
                        // (only as the address, and named)
                        OpCode::Load | OpCode::Store => {
                            at == [1] && access_size(func, r).is_some_and(|sz| self.access(func, r.block, v, sz, r.opcode == OpCode::Store, false).is_some())
                        }
                        // a register holding an address printed as the slot's
                        OpCode::Copy | OpCode::IntAdd | OpCode::IntSub => r.output.is_some_and(|o| !is_rsp(func, o) && self.address(func, o, false).is_some()),
                        // a call's INDIRECT annotations
                        OpCode::Indirect => true,
                        _ => false,
                    }
                })
            });
            if hidden.len() == before {
                break;
            }
        }
        hidden
    }
}

/// The bytes a load reads / a store writes.
pub(crate) fn access_size(func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<u32> {
    match op.opcode {
        OpCode::Load => op.output.map(|o| func.varnodes[o as usize].data.size),
        OpCode::Store => op.inputs.get(2).map(|&v| func.varnodes[v as usize].data.size),
        _ => None,
    }
}
