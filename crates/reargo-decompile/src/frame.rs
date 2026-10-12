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

use std::collections::BTreeMap;

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::condition::{value_key, ValueKey};
use crate::ssa::{OpIdx, SsaFunction, VarId};

const RSP: u64 = 0x20;

/// Most passes over the ops (offsets through phis settle in a few).
const MAX_PASSES: usize = 8;

/// A named slot: its start (a negative offset from the entry `rsp`) and size; `array` when only
/// its address is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    pub start: i64,
    pub size: u32,
    pub array: bool,
}

impl Slot {
    pub fn name(&self) -> String {
        format!("local_{:x}", self.start.unsigned_abs())
    }
}

#[derive(Default)]
pub(crate) struct Frame {
    /// value -> its offset from the entry `rsp` (by value: CSE leaves several names of one)
    offsets: FxHashMap<ValueKey, i64>,
    /// slot start -> slot
    slots: BTreeMap<i64, Slot>,
}

fn is_rsp(func: &SsaFunction, v: VarId) -> bool {
    let d = &func.varnodes[v as usize].data;
    d.space == SpaceId::REGISTER && d.offset == RSP && d.size == 8
}

impl Frame {
    pub fn new(func: &SsaFunction, live: &dyn Fn(OpIdx) -> bool) -> Self {
        let mut offsets: FxHashMap<ValueKey, i64> = FxHashMap::default();
        for v in &func.varnodes {
            if v.def_op.is_none() && is_rsp(func, v.id) {
                offsets.insert(value_key(func, v.id), 0);
            }
        }
        if offsets.is_empty() {
            return Frame::default();
        }
        let konst = |v: VarId| {
            let d = &func.varnodes[v as usize].data;
            (d.space == SpaceId::CONST).then_some(d.offset as i64)
        };
        for _ in 0..MAX_PASSES {
            let mut changed = false;
            for op in &func.ops {
                let Some(out) = op.output else { continue };
                let key = value_key(func, out);
                if op.dead || func.varnodes[out as usize].data.size != 8 || offsets.contains_key(&key) {
                    continue;
                }
                let off = |i: usize| op.inputs.get(i).and_then(|&v| offsets.get(&value_key(func, v)).copied());
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
                    offsets.insert(key, k);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut frame = Frame { offsets, slots: BTreeMap::new() };
        // the slots: the widest access at each start below the return address
        let mut addressed: Vec<i64> = Vec::new();
        for op in func.ops.iter().filter(|o| !o.dead && live(o.index)) {
            match op.opcode {
                OpCode::Load | OpCode::Store => {
                    let Some(size) = access_size(func, op) else { continue };
                    let Some(k) = op.inputs.get(1).and_then(|&v| frame.offset_of(func, v)) else { continue };
                    if k < 0 && k.checked_add(i64::from(size)).is_some_and(|e| e <= 0) {
                        let s = frame.slots.entry(k).or_insert(Slot { start: k, size, array: false });
                        s.size = s.size.max(size);
                    }
                }
                _ => {
                    if let Some(out) = op.output
                        && !is_rsp(func, out)
                        && func.varnodes[out as usize].data.space == SpaceId::REGISTER
                        && let Some(k) = frame.offset_of(func, out)
                        && k < 0
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
                end = k + i64::from(s.size);
            }
        }
        for k in addressed {
            if frame.containing(k).is_some() {
                continue;
            }
            let next = frame.slots.range(k + 1..).next().map_or(0, |(&n, _)| n);
            let size = u32::try_from(next - k).unwrap_or(0);
            if size > 0 {
                frame.slots.insert(k, Slot { start: k, size, array: true });
            }
        }
        frame
    }

    /// The slot containing frame offset `k`, and `k`'s distance into it.
    fn containing(&self, k: i64) -> Option<(Slot, u64)> {
        let (_, s) = self.slots.range(..=k).next_back()?;
        (k < s.start + i64::from(s.size)).then(|| (*s, (k - s.start) as u64))
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
    /// the left-hand side of a store.
    pub fn access(&self, func: &SsaFunction, v: VarId, size: u32, as_lvalue: bool) -> Option<String> {
        let k = self.offset_of(func, v)?;
        let (s, d) = self.containing(k)?;
        let ty = crate::emit::size_to_type(size);
        Some(match (s.array, d, size.cmp(&s.size)) {
            (false, 0, std::cmp::Ordering::Equal) => s.name(),
            (false, 0, std::cmp::Ordering::Less) if as_lvalue => format!("*({ty}*)&{}", s.name()),
            (false, 0, std::cmp::Ordering::Less) => format!("({ty}){}", s.name()),
            // elsewhere: through the slot's address
            _ => format!("*({ty}*){}", self.address_text(s, d, true)),
        })
    }

    /// The address `d` bytes into slot `s` (`&local_48`, `(uint8_t*)&local_48 + 0x8`; an array
    /// is its own address), parenthesised when `operand`.
    fn address_text(&self, s: Slot, d: u64, operand: bool) -> String {
        let base = if s.array { s.name() } else { format!("&{}", s.name()) };
        match (d, operand) {
            (0, _) => base,
            (_, false) => format!("(uint8_t*){base} + 0x{d:x}"),
            (_, true) => format!("((uint8_t*){base} + 0x{d:x})"),
        }
    }

    /// The address value `v` holds as a slot's address: `&local_48`, inside one
    /// `(uint8_t*)&local_48 + 0x8`.
    pub fn address(&self, func: &SsaFunction, v: VarId) -> Option<String> {
        let k = self.offset_of(func, v)?;
        let (s, d) = self.containing(k)?;
        Some(self.address_text(s, d, false))
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
                            at == [1] && access_size(func, r).is_some_and(|sz| self.access(func, v, sz, r.opcode == OpCode::Store).is_some())
                        }
                        // a register holding an address printed as the slot's
                        OpCode::Copy | OpCode::IntAdd | OpCode::IntSub => r.output.is_some_and(|o| !is_rsp(func, o) && self.address(func, o).is_some()),
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
