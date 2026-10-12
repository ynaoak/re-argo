//! Value ranges of the general registers per path (WS86), for the jump-table recovery.
//!
//! A switch's bounds check is not always right before its dispatch: `cmp esi, 5; ja default`
//! may come several blocks earlier, the index copied (`mov eax, esi`) and other tests in
//! between. Read straight back from the `jmp`, the table has no bound; [`Ranges`] finds it by a
//! forward data flow over the lifted instructions:
//!
//! * each block (split at jump targets and after control transfers) starts with, per general
//!   register view (32 / 64 bit), a *value* — two views holding the same value share it, so a
//!   copy made before the check is bounded by it too — and each value an unsigned interval;
//! * an instruction gives the views it writes a new value: a constant, a copy of another view,
//!   a zero extension, `x & c`, `x >> c`, a narrow load are bounded, anything else is unknown; a
//!   call makes the caller-saved registers unknown;
//! * a conditional jump after `cmp r, N` bounds `r`'s value on each edge (`ja`: `r > N` taken,
//!   `r <= N` falling through; `jae` / `jb` / `jbe` alike — unsigned only);
//! * where paths join, a view keeps its value when every path agrees on it (the interval is
//!   the union), else it gets a fresh unknown one.
//!
//! WS87 widened it:
//!
//! * a stack slot (`mov [rsp+0x28], rsi` … `mov rsi, [rsp+0x28]`) holds a value like a register
//!   view does, keyed by the value of `rsp` and the offset, when no address of the frame at or
//!   below it is taken (`lea rdi, [rsp+0x40]` leaves the slots below 0x40 to the function; an
//!   indexed store `[rsp+rax+0x40]` is taken for an array above its constant part);
//! * signed bounds: `cmp r, N; jg / jge / jl / jle` and `test r, r; js / jns` (a value known
//!   non-negative, `movzx`, then `jg 5` falling through is `0..=5`);
//! * `r + c` / `r - c` move the interval when they do not wrap (`lea eax, [rdi-1]`);
//! * a jump table's case edges bound its index (the cases taken to that target: an enum
//!   switch's index is below its case count on each, so a dispatch reading it again later has
//!   the same cases).
//!
//! [`Ranges::at`] answers the interval of a register view as an instruction starts.

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_lift::LiftedInstruction;
use rustc_hash::FxHashMap;

/// An unsigned interval `lo..=hi`.
pub type Interval = (u64, u64);

const FULL: Interval = (0, u64::MAX);

/// A view of a general register: its base offset and size (4 or 8).
type View = (u64, u32);

/// A value: who made it — deterministic, so the iteration settles. The kind in the top bits:
/// written by instruction `k` (`1`), the entry value of a view (`2`), joined at block `b` (`3`).
type Id = u64;

fn slot(v: View) -> u64 {
    (v.0 / 8) * 2 + u64::from(v.1 == 8)
}

fn written(k: usize, v: View) -> Id {
    1 << 62 | (k as u64) << 8 | slot(v)
}

fn entry_value(v: View) -> Id {
    2 << 62 | slot(v)
}

fn joined(b: usize, v: View) -> Id {
    3 << 62 | (b as u64) << 8 | slot(v)
}

/// The value view `v` still holds when the instruction (or join) that made id `old` makes a new
/// one: around a loop, the same instruction writes a new value under the same id, and a view
/// copied from the old one must not pass for the new.
fn stale(old: Id, v: View) -> Id {
    old ^ 1 << 59 ^ slot(v) << 48
}

/// Registers a call may change (System V caller-saved): rax, rcx, rdx, rsi, rdi, r8–r11.
const CALLER_SAVED: [u64; 9] = [0x00, 0x08, 0x10, 0x30, 0x38, 0x80, 0x88, 0x90, 0x98];

/// Passes over the blocks before giving up (a loop that keeps widening).
const MAX_PASSES: usize = 24;

/// Changes of a block's entry state through a back edge before the intervals still changing
/// there are dropped.
const WIDEN_AFTER: usize = 4;

/// `next` with every interval that differs from `prev`'s for the same view / slot unknown.
fn widen(prev: &State, next: &mut State) {
    let mut drop: Vec<Id> = Vec::new();
    for (&view, &id) in &next.views {
        if prev.get(view) != next.get(view) {
            drop.push(id);
        }
    }
    for (slot, &id) in &next.slots {
        let old = prev.slots.get(slot).and_then(|i| prev.ranges.get(i));
        if old != next.ranges.get(&id) {
            drop.push(id);
        }
    }
    for id in drop {
        next.ranges.remove(&id);
    }
}

/// A stack slot: the value id of `rsp`, the offset added to it, the size.
type Slot = (Id, u64, u32);

#[derive(Clone, Default, PartialEq, Debug)]
struct State {
    /// view -> value id
    views: FxHashMap<View, Id>,
    /// value id -> interval (absent = unknown)
    ranges: FxHashMap<Id, Interval>,
    /// stack slot -> value id (WS87)
    slots: FxHashMap<Slot, Id>,
}

/// The view a fresh value stored to a stack slot is made under (no register's).
const STORED: View = (0xF8, 8);

/// What a conditional jump says of a register on one edge (WS87: signed bounds).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Bound {
    /// within the interval
    In(Interval),
    /// signed `<= n` (n >= 0): `0..=n` when the value is known non-negative
    SignedLe(u64),
}

impl State {
    fn get(&self, v: View) -> Interval {
        self.views.get(&v).and_then(|id| self.ranges.get(id)).copied().unwrap_or(FULL)
    }
}

fn is_gpr(v: &VarnodeData) -> bool {
    v.space == SpaceId::REGISTER && v.offset < 0xC0 && v.offset.is_multiple_of(8) && (v.size == 4 || v.size == 8)
}

fn mask(size: u32) -> u64 {
    if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 }
}

/// The ranges at each instruction start of one function's instructions (address order).
pub struct Ranges {
    /// instruction index -> state as it starts (only block starts; the rest is replayed)
    entry: FxHashMap<usize, State>,
    /// block start (instruction index) of each instruction
    block_of: Vec<usize>,
    /// the lowest `rsp` offset whose address the function takes (slots reaching it may change
    /// behind its back: they are not tracked)
    escaped: u64,
}

/// A jump table for [`Ranges::new`]: the index register as the dispatch reads it (`None` when
/// the window overwrites it) and the case targets (case `i` = `targets[i]`).
pub type Cases = FxHashMap<u64, (Option<VarnodeData>, Vec<u64>)>;

const RSP: u64 = 0x20;

/// The lowest constant offset `c` of an `rsp + c` the function uses other than as a load's or
/// a store's address (`lea rdi, [rsp+0x40]`, `mov rdi, rsp`); `rsp + reg + c` (an array) is
/// not counted.
fn escaped_offset(insns: &[LiftedInstruction]) -> u64 {
    let is_rsp = |v: &VarnodeData| v.space == SpaceId::REGISTER && v.offset == RSP && v.size == 8;
    let mut low = u64::MAX;
    for insn in insns {
        for (i, op) in insn.ops.iter().enumerate() {
            let Some(out) = op.output else { continue };
            if is_rsp(&out) {
                continue;
            }
            let c = match (op.opcode, op.inputs.first(), op.inputs.get(1)) {
                (OpCode::IntAdd, Some(a), Some(b)) if is_rsp(a) && b.space == SpaceId::CONST => b.offset,
                (OpCode::Copy, Some(a), _) if is_rsp(a) => 0,
                _ => continue,
            };
            // (an address only loads / stores read)
            let as_address = out.space == SpaceId::UNIQUE
                && insn.ops[i + 1..].iter().all(|o| {
                    o.inputs.iter().enumerate().all(|(j, v)| *v != out || (j == 1 && matches!(o.opcode, OpCode::Load | OpCode::Store)))
                });
            if !as_address {
                low = low.min(c);
            }
        }
    }
    low
}

impl Ranges {
    /// `cases`: the case targets of jump tables, by the `jmp`'s address (edges out of it).
    pub fn new(insns: &[LiftedInstruction], cases: &Cases) -> Option<Self> {
        let n = insns.len();
        if n == 0 {
            return None;
        }
        let index: FxHashMap<u64, usize> = insns.iter().enumerate().map(|(i, x)| (x.address, i)).collect();
        // block leaders
        let mut leader = vec![false; n];
        leader[0] = true;
        // an instruction some modelled edge reaches (a jump, a fall-through, a recovered table)
        let mut reached = vec![false; n];
        reached[0] = true;
        for (i, insn) in insns.iter().enumerate() {
            let ends = insn.ops.iter().any(|o| matches!(o.opcode, OpCode::Branch | OpCode::CBranch | OpCode::BranchInd | OpCode::Return));
            for o in &insn.ops {
                // the target of a jump; a jump table's cases
                let targets: Vec<u64> = match o.opcode {
                    OpCode::Branch | OpCode::CBranch => o.inputs.iter().take(1).filter(|t| t.space == SpaceId::RAM).map(|t| t.offset).collect(),
                    OpCode::BranchInd => cases.get(&insn.address).map(|c| c.1.clone()).unwrap_or_default(),
                    _ => Vec::new(),
                };
                for t in targets {
                    if let Some(&j) = index.get(&t) {
                        leader[j] = true;
                        reached[j] = true;
                    }
                }
            }
            let falls = !insn.ops.iter().any(|o| matches!(o.opcode, OpCode::Branch | OpCode::BranchInd | OpCode::Return));
            if i + 1 < n && insns[i + 1].address == insn.address + u64::from(insn.length) && falls {
                reached[i + 1] = true;
            }
            if i + 1 < n && (ends || insns[i + 1].address != insn.address + u64::from(insn.length)) {
                leader[i + 1] = true;
            }
        }
        let mut block_of = vec![0; n];
        let mut cur = 0;
        for i in 0..n {
            if leader[i] {
                cur = i;
            }
            block_of[i] = cur;
        }
        let this = Ranges { entry: FxHashMap::default(), block_of, escaped: escaped_offset(insns) };
        let starts: Vec<usize> = (0..n).filter(|&i| leader[i]).collect();
        let mut entry: FxHashMap<usize, State> = FxHashMap::default();
        // the entry, and every block no modelled edge reaches (a case of a table not recovered
        // yet, a landing pad): nothing known there — but alignment padding after a jump / return
        // (`nop`s falling into a loop head, WS88) is never run
        let padding = |b: usize| {
            insns[b..].iter().take_while(|i| i.mnemonic.starts_with("nop") || i.mnemonic.starts_with("int3")).count() > 0
                && insns[b..].iter().position(|i| !(i.mnemonic.starts_with("nop") || i.mnemonic.starts_with("int3"))).is_some_and(|p| leader[b + p] || reached[b + p])
        };
        for &b in &starts {
            if b == 0 || (!reached[b] && !padding(b)) {
                entry.insert(b, State::default());
            }
        }
        // per block: the incoming edge states, by predecessor
        let mut incoming: FxHashMap<usize, FxHashMap<usize, State>> = FxHashMap::default();
        let mut updates: FxHashMap<usize, usize> = FxHashMap::default();
        let mut changed = true;
        let mut passes = 0;
        while changed {
            passes += 1;
            if passes > MAX_PASSES {
                return None;
            }
            changed = false;
            for (bi, &s) in starts.iter().enumerate() {
                let Some(mut st) = entry.get(&s).cloned() else { continue };
                let end = starts.get(bi + 1).copied().unwrap_or(n);
                for k in s..end {
                    if k + 1 == end {
                        // the edges out of the block
                        for (t, edge) in this.successors(insns, &index, k, &st, end, cases) {
                            let inc = incoming.entry(t).or_default();
                            if inc.get(&k) != Some(&edge) {
                                inc.insert(k, edge);
                                let mut joined = this.join(t, inc);
                                if entry.get(&t) != Some(&joined) {
                                    // (a value that keeps changing around a loop, `inc r9d`:
                                    // unknown after a few rounds through a back edge, WS87 —
                                    // not where many forward paths join one by one)
                                    let n = updates.entry(t).or_insert(0usize);
                                    if k >= t {
                                        *n += 1;
                                    }
                                    if *n > WIDEN_AFTER
                                        && let Some(prev) = entry.get(&t)
                                    {
                                        widen(prev, &mut joined);
                                    }
                                    entry.insert(t, joined);
                                    changed = true;
                                }
                            }
                        }
                    }
                    this.step(k, &insns[k], &mut st);
                }
            }
        }
        Some(Ranges { entry, ..this })
    }

    /// The state as instruction `k` starts.
    fn state_at(&self, insns: &[LiftedInstruction], k: usize) -> Option<State> {
        let s = self.block_of[k];
        let mut st = self.entry.get(&s)?.clone();
        for (j, insn) in insns[s..k].iter().enumerate() {
            self.step(s + j, insn, &mut st);
        }
        Some(st)
    }

    /// The interval of register view `v` (a general register, 4 or 8 bytes) as instruction `k`
    /// starts; `None` when unknown or unreached.
    pub fn at(&self, insns: &[LiftedInstruction], k: usize, v: &VarnodeData) -> Option<Interval> {
        if !is_gpr(v) {
            return None;
        }
        let r = self.state_at(insns, k)?.get((v.offset, v.size));
        (r.0 > 0 || r.1 < mask(v.size)).then_some(r)
    }

    /// The interval of the index `v` a dispatch at instruction `k` reads as its window starts at
    /// `start`: at `k` itself when the window leaves `v` alone (every path to the dispatch counts,
    /// also those joining inside the window), else at `start` when no path joins in between.
    pub fn at_dispatch(&self, insns: &[LiftedInstruction], start: usize, k: usize, v: &VarnodeData) -> Option<Interval> {
        let written = insns[start..k]
            .iter()
            .flat_map(|i| i.ops.iter())
            .any(|o| o.output.is_some_and(|w| w.space == v.space && w.offset & !7 == v.offset & !7 && w.offset < 0xC0));
        if !written {
            return self.at(insns, k, v);
        }
        (self.block_of[start] == self.block_of[k]).then(|| self.at(insns, start, v)).flatten()
    }

    /// Join the incoming edge states of a block (deterministic value ids per block and view).
    fn join(&self, block: usize, inc: &FxHashMap<usize, State>) -> State {
        let mut preds: Vec<&usize> = inc.keys().collect();
        preds.sort();
        let first = &inc[preds[0]];
        let mut out = State::default();
        for (&view, &id) in &first.views {
            // (an id this block's join made, around a loop: a value of an earlier pass)
            let made_here = id >> 62 == 3 && (id >> 8) & ((1 << 54) - 1) == block as u64;
            let same = !made_here && preds.iter().all(|p| inc[*p].views.get(&view) == Some(&id));
            let r = preds.iter().map(|p| inc[*p].get(view)).fold(None, |acc: Option<Interval>, x| {
                Some(acc.map_or(x, |a| (a.0.min(x.0), a.1.max(x.1))))
            });
            // a value differing between the paths: an id of its own for this block and view
            let nid = if same { id } else { joined(block, view) };
            out.views.insert(view, nid);
            if let Some(r) = r.filter(|&r| r != FULL) {
                // (two views sharing a differing value get the same id only when both agree)
                out.ranges.insert(nid, r);
            }
        }
        // the stack slots every path agrees on (WS87)
        for (&slot, &id) in &first.slots {
            if !preds.iter().all(|p| inc[*p].slots.get(&slot) == Some(&id)) {
                continue;
            }
            out.slots.insert(slot, id);
            if out.ranges.contains_key(&id) || out.views.values().any(|&v| v == id) {
                continue;
            }
            let r = preds.iter().map(|p| inc[*p].ranges.get(&id).copied().unwrap_or(FULL)).fold(None, |acc: Option<Interval>, x| {
                Some(acc.map_or(x, |a| (a.0.min(x.0), a.1.max(x.1))))
            });
            if let Some(r) = r.filter(|&r| r != FULL) {
                out.ranges.insert(id, r);
            }
        }
        // views sharing a merged id must agree on their interval: keep the union
        out
    }

    /// The edges out of the block ending at instruction `k`, with the state on each.
    fn successors(
        &self,
        insns: &[LiftedInstruction],
        index: &FxHashMap<u64, usize>,
        k: usize,
        before: &State,
        end: usize,
        cases: &Cases,
    ) -> Vec<(usize, State)> {
        let insn = &insns[k];
        let mut after = before.clone();
        self.step(k, insn, &mut after);
        let mut out = Vec::new();
        let fall = (end < insns.len()).then_some(end);
        let br = insn.ops.iter().find(|o| matches!(o.opcode, OpCode::Branch | OpCode::CBranch | OpCode::BranchInd | OpCode::Return));
        match br.map(|o| o.opcode) {
            None => out.extend(fall.map(|f| (f, after))),
            Some(OpCode::BranchInd) => {
                let Some((ix, targets)) = cases.get(&insn.address) else { return out };
                let mut seen: Vec<u64> = Vec::new();
                for &t in targets {
                    if seen.contains(&t) {
                        continue;
                    }
                    seen.push(t);
                    let Some(&j) = index.get(&t) else { continue };
                    let mut s = after.clone();
                    // (the cases going there bound the index, WS87)
                    if let Some(ix) = ix.filter(is_gpr) {
                        let lo = targets.iter().position(|&x| x == t).unwrap_or(0) as u64;
                        let hi = targets.iter().rposition(|&x| x == t).unwrap_or(0) as u64;
                        Self::refine(&mut s, k, (ix.offset, ix.size), Bound::In((lo, hi)));
                    }
                    out.push((j, s));
                }
            }
            Some(OpCode::Branch) => {
                if let Some(&t) = br.and_then(|o| o.inputs.first()).filter(|t| t.space == SpaceId::RAM).and_then(|t| index.get(&t.offset)) {
                    out.push((t, after));
                }
            }
            Some(OpCode::CBranch) => {
                let target = br.and_then(|o| o.inputs.first()).filter(|t| t.space == SpaceId::RAM).and_then(|t| index.get(&t.offset)).copied();
                let bound = self.bound(insns, k);
                let refine = |taken: bool| {
                    let mut s = after.clone();
                    if let Some((view, t_bound, f_bound)) = bound {
                        Self::refine(&mut s, k, view, if taken { t_bound } else { f_bound });
                    }
                    s
                };
                if let Some(t) = target {
                    out.push((t, refine(true)));
                }
                if let Some(f) = fall {
                    out.push((f, refine(false)));
                }
            }
            _ => {}
        }
        out
    }

    /// `cmp r, N` right before the conditional jump `k` (nothing in between writes `r` or the
    /// flags): `(r's view, interval when taken, interval when falling through)`.
    fn bound(&self, insns: &[LiftedInstruction], k: usize) -> Option<(View, Bound, Bound)> {
        let jcc = insns[k].mnemonic.split_whitespace().next()?;
        let s = self.block_of[k];
        let c = (s..k).rev().find(|&c| insns[c].ops.iter().any(|o| o.output.is_some_and(|w| w.space == SpaceId::REGISTER && (0x200..0x210).contains(&w.offset))))?;
        let test = insns[c].mnemonic.starts_with("test");
        let (x, n) = if insns[c].mnemonic.starts_with("cmp") {
            let less = insns[c].ops.iter().find(|o| o.opcode == OpCode::IntLess && o.output.is_some_and(|w| w.space == SpaceId::REGISTER && w.offset == 0x201))?;
            (less.inputs[0], less.inputs[1])
        } else if test {
            // `test r, r`: the sign of `r` (WS87)
            let and = insns[c].ops.iter().find(|o| o.opcode == OpCode::IntAnd && o.inputs.len() == 2 && o.inputs[0] == o.inputs[1])?;
            (and.inputs[0], VarnodeData::new(SpaceId::CONST, 0, and.inputs[0].size))
        } else {
            return None;
        };
        if !is_gpr(&x) || n.space != SpaceId::CONST {
            return None;
        }
        let written = insns[c + 1..k].iter().flat_map(|i| i.ops.iter()).any(|o| o.output.is_some_and(|w| w.space == x.space && w.offset & !7 == x.offset));
        if written {
            return None;
        }
        let n = n.offset & mask(x.size);
        let m = mask(x.size);
        // the largest non-negative value of the view
        let top = m >> 1;
        let (t, f) = match jcc {
            "js" if test => (Bound::In((top + 1, m)), Bound::In((0, top))),
            "jns" if test => (Bound::In((0, top)), Bound::In((top + 1, m))),
            _ if test => return None,
            "ja" | "jnbe" => (Bound::In((n.checked_add(1)?, m)), Bound::In((0, n))),
            "jae" | "jnb" | "jnc" => (Bound::In((n, m)), Bound::In((0, n.checked_sub(1)?))),
            "jb" | "jnae" | "jc" => (Bound::In((0, n.checked_sub(1)?)), Bound::In((n, m))),
            "jbe" | "jna" => (Bound::In((0, n)), Bound::In((n.checked_add(1)?, m))),
            // signed, against a non-negative constant (WS87)
            _ if n >= top => return None,
            "jg" | "jnle" => (Bound::In((n + 1, top)), Bound::SignedLe(n)),
            "jge" | "jnl" => (Bound::In((n, top)), Bound::SignedLe(n.checked_sub(1)?)),
            "jl" | "jnge" => (Bound::SignedLe(n.checked_sub(1)?), Bound::In((n, top))),
            "jle" | "jng" => (Bound::SignedLe(n), Bound::In((n + 1, top))),
            _ => return None,
        };
        Some(((x.offset, x.size), t, f))
    }

    /// Narrow the value of `view` (and every view sharing it) to `r`.
    fn refine(st: &mut State, k: usize, view: View, b: Bound) {
        let id = *st.views.entry(view).or_insert_with(|| entry_value(view));
        let cur = st.ranges.get(&id).copied().unwrap_or(FULL);
        let r = match b {
            Bound::In(r) => r,
            // (known non-negative: below the sign bit of the view)
            Bound::SignedLe(n) if cur.1 <= mask(view.1) >> 1 => (0, n),
            Bound::SignedLe(_) => return,
        };
        let lo = cur.0.max(r.0);
        let hi = cur.1.min(r.1);
        if lo > hi {
            // an impossible edge: leave it unknown rather than empty
            return;
        }
        st.ranges.insert(id, (lo, hi));
        // the other view of the same register: a 32-bit bound holds for the 64-bit register
        // when its upper half is zero (it is the same value), and a 64-bit bound below 2^32
        // holds for the 32-bit view
        let other = (view.0, if view.1 == 4 { 8 } else { 4 });
        if st.views.get(&other) == Some(&id) {
            return;
        }
        if view.1 == 8 && hi <= u64::from(u32::MAX) {
            // (a value of its own, made by the jump `k`)
            let oid = written(k, other) | 1 << 61;
            st.views.insert(other, oid);
            st.ranges.insert(oid, (lo, hi));
        }
    }

    /// Run one instruction: the views it writes get their new values.
    fn step(&self, k: usize, insn: &LiftedInstruction, st: &mut State) {
        // the instruction's temporaries: interval, (for a plain copy of a view) its value id and
        // (for `rsp + c`, WS87) the stack address
        let mut tmp: FxHashMap<(u64, u32), Val> = FxHashMap::default();
        let val = |st: &State, tmp: &FxHashMap<(u64, u32), Val>, v: &VarnodeData| -> Val {
            if v.space == SpaceId::CONST {
                let c = v.offset & mask(v.size);
                return ((c, c), None, None);
            }
            if v.space == SpaceId::UNIQUE {
                return tmp.get(&(v.offset, v.size)).copied().unwrap_or(((0, mask(v.size)), None, None));
            }
            if is_gpr(v) {
                // (a view never written holds its entry value: a copy of it shares that)
                let id = st.views.get(&(v.offset, v.size)).copied().unwrap_or_else(|| entry_value((v.offset, v.size)));
                let addr = (v.offset == RSP && v.size == 8).then_some((id, 0));
                return (st.get((v.offset, v.size)), Some(id), addr);
            }
            ((0, mask(v.size)), None, None)
        };
        // a stack slot the function keeps to itself (WS87)
        let tracked = |a: Option<(Id, u64)>, size: u32| a.filter(|&(_, c)| c.checked_add(u64::from(size)).is_some_and(|e| e <= self.escaped));
        for op in &insn.ops {
            if op.opcode == OpCode::Store {
                let (Some(a), Some(v)) = (op.inputs.get(1), op.inputs.get(2)) else { continue };
                let addr = val(st, &tmp, a).2;
                let Some((base, c)) = addr else { continue };
                // the slots it overlaps change
                let end = c.saturating_add(u64::from(v.size));
                st.slots.retain(|&(b, o, sz), _| b != base || o.saturating_add(u64::from(sz)) <= c || o >= end);
                if (v.size == 4 || v.size == 8) && tracked(addr, v.size).is_some() {
                    let (r, id, _) = val(st, &tmp, v);
                    let id = match id {
                        Some(id) => id,
                        None => {
                            let nid = written(k, STORED);
                            Self::renew(st, nid, None);
                            if r != FULL {
                                st.ranges.insert(nid, r);
                            }
                            nid
                        }
                    };
                    st.slots.insert((base, c, v.size), id);
                }
                continue;
            }
            let Some(out) = op.output else { continue };
            let i0 = op.inputs.first().map(|v| val(st, &tmp, v));
            let c1 = op.inputs.get(1).filter(|v| v.space == SpaceId::CONST).map(|v| v.offset);
            let full = (0, mask(out.size));
            let m = mask(out.size);
            let (r, id, addr) = match (op.opcode, i0, c1) {
                (OpCode::Copy, Some(x), _) => x,
                // (a zero extension is the same number: the views share the value, so a bound on
                // `edi` holds for `rdi = zext(edi)`)
                (OpCode::IntZExt, Some((r, id, _)), _) => (r, id, None),
                (OpCode::IntAnd, Some((r, _, _)), Some(c)) => ((0, r.1.min(c & m)), None, None),
                (OpCode::IntRight, Some((r, _, _)), Some(s)) if s < 64 => ((r.0 >> s, r.1 >> s), None, None),
                // the low bytes (the lifter derives `eax` from `rax` after a write)
                (OpCode::Subpiece, Some((r, id, _)), Some(0)) if r.1 <= m => (r, id, None),
                // `rsp + c`: a stack address (WS87)
                (OpCode::IntAdd, Some((_, _, Some((base, 0)))), Some(c)) => (full, None, Some((base, c & m))),
                // `r + c` / `r - c` that does not wrap moves the interval (WS87)
                (OpCode::IntAdd | OpCode::IntSub, Some((r, _, _)), Some(c)) if r != FULL && r.1 <= m => {
                    let c = c & m;
                    // (an added constant above the sign bit subtracts)
                    let (add, n) = match (op.opcode, c > m >> 1) {
                        (OpCode::IntAdd, false) => (true, c),
                        (OpCode::IntAdd, true) => (false, m - c + 1),
                        (_, false) => (false, c),
                        (_, true) => (true, m - c + 1),
                    };
                    let moved = if add {
                        r.1.checked_add(n).filter(|&h| h <= m).map(|h| (r.0 + n, h))
                    } else {
                        r.0.checked_sub(n).map(|l| (l, r.1 - n))
                    };
                    (moved.unwrap_or(full), None, None)
                }
                (OpCode::Load, _, _) => {
                    let a = op.inputs.get(1).map(|v| val(st, &tmp, v).2);
                    match tracked(a.flatten(), out.size).and_then(|(b, c)| st.slots.get(&(b, c, out.size))) {
                        Some(&id) => (st.ranges.get(&id).copied().unwrap_or(full), Some(id), None),
                        None => (full, None, None),
                    }
                }
                _ => (full, None, None),
            };
            let r = (r.0.min(full.1), r.1.min(full.1));
            if out.space == SpaceId::UNIQUE {
                tmp.insert((out.offset, out.size), (r, id, addr));
            } else if is_gpr(&out) {
                let view = (out.offset, out.size);
                let nid = match id {
                    Some(id) => id,
                    None => {
                        let nid = written(k, view);
                        Self::renew(st, nid, Some(view));
                        if r == FULL {
                            st.ranges.remove(&nid);
                        } else {
                            st.ranges.insert(nid, r);
                        }
                        nid
                    }
                };
                st.views.insert(view, nid);
            }
            // (a narrow write — `al`, `ax` — rebuilds the 64-bit register and its 32-bit view
            // with PIECE / SUBPIECE ops of its own, which make them unknown)
        }
        if insn.ops.iter().any(|o| matches!(o.opcode, OpCode::Call | OpCode::CallInd)) {
            for &r in &CALLER_SAVED {
                for sz in [4, 8] {
                    let nid = written(k, (r, sz)) | 1 << 60;
                    st.ranges.remove(&nid);
                    st.views.insert((r, sz), nid);
                }
            }
        }
    }

    /// Instruction `k` makes value `nid` anew (around a loop, the same id as last time): the
    /// views still holding the old value get a stale id of their own, the slots forget it.
    fn renew(st: &mut State, nid: Id, view: Option<View>) {
        let old: Vec<View> = st.views.iter().filter(|&(w, &i)| i == nid && Some(*w) != view).map(|(w, _)| *w).collect();
        for w in old {
            let sid = stale(nid, w);
            match st.ranges.get(&nid).copied() {
                Some(r) => st.ranges.insert(sid, r),
                None => st.ranges.remove(&sid),
            };
            st.views.insert(w, sid);
        }
        st.slots.retain(|_, i| *i != nid);
    }
}

/// A temporary's value in [`Ranges::step`]: interval, value id, stack address.
type Val = (Interval, Option<Id>, Option<(Id, u64)>);

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_lift::x86::X86Lifter;
    use reargo_lift::PcodeLift;
    use reargo_loader::memory::{Memory, MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn lift(code: &[u8]) -> Vec<LiftedInstruction> {
        let mut mem = Memory::new(SpaceId(1), reargo_core::address::Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: 0x1000,
            size: code.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(code)),
        });
        X86Lifter::new_64().lift_range(&mem, 0x1000, 64).unwrap()
    }

    /// WS88: `nop` padding after a jump falls into a loop head but never runs: the values
    /// reaching the head by the jump stay known.
    #[test]
    fn padding_is_not_a_path() {
        let l = lift(&[
            0xb9, 0x05, 0x00, 0x00, 0x00, // 0x1000 mov ecx, 5
            0xeb, 0x01, // 0x1005 jmp 0x1008
            0x90, // 0x1007 nop (padding)
            0x89, 0xc8, // 0x1008 mov eax, ecx
            0xc3, // 0x100a ret
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        let ecx = VarnodeData::new(SpaceId::REGISTER, 0x08, 4);
        assert_eq!(r.at(&l, 3, &ecx), Some((5, 5)));
    }

    #[test]
    fn bound_reaches_a_copy_blocks_later() {
        let l = lift(&[
            0x83, 0xff, 0x03, // 0x1000 cmp edi, 3
            0x77, 0x08, // 0x1003 ja 0x100d
            0x48, 0x85, 0xf6, // 0x1005 test rsi, rsi
            0x74, 0x04, // 0x1008 je 0x100e
            0x89, 0xf8, // 0x100a mov eax, edi
            0x90, // 0x100c nop
            0xc3, // 0x100d ret
            0xc3, // 0x100e ret
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        let edi = VarnodeData::new(SpaceId::REGISTER, 0x38, 4);
        let eax = VarnodeData::new(SpaceId::REGISTER, 0x00, 4);
        let rax = VarnodeData::new(SpaceId::REGISTER, 0x00, 8);
        assert_eq!(r.at(&l, 4, &edi), Some((0, 3)));
        assert_eq!(r.at(&l, 5, &eax), Some((0, 3)));
        assert_eq!(r.at(&l, 5, &rax), Some((0, 3)));
        // where the bounded path joins the one above 3: unknown
        assert_eq!(r.at(&l, 6, &edi), None);
        // past the `je`: rsi == 0 is not a range
        assert_eq!(r.at(&l, 7, &edi), Some((0, 3)));
    }

    /// A block no modelled edge reaches (after an indirect jump; in BDS 0x3e87ee0 a case of a
    /// table not recovered yet) may hold anything: `rsi` reloaded there stays unknown where its
    /// path joins one that copies the compared register into it.
    #[test]
    fn unreached_block_is_unknown() {
        let l = lift(&[
            0x44, 0x89, 0xe6, // 0 mov esi, r12d
            0x41, 0xf6, 0xc7, 0x01, // 1 test r15b, 1
            0x74, 0x07, // 2 je 5
            0xff, 0xe0, // 3 jmp rax
            0x48, 0x8b, 0x74, 0x24, 0x28, // 4 mov rsi, [rsp+0x28]
            0x41, 0x83, 0xfc, 0x03, // 5 cmp r12d, 3
            0x77, 0x01, // 6 ja 8
            0x90, // 7 nop
            0xc3, // 8 ret
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        let rsi = VarnodeData::new(SpaceId::REGISTER, 0x30, 8);
        let r12d = VarnodeData::new(SpaceId::REGISTER, 0xa0, 4);
        assert_eq!(r.at(&l, 7, &r12d), Some((0, 3)));
        assert_eq!(r.at(&l, 7, &rsi), None);
        // the table's cases as edges: the block is reached, from a dispatch nothing bounds
        let jmp = l[3].address;
        let r = Ranges::new(&l, &[(jmp, (None, vec![l[4].address]))].into_iter().collect()).expect("converges");
        assert_eq!(r.at(&l, 7, &rsi), None);
    }
    /// WS87: an index spilled to the stack and reloaded (BDS 0x3e87ee0: `mov [rsp+0x28], rsi`
    /// … `mov rsi, [rsp+0x28]`) is the value stored, so the compared copy bounds it.
    #[test]
    fn spilled_index_keeps_its_value() {
        let code = [
            0x44, 0x89, 0xe6, // 0 mov esi, r12d
            0x48, 0x89, 0x74, 0x24, 0x28, // 1 mov [rsp+0x28], rsi
            0xe8, 0x00, 0x00, 0x00, 0x00, // 2 call (next)
            0x48, 0x8b, 0x74, 0x24, 0x28, // 3 mov rsi, [rsp+0x28]
            0x41, 0x83, 0xfc, 0x03, // 4 cmp r12d, 3
            0x77, 0x01, // 5 ja 7
            0x90, // 6 nop
            0xc3, // 7 ret
        ];
        let l = lift(&code);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        let rsi = VarnodeData::new(SpaceId::REGISTER, 0x30, 8);
        assert_eq!(r.at(&l, 6, &rsi), Some((0, 3)));
        // the slot's address passed on (`lea rdi, [rsp+0x20]` before the call): not tracked
        let mut esc = code[..8].to_vec();
        esc.extend([0x48, 0x8d, 0x7c, 0x24, 0x20]); // lea rdi, [rsp+0x20]
        esc.extend(&code[8..]);
        let l = lift(&esc);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        assert_eq!(r.at(&l, 7, &rsi), None);
    }

    /// WS87: a signed bound on a value known non-negative (`movzx`), and the sign test.
    #[test]
    fn signed_bounds() {
        let l = lift(&[
            0x0f, 0xb6, 0x07, // 0 movzx eax, byte [rdi]
            0x83, 0xf8, 0x05, // 1 cmp eax, 5
            0x7f, 0x01, // 2 jg 4
            0x90, // 3 nop
            0xc3, // 4 ret
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        let eax = VarnodeData::new(SpaceId::REGISTER, 0x00, 4);
        assert_eq!(r.at(&l, 3, &eax), Some((0, 5)));
        // not known non-negative: no bound
        let l = lift(&[
            0x8b, 0x07, // 0 mov eax, [rdi]
            0x83, 0xf8, 0x05, // 1 cmp eax, 5
            0x7f, 0x01, // 2 jg 4
            0x90, // 3 nop
            0xc3, // 4 ret
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        assert_eq!(r.at(&l, 3, &eax), None);
        // ... unless a sign test says so first
        let l = lift(&[
            0x8b, 0x07, // 0 mov eax, [rdi]
            0x85, 0xc0, // 1 test eax, eax
            0x78, 0x06, // 2 js 6
            0x83, 0xf8, 0x05, // 3 cmp eax, 5
            0x7f, 0x01, // 4 jg 6
            0x90, // 5 nop
            0xc3, // 6 ret
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        assert_eq!(r.at(&l, 5, &eax), Some((0, 5)));
    }

    /// WS87: a constant added or subtracted moves the interval, when it does not wrap.
    #[test]
    fn added_constant_moves_the_interval() {
        let l = lift(&[
            0x83, 0xff, 0x04, // 0 cmp edi, 4
            0x77, 0x06, // 1 ja 5
            0x89, 0xf8, // 2 mov eax, edi
            0x83, 0xc0, 0x02, // 3 add eax, 2
            0x90, // 4 nop
            0xc3, // 5 ret
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        let eax = VarnodeData::new(SpaceId::REGISTER, 0x00, 4);
        assert_eq!(r.at(&l, 4, &eax), Some((2, 6)));
        let l = lift(&[
            0x83, 0xff, 0x04, // 0 cmp edi, 4
            0x77, 0x06, // 1 ja 5
            0x89, 0xf8, // 2 mov eax, edi
            0x83, 0xe8, 0x01, // 3 sub eax, 1 (0 wraps)
            0x90, // 4 nop
            0xc3, // 5 ret
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        assert_eq!(r.at(&l, 4, &eax), None);
    }

    /// WS87: the case edges of a table bound its index (an enum switch read again later).
    #[test]
    fn case_edges_bound_the_index() {
        let l = lift(&[
            0xff, 0xe0, // 0 jmp rax (cases 0, 2 -> 1; case 1 -> 3)
            0x90, // 1 nop
            0xc3, // 2 ret
            0x90, // 3 nop
            0xc3, // 4 ret
        ]);
        let eax = VarnodeData::new(SpaceId::REGISTER, 0x00, 4);
        let t = |i: usize| l[i].address;
        let cases: Cases = [(l[0].address, (Some(eax), vec![t(1), t(3), t(1)]))].into_iter().collect();
        let r = Ranges::new(&l, &cases).expect("converges");
        assert_eq!(r.at(&l, 1, &eax), Some((0, 2)));
        assert_eq!(r.at(&l, 3, &eax), Some((1, 1)));
    }

    /// WS87: a loop counter does not keep the iteration going (`inc` around a loop).
    #[test]
    fn loop_counter_settles() {
        let l = lift(&[
            0x31, 0xc0, // 0 xor eax, eax
            0xff, 0xc0, // 1 inc eax
            0x39, 0xf8, // 2 cmp eax, edi
            0x75, 0xfa, // 3 jne 1
            0xc3, // 4 ret
        ]);
        assert!(Ranges::new(&l, &FxHashMap::default()).is_some());
    }
    /// WS87: many forward paths joining one by one are no loop: the join keeps the union.
    #[test]
    fn forward_joins_are_not_widened() {
        let l = lift(&[
            0xb8, 0x00, 0x00, 0x00, 0x00, // 0 mov eax, 0
            0x85, 0xff, 0x74, 0x2a, // 1 test edi, edi; 2 je J
            0xb8, 0x01, 0x00, 0x00, 0x00, // 3 mov eax, 1
            0x85, 0xf6, 0x74, 0x21, // 4, 5
            0xb8, 0x02, 0x00, 0x00, 0x00, // 6
            0x85, 0xd2, 0x74, 0x18, // 7, 8
            0xb8, 0x03, 0x00, 0x00, 0x00, // 9
            0x85, 0xc9, 0x74, 0x0f, // 10, 11
            0xb8, 0x04, 0x00, 0x00, 0x00, // 12
            0x45, 0x85, 0xc0, 0x74, 0x05, // 13, 14
            0xb8, 0x05, 0x00, 0x00, 0x00, // 15
            0x90, // 16 J: nop
            0xc3, // 17
        ]);
        let r = Ranges::new(&l, &FxHashMap::default()).expect("converges");
        let eax = VarnodeData::new(SpaceId::REGISTER, 0x00, 4);
        assert_eq!(r.at(&l, 16, &eax), Some((0, 5)));
    }
}
