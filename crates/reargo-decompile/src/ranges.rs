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

#[derive(Clone, Default, PartialEq, Debug)]
struct State {
    /// view -> value id
    views: FxHashMap<View, Id>,
    /// value id -> interval (absent = unknown)
    ranges: FxHashMap<Id, Interval>,
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
}

impl Ranges {
    /// `cases`: the case targets of jump tables, by the `jmp`'s address (edges out of it).
    pub fn new(insns: &[LiftedInstruction], cases: &FxHashMap<u64, Vec<u64>>) -> Option<Self> {
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
                    OpCode::BranchInd => cases.get(&insn.address).cloned().unwrap_or_default(),
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
        let this = Ranges { entry: FxHashMap::default(), block_of };
        let starts: Vec<usize> = (0..n).filter(|&i| leader[i]).collect();
        let mut entry: FxHashMap<usize, State> = FxHashMap::default();
        // the entry, and every block no modelled edge reaches (a case of a table not recovered
        // yet, a landing pad): nothing known there
        for &b in &starts {
            if !reached[b] || b == 0 {
                entry.insert(b, State::default());
            }
        }
        // per block: the incoming edge states, by predecessor
        let mut incoming: FxHashMap<usize, FxHashMap<usize, State>> = FxHashMap::default();
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
                                let joined = this.join(t, inc);
                                if entry.get(&t) != Some(&joined) {
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
        cases: &FxHashMap<u64, Vec<u64>>,
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
                for t in cases.get(&insn.address).map_or(&[][..], Vec::as_slice) {
                    if let Some(&j) = index.get(t) {
                        out.push((j, after.clone()));
                    }
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
                    if let Some((view, t_range, f_range)) = bound {
                        Self::refine(&mut s, k, view, if taken { t_range } else { f_range });
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
    fn bound(&self, insns: &[LiftedInstruction], k: usize) -> Option<(View, Interval, Interval)> {
        let jcc = insns[k].mnemonic.split_whitespace().next()?;
        let s = self.block_of[k];
        let c = (s..k).rev().find(|&c| insns[c].ops.iter().any(|o| o.output.is_some_and(|w| w.space == SpaceId::REGISTER && (0x200..0x210).contains(&w.offset))))?;
        if !insns[c].mnemonic.starts_with("cmp") {
            return None;
        }
        let less = insns[c].ops.iter().find(|o| o.opcode == OpCode::IntLess && o.output.is_some_and(|w| w.space == SpaceId::REGISTER && w.offset == 0x201))?;
        let (x, n) = (less.inputs[0], less.inputs[1]);
        if !is_gpr(&x) || n.space != SpaceId::CONST {
            return None;
        }
        let written = insns[c + 1..k].iter().flat_map(|i| i.ops.iter()).any(|o| o.output.is_some_and(|w| w.space == x.space && w.offset & !7 == x.offset));
        if written {
            return None;
        }
        let n = n.offset & mask(x.size);
        let m = mask(x.size);
        let le = (0, n);
        let gt = (n.checked_add(1)?, m);
        let lt = (0, n.checked_sub(1)?);
        let ge = (n, m);
        let (t, f) = match jcc {
            "ja" | "jnbe" => (gt, le),
            "jae" | "jnb" | "jnc" => (ge, lt),
            "jb" | "jnae" | "jc" => (lt, ge),
            "jbe" | "jna" => (le, gt),
            _ => return None,
        };
        Some(((x.offset, x.size), t, f))
    }

    /// Narrow the value of `view` (and every view sharing it) to `r`.
    fn refine(st: &mut State, k: usize, view: View, r: Interval) {
        let id = *st.views.entry(view).or_insert_with(|| entry_value(view));
        let cur = st.ranges.get(&id).copied().unwrap_or(FULL);
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
        // the instruction's temporaries: interval and (for a plain copy of a view) its value id
        let mut tmp: FxHashMap<(u64, u32), (Interval, Option<Id>)> = FxHashMap::default();
        let val = |st: &State, tmp: &FxHashMap<(u64, u32), (Interval, Option<Id>)>, v: &VarnodeData| -> (Interval, Option<Id>) {
            if v.space == SpaceId::CONST {
                let c = v.offset & mask(v.size);
                return ((c, c), None);
            }
            if v.space == SpaceId::UNIQUE {
                return tmp.get(&(v.offset, v.size)).copied().unwrap_or(((0, mask(v.size)), None));
            }
            if is_gpr(v) {
                // (a view never written holds its entry value: a copy of it shares that)
                let id = Some(st.views.get(&(v.offset, v.size)).copied().unwrap_or_else(|| entry_value((v.offset, v.size))));
                return (st.get((v.offset, v.size)), id);
            }
            ((0, mask(v.size)), None)
        };
        for op in &insn.ops {
            let Some(out) = op.output else { continue };
            let i0 = op.inputs.first().map(|v| val(st, &tmp, v));
            let c1 = op.inputs.get(1).filter(|v| v.space == SpaceId::CONST).map(|v| v.offset);
            let full = (0, mask(out.size));
            let (r, id) = match (op.opcode, i0, c1) {
                (OpCode::Copy, Some((r, id)), _) => (r, id),
                // (a zero extension is the same number: the views share the value, so a bound on
                // `edi` holds for `rdi = zext(edi)`)
                (OpCode::IntZExt, Some((r, id)), _) => (r, id),
                (OpCode::IntAnd, Some((r, _)), Some(c)) => ((0, r.1.min(c & mask(out.size))), None),
                (OpCode::IntRight, Some((r, _)), Some(s)) if s < 64 => ((r.0 >> s, r.1 >> s), None),
                // the low bytes (the lifter derives `eax` from `rax` after a write)
                (OpCode::Subpiece, Some((r, id)), Some(0)) if r.1 <= mask(out.size) => (r, id),
                (OpCode::Load, _, _) => (full, None),
                _ => (full, None),
            };
            let r = (r.0.min(full.1), r.1.min(full.1));
            if out.space == SpaceId::UNIQUE {
                tmp.insert((out.offset, out.size), (r, id));
            } else if is_gpr(&out) {
                let view = (out.offset, out.size);
                let nid = match id {
                    Some(id) => id,
                    None => {
                        let nid = written(k, view);
                        // the views still holding the value this instruction made last time
                        let old: Vec<View> = st.views.iter().filter(|&(w, &i)| i == nid && *w != view).map(|(w, _)| *w).collect();
                        for w in old {
                            let sid = stale(nid, w);
                            match st.ranges.get(&nid).copied() {
                                Some(r) => st.ranges.insert(sid, r),
                                None => st.ranges.remove(&sid),
                            };
                            st.views.insert(w, sid);
                        }
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
}

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
        let r = Ranges::new(&l, &[(jmp, vec![l[4].address])].into_iter().collect()).expect("converges");
        assert_eq!(r.at(&l, 7, &rsi), None);
    }
}
