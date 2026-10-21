//! Value-Set Analysis (VSA) — abstract interpretation over register
//! / stack values, generalising `cfg_const.rs`'s point-constant
//! tracker.
//!
//! The point-constant tracker treats a register either as "pinned
//! to value V" or "unknown". That's enough to resolve format-string
//! call args but throws away too much for switch-table sizing,
//! buffer-bound recovery, and dead-block detection. VSA tracks each
//! register's value as one of:
//!
//!   * **Top** — unknown, no constraint
//!   * **Const(v)** — equal to a single value
//!   * **Set({v1, v2, …})** — one of a small enumerated set
//!   * **Range(lo, hi)** — interval, inclusive at both ends
//!   * **Bot** — impossible / unreachable
//!
//! Operations:
//!
//!   * `Copy dst, src` — propagate src's abstract value
//!   * `IntAdd dst, a, b` — sum intervals, widen sets, fall to Top if
//!     either side is Top
//!   * `IntAnd dst, a, mask` — narrow a Range to the mask domain
//!   * `Branch` / `CBranch` — refine the per-block successor state
//!     using the branch condition (e.g. `a < N` makes the taken
//!     branch see `a ∈ [lo..N-1]`)
//!
//! Output is the same call-constants shape `cfg_const.rs` produces,
//! plus a per-call-site map of arg → abstract value so downstream
//! analyzers (switch table v2 sizing, buffer bounds) can consume the
//! richer info.

use std::collections::{BTreeMap, BTreeSet};

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, PcodeOp, VarnodeData};
use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_program::Program;
use rayon::prelude::*;
use smallvec::SmallVec;

use crate::blockflow::{self, FlowState};
use crate::byteconst::{bit_mask, eval, is_unmodeled, is_view_refresh, ByteConst};
use crate::func_lift::{external_entries, function_jobs, in_extent, lift_function};

/// Set → Range widening threshold. A `Set` join that crosses this
/// size collapses to a Range envelope to keep the per-block state
/// bounded. 8 is the value the original implementation used; named
/// here so review-time tuning has one source of truth.
const SET_WIDEN_THRESHOLD: usize = 8;

/// Abstract value lattice. Ordered roughly bottom → top by precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbstractValue {
    Bot,
    Const(u64),
    Set(BTreeSet<u64>),
    Range(u64, u64),
    Top,
}

impl AbstractValue {
    pub fn join(&self, other: &Self) -> Self {
        use AbstractValue::*;
        match (self, other) {
            (Bot, x) | (x, Bot) => x.clone(),
            (Top, _) | (_, Top) => Top,
            (Const(a), Const(b)) if a == b => Const(*a),
            (Const(a), Const(b)) => {
                let mut s = BTreeSet::new();
                s.insert(*a);
                s.insert(*b);
                Set(s)
            }
            (Const(a), Set(s)) | (Set(s), Const(a)) => {
                let mut s = s.clone();
                s.insert(*a);
                if s.len() > SET_WIDEN_THRESHOLD {
                    Range(*s.iter().min().unwrap(), *s.iter().max().unwrap())
                } else {
                    Set(s)
                }
            }
            (Set(a), Set(b)) => {
                let s: BTreeSet<u64> = a.union(b).copied().collect();
                if s.len() > SET_WIDEN_THRESHOLD {
                    let lo = *s.iter().min().unwrap();
                    let hi = *s.iter().max().unwrap();
                    Range(lo, hi)
                } else {
                    Set(s)
                }
            }
            (Const(a), Range(lo, hi)) | (Range(lo, hi), Const(a)) => {
                Range((*lo).min(*a), (*hi).max(*a))
            }
            (Set(s), Range(lo, hi)) | (Range(lo, hi), Set(s)) => {
                let smin = *s.iter().min().unwrap_or(lo);
                let smax = *s.iter().max().unwrap_or(hi);
                Range(smin.min(*lo), smax.max(*hi))
            }
            (Range(a, b), Range(c, d)) => Range((*a).min(*c), (*b).max(*d)),
        }
    }

    /// Extract the single concrete value when the abstract domain
    /// pinned us to one. Useful for the CallSiteAnnotator fill-in
    /// path that wants `Option<u64>` anyway.
    pub fn as_single(&self) -> Option<u64> {
        match self {
            Self::Const(v) => Some(*v),
            Self::Set(s) if s.len() == 1 => s.iter().next().copied(),
            Self::Range(lo, hi) if lo == hi => Some(*lo),
            _ => None,
        }
    }
}

/// VSA result: per Call instruction, the abstract value of each
/// REGISTER-space varnode that was non-Top on entry.
pub type VsaResult = BTreeMap<u64, BTreeMap<u64, AbstractValue>>;

/// One register (8 bytes at `offset & !7`) or temporary: its known
/// bytes, or an abstract `Set` / `Range` of its low `size` bytes with
/// the bytes above unknown. Constants are always `Bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Slot {
    Bytes(ByteConst),
    Low(u32, AbstractValue),
}

impl Slot {
    /// The known bytes (none for an abstract value).
    fn bytes(&self) -> ByteConst {
        match self {
            Slot::Bytes(b) => *b,
            Slot::Low(..) => ByteConst::UNKNOWN,
        }
    }

    /// The `size` bytes at byte `pos` as an abstract value.
    fn read(&self, pos: u32, size: u32) -> AbstractValue {
        match self {
            Slot::Bytes(b) => b.bytes_at(pos, size).get(size).map_or(AbstractValue::Top, AbstractValue::Const),
            Slot::Low(ls, v) if pos == 0 && size <= *ls => fit(v.clone(), size),
            Slot::Low(..) => AbstractValue::Top,
        }
    }

    /// The widest low part this slot pins: `(width, value)`.
    fn view(&self) -> Option<(u32, AbstractValue)> {
        match self {
            Slot::Bytes(b) => [8, 4, 2, 1].into_iter().find_map(|w| b.get(w).map(|v| (w, AbstractValue::Const(v)))),
            Slot::Low(s, v) => Some((*s, v.clone())),
        }
    }

    /// CFG join; `None` when nothing survives.
    fn join(&self, other: &Slot) -> Option<Slot> {
        if self == other {
            return Some(self.clone());
        }
        if let (Some((wa, va)), Some((wb, vb))) = (self.view(), other.view()) {
            let w = wa.min(wb);
            let j = normalize(fit(va, w).join(&fit(vb, w)));
            if matches!(j, AbstractValue::Set(_) | AbstractValue::Range(..)) {
                return Some(Slot::Low(w, j));
            }
        }
        let b = self.bytes().intersect(other.bytes());
        (!b.is_unknown()).then_some(Slot::Bytes(b))
    }
}

/// A computed value: known bytes, or an abstract value of the whole
/// output.
enum Val {
    Bytes(ByteConst),
    Abs(AbstractValue),
}

/// `Set` of one value / `Range` of one value → `Const`.
fn normalize(v: AbstractValue) -> AbstractValue {
    match v {
        AbstractValue::Set(s) if s.len() == 1 => AbstractValue::Const(*s.iter().next().unwrap()),
        AbstractValue::Set(s) if s.is_empty() => AbstractValue::Bot,
        AbstractValue::Range(lo, hi) if lo == hi => AbstractValue::Const(lo),
        v => v,
    }
}

/// `v` as a `size`-byte value (truncated); a range that does not fit
/// is unknown.
fn fit(v: AbstractValue, size: u32) -> AbstractValue {
    let m = bit_mask(size);
    normalize(match v {
        AbstractValue::Const(c) => AbstractValue::Const(c & m),
        // (a set that fits stays as it is)
        AbstractValue::Set(s) if s.iter().all(|&x| x & m == x) => AbstractValue::Set(s),
        AbstractValue::Set(s) => AbstractValue::Set(s.into_iter().map(|x| x & m).collect()),
        AbstractValue::Range(lo, hi) if hi <= m => AbstractValue::Range(lo, hi),
        AbstractValue::Range(..) => AbstractValue::Top,
        v => v,
    })
}

/// Sign-extend a `from`-byte value.
fn sext(v: AbstractValue, from: u32) -> AbstractValue {
    let ext = |x: u64| -> u64 {
        let bits = from.min(8) * 8;
        if bits >= 64 { x } else { (((x << (64 - bits)) as i64) >> (64 - bits)) as u64 }
    };
    let sign = |x: u64| from < 8 && x & (1u64 << (from * 8 - 1)) != 0;
    match v {
        AbstractValue::Const(c) => AbstractValue::Const(ext(c)),
        AbstractValue::Set(s) => AbstractValue::Set(s.into_iter().map(ext).collect()),
        AbstractValue::Range(lo, hi) if sign(lo) == sign(hi) => AbstractValue::Range(ext(lo), ext(hi)),
        AbstractValue::Range(..) => AbstractValue::Top,
        v => v,
    }
}

/// `a + b` as an `size`-byte value. A range that wraps is unknown.
fn add(a: AbstractValue, b: AbstractValue, size: u32) -> AbstractValue {
    use AbstractValue::*;
    let m = bit_mask(size);
    let r = match (a, b) {
        (Bot, _) | (_, Bot) => Bot,
        (Top, _) | (_, Top) => Top,
        (Const(x), Const(y)) => Const(x.wrapping_add(y) & m),
        (Const(x), Range(lo, hi)) | (Range(lo, hi), Const(x)) => {
            let (l, h) = (lo.wrapping_add(x) & m, hi.wrapping_add(x) & m);
            if l <= h && h - l == hi - lo { Range(l, h) } else { Top }
        }
        (Range(la, ha), Range(lb, hb)) => match (la.checked_add(lb), ha.checked_add(hb)) {
            (Some(l), Some(h)) if h <= m => Range(l, h),
            _ => Top,
        },
        (Const(x), Set(s)) | (Set(s), Const(x)) => Set(s.into_iter().map(|v| v.wrapping_add(x) & m).collect()),
        _ => Top,
    };
    normalize(r)
}

/// State: registers by base offset, other varnodes by `(space, offset)`
/// with their size. A missing entry is Top.
///
/// A register is either known bytes ([`Slot::Bytes`], in `regs`) or an
/// abstract low part ([`Slot::Low`], in `abs`). The flows keep few
/// values (about one register at a join), so each kind is a small list
/// sorted by key rather than a map or an array of every register: a
/// lookup scans a few entries, and a clone, a comparison or a join
/// touches only what is known. The lists hold no unknown entry, so two
/// states are equal exactly when they hold the same values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    /// Registers with a known byte: `(base, bytes)`, by base.
    regs: SmallVec<[(u64, ByteConst); 4]>,
    /// Registers holding an abstract low part: `(base, width, value)`,
    /// by base.
    abs: Vec<(u64, u32, AbstractValue)>,
    /// Other varnodes: `(space, offset, size, value)`, by `(space,
    /// offset)`.
    temps: Vec<(SpaceId, i64, u32, Slot)>,
}

/// An input of an op as [`State::eval`]'s abstract part reads it.
enum Input {
    Const(u64),
    Top,
    /// A register or temporary holding an abstract value.
    Abstract,
}

impl State {
    /// The known bytes of the register at `base` (none for an abstract
    /// one).
    #[inline]
    fn reg_bytes(&self, base: u64) -> ByteConst {
        for (b, v) in &self.regs {
            if *b >= base {
                return if *b == base { *v } else { ByteConst::UNKNOWN };
            }
        }
        ByteConst::UNKNOWN
    }

    /// The abstract low part of the register at `base`.
    #[inline]
    fn reg_abs(&self, base: u64) -> Option<(u32, &AbstractValue)> {
        if self.abs.is_empty() {
            return None;
        }
        let k = self.abs.binary_search_by_key(&base, |e| e.0).ok()?;
        Some((self.abs[k].1, &self.abs[k].2))
    }

    /// The register at `base` as a slot (`None`: Top).
    fn reg_slot(&self, base: u64) -> Option<Slot> {
        if let Some((w, v)) = self.reg_abs(base) {
            return Some(Slot::Low(w, v.clone()));
        }
        let b = self.reg_bytes(base);
        (!b.is_unknown()).then_some(Slot::Bytes(b))
    }

    /// Set the known bytes of the register at `base`, which holds no
    /// abstract value (unknown: Top).
    #[inline]
    fn set_bytes(&mut self, base: u64, b: ByteConst) {
        let k = self.regs.partition_point(|e| e.0 < base);
        match self.regs.get(k) {
            Some(e) if e.0 == base => {
                if b.is_unknown() {
                    self.regs.remove(k);
                } else {
                    self.regs[k].1 = b;
                }
            }
            _ if b.is_unknown() => {}
            _ => self.regs.insert(k, (base, b)),
        }
    }

    /// Set the register at `base` (`Slot::Bytes(UNKNOWN)`: Top).
    fn set_reg(&mut self, base: u64, slot: Slot) {
        let at = if self.abs.is_empty() { Err(0) } else { self.abs.binary_search_by_key(&base, |e| e.0) };
        match slot {
            Slot::Bytes(b) => {
                if let Ok(k) = at {
                    self.abs.remove(k);
                }
                self.set_bytes(base, b);
            }
            Slot::Low(w, v) => {
                self.set_bytes(base, ByteConst::UNKNOWN);
                match at {
                    Ok(k) => self.abs[k] = (base, w, v),
                    Err(k) => self.abs.insert(k, (base, w, v)),
                }
            }
        }
    }

    /// The temporary at `(space, offset)`: `(size, value)`.
    #[inline]
    fn temp(&self, space: SpaceId, offset: i64) -> Option<(u32, &Slot)> {
        if self.temps.is_empty() {
            return None;
        }
        let k = self.temps.binary_search_by(|e| (e.0, e.1).cmp(&(space, offset))).ok()?;
        Some((self.temps[k].2, &self.temps[k].3))
    }

    /// The known bytes of a varnode.
    fn read_bytes(&self, vn: &VarnodeData) -> ByteConst {
        match vn.space {
            SpaceId::CONST => ByteConst::konst(vn.offset, vn.size),
            SpaceId::REGISTER => match split(vn.offset, vn.size) {
                Some((base, pos)) => self.reg_bytes(base).bytes_at(pos, vn.size),
                None => ByteConst::UNKNOWN,
            },
            s => match self.temp(s, vn.offset as i64) {
                Some((sz, slot)) if sz >= vn.size => slot.bytes().trunc(vn.size),
                _ => ByteConst::UNKNOWN,
            },
        }
    }

    /// The abstract value of a varnode.
    fn read(&self, vn: &VarnodeData) -> AbstractValue {
        match vn.space {
            SpaceId::CONST => AbstractValue::Const(vn.offset & bit_mask(vn.size)),
            SpaceId::REGISTER => match split(vn.offset, vn.size) {
                Some((base, pos)) => match self.reg_abs(base) {
                    Some((w, v)) if pos == 0 && vn.size <= w => fit(v.clone(), vn.size),
                    Some(_) => AbstractValue::Top,
                    None => self
                        .reg_bytes(base)
                        .bytes_at(pos, vn.size)
                        .get(vn.size)
                        .map_or(AbstractValue::Top, AbstractValue::Const),
                },
                None => AbstractValue::Top,
            },
            s => match self.temp(s, vn.offset as i64) {
                Some((sz, slot)) if sz >= vn.size => slot.read(0, vn.size),
                _ => AbstractValue::Top,
            },
        }
    }

    /// [`State::read`] when it is a constant or Top; `Abstract` when
    /// the varnode reads an abstract value (which [`State::read`] may
    /// narrow to a constant).
    #[inline]
    fn read_input(&self, vn: &VarnodeData) -> Input {
        let bytes = match vn.space {
            SpaceId::CONST => return Input::Const(vn.offset & bit_mask(vn.size)),
            SpaceId::REGISTER => match split(vn.offset, vn.size) {
                Some((base, pos)) => {
                    if self.reg_abs(base).is_some() {
                        return Input::Abstract;
                    }
                    self.reg_bytes(base).bytes_at(pos, vn.size)
                }
                None => return Input::Top,
            },
            s => match self.temp(s, vn.offset as i64) {
                Some((sz, Slot::Bytes(b))) if sz >= vn.size => b.trunc(vn.size),
                Some((sz, Slot::Low(..))) if sz >= vn.size => return Input::Abstract,
                _ => return Input::Top,
            },
        };
        bytes.get(vn.size).map_or(Input::Top, Input::Const)
    }

    fn write(&mut self, out: &VarnodeData, v: Val) {
        let v = match v {
            Val::Abs(AbstractValue::Const(c)) => Val::Bytes(ByteConst::konst(c, out.size)),
            Val::Abs(AbstractValue::Top | AbstractValue::Bot) => Val::Bytes(ByteConst::UNKNOWN),
            v => v,
        };
        if out.space == SpaceId::REGISTER {
            let Some((base, pos)) = split(out.offset, out.size) else {
                // forget every register the write touches
                let lo = out.offset & !7;
                let end = out.offset.saturating_add(u64::from(out.size.max(1)));
                self.regs.retain(|e| !(e.0 >= lo && e.0 < end));
                self.abs.retain(|e| !(e.0 >= lo && e.0 < end));
                return;
            };
            match v {
                Val::Abs(a) if pos == 0 => self.set_reg(base, Slot::Low(out.size, a)),
                Val::Abs(_) => {
                    let b = self.reg_bytes(base).merge(pos, out.size, ByteConst::UNKNOWN);
                    self.set_reg(base, Slot::Bytes(b));
                }
                Val::Bytes(b) if self.abs.is_empty() => {
                    // (`reg_bytes` then `set_bytes`, the register found once)
                    let k = self.regs.iter().position(|e| e.0 >= base).unwrap_or(self.regs.len());
                    match self.regs.get_mut(k) {
                        Some(e) if e.0 == base => {
                            let b = e.1.merge(pos, out.size, b);
                            if b.is_unknown() {
                                self.regs.remove(k);
                            } else {
                                e.1 = b;
                            }
                        }
                        // (no byte known before: known where `b` is, none when it knows none)
                        _ if b.trunc(out.size).is_unknown() => {}
                        _ => self.regs.insert(k, (base, ByteConst::UNKNOWN.merge(pos, out.size, b))),
                    }
                }
                Val::Bytes(b) => {
                    let b = self.reg_bytes(base).merge(pos, out.size, b);
                    self.set_reg(base, Slot::Bytes(b));
                }
            }
            return;
        }
        let off = out.offset as i64;
        let space = out.space;
        if !self.temps.is_empty() {
            // forget every entry the write overlaps (an entry is at
            // most 8 bytes wide, so it starts after `off - 8`)
            let end = off.saturating_add(i64::from(out.size.max(1)));
            let lo = self.temps.partition_point(|e| (e.0, e.1) < (space, off.saturating_sub(8)));
            let hi = self.temps.partition_point(|e| (e.0, e.1) < (space, end));
            if lo < hi {
                let mut w = lo;
                for r in lo..hi {
                    let (o, sz) = (self.temps[r].1, self.temps[r].2);
                    if o.saturating_add(i64::from(sz)) <= off {
                        self.temps.swap(w, r);
                        w += 1;
                    }
                }
                self.temps.drain(w..hi);
            }
        }
        if out.size > 8 {
            return;
        }
        let slot = match v {
            Val::Abs(a) => Slot::Low(out.size, a),
            Val::Bytes(b) if !b.trunc(out.size).is_unknown() => Slot::Bytes(b.trunc(out.size)),
            Val::Bytes(_) => return,
        };
        match self.temps.binary_search_by(|e| (e.0, e.1).cmp(&(space, off))) {
            Ok(k) => self.temps[k] = (space, off, out.size, slot),
            Err(k) => self.temps.insert(k, (space, off, out.size, slot)),
        }
    }

    /// The output value of a non-call op.
    fn eval(&self, op: &PcodeOp) -> Val {
        let Some(out) = op.output.as_ref() else {
            return Val::Bytes(ByteConst::UNKNOWN);
        };
        if op.opcode == OpCode::Load {
            return Val::Bytes(ByteConst::UNKNOWN);
        }
        let bytes = eval(op, |vn| self.read_bytes(vn));
        if let Some(b) = bytes
            && b.get(out.size).is_some()
        {
            return Val::Bytes(b);
        }
        let otherwise = Val::Bytes(bytes.unwrap_or(ByteConst::UNKNOWN));
        // The abstract value from inputs that are constants or Top (a
        // constant or Top, as the general case below gives it); `None`
        // when an input is abstract.
        let input = |i: usize| op.inputs.get(i).map_or(Input::Top, |vn| self.read_input(vn));
        let konst: Option<Option<u64>> = match op.opcode {
            OpCode::Copy | OpCode::IntZExt => match input(0) {
                Input::Const(c) => Some(Some(c)),
                Input::Top => Some(None),
                Input::Abstract => None,
            },
            OpCode::IntSExt => match op.inputs.first() {
                None => Some(None),
                Some(vn) => match self.read_input(vn) {
                    Input::Const(c) => match sext(AbstractValue::Const(c), vn.size) {
                        AbstractValue::Const(x) => Some(Some(x)),
                        _ => Some(None),
                    },
                    Input::Top => Some(None),
                    Input::Abstract => None,
                },
            },
            OpCode::Subpiece => match op.inputs.get(1) {
                Some(k) if k.space == SpaceId::CONST && k.offset == 0 => match input(0) {
                    Input::Const(c) => Some(Some(c)),
                    Input::Top => Some(None),
                    Input::Abstract => None,
                },
                // only a set shifts
                Some(k) if k.space == SpaceId::CONST && k.offset < 8 => match input(0) {
                    Input::Abstract => None,
                    _ => Some(None),
                },
                _ => Some(None),
            },
            OpCode::IntAdd => match (input(0), input(1)) {
                (Input::Abstract, _) | (_, Input::Abstract) => None,
                (Input::Const(x), Input::Const(y)) => Some(Some(x.wrapping_add(y) & bit_mask(out.size))),
                _ => Some(None),
            },
            _ => return otherwise,
        };
        match konst {
            Some(Some(c)) if out.size <= 8 => return Val::Bytes(ByteConst::konst(c, out.size)),
            Some(_) => return otherwise,
            None => {}
        }
        let input = |i: usize| op.inputs.get(i).map_or(AbstractValue::Top, |vn| self.read(vn));
        let abs = match op.opcode {
            OpCode::Copy | OpCode::IntZExt => input(0),
            OpCode::IntSExt => op.inputs.first().map_or(AbstractValue::Top, |vn| sext(self.read(vn), vn.size)),
            OpCode::Subpiece => match op.inputs.get(1) {
                Some(k) if k.space == SpaceId::CONST && k.offset == 0 => input(0),
                Some(k) if k.space == SpaceId::CONST && k.offset < 8 => match input(0) {
                    AbstractValue::Set(s) => AbstractValue::Set(s.into_iter().map(|v| v >> (k.offset * 8)).collect()),
                    _ => AbstractValue::Top,
                },
                _ => AbstractValue::Top,
            },
            OpCode::IntAdd => add(input(0), input(1), out.size),
            _ => AbstractValue::Top,
        };
        match fit(abs, out.size.min(8)) {
            a @ (AbstractValue::Set(_) | AbstractValue::Range(..)) if out.size <= 8 => Val::Abs(a),
            AbstractValue::Const(c) if out.size <= 8 => Val::Bytes(ByteConst::konst(c, out.size)),
            _ => otherwise,
        }
    }

    /// Apply one non-call op (inlined: the ops that change nothing, a view refresh or an op
    /// without an output, return before the call to [`Self::apply_output`]).
    #[inline(always)]
    fn apply(&mut self, op: &PcodeOp) {
        if is_unmodeled(op) {
            *self = State::default();
            return;
        }
        let Some(out) = op.output.as_ref() else {
            return;
        };
        if is_view_refresh(op) {
            return;
        }
        self.apply_output(op, out);
    }

    /// [`Self::apply`] of an op that writes `out`.
    #[inline(never)]
    fn apply_output(&mut self, op: &PcodeOp, out: &VarnodeData) {
        let v = self.eval(op);
        self.write(out, v);
    }

    /// Every register whose 8 bytes are pinned, at a call.
    fn call_snapshot(&self) -> BTreeMap<u64, AbstractValue> {
        let consts = self.regs.iter().filter_map(|(b, s)| s.get(8).map(|v| (*b, AbstractValue::Const(v))));
        if self.abs.is_empty() {
            return consts.collect();
        }
        let lows = self.abs.iter().filter_map(|(b, w, v)| {
            let v = Slot::Low(*w, v.clone()).read(0, 8);
            (!matches!(v, AbstractValue::Top | AbstractValue::Bot)).then_some((*b, v))
        });
        consts.chain(lows).collect()
    }

    /// CFG join.
    fn join(&self, other: &State) -> State {
        let mut out = State::default();
        if self.abs.is_empty() && other.abs.is_empty() {
            // known bytes only: merge the two sorted lists
            let mut k = 0;
            for &(base, a) in &self.regs {
                while k < other.regs.len() && other.regs[k].0 < base {
                    k += 1;
                }
                let Some(&(ob, b)) = other.regs.get(k) else { break };
                if ob != base {
                    continue;
                }
                if a == b {
                    out.regs.push((base, a));
                } else if let Some(j) = Slot::Bytes(a).join(&Slot::Bytes(b)) {
                    match j {
                        Slot::Bytes(j) => out.regs.push((base, j)),
                        Slot::Low(w, v) => out.abs.push((base, w, v)),
                    }
                }
            }
        } else {
            let mut bases: SmallVec<[u64; 8]> =
                self.regs.iter().map(|e| e.0).chain(self.abs.iter().map(|e| e.0)).collect();
            bases.sort_unstable();
            for base in bases {
                if let (Some(x), Some(y)) = (self.reg_slot(base), other.reg_slot(base))
                    && let Some(j) = x.join(&y)
                {
                    match j {
                        Slot::Bytes(j) => out.regs.push((base, j)),
                        Slot::Low(w, v) => out.abs.push((base, w, v)),
                    }
                }
            }
        }
        // temporaries: both sorted by key
        let mut k = 0;
        for (space, off, sz, s) in &self.temps {
            while k < other.temps.len() && (other.temps[k].0, other.temps[k].1) < (*space, *off) {
                k += 1;
            }
            if let Some((os, oo, osz, o)) = other.temps.get(k)
                && (*os, *oo) == (*space, *off)
                && osz == sz
                && let Some(j) = s.join(o)
            {
                out.temps.push((*space, *off, *sz, j));
            }
        }
        out
    }
}

/// `(base, byte position)` of a REGISTER access inside one 8-byte
/// register.
fn split(offset: u64, size: u32) -> Option<(u64, u32)> {
    let pos = (offset & 7) as u32;
    (size > 0 && pos + size <= 8).then_some((offset & !7, pos))
}

pub fn run_vsa(lifter: &dyn PcodeLift, program: &Program) -> VsaResult {
    // Lift + propagate each function in parallel (a function's
    // propagation reads only its own lift), then merge the snapshots
    // in listing order, exactly as the sequential walk would.
    let per_func: Vec<Option<CallSnapshots>> = function_jobs(program)
        .par_iter()
        .map(|&(entry, max)| {
            lift_function(lifter, program, entry, max).map(|insns| function_snapshots(program, entry, &insns))
        })
        .collect();
    let mut out = VsaResult::new();
    for snaps in per_func.into_iter().flatten() {
        merge_snapshots(&mut out, snaps);
    }
    out
}

/// One function's call snapshots, in the order its worklist records
/// them (a site may appear once per visit).
pub type CallSnapshots = Vec<(u64, BTreeMap<u64, AbstractValue>)>;

/// Propagate the lifted instructions of the function at `entry`
/// (empty for an empty lift), keeping the call sites it owns. Merge
/// the results of every function, in listing order, with
/// [`merge_snapshots`] to get [`run_vsa`].
pub fn function_snapshots(program: &Program, entry: u64, insns: &[LiftedInstruction]) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    function_snapshots_with(program, entry, insns, &external_entries(program, insns))
}

/// [`function_snapshots`] with the lift's [`external_entries`] already
/// computed.
pub(crate) fn function_snapshots_with(
    program: &Program,
    entry: u64,
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    let mut snaps = function_snapshots_unowned(program, entry, insns, external);
    let owner = crate::func_lift::Owner::new(program, entry);
    snaps.retain(|(addr, _)| owner.owns(*addr));
    snaps
}

/// [`function_snapshots_with`] before it drops the call sites the
/// function at `entry` does not own.
pub(crate) fn function_snapshots_unowned(
    program: &Program,
    entry: u64,
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    propagate_with(insns, external, |a| in_extent(program, entry, a))
}

/// [`function_snapshots_unowned`] over blocks already built for the
/// lift ([`blockflow::Cfg::build`] with the same `external` and
/// [`in_extent`] of the function).
pub(crate) fn function_snapshots_cfg<I: std::borrow::Borrow<LiftedInstruction>>(
    cfg: &blockflow::Cfg,
    insns: &[I],
) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    blockflow::propagate_cfg::<State, _, _>(cfg, insns, State::call_snapshot)
}

/// [`function_snapshots_cfg`] keeping the snapshots of the calls of the
/// instructions `want` accepts ([`blockflow::propagate_cfg_with`]).
pub(crate) fn function_snapshots_cfg_with<I: std::borrow::Borrow<LiftedInstruction>>(
    cfg: &blockflow::Cfg,
    insns: &[I],
    want: impl Fn(usize) -> bool,
    scratch: &mut FlowScratch,
) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    blockflow::propagate_cfg_with::<State, _, _>(cfg, insns, State::call_snapshot, want, &mut scratch.0)
}

/// The buffers of [`function_snapshots_cfg_with`], kept between runs.
#[derive(Default)]
pub(crate) struct FlowScratch(blockflow::FlowScratch<State>);

/// Fold one function's call snapshots into the program-wide map.
pub fn merge_snapshots(out: &mut VsaResult, snaps: CallSnapshots) {
    for (addr, regs) in snaps {
        let entry = out.entry(addr).or_default();
        if entry.is_empty() {
            *entry = regs;
        } else {
            let mut merged: BTreeMap<u64, AbstractValue> = BTreeMap::new();
            for (k, v) in entry.iter() {
                if let Some(other) = regs.get(k) {
                    merged.insert(*k, v.join(other));
                }
            }
            *entry = merged;
        }
    }
}

#[cfg(test)]
fn propagate(insns: &[LiftedInstruction]) -> CallSnapshots {
    propagate_with(insns, &BTreeSet::new(), |_| true)
}

fn propagate_with(
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
    in_body: impl Fn(u64) -> bool,
) -> CallSnapshots {
    blockflow::propagate::<State, _>(insns, external, in_body, State::call_snapshot)
}

impl FlowState for State {
    fn join(&self, other: &Self) -> Self {
        State::join(self, other)
    }
    #[inline]
    fn apply(&mut self, op: &PcodeOp) {
        State::apply(self, op);
    }
    /// SysV: caller-saved registers clobbered (conservatively every
    /// register); temporaries are kept.
    fn after_call(&mut self) {
        self.regs.clear();
        self.abs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_const_const_same() {
        let a = AbstractValue::Const(5);
        let b = AbstractValue::Const(5);
        assert_eq!(a.join(&b), AbstractValue::Const(5));
    }

    #[test]
    fn join_const_const_diff() {
        let a = AbstractValue::Const(1);
        let b = AbstractValue::Const(2);
        match a.join(&b) {
            AbstractValue::Set(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&1) && s.contains(&2));
            }
            other => panic!("expected Set, got {:?}", other),
        }
    }

    #[test]
    fn join_widens_to_range_at_8_elements() {
        let mut s = BTreeSet::new();
        for i in 0..8u64 {
            s.insert(i);
        }
        let a = AbstractValue::Set(s);
        let b = AbstractValue::Const(100);
        match a.join(&b) {
            AbstractValue::Range(lo, hi) => {
                assert_eq!(lo, 0);
                assert_eq!(hi, 100);
            }
            other => panic!("expected Range, got {:?}", other),
        }
    }

    #[test]
    fn join_range_const() {
        let a = AbstractValue::Range(5, 10);
        let b = AbstractValue::Const(20);
        match a.join(&b) {
            AbstractValue::Range(5, 20) => {}
            other => panic!("expected Range(5,20), got {:?}", other),
        }
    }

    #[test]
    fn join_top_dominates() {
        let a = AbstractValue::Const(5);
        let b = AbstractValue::Top;
        assert_eq!(a.join(&b), AbstractValue::Top);
    }

    #[test]
    fn join_bot_neutral() {
        let a = AbstractValue::Bot;
        let b = AbstractValue::Const(7);
        assert_eq!(a.join(&b), AbstractValue::Const(7));
    }

    #[test]
    fn as_single_const() {
        assert_eq!(AbstractValue::Const(42).as_single(), Some(42));
    }

    #[test]
    fn as_single_singleton_set() {
        let mut s = BTreeSet::new();
        s.insert(7);
        assert_eq!(AbstractValue::Set(s).as_single(), Some(7));
    }

    #[test]
    fn as_single_degenerate_range() {
        assert_eq!(AbstractValue::Range(5, 5).as_single(), Some(5));
    }

    #[test]
    fn as_single_unknown_returns_none() {
        assert_eq!(AbstractValue::Top.as_single(), None);
        assert_eq!(AbstractValue::Range(5, 10).as_single(), None);
    }

    /// End-to-end VSA on a synthesised P-code stream — pins down the
    /// worklist convergence behaviour so the post-review refactor
    /// from "scan all blocks every round" to "succs-on-change"
    /// doesn't silently regress.
    ///
    /// Synthesised stream:
    ///   block A (entry, addr 0x1000):
    ///     COPY rdi = CONST(0x42)
    ///     BRANCH 0x2000
    ///   block B (addr 0x2000):
    ///     CALL <some target> ; expect snapshot to record rdi = 0x42
    ///     RETURN
    #[test]
    fn propagate_records_call_snapshot_across_blocks() {
        use reargo_core::address::{Address, SpaceId};
        use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
        use reargo_lift::LiftedInstruction;

        // rdi register offset in the SysV register map = 0x38; using
        // the same convention the rest of the crate does so the
        // result map's inner key is comparable.
        let rdi_off = 0x38u64;

        fn vn_reg(off: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::REGISTER,
                offset: off,
                size: 8,
            }
        }
        fn vn_const(v: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::CONST,
                offset: v,
                size: 8,
            }
        }
        fn vn_ram(addr: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::RAM,
                offset: addr,
                size: 8,
            }
        }
        fn op(opcode: OpCode, inputs: Vec<VarnodeData>, output: Option<VarnodeData>) -> PcodeOp {
            let mut o = PcodeOp::new(opcode, SeqNum::new(Address::new(SpaceId::RAM, 0), 0));
            o.inputs = inputs.into_iter().collect();
            o.output = output;
            o
        }

        let block_a = LiftedInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "block-a".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0x42)], Some(vn_reg(rdi_off))),
                op(OpCode::Branch, vec![vn_ram(0x2000)], None),
            ],
        };
        let block_b = LiftedInstruction {
            address: 0x2000,
            length: 4,
            mnemonic: "block-b".into(),
            ops: vec![
                op(OpCode::Call, vec![vn_const(0xdeadbeef)], None),
                op(OpCode::Return, vec![vn_const(0)], None),
            ],
        };

        let mut result = VsaResult::new();
        merge_snapshots(&mut result, propagate(&[block_a, block_b]));

        let snap = result.get(&0x2000).expect("call snapshot at 0x2000");
        let v = snap.get(&rdi_off).expect("rdi tracked across branch");
        assert_eq!(v.as_single(), Some(0x42));
    }

    /// Convergence: when block A pins rdi to two different values
    /// along two branches, the joined input to the callee block
    /// becomes a Set with both. Verifies the worklist re-walks block
    /// B exactly when out_state for one of its predecessors actually
    /// changed.
    #[test]
    fn propagate_joins_disagreeing_predecessors_into_set() {
        use reargo_core::address::{Address, SpaceId};
        use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
        use reargo_lift::LiftedInstruction;

        let rdi_off = 0x38u64;

        fn vn_reg(off: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::REGISTER,
                offset: off,
                size: 8,
            }
        }
        fn vn_const(v: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::CONST,
                offset: v,
                size: 8,
            }
        }
        fn vn_ram(a: u64) -> VarnodeData {
            VarnodeData {
                space: SpaceId::RAM,
                offset: a,
                size: 8,
            }
        }
        fn op(opcode: OpCode, inputs: Vec<VarnodeData>, output: Option<VarnodeData>) -> PcodeOp {
            let mut o = PcodeOp::new(opcode, SeqNum::new(Address::new(SpaceId::RAM, 0), 0));
            o.inputs = inputs.into_iter().collect();
            o.output = output;
            o
        }

        // entry block at 0x1000: conditional branch to 0x2000 / fall
        // through to 0x1010
        let entry = LiftedInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "entry".into(),
            ops: vec![op(OpCode::CBranch, vec![vn_ram(0x2000)], None)],
        };
        // fall-through block: rdi = 0x42, jmp to 0x3000
        let fallthrough = LiftedInstruction {
            address: 0x1010,
            length: 4,
            mnemonic: "ft".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0x42)], Some(vn_reg(rdi_off))),
                op(OpCode::Branch, vec![vn_ram(0x3000)], None),
            ],
        };
        // taken block: rdi = 0x43, jmp to 0x3000
        let taken = LiftedInstruction {
            address: 0x2000,
            length: 4,
            mnemonic: "taken".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0x43)], Some(vn_reg(rdi_off))),
                op(OpCode::Branch, vec![vn_ram(0x3000)], None),
            ],
        };
        let call_block = LiftedInstruction {
            address: 0x3000,
            length: 4,
            mnemonic: "call".into(),
            ops: vec![
                op(OpCode::Call, vec![vn_const(0xdeadbeef)], None),
                op(OpCode::Return, vec![vn_const(0)], None),
            ],
        };

        let mut result = VsaResult::new();
        merge_snapshots(&mut result, propagate(&[entry, fallthrough, taken, call_block]));

        let snap = result.get(&0x3000).expect("call snapshot at 0x3000");
        let v = snap.get(&rdi_off).expect("rdi joined into call snapshot");
        match v {
            AbstractValue::Set(s) => {
                assert!(s.contains(&0x42) && s.contains(&0x43), "got: {:?}", s);
            }
            other => panic!("expected Set, got {:?}", other),
        }
    }

    /// The `State` before the register file: registers and temporaries
    /// in `BTreeMap`s. The reference for [`state_matches_map_state`].
    mod old {
        use super::super::*;

    /// State: registers by base offset, other varnodes by `(space, offset)`
    /// with their size. A missing entry is Top.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub(super) struct OldState {
        pub(super) regs: BTreeMap<u64, Slot>,
        pub(super) temps: BTreeMap<(SpaceId, i64), (u32, Slot)>,
    }

    impl OldState {
        /// The known bytes of a varnode.
        pub(super) fn read_bytes(&self, vn: &VarnodeData) -> ByteConst {
            match vn.space {
                SpaceId::CONST => ByteConst::konst(vn.offset, vn.size),
                SpaceId::REGISTER => match split(vn.offset, vn.size) {
                    Some((base, pos)) => self.regs.get(&base).map_or(ByteConst::UNKNOWN, |s| s.bytes().bytes_at(pos, vn.size)),
                    None => ByteConst::UNKNOWN,
                },
                s => match self.temps.get(&(s, vn.offset as i64)) {
                    Some((sz, slot)) if *sz >= vn.size => slot.bytes().trunc(vn.size),
                    _ => ByteConst::UNKNOWN,
                },
            }
        }

        /// The abstract value of a varnode.
        pub(super) fn read(&self, vn: &VarnodeData) -> AbstractValue {
            match vn.space {
                SpaceId::CONST => AbstractValue::Const(vn.offset & bit_mask(vn.size)),
                SpaceId::REGISTER => match split(vn.offset, vn.size) {
                    Some((base, pos)) => self.regs.get(&base).map_or(AbstractValue::Top, |s| s.read(pos, vn.size)),
                    None => AbstractValue::Top,
                },
                s => match self.temps.get(&(s, vn.offset as i64)) {
                    Some((sz, slot)) if *sz >= vn.size => slot.read(0, vn.size),
                    _ => AbstractValue::Top,
                },
            }
        }

        fn write(&mut self, out: &VarnodeData, v: Val) {
            let v = match v {
                Val::Abs(AbstractValue::Const(c)) => Val::Bytes(ByteConst::konst(c, out.size)),
                Val::Abs(AbstractValue::Top | AbstractValue::Bot) => Val::Bytes(ByteConst::UNKNOWN),
                v => v,
            };
            if out.space == SpaceId::REGISTER {
                let Some((base, pos)) = split(out.offset, out.size) else {
                    let end = out.offset.saturating_add(u64::from(out.size.max(1)));
                    let bases: Vec<u64> = self.regs.range(out.offset & !7..end).map(|(b, _)| *b).collect();
                    for b in bases {
                        self.regs.remove(&b);
                    }
                    return;
                };
                let next = match v {
                    Val::Abs(a) if pos == 0 => Slot::Low(out.size, a),
                    Val::Abs(_) => Slot::Bytes(self.regs.get(&base).map_or(ByteConst::UNKNOWN, Slot::bytes).merge(
                        pos,
                        out.size,
                        ByteConst::UNKNOWN,
                    )),
                    Val::Bytes(b) => {
                        Slot::Bytes(self.regs.get(&base).map_or(ByteConst::UNKNOWN, Slot::bytes).merge(pos, out.size, b))
                    }
                };
                if next == Slot::Bytes(ByteConst::UNKNOWN) {
                    self.regs.remove(&base);
                } else {
                    self.regs.insert(base, next);
                }
                return;
            }
            let off = out.offset as i64;
            let end = off.saturating_add(i64::from(out.size.max(1)));
            let overlapping: smallvec::SmallVec<[(SpaceId, i64); 4]> = self
                .temps
                .range((out.space, off.saturating_sub(8))..(out.space, end))
                .filter(|((_, o), (sz, _))| o.saturating_add(i64::from(*sz)) > off)
                .map(|(k, _)| *k)
                .collect();
            for k in overlapping {
                self.temps.remove(&k);
            }
            if out.size > 8 {
                return;
            }
            let slot = match v {
                Val::Abs(a) => Slot::Low(out.size, a),
                Val::Bytes(b) if !b.trunc(out.size).is_unknown() => Slot::Bytes(b.trunc(out.size)),
                Val::Bytes(_) => return,
            };
            self.temps.insert((out.space, off), (out.size, slot));
        }

        /// The output value of a non-call op.
        fn eval(&self, op: &PcodeOp) -> Val {
            let Some(out) = op.output.as_ref() else {
                return Val::Bytes(ByteConst::UNKNOWN);
            };
            if op.opcode == OpCode::Load {
                return Val::Bytes(ByteConst::UNKNOWN);
            }
            let bytes = eval(op, |vn| self.read_bytes(vn));
            if let Some(b) = bytes
                && b.get(out.size).is_some()
            {
                return Val::Bytes(b);
            }
            let input = |i: usize| op.inputs.get(i).map_or(AbstractValue::Top, |vn| self.read(vn));
            let abs = match op.opcode {
                OpCode::Copy | OpCode::IntZExt => input(0),
                OpCode::IntSExt => op.inputs.first().map_or(AbstractValue::Top, |vn| sext(self.read(vn), vn.size)),
                OpCode::Subpiece => match op.inputs.get(1) {
                    Some(k) if k.space == SpaceId::CONST && k.offset == 0 => input(0),
                    Some(k) if k.space == SpaceId::CONST && k.offset < 8 => match input(0) {
                        AbstractValue::Set(s) => AbstractValue::Set(s.into_iter().map(|v| v >> (k.offset * 8)).collect()),
                        _ => AbstractValue::Top,
                    },
                    _ => AbstractValue::Top,
                },
                OpCode::IntAdd => add(input(0), input(1), out.size),
                _ => AbstractValue::Top,
            };
            match fit(abs, out.size.min(8)) {
                a @ (AbstractValue::Set(_) | AbstractValue::Range(..)) if out.size <= 8 => Val::Abs(a),
                AbstractValue::Const(c) if out.size <= 8 => Val::Bytes(ByteConst::konst(c, out.size)),
                _ => Val::Bytes(bytes.unwrap_or(ByteConst::UNKNOWN)),
            }
        }

        /// Apply one non-call op.
        pub(super) fn apply(&mut self, op: &PcodeOp) {
            if is_unmodeled(op) {
                *self = OldState::default();
                return;
            }
            let Some(out) = op.output.as_ref() else {
                return;
            };
            if is_view_refresh(op) {
                return;
            }
            let v = self.eval(op);
            self.write(out, v);
        }

        /// Every register whose 8 bytes are pinned, at a call.
        pub(super) fn call_snapshot(&self) -> BTreeMap<u64, AbstractValue> {
            self.regs
                .iter()
                .filter_map(|(b, s)| {
                    let v = s.read(0, 8);
                    (!matches!(v, AbstractValue::Top | AbstractValue::Bot)).then_some((*b, v))
                })
                .collect()
        }

        /// CFG join.
        pub(super) fn join(&self, other: &OldState) -> OldState {
            let regs = self
                .regs
                .iter()
                .filter_map(|(b, s)| Some((*b, s.join(other.regs.get(b)?)?)))
                .collect();
            let temps = self
                .temps
                .iter()
                .filter_map(|(k, (sz, s))| {
                    let (osz, o) = other.temps.get(k)?;
                    (osz == sz).then_some(())?;
                    Some((*k, (*sz, s.join(o)?)))
                })
                .collect();
            OldState { regs, temps }
        }
    }


    }

    /// The new state in the old one's maps.
    fn as_old(s: &State) -> old::OldState {
        let mut regs = BTreeMap::new();
        for (base, b) in &s.regs {
            assert!(!b.is_unknown());
            regs.insert(*base, Slot::Bytes(*b));
        }
        for (base, w, v) in &s.abs {
            assert!(regs.insert(*base, Slot::Low(*w, v.clone())).is_none());
        }
        assert!(s.regs.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(s.abs.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(s.temps.windows(2).all(|w| (w[0].0, w[0].1) < (w[1].0, w[1].1)));
        let temps = s.temps.iter().map(|(sp, o, sz, v)| ((*sp, *o), (*sz, v.clone()))).collect();
        old::OldState { regs, temps }
    }

    /// The list state behaves exactly as the map state on
    /// random op sequences, joins and calls: same contents, reads,
    /// snapshots and equalities.
    #[test]
    fn state_matches_map_state() {
        use crate::byteconst::testseq::{k, op};
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        const BASES: [u64; 12] = [0x0, 0x8, 0x30, 0x38, 0xb8, 0xc0, 0x200, 0x208, 0x218, 0x220, 0x1200, 0x1208];
        const SIZES: [u32; 6] = [1, 2, 4, 8, 8, 16];
        const VALUES: [u64; 8] = [0, 1, 2, 3, 0x80, 0xff, 0xffff_ffff_ffff_fff0, 0x4020_0000];
        let vn = |next: &mut dyn FnMut() -> u64| -> VarnodeData {
            let size = SIZES[(next() % 6) as usize];
            match next() % 10 {
                0..=4 => {
                    let base = BASES[(next() % 12) as usize];
                    let pos = if next().is_multiple_of(3) { next() % 8 } else { 0 };
                    VarnodeData::new(SpaceId::REGISTER, base + pos, size)
                }
                5..=7 => VarnodeData::new(SpaceId::UNIQUE, 0x100 + next() % 24, size),
                8 => VarnodeData::new(SpaceId::RAM, 0x5000 + next() % 16, size),
                _ => k(VALUES[(next() % 8) as usize], size),
            }
        };
        let mut checked = (0, 0, 0, 0);
        for round in 0..300 {
            let mut pool: Vec<(State, old::OldState)> = vec![(State::default(), old::OldState::default())];
            for step in 0..200 {
                let i = (next() as usize) % pool.len();
                match next() % 16 {
                    0 | 1 if pool.len() > 1 => {
                        let j = (next() as usize) % pool.len();
                        let n = pool[i].0.join(&pool[j].0);
                        let o = pool[i].1.join(&pool[j].1);
                        checked.1 += 1;
                        pool.push((n, o));
                    }
                    2 if next().is_multiple_of(4) => {
                        pool[i].0.after_call();
                        pool[i].1.regs.clear();
                    }
                    3 => {
                        let c = pool[i].clone();
                        pool.push(c);
                    }
                    4..=6 => {
                        // pin a whole register
                        let r = VarnodeData::new(SpaceId::REGISTER, BASES[(next() % 12) as usize], 8);
                        let o = op(OpCode::Copy, Some(r), &[k(VALUES[(next() % 8) as usize], 8)]);
                        pool[i].0.apply(&o);
                        pool[i].1.apply(&o);
                    }
                    _ => {
                        let opcode = [
                            OpCode::Copy,
                            OpCode::Copy,
                            OpCode::Copy,
                            OpCode::IntZExt,
                            OpCode::IntSExt,
                            OpCode::Subpiece,
                            OpCode::IntAdd,
                            OpCode::IntAdd,
                            OpCode::IntSub,
                            OpCode::IntAnd,
                            OpCode::IntXor,
                            OpCode::Piece,
                            OpCode::Load,
                            OpCode::CallOther,
                            OpCode::Store,
                            OpCode::IntLess,
                        ][(next() % 16) as usize];
                        let out = vn(&mut next);
                        let a = vn(&mut next);
                        let b = match opcode {
                            OpCode::Subpiece => k(next() % 9, 4),
                            OpCode::CallOther => k([0, 1, 0xff, 0x100][(next() % 4) as usize], 4),
                            _ => vn(&mut next),
                        };
                        let o = match opcode {
                            OpCode::CallOther => op(opcode, Some(out), &[b, a]),
                            OpCode::Store => op(opcode, None, &[a, b]),
                            OpCode::IntZExt | OpCode::IntSExt | OpCode::Copy => op(opcode, Some(out), &[a]),
                            _ => op(opcode, Some(out), &[a, b]),
                        };
                        pool[i].0.apply(&o);
                        pool[i].1.apply(&o);
                    }
                }
                for (n, o) in &pool {
                    assert_eq!(&as_old(n), o, "round {round} step {step}");
                    assert_eq!(n.call_snapshot(), o.call_snapshot(), "round {round} step {step}");
                    let v = vn(&mut next);
                    assert_eq!(n.read(&v), o.read(&v));
                    assert_eq!(n.read_bytes(&v), o.read_bytes(&v));
                    checked.2 += usize::from(n.abs.len() + n.temps.len() > 0);
                    checked.3 += usize::from(n.regs.len() > 4);
                }
                let (a, b) = ((next() as usize) % pool.len(), (next() as usize) % pool.len());
                assert_eq!(pool[a].0 == pool[b].0, pool[a].1 == pool[b].1);
                checked.0 += usize::from(pool[a].0 == pool[b].0 && a != b);
                if pool.len() > 12 {
                    pool.remove((next() as usize) % pool.len());
                }
            }
        }
        // the sequences reach abstract values, temporaries, joins and
        // equal states
        assert!(checked.0 > 100 && checked.1 > 1000 && checked.2 > 10000 && checked.3 > 1000, "{checked:?}");
    }

    /// The lifter's sub-register sequences, each followed by a call.
    #[test]
    fn sub_register_sequences_resolve() {
        use crate::byteconst::testseq::*;
        let snap = |ops: Vec<PcodeOp>| {
            let mut ops = ops;
            ops.push(op(OpCode::Call, None, &[k(0xdead, 8)]));
            let insn = LiftedInstruction { address: 0x1000, length: 4, mnemonic: "x".into(), ops };
            let mut result = VsaResult::new();
            merge_snapshots(&mut result, propagate(&[insn]));
            let s = result.remove(&0x1000).expect("call snapshot");
            move |r: u64| s.get(&r).and_then(AbstractValue::as_single)
        };
        assert_eq!(snap(mov_esi_imm32())(0x30), Some(0x2a));
        let s = snap(lea_rax_mov_rdi());
        assert_eq!((s(0), s(0x38)), (Some(0x402004), Some(0x402004)));
        assert_eq!(snap(mov_rax_then_al())(0), Some(0x7fff_1234_5605));
        let s = snap(ah_write_read());
        assert_eq!((s(0), s(0x08)), (Some(0x0734), Some(7)));
        let s = snap(movsx_movzx());
        assert_eq!(s(0x38), Some(0xffff_ff80));
        assert_eq!(s(0x30), Some(0x80));
        assert_eq!(s(0x80), Some(0xffff_ffff_ffff_ff80));
        assert_eq!(s(0x10), None);
    }

    /// A set flows through a 32-bit move and its view refreshes:
    /// `mov esi, {1|2}` joined, then `mov edi, esi` keeps the set in rdi.
    #[test]
    fn set_survives_32bit_move_and_views() {
        use crate::byteconst::testseq::*;
        let ram = |a: u64| VarnodeData { space: SpaceId::RAM, offset: a, size: 8 };
        let insn = |address: u64, ops: Vec<PcodeOp>| LiftedInstruction { address, length: 4, mnemonic: "x".into(), ops };
        let mut a = with_views(op(OpCode::Copy, Some(reg(0x30, 4)), &[k(1, 4)]));
        a.push(op(OpCode::Branch, None, &[ram(0x3000)]));
        let mut b = with_views(op(OpCode::Copy, Some(reg(0x30, 4)), &[k(2, 4)]));
        b.push(op(OpCode::Branch, None, &[ram(0x3000)]));
        let mut c = with_views(op(OpCode::Copy, Some(reg(0x38, 4)), &[reg(0x30, 4)]));
        c.push(op(OpCode::Call, None, &[k(0xdead, 8)]));
        let insns = [
            insn(0x1000, vec![op(OpCode::CBranch, None, &[ram(0x2000), reg(0x206, 1)])]),
            insn(0x1010, a),
            insn(0x2000, b),
            insn(0x3000, c),
        ];
        let mut result = VsaResult::new();
        merge_snapshots(&mut result, propagate(&insns));
        let snap = result.get(&0x3000).expect("call snapshot");
        assert_eq!(snap.get(&0x38), Some(&AbstractValue::Set([1u64, 2].into_iter().collect())));
    }
}
