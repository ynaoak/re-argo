//! Byte-precise constants with x86 sub-register semantics, shared by the
//! call-site argument trackers (`callsite`, `cfg_const`, `vsa`).
//!
//! The x86 lifter keeps every view of a general-purpose register coherent
//! by mirroring each write into the other views at the *same* REGISTER
//! offset with a different size. `mov esi, 0x2a` lifts to
//!
//! ```text
//! (reg, 0x30, 4) = COPY 0x2a
//! (reg, 0x30, 8) = INT_ZEXT (reg, 0x30, 4)
//! (reg, 0x30, 2) = SUBPIECE (reg, 0x30, 4), 0
//! (reg, 0x30, 1) = SUBPIECE (reg, 0x30, 4), 0
//! ```
//!
//! A tracker keyed on the offset alone loses (or truncates) the value at
//! the trailing narrow writes. Here a register is modelled as the eight
//! bytes at `offset & !7`, each known or not: a write of `size` bytes at
//! byte `offset & 7` replaces exactly those bytes (`ah` = byte 1 of `rax`,
//! offset 1), a read returns those bytes, and a view refresh
//! (`esi = SUBPIECE(rsi, 0)`) is a no-op. Values wider than 8 bytes
//! (XMM) are not tracked: a write to them forgets the bytes it covers.
//!
//! Other spaces (UNIQUE temporaries, …) are kept in a [`ByteMem`] keyed by
//! `(space, offset)` with the access size: a write forgets every entry it
//! overlaps, a read of the same offset returns the low bytes of the entry
//! when it is at least as wide.

use std::collections::BTreeMap;

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, PcodeOp, VarnodeData};

/// Bit mask of the low `size` bytes (`size` ≤ 8).
pub fn bit_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// Byte-known mask of the low `size` bytes (`size` ≤ 8).
#[inline]
fn byte_mask(size: u32) -> u8 {
    // (by table: one load where the shift and the select took several instructions)
    const MASKS: [u8; 9] = [0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];
    MASKS[size.min(8) as usize]
}

/// Bit mask of the bytes set in a byte-known mask.
fn bits_of(known: u8) -> u64 {
    const TABLE: [u64; 256] = {
        let mut t = [0u64; 256];
        let mut k = 0;
        while k < 256 {
            let mut i = 0;
            while i < 8 {
                if k & (1 << i) != 0 {
                    t[k] |= 0xff << (i * 8);
                }
                i += 1;
            }
            k += 1;
        }
        t
    };
    TABLE[known as usize]
}

/// Up to eight bytes of a value, each known or unknown. Unknown bytes
/// read as zero in `value` so equal states compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ByteConst {
    value: u64,
    known: u8,
}

impl ByteConst {
    /// Nothing known.
    pub const UNKNOWN: ByteConst = ByteConst { value: 0, known: 0 };

    fn new(value: u64, known: u8) -> Self {
        Self {
            value: value & bits_of(known),
            known,
        }
    }

    /// The constant `v`, `size` bytes wide (truncated).
    pub fn konst(v: u64, size: u32) -> Self {
        if size == 0 || size > 8 {
            return Self::UNKNOWN;
        }
        Self::new(v, byte_mask(size))
    }

    /// The value of the low `size` bytes when all of them are known.
    pub fn get(&self, size: u32) -> Option<u64> {
        if size == 0 || size > 8 {
            return None;
        }
        let m = byte_mask(size);
        (self.known & m == m).then_some(self.value & bit_mask(size))
    }

    /// Whether no byte is known.
    pub fn is_unknown(&self) -> bool {
        self.known == 0
    }

    /// The low `size` bytes (the rest unknown).
    pub fn trunc(self, size: u32) -> Self {
        Self::new(self.value, self.known & byte_mask(size.min(8)))
    }

    /// The `size` bytes starting at byte `pos`.
    pub fn bytes_at(self, pos: u32, size: u32) -> Self {
        if pos >= 8 {
            return Self::UNKNOWN;
        }
        Self::new(self.value >> (pos * 8), self.known >> pos).trunc(size)
    }

    /// `self` with its bytes `pos..pos + size` replaced by the low
    /// `size` bytes of `v` (known where `v` is).
    #[inline]
    pub fn merge(self, pos: u32, size: u32, v: ByteConst) -> Self {
        let m = byte_mask(size) << pos;
        let v = v.trunc(size);
        Self::new(
            (self.value & !bits_of(m)) | (v.value << (pos * 8)),
            (self.known & !m) | (v.known << pos),
        )
    }

    /// Per-byte intersection: a byte stays known when both sides know
    /// it with the same value.
    pub fn intersect(self, other: ByteConst) -> Self {
        let both = self.known & other.known;
        let diff = (self.value ^ other.value) & bits_of(both);
        Self::new(self.value, both & !nonzero_bytes(diff))
    }
}

/// The mask of the bytes of `x` that are not zero (bit `i`: byte `i`).
fn nonzero_bytes(x: u64) -> u8 {
    const LOW7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    // (the high bit of each byte: set when the byte is not zero)
    let high = (((x & LOW7) + LOW7) | x) & !LOW7;
    // (the high bits gathered into one byte, byte `i`'s at bit `i`)
    ((high >> 7).wrapping_mul(0x0102_0408_1020_4080) >> 56) as u8
}

/// `(base, byte position)` of a REGISTER access when it lies inside one
/// 8-byte register.
fn split(offset: u64, size: u32) -> Option<(u64, u32)> {
    let pos = (offset & 7) as u32;
    (size > 0 && pos + size <= 8).then_some((offset & !7, pos))
}

/// General-purpose registers (`rax`..`r15`, REGISTER offsets
/// `0x00..0xc0`) and the flags (`0x200..0x220`) live in fixed arrays,
/// cheap to read, write, clone and compare; other registers in a map.
const GPR_END: u64 = 0xc0;
const FLAGS_BASE: u64 = 0x200;
const FLAGS_END: u64 = 0x220;

/// REGISTER space as 8-byte registers of [`ByteConst`], keyed by base
/// offset (`offset & !7`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegFile {
    gpr: [ByteConst; (GPR_END / 8) as usize],
    flags: [ByteConst; ((FLAGS_END - FLAGS_BASE) / 8) as usize],
    other: BTreeMap<u64, ByteConst>,
}

impl RegFile {
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, base: u64) -> ByteConst {
        match base {
            b if b < GPR_END => self.gpr[(b / 8) as usize],
            b if (FLAGS_BASE..FLAGS_END).contains(&b) => {
                self.flags[((b - FLAGS_BASE) / 8) as usize]
            }
            b => self.other.get(&b).copied().unwrap_or(ByteConst::UNKNOWN),
        }
    }

    fn set_slot(&mut self, base: u64, v: ByteConst) {
        match base {
            b if b < GPR_END => self.gpr[(b / 8) as usize] = v,
            b if (FLAGS_BASE..FLAGS_END).contains(&b) => {
                self.flags[((b - FLAGS_BASE) / 8) as usize] = v
            }
            b if v.is_unknown() => {
                self.other.remove(&b);
            }
            b => {
                self.other.insert(b, v);
            }
        }
    }

    /// The `size` bytes at `offset`.
    pub fn read(&self, offset: u64, size: u32) -> ByteConst {
        match split(offset, size) {
            Some((base, pos)) => self.slot(base).bytes_at(pos, size),
            None => ByteConst::UNKNOWN,
        }
    }

    /// Write `size` bytes at `offset`; the register's other bytes keep
    /// their value. An access wider than one register forgets every
    /// register it touches.
    pub fn write(&mut self, offset: u64, size: u32, v: ByteConst) {
        let Some((base, pos)) = split(offset, size) else {
            self.forget(offset, size);
            return;
        };
        let next = self.slot(base).merge(pos, size, v);
        self.set_slot(base, next);
    }

    /// Forget the bytes `offset..offset + size`.
    pub fn forget(&mut self, offset: u64, size: u32) {
        let end = offset.saturating_add(u64::from(size.max(1)));
        let mut b = offset & !7;
        while b < end {
            let lo = offset.max(b);
            let hi = end.min(b + 8);
            let next = self
                .slot(b)
                .merge((lo - b) as u32, (hi - lo) as u32, ByteConst::UNKNOWN);
            self.set_slot(b, next);
            b += 8;
        }
    }

    /// The full 8-byte value of the register at `base`, when known.
    pub fn get64(&self, base: u64) -> Option<u64> {
        self.slot(base).get(8)
    }

    /// Set the full 8-byte register at `base`.
    pub fn set64(&mut self, base: u64, v: u64) {
        self.write(base, 8, ByteConst::konst(v, 8));
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Every register whose 8 bytes are all known, as `(base, value)`.
    pub fn full_values(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        let gpr = self.gpr.iter().enumerate().map(|(i, s)| (i as u64 * 8, *s));
        let flags = self
            .flags
            .iter()
            .enumerate()
            .map(|(i, s)| (FLAGS_BASE + i as u64 * 8, *s));
        let other = self.other.iter().map(|(b, s)| (*b, *s));
        gpr.chain(flags)
            .chain(other)
            .filter_map(|(b, s)| s.get(8).map(|v| (b, v)))
    }

    /// Per-byte intersection with `other` (a CFG join).
    pub fn intersect(&self, other: &RegFile) -> RegFile {
        let mut out = RegFile::default();
        for (o, (a, b)) in out.gpr.iter_mut().zip(self.gpr.iter().zip(&other.gpr)) {
            *o = a.intersect(*b);
        }
        for (o, (a, b)) in out
            .flags
            .iter_mut()
            .zip(self.flags.iter().zip(&other.flags))
        {
            *o = a.intersect(*b);
        }
        for (b, s) in &self.other {
            if let Some(o) = other.other.get(b) {
                let j = s.intersect(*o);
                if !j.is_unknown() {
                    out.other.insert(*b, j);
                }
            }
        }
        out
    }
}

/// REGISTER space as [`RegFile`] holds it, kept as a list of the
/// registers with a known byte, sorted by base offset: for the flow
/// states, which are cloned, compared and joined at every block while
/// they hold few values (about one register at a join), where a clone
/// or a join of [`RegFile`] goes over every general-purpose register.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegList {
    regs: smallvec::SmallVec<[(u64, ByteConst); 4]>,
}

impl RegList {
    fn slot(&self, base: u64) -> ByteConst {
        for (b, v) in &self.regs {
            if *b >= base {
                return if *b == base { *v } else { ByteConst::UNKNOWN };
            }
        }
        ByteConst::UNKNOWN
    }

    /// The `size` bytes at `offset` ([`RegFile::read`]).
    pub fn read(&self, offset: u64, size: u32) -> ByteConst {
        match split(offset, size) {
            Some((base, pos)) => self.slot(base).bytes_at(pos, size),
            None => ByteConst::UNKNOWN,
        }
    }

    /// Write `size` bytes at `offset` ([`RegFile::write`]).
    pub fn write(&mut self, offset: u64, size: u32, v: ByteConst) {
        let Some((base, pos)) = split(offset, size) else {
            self.forget(offset, size);
            return;
        };
        // (the slot found once, set to the bytes merged in: removed when none is known)
        let k = self.regs.iter().position(|e| e.0 >= base).unwrap_or(self.regs.len());
        match self.regs.get_mut(k) {
            Some(e) if e.0 == base => {
                let next = e.1.merge(pos, size, v);
                if next.is_unknown() {
                    self.regs.remove(k);
                } else {
                    e.1 = next;
                }
            }
            // (no byte known before: known where `v` is, none when it knows none)
            _ if v.trunc(size).is_unknown() => {}
            _ => self.regs.insert(k, (base, ByteConst::UNKNOWN.merge(pos, size, v))),
        }
    }

    /// Forget the bytes `offset..offset + size` ([`RegFile::forget`]).
    pub fn forget(&mut self, offset: u64, size: u32) {
        let end = offset.saturating_add(u64::from(size.max(1)));
        let lo = offset & !7;
        for e in self.regs.iter_mut().filter(|e| e.0 >= lo && e.0 < end) {
            let b = e.0;
            let (from, to) = (offset.max(b), end.min(b + 8));
            e.1 = e.1.merge((from - b) as u32, (to - from) as u32, ByteConst::UNKNOWN);
        }
        self.regs.retain(|e| !e.1.is_unknown());
    }

    /// The full 8-byte value of the register at `base`, when known.
    pub fn get64(&self, base: u64) -> Option<u64> {
        self.slot(base).get(8)
    }

    /// Set the full 8-byte register at `base`.
    pub fn set64(&mut self, base: u64, v: u64) {
        self.write(base, 8, ByteConst::konst(v, 8));
    }

    pub fn clear(&mut self) {
        self.regs.clear();
    }

    /// Every register whose 8 bytes are all known, as `(base, value)`,
    /// by base.
    pub fn full_values(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.regs.iter().filter_map(|(b, s)| s.get(8).map(|v| (*b, v)))
    }

    /// Per-byte intersection with `other` (a CFG join).
    pub fn intersect(&self, other: &RegList) -> RegList {
        let mut out = RegList::default();
        let mut k = 0;
        for &(base, a) in &self.regs {
            while k < other.regs.len() && other.regs[k].0 < base {
                k += 1;
            }
            match other.regs.get(k) {
                Some(&(ob, b)) if ob == base => {
                    let j = a.intersect(b);
                    if !j.is_unknown() {
                        out.regs.push((base, j));
                    }
                }
                Some(_) => {}
                None => break,
            }
        }
        out
    }
}

/// Non-REGISTER storage (UNIQUE temporaries, stack slots, …): entries of
/// at most 8 bytes keyed by `(space, offset)` with their size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteMem<K: Ord + Copy> {
    /// `(key, offset, size, bytes)`, by `(key, offset)`; no entry is
    /// unknown.
    entries: Vec<(K, i64, u32, ByteConst)>,
}

impl<K: Ord + Copy> Default for ByteMem<K> {
    fn default() -> Self {
        Self { entries: Vec::new() }
    }
}

impl<K: Ord + Copy> ByteMem<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// The `size` bytes at `offset`: an entry starting there at least as
    /// wide gives its low bytes; anything else is unknown.
    pub fn read(&self, space: K, offset: i64, size: u32) -> ByteConst {
        if self.entries.is_empty() {
            return ByteConst::UNKNOWN;
        }
        match self.entries.binary_search_by(|e| (e.0, e.1).cmp(&(space, offset))) {
            Ok(k) if self.entries[k].2 >= size => self.entries[k].3.trunc(size),
            _ => ByteConst::UNKNOWN,
        }
    }

    /// Store `size` bytes at `offset`, forgetting every entry it
    /// overlaps.
    pub fn write(&mut self, space: K, offset: i64, size: u32, v: ByteConst) {
        let end = offset.saturating_add(i64::from(size.max(1)));
        let lo = offset.saturating_sub(8);
        if !self.entries.is_empty() {
            // (an entry is at most 8 bytes wide: one overlapping the
            // write starts after `offset - 8`)
            let from = self.entries.partition_point(|e| (e.0, e.1) < (space, lo));
            let to = self.entries.partition_point(|e| (e.0, e.1) < (space, end));
            if from < to {
                let mut w = from;
                for r in from..to {
                    let (o, sz) = (self.entries[r].1, self.entries[r].2);
                    if o.saturating_add(i64::from(sz)) <= offset {
                        self.entries.swap(w, r);
                        w += 1;
                    }
                }
                self.entries.drain(w..to);
            }
        }
        if size <= 8 && !v.trunc(size).is_unknown() {
            let e = (space, offset, size, v.trunc(size));
            match self.entries.binary_search_by(|e| (e.0, e.1).cmp(&(space, offset))) {
                Ok(k) => self.entries[k] = e,
                Err(k) => self.entries.insert(k, e),
            }
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Entries equal in both (a CFG join).
    pub fn intersect(&self, other: &Self) -> Self {
        let mut entries = Vec::new();
        let mut k = 0;
        for &(space, off, sz, v) in &self.entries {
            while k < other.entries.len() && (other.entries[k].0, other.entries[k].1) < (space, off) {
                k += 1;
            }
            if let Some(&(os, oo, osz, ov)) = other.entries.get(k)
                && (os, oo) == (space, off)
                && osz == sz
            {
                let j = v.intersect(ov);
                if !j.is_unknown() {
                    entries.push((space, off, sz, j));
                }
            }
        }
        Self { entries }
    }
}

/// An instruction the lifter left opaque (`__unmodeled_insn()`, `int3`,
/// e.g. `rep stosq`): it may write any register (and memory), so a
/// tracker forgets everything it knows about registers.
pub fn is_unmodeled(op: &PcodeOp) -> bool {
    use reargo_core::pcode::intrinsic;
    op.opcode == OpCode::CallOther
        && op.inputs.first().is_some_and(|t| {
            t.space == SpaceId::CONST
                && t.offset < intrinsic::BASE
                && t.offset != intrinsic::NORETURN
        })
}

/// `out = SUBPIECE(in, k)` where `out` is the bytes of `in` at byte `k`
/// of the same register: a view refresh, a no-op for byte-precise
/// register state (`esi = SUBPIECE(rsi, 0)` after `mov rsi, …`).
pub fn is_view_refresh(op: &PcodeOp) -> bool {
    if op.opcode != OpCode::Subpiece {
        return false;
    }
    // (the inputs read once, the conditions combined without branches)
    let (Some(out), [src, k, ..]) = (op.output.as_ref(), op.inputs.as_slice()) else {
        return false;
    };
    (out.space == SpaceId::REGISTER)
        & (src.space == SpaceId::REGISTER)
        & (k.space == SpaceId::CONST)
        & (out.offset == src.offset.wrapping_add(k.offset))
        & (k.offset.saturating_add(u64::from(out.size)) <= u64::from(src.size))
}

/// Evaluate `op`'s output over byte-partial values, `read` giving each
/// input (already `size` bytes wide). `None` when the op is not modelled
/// or its output is wider than 8 bytes: the output is then unknown.
///
/// Byte moves (COPY, INT_ZEXT, INT_SEXT, SUBPIECE, PIECE) keep exactly
/// the bytes they can; arithmetic needs fully known inputs, except
/// `x ^ x` / `x - x`, which are 0.
pub fn eval(op: &PcodeOp, read: impl Fn(&VarnodeData) -> ByteConst) -> Option<ByteConst> {
    let out = op.output.as_ref()?;
    if out.size == 0 || out.size > 8 {
        return None;
    }
    let osz = out.size;
    let input = |i: usize| op.inputs.get(i);
    /// Input `i` of `op` through `read` (inlined: a call per input cost more than the read).
    #[inline(always)]
    fn value(op: &PcodeOp, i: usize, read: &impl Fn(&VarnodeData) -> ByteConst) -> Option<ByteConst> {
        let vn = op.inputs.get(i)?;
        if vn.size == 0 || vn.size > 8 {
            return None;
        }
        Some(read(vn).trunc(vn.size))
    }
    let val = |i: usize| value(op, i, &read);
    let full = |i: usize| -> Option<u64> { val(i)?.get(input(i)?.size) };
    let r = match op.opcode {
        OpCode::Copy => val(0)?,
        OpCode::IntZExt => {
            let isz = input(0)?.size;
            let v = val(0)?;
            // the bytes above the input are known zero
            ByteConst::new(v.value, v.known | (byte_mask(8) & !byte_mask(isz)))
        }
        OpCode::IntSExt => {
            let isz = input(0)?.size;
            let v = val(0)?;
            match v.bytes_at(isz - 1, 1).get(1) {
                Some(top) => {
                    let fill: u64 = if top & 0x80 != 0 { !bit_mask(isz) } else { 0 };
                    ByteConst::new(v.value | fill, v.known | (byte_mask(8) & !byte_mask(isz)))
                }
                None => v,
            }
        }
        OpCode::Subpiece => {
            let k = input(1).filter(|k| k.space == SpaceId::CONST)?.offset;
            let k = u32::try_from(k).ok()?;
            val(0)?.bytes_at(k, osz)
        }
        OpCode::Piece => {
            let lo_sz = input(1)?.size;
            if lo_sz + input(0)?.size > 8 {
                return None;
            }
            let (hi, lo) = (val(0)?, val(1)?);
            lo.trunc(lo_sz).merge(lo_sz, 8 - lo_sz, hi)
        }
        OpCode::IntXor | OpCode::IntSub if input(0).is_some() && input(0) == input(1) => {
            ByteConst::konst(0, 8)
        }
        OpCode::IntAdd
        | OpCode::IntSub
        | OpCode::IntAnd
        | OpCode::IntOr
        | OpCode::IntXor
        | OpCode::IntMult => {
            let (a, b) = (full(0)?, full(1)?);
            ByteConst::konst(
                match op.opcode {
                    OpCode::IntAdd => a.wrapping_add(b),
                    OpCode::IntSub => a.wrapping_sub(b),
                    OpCode::IntAnd => a & b,
                    OpCode::IntOr => a | b,
                    OpCode::IntXor => a ^ b,
                    _ => a.wrapping_mul(b),
                },
                8,
            )
        }
        OpCode::IntLeft | OpCode::IntRight => {
            let (a, n) = (full(0)?, full(1)?);
            let v = if n >= u64::from(input(0)?.size * 8) {
                0
            } else if op.opcode == OpCode::IntLeft {
                a << n
            } else {
                a >> n
            };
            ByteConst::konst(v, 8)
        }
        OpCode::Int2Comp => ByteConst::konst(full(0)?.wrapping_neg(), 8),
        OpCode::IntNegate => ByteConst::konst(!full(0)?, 8),
        _ => return None,
    };
    Some(r.trunc(osz))
}

/// P-code sequences as the x86 lifter emits them, for the trackers'
/// tests.
#[cfg(test)]
pub(crate) mod testseq {
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};

    pub fn reg(off: u64, size: u32) -> VarnodeData {
        VarnodeData::new(SpaceId::REGISTER, off, size)
    }
    pub fn k(v: u64, size: u32) -> VarnodeData {
        VarnodeData::new(SpaceId::CONST, v, size)
    }
    pub fn uniq(off: u64, size: u32) -> VarnodeData {
        VarnodeData::new(SpaceId::UNIQUE, off, size)
    }
    pub fn op(opcode: OpCode, output: Option<VarnodeData>, inputs: &[VarnodeData]) -> PcodeOp {
        let mut o = PcodeOp::new(opcode, SeqNum::new(Address::new(SpaceId::RAM, 0x1000), 0));
        o.inputs = inputs.iter().copied().collect();
        o.output = output;
        o
    }

    /// The view refreshes after a write of `size` bytes to the GPR at
    /// `off` (`zero_extend_gpr32_writes` in the x86 lifter).
    pub fn views(off: u64, size: u32) -> Vec<PcodeOp> {
        let sub = |sz: u32, from: u32| {
            op(
                OpCode::Subpiece,
                Some(reg(off, sz)),
                &[reg(off, from), k(0, 4)],
            )
        };
        match size {
            8 => vec![sub(4, 8), sub(2, 8), sub(1, 8)],
            4 => vec![
                op(OpCode::IntZExt, Some(reg(off, 8)), &[reg(off, 4)]),
                sub(2, 4),
                sub(1, 4),
            ],
            n => {
                let hi = uniq(0x7e00, 8 - n);
                vec![
                    op(
                        OpCode::Subpiece,
                        Some(hi),
                        &[reg(off, 8), k(u64::from(n), 4)],
                    ),
                    op(OpCode::Piece, Some(reg(off, 8)), &[hi, reg(off, n)]),
                    sub(4, 8),
                    sub(if n == 2 { 1 } else { 2 }, 8),
                ]
            }
        }
    }

    /// `op` followed by the view refreshes of its GPR output.
    pub fn with_views(o: PcodeOp) -> Vec<PcodeOp> {
        let out = o.output.expect("output");
        let mut v = vec![o];
        v.extend(views(out.offset, out.size));
        v
    }

    /// `mov esi, 0x2a`
    pub fn mov_esi_imm32() -> Vec<PcodeOp> {
        with_views(op(OpCode::Copy, Some(reg(0x30, 4)), &[k(0x2a, 4)]))
    }

    /// `lea rax, [0x402004]; mov rdi, rax`
    pub fn lea_rax_mov_rdi() -> Vec<PcodeOp> {
        let mut v = with_views(op(OpCode::Copy, Some(reg(0, 8)), &[k(0x402004, 8)]));
        v.extend(with_views(op(
            OpCode::Copy,
            Some(reg(0x38, 8)),
            &[reg(0, 8)],
        )));
        v
    }

    /// `mov rax, 0x7fff12345678; mov al, 5` (rax = 0x7fff12345605)
    pub fn mov_rax_then_al() -> Vec<PcodeOp> {
        let mut v = with_views(op(OpCode::Copy, Some(reg(0, 8)), &[k(0x7fff_1234_5678, 8)]));
        v.extend(with_views(op(OpCode::Copy, Some(reg(0, 1)), &[k(5, 1)])));
        v
    }

    /// `mov eax, 0x1234; mov ah, 7; movzx ecx, ah` (rax = 0x0734, rcx = 7)
    pub fn ah_write_read() -> Vec<PcodeOp> {
        let mut v = with_views(op(OpCode::Copy, Some(reg(0, 4)), &[k(0x1234, 4)]));
        let hi = uniq(0x7e10, 6);
        v.extend([
            op(OpCode::Copy, Some(reg(1, 1)), &[k(7, 1)]),
            op(OpCode::Piece, Some(reg(0, 2)), &[reg(1, 1), reg(0, 1)]),
            op(OpCode::Subpiece, Some(hi), &[reg(0, 8), k(2, 4)]),
            op(OpCode::Piece, Some(reg(0, 8)), &[hi, reg(0, 2)]),
            op(OpCode::Subpiece, Some(reg(0, 4)), &[reg(0, 8), k(0, 4)]),
            op(OpCode::Subpiece, Some(reg(1, 1)), &[reg(0, 8), k(1, 4)]),
        ]);
        v.extend(with_views(op(
            OpCode::IntZExt,
            Some(reg(0x08, 4)),
            &[reg(1, 1)],
        )));
        v
    }

    /// `mov dl, 0x80; movsx edi, dl; movzx esi, dl; movsxd r8, edi`
    /// (rdi = 0xffffff80, rsi = 0x80, r8 = 0xffffffffffffff80; rdx unknown)
    pub fn movsx_movzx() -> Vec<PcodeOp> {
        let mut v = with_views(op(OpCode::Copy, Some(reg(0x10, 1)), &[k(0x80, 1)]));
        v.extend(with_views(op(
            OpCode::IntSExt,
            Some(reg(0x38, 4)),
            &[reg(0x10, 1)],
        )));
        v.extend(with_views(op(
            OpCode::IntZExt,
            Some(reg(0x30, 4)),
            &[reg(0x10, 1)],
        )));
        v.extend(with_views(op(
            OpCode::IntSExt,
            Some(reg(0x80, 8)),
            &[reg(0x38, 4)],
        )));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Address;

    /// [`ByteMem`] as it was, on a `BTreeMap`: the reference for
    /// [`list_storage_matches_maps`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OldByteMem<K: Ord + Copy> {
        map: BTreeMap<(K, i64), (u32, ByteConst)>,
    }

    impl<K: Ord + Copy> Default for OldByteMem<K> {
        fn default() -> Self {
            Self {
                map: BTreeMap::new(),
            }
        }
    }

    impl<K: Ord + Copy> OldByteMem<K> {
        pub fn new() -> Self {
            Self::default()
        }

        /// The `size` bytes at `offset`: an entry starting there at least as
        /// wide gives its low bytes; anything else is unknown.
        pub fn read(&self, space: K, offset: i64, size: u32) -> ByteConst {
            match self.map.get(&(space, offset)) {
                Some(&(sz, v)) if sz >= size => v.trunc(size),
                _ => ByteConst::UNKNOWN,
            }
        }

        /// Store `size` bytes at `offset`, forgetting every entry it
        /// overlaps.
        pub fn write(&mut self, space: K, offset: i64, size: u32, v: ByteConst) {
            let end = offset.saturating_add(i64::from(size.max(1)));
            let lo = offset.saturating_sub(8);
            let overlapping: smallvec::SmallVec<[(K, i64); 4]> = self
                .map
                .range((space, lo)..(space, end))
                .filter(|((_, o), (sz, _))| o.saturating_add(i64::from(*sz)) > offset)
                .map(|(k, _)| *k)
                .collect();
            for k in overlapping {
                self.map.remove(&k);
            }
            if size <= 8 && !v.trunc(size).is_unknown() {
                self.map.insert((space, offset), (size, v.trunc(size)));
            }
        }

        pub fn clear(&mut self) {
            self.map.clear();
        }

        /// Entries equal in both (a CFG join).
        pub fn intersect(&self, other: &Self) -> Self {
            let mut map = BTreeMap::new();
            for (k, (sz, v)) in &self.map {
                if let Some((osz, ov)) = other.map.get(k)
                    && osz == sz
                {
                    let j = v.intersect(*ov);
                    if !j.is_unknown() {
                        map.insert(*k, (*sz, j));
                    }
                }
            }
            Self { map }
        }
    }

    /// [`RegList`] behaves exactly as [`RegFile`] and [`ByteMem`] as
    /// [`OldByteMem`] on random writes, forgets, clears and joins.
    #[test]
    fn list_storage_matches_maps() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        const BASES: [u64; 10] = [0x0, 0x8, 0x38, 0xb8, 0xc0, 0x200, 0x218, 0x220, 0x1200, 0x1208];
        const SIZES: [u32; 7] = [0, 1, 2, 4, 8, 8, 16];
        let all_bases: Vec<u64> = (0..0x1220u64).step_by(8).collect();
        let (mut joins, mut full) = (0, 0);
        for _ in 0..200 {
            let mut pool: Vec<(RegFile, RegList, OldByteMem<u8>, ByteMem<u8>)> =
                vec![(RegFile::new(), RegList::default(), OldByteMem::new(), ByteMem::new())];
            for _ in 0..150 {
                let i = (next() as usize) % pool.len();
                let off = BASES[(next() % 10) as usize] + if next().is_multiple_of(3) { next() % 8 } else { 0 };
                let size = SIZES[(next() % 7) as usize];
                let v = ByteConst::new(next() % 4, next() as u8);
                match next() % 10 {
                    0 if pool.len() > 1 => {
                        let j = (next() as usize) % pool.len();
                        let n = (
                            pool[i].0.intersect(&pool[j].0),
                            pool[i].1.intersect(&pool[j].1),
                            pool[i].2.intersect(&pool[j].2),
                            pool[i].3.intersect(&pool[j].3),
                        );
                        joins += 1;
                        pool.push(n);
                    }
                    1 => {
                        pool[i].0.forget(off, size);
                        pool[i].1.forget(off, size);
                    }
                    2 if next().is_multiple_of(4) => {
                        pool[i].0.clear();
                        pool[i].1.clear();
                        pool[i].2.clear();
                        pool[i].3.clear();
                    }
                    3 => {
                        let c = pool[i].clone();
                        pool.push(c);
                    }
                    _ => {
                        pool[i].0.write(off, size, v);
                        pool[i].1.write(off, size, v);
                        let (sp, o) = ((next() % 2) as u8, (next() % 40) as i64 - 8);
                        pool[i].2.write(sp, o, size, v);
                        pool[i].3.write(sp, o, size, v);
                    }
                }
                for (f, l, om, m) in &pool {
                    for &b in &all_bases {
                        assert_eq!(f.slot(b), l.slot(b), "base {b:#x}");
                    }
                    let mut fv: Vec<_> = f.full_values().collect();
                    fv.sort_unstable();
                    assert_eq!(fv, l.full_values().collect::<Vec<_>>());
                    full += fv.len();
                    let olds: Vec<_> = om.map.iter().map(|(k, (sz, v))| (k.0, k.1, *sz, *v)).collect();
                    assert_eq!(olds, m.entries);
                    for sp in 0..2u8 {
                        for o in -8..32 {
                            for sz in [1, 2, 4, 8] {
                                assert_eq!(om.read(sp, o, sz), m.read(sp, o, sz));
                            }
                        }
                    }
                }
                let (a, b) = ((next() as usize) % pool.len(), (next() as usize) % pool.len());
                assert_eq!(pool[a].0 == pool[b].0, pool[a].1 == pool[b].1);
                assert_eq!(pool[a].2 == pool[b].2, pool[a].3 == pool[b].3);
                if pool.len() > 10 {
                    pool.remove((next() as usize) % pool.len());
                }
            }
        }
        assert!(joins > 1000 && full > 1000, "{joins} {full}");
    }

    #[test]
    fn nonzero_bytes_matches_per_byte() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..100_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            // (bytes zero, 0x80, 0x7f, 0xff, 0x01 or random, by the seed)
            let x = (0..8).fold(0u64, |x, i| {
                let pick = (seed >> (i * 3)) & 7;
                let b = match pick {
                    0..=2 => 0,
                    3 => 0x80,
                    4 => 0x7f,
                    5 => 0xff,
                    6 => 0x01,
                    _ => (seed >> (24 + i * 4)) & 0xff,
                };
                x | (b << (i * 8))
            });
            let want = (0..8).filter(|i| (x >> (i * 8)) & 0xff != 0).fold(0u8, |m, i| m | (1 << i));
            assert_eq!(nonzero_bytes(x), want, "{x:#x}");
        }
    }
    use reargo_core::pcode::SeqNum;

    fn reg(off: u64, size: u32) -> VarnodeData {
        VarnodeData::new(SpaceId::REGISTER, off, size)
    }
    fn k(v: u64, size: u32) -> VarnodeData {
        VarnodeData::new(SpaceId::CONST, v, size)
    }
    fn op(opcode: OpCode, out: VarnodeData, inputs: &[VarnodeData]) -> PcodeOp {
        let mut o = PcodeOp::new(opcode, SeqNum::new(Address::new(SpaceId::RAM, 0), 0));
        o.inputs = inputs.iter().copied().collect();
        o.output = Some(out);
        o
    }
    fn run(regs: &mut RegFile, ops: &[PcodeOp]) {
        for o in ops {
            if is_view_refresh(o) {
                continue;
            }
            let out = o.output.unwrap();
            let v = eval(o, |vn| match vn.space {
                SpaceId::CONST => ByteConst::konst(vn.offset, vn.size),
                SpaceId::REGISTER => regs.read(vn.offset, vn.size),
                _ => ByteConst::UNKNOWN,
            })
            .unwrap_or(ByteConst::UNKNOWN);
            regs.write(out.offset, out.size, v);
        }
    }

    #[test]
    fn mov_esi_imm32_mirrors_keep_value() {
        let mut r = RegFile::new();
        run(
            &mut r,
            &[
                op(OpCode::Copy, reg(0x30, 4), &[k(0x2a, 4)]),
                op(OpCode::IntZExt, reg(0x30, 8), &[reg(0x30, 4)]),
                op(OpCode::Subpiece, reg(0x30, 2), &[reg(0x30, 4), k(0, 4)]),
                op(OpCode::Subpiece, reg(0x30, 1), &[reg(0x30, 4), k(0, 4)]),
            ],
        );
        assert_eq!(r.get64(0x30), Some(0x2a));
    }

    #[test]
    fn mov_al_merges_into_known_rax() {
        let mut r = RegFile::new();
        r.set64(0, 0x1122_3344_5566_7788);
        // mov al, 5: al = 5; hi = SUBPIECE(rax, 1); rax = PIECE(hi, al); views
        let hi = VarnodeData::new(SpaceId::UNIQUE, 0x7e00, 7);
        let mut regs_and_tmp = |ops: &[PcodeOp]| {
            let mut tmp: ByteMem<SpaceId> = ByteMem::new();
            for o in ops {
                if is_view_refresh(o) {
                    continue;
                }
                let out = o.output.unwrap();
                let v = eval(o, |vn| match vn.space {
                    SpaceId::CONST => ByteConst::konst(vn.offset, vn.size),
                    SpaceId::REGISTER => r.read(vn.offset, vn.size),
                    s => tmp.read(s, vn.offset as i64, vn.size),
                })
                .unwrap_or(ByteConst::UNKNOWN);
                if out.space == SpaceId::REGISTER {
                    r.write(out.offset, out.size, v);
                } else {
                    tmp.write(out.space, out.offset as i64, out.size, v);
                }
            }
        };
        regs_and_tmp(&[
            op(OpCode::Copy, reg(0, 1), &[k(5, 1)]),
            op(OpCode::Subpiece, hi, &[reg(0, 8), k(1, 4)]),
            op(OpCode::Piece, reg(0, 8), &[hi, reg(0, 1)]),
            op(OpCode::Subpiece, reg(0, 4), &[reg(0, 8), k(0, 4)]),
            op(OpCode::Subpiece, reg(0, 2), &[reg(0, 8), k(0, 4)]),
        ]);
        assert_eq!(r.get64(0), Some(0x1122_3344_5566_7705));
    }

    #[test]
    fn ah_is_byte_one() {
        let mut r = RegFile::new();
        r.set64(0, 0x1234);
        assert_eq!(r.read(1, 1).get(1), Some(0x12));
        r.write(1, 1, ByteConst::konst(0xab, 1));
        assert_eq!(r.get64(0), Some(0xab34));
        r.write(1, 1, ByteConst::UNKNOWN);
        assert_eq!(r.get64(0), None);
        assert_eq!(r.read(0, 1).get(1), Some(0x34));
    }

    #[test]
    fn sext_and_zext() {
        let mut r = RegFile::new();
        r.write(0x08, 1, ByteConst::konst(0xf0, 1)); // cl = 0xf0, rest unknown
        run(
            &mut r,
            &[
                op(OpCode::IntSExt, reg(0x38, 4), &[reg(0x08, 1)]), // movsx edi, cl
                op(OpCode::IntZExt, reg(0x38, 8), &[reg(0x38, 4)]),
                op(OpCode::IntZExt, reg(0x30, 4), &[reg(0x08, 1)]), // movzx esi, cl
                op(OpCode::IntZExt, reg(0x30, 8), &[reg(0x30, 4)]),
            ],
        );
        assert_eq!(r.get64(0x38), Some(0xffff_fff0));
        assert_eq!(r.get64(0x30), Some(0xf0));
    }

    #[test]
    fn unknown_low_bytes_make_full_unknown() {
        let mut r = RegFile::new();
        r.set64(0x38, 0x402004);
        r.write(0x38, 4, ByteConst::UNKNOWN);
        assert_eq!(r.get64(0x38), None);
        assert_eq!(r.read(0x3c, 4).get(4), Some(0));
    }

    #[test]
    fn wide_write_forgets() {
        let mut r = RegFile::new();
        r.set64(0x1200, 1);
        r.set64(0x1208, 2);
        r.set64(0x1210, 3);
        r.write(0x1200, 16, ByteConst::konst(9, 8));
        assert_eq!(r.get64(0x1200), None);
        assert_eq!(r.get64(0x1208), None);
        assert_eq!(r.get64(0x1210), Some(3));
    }

    #[test]
    fn mem_overlap_forgets() {
        let mut m: ByteMem<SpaceId> = ByteMem::new();
        m.write(
            SpaceId::UNIQUE,
            0x100,
            8,
            ByteConst::konst(0x1122334455667788, 8),
        );
        assert_eq!(m.read(SpaceId::UNIQUE, 0x100, 4).get(4), Some(0x55667788));
        m.write(SpaceId::UNIQUE, 0x104, 1, ByteConst::konst(1, 1));
        assert_eq!(m.read(SpaceId::UNIQUE, 0x100, 8).get(8), None);
        assert_eq!(m.read(SpaceId::UNIQUE, 0x104, 1).get(1), Some(1));
    }

    #[test]
    fn bits_of_spreads_bytes() {
        for k in 0..=255u8 {
            let slow = (0..8)
                .filter(|i| k & (1 << i) != 0)
                .fold(0u64, |m, i| m | (0xffu64 << (i * 8)));
            assert_eq!(bits_of(k), slow, "{k:#x}");
        }
    }

    #[test]
    fn intersect_bytes() {
        let a = ByteConst::konst(0x1234, 8);
        let b = ByteConst::konst(0x5634, 8);
        let j = a.intersect(b);
        assert_eq!(j.get(1), Some(0x34));
        assert_eq!(j.get(2), None);
        assert_eq!(j.bytes_at(2, 6).get(6), Some(0));
    }
}
