//! x86 integer instructions whose flags depend on the shift count, a carry chain or the full
//! product, checked against the CPU by `tests/x86_vs_cpu.rs` (WS84).
//!
//! Flags follow the Intel SDM: a flag the SDM leaves *undefined* for an input is left as it
//! was (no write), a flag left *unaffected* is never written, and a flag that only changes for
//! a non-zero count (`shl r, cl` with `cl & 31 == 0` changes nothing) is written as
//! `SELECT(count != 0, new, old)` when the count is a register.

use super::*;

/// Temporaries of these lifts (above the offsets the rest of the lifter uses, and 0x10 apart
/// so a 16-byte product never overlaps the next one).
const TMP_BASE: u64 = 0x2000;

/// Emits p-code for one instruction.
struct Emit<'a> {
    ops: &'a mut Vec<PcodeOp>,
    seq: &'a mut u32,
    at: Address,
    next: u64,
}

impl<'a> Emit<'a> {
    fn new(ops: &'a mut Vec<PcodeOp>, seq: &'a mut u32, address: u64) -> Self {
        Emit { ops, seq, at: Address::new(RAM_SPACE, address), next: TMP_BASE }
    }

    fn put(&mut self, opcode: OpCode, output: Option<VarnodeData>, inputs: &[VarnodeData]) {
        self.ops.push(PcodeOp {
            opcode,
            seq: SeqNum::new(self.at, *self.seq),
            output,
            inputs: SmallVec::from_slice(inputs),
        });
        *self.seq += 1;
    }

    fn set(&mut self, opcode: OpCode, output: VarnodeData, inputs: &[VarnodeData]) {
        self.put(opcode, Some(output), inputs);
    }

    /// A fresh temporary holding `opcode(inputs)`.
    fn tmp(&mut self, opcode: OpCode, size: u32, inputs: &[VarnodeData]) -> VarnodeData {
        let out = unique(self.next, size);
        self.next += 0x10;
        self.set(opcode, out, inputs);
        out
    }

    /// `v` converted to `size` bytes (zero-extended or truncated; a constant is re-sized).
    fn resize(&mut self, v: VarnodeData, size: u32) -> VarnodeData {
        if v.size == size {
            v
        } else if v.space == CONST_SPACE {
            let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
            constant(v.offset & mask, size)
        } else if v.size < size {
            self.tmp(OpCode::IntZExt, size, &[v])
        } else {
            self.tmp(OpCode::Subpiece, size, &[v, constant(0, 4)])
        }
    }

    /// Bit `k` of `x` (any size) as a boolean.
    fn bit(&mut self, x: VarnodeData, k: VarnodeData) -> VarnodeData {
        let s = self.tmp(OpCode::IntRight, x.size, &[x, k]);
        let b = self.tmp(OpCode::IntAnd, x.size, &[s, constant(1, x.size)]);
        self.tmp(OpCode::IntNotEqual, 1, &[b, constant(0, x.size)])
    }

    /// The sign bit of `x` as a boolean.
    fn msb(&mut self, x: VarnodeData) -> VarnodeData {
        self.tmp(OpCode::IntSLess, 1, &[x, constant(0, x.size)])
    }

    /// ZF and SF from a result.
    fn zf_sf(&mut self, r: VarnodeData) -> (VarnodeData, VarnodeData) {
        let z = self.tmp(OpCode::IntEqual, 1, &[r, constant(0, r.size)]);
        let s = self.msb(r);
        (z, s)
    }

    /// Write `flag = value`, or `flag = changed ? value : flag` when `changed` is given.
    fn flag(&mut self, off: u64, value: VarnodeData, changed: Option<VarnodeData>) {
        match changed {
            None => self.set(OpCode::Copy, reg(off, 1), &[value]),
            Some(c) => self.set(OpCode::Select, reg(off, 1), &[c, value, reg(off, 1)]),
        }
    }
}

/// Write flags with the op that computes them: `t = a == 0; …; ZF = t` becomes `ZF = a == 0`
/// (and later readers of `t` read ZF), when nothing in between reads the old flag. Keeps the
/// p-code in the shape the decompiler's flag folding expects (`ZF = IntEqual(…)`).
fn fold_flag_copies(ops: &mut Vec<PcodeOp>) {
    let is_flag = |v: &VarnodeData| v.space == REG_SPACE && (0x200..0x210).contains(&v.offset) && v.size == 1;
    let mut i = 0;
    while i < ops.len() {
        let op = &ops[i];
        let (Some(f), [t]) = (op.output, op.inputs.as_slice()) else {
            i += 1;
            continue;
        };
        let t = *t;
        if op.opcode != OpCode::Copy || !is_flag(&f) || t.space != UNIQUE_SPACE {
            i += 1;
            continue;
        }
        let Some(d) = ops[..i].iter().rposition(|o| o.output == Some(t)) else {
            i += 1;
            continue;
        };
        let reads_flag = ops[d + 1..i].iter().any(|o| o.inputs.contains(&f) || o.output == Some(f));
        let flag_rewritten = ops[i + 1..].iter().any(|o| o.output == Some(f) || o.output == Some(t));
        if reads_flag || flag_rewritten {
            i += 1;
            continue;
        }
        ops[d].output = Some(f);
        ops.remove(i);
        for o in ops[d + 1..].iter_mut() {
            for inp in o.inputs.iter_mut() {
                if *inp == t {
                    *inp = f;
                }
            }
        }
    }
    for (k, op) in ops.iter_mut().enumerate() {
        op.seq.order = k as u32;
    }
}

/// A shift/rotate count after the x86 mask (`& 31`, `& 63` for 64-bit operands).
enum Count {
    Const(u64),
    /// the masked count, in a temporary of the count register's size (`cl & 31`; a shift
    /// amount may be narrower than the value shifted)
    Var(VarnodeData),
}

impl Count {
    fn value(&self, size: u32) -> VarnodeData {
        match self {
            Count::Const(n) => constant(*n, size),
            Count::Var(v) => *v,
        }
    }
}

/// For a register count: `count != 0`, the condition under which the flags change.
fn changed(e: &mut Emit, n: &Count) -> Option<VarnodeData> {
    match n {
        Count::Const(_) => None,
        Count::Var(v) => Some(e.tmp(OpCode::IntNotEqual, 1, &[*v, constant(0, v.size)])),
    }
}

fn mask_count(e: &mut Emit, cnt: VarnodeData, size: u32) -> Count {
    let mask = if size == 8 { 63 } else { 31 };
    if cnt.space == CONST_SPACE {
        return Count::Const(cnt.offset & mask);
    }
    Count::Var(e.tmp(OpCode::IntAnd, cnt.size, &[cnt, constant(mask, cnt.size)]))
}

/// The positive condition code of a negated one (`ne` -> `e`), so a `cmovne` can select on
/// the flag itself with its arms swapped.
fn positive_cc(cc: iced_x86::ConditionCode) -> (iced_x86::ConditionCode, bool) {
    use iced_x86::ConditionCode as C;
    match cc {
        C::ne => (C::e, true),
        C::ae => (C::b, true),
        C::ns => (C::s, true),
        C::no => (C::o, true),
        C::a => (C::be, true),
        C::ge => (C::l, true),
        C::g => (C::le, true),
        C::np => (C::p, true),
        c => (c, false),
    }
}

impl X86Lifter {
    /// The instructions lifted here, or None.
    pub(super) fn lift_bits(
        &self,
        insn: &iced_x86::Instruction,
        address: u64,
    ) -> Option<Result<Vec<PcodeOp>, LiftError>> {
        use iced_x86::Mnemonic::*;
        let lifted = match insn.mnemonic() {
            Shl | Sal | Shr | Sar => self.lift_shift(insn, address),
            Rol | Ror => self.lift_rotate(insn, address),
            Shld | Shrd => self.lift_double_shift(insn, address),
            Adc | Sbb => self.lift_carry_chain(insn, address),
            Bt | Bts | Btr | Btc => self.lift_bit_test(insn, address),
            Mul | Imul => self.lift_multiply(insn, address),
            Cmpxchg => self.lift_cmpxchg(insn, address),
            Bsf | Bsr | Tzcnt | Lzcnt | Popcnt => self.lift_bit_count(insn, address),
            Bswap => self.lift_bswap(insn, address),
            Cmova | Cmovae | Cmovb | Cmovbe | Cmove | Cmovne | Cmovg | Cmovge | Cmovl | Cmovle
            | Cmovo | Cmovno | Cmovs | Cmovns => self.lift_cmov(insn, address),
            _ => return None,
        };
        Some(lifted.map(|mut ops| {
            fold_flag_copies(&mut ops);
            ops
        }))
    }

    /// `shl`/`shr`/`sar`: CF = the last bit shifted out, OF for a 1-bit shift, SF/ZF from the
    /// result; nothing changes for a zero count.
    fn lift_shift(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        use iced_x86::Mnemonic::*;
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let dst = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
        let cnt = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
        let (sz, w) = (dst.size, dst.size as u64 * 8);
        let mnem = insn.mnemonic();
        {
            let mut e = Emit::new(&mut ops, &mut sb, address);
            let n = mask_count(&mut e, cnt, sz);
            if let Count::Const(0) = n {
                return Ok(ops); // a zero count changes nothing (not even the flags)
            }
            let nv = n.value(sz);
            let nsz = nv.size;
            // CF, from the operand before the shift
            let cf = match mnem {
                Shr => {
                    let k = e.tmp(OpCode::IntSub, nsz, &[nv, constant(1, nsz)]);
                    e.bit(dst, k)
                }
                Sar => {
                    let k = e.tmp(OpCode::IntSub, nsz, &[nv, constant(1, nsz)]);
                    let s = e.tmp(OpCode::IntSRight, sz, &[dst, k]);
                    let b = e.tmp(OpCode::IntAnd, sz, &[s, constant(1, sz)]);
                    e.tmp(OpCode::IntNotEqual, 1, &[b, constant(0, sz)])
                }
                _ => {
                    let k = e.tmp(OpCode::IntSub, nsz, &[constant(w, nsz), nv]);
                    e.bit(dst, k)
                }
            };
            let old_msb = (mnem == Shr).then(|| e.msb(dst));
            let opcode = match mnem {
                Shr => OpCode::IntRight,
                Sar => OpCode::IntSRight,
                _ => OpCode::IntLeft,
            };
            e.set(opcode, dst, &[dst, nv]);
            let (zf, sf) = e.zf_sf(dst);
            // OF (defined for a 1-bit shift only): SHL = MSB(result) ^ CF, SHR = the old MSB,
            // SAR = 0
            let of = match mnem {
                Shr => old_msb,
                Sar => Some(constant(0, 1)),
                _ => Some(e.tmp(OpCode::BoolXor, 1, &[sf, cf])),
            };
            let ch = changed(&mut e, &n);
            e.flag(CF_OFFSET, cf, ch);
            e.flag(ZF_OFFSET, zf, ch);
            e.flag(SF_OFFSET, sf, ch);
            match n {
                Count::Const(1) | Count::Var(_) => e.flag(OF_OFFSET, of.unwrap(), ch),
                Count::Const(_) => {} // undefined: left as it was
            }
        }
        self.write_back_if_memory(insn, 0, dst, &mut ops, &mut sb, address)?;
        Ok(ops)
    }

    /// `rol`/`ror`: CF = the bit rotated into the end, OF for a 1-bit rotate; SF/ZF unaffected.
    fn lift_rotate(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let dst = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
        let cnt = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
        let (sz, w) = (dst.size, dst.size as u64 * 8);
        let is_ror = insn.mnemonic() == iced_x86::Mnemonic::Ror;
        {
            let mut e = Emit::new(&mut ops, &mut sb, address);
            let n = mask_count(&mut e, cnt, sz);
            if let Count::Const(0) = n {
                return Ok(ops);
            }
            // the rotation is by `count mod width` (`rol al, 8` rotates by 0 but sets CF)
            let r = match &n {
                Count::Const(k) => constant(k & (w - 1), sz),
                Count::Var(v) => e.tmp(OpCode::IntAnd, v.size, &[*v, constant(w - 1, v.size)]),
            };
            let comp = e.tmp(OpCode::IntSub, r.size, &[constant(w, r.size), r]);
            let (first, second) = if is_ror {
                (OpCode::IntRight, OpCode::IntLeft)
            } else {
                (OpCode::IntLeft, OpCode::IntRight)
            };
            let a = e.tmp(first, sz, &[dst, r]);
            let b = e.tmp(second, sz, &[dst, comp]);
            e.set(OpCode::IntOr, dst, &[a, b]);
            let msb = e.msb(dst);
            let (cf, of) = if is_ror {
                // CF = MSB(result), OF = MSB ^ MSB-1
                let next = e.bit(dst, constant(w - 2, sz));
                (msb, e.tmp(OpCode::BoolXor, 1, &[msb, next]))
            } else {
                // CF = LSB(result), OF = MSB ^ CF
                let lsb = e.bit(dst, constant(0, sz));
                (lsb, e.tmp(OpCode::BoolXor, 1, &[msb, lsb]))
            };
            let ch = changed(&mut e, &n);
            e.flag(CF_OFFSET, cf, ch);
            match n {
                Count::Const(1) | Count::Var(_) => e.flag(OF_OFFSET, of, ch),
                Count::Const(_) => {}
            }
        }
        self.write_back_if_memory(insn, 0, dst, &mut ops, &mut sb, address)?;
        Ok(ops)
    }

    /// `shld dst, src, n` = `(dst << n) | (src >> (w - n))`, `shrd` the mirror image. CF = the
    /// last bit shifted out of `dst`, OF for a 1-bit shift (sign change), SF/ZF from the result.
    fn lift_double_shift(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let dst = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
        let src = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
        let cnt = self.lift_operand(insn, 2, &mut ops, &mut sb, address)?;
        let (sz, w) = (dst.size, dst.size as u64 * 8);
        let left = insn.mnemonic() == iced_x86::Mnemonic::Shld;
        {
            let mut e = Emit::new(&mut ops, &mut sb, address);
            let n = mask_count(&mut e, cnt, sz);
            if let Count::Const(0) = n {
                return Ok(ops);
            }
            let nv = n.value(sz);
            let nsz = nv.size;
            let comp = e.tmp(OpCode::IntSub, nsz, &[constant(w, nsz), nv]);
            let cf = if left {
                e.bit(dst, comp)
            } else {
                let k = e.tmp(OpCode::IntSub, nsz, &[nv, constant(1, nsz)]);
                e.bit(dst, k)
            };
            let old_msb = e.msb(dst);
            let (first, second) = if left {
                (OpCode::IntLeft, OpCode::IntRight)
            } else {
                (OpCode::IntRight, OpCode::IntLeft)
            };
            let a = e.tmp(first, sz, &[dst, nv]);
            let b = e.tmp(second, sz, &[src, comp]);
            e.set(OpCode::IntOr, dst, &[a, b]);
            let (zf, sf) = e.zf_sf(dst);
            let of = e.tmp(OpCode::BoolXor, 1, &[sf, old_msb]);
            let ch = changed(&mut e, &n);
            e.flag(CF_OFFSET, cf, ch);
            e.flag(ZF_OFFSET, zf, ch);
            e.flag(SF_OFFSET, sf, ch);
            match n {
                Count::Const(1) | Count::Var(_) => e.flag(OF_OFFSET, of, ch),
                Count::Const(_) => {}
            }
        }
        self.write_back_if_memory(insn, 0, dst, &mut ops, &mut sb, address)?;
        Ok(ops)
    }

    /// `adc`/`sbb`: `dst = dst ± src ± CF` in two steps; CF = either step's carry, OF = the
    /// steps' signed overflows xor-ed (both can not overflow the same way), SF/ZF from the
    /// result.
    fn lift_carry_chain(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let (dst, src) = self.lift_two_operands(insn, &mut ops, &mut sb, address)?;
        let sbb = insn.mnemonic() == iced_x86::Mnemonic::Sbb;
        let sz = dst.size;
        let (arith, carry, overflow) = if sbb {
            (OpCode::IntSub, OpCode::IntLess, OpCode::IntSBorrow)
        } else {
            (OpCode::IntAdd, OpCode::IntCarry, OpCode::IntSCarry)
        };
        {
            let mut e = Emit::new(&mut ops, &mut sb, address);
            let cf_in = e.tmp(OpCode::IntZExt, sz, &[reg(CF_OFFSET, 1)]);
            let c1 = e.tmp(carry, 1, &[dst, src]);
            let o1 = e.tmp(overflow, 1, &[dst, src]);
            let step = e.tmp(arith, sz, &[dst, src]);
            let c2 = e.tmp(carry, 1, &[step, cf_in]);
            let o2 = e.tmp(overflow, 1, &[step, cf_in]);
            e.set(arith, dst, &[step, cf_in]);
            e.set(OpCode::BoolOr, reg(CF_OFFSET, 1), &[c1, c2]);
            e.set(OpCode::BoolXor, reg(OF_OFFSET, 1), &[o1, o2]);
            let (zf, sf) = e.zf_sf(dst);
            e.flag(ZF_OFFSET, zf, None);
            e.flag(SF_OFFSET, sf, None);
        }
        self.write_back_if_memory(insn, 0, dst, &mut ops, &mut sb, address)?;
        Ok(ops)
    }

    /// `bt`/`bts`/`btr`/`btc`: CF = the bit (offset mod the operand width), then set / clear /
    /// complement it. ZF is unaffected. (The bit-string form, a memory operand with a register
    /// offset beyond the operand, is not modelled.)
    fn lift_bit_test(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        use iced_x86::Mnemonic::*;
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let val = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
        let bit = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
        let sz = val.size;
        let mnem = insn.mnemonic();
        {
            let mut e = Emit::new(&mut ops, &mut sb, address);
            let b = e.resize(bit, sz);
            let k = if b.space == CONST_SPACE {
                constant(b.offset & (sz as u64 * 8 - 1), sz)
            } else {
                e.tmp(OpCode::IntAnd, sz, &[b, constant(sz as u64 * 8 - 1, sz)])
            };
            let cf = e.bit(val, k);
            e.flag(CF_OFFSET, cf, None);
            if mnem != Bt {
                let m = e.tmp(OpCode::IntLeft, sz, &[constant(1, sz), k]);
                match mnem {
                    Bts => e.set(OpCode::IntOr, val, &[val, m]),
                    Btr => {
                        let nm = e.tmp(OpCode::IntNegate, sz, &[m]);
                        e.set(OpCode::IntAnd, val, &[val, nm]);
                    }
                    _ => e.set(OpCode::IntXor, val, &[val, m]),
                }
            }
        }
        if mnem != Bt {
            self.write_back_if_memory(insn, 0, val, &mut ops, &mut sb, address)?;
        }
        Ok(ops)
    }

    /// `imul` (1/2/3 operands) and `mul`. CF = OF = "the product does not fit the low half"
    /// (unsigned: the high half is not 0; signed: it is not the sign of the low half). SF/ZF
    /// are undefined and left as they were.
    fn lift_multiply(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        use iced_x86::Register as R;
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let signed = insn.mnemonic() == iced_x86::Mnemonic::Imul;
        let ext = if signed { OpCode::IntSExt } else { OpCode::IntZExt };
        if insn.op_count() >= 2 {
            // dst = a * b, truncated (`imul ecx, ecx, 0x6C078965` = the MT19937 init step:
            // the immediate is a multiplicand and dst is not an input)
            let dst = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
            let (a, b) = if insn.op_count() == 3 {
                let a = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
                (a, self.lift_operand(insn, 2, &mut ops, &mut sb, address)?)
            } else {
                (dst, self.lift_operand(insn, 1, &mut ops, &mut sb, address)?)
            };
            let sz = dst.size;
            let mut e = Emit::new(&mut ops, &mut sb, address);
            let b = e.resize(b, sz);
            let wa = e.tmp(OpCode::IntSExt, sz * 2, &[a]);
            let wb = e.tmp(OpCode::IntSExt, sz * 2, &[b]);
            let wide = e.tmp(OpCode::IntMult, sz * 2, &[wa, wb]);
            let hi = e.tmp(OpCode::Subpiece, sz, &[wide, constant(sz as u64, 4)]);
            e.set(OpCode::IntMult, dst, &[a, b]);
            let sign = e.tmp(OpCode::IntSRight, sz, &[dst, constant(sz as u64 * 8 - 1, sz)]);
            let of = e.tmp(OpCode::IntNotEqual, 1, &[hi, sign]);
            e.flag(OF_OFFSET, of, None);
            e.flag(CF_OFFSET, of, None);
            return Ok(ops);
        }
        // one operand: {D:A} = A * src, the full product (the RNG multiply)
        let src = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
        let s = src.size;
        let mut e = Emit::new(&mut ops, &mut sb, address);
        if s == 1 {
            // AX = AL * src
            let al = reg(0, 1);
            let ax = reg(0, 2);
            let wa = e.tmp(ext, 2, &[al]);
            let ws = e.tmp(ext, 2, &[src]);
            e.set(OpCode::IntMult, ax, &[wa, ws]);
            let hi = e.tmp(OpCode::Subpiece, 1, &[ax, constant(1, 4)]);
            let lo = e.tmp(OpCode::Subpiece, 1, &[ax, constant(0, 4)]);
            let of = self.mul_overflow(&mut e, signed, hi, lo);
            e.flag(OF_OFFSET, of, None);
            e.flag(CF_OFFSET, of, None);
            return Ok(ops);
        }
        let (acc_r, hi_r) = match s {
            8 => (R::RAX, R::RDX),
            4 => (R::EAX, R::EDX),
            _ => (R::AX, R::DX),
        };
        let acc = iced_reg_to_varnode(acc_r).unwrap_or_else(|| constant(0, s));
        let hi = iced_reg_to_varnode(hi_r).unwrap_or_else(|| constant(0, s));
        let wa = e.tmp(ext, s * 2, &[acc]);
        let ws = e.tmp(ext, s * 2, &[src]);
        let prod = e.tmp(OpCode::IntMult, s * 2, &[wa, ws]);
        e.set(OpCode::Subpiece, acc, &[prod, constant(0, 4)]);
        e.set(OpCode::Subpiece, hi, &[prod, constant(s as u64, 4)]);
        let of = self.mul_overflow(&mut e, signed, hi, acc);
        e.flag(OF_OFFSET, of, None);
        e.flag(CF_OFFSET, of, None);
        Ok(ops)
    }

    /// Does the product with halves `hi:lo` not fit `lo`?
    fn mul_overflow(&self, e: &mut Emit, signed: bool, hi: VarnodeData, lo: VarnodeData) -> VarnodeData {
        let sz = lo.size;
        let expect = if signed {
            e.tmp(OpCode::IntSRight, sz, &[lo, constant(sz as u64 * 8 - 1, sz)])
        } else {
            constant(0, sz)
        };
        e.tmp(OpCode::IntNotEqual, 1, &[hi, expect])
    }

    /// `cmpxchg dst, src`: compare the accumulator with `dst` (all flags as `cmp`); equal:
    /// `dst = src`; else the accumulator gets `dst` (a memory `dst` is written back unchanged).
    fn lift_cmpxchg(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let old = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
        let src = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
        let sz = old.size;
        let acc = reg(0, sz);
        let newdst;
        {
            let mut e = Emit::new(&mut ops, &mut sb, address);
            let d = e.tmp(OpCode::IntSub, sz, &[acc, old]);
            e.set(OpCode::IntLess, reg(CF_OFFSET, 1), &[acc, old]);
            e.set(OpCode::IntSBorrow, reg(OF_OFFSET, 1), &[acc, old]);
            let (zf, sf) = e.zf_sf(d);
            e.flag(ZF_OFFSET, zf, None);
            e.flag(SF_OFFSET, sf, None);
            let zf = reg(ZF_OFFSET, 1);
            newdst = e.tmp(OpCode::Select, sz, &[zf, src, old]);
            // the accumulator is written only when not equal (`eax` then zero-extends into
            // rax; when equal rax keeps its upper half)
            if sz == 4 {
                let wide = e.tmp(OpCode::IntZExt, 8, &[old]);
                e.set(OpCode::Select, reg(0, 8), &[zf, reg(0, 8), wide]);
            } else {
                e.set(OpCode::Select, acc, &[zf, acc, old]);
            }
            if insn.op_kind(0) != iced_x86::OpKind::Memory {
                if sz == 4 {
                    // a 32-bit register is written (zero-extended) only when equal: the CPU
                    // keeps `rcx` whole when `cmpxchg ecx, edx` fails
                    let full = reg(old.offset, 8);
                    let wide = e.tmp(OpCode::IntZExt, 8, &[src]);
                    e.set(OpCode::Select, full, &[zf, wide, full]);
                } else {
                    e.set(OpCode::Copy, old, &[newdst]);
                }
            }
        }
        self.write_back_if_memory(insn, 0, newdst, &mut ops, &mut sb, address)?;
        Ok(ops)
    }

    /// `bsf`/`bsr` (named intrinsics; ZF = source is zero), `tzcnt` (intrinsic), `lzcnt`
    /// (LZCOUNT) with CF = source is zero and ZF = result is zero, `popcnt` (POPCOUNT) with
    /// ZF = source is zero and CF/OF/SF cleared.
    fn lift_bit_count(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        use iced_x86::Mnemonic::*;
        use reargo_core::pcode::intrinsic;
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let dst = self.lift_operand_no_load(insn, 0, &mut ops, &mut sb, address)?;
        let src = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
        let mut e = Emit::new(&mut ops, &mut sb, address);
        let zero = e.tmp(OpCode::IntEqual, 1, &[src, constant(0, src.size)]);
        match insn.mnemonic() {
            m @ (Bsf | Bsr | Tzcnt) => {
                let tag = match m {
                    Bsf => intrinsic::BSF,
                    Bsr => intrinsic::BSR,
                    _ => intrinsic::TZCNT,
                };
                e.set(OpCode::CallOther, dst, &[constant(tag, 8), src]);
                if m == Tzcnt {
                    e.flag(CF_OFFSET, zero, None);
                    let (zf, _) = e.zf_sf(dst);
                    e.flag(ZF_OFFSET, zf, None);
                } else {
                    e.flag(ZF_OFFSET, zero, None);
                }
            }
            Lzcnt => {
                e.set(OpCode::LzCount, dst, &[src]);
                e.flag(CF_OFFSET, zero, None);
                let (zf, _) = e.zf_sf(dst);
                e.flag(ZF_OFFSET, zf, None);
            }
            _ => {
                e.set(OpCode::PopCount, dst, &[src]);
                e.flag(ZF_OFFSET, zero, None);
                for f in [CF_OFFSET, OF_OFFSET, SF_OFFSET] {
                    e.flag(f, constant(0, 1), None);
                }
            }
        }
        Ok(ops)
    }

    /// `bswap r` (named intrinsic; no flags).
    fn lift_bswap(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let dst = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
        let mut e = Emit::new(&mut ops, &mut sb, address);
        e.set(OpCode::CallOther, dst, &[constant(reargo_core::pcode::intrinsic::BSWAP, 8), dst]);
        Ok(ops)
    }

    /// `cmovcc dst, src` = `SELECT(c, src, dst)`; a negated condition (`cmovne`) selects on the
    /// flag itself with the arms swapped (`ZF ? dst : src`). A 32-bit `dst` is written (and so
    /// zero-extended) even when the condition is false.
    fn lift_cmov(&self, insn: &iced_x86::Instruction, address: u64) -> Result<Vec<PcodeOp>, LiftError> {
        let mut ops = Vec::new();
        let mut sb = 0u32;
        let dst = self.lift_operand(insn, 0, &mut ops, &mut sb, address)?;
        let src = self.lift_operand(insn, 1, &mut ops, &mut sb, address)?;
        let (cc, negated) = positive_cc(insn.condition_code());
        let Some(c) = self.cc_condition(cc, &mut ops, &mut sb, address) else {
            // parity (PF is not modelled for integer ops): leave dst as it was
            return Ok(ops);
        };
        let mut e = Emit::new(&mut ops, &mut sb, address);
        let (t, f) = if negated { (dst, src) } else { (src, dst) };
        e.set(OpCode::Select, dst, &[c, t, f]);
        Ok(ops)
    }
}
