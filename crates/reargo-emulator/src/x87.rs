//! 80-bit extended floats (the x87 `long double`, WS89) for the size-10 FLOAT_* p-code the x86
//! lifter emits for x87 instructions.
//!
//! A value is the 10 bytes of the x87 register / `tbyte` memory format in the low 80 bits of a
//! `u128` (64-bit significand with its explicit integer bit, 15-bit exponent, sign).
//!
//! On x86-64 every operation runs the x87 instruction itself on the host CPU, with the control
//! word set to 0x37F (all exceptions masked, 64-bit precision, round to nearest; a conversion to
//! an integer takes the rounding it is given), so the results are bit-exact — NaN payloads,
//! denormals and the invalid encodings (unnormals, pseudo-NaNs) included. On other hosts the
//! value goes through an `f64` (an approximation: 11 bits of the significand and the exponent
//! range beyond `f64` are lost).

/// How two values compare (`fucomi`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    Less,
    Equal,
    Greater,
    Unordered,
}

/// The arithmetic operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bin {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Un {
    Neg,
    Abs,
    Sqrt,
}

const MASK80: u128 = (1u128 << 80) - 1;

fn bytes(v: u128) -> [u8; 16] {
    (v & MASK80).to_le_bytes()
}

#[cfg(target_arch = "x86_64")]
mod host {
    /// Run x87 instructions with the control word `cw` (exceptions masked: bits 0-5 set),
    /// restoring the caller's control word and clearing the exception flags they set. The
    /// instructions must leave the register stack empty.
    macro_rules! x87 {
        ($cw:expr, [$($ins:literal),* $(,)?], $($args:tt)*) => {{
            let cw: u16 = $cw | 0x3f;
            let mut saved: u16 = 0;
            // SAFETY: the instructions only touch the x87 state (all of it declared clobbered,
            // and the stack left empty), the local buffers the pointers point at, and the
            // control word, which is restored.
            unsafe {
                core::arch::asm!(
                    "fnstcw word ptr [{saved}]",
                    "fldcw word ptr [{cw}]",
                    $($ins,)*
                    "fnclex",
                    "fldcw word ptr [{saved}]",
                    saved = in(reg) &raw mut saved,
                    cw = in(reg) &raw const cw,
                    $($args)*
                    out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _,
                    out("st(4)") _, out("st(5)") _, out("st(6)") _, out("st(7)") _,
                    options(nostack),
                );
            }
        }};
    }

    /// 64-bit precision, round to nearest
    const CW: u16 = 0x37f;

    pub fn bin(op: super::Bin, a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        let mut o = [0u8; 16];
        let (a, b, out) = (a.as_ptr(), b.as_ptr(), o.as_mut_ptr());
        // (only the `st(0), st(i)` forms: their operand order is the same in every assembler)
        match op {
            super::Bin::Add => x87!(CW, ["fld tbyte ptr [{b}]", "fld tbyte ptr [{a}]", "fadd st(0), st(1)", "fstp tbyte ptr [{o}]", "fstp st(0)"], a = in(reg) a, b = in(reg) b, o = in(reg) out,),
            super::Bin::Sub => x87!(CW, ["fld tbyte ptr [{b}]", "fld tbyte ptr [{a}]", "fsub st(0), st(1)", "fstp tbyte ptr [{o}]", "fstp st(0)"], a = in(reg) a, b = in(reg) b, o = in(reg) out,),
            super::Bin::Mul => x87!(CW, ["fld tbyte ptr [{b}]", "fld tbyte ptr [{a}]", "fmul st(0), st(1)", "fstp tbyte ptr [{o}]", "fstp st(0)"], a = in(reg) a, b = in(reg) b, o = in(reg) out,),
            super::Bin::Div => x87!(CW, ["fld tbyte ptr [{b}]", "fld tbyte ptr [{a}]", "fdiv st(0), st(1)", "fstp tbyte ptr [{o}]", "fstp st(0)"], a = in(reg) a, b = in(reg) b, o = in(reg) out,),
        }
        o
    }

    pub fn un(op: super::Un, a: &[u8; 16]) -> [u8; 16] {
        let mut o = [0u8; 16];
        let (a, out) = (a.as_ptr(), o.as_mut_ptr());
        match op {
            super::Un::Neg => x87!(CW, ["fld tbyte ptr [{a}]", "fchs", "fstp tbyte ptr [{o}]"], a = in(reg) a, o = in(reg) out,),
            super::Un::Abs => x87!(CW, ["fld tbyte ptr [{a}]", "fabs", "fstp tbyte ptr [{o}]"], a = in(reg) a, o = in(reg) out,),
            super::Un::Sqrt => x87!(CW, ["fld tbyte ptr [{a}]", "fsqrt", "fstp tbyte ptr [{o}]"], a = in(reg) a, o = in(reg) out,),
        }
        o
    }

    pub fn cmp(a: &[u8; 16], b: &[u8; 16]) -> super::Cmp {
        let (cf, zf, pf): (u8, u8, u8);
        let (a, b) = (a.as_ptr(), b.as_ptr());
        x87!(CW, ["fld tbyte ptr [{b}]", "fld tbyte ptr [{a}]", "fucomip st, st(1)", "setb {cf}", "sete {zf}", "setp {pf}", "fstp st(0)"],
            a = in(reg) a, b = in(reg) b, cf = out(reg_byte) cf, zf = out(reg_byte) zf, pf = out(reg_byte) pf,);
        match (pf, zf, cf) {
            (1, _, _) => super::Cmp::Unordered,
            (_, 1, _) => super::Cmp::Equal,
            (_, _, 1) => super::Cmp::Less,
            _ => super::Cmp::Greater,
        }
    }

    pub fn from_float(bits: u64, size: u32) -> [u8; 16] {
        let mut o = [0u8; 16];
        let (i, out) = (&raw const bits, o.as_mut_ptr());
        if size == 4 {
            x87!(CW, ["fld dword ptr [{i}]", "fstp tbyte ptr [{o}]"], i = in(reg) i, o = in(reg) out,);
        } else {
            x87!(CW, ["fld qword ptr [{i}]", "fstp tbyte ptr [{o}]"], i = in(reg) i, o = in(reg) out,);
        }
        o
    }

    pub fn to_float(a: &[u8; 16], size: u32) -> u64 {
        let mut o = 0u64;
        let (a, out) = (a.as_ptr(), &raw mut o);
        if size == 4 {
            x87!(CW, ["fld tbyte ptr [{a}]", "fstp dword ptr [{o}]"], a = in(reg) a, o = in(reg) out,);
        } else {
            x87!(CW, ["fld tbyte ptr [{a}]", "fstp qword ptr [{o}]"], a = in(reg) a, o = in(reg) out,);
        }
        o
    }

    pub fn from_int(v: i64) -> [u8; 16] {
        let mut o = [0u8; 16];
        let (i, out) = (&raw const v, o.as_mut_ptr());
        x87!(CW, ["fild qword ptr [{i}]", "fstp tbyte ptr [{o}]"], i = in(reg) i, o = in(reg) out,);
        o
    }

    pub fn to_int(a: &[u8; 16], size: u32, rc: u8) -> u64 {
        let mut o = 0u64;
        let cw = (CW & !0xc00) | (u16::from(rc & 3) << 10);
        let (a, out) = (a.as_ptr(), &raw mut o);
        match size {
            2 => x87!(cw, ["fld tbyte ptr [{a}]", "fistp word ptr [{o}]"], a = in(reg) a, o = in(reg) out,),
            4 => x87!(cw, ["fld tbyte ptr [{a}]", "fistp dword ptr [{o}]"], a = in(reg) a, o = in(reg) out,),
            _ => x87!(cw, ["fld tbyte ptr [{a}]", "fistp qword ptr [{o}]"], a = in(reg) a, o = in(reg) out,),
        }
        o
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod host {
    //! The approximation through `f64` (see the module documentation).
    fn get(a: &[u8; 16]) -> f64 {
        let v = u128::from_le_bytes(*a);
        let (sign, exp, man) = ((v >> 79) & 1 == 1, ((v >> 64) & 0x7fff) as i32, v as u64);
        let x = if exp == 0x7fff {
            if man << 1 == 0 { f64::INFINITY } else { f64::NAN }
        } else {
            man as f64 * 2f64.powi(exp.max(1) - 16383 - 63)
        };
        if sign { -x } else { x }
    }
    fn put(x: f64) -> [u8; 16] {
        let sign = u128::from(x.is_sign_negative()) << 79;
        let v = if x.is_nan() {
            0x7fffu128 << 64 | 0xc000_0000_0000_0000
        } else if x.is_infinite() {
            0x7fffu128 << 64 | 0x8000_0000_0000_0000
        } else if x == 0.0 {
            0
        } else {
            let b = x.abs().to_bits();
            let (e, m) = ((b >> 52) as i32, b & ((1 << 52) - 1));
            let (e, m) = if e == 0 {
                let s = m.leading_zeros() - 11; // normalise a denormal
                (1 - s as i32, m << s)
            } else {
                (e, m | 1 << 52)
            };
            ((e - 1023 + 16383) as u128) << 64 | u128::from(m << 11)
        };
        (sign | v).to_le_bytes()
    }
    pub fn bin(op: super::Bin, a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        let (x, y) = (get(a), get(b));
        put(match op {
            super::Bin::Add => x + y,
            super::Bin::Sub => x - y,
            super::Bin::Mul => x * y,
            super::Bin::Div => x / y,
        })
    }
    pub fn un(op: super::Un, a: &[u8; 16]) -> [u8; 16] {
        let x = get(a);
        put(match op {
            super::Un::Neg => -x,
            super::Un::Abs => x.abs(),
            super::Un::Sqrt => x.sqrt(),
        })
    }
    pub fn cmp(a: &[u8; 16], b: &[u8; 16]) -> super::Cmp {
        match get(a).partial_cmp(&get(b)) {
            Some(std::cmp::Ordering::Less) => super::Cmp::Less,
            Some(std::cmp::Ordering::Equal) => super::Cmp::Equal,
            Some(std::cmp::Ordering::Greater) => super::Cmp::Greater,
            None => super::Cmp::Unordered,
        }
    }
    pub fn from_float(bits: u64, size: u32) -> [u8; 16] {
        put(if size == 4 { f64::from(f32::from_bits(bits as u32)) } else { f64::from_bits(bits) })
    }
    pub fn to_float(a: &[u8; 16], size: u32) -> u64 {
        let x = get(a);
        if size == 4 { u64::from((x as f32).to_bits()) } else { x.to_bits() }
    }
    pub fn from_int(v: i64) -> [u8; 16] {
        put(v as f64)
    }
    pub fn to_int(a: &[u8; 16], size: u32, rc: u8) -> u64 {
        let x = get(a);
        let r = match rc & 3 {
            0 => x.round_ties_even(),
            1 => x.floor(),
            2 => x.ceil(),
            _ => x.trunc(),
        };
        let bits = size * 8;
        let (lo, hi) = (-(2f64.powi(bits as i32 - 1)), 2f64.powi(bits as i32 - 1));
        let v = if r.is_nan() || r < lo || r >= hi { 1i64 << (bits - 1) } else { r as i64 };
        v as u64 & (u64::MAX >> (64 - bits))
    }
}

fn val(b: [u8; 16]) -> u128 {
    u128::from_le_bytes(b) & MASK80
}

/// `a op b`, rounded to nearest.
pub fn bin(op: Bin, a: u128, b: u128) -> u128 {
    val(host::bin(op, &bytes(a), &bytes(b)))
}

/// `-a`, `|a|`, `sqrt(a)`.
pub fn un(op: Un, a: u128) -> u128 {
    val(host::un(op, &bytes(a)))
}

/// How `a` compares to `b`.
pub fn cmp(a: u128, b: u128) -> Cmp {
    host::cmp(&bytes(a), &bytes(b))
}

/// The `float` (`size` 4) or `double` (8) with these bits, extended (exact).
pub fn from_float(bits: u64, size: u32) -> u128 {
    val(host::from_float(bits, size))
}

/// `a` as a `float` (`size` 4) or `double` (8), rounded to nearest.
pub fn to_float(a: u128, size: u32) -> u64 {
    host::to_float(&bytes(a), size)
}

/// A signed integer, extended (exact).
pub fn from_int(v: i64) -> u128 {
    val(host::from_int(v))
}

/// `fistp`: `a` as a signed integer of `size` bytes, rounded as the control word's rounding
/// control `rc` says (0 nearest, 1 down, 2 up, 3 toward zero); a NaN or a value out of range is
/// the "integer indefinite" (the lowest value).
pub fn to_int(a: u128, size: u32, rc: u8) -> u64 {
    let v = host::to_int(&bytes(a), size, rc);
    if size >= 8 { v } else { v & ((1u64 << (size * 8)) - 1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: u128 = 0x3fff_8000_0000_0000_0000;
    const TWO: u128 = 0x4000_8000_0000_0000_0000;
    const THREE: u128 = 0x4000_c000_0000_0000_0000;

    #[test]
    fn arithmetic_and_conversions() {
        assert_eq!(from_float(1.0f64.to_bits(), 8), ONE);
        assert_eq!(from_float(u64::from(2.0f32.to_bits()), 4), TWO);
        assert_eq!(from_int(3), THREE);
        assert_eq!(bin(Bin::Add, ONE, TWO), THREE);
        assert_eq!(bin(Bin::Sub, ONE, TWO), ONE | 1 << 79);
        assert_eq!(bin(Bin::Mul, TWO, THREE), from_int(6));
        assert_eq!(to_float(bin(Bin::Div, ONE, THREE), 8), (1.0f64 / 3.0).to_bits());
        assert_eq!(un(Un::Neg, ONE), ONE | 1 << 79);
        assert_eq!(cmp(ONE, TWO), Cmp::Less);
        assert_eq!(cmp(TWO, TWO), Cmp::Equal);
        assert_eq!(cmp(THREE, TWO), Cmp::Greater);
        let nan = from_float(f64::NAN.to_bits(), 8);
        assert_eq!(cmp(nan, ONE), Cmp::Unordered);
        // 2.5 → 2 (to even) / 2 (down) / 3 (up) / 2 (toward zero)
        let x = from_float(2.5f64.to_bits(), 8);
        assert_eq!([0, 1, 2, 3].map(|rc| to_int(x, 4, rc)), [2, 2, 3, 2]);
        assert_eq!(to_int(nan, 2, 0), 0x8000);
        assert_eq!(to_int(from_float(1e30f64.to_bits(), 8), 8, 3), 1 << 63);
    }

    /// The 64-bit significand: 1 + 2^-63 is exact (an `f64` would round it away).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn extended_precision() {
        let tiny = 0x3fc0_8000_0000_0000_0000u128; // 2^-63
        assert_eq!(bin(Bin::Add, ONE, tiny), ONE | 1);
    }
}
