//! The AArch64 instructions whose operands depend on their address, decoded without a
//! disassembler: the disassembler's and the lifter's work on them is the target arithmetic.
//!
//! [`is_pc_relative`] tells the words an AArch64 instruction reads the PC in (every other
//! encoding decodes the same at every address); [`PcRelative::decode`] decodes the branch and
//! address-forming ones (`B` / `BL`, `B.cond`, `CBZ` / `CBNZ`, `TBZ` / `TBNZ`, `ADR` / `ADRP`)
//! and [`PcRelative::text`] gives their text as Capstone prints it (the tests of the
//! disassembler and the lifter check both against Capstone).

/// Does the instruction `word` read the PC (its operands, text or lift depend on its
/// address)? The PC-relative encodings: `B` / `BL`, `CBZ` / `CBNZ`, `TBZ` / `TBNZ`, `B.cond`,
/// `ADR` / `ADRP` and the literal loads (`LDR` / `LDRSW` / `PRFM` / SIMD `LDR` `label`).
pub fn is_pc_relative(word: u32) -> bool {
    (word >> 26) & 0x1f == 0x05 // B, BL
        || (word >> 25) & 0x3e == 0x1a // CBZ/CBNZ (011010), TBZ/TBNZ (011011)
        || (word >> 24) & 0xfe == 0x54 // B.cond
        || (word >> 24) & 0x1f == 0x10 // ADR, ADRP
        || (word >> 24) & 0x3b == 0x18 // load literal
}

/// A decoded PC-relative branch or address-forming instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcRelative {
    /// `B` (`link`: `BL`) to `target`.
    Branch { link: bool, target: u64 },
    /// `B.cond` (`cond` the 4-bit condition field) to `target`.
    CondBranch { cond: u8, target: u64 },
    /// `CBZ` (`nonzero`: `CBNZ`) of register `rt` (`x`: the 64-bit view).
    CompareBranch { nonzero: bool, x: bool, rt: u8, target: u64 },
    /// `TBZ` (`nonzero`: `TBNZ`) of bit `bit` of register `rt` (`x`: the 64-bit view).
    TestBranch { nonzero: bool, x: bool, rt: u8, bit: u8, target: u64 },
    /// `ADR` (`page`: `ADRP`) of `target` into `rd`.
    Address { page: bool, rd: u8, target: u64 },
}

fn sext(value: u32, bits: u32) -> i64 {
    ((value as i64) << (64 - bits)) >> (64 - bits)
}

/// Capstone's condition names, by the 4-bit field.
const CONDS: [&str; 16] = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"];

impl PcRelative {
    /// The instruction `word` at `address`, when it is one of these.
    pub fn decode(word: u32, address: u64) -> Option<Self> {
        let rel = |offset: i64| address.wrapping_add(offset as u64);
        if (word >> 26) & 0x1f == 0x05 {
            return Some(Self::Branch { link: word >> 31 == 1, target: rel(sext(word & 0x03ff_ffff, 26) << 2) });
        }
        if word & 0xff00_0010 == 0x5400_0000 {
            return Some(Self::CondBranch { cond: (word & 0xf) as u8, target: rel(sext((word >> 5) & 0x7_ffff, 19) << 2) });
        }
        if word & 0x7e00_0000 == 0x3400_0000 {
            return Some(Self::CompareBranch {
                nonzero: (word >> 24) & 1 == 1,
                x: word >> 31 == 1,
                rt: (word & 0x1f) as u8,
                target: rel(sext((word >> 5) & 0x7_ffff, 19) << 2),
            });
        }
        if word & 0x7e00_0000 == 0x3600_0000 {
            return Some(Self::TestBranch {
                nonzero: (word >> 24) & 1 == 1,
                x: word >> 31 == 1,
                rt: (word & 0x1f) as u8,
                bit: (((word >> 31) << 5) | ((word >> 19) & 0x1f)) as u8,
                target: rel(sext((word >> 5) & 0x3fff, 14) << 2),
            });
        }
        if word & 0x1f00_0000 == 0x1000_0000 {
            let imm = sext((((word >> 5) & 0x7_ffff) << 2) | ((word >> 29) & 3), 21);
            let page = word >> 31 == 1;
            let target = if page { (address & !0xfff).wrapping_add((imm << 12) as u64) } else { rel(imm) };
            return Some(Self::Address { page, rd: (word & 0x1f) as u8, target });
        }
        None
    }

    /// The target (the address formed, for `ADR` / `ADRP`).
    pub fn target(&self) -> u64 {
        match *self {
            Self::Branch { target, .. }
            | Self::CondBranch { target, .. }
            | Self::CompareBranch { target, .. }
            | Self::TestBranch { target, .. }
            | Self::Address { target, .. } => target,
        }
    }

    /// The mnemonic and the operands, as Capstone prints them.
    pub fn text(&self) -> (String, String) {
        let reg = |x: bool, r: u8| match (x, r) {
            (true, 31) => "xzr".to_string(),
            (false, 31) => "wzr".to_string(),
            (true, r) => format!("x{r}"),
            (false, r) => format!("w{r}"),
        };
        let target = bang(self.target());
        match *self {
            Self::Branch { link, .. } => ((if link { "bl" } else { "b" }).to_string(), target),
            Self::CondBranch { cond, .. } => (format!("b.{}", CONDS[usize::from(cond)]), target),
            Self::CompareBranch { nonzero, x, rt, .. } => ((if nonzero { "cbnz" } else { "cbz" }).to_string(), format!("{}, {target}", reg(x, rt))),
            Self::TestBranch { nonzero, x, rt, bit, .. } => {
                ((if nonzero { "tbnz" } else { "tbz" }).to_string(), format!("{}, {}, {target}", reg(x, rt), bang(u64::from(bit))))
            }
            Self::Address { page, rd, .. } => ((if page { "adrp" } else { "adr" }).to_string(), format!("{}, {target}", reg(true, rd))),
        }
    }
}

/// An unsigned immediate as Capstone prints it (`printUInt64Bang`): `#0x…` above 9, else
/// decimal.
fn bang(v: u64) -> String {
    if v > 9 { format!("#0x{v:x}") } else { format!("#{v}") }
}
