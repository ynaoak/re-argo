//! Magic-number division annotator.
//!
//! Compilers turn `x / C` and `x % C` (C a non-power-of-two constant) into a
//! multiply by a "magic" reciprocal followed by a shift (Hacker's Delight ch.
//! 10). In disassembly this surfaces only as `imul reg, reg, 0x4EC4EC4F` — the
//! divisor `13` is invisible. This analyzer recognises the signed/unsigned
//! 32-bit division magics for small divisors and annotates the `imul` with the
//! recovered divisor (e.g. `// ÷13 (division magic)`). Modulo-heavy code —
//! RNG state mixing, Fisher–Yates permutation ranges, hash bucketing, the
//! Minecraft End island-weight `% 13` — becomes readable without hand-matching
//! the constant.

use std::collections::HashMap;
use std::sync::OnceLock;

use iced_x86::{Decoder, DecoderOptions, Instruction as IcedInsn, Mnemonic, OpKind};
use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct MagicDivisionAnalyzer;

/// Signed 32-bit division magic (Hacker's Delight, Fig. 10-1). Returns
/// `(magic, shift)` such that `n / d ≈ (n * magic) >> (32 + shift)` (+ sign
/// correction).
fn magic_s32(d: i32) -> (u32, u32) {
    let ad = (d as i64).unsigned_abs() as u32; // |d|
    let two31 = 0x8000_0000u32;
    let t = two31.wrapping_add((d as u32) >> 31);
    let anc = t - 1 - t % ad; // |nc|
    let mut p = 31u32;
    let mut q1 = two31 / anc;
    let mut r1 = two31 - q1 * anc;
    let mut q2 = two31 / ad;
    let mut r2 = two31 - q2 * ad;
    loop {
        p += 1;
        q1 = q1.wrapping_mul(2);
        r1 = r1.wrapping_mul(2);
        if r1 >= anc {
            q1 += 1;
            r1 -= anc;
        }
        q2 = q2.wrapping_mul(2);
        r2 = r2.wrapping_mul(2);
        if r2 >= ad {
            q2 += 1;
            r2 -= ad;
        }
        let delta = ad - r2;
        if q1 >= delta && !(q1 == delta && r1 == 0) {
            break;
        }
    }
    let mut magic = q2.wrapping_add(1);
    if d < 0 {
        magic = magic.wrapping_neg();
    }
    (magic, p - 32)
}

/// Unsigned 32-bit division magic (Hacker's Delight, Fig. 10-3). Returns
/// `(magic, shift, add_indicator)`. We only need the magic for the lookup.
fn magic_u32(d: u32) -> u32 {
    let two31 = 0x8000_0000u32;
    let nc = u32::MAX - d.wrapping_neg().wrapping_rem(d);
    let mut p = 31u32;
    let mut q1 = two31 / nc;
    let mut r1 = two31 - q1 * nc;
    let mut q2 = (two31 - 1) / d;
    let mut r2 = (two31 - 1) - q2 * d;
    loop {
        p += 1;
        if r1 >= nc - r1 {
            q1 = q1.wrapping_mul(2) + 1;
            r1 = r1.wrapping_mul(2) - nc;
        } else {
            q1 = q1.wrapping_mul(2);
            r1 = r1.wrapping_mul(2);
        }
        if r2 + 1 >= d - r2 {
            q2 = q2.wrapping_mul(2) + 1;
            r2 = r2.wrapping_mul(2) + 1 - d;
        } else {
            q2 = q2.wrapping_mul(2) + 1;
            r2 = r2.wrapping_mul(2) + 1;
        }
        let delta = d - 1 - r2;
        if !(p < 64 && (q1 < delta || (q1 == delta && r1 == 0))) {
            break;
        }
    }
    q2.wrapping_add(1)
}

/// Reverse lookup: magic constant (as it appears in an `imul` immediate) → the
/// divisor it implements. Covers divisors 3..=1024 (powers of two use shifts,
/// not magics, so they're irrelevant). Both signed and unsigned magics, since
/// the same constant rarely collides for distinct small divisors.
fn magic_table() -> &'static HashMap<u32, u32> {
    static T: OnceLock<HashMap<u32, u32>> = OnceLock::new();
    T.get_or_init(|| {
        let mut m = HashMap::new();
        // A divisor `d` and its `d·2^k` multiples share the same magic constant
        // (they differ only in the post-multiply shift), so iterate ascending
        // and keep the SMALLEST divisor for each magic — that's the canonical
        // odd/base divisor a reader wants to see (`÷13`, not `÷832`).
        for d in 3u32..=1024 {
            if d.is_power_of_two() {
                continue;
            }
            m.entry(magic_u32(d)).or_insert(d);
            m.entry(magic_s32(d as i32).0).or_insert(d);
        }
        m
    })
}

/// Look up a divisor for a magic immediate (matches the value as a u32 — 64-bit
/// `imul r64, r64, imm32` sign-extends, but the magic itself is the 32-bit
/// pattern). Returns None for ordinary multipliers.
pub fn divisor_for_magic(imm: u64) -> Option<u32> {
    magic_table().get(&(imm as u32)).copied()
}

impl Analyzer for MagicDivisionAnalyzer {
    fn name(&self) -> &str {
        "Magic Division"
    }

    fn description(&self) -> &str {
        "Annotates `imul reg, reg, MAGIC` division-by-constant magics with the divisor"
    }

    fn priority(&self) -> u32 {
        904
    }

    fn provides(&self) -> &'static [&'static str] {
        &["comments"]
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let insns: Vec<(u64, Vec<u8>)> = program
            .listing
            .instructions()
            .map(|i| (i.address, i.bytes.to_vec()))
            .collect();

        let mut annotated = 0usize;
        for (addr, bytes) in &insns {
            let Some(d) = decode_magic_imul(*addr, bytes) else {
                continue;
            };
            if program.comments.get(*addr, CommentType::Eol).is_some() {
                continue;
            }
            program.comments.set(
                *addr,
                CommentType::Eol,
                format!("÷{} (division magic)", d),
            );
            annotated += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: annotated,
            instructions_decoded: 0,
        })
    }
}

/// If `bytes` at `addr` decode to a 3-operand `imul reg, reg, imm` whose
/// immediate is a known division magic, return the divisor. Public so the
/// disassembler's `-A` annotation can surface it inline (the decompiler folds
/// the magic sequence, so disasm is the reliable place to see it).
pub fn magic_imul_divisor(addr: u64, bytes: &[u8]) -> Option<u32> {
    decode_magic_imul(addr, bytes)
}

/// If `bytes` at `addr` decode to a 3-operand `imul reg, reg, imm` whose
/// immediate is a known division magic, return the divisor.
fn decode_magic_imul(addr: u64, bytes: &[u8]) -> Option<u32> {
    let mut dec = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut ii = IcedInsn::default();
    dec.decode_out(&mut ii);
    if ii.is_invalid() || ii.mnemonic() != Mnemonic::Imul || ii.op_count() != 3 {
        return None;
    }
    // op2 must be an immediate; magics are large (high bit set) so this won't
    // fire on a real `x * 13` small multiplier.
    if !matches!(
        ii.op_kind(2),
        OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate8to32 | OpKind::Immediate8to64
    ) {
        return None;
    }
    let imm = ii.immediate(2);
    // Only treat high-magnitude constants as magics (a genuine small
    // multiplier like `*13` has the low bits, not a reciprocal pattern).
    if (imm as u32) < 0x1000_0000 {
        return None;
    }
    divisor_for_magic(imm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn div13_magic_is_recognised() {
        // 0x4EC4EC4F is the classic signed ÷13 magic (the Minecraft End
        // island-weight `% 13`).
        assert_eq!(magic_s32(13).0, 0x4EC4EC4F);
        assert_eq!(divisor_for_magic(0x4EC4EC4F), Some(13));
    }

    #[test]
    fn common_divisors_round_trip() {
        // Odd divisors are canonical (an even d = d_odd·2^k shares d_odd's
        // magic and resolves to the odd base — see the table comment).
        for d in [3i32, 5, 7, 9, 11, 13, 25, 100 + 1, 1000 + 1] {
            let (magic, _) = magic_s32(d);
            assert_eq!(divisor_for_magic(magic as u64), Some(d as u32), "d={}", d);
        }
    }

    #[test]
    fn ordinary_multiplier_is_not_a_magic() {
        // small multipliers must not be misread as division magics.
        assert_eq!(divisor_for_magic(13), None);
        assert_eq!(divisor_for_magic(3439), None); // the *3439 island-weight factor
    }
}
