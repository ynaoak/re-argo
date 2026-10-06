//! Float-constant annotator.
//!
//! Scalar-float code (game world-gen noise, DSP, graphics math) loads its
//! magic constants from `.rodata` via rip-relative `movss`/`movsd`/`addsd`/…
//! In the decompiler those previously showed only as `*(uint32_t*)0xee4034`,
//! hiding the value that matters for reverse-engineering. This analyzer
//! decodes each float instruction with a rip-relative memory operand, reads
//! the constant from the image, and attaches an EOL comment with the literal
//! value (plus a `1/N` hint for clean power-of-two reciprocals — e.g. the
//! Perlin `1/64` coordinate scale).

use iced_x86::{Decoder, DecoderOptions, Instruction as IcedInsn, Mnemonic, OpKind, Register};
use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct FloatConstantAnalyzer;

/// Element width (bytes) of a float SSE mnemonic that can load a constant,
/// or `None` if the mnemonic isn't a float-from-memory op we annotate.
fn float_width(m: Mnemonic) -> Option<u32> {
    use Mnemonic::*;
    match m {
        Movsd | Addsd | Subsd | Mulsd | Divsd | Comisd | Ucomisd | Sqrtsd | Minsd | Maxsd
        | Cvtsd2ss => Some(8),
        Movss | Addss | Subss | Mulss | Divss | Comiss | Ucomiss | Sqrtss | Minss | Maxss
        | Cvtss2sd => Some(4),
        _ => None,
    }
}

/// Packed-float SSE/AVX mnemonics that read a whole 128-bit constant from
/// memory: returns the element width (4 = `ps`, 8 = `pd`). Vectorised
/// world-gen code (e.g. BDS density slides) keeps per-lane scale tables in
/// `.rodata` and loads them with `mulps xmm, [rip+…]`; without this they
/// decompiled as an opaque `*(void*)0x128f2d0`.
fn packed_float_width(m: Mnemonic) -> Option<u32> {
    use Mnemonic::*;
    match m {
        Movaps | Movups | Addps | Subps | Mulps | Divps | Minps | Maxps | Sqrtps | Cmpps
        | Andps | Andnps | Orps | Xorps | Unpcklps | Unpckhps | Shufps | Vmovaps | Vmovups
        | Vaddps | Vsubps | Vmulps | Vdivps | Vminps | Vmaxps | Vandps | Vorps | Vxorps => {
            Some(4)
        }
        Movapd | Movupd | Addpd | Subpd | Mulpd | Divpd | Minpd | Maxpd | Sqrtpd | Cmppd
        | Andpd | Andnpd | Orpd | Xorpd | Unpcklpd | Unpckhpd | Shufpd | Vmovapd | Vmovupd
        | Vaddpd | Vsubpd | Vmulpd | Vdivpd | Vminpd | Vmaxpd | Vandpd | Vorpd | Vxorpd => {
            Some(8)
        }
        _ => None,
    }
}

/// Render a 128-bit packed constant (`lanes` little-endian elements of
/// `width` bytes) as `v4f32 const [a, b, c, d]` / `v2f64 const [a, b]`.
/// Lanes that are all equal collapse to `v4f32 const splat(a)`.
/// The `f32` bit pattern an `f32` lane widened to `f64` came from, NaN payload included. `as f32`
/// is free to return a canonical NaN (it does on Windows/MSVC builds), which turned the
/// `0x7fffffff` abs mask into `0x7fc00000`; a widened `f32` keeps its 23 mantissa bits in the top
/// of the `f64` mantissa, so they are recovered exactly.
fn f64_to_f32_bits(v: f64) -> u32 {
    if !v.is_nan() {
        return (v as f32).to_bits();
    }
    let b = v.to_bits();
    let sign = ((b >> 63) as u32) << 31;
    sign | 0x7f80_0000 | ((b >> 29) as u32 & 0x007f_ffff)
}

fn format_packed(vals: &[f64], width: u32) -> String {
    let ty = if width == 4 { "v4f32" } else { "v2f64" };
    if vals.iter().any(|v| v.is_nan()) {
        // Bit masks (abs / sign-flip tables for andps/xorps) are NaN as
        // floats; show the raw lanes instead.
        let parts: Vec<String> = vals
            .iter()
            .map(|v| {
                if width == 4 {
                    format!("{:#010x}", f64_to_f32_bits(*v))
                } else {
                    format!("{:#018x}", v.to_bits())
                }
            })
            .collect();
        return format!("{} mask [{}]", ty, parts.join(", "));
    }
    if vals.iter().all(|v| v.to_bits() == vals[0].to_bits()) {
        return format!("{} const splat({})", ty, vals[0]);
    }
    let parts: Vec<String> = vals.iter().map(|v| format!("{}", v)).collect();
    format!("{} const [{}]", ty, parts.join(", "))
}

/// Render a float with a short round-trip form plus a `1/N` reciprocal hint
/// for clean values (the constants RE cares about are usually `1/2^k` scales
/// or small rationals).
fn format_const(v: f64, width: u32) -> String {
    let ty = if width == 4 { "f32" } else { "f64" };
    let mut s = format!("{} const {}", ty, v);
    if v != 0.0 && v.is_finite() {
        let r = 1.0 / v;
        let rr = r.round();
        if (2.0..=1.0e9).contains(&rr) && (r - rr).abs() < 1e-6 * rr.abs() {
            s.push_str(&format!(" (= 1/{})", rr as i64));
        }
    }
    s
}

impl Analyzer for FloatConstantAnalyzer {
    fn name(&self) -> &str {
        "Float Constant"
    }

    fn description(&self) -> &str {
        "Annotates rip-relative float/double constant loads with their literal value"
    }

    fn priority(&self) -> u32 {
        905
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

        // Valid target ranges = initialized sections (so we don't read holes).
        let ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.address != 0 && s.size > 0)
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Snapshot (addr, bytes) so we decode against an immutable view.
        let insns: Vec<(u64, Vec<u8>)> = program
            .listing
            .instructions()
            .map(|i| (i.address, i.bytes.to_vec()))
            .collect();

        let mut annotated = 0usize;
        for (addr, bytes) in &insns {
            if let Some((target, width)) = decode_packed_const_load(*addr, bytes) {
                if !ranges.iter().any(|(s, e)| target >= *s && target + 16 <= *e) {
                    continue;
                }
                let lanes = 16 / width;
                let mut vals = Vec::with_capacity(lanes as usize);
                for k in 0..lanes {
                    let a = target + (k * width) as u64;
                    let v = match width {
                        4 => program.info.memory.read_u32(a).ok().map(|b| f32::from_bits(b) as f64),
                        _ => program.info.memory.read_u64(a).ok().map(f64::from_bits),
                    };
                    match v {
                        Some(v) => vals.push(v),
                        None => break,
                    }
                }
                if vals.len() as u32 != lanes
                    || program.comments.get(*addr, CommentType::Eol).is_some()
                {
                    continue;
                }
                program
                    .comments
                    .set(*addr, CommentType::Eol, format_packed(&vals, width));
                annotated += 1;
                continue;
            }
            let Some((target, width)) = decode_float_const_load(*addr, bytes) else {
                continue;
            };
            if !ranges.iter().any(|(s, e)| target >= *s && target < *e) {
                continue;
            }
            let value = match width {
                4 => program.info.memory.read_u32(target).ok().map(|b| f32::from_bits(b) as f64),
                8 => program.info.memory.read_u64(target).ok().map(f64::from_bits),
                _ => None,
            };
            let Some(v) = value else { continue };
            // Don't clobber an existing EOL comment.
            if program.comments.get(*addr, CommentType::Eol).is_some() {
                continue;
            }
            program
                .comments
                .set(*addr, CommentType::Eol, format_const(v, width));
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

/// Decode `code` (placed at virtual address `base`, `bits` = 32/64) and return
/// every rip-relative memory **data** target it references, as
/// `(target_va, access_width_bytes)`. Used by `carve` to pull a function's
/// constant pool / jump tables into the carved file so float-constant
/// annotation and rodata-dependent decompilation work on the carve.
pub fn rip_relative_data_targets(code: &[u8], base: u64, bits: u32) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    if code.is_empty() {
        return out;
    }
    let mut dec = Decoder::with_ip(bits, code, base, DecoderOptions::NONE);
    let mut ii = IcedInsn::default();
    while dec.can_decode() {
        dec.decode_out(&mut ii);
        if ii.is_invalid() {
            continue;
        }
        let has_mem = (0..ii.op_count()).any(|i| ii.op_kind(i) == OpKind::Memory);
        if has_mem && ii.memory_base() == Register::RIP {
            let mut sz = ii.memory_size().size() as u32;
            if sz == 0 {
                sz = 8;
            }
            out.push((ii.memory_displacement64(), sz));
        }
    }
    out
}

/// If `bytes` at `addr` decode to a float SSE op with a rip-relative memory
/// operand, return `(effective_target_address, element_width_bytes)`.
fn decode_float_const_load(addr: u64, bytes: &[u8]) -> Option<(u64, u32)> {
    let mut dec = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut ii = IcedInsn::default();
    dec.decode_out(&mut ii);
    if ii.is_invalid() {
        return None;
    }
    let width = float_width(ii.mnemonic())?;
    // Must have a memory operand based on RIP (a constant pool reference).
    let mem = (0..ii.op_count()).any(|i| ii.op_kind(i) == OpKind::Memory);
    if !mem || ii.memory_base() != Register::RIP {
        return None;
    }
    // iced's memory_displacement64() already folds in rip + insn length, so
    // it is the effective constant-pool address.
    Some((ii.memory_displacement64(), width))
}

/// If `bytes` at `addr` decode to a packed-float op whose memory operand is a
/// RIP-relative 128-bit constant, return `(target, element_width_bytes)`.
fn decode_packed_const_load(addr: u64, bytes: &[u8]) -> Option<(u64, u32)> {
    let mut dec = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut ii = IcedInsn::default();
    dec.decode_out(&mut ii);
    if ii.is_invalid() {
        return None;
    }
    let width = packed_float_width(ii.mnemonic())?;
    let mem = (0..ii.op_count()).any(|i| ii.op_kind(i) == OpKind::Memory);
    if !mem || ii.memory_base() != Register::RIP || ii.memory_size().size() != 16 {
        return None;
    }
    Some((ii.memory_displacement64(), width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_movss_rip_relative() {
        // movss xmm1, [rip+0x10] = f3 0f 10 0d 10 00 00 00
        // ip 0x1000, len 8 -> effective 0x1000+8+0x10 = 0x1018
        let bytes = [0xf3, 0x0f, 0x10, 0x0d, 0x10, 0x00, 0x00, 0x00];
        let (target, width) = decode_float_const_load(0x1000, &bytes).unwrap();
        assert_eq!(target, 0x1018);
        assert_eq!(width, 4);
    }

    #[test]
    fn ignores_stack_relative_load() {
        // movss xmm0, [rsp+0x14] = f3 0f 10 44 24 14  (base rsp, not rip)
        let bytes = [0xf3, 0x0f, 0x10, 0x44, 0x24, 0x14];
        assert!(decode_float_const_load(0x1000, &bytes).is_none());
    }

    #[test]
    fn ignores_integer_op() {
        // mov eax, [rip+0x10] = 8b 05 10 00 00 00 (not a float op)
        let bytes = [0x8b, 0x05, 0x10, 0x00, 0x00, 0x00];
        assert!(decode_float_const_load(0x1000, &bytes).is_none());
    }

    #[test]
    fn detects_mulps_rip_relative_vector() {
        // mulps xmm0, [rip+0x10] = 0f 59 05 10 00 00 00 (len 7)
        let bytes = [0x0f, 0x59, 0x05, 0x10, 0x00, 0x00, 0x00];
        let (target, width) = decode_packed_const_load(0x1000, &bytes).unwrap();
        assert_eq!(target, 0x1017);
        assert_eq!(width, 4);
        // the scalar decoder must not claim it
        assert!(decode_float_const_load(0x1000, &bytes).is_none());
        // mulpd xmm0, [rip+0x10] = 66 0f 59 05 10 00 00 00
        let pd = [0x66, 0x0f, 0x59, 0x05, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(decode_packed_const_load(0x1000, &pd).unwrap().1, 8);
    }

    #[test]
    fn formats_packed() {
        assert_eq!(format_packed(&[1.0, 2.5, -8.0, 0.0], 4), "v4f32 const [1, 2.5, -8, 0]");
        assert_eq!(format_packed(&[0.5; 4], 4), "v4f32 const splat(0.5)");
        assert_eq!(format_packed(&[684.412, 1.0], 8), "v2f64 const [684.412, 1]");
        // `black_box`: a const-folded `as f64` may canonicalise the NaN (the analyzer widens
        // lanes read at run time, which keeps the payload)
        let abs = std::hint::black_box(f32::from_bits(0x7fff_ffff)) as f64;
        assert_eq!(
            format_packed(&[abs; 4], 4),
            "v4f32 mask [0x7fffffff, 0x7fffffff, 0x7fffffff, 0x7fffffff]"
        );
    }

    #[test]
    fn annotates_packed_constant_end_to_end() {
        use crate::discovery::FunctionDiscoveryAnalyzer;
        use crate::testutil::helpers::make_x86_64_program_with_data;

        let code_addr = 0x1000u64;
        let data_addr = 0x2000u64;
        // mulps xmm0, [rip+0xff9] ; ret   (len 7 -> rip 0x1007 + 0xff9 = 0x2000)
        let code = [0x0f, 0x59, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0xc3];
        let mut data = Vec::new();
        for v in [1.0f32, 0.5, 0.25, -8.0] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        let mut prog = make_x86_64_program_with_data(&code, &data, code_addr, data_addr);
        FunctionDiscoveryAnalyzer.analyze(&mut prog).unwrap();
        let res = FloatConstantAnalyzer.analyze(&mut prog).unwrap();
        assert_eq!(res.references_found, 1);
        let c = prog.comments.get(code_addr, CommentType::Eol).expect("eol comment");
        assert_eq!(c, "v4f32 const [1, 0.5, 0.25, -8]");
    }

    #[test]
    fn formats_reciprocal_hint() {
        // 1/64 = 0.015625
        let s = format_const(0.015625, 4);
        assert!(s.contains("1/64"), "got: {s}");
        // a non-clean value gets no hint
        let s2 = format_const(1.0181268882175227, 8);
        assert!(!s2.contains("1/"), "got: {s2}");
    }

    #[test]
    fn annotates_rip_relative_constant_end_to_end() {
        use crate::discovery::FunctionDiscoveryAnalyzer;
        use crate::testutil::helpers::make_x86_64_program_with_data;
        use reargo_program::comments::CommentType;

        let code_addr = 0x1000u64;
        let data_addr = 0x2000u64;
        // movss xmm0, [rip+0xff8] ; ret
        //   ip 0x1000, len 8 -> rip 0x1008, +0xff8 = 0x2000 (data_addr)
        let code = [0xf3, 0x0f, 0x10, 0x05, 0xf8, 0x0f, 0x00, 0x00, 0xc3];
        // f32 0.015625 = 0x3C800000 little-endian
        let data = [0x00, 0x00, 0x80, 0x3c];

        let mut prog = make_x86_64_program_with_data(&code, &data, code_addr, data_addr);
        FunctionDiscoveryAnalyzer.analyze(&mut prog).unwrap();
        let res = FloatConstantAnalyzer.analyze(&mut prog).unwrap();

        assert_eq!(res.references_found, 1, "expected one annotated constant");
        let c = prog
            .comments
            .get(code_addr, CommentType::Eol)
            .expect("eol comment at movss");
        assert!(c.contains("0.015625"), "got: {c}");
        assert!(c.contains("1/64"), "got: {c}");
        assert!(c.contains("f32"), "got: {c}");
    }
}
