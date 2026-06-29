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
