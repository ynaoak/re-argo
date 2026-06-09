//! Recognise printable ASCII byte runs embedded in x86_64 `MOV imm` /
//! `MOVABS imm64` encodings and emit an EOL preview.
//!
//! Compilers (especially when targeting size or when the literal is
//! ≤ 8 bytes) emit short strings as a single immediate load:
//!
//! ```asm
//!   movabs $0x7473206f6c6c6568, %rax    ; "hello st"
//!   mov    $0x216b6361, %edx            ; "ack!"
//! ```
//!
//! `.rodata` never holds these — they live entirely inside the
//! instruction encoding — so `StringReferenceAnalyzer` and friends
//! can't see them. This is the same recovery `StackStringAnalyzer`
//! does for the runs of stack stores that build a 16-byte literal,
//! but at the single-instruction granularity.
//!
//! Patterns matched (REX-prefixed forms covered too):
//!
//! ```text
//!   B8+rd imm32              mov   r32, imm32
//!   48 B8+rd imm64           movabs r64, imm64    (REX.W)
//!   C7 /0 imm32              mov   r/m32, imm32  (RAX form: C7 C0 …)
//!   48 C7 /0 imm32           mov   r/m64, sx imm32
//! ```
//!
//! Only the *immediate* part is inspected as bytes; we don't try to
//! parse out the destination register because the EOL annotation
//! is keyed on the instruction address only.

use gr_program::comments::CommentType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct ImmediateStringAnnotator;

impl Analyzer for ImmediateStringAnnotator {
    fn name(&self) -> &str {
        "Immediate String"
    }
    fn description(&self) -> &str {
        "Decodes printable ASCII embedded in MOV imm / MOVABS imm64 encodings"
    }
    fn priority(&self) -> u32 {
        // Right after StackString (650); both write EOL/Pre comments
        // that need to land before CallSiteAnnotator's pre-comment.
        660
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, gr_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let candidates: Vec<(u64, [u8; 8], usize)> = program
            .listing
            .instructions()
            .filter_map(|i| extract_imm(&i.bytes).map(|(b, n)| (i.address, b, n)))
            .collect();

        let mut emitted = 0usize;
        for (addr, bytes, n) in candidates {
            if program.comments.get(addr, CommentType::Eol).is_some() {
                continue;
            }
            let Some(preview) = printable_preview(&bytes[..n]) else {
                continue;
            };
            program
                .comments
                .set(addr, CommentType::Eol, format!("\"{}\"", preview));
            emitted += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: emitted,
        })
    }
}

/// Extract the immediate bytes and their effective width from a MOV
/// imm / MOVABS imm encoding. Returns `(bytes, width)` where only
/// `bytes[..width]` carry meaningful data.
fn extract_imm(bytes: &[u8]) -> Option<([u8; 8], usize)> {
    // 48 B8+rd imm64 — MOVABS r64, imm64 (10 bytes)
    if bytes.len() >= 10 && bytes[0] == 0x48 && (bytes[1] & 0xF8) == 0xB8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[2..10]);
        return Some((b, 8));
    }
    // 49 B8+rd imm64 — MOVABS r8..r15, imm64 (10 bytes, REX.W+REX.B)
    if bytes.len() >= 10 && bytes[0] == 0x49 && (bytes[1] & 0xF8) == 0xB8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[2..10]);
        return Some((b, 8));
    }
    // B8+rd imm32 — MOV r32, imm32 (5 bytes)
    if bytes.len() >= 5 && (bytes[0] & 0xF8) == 0xB8 {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&bytes[1..5]);
        return Some((b, 4));
    }
    // 41 B8+rd imm32 — MOV r8d..r15d, imm32 (6 bytes, REX.B)
    if bytes.len() >= 6 && bytes[0] == 0x41 && (bytes[1] & 0xF8) == 0xB8 {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&bytes[2..6]);
        return Some((b, 4));
    }
    // C7 C0+rd imm32 — MOV r32, imm32 (alternate form) (6 bytes)
    // (We only need this when the ModR/M selects RAX..R15D as a
    // register destination, i.e., mod=11.)
    if bytes.len() >= 6 && bytes[0] == 0xC7 && (bytes[1] & 0xC0) == 0xC0 {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&bytes[2..6]);
        return Some((b, 4));
    }
    None
}

/// Return a quoted preview when the byte run is mostly printable ASCII
/// (≥ 4 chars before any NUL, ≥ 80 % printable overall). Mirrors the
/// thresholds in `stackstr` / `string_xref` so the three analyzers
/// produce consistent-looking output.
fn printable_preview(bytes: &[u8]) -> Option<String> {
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if nul < 4 {
        return None;
    }
    let s = &bytes[..nul];
    let printable = s
        .iter()
        .filter(|&&b| (b' '..=b'~').contains(&b) || b == b'\n' || b == b'\t')
        .count();
    if printable * 5 < s.len() * 4 {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    for &b in s {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            _ => out.push(b as char),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn movabs_rax_ascii() {
        // 48 b8 68 65 6c 6c 6f 20 73 74 — movabs $0x7473206f6c6c6568, %rax
        let bytes = [
            0x48, 0xB8, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x73, 0x74,
        ];
        let (imm, width) = extract_imm(&bytes).unwrap();
        assert_eq!(width, 8);
        assert_eq!(&imm[..8], b"hello st");
        assert_eq!(printable_preview(&imm[..width]).as_deref(), Some("hello st"));
    }

    #[test]
    fn mov_edx_ascii_4byte() {
        // ba 61 63 6b 21 — mov $0x216b6361, %edx ("ack!")
        let bytes = [0xBA, 0x61, 0x63, 0x6B, 0x21];
        let (imm, width) = extract_imm(&bytes).unwrap();
        assert_eq!(width, 4);
        assert_eq!(&imm[..4], b"ack!");
        assert_eq!(printable_preview(&imm[..width]).as_deref(), Some("ack!"));
    }

    #[test]
    fn rejects_non_mov_imm() {
        // 48 89 e5 — mov rbp, rsp
        assert!(extract_imm(&[0x48, 0x89, 0xE5]).is_none());
    }

    #[test]
    fn rejects_garbage_immediate() {
        // movabs with non-printable junk
        let bytes = [
            0x48, 0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let (imm, width) = extract_imm(&bytes).unwrap();
        assert!(printable_preview(&imm[..width]).is_none());
    }

    #[test]
    fn rejects_short_ascii_run() {
        // "hi" is only 2 chars before NUL — below 4-char threshold
        let bytes = [0xB8, 0x68, 0x69, 0x00, 0x00];
        let (imm, width) = extract_imm(&bytes).unwrap();
        assert!(printable_preview(&imm[..width]).is_none());
    }
}
