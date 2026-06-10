//! Detect compiler-inlined memcpy / memset / memcmp / strlen patterns.
//!
//! Modern compilers replace short calls to `memcpy`/`memset`/etc.
//! with a single string instruction or a small unrolled loop. IDA
//! and Binary Ninja annotate these so users don't have to recognise
//! the canonical encodings on sight. We do the same here, at the
//! single-instruction level:
//!
//! ```asm
//!   f3 a4                rep movsb            ; inlined memcpy
//!   f3 48 a5             rep movsq            ; inlined memcpy (qword stride)
//!   f3 aa                rep stosb            ; inlined memset
//!   f3 48 ab             rep stosq            ; inlined memset (qword stride)
//!   f3 a6                repe cmpsb           ; inlined memcmp
//!   f3 ae                repe scasb           ; inlined strlen / memchr
//! ```
//!
//! These bytes are diagnostic — there's no other instruction with
//! the same encoding — so we just byte-pattern match and emit a
//! pre-comment that explains what the loop is actually doing.

use gr_program::comments::CommentType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct InlineMemAnalyzer;

impl Analyzer for InlineMemAnalyzer {
    fn name(&self) -> &str {
        "Inline Memcpy/Memset"
    }
    fn description(&self) -> &str {
        "Annotates rep-prefixed string instructions as inlined libc primitives"
    }
    fn priority(&self) -> u32 {
        // After Stack / discovery so we know which functions contain
        // each insn, but before xref-report consumes the comment stream.
        680
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

        let candidates: Vec<(u64, &'static str)> = program
            .listing
            .instructions()
            .filter_map(|i| classify(&i.bytes).map(|c| (i.address, c)))
            .collect();

        let mut emitted = 0usize;
        for (addr, note) in candidates {
            if program.comments.get(addr, CommentType::Pre).is_some() {
                continue;
            }
            program.comments.set(addr, CommentType::Pre, note);
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

/// Match the `rep`/`repe`/`repne`-prefixed string ops the compiler
/// emits in lieu of a libc call. `REPE`/`REPNE` use the same `F3`/`F2`
/// prefixes; we use the trailing opcode to disambiguate the operation.
fn classify(bytes: &[u8]) -> Option<&'static str> {
    if bytes.is_empty() {
        return None;
    }
    let rep = matches!(bytes[0], 0xF3); // REP / REPE
    let repne = matches!(bytes[0], 0xF2);
    if !rep && !repne {
        return None;
    }
    // Optional REX.W (48) between the prefix and the opcode for qword
    // variants.
    let op_idx = if bytes.len() >= 3 && bytes[1] == 0x48 { 2 } else { 1 };
    if bytes.len() <= op_idx {
        return None;
    }
    let qword = op_idx == 2;
    match bytes[op_idx] {
        // MOVS — copy
        0xA4 if rep => Some("inlined memcpy (byte stride)"),
        0xA5 if rep => Some(if qword {
            "inlined memcpy (qword stride)"
        } else {
            "inlined memcpy (dword stride)"
        }),
        // STOS — fill
        0xAA if rep => Some("inlined memset (byte stride)"),
        0xAB if rep => Some(if qword {
            "inlined memset (qword stride)"
        } else {
            "inlined memset (dword stride)"
        }),
        // CMPS — compare
        0xA6 => Some("inlined memcmp (byte stride)"),
        0xA7 => Some(if qword {
            "inlined memcmp (qword stride)"
        } else {
            "inlined memcmp (dword stride)"
        }),
        // SCAS — search
        0xAE if repne => Some("inlined memchr / strchr"),
        0xAE if rep => Some("inlined strlen-style scan"),
        0xAF => Some("inlined word/dword/qword scan"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rep_movsb() {
        assert_eq!(classify(&[0xF3, 0xA4]).unwrap(), "inlined memcpy (byte stride)");
    }

    #[test]
    fn rep_movsq() {
        assert_eq!(
            classify(&[0xF3, 0x48, 0xA5]).unwrap(),
            "inlined memcpy (qword stride)"
        );
    }

    #[test]
    fn rep_stosb_and_stosq() {
        assert!(classify(&[0xF3, 0xAA]).unwrap().starts_with("inlined memset"));
        assert_eq!(
            classify(&[0xF3, 0x48, 0xAB]).unwrap(),
            "inlined memset (qword stride)"
        );
    }

    #[test]
    fn repne_scasb_is_memchr() {
        assert_eq!(classify(&[0xF2, 0xAE]).unwrap(), "inlined memchr / strchr");
    }

    #[test]
    fn plain_mov_ignored() {
        assert!(classify(&[0x48, 0x89, 0xE5]).is_none());
    }

    #[test]
    fn empty_ignored() {
        assert!(classify(&[]).is_none());
    }
}
