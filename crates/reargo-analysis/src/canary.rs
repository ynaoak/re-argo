//! Detect stack-protector ("canary") usage per function.
//!
//! Same purpose as Binary Ninja's "Stack Cookie Detected" tag and
//! IDA's stack-protector marker: identify functions that load a TLS-
//! resident canary, store it on the stack, and verify it before
//! returning. We're not trying to do exploit-analysis here — just to
//! surface a `stack_protected: true` annotation so users can quickly
//! tell which paths the compiler considered worth hardening.
//!
//! Detection rules (x86_64 Linux SysV):
//!
//! 1. The function loads the canary from `%fs:0x28` — encoded as
//!    `64 48 8b 04 25 28 00 00 00` (`mov rax, qword ptr fs:0x28`).
//!    Some prologues use `gs:0x28` instead (`65 48 …`).
//! 2. AND it calls `__stack_chk_fail` (already resolved by Signature
//!    Applier — we just look for the name in `call_targets`).
//!
//! Either rule alone is a weaker signal; both together is conclusive.
//! Functions with just rule 1 get marked `canary_load: true` (so we
//! still report on inlined-fail paths that don't `call` the helper).

use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct StackCanaryAnalyzer;

impl Analyzer for StackCanaryAnalyzer {
    fn name(&self) -> &str {
        "Stack Canary"
    }
    fn description(&self) -> &str {
        "Flags functions that use the stack-protector (SSP) canary"
    }
    fn priority(&self) -> u32 {
        // After Signatures (700) so __stack_chk_fail is named; before
        // CrossReferenceReport.
        720
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

        let chk_fail_addrs: std::collections::BTreeSet<u64> = program
            .symbol_table
            .iter()
            .filter(|s| {
                let n = s.name.strip_suffix("@plt").unwrap_or(&s.name);
                n == "__stack_chk_fail"
            })
            .map(|s| s.address)
            .collect();

        struct FuncSnap {
            entry: u64,
            ranges: Vec<(u64, u64)>,
            calls_chk: bool,
        }
        let func_ranges: Vec<FuncSnap> = program
            .listing
            .functions()
            .map(|f| FuncSnap {
                entry: f.entry_point,
                ranges: f
                    .body
                    .ranges()
                    .map(|r| (r.start.offset, r.start.offset + r.size))
                    .collect(),
                calls_chk: f.call_targets.iter().any(|t| chk_fail_addrs.contains(t)),
            })
            .collect();

        let mut marked = 0usize;
        let mut annotations: Vec<(u64, &'static str)> = Vec::new();
        for snap in &func_ranges {
            let mut has_canary_load = false;
            for (start, end) in &snap.ranges {
                for insn in program.listing.instructions_in_range(*start, *end) {
                    if is_canary_load(&insn.bytes) {
                        has_canary_load = true;
                        break;
                    }
                }
                if has_canary_load {
                    break;
                }
            }
            if has_canary_load && snap.calls_chk {
                annotations.push((snap.entry, "stack-protected"));
                marked += 1;
            } else if has_canary_load {
                annotations.push((snap.entry, "canary load (no __stack_chk_fail call seen)"));
                marked += 1;
            }
        }

        for (addr, note) in annotations {
            if program.comments.get(addr, CommentType::Plate).is_none() {
                program.comments.set(addr, CommentType::Plate, note);
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: marked,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// `mov rax, qword ptr fs:0x28` or `gs:0x28`. The exact byte sequence
/// is what every gcc / clang prologue emits when `-fstack-protector*`
/// is on; matching the bytes directly is faster and more reliable than
/// re-lifting and walking P-code segments here.
fn is_canary_load(bytes: &[u8]) -> bool {
    if bytes.len() < 9 {
        return false;
    }
    let seg = bytes[0];
    seg == 0x64 || seg == 0x65   // fs: or gs:
        && bytes[1] == 0x48      // REX.W
        && bytes[2] == 0x8B      // mov r64, r/m64
        && bytes[3] == 0x04      // ModR/M: rax + SIB
        && bytes[4] == 0x25      // SIB: disp32 absolute
        && bytes[5] == 0x28      // disp32 byte 0
        && bytes[6] == 0x00
        && bytes[7] == 0x00
        && bytes[8] == 0x00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_fs_28_load() {
        // 64 48 8b 04 25 28 00 00 00 : mov rax, qword ptr fs:0x28
        let bytes = [0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00];
        assert!(is_canary_load(&bytes));
    }

    #[test]
    fn detects_gs_28_load() {
        let bytes = [0x65, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00];
        assert!(is_canary_load(&bytes));
    }

    #[test]
    fn rejects_non_canary() {
        assert!(!is_canary_load(&[0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]));
        assert!(!is_canary_load(&[])); // empty
    }
}
