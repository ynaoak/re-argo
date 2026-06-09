//! Detect thread-local storage (TLS) variable accesses via `fs:`/`gs:`
//! segment overrides and emit an EOL annotation.
//!
//! On Linux x86_64, the kernel sets `fs.base` to point at the calling
//! thread's TCB; `fs:0x28` is the stack-protector canary (handled by
//! `canary.rs`), and `fs:0xN` for other N is a thread-local slot —
//! `__thread int x` from C, `thread_local!` in Rust, or per-thread
//! libc errno. Windows uses `gs:` instead and `gs:0x30` is the PEB
//! pointer.
//!
//! This analyzer pattern-matches the four common encodings and emits
//! a one-line hint at the instruction's address:
//!
//! ```asm
//!   mov rax, qword ptr fs:0x60   ; TLS read fs:0x60
//!   mov qword ptr fs:0x68, rdi   ; TLS write fs:0x68
//! ```
//!
//! Canary loads (`fs:0x28`) are deliberately skipped — `canary.rs`
//! emits a richer plate annotation for those.

use gr_program::comments::CommentType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct TlsVariableAnalyzer;

impl Analyzer for TlsVariableAnalyzer {
    fn name(&self) -> &str {
        "TLS Variable"
    }
    fn description(&self) -> &str {
        "Annotates fs:/gs: segment-override accesses as TLS variable reads/writes"
    }
    fn priority(&self) -> u32 {
        // After canary detection (720) so the canary load isn't
        // double-annotated as a generic TLS read.
        725
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

        let candidates: Vec<(u64, String)> = program
            .listing
            .instructions()
            .filter_map(|i| classify(&i.bytes).map(|c| (i.address, c)))
            .collect();

        let mut emitted = 0usize;
        for (addr, note) in candidates {
            if program.comments.get(addr, CommentType::Eol).is_some() {
                continue;
            }
            program.comments.set(addr, CommentType::Eol, note);
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

/// Return a human-readable note when `bytes` encodes a `fs:`/`gs:`
/// segment-prefixed instruction. Handles both 64-bit (REX.W) and
/// 32-bit forms and the common arithmetic ops compilers emit when
/// updating a TLS variable in place:
///
/// ```text
///   64 48 8b 04 25 disp32     mov r64, qword ptr fs:disp32
///   64    8b 04 25 disp32     mov r32, dword ptr fs:disp32
///   64    89 1c 25 disp32     mov dword ptr fs:disp32, r32
///   64    03 1c 25 disp32     add r32, dword ptr fs:disp32
///   64    01 1c 25 disp32     add dword ptr fs:disp32, r32
/// ```
///
/// Canary slot (`fs:0x28`) returns `None` — `canary.rs` owns it.
fn classify(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let seg = match bytes[0] {
        0x64 => "fs",
        0x65 => "gs",
        _ => return None,
    };

    // Skip an optional REX prefix (0x40..0x4f). REX.W=0x48 is the
    // qword variant; everything else is dword.
    let (op_idx, qword) = if bytes.len() >= 2 && (bytes[1] & 0xF0) == 0x40 {
        (2, bytes[1] & 0x08 != 0)
    } else {
        (1, false)
    };
    if bytes.len() < op_idx + 7 {
        return None;
    }

    // Direction inferred from the opcode. We're deliberately loose:
    // anything with a SIB-with-disp32 absolute address against an
    // fs:/gs: segment is interesting enough to annotate.
    let action = match bytes[op_idx] {
        0x8B => "read",  // MOV r, [mem]
        0x89 => "write", // MOV [mem], r
        0x03 => "read",  // ADD r, [mem]
        0x01 => "rmw",   // ADD [mem], r
        0x2B => "read",  // SUB r, [mem]
        0x29 => "rmw",   // SUB [mem], r
        0x3B => "cmp",   // CMP r, [mem]
        0x39 => "cmp",   // CMP [mem], r
        _ => return None,
    };

    let modrm = bytes[op_idx + 1];
    let sib = bytes[op_idx + 2];
    // disp32 absolute requires ModR/M.mod=00, ModR/M.r/m=100 (SIB),
    // and SIB = b'.b101'00 i.e., 0x25.
    if modrm & 0xC7 != 0x04 || sib != 0x25 {
        return None;
    }

    let disp = i32::from_le_bytes([
        bytes[op_idx + 3],
        bytes[op_idx + 4],
        bytes[op_idx + 5],
        bytes[op_idx + 6],
    ]);
    if seg == "fs" && disp == 0x28 {
        return None;
    }

    let width = if qword { "qword" } else { "dword" };
    let label = well_known(seg, disp as u32);
    let disp_str = if disp < 0 {
        format!("-0x{:x}", -(disp as i64))
    } else {
        format!("0x{:x}", disp)
    };
    Some(if let Some(l) = label {
        format!("TLS {} {} {}:{}  ({})", action, width, seg, disp_str, l)
    } else {
        format!("TLS {} {} {}:{}", action, width, seg, disp_str)
    })
}

/// Identify the slot when it's a well-known platform field (errno,
/// PEB, TEB, etc.) — saves the user from chasing offsets.
fn well_known(seg: &str, disp: u32) -> Option<&'static str> {
    match (seg, disp) {
        ("fs", 0x00) => Some("TCB self-pointer"),
        ("fs", 0x10) => Some("glibc errno"),
        ("gs", 0x30) => Some("Win64 PEB"),
        ("gs", 0x60) => Some("Win64 PEB.Ldr"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_read_qword_non_canary() {
        // 64 48 8b 04 25 60 00 00 00 — mov rax, qword ptr fs:0x60
        let bytes = [0x64, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let note = classify(&bytes).unwrap();
        assert!(note.starts_with("TLS read qword fs:0x60"));
    }

    #[test]
    fn fs_write_qword() {
        // 64 48 89 04 25 68 00 00 00 — mov qword ptr fs:0x68, rax
        let bytes = [0x64, 0x48, 0x89, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00];
        let note = classify(&bytes).unwrap();
        assert!(note.starts_with("TLS write qword fs:0x68"));
    }

    #[test]
    fn fs_read_dword_no_rex() {
        // 64 8b 04 25 60 00 00 00 — mov eax, dword ptr fs:0x60
        let bytes = [0x64, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let note = classify(&bytes).unwrap();
        assert!(note.starts_with("TLS read dword fs:0x60"));
    }

    #[test]
    fn fs_add_dword_rmw() {
        // 64 01 1c 25 fc ff ff ff — add dword ptr fs:-4, ebx
        let bytes = [0x64, 0x01, 0x1C, 0x25, 0xFC, 0xFF, 0xFF, 0xFF];
        let note = classify(&bytes).unwrap();
        assert!(note.contains("rmw"));
        assert!(note.contains("-0x4"));
    }

    #[test]
    fn canary_skipped() {
        let bytes = [0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00];
        assert!(classify(&bytes).is_none());
    }

    #[test]
    fn gs_peb() {
        let bytes = [0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00];
        let note = classify(&bytes).unwrap();
        assert!(note.contains("Win64 PEB"));
    }

    #[test]
    fn non_segment_ignored() {
        // mov rax, qword ptr [rdi] — no segment override
        assert!(classify(&[0x48, 0x8B, 0x07]).is_none());
    }
}
