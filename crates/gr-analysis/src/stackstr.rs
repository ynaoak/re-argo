//! Reconstruct inline stack strings — Binary-Ninja-style.
//!
//! Compilers emit obfuscated / size-bound C string literals as a run of
//! immediate-to-stack stores at adjacent offsets:
//!
//! ```asm
//! mov dword ptr [rbp-0x10], 0x6c6c6568   ; "hell"
//! mov dword ptr [rbp-0x0c], 0x6f6c6c     ; "llo\0"
//! ```
//!
//! IDA, BN, and Ghidra all reassemble that byte stream into the literal
//! it actually represents. We do the same: walk each function's
//! instructions, pattern-match the x86_64 `MOV [stack+disp], imm`
//! family, sort the captures by stack offset, then stitch adjacent
//! captures into a byte buffer. Buffers that contain ≥ 4 printable
//! ASCII bytes (and a NUL or natural break) get emitted as a pre-comment
//! at the address of the *first* store in the run.
//!
//! Only x86_64 today. The byte patterns we recognise (disp8 form):
//!
//! ```text
//!   C6 45 XX YY                 mov byte  [rbp+disp8], imm8
//!   66 C7 45 XX YY YY           mov word  [rbp+disp8], imm16
//!   C7 45 XX YY YY YY YY        mov dword [rbp+disp8], imm32
//!   48 C7 45 XX YY YY YY YY     mov qword [rbp+disp8], imm32  (sign-ext)
//!
//!   C6 44 24 XX YY              mov byte  [rsp+disp8], imm8
//!   66 C7 44 24 XX YY YY        mov word  [rsp+disp8], imm16
//!   C7 44 24 XX YY YY YY YY     mov dword [rsp+disp8], imm32
//!   48 C7 44 24 XX YY YY YY YY  mov qword [rsp+disp8], imm32  (sign-ext)
//! ```
//!
//! Larger displacements (disp32 ModR/M variants) are rare for inline
//! strings — those are off in DT_RODATA — and not handled here.

use gr_program::comments::CommentType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct StackStringAnalyzer;

impl Analyzer for StackStringAnalyzer {
    fn name(&self) -> &str {
        "Stack String"
    }
    fn description(&self) -> &str {
        "Reconstructs inline stack-allocated string literals from MOV imm runs"
    }
    fn priority(&self) -> u32 {
        // After StackFrame (350) so stack vars exist when we add the
        // comments; before CallSiteAnnotator (750) so the comment we
        // write doesn't clash with a call-site preview.
        650
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

        // Snapshot each function's body as a flat list of address
        // ranges. `AddressSet` keeps one range per basic block (or per
        // contiguous instruction), so we have to walk *every* range to
        // see the full body — taking just the first one only scans the
        // function prologue.
        let func_ranges: Vec<Vec<(u64, u64)>> = program
            .listing
            .functions()
            .map(|f| {
                f.body
                    .ranges()
                    .map(|r| (r.start.offset, r.start.offset + r.size))
                    .collect()
            })
            .collect();

        let mut pending: Vec<(u64, String)> = Vec::new();

        for ranges in &func_ranges {
            let mut captures: Vec<StackImmStore> = Vec::new();
            for (start, end) in ranges {
                for insn in program.listing.instructions_in_range(*start, *end) {
                    if let Some(cap) = parse_stack_imm_store(insn.address, &insn.bytes) {
                        captures.push(cap);
                    }
                }
            }
            for run in stitch_runs(&captures) {
                if let Some(text) = printable_preview(&run.bytes) {
                    pending.push((run.first_addr, format!("stack_string: \"{}\"", text)));
                }
            }
        }

        let mut emitted = 0usize;
        for (addr, text) in pending {
            if program.comments.get(addr, CommentType::Pre).is_some() {
                continue;
            }
            program.comments.set(addr, CommentType::Pre, text);
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

#[derive(Debug, Clone)]
struct StackImmStore {
    insn_addr: u64,
    /// Signed displacement from RBP or RSP, in bytes.
    disp: i32,
    /// Width of the store (1, 2, 4, or 8).
    width: u32,
    /// Bytes that are actually written to the stack at `disp..disp+width`.
    data: [u8; 8],
}

/// Recognise the eight `MOV [rbp/rsp+disp8], imm{8,16,32,32→64}`
/// encodings. Returns `None` for everything else; callers can keep
/// dispatching on instruction bytes safely.
fn parse_stack_imm_store(addr: u64, bytes: &[u8]) -> Option<StackImmStore> {
    // [rbp+disp8] forms — ModR/M = 0x45.
    if bytes.len() >= 4 && bytes[0] == 0xC6 && bytes[1] == 0x45 {
        return Some(make(addr, bytes[2] as i8 as i32, 1, &[bytes[3]]));
    }
    if bytes.len() >= 6 && bytes[0] == 0x66 && bytes[1] == 0xC7 && bytes[2] == 0x45 {
        return Some(make(addr, bytes[3] as i8 as i32, 2, &bytes[4..6]));
    }
    if bytes.len() >= 7 && bytes[0] == 0xC7 && bytes[1] == 0x45 {
        return Some(make(addr, bytes[2] as i8 as i32, 4, &bytes[3..7]));
    }
    if bytes.len() >= 8 && bytes[0] == 0x48 && bytes[1] == 0xC7 && bytes[2] == 0x45 {
        let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        return Some(make(addr, bytes[3] as i8 as i32, 8, &(imm as i64).to_le_bytes()));
    }

    // [rsp+disp8] forms — ModR/M = 0x44, SIB = 0x24.
    if bytes.len() >= 5 && bytes[0] == 0xC6 && bytes[1] == 0x44 && bytes[2] == 0x24 {
        return Some(make(addr, bytes[3] as i8 as i32, 1, &[bytes[4]]));
    }
    if bytes.len() >= 7
        && bytes[0] == 0x66
        && bytes[1] == 0xC7
        && bytes[2] == 0x44
        && bytes[3] == 0x24
    {
        return Some(make(addr, bytes[4] as i8 as i32, 2, &bytes[5..7]));
    }
    if bytes.len() >= 8 && bytes[0] == 0xC7 && bytes[1] == 0x44 && bytes[2] == 0x24 {
        return Some(make(addr, bytes[3] as i8 as i32, 4, &bytes[4..8]));
    }
    if bytes.len() >= 9
        && bytes[0] == 0x48
        && bytes[1] == 0xC7
        && bytes[2] == 0x44
        && bytes[3] == 0x24
    {
        let imm = i32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        return Some(make(addr, bytes[4] as i8 as i32, 8, &(imm as i64).to_le_bytes()));
    }
    None
}

fn make(addr: u64, disp: i32, width: u32, data: &[u8]) -> StackImmStore {
    let mut buf = [0u8; 8];
    let n = data.len().min(8);
    buf[..n].copy_from_slice(&data[..n]);
    StackImmStore {
        insn_addr: addr,
        disp,
        width,
        data: buf,
    }
}

struct StitchedRun {
    first_addr: u64,
    bytes: Vec<u8>,
}

/// Sort captures by displacement, then walk the sorted list and stitch
/// adjacent (`disp + width == next.disp`) entries into a single byte run.
/// We keep the *earliest* instruction address of each run because that's
/// where the user-facing comment belongs (top of the literal in program
/// order, not lowest stack offset).
fn stitch_runs(captures: &[StackImmStore]) -> Vec<StitchedRun> {
    if captures.is_empty() {
        return Vec::new();
    }
    let mut sorted = captures.to_vec();
    sorted.sort_by_key(|c| c.disp);

    let mut runs = Vec::new();
    let mut cur_bytes: Vec<u8> = Vec::new();
    let mut cur_addr: u64 = u64::MAX;
    let mut cur_next: i32 = i32::MIN;

    for c in &sorted {
        let extend = !cur_bytes.is_empty() && c.disp == cur_next;
        if !extend {
            if !cur_bytes.is_empty() {
                runs.push(StitchedRun {
                    first_addr: cur_addr,
                    bytes: std::mem::take(&mut cur_bytes),
                });
            }
            cur_addr = c.insn_addr;
        } else if c.insn_addr < cur_addr {
            cur_addr = c.insn_addr;
        }
        cur_bytes.extend_from_slice(&c.data[..c.width as usize]);
        cur_next = c.disp + c.width as i32;
    }
    if !cur_bytes.is_empty() {
        runs.push(StitchedRun {
            first_addr: cur_addr,
            bytes: cur_bytes,
        });
    }
    runs
}

/// Return a quoted preview of the run if it contains ≥ 4 printable
/// ASCII bytes (allowing `\n`, `\t`, `\r`) before the first NUL, and
/// the rest of the buffer up to NUL is also printable. Trailing NUL
/// terminator is required when the run is fully consumed without one.
fn printable_preview(bytes: &[u8]) -> Option<String> {
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if nul < 4 {
        return None;
    }
    let slice = &bytes[..nul];
    if !slice
        .iter()
        .all(|&b| (b' '..=b'~').contains(&b) || b == b'\n' || b == b'\t' || b == b'\r')
    {
        return None;
    }
    let mut out = String::with_capacity(slice.len());
    for &b in slice {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\r' => out.push_str("\\r"),
            _ => out.push(b as char),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mov_byte_rbp_disp8() {
        // C6 45 F8 41 :  mov byte ptr [rbp-8], 0x41
        let bytes = [0xC6, 0x45, 0xF8, 0x41];
        let cap = parse_stack_imm_store(0x1000, &bytes).unwrap();
        assert_eq!(cap.disp, -8);
        assert_eq!(cap.width, 1);
        assert_eq!(cap.data[0], 0x41);
    }

    #[test]
    fn parses_mov_dword_rbp_disp8() {
        // C7 45 F0 68 65 6C 6C  :  mov dword ptr [rbp-0x10], 0x6c6c6568 ("hell")
        let bytes = [0xC7, 0x45, 0xF0, 0x68, 0x65, 0x6C, 0x6C];
        let cap = parse_stack_imm_store(0x2000, &bytes).unwrap();
        assert_eq!(cap.disp, -16);
        assert_eq!(cap.width, 4);
        assert_eq!(&cap.data[..4], b"hell");
    }

    #[test]
    fn parses_mov_dword_rsp_disp8() {
        // C7 44 24 10 68 69 21 00 : mov dword ptr [rsp+0x10], 0x002169_68 ("hi!\0")
        let bytes = [0xC7, 0x44, 0x24, 0x10, 0x68, 0x69, 0x21, 0x00];
        let cap = parse_stack_imm_store(0x3000, &bytes).unwrap();
        assert_eq!(cap.disp, 0x10);
        assert_eq!(cap.width, 4);
        assert_eq!(&cap.data[..4], b"hi!\0");
    }

    #[test]
    fn rejects_unrelated_insn() {
        // 48 89 E5 : mov rbp, rsp
        assert!(parse_stack_imm_store(0x4000, &[0x48, 0x89, 0xE5]).is_none());
    }

    #[test]
    fn stitches_two_adjacent_dwords() {
        let a = make(0x100, -16, 4, b"hell");
        let b = make(0x107, -12, 4, b"o!\0\0");
        let runs = stitch_runs(&[a, b]);
        assert_eq!(runs.len(), 1);
        assert_eq!(&runs[0].bytes, b"hello!\0\0");
        assert_eq!(runs[0].first_addr, 0x100);
    }

    #[test]
    fn does_not_stitch_gap() {
        let a = make(0x100, -16, 4, b"hell");
        // gap at disp -12..-8: skip → starts new run.
        let b = make(0x110, -8, 4, b"abcd");
        let runs = stitch_runs(&[a, b]);
        assert_eq!(runs.len(), 2);
    }

    #[test]
    fn preview_requires_printable_run() {
        assert_eq!(printable_preview(b"hello\0").as_deref(), Some("hello"));
        assert!(printable_preview(b"hi\0").is_none()); // < 4 chars
        assert!(printable_preview(b"\x01\x02\x03hello\0").is_none()); // garbage prefix
    }

    #[test]
    fn preview_escapes_quote_and_newline() {
        assert_eq!(printable_preview(b"a\"b\nc\0").as_deref(), Some("a\\\"b\\nc"));
    }
}
