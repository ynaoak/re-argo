//! Find a function's entry from an interior address — without full analysis.
//!
//! On a multi-hundred-MB stripped binary the full function-discovery pipeline
//! is impractical, and an arbitrary `carve --start` window treats its own
//! first byte as a function entry (bisecting the real one). This recovers the
//! true x86-64 entry by scanning backward for a function boundary: a preceding
//! terminator (`ret`/`jmp`/`int3`) and/or alignment padding, after which a
//! candidate start whose linear disassembly reaches the query address on an
//! instruction boundary is the enclosing function.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction as IcedInsn};
use reargo_loader::{BinaryInfo, SectionFlags};

/// Find the entry of the function containing `addr` by backward scan, looking
/// at most `max_back` bytes earlier. Returns `None` if no plausible boundary
/// is found (then `addr` itself is the best guess).
pub fn find_function_start(info: &BinaryInfo, addr: u64, max_back: u64) -> Option<u64> {
    if !matches!(
        info.arch,
        reargo_loader::Architecture::X86_64 | reargo_loader::Architecture::X86
    ) {
        return None;
    }
    let bits = info.bits;
    // Bound the scan to the containing executable section.
    let sec = info
        .sections
        .iter()
        .find(|s| s.flags.contains(SectionFlags::EXECUTE) && addr >= s.address && addr < s.address + s.size)?;
    let lo = addr.saturating_sub(max_back).max(sec.address);

    // Read the window [lo, addr] once.
    let len = (addr - lo) as usize + 16;
    let mut buf = vec![0u8; len];
    if info.memory.read_bytes(lo, &mut buf).is_err() {
        for (i, b) in buf.iter_mut().enumerate() {
            if let Some(v) = info.memory.read_byte(lo + i as u64) {
                *b = v;
            }
        }
    }

    // A position `p` is the function entry iff (a) the byte before it ends a
    // function (ret/retf/int3/nop padding) — or it's the section start — and
    // (b) a linear decode p->addr is clean with no function boundary in
    // between. The true entry is the SMALLEST such `p` (earliest contiguous
    // body preceded by a boundary). Scan from addr downward, keep the smallest.
    let mut best: Option<u64> = None;
    let mut p = addr;
    loop {
        let off = (p - lo) as usize;
        let prev_is_boundary = off == 0 || matches!(buf[off - 1], 0xC3 | 0xCB | 0xCC | 0x90);
        if prev_is_boundary && linear_reaches(&buf[off..], p, addr, bits) {
            best = Some(p);
        }
        if p == lo {
            break;
        }
        p -= 1;
    }
    best
}

/// Does a linear disassembly starting at `start` (bytes = `code`) reach
/// `target` as an instruction boundary, with no function boundary (an invalid
/// op, or a `ret`/unconditional-jump landing at or before `target`) in
/// between? A terminator whose next ip is `<= target` means `start` belongs to
/// an earlier function, so `start` does not enclose `target`.
fn linear_reaches(code: &[u8], start: u64, target: u64, bits: u32) -> bool {
    if start == target {
        return true;
    }
    let mut dec = Decoder::with_ip(bits, code, start, DecoderOptions::NONE);
    let mut ii = IcedInsn::default();
    let mut ip = start;
    let mut steps = 0;
    while dec.can_decode() && ip < target && steps < 4096 {
        dec.decode_out(&mut ii);
        if ii.is_invalid() {
            return false;
        }
        ip = ii.next_ip();
        steps += 1;
        // Only a `ret` is a definitive function boundary. Unconditional jumps
        // are common *inside* a function (jump tables, loop back-edges, switch
        // fallthrough), so rejecting on them makes large functions unfindable —
        // accept them and rely on the `ret`-preceded entry + smallest-start
        // selection to pick the true boundary.
        if ii.flow_control() == FlowControl::Return && ip <= target {
            return false; // function boundary at/before target
        }
    }
    ip == target
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::helpers::make_x86_64_program;

    #[test]
    fn finds_entry_after_ret() {
        // 0x1000: ret (c3)               <- end of previous fn
        // 0x1001: push rbp; mov rbp,rsp  <- entry of our fn
        // 0x1005: xor eax,eax            <- query lands here
        // 0x1007: pop rbp; ret
        let code = vec![
            0xc3, // 0x1000 ret
            0x55, 0x48, 0x89, 0xe5, // 0x1001 push rbp; mov rbp,rsp
            0x31, 0xc0, // 0x1005 xor eax,eax
            0x5d, 0xc3, // pop rbp; ret
        ];
        let prog = make_x86_64_program(&code, 0x1000);
        let start = find_function_start(&prog.info, 0x1005, 0x100).unwrap();
        assert_eq!(start, 0x1001, "entry is right after the preceding ret");
    }

    #[test]
    fn finds_entry_across_internal_unconditional_jump() {
        // A function with an internal `jmp` (loop back-edge / switch) must
        // still be findable — the jmp is NOT a function boundary, only `ret` is.
        // 0x1000: ret                         (prev fn end)
        // 0x1001: xor eax,eax                 (entry)
        // 0x1003: jmp +2 (to 0x1007)          (internal unconditional jump)
        // 0x1005: int3; int3
        // 0x1007: nop                         (query here)
        // 0x1008: ret
        let code = vec![
            0xc3, // 0x1000 ret
            0x31, 0xc0, // 0x1001 xor eax,eax
            0xeb, 0x02, // 0x1003 jmp 0x1007
            0xcc, 0xcc, // 0x1005 int3 pad
            0x90, // 0x1007 nop  (query)
            0xc3, // 0x1008 ret
        ];
        let prog = make_x86_64_program(&code, 0x1000);
        let start = find_function_start(&prog.info, 0x1007, 0x100).unwrap();
        assert_eq!(start, 0x1001, "internal jmp must not block finding the entry");
    }

    #[test]
    fn query_at_entry_returns_entry() {
        let code = vec![0xc3, 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        let prog = make_x86_64_program(&code, 0x2000);
        let start = find_function_start(&prog.info, 0x2001, 0x100).unwrap();
        assert_eq!(start, 0x2001);
    }
}
