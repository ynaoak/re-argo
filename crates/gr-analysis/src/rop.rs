//! ROP gadget finder for x86 / x64 binaries.
//!
//! Walks every executable section, locates each `ret` (0xC3 / 0xC2
//! imm16), then disassembles backwards up to `max_depth` bytes to
//! enumerate the valid instruction sequences ending at that `ret`.
//! Output is the same shape as `ROPgadget` / `ropper`:
//!
//! ```text
//! 0x004012a0 : pop rdi ; ret
//! 0x004012a2 : pop rsi ; pop rdi ; ret
//! 0x00401300 : mov rax, qword ptr [rdi] ; ret
//! ```
//!
//! Only valid sequences are reported — invalid bytes, unknown
//! mnemonics, or control-flow ops other than `ret` in the middle of
//! a candidate window disqualify the window. `jmp` / `call` are also
//! excluded so gadgets stay "clean" (single ret terminator).
//!
//! Not wired into the analyzer pipeline because the cost scales with
//! `executable_bytes × max_depth × depth^2`. Exposed instead via the
//! `rop` CLI command which loads the binary, decodes on demand, and
//! prints / filters.

use std::collections::BTreeMap;

use gr_loader::{Architecture, BinaryInfo, SectionFlags};

/// Default search window — number of bytes preceding the `ret` we
/// try to disassemble backwards through. ROPgadget defaults to 5
/// instructions which fits comfortably inside this byte budget.
pub const DEFAULT_DEPTH: usize = 20;

/// Default maximum instructions in a gadget (excluding the ret).
pub const DEFAULT_MAX_INSNS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gadget {
    /// Address of the first instruction in the gadget.
    pub address: u64,
    /// Mnemonic strings joined by `" ; "` (matches ropper/ROPgadget).
    pub text: String,
}

#[derive(Debug, Clone, Copy)]
pub struct RopOptions {
    /// Bytes to walk back from each `ret`. Larger values find more
    /// gadgets at quadratic-ish cost.
    pub depth_bytes: usize,
    /// Maximum number of instructions in each gadget (not counting
    /// the trailing `ret`).
    pub max_insns: usize,
    /// When true, restrict to gadgets only made of "useful" mnemonics
    /// (pop / mov / xor / add / sub / push / xchg / lea / inc / dec).
    /// The vast majority of practical gadgets fall in this set; the
    /// flag prunes the inevitable garbage from raw `xx ret` byte runs.
    pub useful_only: bool,
}

impl Default for RopOptions {
    fn default() -> Self {
        Self {
            depth_bytes: DEFAULT_DEPTH,
            max_insns: DEFAULT_MAX_INSNS,
            useful_only: false,
        }
    }
}

/// Find ROP gadgets across every executable section of an x86 / x64
/// binary. Returns a sorted, de-duplicated list keyed by address.
/// Other architectures return an empty list — gadget hunting on
/// fixed-width RISC ISAs requires a different recipe and isn't worth
/// the maintenance burden until requested.
pub fn find_gadgets(info: &BinaryInfo, opts: RopOptions) -> Vec<Gadget> {
    let bitness = match info.arch {
        Architecture::X86 => 32,
        Architecture::X86_64 => 64,
        _ => return Vec::new(),
    };

    let mut by_addr: BTreeMap<u64, String> = BTreeMap::new();

    for section in &info.sections {
        if !section.flags.contains(SectionFlags::EXECUTE) {
            continue;
        }
        if section.size == 0 {
            continue;
        }
        let len = section.size as usize;
        let mut buf = vec![0u8; len];
        if info.memory.read_bytes(section.address, &mut buf).is_err() {
            continue;
        }

        for ret_pos in find_ret_positions(&buf) {
            let ret_len = ret_instruction_length(&buf[ret_pos..]);
            let max_back = ret_pos.min(opts.depth_bytes);

            for back in 1..=max_back {
                let candidate_start = ret_pos - back;
                let abs_addr = section.address + candidate_start as u64;
                let window = &buf[candidate_start..ret_pos + ret_len];
                if let Some(text) = try_decode_gadget(window, abs_addr, bitness, opts) {
                    by_addr.entry(abs_addr).or_insert(text);
                }
            }
        }
    }

    by_addr
        .into_iter()
        .map(|(address, text)| Gadget { address, text })
        .collect()
}

fn find_ret_positions(buf: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    for (i, &b) in buf.iter().enumerate() {
        // C3: ret. C2 imm16: ret with imm16 byte unwind.
        if b == 0xC3 || (b == 0xC2 && i + 2 < buf.len()) {
            out.push(i);
        }
    }
    out
}

fn ret_instruction_length(slice: &[u8]) -> usize {
    match slice.first() {
        Some(0xC3) => 1,
        Some(0xC2) => 3,
        _ => 1,
    }
}

fn try_decode_gadget(
    bytes: &[u8],
    address: u64,
    bitness: u32,
    opts: RopOptions,
) -> Option<String> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, Instruction};

    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut insns: Vec<String> = Vec::with_capacity(opts.max_insns + 1);
    let mut consumed = 0usize;
    let mut saw_ret = false;

    while decoder.can_decode() {
        if insns.len() > opts.max_insns {
            return None;
        }
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            return None;
        }
        let ilen = instruction.len();
        if ilen == 0 {
            return None;
        }

        let flow = instruction.flow_control();
        match flow {
            FlowControl::Return => {
                if consumed + ilen != bytes.len() {
                    return None;
                }
                if insns.is_empty() {
                    return None;
                }
                saw_ret = true;
                consumed += ilen;
                break;
            }
            FlowControl::Next => {}
            // Anything else (jmp, call, conditional, interrupt) makes
            // this a noisy "non-gadget".
            _ => return None,
        }

        let mut text = String::new();
        formatter.format_mnemonic(&instruction, &mut text);
        let opc = instruction.op_count();
        if opc > 0 {
            text.push(' ');
            for i in 0..opc {
                if i > 0 {
                    text.push_str(", ");
                }
                let _ = formatter.format_operand(&instruction, &mut text, i);
            }
        }
        if opts.useful_only && !is_useful_mnemonic(&text) {
            return None;
        }
        insns.push(text);
        consumed += ilen;
    }

    if !saw_ret || consumed != bytes.len() {
        return None;
    }

    insns.push("ret".into());
    Some(insns.join(" ; "))
}

fn is_useful_mnemonic(insn_text: &str) -> bool {
    let head = insn_text.split_whitespace().next().unwrap_or("");
    matches!(
        head,
        "pop" | "push" | "mov" | "xor" | "add" | "sub" | "and" | "or"
        | "xchg" | "lea" | "inc" | "dec" | "neg" | "not"
        | "shl" | "shr" | "sar" | "rol" | "ror"
        | "mul" | "imul" | "leave" | "nop"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x64() -> RopOptions {
        RopOptions::default()
    }

    #[test]
    fn pop_rdi_ret() {
        // 5F C3: pop rdi ; ret
        let bytes = [0x5Fu8, 0xC3];
        let g = try_decode_gadget(&bytes, 0x1000, 64, x64()).expect("gadget");
        assert_eq!(g, "pop rdi ; ret");
    }

    #[test]
    fn pop_rsi_pop_rdi_ret() {
        // 5E 5F C3: pop rsi ; pop rdi ; ret
        let bytes = [0x5E, 0x5F, 0xC3];
        let g = try_decode_gadget(&bytes, 0x2000, 64, x64()).expect("gadget");
        assert_eq!(g, "pop rsi ; pop rdi ; ret");
    }

    #[test]
    fn lone_ret_is_not_gadget() {
        // Standalone ret with no preceding insn is not interesting.
        let bytes = [0xC3];
        assert!(try_decode_gadget(&bytes, 0x3000, 64, x64()).is_none());
    }

    #[test]
    fn invalid_bytes_rejected() {
        // 0x06 is invalid in 64-bit mode.
        let bytes = [0x06, 0xC3];
        assert!(try_decode_gadget(&bytes, 0x4000, 64, x64()).is_none());
    }

    #[test]
    fn jmp_in_middle_rejected() {
        // EB 00 C3: jmp +0 ; ret — control flow in the middle, not a clean gadget.
        let bytes = [0xEB, 0x00, 0xC3];
        assert!(try_decode_gadget(&bytes, 0x5000, 64, x64()).is_none());
    }

    #[test]
    fn useful_only_filters_garbage() {
        // 5F C3 = pop rdi ; ret — passes useful filter.
        let opts = RopOptions { useful_only: true, ..Default::default() };
        let bytes = [0x5F, 0xC3];
        assert!(try_decode_gadget(&bytes, 0x6000, 64, opts).is_some());
    }
}
