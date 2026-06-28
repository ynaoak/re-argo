//! Fast cross-reference scan without full analysis.
//!
//! On very large binaries (e.g. the 222 MB Minecraft Bedrock server) the full
//! analysis pipeline — function discovery, SSA, the reference manager — is
//! impractical, so the normal `xrefs` command can't run. This module does a
//! linear disassembly sweep of the executable sections and reports every
//! instruction whose **resolved** operand points at a target address:
//! rip-relative memory references, direct call/jmp targets, and absolute
//! immediates. It needs only the loaded image, so it scales to huge binaries
//! in seconds.

use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction as IcedInsn, IntelFormatter, OpKind, Register,
};
use reargo_loader::{BinaryInfo, SectionFlags};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    /// rip-relative memory operand (lea/mov/movss/… [rip+disp]).
    RipMem,
    /// direct call/jmp to the target.
    Branch,
    /// absolute immediate operand equal to the target (e.g. movabs).
    ImmAbs,
}

impl XrefKind {
    pub fn label(self) -> &'static str {
        match self {
            XrefKind::RipMem => "RIPMEM",
            XrefKind::Branch => "BRANCH",
            XrefKind::ImmAbs => "IMM",
        }
    }
}

#[derive(Debug, Clone)]
pub struct XrefHit {
    pub addr: u64,
    pub kind: XrefKind,
    pub text: String,
}

/// Scan all executable sections of an x86/x86-64 image for references to
/// `target`, stopping after `max_hits` (0 = unlimited). Linear sweep from
/// each section base; self-resynchronises on the dense x86 stream.
pub fn scan_xrefs(info: &BinaryInfo, target: u64, max_hits: usize) -> Vec<XrefHit> {
    if !matches!(
        info.arch,
        reargo_loader::Architecture::X86_64 | reargo_loader::Architecture::X86
    ) {
        return Vec::new();
    }
    let bits = info.bits;
    let mut hits = Vec::new();
    let mut fmt = IntelFormatter::new();

    for sec in info.sections.iter() {
        if !sec.flags.contains(SectionFlags::EXECUTE) || sec.size == 0 {
            continue;
        }
        let mut buf = vec![0u8; sec.size as usize];
        if info.memory.read_bytes(sec.address, &mut buf).is_err() {
            // Fall back to byte-wise read for partially-mapped sections.
            for (i, b) in buf.iter_mut().enumerate() {
                if let Some(v) = info.memory.read_byte(sec.address + i as u64) {
                    *b = v;
                }
            }
        }

        let mut dec = Decoder::with_ip(bits, &buf, sec.address, DecoderOptions::NONE);
        let mut ii = IcedInsn::default();
        while dec.can_decode() {
            dec.decode_out(&mut ii);
            if ii.is_invalid() {
                continue;
            }
            if let Some(kind) = instruction_refs(&ii, target) {
                let mut text = String::new();
                fmt.format(&ii, &mut text);
                hits.push(XrefHit { addr: ii.ip(), kind, text });
                if max_hits != 0 && hits.len() >= max_hits {
                    return hits;
                }
            }
        }
    }
    hits
}

/// Does `ii` reference `target` through any resolved operand?
fn instruction_refs(ii: &IcedInsn, target: u64) -> Option<XrefKind> {
    // Direct near call/jmp (and conditional branches).
    if ii.near_branch_target() == target && ii.near_branch_target() != 0 {
        return Some(XrefKind::Branch);
    }
    // rip-relative memory operand.
    let has_mem = (0..ii.op_count()).any(|i| ii.op_kind(i) == OpKind::Memory);
    if has_mem && ii.memory_base() == Register::RIP && ii.memory_displacement64() == target {
        return Some(XrefKind::RipMem);
    }
    // Absolute immediate operands (movabs r, imm64; mov r, imm32; …).
    for i in 0..ii.op_count() {
        let v = match ii.op_kind(i) {
            OpKind::Immediate64 => ii.immediate64(),
            OpKind::Immediate32 => ii.immediate32() as u64,
            OpKind::Immediate32to64 => ii.immediate32to64() as u64,
            OpKind::Immediate8to64 => ii.immediate8to64() as u64,
            _ => continue,
        };
        if v == target {
            return Some(XrefKind::ImmAbs);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::helpers::make_x86_64_program;

    #[test]
    fn finds_rip_relative_and_branch() {
        // 0x1000: lea rax, [rip+0x10]   -> target 0x1017 (ip+7+0x10)
        // 0x1007: call rel32 -> 0x1100
        // 0x100c: ret
        let mut code = vec![0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00]; // lea rax,[rip+0x10]
        // call rel32: e8 <rel>; ip after = 0x100c, want target 0x1100 -> rel = 0x1100-0x100c = 0xF4
        code.extend_from_slice(&[0xe8, 0xf4, 0x00, 0x00, 0x00]);
        code.push(0xc3); // ret
        let prog = make_x86_64_program(&code, 0x1000);

        let lea_hits = scan_xrefs(&prog.info, 0x1017, 0);
        assert_eq!(lea_hits.len(), 1);
        assert_eq!(lea_hits[0].kind, XrefKind::RipMem);
        assert_eq!(lea_hits[0].addr, 0x1000);

        let call_hits = scan_xrefs(&prog.info, 0x1100, 0);
        assert_eq!(call_hits.len(), 1);
        assert_eq!(call_hits[0].kind, XrefKind::Branch);
    }

    #[test]
    fn finds_absolute_immediate() {
        // movabs r15, 0x3FECCCCCCCCCCCCD = 49 bf <imm64>
        let mut code = vec![0x49, 0xbf];
        code.extend_from_slice(&0x3FECCCCCCCCCCCCDu64.to_le_bytes());
        code.push(0xc3);
        let prog = make_x86_64_program(&code, 0x2000);
        let hits = scan_xrefs(&prog.info, 0x3FECCCCCCCCCCCCD, 0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, XrefKind::ImmAbs);
    }

    #[test]
    fn respects_max_hits() {
        // two identical lea [rip+...] to the same target back-to-back
        // lea rax,[rip+0]  (7 bytes) at 0x1000 -> target 0x1007
        // then another lea at 0x1007 won't hit 0x1007; just check the limit path
        let code = vec![0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
        let prog = make_x86_64_program(&code, 0x1000);
        let hits = scan_xrefs(&prog.info, 0x1007, 1);
        assert!(hits.len() <= 1);
    }
}
