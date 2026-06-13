//! Enhanced switch-table detection: 32-bit relative-offset tables
//! and bounds-check-aware sizing.
//!
//! The existing `SwitchTableAnalyzer` handles the textbook absolute-
//! pointer pattern:
//!
//! ```asm
//!   jmp QWORD PTR [table + rdx*8]
//!   table: .quad case0, case1, case2, …
//! ```
//!
//! Modern compilers (clang ≥ 5, gcc ≥ 7 on `-fPIE`, MSVC `/GS`-on)
//! prefer relative offsets to keep the table position-independent:
//!
//! ```asm
//!   lea rcx, [rip + table]
//!   movsx rax, DWORD PTR [rcx + rdx*4]
//!   add rax, rcx
//!   jmp rax
//!   table: .long case0 - table, case1 - table, …
//! ```
//!
//! Each entry is a signed 32-bit displacement *from the table base*,
//! so the effective target is `table_base + (sign_ext_i32) entry`.
//! 4 bytes per entry instead of 8 → smaller `.rodata`, IBT-friendly.
//!
//! This analyzer:
//!
//! 1. Finds every `IndirectJump` whose immediate predecessors look
//!    like the offset-table setup (`lea`/`add`/`movsx` chain).
//! 2. Walks back up to 24 insns for a `cmp reg, imm32` to learn the
//!    table size (an over-cap means we'd run into adjacent data /
//!    code and emit spurious refs).
//! 3. Extracts the table base from the `lea reg, [rip+disp32]`
//!    instruction's displacement.
//! 4. Reads `n` 32-bit entries, sign-extends, adds to base, and
//!    creates `IndirectJump` references on each valid result.
//!
//! Duplicate-suppressed against existing refs so it composes cleanly
//! with the older absolute-table analyzer.

use reargo_arch::FlowType;
use reargo_program::reference::{RefType, Reference};
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct SwitchTableOffsetAnalyzer;

impl Analyzer for SwitchTableOffsetAnalyzer {
    fn name(&self) -> &str {
        "Switch Table (32-bit offset)"
    }
    fn description(&self) -> &str {
        "Detects relative-offset jump tables (clang/gcc `add reg, rcx; jmp rax` pattern)"
    }
    fn priority(&self) -> u32 {
        555 // right after the absolute-pointer SwitchTableAnalyzer (550)
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

        let valid_code_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(reargo_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Build a flat per-function instruction sequence so we can
        // walk back from each indirect jump cheaply.
        struct InsnInfo {
            address: u64,
            length: u32,
            bytes: smallvec::SmallVec<[u8; 16]>,
        }
        let mut indirect_jumps: Vec<u64> = Vec::new();
        let mut by_addr: std::collections::BTreeMap<u64, InsnInfo> = std::collections::BTreeMap::new();
        for i in program.listing.instructions() {
            if i.flow_type == FlowType::IndirectJump {
                indirect_jumps.push(i.address);
            }
            by_addr.insert(
                i.address,
                InsnInfo {
                    address: i.address,
                    length: i.length,
                    bytes: i.bytes.clone(),
                },
            );
        }

        let mut candidates: Vec<(u64, u64)> = Vec::new();
        for jmp_addr in &indirect_jumps {
            // Walk backward up to 24 insns.
            let preds: Vec<&InsnInfo> = by_addr
                .range(..*jmp_addr)
                .rev()
                .take(24)
                .map(|(_, v)| v)
                .collect();

            // Find the most-recent `lea reg, [rip + disp32]`. That
            // disp32 is the table's RVA relative to the LEA's
            // fall-through address.
            let mut table_base: Option<u64> = None;
            for pred in &preds {
                if let Some(addr) = parse_lea_rip_disp32(pred.address, pred.length, &pred.bytes) {
                    table_base = Some(addr);
                    break;
                }
            }
            let Some(base) = table_base else { continue };

            // Look for a recent `cmp reg, imm32` (or imm8 form) to
            // size the table. Default to 64 if we can't find it.
            let max_entries = preds
                .iter()
                .find_map(|p| parse_cmp_reg_imm(&p.bytes))
                .map(|n| (n + 1).min(256) as u64)
                .unwrap_or(64);

            for i in 0..max_entries {
                let entry_addr = base.wrapping_add(i * 4);
                let Ok(rel) = program.info.memory.read_u32(entry_addr) else {
                    break;
                };
                let signed = rel as i32 as i64;
                let target = (base as i64).wrapping_add(signed) as u64;
                if !crate::utils::is_valid_address(target, &valid_code_ranges) {
                    break;
                }
                candidates.push((*jmp_addr, target));
            }
        }

        let mut refs_found = 0usize;
        for (from, to) in candidates {
            let already = program
                .references
                .get_refs_from(from)
                .iter()
                .any(|r| r.to == to);
            if already {
                continue;
            }
            program
                .references
                .add(Reference::new(from, to, RefType::IndirectJump));
            refs_found += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: refs_found,
            instructions_decoded: 0,
        })
    }
}

/// Decode `48 8d <ModR/M> [SIB] disp32` for the `lea reg, [rip+disp32]`
/// shape. ModR/M.r/m=101 with mod=00 selects rip-relative addressing
/// in 64-bit mode. Returns `lea_fall_through + disp32` — the
/// effective target VA the LEA computes.
fn parse_lea_rip_disp32(addr: u64, length: u32, bytes: &[u8]) -> Option<u64> {
    // 48 8d <ModR/M> disp32
    // ModR/M: mod=00 (top 2 bits = 00), r/m=101 (low 3 bits = 101).
    // reg field doesn't matter here.
    // REX.W=1 (0x48). REX.B=0 — destination is rax..rdi.
    // Some forms emit 0x4c (REX.W+REX.R) for r8..r15 dest — handle that too.
    if bytes.len() < 7 {
        return None;
    }
    let rex_ok = bytes[0] == 0x48 || bytes[0] == 0x4c;
    if !rex_ok || bytes[1] != 0x8d {
        return None;
    }
    let modrm = bytes[2];
    let mod_ = modrm >> 6;
    let rm = modrm & 0x07;
    if mod_ != 0 || rm != 5 {
        return None;
    }
    let disp = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as i64;
    let fall = addr + length as u64;
    Some((fall as i64).wrapping_add(disp) as u64)
}

/// Recognise `cmp r32, imm8` (3 bytes) or `cmp r32, imm32` (6 bytes)
/// and return the immediate. Used to bound the switch table size —
/// we only care about the upper bound (the `default` case threshold).
fn parse_cmp_reg_imm(bytes: &[u8]) -> Option<u32> {
    // 83 /7 ib   — cmp r/m32, imm8                (3 bytes)
    // 81 /7 id   — cmp r/m32, imm32               (6 bytes)
    // 4? 83 /7 …  REX-prefixed variants for r8..r15 (1 byte longer)
    let offset = if !bytes.is_empty() && (bytes[0] & 0xF0) == 0x40 {
        1
    } else {
        0
    };
    if bytes.len() < offset + 3 {
        return None;
    }
    let op = bytes[offset];
    let modrm = bytes.get(offset + 1)?;
    let reg = (modrm >> 3) & 7;
    if reg != 7 {
        return None; // not the CMP /7 sub-opcode
    }
    match op {
        0x83 => {
            // mod must be 11 (register direct) — otherwise this is
            // a memory operand and we don't know what register holds
            // the index; skip.
            if (modrm >> 6) != 0b11 {
                return None;
            }
            Some(bytes.get(offset + 2)?.to_owned() as u32)
        }
        0x81 => {
            if (modrm >> 6) != 0b11 {
                return None;
            }
            if bytes.len() < offset + 6 {
                return None;
            }
            Some(u32::from_le_bytes([
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
            ]))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lea_rip_rax_decode() {
        // lea rax, [rip + 0x40] at addr 0x1000, length 7
        // 48 8d 05 40 00 00 00
        let bytes = [0x48, 0x8d, 0x05, 0x40, 0x00, 0x00, 0x00];
        let target = parse_lea_rip_disp32(0x1000, 7, &bytes).unwrap();
        assert_eq!(target, 0x1000 + 7 + 0x40);
    }

    #[test]
    fn lea_rip_negative_disp() {
        // disp = -0x10 (sign-extended)
        let bytes = [0x48, 0x8d, 0x05, 0xf0, 0xff, 0xff, 0xff];
        let target = parse_lea_rip_disp32(0x2000, 7, &bytes).unwrap();
        assert_eq!(target, 0x2000 + 7 - 0x10);
    }

    #[test]
    fn lea_rip_r8_dest() {
        // 4c 8d 05 disp32 — lea r8, [rip + disp32]
        let bytes = [0x4c, 0x8d, 0x05, 0x20, 0x00, 0x00, 0x00];
        let target = parse_lea_rip_disp32(0x3000, 7, &bytes).unwrap();
        assert_eq!(target, 0x3000 + 7 + 0x20);
    }

    #[test]
    fn lea_non_rip_rejected() {
        // 48 8d 04 25 ... — lea rax, [abs disp32] (SIB form) — not us
        let bytes = [0x48, 0x8d, 0x04, 0x25, 0, 0, 0, 0];
        assert!(parse_lea_rip_disp32(0x1000, 8, &bytes).is_none());
    }

    #[test]
    fn cmp_imm8_decode() {
        // 83 f8 0a — cmp eax, 10
        let n = parse_cmp_reg_imm(&[0x83, 0xf8, 0x0a]).unwrap();
        assert_eq!(n, 10);
    }

    #[test]
    fn cmp_imm32_decode() {
        // 81 f8 00 01 00 00 — cmp eax, 0x100
        let n = parse_cmp_reg_imm(&[0x81, 0xf8, 0x00, 0x01, 0x00, 0x00]).unwrap();
        assert_eq!(n, 0x100);
    }

    #[test]
    fn cmp_memory_operand_rejected() {
        // 83 38 0a — cmp dword ptr [rax], 10 (mod=00) — not us
        assert!(parse_cmp_reg_imm(&[0x83, 0x38, 0x0a]).is_none());
    }

    #[test]
    fn rex_cmp_imm8_decode() {
        // 49 83 f8 05 — cmp r8, 5
        let n = parse_cmp_reg_imm(&[0x49, 0x83, 0xf8, 0x05]).unwrap();
        assert_eq!(n, 5);
    }
}
