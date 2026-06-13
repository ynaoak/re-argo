//! P-code-level reference recovery.
//!
//! The byte-scan analyzers (ScalarReference / DataReference /
//! StringReference) find 4-byte windows in raw instruction bytes
//! that look like pointers. That misses every x86_64 reference
//! emitted through rip-relative addressing -- in
//!
//!   lea rax, [rip + disp]    ; 48 8d 05 dd dd dd dd
//!
//! the bytes contain the 32-bit *offset* `disp`, NOT the absolute
//! target. On Minecraft / any large stripped 64-bit binary that's
//! the dominant way data is referenced, and the user-visible effect
//! is "`xrefs <data>` returns none even though the analyst can see
//! the lea by hand."
//!
//! This module recovers those references by walking the *lifted*
//! P-code -- after PR #21's fix the lifter folds rip+len+disp into
//! a CONST varnode, so a `Copy reg = CONST(addr)` or `Load/Store
//! [CONST(addr)]` is the resolved absolute address. We scan for
//! those constants, validate them against the section table, and
//! emit `DataRead` / `DataWrite` / `UnconditionalJump` references
//! the way the byte-scan analyzers would have if the address were
//! literally in the bytes.
//!
//! Same pattern as the existing parallel-collect / serial-apply
//! analyzers: per-function lift runs under rayon, then the apply
//! step writes into `program.references` serially.

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use reargo_lift::PcodeLift;
use reargo_loader::SectionFlags;
use reargo_program::reference::{RefType, Reference};
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

/// Section classification cached up-front so the per-instruction
/// filter is a tight tuple comparison instead of an O(sections)
/// linear scan with bitflag tests.
#[derive(Debug, Clone)]
struct SectionMap {
    /// (start, end, is_executable)
    ranges: Vec<(u64, u64, bool)>,
}

impl SectionMap {
    fn from(program: &Program) -> Self {
        let ranges = program
            .info
            .sections
            .iter()
            .filter(|s| s.size > 0 && s.address != 0)
            .map(|s| {
                (
                    s.address,
                    s.address + s.size,
                    s.flags.contains(SectionFlags::EXECUTE),
                )
            })
            .collect();
        Self { ranges }
    }

    /// `(in_section, in_executable_section)`.
    fn classify(&self, addr: u64) -> (bool, bool) {
        for &(s, e, exec) in &self.ranges {
            if addr >= s && addr < e {
                return (true, exec);
            }
        }
        (false, false)
    }
}

pub struct PcodeReferenceAnalyzer;

impl Analyzer for PcodeReferenceAnalyzer {
    fn name(&self) -> &str {
        "P-code Reference"
    }

    fn description(&self) -> &str {
        "Recovers references emitted via rip-relative addressing by walking lifted P-code (catches `lea reg, [rip+disp]` that byte-scan misses)"
    }

    fn priority(&self) -> u32 {
        // After the byte-scan analyzers (ScalarReference @ 300,
        // DataReference @ 500) so this pass's adds are deduped
        // against the cheaper scans rather than the other way round.
        510
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        // x86_64 only for now: the rip-relative gap is what motivates
        // the analyzer. ARM ADRP / ADR are already resolved to
        // absolute addresses by the capstone-backed lifter, so byte-
        // scan covers them. RISC-V / MIPS likewise.
        if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let lifter: Box<dyn PcodeLift> =
            Box::new(reargo_lift::x86::X86Lifter::new_64());
        let lifter = &*lifter;
        let sections = SectionMap::from(program);

        let entries: Vec<u64> = program
            .listing
            .functions()
            .map(|f| f.entry_point)
            .collect();

        // Phase 1 (parallel): per-function lift + scan. Each task
        // sees an immutable Program view and produces candidate
        // refs; no per-call mutation contention.
        let candidates: Vec<(u64, u64, RefType)> = entries
            .par_iter()
            .flat_map_iter(|&entry| scan_function(lifter, program, &sections, entry).into_iter())
            .collect();

        // Phase 2 (serial): dedup against existing refs and apply.
        let mut refs_found = 0usize;
        for (from, to, kind) in candidates {
            if program
                .references
                .get_refs_from(from)
                .iter()
                .any(|r| r.to == to && r.ref_type == kind)
            {
                continue;
            }
            program
                .references
                .add(Reference::new(from, to, kind));
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

/// Lift one function and return every `(from_insn_addr, target,
/// kind)` reference its P-code reveals.
fn scan_function(
    lifter: &dyn PcodeLift,
    program: &Program,
    sections: &SectionMap,
    entry: u64,
) -> Vec<(u64, u64, RefType)> {
    let func = match program.listing.get_function(entry) {
        Some(f) => f,
        None => return Vec::new(),
    };
    // Same sizing as the decompile path: floor at 500 so a tiny
    // discovery body still covers reachable lift.
    let max_insns = func
        .body
        .ranges()
        .map(|r| r.size as usize)
        .sum::<usize>()
        .max(500);
    let lifted = match lifter.lift_range(&program.info.memory, entry, max_insns) {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };

    let mut out: Vec<(u64, u64, RefType)> = Vec::new();
    for insn in &lifted {
        for op in &insn.ops {
            match op.opcode {
                // `lea reg, [absolute]` / `mov reg, &global` after
                // rip-relative resolution land here as a Copy whose
                // source is a CONST varnode holding the absolute
                // target.
                OpCode::Copy => {
                    if let Some(src) = op.inputs.first()
                        && src.space == SpaceId::CONST
                    {
                        emit_if_in_section(insn.address, src.offset, sections, &mut out);
                    }
                }
                // `mov reg, [rip+disp]` lifts to Load with the
                // address as input[1] (input[0] is the space-id
                // constant).
                OpCode::Load => {
                    if let Some(addr_vn) = op.inputs.get(1)
                        && addr_vn.space == SpaceId::CONST
                    {
                        emit_load_store(insn.address, addr_vn.offset, RefType::DataRead, sections, &mut out);
                    }
                }
                // `mov [rip+disp], reg` lifts to Store with the
                // address as input[1].
                OpCode::Store => {
                    if let Some(addr_vn) = op.inputs.get(1)
                        && addr_vn.space == SpaceId::CONST
                    {
                        emit_load_store(insn.address, addr_vn.offset, RefType::DataWrite, sections, &mut out);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Generic CONST -> reference emit for Copy-style ops. Classifies
/// based on whether the target is in an executable section.
fn emit_if_in_section(
    from: u64,
    to: u64,
    sections: &SectionMap,
    out: &mut Vec<(u64, u64, RefType)>,
) {
    let (in_sec, exec) = sections.classify(to);
    if !in_sec {
        return;
    }
    let kind = if exec {
        // A code-pointer load (callback addressed, vtable entry
        // taken, jump-table base, ...). Tag as UnconditionalJump:
        // it isn't a literal branch, but it's the same as what the
        // ScalarReferenceAnalyzer tags such constants as -- keeping
        // the convention so xref consumers stay consistent.
        RefType::UnconditionalJump
    } else {
        RefType::DataRead
    };
    out.push((from, to, kind));
}

fn emit_load_store(
    from: u64,
    to: u64,
    kind: RefType,
    sections: &SectionMap,
    out: &mut Vec<(u64, u64, RefType)>,
) {
    let (in_sec, _) = sections.classify(to);
    if !in_sec {
        return;
    }
    out.push((from, to, kind));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sections(ranges: &[(u64, u64, bool)]) -> SectionMap {
        SectionMap {
            ranges: ranges.to_vec(),
        }
    }

    #[test]
    fn classify_inside_data_section() {
        let s = make_sections(&[(0x400000, 0x500000, false)]);
        assert_eq!(s.classify(0x400010), (true, false));
    }

    #[test]
    fn classify_inside_exec_section() {
        let s = make_sections(&[(0x400000, 0x500000, true)]);
        assert_eq!(s.classify(0x400010), (true, true));
    }

    #[test]
    fn classify_outside() {
        let s = make_sections(&[(0x400000, 0x500000, false)]);
        assert_eq!(s.classify(0x100), (false, false));
        assert_eq!(s.classify(0x500000), (false, false)); // exclusive end
    }

    #[test]
    fn emit_data_load_when_in_data_section() {
        let s = make_sections(&[(0x400000, 0x500000, false)]);
        let mut out = Vec::new();
        emit_if_in_section(0x1000, 0x400100, &s, &mut out);
        assert_eq!(out, vec![(0x1000, 0x400100, RefType::DataRead)]);
    }

    #[test]
    fn emit_code_ptr_when_in_exec_section() {
        let s = make_sections(&[(0x400000, 0x500000, true)]);
        let mut out = Vec::new();
        emit_if_in_section(0x1000, 0x400100, &s, &mut out);
        assert_eq!(out, vec![(0x1000, 0x400100, RefType::UnconditionalJump)]);
    }

    #[test]
    fn emit_skips_non_section_targets() {
        let s = make_sections(&[(0x400000, 0x500000, false)]);
        let mut out = Vec::new();
        emit_if_in_section(0x1000, 0x1, &s, &mut out);
        assert!(out.is_empty());
    }
}
