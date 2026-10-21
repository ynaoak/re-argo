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
//! analyzers: per-function lift runs under rayon (neighbouring
//! functions sharing their lifted instructions, see `range_lift`),
//! then the apply step writes into `program.references` serially.

use rayon::prelude::*;
use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use reargo_lift::LiftedInstruction;
use reargo_loader::SectionFlags;
use reargo_program::reference::{RefType, Reference};
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, State};

/// Section classification cached up-front so the per-instruction
/// filter is a tight tuple comparison instead of an O(sections)
/// linear scan with bitflag tests.
#[derive(Debug, Clone)]
pub(crate) struct SectionMap {
    /// The starts of the intervals on which `classify` is constant, ascending, beginning at
    /// 0, with its answer on each (the first range in section order holding the address).
    starts: Vec<u64>,
    class: Vec<(bool, bool)>,
    /// The lowest start and highest end of the ranges.
    lo: u64,
    hi: u64,
}

impl SectionMap {
    pub(crate) fn from(program: &Program) -> Self {
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
        Self::of_ranges(ranges)
    }

    /// `ranges`: (start, end, is_executable).
    fn of_ranges(ranges: Vec<(u64, u64, bool)>) -> Self {
        let lo = ranges.iter().map(|r| r.0).min().unwrap_or(0);
        let hi = ranges.iter().map(|r| r.1).max().unwrap_or(0);
        // the answer changes only at a range's start or end: one interval per boundary
        let mut starts: Vec<u64> = std::iter::once(0).chain(ranges.iter().flat_map(|r| [r.0, r.1])).collect();
        starts.sort_unstable();
        starts.dedup();
        let first_holding = |addr: u64| {
            ranges.iter().find(|&&(s, e, _)| addr >= s && addr < e).map_or((false, false), |&(_, _, exec)| (true, exec))
        };
        let class = starts.iter().map(|&b| first_holding(b)).collect();
        Self { starts, class, lo, hi }
    }

    /// Whether `addr` is in a section (`classify(addr).0`).
    #[inline]
    fn contains(&self, addr: u64) -> bool {
        addr >= self.lo && addr < self.hi && self.classify(addr).0
    }

    /// `(in_section, in_executable_section)`: of the first range (in section order) that
    /// holds `addr`.
    fn classify(&self, addr: u64) -> (bool, bool) {
        // (`starts[0]` is 0: an interval holds every address)
        self.class[self.starts.partition_point(|&b| b <= addr) - 1]
    }
}

pub struct PcodeReferenceAnalyzer;

impl Analyzer for PcodeReferenceAnalyzer {
    fn writes(&self) -> State {
        State::REFERENCES.union(State::CACHE)
    }
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

        let tt = std::time::Instant::now();
        let sections = SectionMap::from(program);

        let jobs: Vec<(u64, usize)> = crate::func_lift::map_functions(program, |f| (f.entry_point, budget(f)));
        crate::tr!(tt, "pcoderef jobs {}", jobs.len());

        // Phase 1 (parallel): per-function lift + scan. Each task
        // sees an immutable Program view and produces candidate
        // refs; no per-call mutation contention. Neighbouring
        // functions' lifts overlap, so they share lifted instructions.
        // A function's candidates depend only on its lift and the
        // sections: those the Stack Frame analyzer computed ahead
        // ([`Ahead`]) for the same lift are taken as they are.
        let ahead = program.analysis_cache.take::<Ahead>().map(|a| a.0);
        crate::tr!(tt, "pcoderef ahead {}", ahead.as_ref().map_or(0, |a| a.len()));
        let candidates: Vec<(u64, u64, RefType)> = crate::range_lift::with_ahead(&jobs, ahead, |missing| {
            crate::tr!(tt, "pcoderef missing {} budget {}", missing.len(), missing.iter().map(|m| m.1).sum::<usize>());
            crate::range_lift::map_lifted_ranges(&program.info.memory, missing, |_, insns| {
                scan_lifted(insns, &sections)
            })
        })
        .into_iter()
        .flatten()
        .collect();

        crate::tr!(tt, "pcoderef candidates {}", candidates.len());
        // Phase 2: dedup against existing refs and apply — each candidate
        // added unless a reference from its source to its target of its
        // kind is there (before, or added for an earlier candidate): the
        // first of each that is not there before, in order, in bulk.
        let references = &program.references;
        let present: Vec<bool> = candidates
            .par_iter()
            .with_min_len(4096)
            .map(|&(from, to, kind)| references.get_refs_from(from).iter().any(|r| r.to == to && r.ref_type == kind))
            .collect();
        crate::tr!(tt, "pcoderef present");
        let mut seen: rustc_hash::FxHashSet<(u64, u64, RefType)> = rustc_hash::FxHashSet::default();
        let added: Vec<Reference> = candidates
            .into_iter()
            .zip(present)
            .filter(|&(c, present)| !present && seen.insert(c))
            .map(|((from, to, kind), _)| Reference::new(from, to, kind))
            .collect();
        let refs_found = added.len();
        crate::tr!(tt, "pcoderef seen {}", added.len());
        program.references.add_all(&added);
        crate::tr!(tt, "pcoderef added");

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: refs_found,
            instructions_decoded: 0,
        })
    }
}

/// The instructions lifted from a function's entry: same sizing as the
/// decompile path, floored at 500 so a tiny discovery body still covers
/// reachable lift.
pub(crate) fn budget(f: &reargo_program::function::Function) -> usize {
    crate::func_lift::body_size(f).max(500)
}

/// [`scan_lifted`] of functions, computed ahead of this analyzer from
/// the same lift, by `(entry, budget)`.
pub(crate) struct Ahead(pub crate::range_lift::AheadMap<Vec<(u64, u64, RefType)>>);

/// Every `(from_insn_addr, target, kind)` reference the P-code of
/// one function's lifted range reveals.
pub(crate) fn scan_lifted(lifted: &[&LiftedInstruction], sections: &SectionMap) -> Vec<(u64, u64, RefType)> {
    let mut out: Vec<(u64, u64, RefType)> = Vec::new();
    for insn in lifted {
        scan_insn(insn, sections, &mut out);
    }
    out
}

/// [`scan_lifted`] of a range from a lift cache: an instruction not lifted
/// yet is lifted only when its decode shows a constant in a section that
/// its lift may hold where the scan reads one (else it adds nothing).
pub(crate) fn scan_range(insns: &[reargo_lift::x86::RangeInsn], sections: &SectionMap) -> Vec<(u64, u64, RefType)> {
    let mut out: Vec<(u64, u64, RefType)> = Vec::new();
    let keep = reargo_lift::x86::ConstKeep::new(|c| sections.contains(c));
    for insn in insns {
        if let Some(insn) = insn.lifted_unless_no_const(&keep) {
            scan_insn(insn, sections, &mut out);
        }
    }
    out
}

/// The references of one instruction's P-code (added to `out`).
fn scan_insn(insn: &LiftedInstruction, sections: &SectionMap, out: &mut Vec<(u64, u64, RefType)>) {
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
                    emit_if_in_section(insn.address, src.offset, sections, out);
                }
            }
            // `mov reg, [rip+disp]` lifts to Load with the
            // address as input[1] (input[0] is the space-id
            // constant).
            OpCode::Load => {
                if let Some(addr_vn) = op.inputs.get(1)
                    && addr_vn.space == SpaceId::CONST
                {
                    emit_load_store(insn.address, addr_vn.offset, RefType::DataRead, sections, out);
                }
            }
            // `mov [rip+disp], reg` lifts to Store with the
            // address as input[1].
            OpCode::Store => {
                if let Some(addr_vn) = op.inputs.get(1)
                    && addr_vn.space == SpaceId::CONST
                {
                    emit_load_store(insn.address, addr_vn.offset, RefType::DataWrite, sections, out);
                }
            }
            _ => {}
        }
    }
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
        SectionMap::of_ranges(ranges.to_vec())
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
    fn classify_matches_first_holding_range() {
        let ranges = vec![(0x1000, 0x2000, false), (0x1800, 0x3000, true), (0x2800, 0x2900, false), (0x5000, 0x5000, true), (0x4000, 0x4800, true), (0x4800, 0x5000, false)];
        let s = SectionMap::of_ranges(ranges.clone());
        for a in (0..0x6000u64).step_by(3).chain([0, 0xfff, 0x1000, 0x17ff, 0x1800, 0x1fff, 0x2000, 0x27ff, 0x2800, 0x28ff, 0x2900, 0x2fff, 0x3000, 0x47ff, 0x4800, 0x4fff, 0x5000, u64::MAX]) {
            let want = ranges.iter().find(|&&(s, e, _)| a >= s && a < e).map_or((false, false), |&(_, _, x)| (true, x));
            assert_eq!(s.classify(a), want, "{a:#x}");
        }
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
