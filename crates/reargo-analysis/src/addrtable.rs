//! Address-table recovery: scan data sections for runs of in-section
//! pointers (vtables, function-pointer tables, jump tables, string
//! tables, callback registries) and emit a reference per entry.
//!
//! This is the static-analysis half of Ghidra's `AddressTableAnalyzer`.
//! Two motivations:
//!
//! 1. The PR #24 P-code reference analyzer catches `lea reg, [&sym]`
//!    -- the *load* of a single pointer. But callback registries
//!    and C++ vtables sit in `.rodata` / `.data.rel.ro` as bare
//!    arrays of function addresses with nothing in the code pointing
//!    at them other than (eventually) an indirect call. Without this
//!    scanner, `xrefs <function>` returns "none" even though the
//!    function's address sits literally in `.rodata[N..N+8]`.
//!
//! 2. The user-report case "noise registered into a parser table at
//!    0xca3a000": the table itself is bytes, and the byte-scan
//!    `DataReferenceAnalyzer` only fires on a code-instruction
//!    operand. The table entries are NOT code; they are addresses
//!    sitting in data, and only this analyzer sees them.
//!
//! Output: one `Reference` per recognised table entry. From-address
//! is the entry's location in memory (so `xrefs entry_addr` shows
//! the table location); to-address is the resolved target; kind is
//! `UnconditionalJump` for code targets (vtable / callback / jump
//! table) or `DataRead` for data targets (string table / globals
//! array). Same convention as `ScalarReferenceAnalyzer` so xref
//! consumers stay consistent.

use reargo_loader::SectionFlags;
use reargo_program::reference::{RefType, Reference};
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

/// Minimum number of consecutive in-section pointers to accept as a
/// "table". Three entries is short enough to catch tiny callback
/// arrays and long enough to keep noise (a single stored pointer
/// surrounded by floats) out of the result.
const MIN_TABLE_LEN: usize = 3;

/// Don't classify low addresses as pointers even if a section
/// nominally starts at 0 -- they're typically counts / flags. Ghidra
/// uses 0x1000 as the default low-address cutoff for the same reason.
const MIN_VALID_ADDR: u64 = 0x1000;

pub struct AddressTableAnalyzer;

impl Analyzer for AddressTableAnalyzer {
    fn name(&self) -> &str {
        "Address Table"
    }

    fn description(&self) -> &str {
        "Detects runs of in-section pointers in data sections (vtables, callback tables, jump tables) and emits a reference per entry"
    }

    fn priority(&self) -> u32 {
        // After PcodeReferenceAnalyzer (510) so its byte-level adds
        // are deduped against the per-instruction P-code refs.
        520
    }

    fn prepare_reads(&self) -> Option<State> {
        Some(State::NONE)
    }
    fn writes(&self) -> State {
        State::REFERENCES
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    fn prepare(&self, program: &Program) -> Prepared {
        let ptr_size = (program.info.bits / 8) as u64;
        if !(ptr_size == 4 || ptr_size == 8) {
            return Box::new(Vec::<(u64, u64, RefType)>::new());
        }

        // Section classification cache: (start, end, is_executable).
        // Used both to enumerate candidate-bearing data sections and
        // to classify resolved target addresses.
        let sections: Vec<(u64, u64, bool)> = program
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

        // Tables live in non-executable sections (.rodata / .data /
        // .data.rel.ro / .bss is mostly zero so it's filtered later
        // by the read step). Don't scan code sections for tables --
        // those are mostly instructions and would produce massive
        // false positives.
        let data_sections: Vec<(u64, u64)> = sections
            .iter()
            .filter(|(_, _, exec)| !exec)
            .map(|(s, e, _)| (*s, *e))
            .collect();

        // Phase 1 (parallel): scan each data section for table runs
        // and emit candidate refs against an immutable Program view.
        let candidates: Vec<(u64, u64, RefType)> = data_sections
            .par_iter()
            .flat_map_iter(|&(start, end)| {
                scan_section(program, start, end, ptr_size, &sections).into_iter()
            })
            .collect();

        // Phase 2 (serial): dedup against existing refs and apply.
        Box::new(candidates)
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let candidates: Vec<(u64, u64, RefType)> = crate::analyzer::prepared(prepared);
        let mut refs_found = 0usize;
        for (from, to, kind) in candidates {
            if program.references.add_unless(Reference::new(from, to, kind), |r| r.to == to && r.ref_type == kind) {
                refs_found += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: refs_found,
            instructions_decoded: 0,
        })
    }
}

/// Walk one section looking for consecutive in-section pointer runs.
fn scan_section(
    program: &Program,
    start: u64,
    end: u64,
    ptr_size: u64,
    sections: &[(u64, u64, bool)],
) -> Vec<(u64, u64, RefType)> {
    let mut out: Vec<(u64, u64, RefType)> = Vec::new();
    // Step by pointer size, aligned. Tables are virtually always
    // pointer-aligned in real binaries (ABI / linker enforce this).
    let first = (start + ptr_size - 1) & !(ptr_size - 1);
    // The slots `first + k * ptr_size` that end by `end`.
    let n = end.saturating_sub(first) / ptr_size;
    // What `read_ptr` reads at slot `k`: from one slice of the section's block when it
    // holds them all (the same bytes, see `Memory::slice`), else slot by slot.
    let memory = &program.info.memory;
    let bytes = memory.slice(first, n * ptr_size).filter(|_| n > 0);
    let big = matches!(memory.endian(), reargo_core::address::Endian::Big);
    let read = |k: u64| -> Option<u64> {
        let val = match bytes {
            Some(b) => {
                let at = (k * ptr_size) as usize;
                if ptr_size == 8 {
                    let w: [u8; 8] = b[at..at + 8].try_into().unwrap();
                    if big { u64::from_be_bytes(w) } else { u64::from_le_bytes(w) }
                } else {
                    let w: [u8; 4] = b[at..at + 4].try_into().unwrap();
                    u64::from(if big { u32::from_be_bytes(w) } else { u32::from_le_bytes(w) })
                }
            }
            None => return read_ptr(program, first + k * ptr_size, ptr_size),
        };
        (val >= MIN_VALID_ADDR).then_some(val)
    };
    // `is_section_addr`: a binary search over the sections' ranges merged
    let merged = merge_ranges(sections);
    let in_sections = |a: u64| {
        let i = merged.partition_point(|&(s, _)| s <= a);
        i > 0 && a < merged[i - 1].1
    };

    let mut i = 0u64;
    while i + MIN_TABLE_LEN as u64 <= n {
        // Try to collect a run starting here. `read` returns
        // Option<u64>, with None for "couldn't read" or "below the
        // low-address cutoff" -- a NULL or junk entry ends the run.
        let mut run_len = 0u64;
        while i + run_len < n {
            let Some(val) = read(i + run_len) else {
                break;
            };
            if !in_sections(val) {
                break;
            }
            run_len += 1;
        }

        if run_len >= MIN_TABLE_LEN as u64 {
            // Emit one reference per entry.
            for k in i..i + run_len {
                // Safe to unwrap: we just verified read above.
                let val = read(k).unwrap();
                let kind = ref_kind_for(val, sections);
                out.push((first + k * ptr_size, val, kind));
            }
            i += run_len;
        } else {
            // Slide forward one pointer slot. We don't try every
            // byte offset -- pointer-misaligned tables are very rare
            // in practice and the false-positive cost of unaligned
            // scanning is high.
            i += 1;
        }
    }
    out
}

/// The union of the sections' `[s, e)` ranges, sorted and merged.
fn merge_ranges(sections: &[(u64, u64, bool)]) -> Vec<(u64, u64)> {
    let mut raw: Vec<(u64, u64)> = sections.iter().map(|&(s, e, _)| (s, e)).filter(|(s, e)| s < e).collect();
    raw.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(raw.len());
    for (s, e) in raw {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

/// Read a pointer of `ptr_size` bytes from `addr`. Returns None for
/// read failure, NULL, or "obviously not a pointer" (below the
/// low-address cutoff).
fn read_ptr(program: &Program, addr: u64, ptr_size: u64) -> Option<u64> {
    let val = match ptr_size {
        4 => program.info.memory.read_u32(addr).ok()? as u64,
        8 => program.info.memory.read_u64(addr).ok()?,
        _ => return None,
    };
    if val < MIN_VALID_ADDR {
        return None;
    }
    Some(val)
}

#[cfg(test)]
fn is_section_addr(addr: u64, sections: &[(u64, u64, bool)]) -> bool {
    sections
        .iter()
        .any(|&(s, e, _)| addr >= s && addr < e)
}

fn ref_kind_for(addr: u64, sections: &[(u64, u64, bool)]) -> RefType {
    let exec = sections
        .iter()
        .any(|&(s, e, exec)| exec && addr >= s && addr < e);
    if exec {
        // Function-pointer table entry -- treat the same way the
        // PcodeReferenceAnalyzer / ScalarReferenceAnalyzer tag a
        // code-section CONST so callers of `xrefs <function>` get
        // the table entry alongside any direct calls.
        RefType::UnconditionalJump
    } else {
        RefType::DataRead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sections() -> Vec<(u64, u64, bool)> {
        vec![
            (0x1000, 0x2000, true),   // code
            (0x2000, 0x3000, false),  // data
            (0x3000, 0x4000, false),  // more data
        ]
    }

    #[test]
    fn classify_code_pointer_as_jump() {
        assert_eq!(ref_kind_for(0x1100, &make_sections()), RefType::UnconditionalJump);
    }

    #[test]
    fn classify_data_pointer_as_dataread() {
        assert_eq!(ref_kind_for(0x2100, &make_sections()), RefType::DataRead);
    }

    #[test]
    fn is_section_addr_inside() {
        assert!(is_section_addr(0x1500, &make_sections()));
        assert!(is_section_addr(0x2999, &make_sections()));
    }

    #[test]
    fn merged_ranges_match_any_section() {
        let sections = vec![(0x1000, 0x2000, true), (0x1800, 0x2800, false), (0x3000, 0x3000, false), (0x3000, 0x3100, false), (0x3100, 0x3200, true), (0x500, 0x600, false)];
        let merged = merge_ranges(&sections);
        for a in (0..0x4000u64).step_by(7).chain([0x5ff, 0x600, 0x1fff, 0x2000, 0x27ff, 0x2800, 0x30ff, 0x3100, 0x31ff, 0x3200]) {
            let i = merged.partition_point(|&(s, _)| s <= a);
            assert_eq!(i > 0 && a < merged[i - 1].1, is_section_addr(a, &sections), "{a:#x}");
        }
    }

    #[test]
    fn is_section_addr_outside() {
        assert!(!is_section_addr(0x100, &make_sections()));
        assert!(!is_section_addr(0x4000, &make_sections())); // exclusive end
        assert!(!is_section_addr(0x9000, &make_sections()));
    }
}
