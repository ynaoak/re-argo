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

use gr_loader::SectionFlags;
use gr_program::reference::{RefType, Reference};
use gr_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

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

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let ptr_size = (program.info.bits / 8) as u64;
        if !(ptr_size == 4 || ptr_size == 8) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
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

/// Walk one section looking for consecutive in-section pointer runs.
fn scan_section(
    program: &Program,
    start: u64,
    end: u64,
    ptr_size: u64,
    sections: &[(u64, u64, bool)],
) -> Vec<(u64, u64, RefType)> {
    let mut out: Vec<(u64, u64, RefType)> = Vec::new();
    let mut addr = start;
    // Step by pointer size, aligned. Tables are virtually always
    // pointer-aligned in real binaries (ABI / linker enforce this).
    addr = (addr + ptr_size - 1) & !(ptr_size - 1);

    while addr + ptr_size * (MIN_TABLE_LEN as u64) <= end {
        // Try to collect a run starting here. read_ptr returns
        // Option<u64>, with None for "couldn't read" or "below the
        // low-address cutoff" -- a NULL or junk entry ends the run.
        let mut run_len = 0u64;
        loop {
            let entry_addr = addr + run_len * ptr_size;
            if entry_addr + ptr_size > end {
                break;
            }
            let Some(val) = read_ptr(program, entry_addr, ptr_size) else {
                break;
            };
            if !is_section_addr(val, sections) {
                break;
            }
            run_len += 1;
        }

        if run_len >= MIN_TABLE_LEN as u64 {
            // Emit one reference per entry.
            for i in 0..run_len {
                let entry_addr = addr + i * ptr_size;
                // Safe to unwrap: we just verified read above.
                let val = read_ptr(program, entry_addr, ptr_size).unwrap();
                let kind = ref_kind_for(val, sections);
                out.push((entry_addr, val, kind));
            }
            addr += run_len * ptr_size;
        } else {
            // Slide forward one pointer slot. We don't try every
            // byte offset -- pointer-misaligned tables are very rare
            // in practice and the false-positive cost of unaligned
            // scanning is high.
            addr += ptr_size;
        }
    }
    out
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
    fn is_section_addr_outside() {
        assert!(!is_section_addr(0x100, &make_sections()));
        assert!(!is_section_addr(0x4000, &make_sections())); // exclusive end
        assert!(!is_section_addr(0x9000, &make_sections()));
    }
}
