use reargo_program::reference::{RefType, Reference};
use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct ScalarReferenceAnalyzer;

impl Analyzer for ScalarReferenceAnalyzer {
    fn name(&self) -> &str {
        "Scalar Reference"
    }

    fn description(&self) -> &str {
        "Resolves constant operands that point to data or strings"
    }

    fn priority(&self) -> u32 {
        300
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut refs_found = 0;

        let valid_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.address != 0 && s.size > 0)
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Phase 1: scan each instruction's bytes for pointer-shaped
        // 32-bit words in parallel. Window scanning is the dominant
        // cost (millions of windows in a real binary) and is pure
        // function-local against immutable inputs (insn.bytes,
        // valid_ranges), so rayon's parallel iterator gives
        // near-linear speed-up on multi-core machines.
        //
        // Materialise the instruction snapshot into a Vec first
        // because `program.listing.instructions()` is a serial
        // iterator; collecting once and then `par_iter`ing is cheaper
        // than locking on every step.
        let insn_snapshot: Vec<_> = program
            .listing
            .instructions()
            .map(|insn| (insn.address, insn.bytes.clone()))
            .collect();

        let instructions: Vec<(u64, Vec<u64>)> = insn_snapshot
            .par_iter()
            .map(|(addr, bytes)| {
                let constants: Vec<u64> = bytes
                    .windows(4)
                    .filter_map(|w| {
                        let val = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64;
                        if is_valid_pointer(val, &valid_ranges) {
                            Some(val)
                        } else {
                            None
                        }
                    })
                    .collect();
                (*addr, constants)
            })
            .filter(|(_, c)| !c.is_empty())
            .collect();

        for (insn_addr, constants) in &instructions {
            for &target in constants {
                if program.references.get_refs_from(*insn_addr).iter().any(|r| r.to == target) {
                    continue;
                }
                let ref_type = if is_in_executable_section(target, &program.info.sections) {
                    RefType::UnconditionalJump
                } else {
                    RefType::DataRead
                };
                program.references.add(Reference::new(*insn_addr, target, ref_type));
                refs_found += 1;

                if program.symbol_table.primary_at(target).is_none()
                    && let Some(s) = try_read_string(&program.info.memory, target) {
                        program.symbol_table.add(Symbol::new(
                            format!("DAT_{:x}", target),
                            target,
                            SymbolType::Data,
                            SourceType::Analysis,
                        ));
                        let _ = s;
                    }
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

fn is_valid_pointer(val: u64, ranges: &[(u64, u64)]) -> bool {
    if val < 0x1000 {
        return false;
    }
    ranges.iter().any(|&(start, end)| val >= start && val < end)
}

fn is_in_executable_section(addr: u64, sections: &[reargo_loader::Section]) -> bool {
    sections.iter().any(|s| {
        s.flags.contains(reargo_loader::SectionFlags::EXECUTE)
            && addr >= s.address
            && addr < s.address + s.size
    })
}

fn try_read_string(memory: &reargo_loader::Memory, addr: u64) -> Option<String> {
    let mut result = Vec::new();
    for i in 0..256u64 {
        match memory.read_byte(addr + i) {
            Some(0) if result.len() >= 4 => {
                return std::str::from_utf8(&result).ok().map(|s| s.to_string());
            }
            Some(0) => return None,
            Some(b) if (0x20..=0x7e).contains(&b) => result.push(b),
            _ => return None,
        }
    }
    None
}

pub struct NoReturnAnalyzer;

impl Analyzer for NoReturnAnalyzer {
    fn name(&self) -> &str {
        "No-Return Detection"
    }

    fn description(&self) -> &str {
        "Marks functions that never return using the signature DB + heuristics"
    }

    fn priority(&self) -> u32 {
        250
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        use std::sync::OnceLock;
        use crate::signatures::SignatureDatabase;
        static DB: OnceLock<SignatureDatabase> = OnceLock::new();
        let db = DB.get_or_init(SignatureDatabase::new);

        // Build a name-set from the signature DB plus a few Rust/language-runtime names
        // not covered there.
        let mut name_set: std::collections::HashSet<String> = db
            .no_return_names()
            .flat_map(|n| {
                [
                    n.to_owned(),
                    format!("{n}@plt"),
                    format!("{n}@got.plt"),
                ]
            })
            .collect();

        // Language-runtime no-return names not in the C/Win32 signature DB
        for extra in &[
            "panic",
            "rust_panic",
            "core::panicking::panic",
            "std::process::exit",
            "__aeabi_unwind_cpp_pr0",
            "__aeabi_unwind_cpp_pr1",
            "abort@plt",
            "_abort",
        ] {
            name_set.insert(extra.to_string());
        }

        // Step 1: mark functions whose symbol name is in the no-return set
        let no_return_addrs: std::collections::BTreeSet<u64> = program
            .symbol_table
            .iter()
            .filter(|sym| name_set.contains(&sym.name))
            .map(|sym| sym.address)
            .collect();

        let mut marked = 0usize;
        for &addr in &no_return_addrs {
            if let Some(func) = program.listing.get_function_mut(addr)
                && !func.no_return
            {
                func.no_return = true;
                marked += 1;
            }
        }

        // Step 2: count callers that only call no-return targets (heuristic)
        let func_entries: Vec<u64> = program.listing.functions().map(|f| f.entry_point).collect();
        let mut detected = 0;
        for entry in func_entries {
            if let Some(func) = program.listing.get_function(entry)
                && func.call_targets.iter().any(|t| no_return_addrs.contains(t))
            {
                detected += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: detected,
            references_found: marked,
            instructions_decoded: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_pointer_check() {
        let ranges = vec![(0x400000, 0x500000), (0x600000, 0x700000)];
        assert!(is_valid_pointer(0x400100, &ranges));
        assert!(!is_valid_pointer(0x100, &ranges));
        assert!(!is_valid_pointer(0x550000, &ranges));
    }
}
