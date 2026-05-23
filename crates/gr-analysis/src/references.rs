use gr_program::reference::{RefType, Reference};
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

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

        let instructions: Vec<(u64, Vec<u64>)> = program
            .listing
            .instructions()
            .map(|insn| {
                let constants: Vec<u64> = insn
                    .bytes
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
                (insn.address, constants)
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

fn is_in_executable_section(addr: u64, sections: &[gr_loader::Section]) -> bool {
    sections.iter().any(|s| {
        s.flags.contains(gr_loader::SectionFlags::EXECUTE)
            && addr >= s.address
            && addr < s.address + s.size
    })
}

fn try_read_string(memory: &gr_loader::Memory, addr: u64) -> Option<String> {
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
        "Identifies functions that never return (exit, abort, etc.)"
    }

    fn priority(&self) -> u32 {
        250
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let no_return_names = [
            "exit", "_exit", "abort", "_abort", "__cxa_throw",
            "ExitProcess", "TerminateProcess", "__stack_chk_fail",
            "panic", "__assert_fail", "err", "errx",
        ];

        let no_return_addrs: Vec<u64> = program
            .symbol_table
            .iter()
            .filter(|sym| no_return_names.iter().any(|&n| sym.name == n || sym.name.ends_with(&"@plt".to_string())))
            .filter(|sym| no_return_names.iter().any(|&n| {
                sym.name == n || sym.name == format!("{}@plt", n)
            }))
            .map(|sym| sym.address)
            .collect();

        let mut detected = 0;
        let func_entries: Vec<u64> = program.listing.functions().map(|f| f.entry_point).collect();
        for entry in func_entries {
            if let Some(func) = program.listing.get_function(entry) {
                let calls_noreturn = func
                    .call_targets
                    .iter()
                    .any(|t| no_return_addrs.contains(t));
                if calls_noreturn {
                    detected += 1;
                }
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: detected,
            references_found: 0,
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
