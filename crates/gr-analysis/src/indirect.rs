use gr_arch::FlowType;
use gr_program::reference::{RefType, Reference};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct IndirectCallAnalyzer;

impl Analyzer for IndirectCallAnalyzer {
    fn name(&self) -> &str { "Indirect Call" }
    fn description(&self) -> &str { "Resolves indirect call targets from GOT/IAT entries" }
    fn priority(&self) -> u32 { 580 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut resolved = 0;

        let indirect_calls: Vec<u64> = program.listing.instructions()
            .filter(|i| i.flow_type == FlowType::IndirectCall)
            .map(|i| i.address)
            .collect();

        for &addr in &indirect_calls {
            for import in &program.info.imports {
                if !program.references.get_refs_from(addr).iter().any(|r| r.to == import.plt_address) {
                    let distance = import.got_address.abs_diff(addr);
                    if distance < 0x100000 {
                        program.references.add(Reference::new(addr, import.plt_address, RefType::IndirectCall));
                        resolved += 1;
                        break;
                    }
                }
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: resolved,
            instructions_decoded: 0,
        })
    }
}

pub struct StringReferenceAnalyzer;

impl Analyzer for StringReferenceAnalyzer {
    fn name(&self) -> &str { "String Reference" }
    fn description(&self) -> &str { "Creates references from code to string data" }
    fn priority(&self) -> u32 { 590 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut refs_found = 0;

        let string_addrs: Vec<u64> = program.symbol_table.iter()
            .filter(|s| s.name.starts_with("s_"))
            .map(|s| s.address)
            .collect();

        let insn_addrs: Vec<u64> = program.listing.instructions()
            .map(|i| i.address)
            .collect();

        for &insn_addr in &insn_addrs {
            if let Some(insn) = program.listing.get_instruction(insn_addr) {
                for &str_addr in &string_addrs {
                    if insn.bytes.len() >= 4 {
                        let addr_bytes = (str_addr as u32).to_le_bytes();
                        if insn.bytes.windows(4).any(|w| w == &addr_bytes[..])
                            && !program.references.get_refs_from(insn_addr).iter().any(|r| r.to == str_addr) {
                                program.references.add(Reference::new(insn_addr, str_addr, RefType::DataRead));
                                refs_found += 1;
                            }
                    }
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
