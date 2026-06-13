use reargo_program::reference::{RefType, Reference};
use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct VTableAnalyzer;

impl Analyzer for VTableAnalyzer {
    fn name(&self) -> &str {
        "VTable"
    }
    fn description(&self) -> &str {
        "Detects C++ virtual function tables (vtables) by finding pointer arrays to code"
    }
    fn priority(&self) -> u32 {
        600
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut vtables_found = 0;
        let ptr_size = (program.info.bits / 8) as u64;

        let code_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(reargo_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.address + s.size))
            .collect();

        let data_sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| {
                let name = s.name.to_lowercase();
                (name.contains(".rodata") || name.contains(".rdata") || name.contains(".data.rel.ro"))
                    && s.address != 0
            })
            .map(|s| (s.address, s.size))
            .collect();

        for &(section_addr, section_size) in &data_sections {
            let mut offset = 0u64;
            while offset + ptr_size * 3 <= section_size {
                let addr = section_addr + offset;
                let mut consecutive_code_ptrs = 0u64;

                for i in 0..32u64 {
                    let entry_addr = addr + i * ptr_size;
                    let ptr_val = if ptr_size == 8 {
                        program.info.memory.read_u64(entry_addr).ok()
                    } else {
                        program.info.memory.read_u32(entry_addr).ok().map(|v| v as u64)
                    };

                    if let Some(val) = ptr_val {
                        if crate::utils::is_valid_address(val, &code_ranges) {
                            consecutive_code_ptrs += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if consecutive_code_ptrs >= 3 {
                    let vtable_name = format!("vtable_{:x}", addr);
                    if program.symbol_table.primary_at(addr).is_none() {
                        program.symbol_table.add(Symbol::new(
                            vtable_name,
                            addr,
                            SymbolType::Data,
                            SourceType::Analysis,
                        ));
                    }

                    for i in 0..consecutive_code_ptrs {
                        let entry_addr = addr + i * ptr_size;
                        let target = if ptr_size == 8 {
                            program.info.memory.read_u64(entry_addr).unwrap_or(0)
                        } else {
                            program.info.memory.read_u32(entry_addr).unwrap_or(0) as u64
                        };
                        program
                            .references
                            .add(Reference::new(entry_addr, target, RefType::DataRead));
                    }

                    vtables_found += 1;
                    offset += consecutive_code_ptrs * ptr_size;
                } else {
                    offset += ptr_size;
                }
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: vtables_found,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::helpers::make_x86_64_program_with_data;

    #[test]
    fn detect_vtable_in_rodata() {
        // .text: 4 tiny functions (just ret)
        let code_addr = 0x1000u64;
        let data_addr = 0x2000u64;
        let code = [0xc3; 16]; // 16 bytes of ret

        // .rodata: 4 consecutive 8-byte pointers into .text
        let mut data = Vec::new();
        for i in 0..4u64 {
            data.extend_from_slice(&(code_addr + i).to_le_bytes());
        }
        // followed by a non-code value
        data.extend_from_slice(&0u64.to_le_bytes());

        let mut program = make_x86_64_program_with_data(&code, &data, code_addr, data_addr);
        let result = VTableAnalyzer.analyze(&mut program).unwrap();
        assert!(result.functions_found >= 1);
        assert!(program.symbol_table.primary_at(data_addr).is_some());
    }

    #[test]
    fn no_vtable_without_code_pointers() {
        let code = [0xc3; 4];
        let data = [0u8; 64]; // all zeros
        let mut program = make_x86_64_program_with_data(&code, &data, 0x1000, 0x2000);
        let result = VTableAnalyzer.analyze(&mut program).unwrap();
        assert_eq!(result.functions_found, 0);
    }
}

