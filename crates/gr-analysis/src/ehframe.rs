use gr_program::function::Function;
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct EhFrameAnalyzer;

impl Analyzer for EhFrameAnalyzer {
    fn name(&self) -> &str {
        "EH Frame"
    }
    fn description(&self) -> &str {
        "Uses .eh_frame/.eh_frame_hdr to discover function boundaries"
    }
    fn priority(&self) -> u32 {
        90
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if program.info.format != gr_loader::BinaryFormat::Elf {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let mut functions_found = 0;

        for func in &program.info.dwarf.functions {
            if func.low_pc == 0 || func.high_pc <= func.low_pc {
                continue;
            }
            if program.listing.has_function(func.low_pc) {
                continue;
            }
            if program.symbol_table.primary_at(func.low_pc).is_none() {
                program.symbol_table.add(Symbol::new(
                    func.name.clone(),
                    func.low_pc,
                    SymbolType::Function,
                    SourceType::Analysis,
                ));
            }
            if !program.listing.has_function(func.low_pc) {
                program
                    .listing
                    .add_function(Function::new(func.low_pc, func.name.clone()));
                functions_found += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}
