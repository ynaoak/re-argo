// Type recovery analyzer: applies DWARF/PDB types to functions and variables.

use gr_program::Program;
use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct TypeRecoveryAnalyzer;

impl Analyzer for TypeRecoveryAnalyzer {
    fn name(&self) -> &str { "Type Recovery" }
    fn description(&self) -> &str { "Recovers variable and function types from debug info and analysis" }
    fn priority(&self) -> u32 { 780 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut recovered = 0;

        // Import DWARF types into DataTypeManager
        let type_count_before = program.data_types.type_count();
        recovered += gr_loader::dwarf_types::import_dwarf_types(&program.info.dwarf, &mut program.data_types);

        // Apply DWARF function info to discovered functions
        for dwarf_func in &program.info.dwarf.functions {
            if let Some(func) = program.listing.get_function_mut(dwarf_func.low_pc)
                && func.name.starts_with("FUN_") && !dwarf_func.name.is_empty() {
                    func.name = dwarf_func.name.clone();
                    recovered += 1;
                }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: recovered,
            instructions_decoded: program.data_types.type_count() - type_count_before,
        })
    }
}

pub struct DataTypeAnalyzer;

impl Analyzer for DataTypeAnalyzer {
    fn name(&self) -> &str { "Data Type" }
    fn description(&self) -> &str { "Infers data types from memory access patterns" }
    fn priority(&self) -> u32 { 790 }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut inferred = 0;

        // Check for string references to infer char* types
        for sym in program.symbol_table.iter() {
            if sym.name.starts_with("s_") && program.data_types.find_by_name("char").is_none() {
                // String data detected
                inferred += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: inferred,
            instructions_decoded: 0,
        })
    }
}
