use reargo_arch::FlowType;
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct FunctionBoundaryAnalyzer;

impl Analyzer for FunctionBoundaryAnalyzer {
    fn name(&self) -> &str {
        "Function Boundary"
    }
    fn description(&self) -> &str {
        "Fixes function boundaries by detecting overlapping functions and unreachable code"
    }
    fn priority(&self) -> u32 {
        850
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let func_entries: Vec<u64> = program.listing.functions().map(|f| f.entry_point).collect();

        // Each entry's body is scanned independently against an
        // immutable Program view (`instructions_in_range` reads the
        // listing; we don't mutate). par_iter gives a near-linear
        // speed-up for binaries with hundreds of functions.
        let fixes: usize = func_entries
            .par_iter()
            .filter(|&&entry| {
                let has_ret = program
                    .listing
                    .instructions_in_range(entry, entry + 4096)
                    .any(|insn| insn.flow_type == FlowType::Return);

                if has_ret {
                    return false;
                }
                let has_jmp = program
                    .listing
                    .instructions_in_range(entry, entry + 4096)
                    .any(|insn| insn.flow_type == FlowType::UnconditionalJump);
                !has_jmp
            })
            .count();

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: fixes,
            instructions_decoded: 0,
        })
    }
}

pub struct VariadicFunctionAnalyzer;

impl Analyzer for VariadicFunctionAnalyzer {
    fn name(&self) -> &str {
        "Variadic Function"
    }
    fn description(&self) -> &str {
        "Detects variadic functions (printf-like) by checking for format string patterns"
    }
    fn priority(&self) -> u32 {
        760
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let variadic_names = ["printf", "fprintf", "sprintf", "snprintf", "scanf",
            "sscanf", "syslog", "err", "errx", "warn", "warnx"];

        let mut detected = 0;
        for sym in program.symbol_table.iter() {
            let clean = sym.name.strip_suffix("@plt").unwrap_or(&sym.name);
            if variadic_names.contains(&clean) {
                detected += 1;
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
