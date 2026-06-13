//! Surface DWARF debug info as listing annotations.
//!
//! The loader already parses `.debug_info` into `program.info.dwarf`,
//! but nothing in the analysis pipeline picks the parameter / source
//! / line info up. This analyzer:
//!
//! 1. For every DWARF function that maps to a discovered listing
//!    function: writes a plate comment naming the source file + line
//!    (`src: lib.rs:142`).
//! 2. Stashes parameter names + types in `metadata.func_<addr>_dwarf_params`
//!    so the decompiler / future emitters can consume them when typing
//!    function declarations.
//! 3. Promotes the DWARF return type into `metadata.func_<addr>_return_type`.
//!
//! All output is metadata + comments — we don't mutate the
//! signature DB or Function struct, both because the DWARF types
//! are textual rather than canonical and because the same binary
//! can be reanalyzed with different override sets without
//! corrupting these.

use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct DwarfEnrichmentAnalyzer;

impl Analyzer for DwarfEnrichmentAnalyzer {
    fn name(&self) -> &str {
        "DWARF Enrichment"
    }
    fn description(&self) -> &str {
        "Lifts DWARF parameters / source file+line into listing comments + metadata"
    }
    fn priority(&self) -> u32 {
        // After CRT / late discovery have settled function entries
        // but before annotation-rendering passes (CallSiteAnnotator
        // at 750 etc.) so the plate is visible alongside other
        // analyzer plates.
        735
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let dwarf_funcs: Vec<reargo_loader::dwarf::DwarfFunctionInfo> =
            program.info.dwarf.functions.clone();
        let mut enriched = 0usize;

        for f in &dwarf_funcs {
            if f.low_pc == 0 {
                continue;
            }
            let addr = f.low_pc;

            // Source file + line plate.
            if let (Some(src), Some(line)) = (f.source_file.as_ref(), f.source_line)
                && program.comments.get(addr, CommentType::Plate).is_none()
            {
                let basename = src.rsplit('/').next().unwrap_or(src);
                program.comments.set(
                    addr,
                    CommentType::Plate,
                    format!("src: {}:{}", basename, line),
                );
                enriched += 1;
            }

            // Parameter list summary into metadata.
            if !f.parameters.is_empty() {
                let summary = f
                    .parameters
                    .iter()
                    .map(|p| format!("{}: {}", p.name, p.type_name))
                    .collect::<Vec<_>>()
                    .join(", ");
                program
                    .metadata
                    .set_property(format!("func_{:x}_dwarf_params", addr), summary);
            }
            if let Some(ret) = f.return_type.as_ref() {
                program
                    .metadata
                    .set_property(format!("func_{:x}_return_type", addr), ret.clone());
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: enriched,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        let _ = super::DwarfEnrichmentAnalyzer;
    }
}
