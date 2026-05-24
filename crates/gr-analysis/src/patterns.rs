use gr_program::function::Function;
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct PatternFunctionAnalyzer;

const X86_64_PROLOGUE_PATTERNS: &[&[u8]] = &[
    &[0x55, 0x48, 0x89, 0xE5],         // push rbp; mov rbp, rsp
    &[0x55, 0x48, 0x8B, 0xEC],         // push rbp; mov rbp, rsp (alt)
    &[0x48, 0x83, 0xEC],               // sub rsp, imm8
    &[0x48, 0x81, 0xEC],               // sub rsp, imm32
    &[0x40, 0x53],                      // push rbx (REX)
    &[0x40, 0x55],                      // push rbp (REX)
    &[0x41, 0x54],                      // push r12
    &[0x41, 0x55],                      // push r13
    &[0x41, 0x56],                      // push r14
    &[0x41, 0x57],                      // push r15
];

impl Analyzer for PatternFunctionAnalyzer {
    fn name(&self) -> &str {
        "Pattern Function"
    }
    fn description(&self) -> &str {
        "Detects function starts by byte prologue patterns"
    }
    fn priority(&self) -> u32 {
        180
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(
            program.info.arch,
            gr_loader::Architecture::X86_64 | gr_loader::Architecture::X86
        ) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let mut found = 0;
        let text_sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(gr_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.size))
            .collect();

        for &(base, size) in &text_sections {
            let mut offset = 0u64;
            while offset + 4 <= size {
                let addr = base + offset;
                if program.listing.has_function(addr) || program.listing.has_instruction(addr) {
                    offset += 1;
                    continue;
                }

                let mut buf = [0u8; 8];
                let read = buf.len().min((size - offset) as usize);
                if program.info.memory.read_bytes(addr, &mut buf[..read]).is_err() {
                    offset += 1;
                    continue;
                }

                let matched = X86_64_PROLOGUE_PATTERNS
                    .iter()
                    .any(|pat| buf.starts_with(pat));

                if matched {
                    if buf[0] == 0xCC || buf[0] == 0x00 {
                        offset += 1;
                        continue;
                    }

                    let name = format!("FUN_{:08x}", addr);
                    program.symbol_table.add(Symbol::new(
                        name.clone(),
                        addr,
                        SymbolType::Function,
                        SourceType::Analysis,
                    ));
                    program
                        .listing
                        .add_function(Function::new(addr, name));
                    found += 1;
                    offset += 4;
                } else {
                    offset += 1;
                }
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: found,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

pub struct StructLayoutAnalyzer;

impl Analyzer for StructLayoutAnalyzer {
    fn name(&self) -> &str {
        "Struct Layout"
    }
    fn description(&self) -> &str {
        "Infers structure field layouts from memory access patterns"
    }
    fn priority(&self) -> u32 {
        800
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut struct_hints = 0;

        let func_entries: Vec<u64> = program
            .listing
            .functions()
            .map(|f| f.entry_point)
            .collect();

        for entry in func_entries {
            if let Some(func) = program.listing.get_function(entry) {
                let stack_vars = func.stack_frame.variables.len();
                if stack_vars >= 3 {
                    struct_hints += 1;
                }
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: struct_hints,
            instructions_decoded: 0,
        })
    }
}
