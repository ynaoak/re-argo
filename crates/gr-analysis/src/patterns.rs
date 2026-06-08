use gr_program::function::Function;
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct PatternFunctionAnalyzer;

/// Only 4+ byte prologue patterns -- short 2-3 byte forms like
/// `sub rsp, imm8` (`48 83 EC`) or `push r12` (`41 54`) appear far
/// too often inside instruction operands and unrelated data to be
/// reliable function-start signals. Stripped binaries produced
/// hundreds of thousands of false positives from the short patterns
/// before we tightened to this 4+ byte set.
const X86_64_PROLOGUE_PATTERNS: &[&[u8]] = &[
    &[0x55, 0x48, 0x89, 0xE5],         // push rbp; mov rbp, rsp
    &[0x55, 0x48, 0x8B, 0xEC],         // push rbp; mov rbp, rsp (alt)
    &[0x48, 0x81, 0xEC],               // sub rsp, imm32 -- 3 bytes but
                                       // followed by a 4-byte imm that
                                       // we don't need to parse here;
                                       // the boundary check below filters
                                       // the random-position matches.
];

/// A real function start sits immediately after some boundary
/// marker: the previous function's ret (0xC3 / 0xC2), an int3
/// padding (0xCC), nop padding (0x90), or zero-fill padding (0x00).
/// If the byte preceding our candidate address is anything else, we
/// are matching a prologue pattern mid-instruction inside another
/// function -- a guaranteed false positive that this single check
/// eliminates the bulk of.
fn is_boundary_byte(b: u8) -> bool {
    matches!(b, 0xC3 | 0xC2 | 0xCC | 0x90 | 0x00)
}

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

                // Skip addresses that are already known to be inside
                // a function body. `has_function` only catches the
                // entry; `function_containing` catches mid-body
                // matches that the previous predicate missed and was
                // the main escape valve for false positives in
                // stripped binaries.
                if program.listing.has_function(addr)
                    || program.listing.has_instruction(addr)
                    || program.listing.function_containing(addr).is_some()
                {
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

                    // Require a function-boundary byte immediately
                    // before `addr`. Without this gate the prologue
                    // pattern matches anywhere inside other functions
                    // (e.g. a `push rbp` inside an ABI-conformant call
                    // sequence) -- on a stripped libc we were emitting
                    // ~384k spurious FUN_* symbols.
                    if offset > 0 {
                        let prev = base + offset - 1;
                        let mut pb = [0u8; 1];
                        let prev_ok = program
                            .info
                            .memory
                            .read_bytes(prev, &mut pb)
                            .is_ok()
                            && is_boundary_byte(pb[0]);
                        if !prev_ok {
                            offset += 1;
                            continue;
                        }
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
