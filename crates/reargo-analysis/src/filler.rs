use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

pub struct FillerBytesAnalyzer;

impl Analyzer for FillerBytesAnalyzer {
    fn name(&self) -> &str {
        "Filler Bytes"
    }
    fn description(&self) -> &str {
        "Detects padding/filler byte patterns between functions (0xCC, 0x90, 0x00)"
    }
    fn priority(&self) -> u32 {
        150
    }
    fn prepare_reads(&self) -> Option<State> {
        Some(State::INSNS)
    }
    fn writes(&self) -> State {
        State::NONE
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    fn apply(&self, _program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        Ok(crate::analyzer::prepared(prepared))
    }
    /// Only a count: the result is all there is to apply.
    fn prepare(&self, program: &Program) -> Prepared {
        let mut filler_regions = 0usize;
        let text_sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(reargo_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.size))
            .collect();

        for &(addr, size) in &text_sections {
            // The section's instruction starts, in order: the bytes are
            // visited in increasing order, so whether one starts an
            // instruction is found by moving along them.
            let mut starts = program.listing.instructions_in_range(addr, addr + size).map(|i| i.address).peekable();
            let mut has_instruction = |a: u64| {
                while starts.next_if(|&s| s < a).is_some() {}
                starts.peek() == Some(&a)
            };
            // Read the section once: a byte that is no filler byte
            // moves on by one whatever the listing holds, so the
            // instruction lookup is only needed for filler bytes.
            let section_bytes = program.info.memory.slice(addr, size);
            let mut offset = 0u64;
            while offset < size {
                let current = addr + offset;
                if let Some(bytes) = section_bytes
                    && !matches!(bytes[offset as usize], 0xCC | 0x90 | 0x00)
                {
                    // (on to the next filler byte: every byte before it moves on by one)
                    offset = memchr::memchr3(0xCC, 0x90, 0x00, &bytes[offset as usize..]).map_or(size, |i| offset + i as u64);
                    continue;
                }
                if has_instruction(current) {
                    offset += 1;
                    continue;
                }
                let byte = match section_bytes {
                    Some(bytes) => Some(bytes[offset as usize]),
                    None => program.info.memory.read_byte(current),
                };
                match byte {
                    Some(filler_byte @ (0xCC | 0x90 | 0x00)) => {
                        let start = current;
                        let mut end = current + 1;
                        while end < addr + size {
                            let next = match section_bytes {
                                Some(bytes) => Some(bytes[(end - addr) as usize]),
                                None => program.info.memory.read_byte(end),
                            };
                            if next != Some(filler_byte) {
                                break;
                            }
                            end += 1;
                        }
                        let len = end - start;
                        if len >= 2 {
                            filler_regions += 1;
                        }
                        offset += len;
                    }
                    _ => {
                        offset += 1;
                    }
                }
            }
        }

        Box::new(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: filler_regions,
        })
    }
}
