use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

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
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut filler_regions = 0usize;
        let text_sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(gr_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.size))
            .collect();

        for &(addr, size) in &text_sections {
            let mut offset = 0u64;
            while offset < size {
                let current = addr + offset;
                if program.listing.has_instruction(current) {
                    offset += 1;
                    continue;
                }
                let byte = program.info.memory.read_byte(current);
                match byte {
                    Some(0xCC) | Some(0x90) | Some(0x00) => {
                        let start = current;
                        let filler_byte = byte.unwrap();
                        let mut end = current + 1;
                        while end < addr + size {
                            if program.info.memory.read_byte(end) != Some(filler_byte) {
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

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: filler_regions,
        })
    }
}
