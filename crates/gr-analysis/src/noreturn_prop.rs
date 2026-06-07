use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct NoReturnPropagationAnalyzer;

impl Analyzer for NoReturnPropagationAnalyzer {
    fn name(&self) -> &str {
        "No-Return Propagation"
    }
    fn description(&self) -> &str {
        "Propagates no-return status through call chains"
    }
    fn priority(&self) -> u32 {
        750
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        use rustc_hash::FxHashSet;
        let propagated = 0;

        // Build the set of known function entry points ONCE. The
        // previous code re-iterated `program.listing.functions()`
        // inside the outer `filter`, giving an O(K * N) walk where
        // K is the number of one-call-target candidates and N is
        // the function count -- nominal for small binaries, O(N^2)
        // in the worst case.
        let entry_points: FxHashSet<u64> = program
            .listing
            .functions()
            .map(|f| f.entry_point)
            .collect();

        let no_return_funcs: Vec<u64> = program
            .listing
            .functions()
            .filter(|f| {
                f.call_targets.len() == 1
                    && f.body.len() <= 3
                    && f.call_targets.iter().any(|t| entry_points.contains(t))
            })
            .map(|f| f.entry_point)
            .collect();

        // The actual no-return propagation is still TODO -- this
        // analyzer currently only collects candidates. Once the
        // propagation logic lands the candidate set is the input
        // and `propagated` will be its size.
        let _ = no_return_funcs;
        let _ = propagated;

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: propagated,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

pub struct DuplicateCodeAnalyzer;

impl Analyzer for DuplicateCodeAnalyzer {
    fn name(&self) -> &str {
        "Duplicate Code"
    }
    fn description(&self) -> &str {
        "Detects functions with identical byte patterns (clones/copies)"
    }
    fn priority(&self) -> u32 {
        900
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut duplicates = 0;
        let mut seen_hashes: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();

        let func_entries: Vec<u64> = program.listing.functions().map(|f| f.entry_point).collect();

        for entry in &func_entries {
            let mut hash: u64 = 0xcbf29ce484222325;
            let mut count = 0;
            for insn in program.listing.instructions_in_range(*entry, *entry + 64) {
                for &b in insn.bytes.iter() {
                    hash ^= b as u64;
                    hash = hash.wrapping_mul(0x100000001b3);
                }
                count += 1;
                if count >= 8 {
                    break;
                }
            }

            if count >= 4 {
                if let Some(&existing) = seen_hashes.get(&hash) {
                    if existing != *entry {
                        duplicates += 1;
                    }
                } else {
                    seen_hashes.insert(hash, *entry);
                }
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: duplicates,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}
