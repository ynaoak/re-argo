//! Per-function complexity metrics: McCabe cyclomatic complexity,
//! basic-block count, instruction count, fan-in / fan-out.
//!
//! Same numbers IDA's "Function Properties" tab and Binary Ninja's
//! "Analysis Statistics" pane present. We compute them once during
//! the analysis pass and write them into `program.metadata.properties`
//! under a `func_<addr>_*` key namespace so the `metrics` CLI and any
//! downstream report can consume them without re-walking the listing.
//!
//! Formula:
//!
//! ```text
//!   McCabe(M) = E - N + 2 P
//!             = (decision_points) + 1
//! ```
//!
//! where `decision_points` counts every conditional branch in the
//! function. Switch tables count as `(n_targets - 1)` decisions; we
//! approximate this with `n_branch_targets + n_conditional` since
//! the listing already exposes both. A function with no branches
//! has complexity 1 (the canonical "trivial" value).

use std::collections::BTreeMap;

use reargo_arch::FlowType;
use rayon::prelude::*;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

pub struct ComplexityAnalyzer;

#[derive(Debug, Default, Clone, Copy)]
pub struct FunctionMetrics {
    pub instructions: usize,
    pub basic_blocks: usize,
    pub cyclomatic: usize,
    pub fan_in: usize,
    pub fan_out: usize,
    pub stack_size: u64,
}

impl Analyzer for ComplexityAnalyzer {
    fn name(&self) -> &str {
        "Complexity Metrics"
    }
    fn description(&self) -> &str {
        "Computes McCabe cyclomatic complexity + block / fan-in / fan-out per function"
    }
    fn priority(&self) -> u32 {
        // After everything that may add/rename functions or refs.
        // Same band as CrossReferenceReport (900).
        900
    }
    fn prepare_reads(&self) -> Option<State> {
        Some(State::CODE.union(State::FUNC_OTHER))
    }
    fn writes(&self) -> State {
        State::METADATA
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    fn prepare(&self, program: &Program) -> Prepared {
        // Build a global "called function entries" multiset for fan_in.
        let mut callers_of: BTreeMap<u64, usize> = BTreeMap::new();
        for func in program.listing.functions() {
            for &t in &func.call_targets {
                *callers_of.entry(t).or_insert(0) += 1;
            }
        }

        // Compute every function's metrics first, then write them, so
        // the listing borrow doesn't fight the metadata writes.
        // Functions are independent: computed in parallel, kept in
        // function order.
        let funcs: Vec<&reargo_program::function::Function> = program.listing.functions().collect();
        let listing = &program.listing;
        // (the body walks read the instructions sorted: no instruction is
        // listed after this analyzer)
        listing.sorted_instructions();
        let computed: Vec<(String, String)> = funcs
            .par_iter()
            .map(|f| {
                let entry = f.entry_point;
                let mut instructions = 0usize;
                let mut conditional = 0usize;
                // (sorted and deduplicated once all are in)
                let mut block_starts: Vec<u64> = vec![entry];
                // `prev_was_branch` starts false in each body range.
                let mut prev_was_branch = false;
                listing.for_each_body_instruction(&f.body, |first, insn| {
                    if first {
                        prev_was_branch = false;
                    }
                    instructions += 1;
                    if prev_was_branch {
                        block_starts.push(insn.address);
                    }
                    prev_was_branch = false;
                    match insn.flow_type {
                        FlowType::ConditionalJump => {
                            conditional += 1;
                            if let Some(t) = insn.branch_target {
                                block_starts.push(t);
                            }
                            prev_was_branch = true;
                        }
                        FlowType::UnconditionalJump => {
                            if let Some(t) = insn.branch_target {
                                block_starts.push(t);
                            }
                            prev_was_branch = true;
                        }
                        _ => {}
                    }
                });
                block_starts.sort_unstable();
                block_starts.dedup();
                let basic_blocks = block_starts.len().max(1);
                let cyclomatic = conditional + 1;

                let metrics = FunctionMetrics {
                    instructions,
                    basic_blocks,
                    cyclomatic,
                    fan_in: callers_of.get(&entry).copied().unwrap_or(0),
                    fan_out: f.call_targets.len(),
                    stack_size: f.stack_frame.local_size,
                };
                // (the property formatted here, in parallel: `apply` only
                // sets it)
                (
                    format!("func_{:x}_metrics", entry),
                    format!(
                        "insns={} blocks={} mccabe={} fan_in={} fan_out={} stack={}",
                        metrics.instructions,
                        metrics.basic_blocks,
                        metrics.cyclomatic,
                        metrics.fan_in,
                        metrics.fan_out,
                        metrics.stack_size
                    ),
                )
            })
            .collect();
        drop(funcs);
        Box::new(computed)
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let computed: Vec<(String, String)> = crate::analyzer::prepared(prepared);
        let mut counted = 0usize;
        for (key, value) in computed {
            program.metadata.set_property(key, value);
            counted += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: counted,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// Re-extract the metrics from a `metadata.properties` value written
/// by the analyzer. Returns `None` when the key is missing or
/// malformed. Used by the `metrics` CLI command so callers don't
/// need to re-run analysis to read what was already computed.
pub fn parse_metrics(value: &str) -> Option<FunctionMetrics> {
    let mut m = FunctionMetrics::default();
    for kv in value.split_whitespace() {
        let (k, v) = kv.split_once('=')?;
        match k {
            "insns" => m.instructions = v.parse().ok()?,
            "blocks" => m.basic_blocks = v.parse().ok()?,
            "mccabe" => m.cyclomatic = v.parse().ok()?,
            "fan_in" => m.fan_in = v.parse().ok()?,
            "fan_out" => m.fan_out = v.parse().ok()?,
            "stack" => m.stack_size = v.parse().ok()?,
            _ => return None,
        }
    }
    Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_roundtrip() {
        let s = "insns=42 blocks=5 mccabe=3 fan_in=1 fan_out=2 stack=32";
        let m = parse_metrics(s).unwrap();
        assert_eq!(m.instructions, 42);
        assert_eq!(m.basic_blocks, 5);
        assert_eq!(m.cyclomatic, 3);
        assert_eq!(m.fan_in, 1);
        assert_eq!(m.fan_out, 2);
        assert_eq!(m.stack_size, 32);
    }

    #[test]
    fn rejects_unknown_key() {
        assert!(parse_metrics("foo=1").is_none());
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_metrics("insns blocks=2").is_none());
    }
}
