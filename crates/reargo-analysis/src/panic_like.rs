//! Detect "panic-like" functions and propagate `no_return` through
//! the call graph.
//!
//! A function is panic-like when every reachable exit calls into a
//! no-return primitive (`abort`, `exit`, `__stack_chk_fail`,
//! `__cxa_throw`, `_Unwind_Resume`, …). Rust's `panic_*` family,
//! C++'s `__cxa_throw_bad_alloc`, glibc's `__libc_message`, libc++'s
//! `__throw_*` family all match this shape.
//!
//! Knowing a function never returns lets the decompiler omit the
//! fall-through edge after a call site (`call panic; ud2`-style
//! patterns become visible), tightens xref reports, and gives the
//! anti-debug / exception-flow analyzers a cleaner picture. The
//! existing `NoReturnPropagationAnalyzer` does a single-step
//! propagation from known no-returns; this one runs to fixpoint
//! over the discovered set so multi-hop chains (
//! `foo → bar → baz → abort`) get tagged.
//!
//! Detection rule:
//!
//! * The function's body contains at least one terminator instruction.
//! * Every terminator is either a `Return` *that's preceded by no
//!   side effect since the function entry* (unreachable trailing
//!   `ret` after a no-return call — gcc emits these as canary
//!   epilogues), or a tail-call / direct call to a known no-return.
//!
//! We approximate this with a simpler but solid proxy:
//!
//! * `call_targets` is a subset of the *known no-return* set.
//! * The function contains at least one direct call.
//! * Either the function is small (≤ 14 insns — typical panic
//!   wrapper size) OR every call in the body is to a no-return.
//!
//! Rust / libc++ `_Unwind_Resume`-only bodies satisfy this in one
//! pass; multi-hop propagation kicks in via fixpoint.

use std::collections::BTreeSet;

use reargo_arch::FlowType;
use reargo_program::comments::CommentType;
use rayon::prelude::*;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

pub struct PanicLikeAnalyzer;

impl Analyzer for PanicLikeAnalyzer {
    fn name(&self) -> &str {
        "Panic-Like"
    }
    fn description(&self) -> &str {
        "Marks functions whose every reachable path leads to a no-return primitive"
    }
    fn priority(&self) -> u32 {
        // After NoReturnPropagation (existing single-step) so we
        // start from its result.
        870
    }
    fn prepare_reads(&self) -> Option<State> {
        Some(State::CODE.union(State::FUNC_NO_RETURN))
    }
    fn writes(&self) -> State {
        State::FUNC_NO_RETURN.union(State::COMMENTS)
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    /// The functions to mark (those already no-return included).
    fn prepare(&self, program: &Program) -> Prepared {
        // Seed: every function already flagged `no_return = true`
        // by an earlier analyzer (NoReturnAnalyzer / signature DB /
        // NoReturnPropagationAnalyzer).
        let mut no_return: BTreeSet<u64> = program
            .listing
            .functions()
            .filter(|f| f.no_return)
            .map(|f| f.entry_point)
            .collect();

        // Only a function with a direct call, a call target and at most
        // 30 instructions can be marked: those are walked below. They
        // are walked in parallel, kept in function order.
        struct FuncSnap {
            entry: u64,
            call_targets: Vec<u64>,
        }
        let funcs: Vec<&reargo_program::function::Function> = program.listing.functions().collect();
        let listing = &program.listing;
        // (the body walks read the instructions sorted: no instruction is
        // listed after this analyzer)
        listing.sorted_instructions();
        let snaps: Vec<FuncSnap> = funcs
            .par_iter()
            .filter_map(|f| {
                if f.call_targets.is_empty() {
                    return None;
                }
                let mut direct_call_count = 0usize;
                let mut insn_count = 0usize;
                listing.for_each_body_instruction(&f.body, |_, ins| {
                    insn_count += 1;
                    if ins.flow_type == FlowType::Call {
                        direct_call_count += 1;
                    }
                });
                (direct_call_count != 0 && insn_count <= 30)
                    .then(|| FuncSnap { entry: f.entry_point, call_targets: f.call_targets.iter().copied().collect() })
            })
            .collect();

        // Fixpoint: repeatedly add functions whose call_targets are a
        // non-empty subset of `no_return` (the set reached does not
        // depend on the order they are added in).
        //
        // Strict propagation rule: *every* direct call in the
        // body targets a known no-return primitive AND the
        // function is small. `any_no_return` would also catch
        // `if (!p) panic(); return q;` shapes where the
        // conditional success path still returns normally —
        // that's a wrong rename, so we hold to the subset
        // check even at the cost of some recall.
        let mut added = 0usize;
        loop {
            let mut changed = false;
            for snap in &snaps {
                if no_return.contains(&snap.entry) {
                    continue;
                }
                if !snap.call_targets.iter().all(|t| no_return.contains(t)) {
                    continue;
                }
                no_return.insert(snap.entry);
                added += 1;
                changed = true;
            }
            if !changed {
                break;
            }
        }

        let _ = added;
        Box::new(no_return.into_iter().collect::<Vec<u64>>())
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let to_mark: Vec<u64> = crate::analyzer::prepared(prepared);
        // Apply the new no_return flag to the listing + emit a
        // plate comment so the user sees it without grepping
        // metadata.
        let mut marked = 0usize;
        for entry in to_mark {
            if let Some(f) = program.listing.get_function_mut(entry)
                && !f.no_return
            {
                f.no_return = true;
                marked += 1;
            }
            if program.comments.get(entry, CommentType::Plate).is_none() {
                program.comments.set(
                    entry,
                    CommentType::Plate,
                    "no-return (panic-like)",
                );
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: marked,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_compiles() {
        let _ = PanicLikeAnalyzer;
    }
}
