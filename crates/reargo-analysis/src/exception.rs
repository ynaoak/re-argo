//! Surface C++ exception flow.
//!
//! When a function uses C++ exceptions, the compiler emits calls
//! to Itanium ABI runtime helpers — `__cxa_throw`,
//! `__cxa_allocate_exception`, `__cxa_begin_catch`, `_Unwind_Resume`,
//! `__gxx_personality_v0` — that are easy to spot in the import
//! table. Knowing which functions touch the EH machinery is useful
//! in stripped binaries (mid-level "looks like try-block territory"
//! hint) and in security-style review (no-exception code paths
//! deserve more scrutiny).
//!
//! For each call site whose target is a known EH primitive we emit
//! a pre-comment describing what's happening:
//!
//! ```text
//!   call __cxa_throw          ; C++ throw — does not return
//!   call __cxa_begin_catch    ; C++ catch entry
//! ```
//!
//! For the *containing* function we set a plate comment hinting at
//! the kind of EH interaction observed (throw / catch / cleanup).

use std::collections::{BTreeMap, BTreeSet};

use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

pub struct ExceptionFlowAnalyzer;

/// What [`ExceptionFlowAnalyzer::prepare`] found: each direct call of
/// an EH helper from a listed instruction (in reference order) with
/// its note, and each non-thunk function calling one, with its plate
/// (the functions' names are checked at `apply`).
type Found = (Vec<(u64, &'static str)>, Vec<(u64, String)>);

impl Analyzer for ExceptionFlowAnalyzer {
    fn prepare_reads(&self) -> Option<State> {
        // (the symbols of the EH helpers it looks for by name)
        Some(State::CODE.union(State::REFERENCES).union(State::SYMBOLS.difference(State::STRING_SYMBOLS)))
    }
    fn writes(&self) -> State {
        State::COMMENTS
    }
    fn name(&self) -> &str {
        "Exception Flow"
    }
    fn description(&self) -> &str {
        "Marks functions that throw / catch C++ exceptions via Itanium ABI helpers"
    }
    fn priority(&self) -> u32 {
        // After Signatures (700) + CallSiteAnnotator (750).
        // We're additive — write Post / Plate slots only.
        790
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    fn prepare(&self, program: &Program) -> Prepared {
        // Index EH helper addresses by behaviour class.
        let mut throw_addrs: BTreeSet<u64> = BTreeSet::new();
        let mut catch_addrs: BTreeSet<u64> = BTreeSet::new();
        let mut unwind_addrs: BTreeSet<u64> = BTreeSet::new();
        for s in program.symbol_table.iter() {
            let n = s.name.strip_suffix("@plt").unwrap_or(&s.name);
            match n {
                "__cxa_throw" | "__cxa_rethrow" | "__cxa_allocate_exception" => {
                    throw_addrs.insert(s.address);
                }
                "__cxa_begin_catch" | "__cxa_end_catch" | "__cxa_get_exception_ptr" => {
                    catch_addrs.insert(s.address);
                }
                "_Unwind_Resume"
                | "_Unwind_RaiseException"
                | "__gxx_personality_v0"
                | "__cxa_call_unexpected" => {
                    unwind_addrs.insert(s.address);
                }
                _ => {}
            }
        }
        if throw_addrs.is_empty() && catch_addrs.is_empty() && unwind_addrs.is_empty() {
            return Box::new(None::<Found>);
        }

        // Per-function aggregation of which classes were observed.
        #[derive(Default)]
        struct EhUse {
            throws: bool,
            catches: bool,
            unwinds: bool,
        }
        let mut per_func: BTreeMap<u64, EhUse> = BTreeMap::new();

        // PLT stubs / thunks call EH primitives by construction
        // (a `printf@plt` "calls" the GOT slot which can resolve to
        // a libc that internally throws). Skip them — the EH plate
        // is only meaningful on actual caller functions. (A name with
        // `@plt` is skipped at `apply`, where the names are final.)
        for f in program.listing.functions().filter(|f| !f.is_thunk) {
            let mut use_ = EhUse::default();
            for t in &f.call_targets {
                if throw_addrs.contains(t) {
                    use_.throws = true;
                }
                if catch_addrs.contains(t) {
                    use_.catches = true;
                }
                if unwind_addrs.contains(t) {
                    use_.unwinds = true;
                }
            }
            if use_.throws || use_.catches || use_.unwinds {
                per_func.insert(f.entry_point, use_);
            }
        }

        // Find every call instruction and decorate the matching ones.
        // We walk the function bodies' references (already populated
        // by ScalarReference / DataReference / PcodeReference).
        // Direct calls only: `lea` / `mov` of an EH symbol is
        // plumbing, and `IndirectCall` refs are produced by the
        // IndirectCallAnalyzer's coarse "nearest import" heuristic
        // and don't carry enough provenance to drive EH flagging.
        let edges: Vec<(u64, &'static str)> = program
            .references
            .all_refs()
            .filter(|r| {
                matches!(
                    r.ref_type,
                    reargo_program::reference::RefType::UnconditionalCall
                        | reargo_program::reference::RefType::ConditionalCall
                )
            })
            .filter(|r| {
                throw_addrs.contains(&r.to)
                    || catch_addrs.contains(&r.to)
                    || unwind_addrs.contains(&r.to)
            })
            // Only annotate code references — GOT relocations etc.
            // also point at these symbols but aren't user-meaningful.
            .filter(|r| program.listing.get_instruction(r.from).is_some())
            .map(|r| {
                let note = if throw_addrs.contains(&r.to) {
                    "C++ throw / allocate (Itanium ABI)"
                } else if catch_addrs.contains(&r.to) {
                    "C++ catch entry / exit (Itanium ABI)"
                } else {
                    "C++ unwind / personality (Itanium ABI)"
                };
                (r.from, note)
            })
            .collect();

        // Plate comments on each EH-using function summarising the
        // role(s).
        let plates: Vec<(u64, String)> = per_func
            .into_iter()
            .map(|(entry, use_)| {
                let mut roles: Vec<&str> = Vec::new();
                if use_.throws {
                    roles.push("throws");
                }
                if use_.catches {
                    roles.push("catches");
                }
                if use_.unwinds {
                    roles.push("unwinds");
                }
                (entry, format!("C++ EH: {}", roles.join(" / ")))
            })
            .collect();
        Box::new(Some::<Found>((edges, plates)))
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let found: Option<Found> = crate::analyzer::prepared(prepared);
        let Some((edges, plates)) = found else {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        };
        let mut emitted = 0usize;

        // (1) Per-call-site Post comments.
        for (from, note) in edges {
            if program.comments.get(from, CommentType::Post).is_some() {
                continue;
            }
            program.comments.set(from, CommentType::Post, note);
            emitted += 1;
        }

        // (2) The plates of the functions not named as a PLT stub.
        let mut functions = 0usize;
        for (entry, text) in plates {
            if program.listing.get_function(entry).is_some_and(|f| f.name.contains("@plt")) {
                continue;
            }
            functions += 1;
            if program.comments.get(entry, CommentType::Plate).is_some() {
                continue;
            }
            program.comments.set(entry, CommentType::Plate, text);
            emitted += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: functions,
            references_found: 0,
            instructions_decoded: emitted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ExceptionFlow is data-driven over the symbol table + reference
    // graph — exercised end-to-end by the analysis test corpus.
    // No isolated helpers to unit-test.
    #[test]
    fn module_compiles() {
        let _ = ExceptionFlowAnalyzer;
    }
}
