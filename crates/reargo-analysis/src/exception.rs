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

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct ExceptionFlowAnalyzer;

impl Analyzer for ExceptionFlowAnalyzer {
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
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        // Per-function aggregation of which classes were observed.
        #[derive(Default)]
        struct EhUse {
            throws: bool,
            catches: bool,
            unwinds: bool,
        }
        let mut per_func: BTreeMap<u64, EhUse> = BTreeMap::new();

        // (1) Per-call-site Post comments.
        let mut emitted = 0usize;
        // PLT stubs / thunks call EH primitives by construction
        // (a `printf@plt` "calls" the GOT slot which can resolve to
        // a libc that internally throws). Skip them — the EH plate
        // is only meaningful on actual caller functions.
        let func_targets: Vec<(u64, Vec<u64>)> = program
            .listing
            .functions()
            .filter(|f| !f.is_thunk && !f.name.contains("@plt"))
            .map(|f| (f.entry_point, f.call_targets.iter().copied().collect()))
            .collect();

        for (entry, targets) in &func_targets {
            let mut use_ = EhUse::default();
            for t in targets {
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
                per_func.insert(*entry, use_);
            }
        }

        // Find every call instruction and decorate the matching ones.
        // We walk the function bodies' references (already populated
        // by ScalarReference / DataReference / PcodeReference).
        // Direct calls only: `lea` / `mov` of an EH symbol is
        // plumbing, and `IndirectCall` refs are produced by the
        // IndirectCallAnalyzer's coarse "nearest import" heuristic
        // and don't carry enough provenance to drive EH flagging.
        let edges: Vec<(u64, u64)> = program
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
            .map(|r| (r.from, r.to))
            .collect();

        for (from, to) in edges {
            // Only annotate code references — GOT relocations etc.
            // also point at these symbols but aren't user-meaningful.
            if program
                .listing
                .instructions_in_range(from, from + 1)
                .next()
                .is_none()
            {
                continue;
            }
            let note = if throw_addrs.contains(&to) {
                "C++ throw / allocate (Itanium ABI)"
            } else if catch_addrs.contains(&to) {
                "C++ catch entry / exit (Itanium ABI)"
            } else {
                "C++ unwind / personality (Itanium ABI)"
            };
            if program.comments.get(from, CommentType::Post).is_some() {
                continue;
            }
            program.comments.set(from, CommentType::Post, note);
            emitted += 1;
        }

        // (2) Plate comments on each EH-using function summarising
        // the role(s).
        for (entry, use_) in &per_func {
            if program.comments.get(*entry, CommentType::Plate).is_some() {
                continue;
            }
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
            program.comments.set(
                *entry,
                CommentType::Plate,
                format!("C++ EH: {}", roles.join(" / ")),
            );
            emitted += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: per_func.len(),
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
