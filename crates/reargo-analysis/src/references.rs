use reargo_program::reference::{RefType, Reference};
use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;
use rayon::prelude::*;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

pub struct ScalarReferenceAnalyzer;

/// With each constant, what the serial phase asks of it that
/// depends only on the bytes and on the references the
/// instruction had before this pass: whether it is one already,
/// whether it is in an executable section, and whether a string
/// starts there.
struct Constant {
    target: u64,
    known: bool,
    executable: bool,
    string: bool,
}

impl Analyzer for ScalarReferenceAnalyzer {
    fn name(&self) -> &str {
        "Scalar Reference"
    }

    fn description(&self) -> &str {
        "Resolves constant operands that point to data or strings"
    }

    fn priority(&self) -> u32 {
        300
    }

    fn prepare_reads(&self) -> Option<State> {
        Some(State::INSNS.union(State::REFERENCES))
    }
    fn writes(&self) -> State {
        State::REFERENCES.union(State::SYMBOLS)
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    /// Each instruction with pointer-shaped constants, and those.
    fn prepare(&self, program: &Program) -> Prepared {
        let valid_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.address != 0 && s.size > 0)
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Phase 1: scan each instruction's bytes for pointer-shaped
        // 32-bit words in parallel. Window scanning is the dominant
        // cost (millions of windows in a real binary) and is pure
        // function-local against immutable inputs (insn.bytes,
        // valid_ranges), so rayon's parallel iterator gives
        // near-linear speed-up on multi-core machines.
        //
        // Materialise the instruction snapshot into a Vec first
        // because `program.listing.instructions()` is a serial
        // iterator; collecting once and then `par_iter`ing is cheaper
        // than locking on every step.
        // (the listing's parts in parallel, in order)
        let insn_snapshot: Vec<_> =
            program.listing.map_instruction_parts(|insns| insns.map(|insn| (insn.address, &insn.bytes)).collect::<Vec<_>>()).concat();
        // no section below `lowest` or at / above `highest`: most
        // windows are rejected by these two compares
        let lowest = valid_ranges.iter().map(|r| r.0).min().unwrap_or(0);
        let highest = valid_ranges.iter().map(|r| r.1).max().unwrap_or(0);

        let instructions: Vec<(u64, Vec<Constant>)> = insn_snapshot
            .par_iter()
            .map(|(addr, bytes)| {
                let constants: Vec<Constant> = bytes
                    .windows(4)
                    .filter_map(|w| {
                        let val = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64;
                        if val >= lowest && val < highest && is_valid_pointer(val, &valid_ranges) {
                            Some(val)
                        } else {
                            None
                        }
                    })
                    .map(|target| Constant {
                        target,
                        known: program.references.get_refs_from(*addr).iter().any(|r| r.to == target),
                        executable: is_in_executable_section(target, &program.info.sections),
                        string: try_read_string(&program.info.memory, target).is_some(),
                    })
                    .collect();
                (*addr, constants)
            })
            .filter(|(_, c)| !c.is_empty())
            .collect();

        Box::new(instructions)
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let instructions: Vec<(u64, Vec<Constant>)> = crate::analyzer::prepared(prepared);
        // (the references and the symbols in bulk, in the same order, after;
        // a target named here counts as named for the ones after)
        let mut refs: Vec<Reference> = Vec::new();
        let mut symbols: Vec<Symbol> = Vec::new();
        let mut named: rustc_hash::FxHashSet<u64> = rustc_hash::FxHashSet::default();
        for (insn_addr, constants) in &instructions {
            for (k, c) in constants.iter().enumerate() {
                let target = c.target;
                // the references from this instruction: those before
                // this pass, and those it added for the constants before
                if c.known || constants[..k].iter().any(|p| !p.known && p.target == target) {
                    continue;
                }
                let ref_type = if c.executable {
                    RefType::UnconditionalJump
                } else {
                    RefType::DataRead
                };
                refs.push(Reference::new(*insn_addr, target, ref_type));

                if c.string && program.symbol_table.primary_at(target).is_none() && named.insert(target) {
                    symbols.push(Symbol::new(
                        format!("DAT_{:x}", target),
                        target,
                        SymbolType::Data,
                        SourceType::Analysis,
                    ));
                }
            }
        }
        let tt = std::time::Instant::now();
        program.symbol_table.add_all(symbols);
        crate::tr!(tt, "scalar symbols");
        let refs_found = refs.len();
        program.references.add_all(&refs);
        crate::tr!(tt, "scalar refs {}", refs.len());

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: refs_found,
            instructions_decoded: 0,
        })
    }
}

/// Add each reference of `candidates` unless one from its source with the
/// same `key` is there — as `ReferenceManager::add_unless` of each in turn
/// with `key(r) == key(candidate)` as the test does (the ones it added
/// before count) —, in bulk: whether one is there before looked up in
/// parallel, the first of each repeat kept, the rest added at once
/// (`ReferenceManager::add_all`, the same lists in the same order).
/// Returns how many were added.
pub(crate) fn add_unless_keyed<K: Eq + std::hash::Hash + Send>(
    references: &mut reargo_program::reference::ReferenceManager,
    candidates: Vec<Reference>,
    key: impl Fn(&Reference) -> K + Sync,
) -> usize {
    let present: Vec<bool> = {
        let references = &*references;
        candidates
            .par_iter()
            .with_min_len(4096)
            .map(|c| {
                let k = key(c);
                references.get_refs_from(c.from).iter().any(|r| key(r) == k)
            })
            .collect()
    };
    let tt = std::time::Instant::now();
    let mut seen: rustc_hash::FxHashSet<(u64, K)> = rustc_hash::FxHashSet::default();
    let added: Vec<Reference> = candidates
        .into_iter()
        .zip(present)
        .filter(|&(c, present)| !present && seen.insert((c.from, key(&c))))
        .map(|(c, _)| c)
        .collect();
    crate::tr!(tt, "add_unless_keyed seen {} of {}", added.len(), references.len());
    references.add_all(&added);
    crate::tr!(tt, "add_unless_keyed added");
    added.len()
}

fn is_valid_pointer(val: u64, ranges: &[(u64, u64)]) -> bool {
    if val < 0x1000 {
        return false;
    }
    ranges.iter().any(|&(start, end)| val >= start && val < end)
}

fn is_in_executable_section(addr: u64, sections: &[reargo_loader::Section]) -> bool {
    sections.iter().any(|s| {
        s.flags.contains(reargo_loader::SectionFlags::EXECUTE)
            && addr >= s.address
            && addr < s.address + s.size
    })
}

fn try_read_string(memory: &reargo_loader::Memory, addr: u64) -> Option<String> {
    let mut result = Vec::new();
    for i in 0..256u64 {
        match memory.read_byte(addr + i) {
            Some(0) if result.len() >= 4 => {
                return std::str::from_utf8(&result).ok().map(|s| s.to_string());
            }
            Some(0) => return None,
            Some(b) if (0x20..=0x7e).contains(&b) => result.push(b),
            _ => return None,
        }
    }
    None
}

pub struct NoReturnAnalyzer;

impl Analyzer for NoReturnAnalyzer {
    fn writes(&self) -> State {
        State::FUNC_NO_RETURN
    }
    fn name(&self) -> &str {
        "No-Return Detection"
    }

    fn description(&self) -> &str {
        "Marks functions that never return using the signature DB + heuristics"
    }

    fn priority(&self) -> u32 {
        250
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        use std::sync::OnceLock;
        use crate::signatures::SignatureDatabase;
        static DB: OnceLock<SignatureDatabase> = OnceLock::new();
        let db = DB.get_or_init(SignatureDatabase::new);

        // Build a name-set from the signature DB plus a few Rust/language-runtime names
        // not covered there.
        let mut name_set: std::collections::HashSet<String> = db
            .no_return_names()
            .flat_map(|n| {
                [
                    n.to_owned(),
                    format!("{n}@plt"),
                    format!("{n}@got.plt"),
                ]
            })
            .collect();

        // Language-runtime no-return names not in the C/Win32 signature DB
        for extra in &[
            "panic",
            "rust_panic",
            "core::panicking::panic",
            "std::process::exit",
            "__aeabi_unwind_cpp_pr0",
            "__aeabi_unwind_cpp_pr1",
            "abort@plt",
            "_abort",
        ] {
            name_set.insert(extra.to_string());
        }

        // Step 1: mark functions whose symbol name is in the no-return set
        let no_return_addrs: std::collections::BTreeSet<u64> = program
            .symbol_table
            .iter()
            .filter(|sym| name_set.contains(&sym.name))
            .map(|sym| sym.address)
            .collect();

        let mut marked = 0usize;
        for &addr in &no_return_addrs {
            if let Some(func) = program.listing.get_function_mut(addr)
                && !func.no_return
            {
                func.no_return = true;
                marked += 1;
            }
        }

        // Step 2: count callers that only call no-return targets (heuristic)
        let func_entries: Vec<u64> = program.listing.functions().map(|f| f.entry_point).collect();
        let mut detected = 0;
        for entry in func_entries {
            if let Some(func) = program.listing.get_function(entry)
                && func.call_targets.iter().any(|t| no_return_addrs.contains(t))
            {
                detected += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: detected,
            references_found: marked,
            instructions_decoded: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adding in bulk unless a reference with the same key is there gives
    /// the lists, the jump log and the count of `add_unless` one at a time,
    /// for both keys the analyzers use.
    #[test]
    fn keyed_bulk_add_matches_add_unless() {
        use reargo_program::reference::ReferenceManager;
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let kinds = [RefType::DataRead, RefType::UnconditionalJump, RefType::ConditionalJump, RefType::UnconditionalCall];
        for n in [0usize, 10, 3000, 20000] {
            let mut r = || Reference::new(0x1000 + next() % 400, 0x9000 + next() % 50, kinds[(next() % 4) as usize]);
            let existing: Vec<Reference> = (0..n / 3).map(|_| r()).collect();
            let candidates: Vec<Reference> = (0..n).map(|_| r()).collect();
            let state = |m: &ReferenceManager| {
                let all: Vec<Reference> = m.all_refs().copied().collect();
                let to: Vec<Vec<Reference>> = (0x9000..0x9000 + 50).map(|t| m.get_refs_to(t).to_vec()).collect();
                (all, to)
            };
            for by_kind in [true, false] {
                let mut one = ReferenceManager::new();
                one.add_all(&existing);
                let mut bulk = ReferenceManager::new();
                bulk.add_all(&existing);
                let (one_mark, bulk_mark) = (one.jump_mark(), bulk.jump_mark());
                let mut added = 0;
                for &c in &candidates {
                    if one.add_unless(c, |e| e.to == c.to && (!by_kind || e.ref_type == c.ref_type)) {
                        added += 1;
                    }
                }
                let got = if by_kind {
                    add_unless_keyed(&mut bulk, candidates.clone(), |r| (r.to, Some(r.ref_type)))
                } else {
                    add_unless_keyed(&mut bulk, candidates.clone(), |r| (r.to, None::<RefType>))
                };
                assert_eq!(got, added, "{n} {by_kind}");
                let (a, b) = (state(&one), state(&bulk));
                assert_eq!(a.0, b.0, "{n} {by_kind}");
                assert_eq!(a.1, b.1, "{n} {by_kind}");
                assert_eq!(one.jumps_since(one_mark), bulk.jumps_since(bulk_mark), "{n} {by_kind}");
                assert!(one.jumps_since(one_mark).is_some());
            }
        }
    }

    #[test]
    fn valid_pointer_check() {
        let ranges = vec![(0x400000, 0x500000), (0x600000, 0x700000)];
        assert!(is_valid_pointer(0x400100, &ranges));
        assert!(!is_valid_pointer(0x100, &ranges));
        assert!(!is_valid_pointer(0x550000, &ranges));
    }
}
