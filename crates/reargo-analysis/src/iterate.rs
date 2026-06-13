//! Heuristic correction-proposal engine.
//!
//! Auto-analysis is never perfect, and PR #22 added the persistent
//! `OverrideSet` layer so manual corrections survive re-analysis.
//! This module is the bridge between those two: scan a freshly-
//! analysed program for clear-cut analyser mistakes and propose
//! concrete `Correction`s that, when applied to the override
//! sidecar and re-analysed, push the model closer to correct.
//!
//! It powers two flows:
//!
//! * **AI-driven** -- exposed through MCP tools (`propose_corrections`,
//!   `apply_override`, `assess_function`, `reanalyze`) so a Claude /
//!   other agent can sit in a loop: ask for proposals, decide which
//!   to apply, re-analyse, re-decompile, repeat.
//!
//! * **Auto-driven** -- the `iterate` CLI subcommand runs the
//!   propose -> apply -> re-analyse loop locally to a fixpoint
//!   without an AI in the loop, using only the deterministic
//!   heuristics here.
//!
//! Heuristics implemented (v1):
//!
//! 1. **MissingCallTargetFunction** -- a Call op whose `branch_target`
//!    is a code-section address with no function defined.
//!    Proposes `ForceFunction`. The most common "auto-analysis
//!    missed it" case on stripped binaries.
//!
//! 2. **TinyFunctionAfterRetPadding** -- a function whose body is
//!    only 1-2 instructions and starts immediately after a long
//!    int3/nop run. Likely a pattern-matcher false positive.
//!    Proposes `NotFunction`.
//!
//! 3. **EmptyFunction** -- a function whose body has zero
//!    discovered instructions (discovery stopped before lifting
//!    anything). Proposes `NotFunction`.
//!
//! Each proposal carries a `reason` string so the AI / user sees
//! WHY the heuristic suggested it.

use std::collections::BTreeSet;

use reargo_arch::FlowType;
use reargo_program::overrides::OverrideSet;
use reargo_program::Program;

/// One proposed manual correction with an explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correction {
    pub kind: CorrectionKind,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrectionKind {
    /// Force the address to be a function entry.
    ForceFunction { addr: u64 },
    /// Remove the auto-discovered function at the address.
    NotFunction { addr: u64 },
    /// Rename the function / symbol at the address.
    Rename { addr: u64, name: String },
    /// Pin the calling convention at the address.
    SetCallingConvention { addr: u64, cc: String },
}

impl Correction {
    /// Merge this correction into the given override set.
    pub fn apply_to(&self, set: &mut OverrideSet) {
        match &self.kind {
            CorrectionKind::ForceFunction { addr } => {
                if !set.force_functions.contains(addr) {
                    set.force_functions.push(*addr);
                }
                // If the same address was previously remove-listed
                // by an older round, the apply-time ordering in
                // OverrideSet::apply (remove-before-force) handles
                // it; we don't undo the not-func here because the
                // user may have meant both.
            }
            CorrectionKind::NotFunction { addr } => {
                if !set.remove_functions.contains(addr) {
                    set.remove_functions.push(*addr);
                }
            }
            CorrectionKind::Rename { addr, name } => {
                set.names.insert(*addr, name.clone());
            }
            CorrectionKind::SetCallingConvention { addr, cc } => {
                set.calling_conventions.insert(*addr, cc.clone());
            }
        }
    }

    /// Short address tag for log output.
    pub fn addr(&self) -> u64 {
        match &self.kind {
            CorrectionKind::ForceFunction { addr }
            | CorrectionKind::NotFunction { addr }
            | CorrectionKind::Rename { addr, .. }
            | CorrectionKind::SetCallingConvention { addr, .. } => *addr,
        }
    }
}

/// Per-function assessment surfaced to the AI / iterate loop. The
/// numbers are stable enough to compare across rounds so the caller
/// can tell whether a correction actually improved things.
#[derive(Debug, Clone)]
pub struct FunctionAssessment {
    pub entry: u64,
    pub name: String,
    pub instruction_count: usize,
    pub body_byte_size: u64,
    /// Number of distinct Call op sites in the body.
    pub call_sites: usize,
    /// `true` if the body's last instruction (in address order) is a
    /// Call (rather than Return / unconditional jump). A strong
    /// "discovery stopped at the first call" signal.
    pub ends_on_call: bool,
    /// Addresses of statically-known call targets that don't
    /// resolve to a function in this program. Each is a candidate
    /// for `force_function`.
    pub unresolved_call_targets: Vec<u64>,
}

impl FunctionAssessment {
    /// Single-line summary, suitable for printing in the iterate
    /// driver's per-round log.
    pub fn one_line(&self) -> String {
        format!(
            "0x{:08x}  {:<32}  insns={}  bytes={}  calls={}{}{}",
            self.entry,
            self.name,
            self.instruction_count,
            self.body_byte_size,
            self.call_sites,
            if self.ends_on_call {
                "  TRUNCATED-AT-CALL"
            } else {
                ""
            },
            if self.unresolved_call_targets.is_empty() {
                String::new()
            } else {
                format!(
                    "  unresolved-targets={}",
                    self.unresolved_call_targets.len()
                )
            },
        )
    }
}

/// Compute an assessment for a single function. Returns `None` if
/// no such function exists.
pub fn assess_function(program: &Program, entry: u64) -> Option<FunctionAssessment> {
    let func = program.listing.get_function(entry)?;
    let body_byte_size: u64 = func.body.ranges().map(|r| r.size).sum();

    // Walk every instruction in the function body for call-flow
    // statistics.
    let mut call_sites = 0usize;
    let mut last_flow = FlowType::Fall;
    let mut instruction_count = 0usize;
    let mut unresolved: Vec<u64> = Vec::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();

    for range in func.body.ranges() {
        let start = range.start.offset;
        let end = start + range.size;
        for insn in program.listing.instructions_in_range(start, end) {
            instruction_count += 1;
            last_flow = insn.flow_type;
            if matches!(insn.flow_type, FlowType::Call) {
                call_sites += 1;
                if let Some(target) = insn.branch_target
                    && !program.listing.has_function(target)
                    && in_executable_section(target, program)
                    && seen.insert(target)
                {
                    unresolved.push(target);
                }
            }
        }
    }

    Some(FunctionAssessment {
        entry,
        name: func.name.clone(),
        instruction_count,
        body_byte_size,
        call_sites,
        ends_on_call: matches!(last_flow, FlowType::Call),
        unresolved_call_targets: unresolved,
    })
}

/// Walk every discovered function and propose corrections, with no
/// pre-existing override context. Equivalent to
/// `propose_corrections_ctx(program, None)`.
pub fn propose_corrections(program: &Program) -> Vec<Correction> {
    propose_corrections_ctx(program, None)
}

/// Like `propose_corrections`, but suppresses proposals that would
/// fight corrections already recorded in `overrides`:
///
/// * Don't propose `NotFunction` for an address the user / loop has
///   `force_function`ed (e.g. a force-added entry whose body is
///   still empty -- that's expected, not a false positive).
/// * Don't propose `ForceFunction` for an address already on the
///   `remove_functions` list.
///
/// This is what makes the auto-iterate loop converge cleanly instead
/// of oscillating between adding and removing the same entry.
pub fn propose_corrections_ctx(
    program: &Program,
    overrides: Option<&OverrideSet>,
) -> Vec<Correction> {
    let forced: BTreeSet<u64> = overrides
        .map(|o| o.force_functions.iter().copied().collect())
        .unwrap_or_default();
    let removed: BTreeSet<u64> = overrides
        .map(|o| o.remove_functions.iter().copied().collect())
        .unwrap_or_default();

    let mut out: Vec<Correction> = Vec::new();
    let mut suggested_force: BTreeSet<u64> = BTreeSet::new();

    for func in program.listing.functions() {
        let entry = func.entry_point;
        let body_size: u64 = func.body.ranges().map(|r| r.size).sum();

        // Never re-propose removing something explicitly forced.
        let pinned = forced.contains(&entry);

        // Only auto-discovered functions (named `FUN_*`, i.e. with no
        // better symbol) are candidates for removal. A function that
        // carries a real name from the symbol table / debug info is
        // assumed correct even if discovery failed to lift its body
        // -- removing it would throw away a genuine symbol.
        let auto_named = func.name.starts_with("FUN_");
        // Likewise, never propose removing the program entry point.
        let is_entry = entry == program.entry_point();

        // Heuristic 3: EmptyFunction
        let insn_count = func
            .body
            .ranges()
            .map(|r| {
                program
                    .listing
                    .instructions_in_range(r.start.offset, r.start.offset + r.size)
                    .count()
            })
            .sum::<usize>();
        if insn_count == 0 && body_size == 0 {
            if auto_named && !is_entry && !pinned {
                out.push(Correction {
                    kind: CorrectionKind::NotFunction { addr: entry },
                    reason: "auto-discovered function with no lifted instructions -- likely spurious".into(),
                });
            }
            continue;
        }

        // Heuristic 1: MissingCallTargetFunction -- collect unique
        // call targets across the body that aren't already defined.
        for range in func.body.ranges() {
            for insn in program
                .listing
                .instructions_in_range(range.start.offset, range.start.offset + range.size)
            {
                if !matches!(insn.flow_type, FlowType::Call) {
                    continue;
                }
                let Some(target) = insn.branch_target else { continue };
                if program.listing.has_function(target) {
                    continue;
                }
                if !in_executable_section(target, program) {
                    continue;
                }
                // Don't fight an explicit remove of this target.
                if removed.contains(&target) {
                    continue;
                }
                if suggested_force.insert(target) {
                    out.push(Correction {
                        kind: CorrectionKind::ForceFunction { addr: target },
                        reason: format!(
                            "called from 0x{:08x} (function 0x{:08x}) but not defined as a function",
                            insn.address, entry
                        ),
                    });
                }
            }
        }

        // Heuristic 2: TinyFunctionAfterRetPadding -- a 1-2 insn
        // function whose first byte is preceded by >=3 padding
        // bytes (int3/nop/null). Heuristic for pattern-matcher
        // false positives on stripped binaries. Auto-named only,
        // never the entry point.
        if auto_named
            && !is_entry
            && !pinned
            && insn_count <= 2
            && body_size <= 8
            && is_after_long_padding(program, entry)
        {
            out.push(Correction {
                kind: CorrectionKind::NotFunction { addr: entry },
                reason: format!(
                    "{}-insn function ({} bytes) sitting after >=3 bytes of padding -- likely pattern false positive",
                    insn_count, body_size
                ),
            });
        }
    }

    out
}

fn in_executable_section(addr: u64, program: &Program) -> bool {
    program
        .info
        .sections
        .iter()
        .any(|s| s.flags.contains(reargo_loader::SectionFlags::EXECUTE) && addr >= s.address && addr < s.address + s.size)
}

/// True if the 3 bytes immediately preceding `addr` are all padding
/// bytes (int3 / nop / null). Cheap proxy for "we're sitting in a
/// stripped binary's inter-function padding region".
fn is_after_long_padding(program: &Program, addr: u64) -> bool {
    if addr < 3 {
        return false;
    }
    let mut buf = [0u8; 3];
    if program
        .info
        .memory
        .read_bytes(addr - 3, &mut buf)
        .is_err()
    {
        return false;
    }
    buf.iter().all(|&b| matches!(b, 0xCC | 0x90 | 0x00))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correction_apply_dedup() {
        let mut set = OverrideSet::default();
        let c1 = Correction {
            kind: CorrectionKind::ForceFunction { addr: 0x1234 },
            reason: "test".into(),
        };
        c1.apply_to(&mut set);
        c1.apply_to(&mut set);
        assert_eq!(set.force_functions, vec![0x1234]);
    }

    #[test]
    fn correction_addr_uniform() {
        let c = Correction {
            kind: CorrectionKind::Rename {
                addr: 0xdeadbeef,
                name: "x".into(),
            },
            reason: String::new(),
        };
        assert_eq!(c.addr(), 0xdeadbeef);
    }
}
