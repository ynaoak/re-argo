//! Linear-sweep speculative function discovery.
//!
//! Binary Ninja's `analysis.linearSweep` runs after recursive descent
//! and walks every executable section byte-by-byte (well, aligned)
//! looking for instructions that look like function prologues. Each
//! candidate is speculatively lifted; if the lift terminates at a
//! `ret` without colliding with already-decoded territory, the
//! candidate is registered as a new function.
//!
//! Our `FunctionDiscoveryAnalyzer` is recursive-descent only — it
//! starts from `entry_point + symbol_table + .init_array`. On
//! stripped binaries with no exported function symbols this catches
//! `main` and its transitive callees, but misses every function the
//! callgraph doesn't reach (handler tables registered at runtime,
//! dead-but-still-emitted code, callback arrays in `.data.rel.ro`,
//! libgcc thunks…).
//!
//! Linear sweep is the standard fix. We do it conservatively:
//!
//! 1. Walk each executable section at 16-byte alignment (the linker's
//!    default function alignment on x86_64 / arm64).
//! 2. Skip candidates already inside a discovered function body.
//! 3. Match against a small prologue dictionary
//!    (`endbr64 + push rbp`, `push rbp + mov rbp, rsp`,
//!    `sub rsp, imm8`, `endbr64 + sub rsp, …`).
//! 4. Speculatively lift up to 256 instructions; accept the
//!    candidate iff:
//!      * a `ret` (or other terminator) is reached, AND
//!      * the body doesn't overlap an existing function.
//! 5. Register the survivor as a `FUN_<addr>` function; later
//!    analyzers (CrtPattern / StringHintRename / signature DB)
//!    rename it if they recognise the shape.
//!
//! Safe to run after FunctionDiscovery — anything we find here is
//! by construction outside the recursive-descent reach. Stops at
//! the section boundary, so .rodata bytes after .text are untouched.

use std::collections::BTreeSet;

use reargo_arch::FlowType;
use reargo_lift::PcodeLift;
use reargo_program::function::Function;
use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct LinearSweepAnalyzer;

impl Analyzer for LinearSweepAnalyzer {
    fn name(&self) -> &str {
        "Linear Sweep"
    }
    fn description(&self) -> &str {
        "Speculative function discovery via prologue scan + lift-and-validate"
    }
    fn priority(&self) -> u32 {
        // After CrtAnalyzer (710) + LateDiscovery (730) so `main` and
        // every CrtPattern-recovered body is in the listing before
        // we walk uncovered territory. Running earlier (the previous
        // 480 slot) caused stripped binaries to register `main`'s
        // prologue or interior bytes as `FUN_*` because CrtAnalyzer
        // hadn't seeded the function yet, leaving its body absent
        // from `covered`.
        //
        // 740 sits between LateDiscovery (730) and CallSiteAnnotator
        // (750) so signature-driven renamers see the new entries
        // in the same round as everything else.
        740
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
            // Prologue patterns + lifter are x86_64-specific for
            // now. Add ARM64 / RISC-V variants later if needed.
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        // Build set of (start, end) tuples for every existing
        // function body so we can reject candidates that fall
        // inside known territory.
        let mut covered: Vec<(u64, u64)> = Vec::new();
        for f in program.listing.functions() {
            for r in f.body.ranges() {
                covered.push((r.start.offset, r.start.offset + r.size));
            }
        }
        covered.sort_by_key(|(s, _)| *s);

        let exec_sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(reargo_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.address + s.size))
            .collect();

        let lifter: Box<dyn PcodeLift> = Box::new(reargo_lift::x86::X86Lifter::new_64());
        let mut new_functions: Vec<(u64, u64)> = Vec::new();
        let mut visited: BTreeSet<u64> = BTreeSet::new();

        for (sec_start, sec_end) in &exec_sections {
            let mut addr = (*sec_start + 15) & !15;
            while addr + 8 < *sec_end {
                // Skip when EITHER the address is already inside a
                // known function body OR we've already tried it this
                // run. The previous form used `&&` AND short-circuited
                // past `visited.insert` for the dominant case, so
                // `visited` never populated and we re-walked every
                // address.
                if is_inside_function_body(addr, &covered) || !visited.insert(addr) {
                    addr += 16;
                    continue;
                }
                // Pull 16 bytes to test against the prologue dict.
                let mut probe = [0u8; 16];
                if program.info.memory.read_bytes(addr, &mut probe).is_err() {
                    addr += 16;
                    continue;
                }
                if !looks_like_prologue(&probe) {
                    addr += 16;
                    continue;
                }
                // Speculatively lift up to 256 insns. Accept the
                // candidate iff the lift reaches a Return / IndirectJump
                // and doesn't overlap existing functions. On accept,
                // record the lifted range so subsequent 16-byte-aligned
                // candidates inside the newly-found body get skipped
                // by the next iteration's `is_inside_function_body`
                // check (and not re-validated).
                if let Some(end) = validate_candidate_with_extent(&*lifter, program, addr, &covered)
                {
                    new_functions.push((addr, end));
                    covered.push((addr, end));
                    // Re-sort so the binary-search-style scan stays
                    // consistent. Cost is linear-in-N; the candidate
                    // count is bounded by section size / 16 so this
                    // doesn't dominate.
                    covered.sort_by_key(|(s, _)| *s);
                }
                addr += 16;
            }
        }

        let mut added = 0usize;
        for (entry, _end) in &new_functions {
            if program.listing.has_function(*entry) {
                continue;
            }
            program
                .listing
                .add_function(Function::new(*entry, format!("FUN_{:08x}", entry)));
            if program.symbol_table.primary_at(*entry).is_none() {
                program.symbol_table.add(Symbol::new(
                    format!("FUN_{:08x}", entry),
                    *entry,
                    SymbolType::Function,
                    SourceType::Analysis,
                ));
            }
            added += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: added,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

fn is_inside_function_body(addr: u64, covered: &[(u64, u64)]) -> bool {
    covered.iter().any(|(s, e)| addr >= *s && addr < *e)
}

/// Match the four prologue families most x86_64 code uses. Keeping
/// this in sync with `crt_patterns.rs`'s no-pie prologue set is
/// intentional — anything we'd recognise as a CRT helper there is
/// also worth trying here.
fn looks_like_prologue(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    // endbr64 + ... (every CET-enabled function on modern Linux)
    if bytes[0] == 0xf3 && bytes[1] == 0x0f && bytes[2] == 0x1e && bytes[3] == 0xfa {
        return true;
    }
    // push rbp + mov rbp, rsp (gcc -O0 / clang default)
    if bytes.len() >= 4
        && bytes[0] == 0x55
        && bytes[1] == 0x48
        && bytes[2] == 0x89
        && bytes[3] == 0xe5
    {
        return true;
    }
    // sub rsp, imm8 (gcc -O2 leaf-function leadin)
    if bytes.len() >= 4
        && bytes[0] == 0x48
        && bytes[1] == 0x83
        && bytes[2] == 0xec
    {
        return true;
    }
    // push r15 / push r14 / push rbx — registers callees must
    // preserve. Common on optimised builds with no frame pointer.
    if matches!(bytes[0], 0x53 | 0x55 | 0x56 | 0x57)
        || (bytes[0] == 0x41 && (0x54..=0x57).contains(&bytes[1]))
    {
        return true;
    }
    false
}

/// Lift the candidate up to 256 instructions. Accept it iff:
///  * the lift produces ≥ 3 instructions (single-`ret` runs aren't
///    interesting; CRT thunks are picked up by CrtPatternAnalyzer)
///  * the lift terminates at a Return / IndirectJump / IndirectCall
///  * none of the lifted addresses fall inside an existing
///    function's body — overlap means we re-discovered a known
///    function or stumbled into the middle of one
///
/// On accept, returns `Some(end_address)` where `end_address` is
/// exclusive (last_insn.address + last_insn.length). Callers feed
/// this back into `covered` so adjacent candidates inside the
/// just-discovered body get skipped without re-lifting.
fn validate_candidate_with_extent(
    lifter: &dyn PcodeLift,
    program: &Program,
    entry: u64,
    covered: &[(u64, u64)],
) -> Option<u64> {
    let lifted = lifter.lift_range(&program.info.memory, entry, 256).ok()?;
    if lifted.len() < 3 {
        return None;
    }
    let mut terminator_idx: Option<usize> = None;
    for (i, insn) in lifted.iter().enumerate() {
        if is_inside_function_body(insn.address, covered) {
            return None;
        }
        // Look at the underlying `DecodedInstruction.flow_type` via
        // the listing if the address is decoded, else inspect the
        // P-code op to detect a Return. The lifter's
        // `LiftedInstruction` carries the raw bytes + ops but not
        // the high-level flow_type, so we check op opcode directly.
        let pcode_terminates = insn.ops.iter().any(|op| {
            matches!(
                op.opcode,
                reargo_core::pcode::OpCode::Return | reargo_core::pcode::OpCode::BranchInd
            )
        });
        let flow_terminates = program
            .listing
            .instructions_in_range(insn.address, insn.address + 1)
            .next()
            .is_some_and(|m| {
                matches!(
                    m.flow_type,
                    FlowType::Return | FlowType::IndirectJump | FlowType::IndirectCall
                )
            });
        if pcode_terminates || flow_terminates {
            terminator_idx = Some(i);
            break;
        }
    }
    let idx = terminator_idx?;
    let last = &lifted[idx];
    Some(last.address + last.length as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endbr64_prologue_matches() {
        let bytes = [0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5];
        assert!(looks_like_prologue(&bytes));
    }

    #[test]
    fn push_rbp_prologue_matches() {
        let bytes = [0x55, 0x48, 0x89, 0xe5];
        assert!(looks_like_prologue(&bytes));
    }

    #[test]
    fn sub_rsp_leaf_matches() {
        // sub rsp, 0x28
        let bytes = [0x48, 0x83, 0xec, 0x28];
        assert!(looks_like_prologue(&bytes));
    }

    #[test]
    fn push_callee_saved_matches() {
        // push r15
        assert!(looks_like_prologue(&[0x41, 0x57, 0x00, 0x00]));
        // push rbx
        assert!(looks_like_prologue(&[0x53, 0x48, 0x89, 0xe5]));
    }

    #[test]
    fn random_bytes_rejected() {
        assert!(!looks_like_prologue(&[0x00, 0x00, 0x00, 0x00]));
        assert!(!looks_like_prologue(&[0x90, 0x90, 0x90, 0x90]));
    }

    #[test]
    fn coverage_overlap_detection() {
        let covered = vec![(0x1000, 0x1100), (0x2000, 0x2050)];
        assert!(is_inside_function_body(0x1050, &covered));
        assert!(is_inside_function_body(0x2049, &covered));
        assert!(!is_inside_function_body(0x1500, &covered));
        assert!(!is_inside_function_body(0x2050, &covered));
    }

    /// Synthesise a tiny ELF-shaped Program with a single
    /// push/mov/ret routine and confirm the validator accepts it
    /// AND reports an end address pointing past the `ret`. This is
    /// the regression test for the post-review fix that swapped
    /// `validate_candidate -> bool` for `validate_candidate_with_extent
    /// -> Option<u64>`.
    #[test]
    fn validate_returns_end_address_for_simple_function() {
        use crate::testutil::helpers::make_x86_64_program;

        // push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let code: [u8; 8] = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let entry = 0x1000u64;
        let program = make_x86_64_program(&code, entry);
        let lifter = reargo_lift::x86::X86Lifter::new_64();

        let end = validate_candidate_with_extent(&lifter, &program, entry, &[])
            .expect("simple ret-terminated routine should validate");
        // ret is the last byte: addr 0x1007, length 1 → end = 0x1008.
        assert_eq!(end, entry + code.len() as u64);
    }

    /// Bodies that overlap an already-covered range must be rejected
    /// even if they would otherwise terminate. This pins down the
    /// "don't re-discover the same function" guarantee.
    #[test]
    fn validate_rejects_when_overlap_with_covered() {
        use crate::testutil::helpers::make_x86_64_program;

        let code: [u8; 8] = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let entry = 0x1000u64;
        let program = make_x86_64_program(&code, entry);
        let lifter = reargo_lift::x86::X86Lifter::new_64();

        // Cover 0x1004..0x1008 so the lift collides on its third
        // instruction (`xor eax, eax` at 0x1004).
        let covered = vec![(0x1004u64, 0x1008u64)];
        assert!(
            validate_candidate_with_extent(&lifter, &program, entry, &covered).is_none(),
            "overlap with covered range must reject"
        );
    }

    /// Sequences with no terminator must be rejected — otherwise the
    /// sweep would happily mark the middle of `.text` as a function
    /// every 16 bytes.
    #[test]
    fn validate_rejects_when_no_terminator() {
        use crate::testutil::helpers::make_x86_64_program;

        // Four `mov eax, eax` style fillers, no ret.
        let code: [u8; 16] = [
            0x89, 0xc0, 0x89, 0xc0, 0x89, 0xc0, 0x89, 0xc0, 0x89, 0xc0, 0x89, 0xc0, 0x89, 0xc0,
            0x89, 0xc0,
        ];
        let entry = 0x2000u64;
        let program = make_x86_64_program(&code, entry);
        let lifter = reargo_lift::x86::X86Lifter::new_64();

        assert!(validate_candidate_with_extent(&lifter, &program, entry, &[]).is_none());
    }
}
