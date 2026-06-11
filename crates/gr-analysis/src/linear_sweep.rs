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

use gr_arch::FlowType;
use gr_lift::PcodeLift;
use gr_program::function::Function;
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

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
        // After CrtPattern (470) so we don't fight its renames;
        // before signature-driven passes so the new functions get
        // every downstream analyzer's full treatment.
        480
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, gr_loader::Architecture::X86_64) {
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
            .filter(|s| s.flags.contains(gr_loader::SectionFlags::EXECUTE))
            .map(|s| (s.address, s.address + s.size))
            .collect();

        let lifter: Box<dyn PcodeLift> = Box::new(gr_lift::x86::X86Lifter::new_64());
        let mut new_functions: Vec<u64> = Vec::new();
        let mut visited: BTreeSet<u64> = BTreeSet::new();

        for (sec_start, sec_end) in &exec_sections {
            let mut addr = (*sec_start + 15) & !15;
            while addr + 8 < *sec_end {
                if !is_uncovered(addr, &covered) && !visited.insert(addr) {
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
                if is_inside_function_body(addr, &covered) {
                    addr += 16;
                    continue;
                }
                // Speculatively lift up to 256 insns. Accept the
                // candidate iff the lift reaches a Return / IndirectJump
                // and doesn't overlap existing functions.
                if validate_candidate(&*lifter, program, addr, &covered) {
                    new_functions.push(addr);
                }
                addr += 16;
            }
        }

        let mut added = 0usize;
        for entry in &new_functions {
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

fn is_uncovered(addr: u64, covered: &[(u64, u64)]) -> bool {
    !covered.iter().any(|(s, e)| addr >= *s && addr < *e)
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
fn validate_candidate(
    lifter: &dyn PcodeLift,
    program: &Program,
    entry: u64,
    covered: &[(u64, u64)],
) -> bool {
    let Ok(lifted) = lifter.lift_range(&program.info.memory, entry, 256) else {
        return false;
    };
    if lifted.len() < 3 {
        return false;
    }
    let mut terminated = false;
    for insn in &lifted {
        if is_inside_function_body(insn.address, covered) {
            return false;
        }
        // Look at the underlying `DecodedInstruction.flow_type` via
        // the listing if the address is decoded, else inspect the
        // P-code op to detect a Return. The lifter's
        // `LiftedInstruction` carries the raw bytes + ops but not
        // the high-level flow_type, so we check op opcode directly.
        for op in &insn.ops {
            if matches!(
                op.opcode,
                gr_core::pcode::OpCode::Return
                    | gr_core::pcode::OpCode::BranchInd
            ) {
                terminated = true;
                break;
            }
        }
        if terminated {
            break;
        }
        if let Some(insn_meta) = program.listing.instructions_in_range(insn.address, insn.address + 1).next()
            && matches!(insn_meta.flow_type, FlowType::Return | FlowType::IndirectJump | FlowType::IndirectCall)
        {
            terminated = true;
            break;
        }
    }
    terminated
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
}
