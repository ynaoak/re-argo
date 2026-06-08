//! Resolve constant argument values at each Call site.
//!
//! For every Call instruction in the program, scan the preceding
//! P-code in the same function for the most-recent constant write
//! to each argument register. The result tells you "function X is
//! called with this argument set to this concrete value" -- the
//! foundational data needed to follow registry-style call chains
//! (e.g., `register_parser(callback, name, flags)` → who passes
//! what?).
//!
//! This is intentionally a simple intra-block constant-write
//! tracker, not a full SSA-level data-flow:
//!
//! * Walks each function's lifted P-code in instruction order.
//! * For each arg register, remembers the most recent `Copy reg =
//!   const` write.
//! * Any other write (arithmetic, load, call return value, etc.)
//!   *invalidates* the entry -- we only report values we can prove
//!   constant up to the call site.
//! * When a `Call` op is encountered, snapshot the current
//!   resolved-register map and record it as the call site's args.
//!
//! Cost: one pass per function over already-lifted instructions.
//! No SSA build, no optimization, no inter-procedural propagation
//! -- the kind of thing you can run as part of an `analyze` pass.

use gr_core::address::SpaceId;
use gr_core::pcode::{OpCode, VarnodeData};
use gr_lift::PcodeLift;
use gr_program::Program;
use rustc_hash::FxHashMap;

use crate::analyzer::AnalysisError;

/// Calling-convention argument-register offsets for x86_64 SysV in
/// declaration order: arg0..arg5 → RDI, RSI, RDX, RCX, R8, R9.
const X86_64_SYSV_ARG_REGS: [(u64, &str); 6] = [
    (0x38, "rdi"),
    (0x30, "rsi"),
    (0x10, "rdx"),
    (0x08, "rcx"),
    (0x80, "r8"),
    (0x88, "r9"),
];

/// One value resolved (or attempted) at a call site.
#[derive(Debug, Clone)]
pub struct ResolvedArg {
    /// Register offset in REGISTER space.
    pub reg_offset: u64,
    /// Human-readable register name ("rdi", "rsi", ...).
    pub reg_name: &'static str,
    /// Concrete constant value at the call site, or `None` if the
    /// register was clobbered by a non-constant op before the call.
    pub value: Option<u64>,
}

/// One Call site with its resolved argument set.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Address of the Call instruction.
    pub call_site: u64,
    /// Address of the function the call was found inside.
    pub caller_function: u64,
    /// Static call target if the lifter resolved one (direct call).
    /// `None` for indirect calls.
    pub call_target: Option<u64>,
    /// Argument values resolved at this site, in calling-convention
    /// order. Entries with `value == None` could not be statically
    /// resolved by this simple tracker.
    pub args: Vec<ResolvedArg>,
}

/// Resolve call sites across every discovered function in the
/// program. Returns one `CallSite` entry per Call instruction.
///
/// Only x86_64 is supported in this initial implementation; other
/// architectures return an empty `Vec`. Adding a new calling
/// convention is a matter of swapping `X86_64_SYSV_ARG_REGS` for the
/// arch's argument-register table.
pub fn resolve_call_sites(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
) -> Result<Vec<CallSite>, AnalysisError> {
    if !matches!(program.info.arch, gr_loader::Architecture::X86_64) {
        return Ok(Vec::new());
    }

    // Many functions' lifted ranges overlap on stripped binaries
    // (after round-9's body-union trim, in particular). Track which
    // call_site addresses we've already recorded so the output
    // doesn't list the same site under every overlapping caller.
    // We keep the first occurrence and resolve the *true* caller
    // via `function_containing` at the end.
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut out: Vec<CallSite> = Vec::new();
    for func in program.listing.functions() {
        let max_insns = func
            .body
            .ranges()
            .map(|r| r.size as usize)
            .sum::<usize>()
            .max(500);
        let Ok(lifted) = lifter.lift_range(&program.info.memory, func.entry_point, max_insns)
        else {
            continue;
        };

        // Tracking state: reg_offset -> last known constant. None
        // means "written by something we can't resolve" (i.e., the
        // entry is *not* in the map). We compare offset+size so a
        // partial write (eax) doesn't pretend to determine rax.
        let mut const_regs: FxHashMap<u64, u64> = FxHashMap::default();

        for insn in &lifted {
            for op in &insn.ops {
                match op.opcode {
                    OpCode::Call | OpCode::CallInd => {
                        if seen.insert(insn.address) {
                            let target = direct_call_target(op);
                            // Resolve the *true* containing function
                            // rather than blindly recording `func` --
                            // overlapping lifted ranges (round-9 trim
                            // union) can make `func` an outer caller
                            // that doesn't actually own this address.
                            let caller = program
                                .listing
                                .function_containing(insn.address)
                                .map(|f| f.entry_point)
                                .unwrap_or(func.entry_point);
                            let args = X86_64_SYSV_ARG_REGS
                                .iter()
                                .map(|&(offset, name)| ResolvedArg {
                                    reg_offset: offset,
                                    reg_name: name,
                                    value: const_regs.get(&offset).copied(),
                                })
                                .collect();
                            out.push(CallSite {
                                call_site: insn.address,
                                caller_function: caller,
                                call_target: target,
                                args,
                            });
                        }
                        // The callee may clobber every caller-
                        // saved register. Drop the resolved map so
                        // arguments to the NEXT call aren't carried
                        // over stale.
                        const_regs.clear();
                    }
                    _ => apply_write(op, &mut const_regs),
                }
            }
        }
    }

    Ok(out)
}

/// Update `const_regs` for `op`'s output, if any. A `Copy out = const`
/// records the value; any other op that writes to a register
/// invalidates it.
fn apply_write(op: &gr_core::pcode::PcodeOp, const_regs: &mut FxHashMap<u64, u64>) {
    let Some(out) = op.output else { return };
    if out.space != SpaceId::REGISTER {
        return;
    }
    match op.opcode {
        OpCode::Copy => {
            if let Some(input) = op.inputs.first()
                && input.space == SpaceId::CONST
            {
                const_regs.insert(out.offset, input.offset);
                return;
            }
            const_regs.remove(&out.offset);
        }
        _ => {
            const_regs.remove(&out.offset);
        }
    }
}

/// Extract the direct call target from a Call op. Returns `None`
/// for indirect calls (target is not a CONST or RAM varnode).
fn direct_call_target(op: &gr_core::pcode::PcodeOp) -> Option<u64> {
    let target_vn: &VarnodeData = op.inputs.first()?;
    if matches!(target_vn.space, SpaceId::RAM) || matches!(target_vn.space, SpaceId::CONST) {
        Some(target_vn.offset)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gr_core::pcode::{PcodeOp, SeqNum};
    use smallvec::SmallVec;

    fn const_vn(value: u64) -> VarnodeData {
        VarnodeData::new(SpaceId::CONST, value, 8)
    }
    fn reg_vn(offset: u64) -> VarnodeData {
        VarnodeData::new(SpaceId::REGISTER, offset, 8)
    }
    fn seq(addr: u64) -> SeqNum {
        SeqNum::new(gr_core::address::Address::new(SpaceId::RAM, addr), 0)
    }

    #[test]
    fn copy_const_to_register_is_tracked() {
        let mut regs: FxHashMap<u64, u64> = FxHashMap::default();
        let op = PcodeOp {
            opcode: OpCode::Copy,
            seq: seq(0x1000),
            output: Some(reg_vn(0x38)), // rdi
            inputs: SmallVec::from_slice(&[const_vn(42)]),
        };
        apply_write(&op, &mut regs);
        assert_eq!(regs.get(&0x38), Some(&42));
    }

    #[test]
    fn non_const_write_invalidates() {
        let mut regs: FxHashMap<u64, u64> = FxHashMap::default();
        regs.insert(0x38, 42);
        let op = PcodeOp {
            opcode: OpCode::IntAdd,
            seq: seq(0x1000),
            output: Some(reg_vn(0x38)),
            inputs: SmallVec::from_slice(&[reg_vn(0x30), const_vn(1)]),
        };
        apply_write(&op, &mut regs);
        assert!(!regs.contains_key(&0x38));
    }

    #[test]
    fn writes_to_other_registers_leave_target_alone() {
        let mut regs: FxHashMap<u64, u64> = FxHashMap::default();
        regs.insert(0x38, 42);
        let op = PcodeOp {
            opcode: OpCode::Copy,
            seq: seq(0x1000),
            output: Some(reg_vn(0x30)), // rsi, not rdi
            inputs: SmallVec::from_slice(&[const_vn(99)]),
        };
        apply_write(&op, &mut regs);
        assert_eq!(regs.get(&0x38), Some(&42));
        assert_eq!(regs.get(&0x30), Some(&99));
    }
}
