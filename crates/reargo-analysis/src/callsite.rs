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

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_lift::PcodeLift;
use reargo_program::Program;
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
    resolve_inner(lifter, program, &ParamSummaries::default())
}

/// Per-function summary of values its parameter registers have ever
/// been called with. Indexed by argument position 0..5 in
/// calling-convention order (RDI, RSI, RDX, RCX, R8, R9 for SysV).
///
/// Built from a `Vec<CallSite>` by `build_param_summaries`: for
/// every call to function F with a resolved `args[i] = Some(v)`, the
/// value `v` is added to F's `params[i]` set. When the set has
/// exactly one element, that parameter has a *known* value at every
/// call site we observed -- the inter-procedural propagator below
/// uses that to extend the constant-tracking inside F.
pub type ParamSummaries = FxHashMap<u64, Vec<std::collections::HashSet<u64>>>;

/// Roll up `sites` into "for each function, what constants does each
/// of its parameter registers ever receive?"  Foundation for
/// inter-procedural propagation: a function whose param 0 is always
/// called with `&handler` can be analysed as if `handler` were a
/// compile-time constant in its body.
pub fn build_param_summaries(sites: &[CallSite]) -> ParamSummaries {
    let mut out: ParamSummaries = FxHashMap::default();
    for site in sites {
        let Some(target) = site.call_target else {
            continue;
        };
        let entry = out
            .entry(target)
            .or_insert_with(|| vec![std::collections::HashSet::new(); X86_64_SYSV_ARG_REGS.len()]);
        for (i, arg) in site.args.iter().enumerate() {
            if let Some(v) = arg.value {
                entry[i].insert(v);
            }
        }
    }
    out
}

/// Re-resolve call sites with the given parameter summaries seeded
/// into each function's initial register map. A parameter with a
/// *single* observed value is treated as a compile-time constant on
/// entry; parameters with multiple values (call site polymorphism)
/// are left unresolved.
///
/// This is the single-step inter-procedural propagator. Call it in
/// a fixpoint loop (via `resolve_call_sites_iterative`) to extend
/// reach across longer call chains: each round, newly-resolved
/// arguments at outer call sites feed back into the summary for the
/// next round, and chains like
///     register_parser(my_parser) -> list_add(my_parser) -> ...
/// surface end-to-end.
pub fn resolve_call_sites_with_summaries(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    summaries: &ParamSummaries,
) -> Result<Vec<CallSite>, AnalysisError> {
    resolve_inner(lifter, program, summaries)
}

/// Shared per-function walk that powers both `resolve_call_sites`
/// (intra-function only -- pass an empty `ParamSummaries`) and
/// `resolve_call_sites_with_summaries` (inter-procedural propagation
/// -- pass the rolled-up summaries from a previous round).
fn resolve_inner(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    summaries: &ParamSummaries,
) -> Result<Vec<CallSite>, AnalysisError> {
    if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
        return Ok(Vec::new());
    }

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

        let mut tracker = Tracker::new();
        if let Some(summary) = summaries.get(&func.entry_point) {
            tracker.seed_from_summary(summary);
        }

        for insn in &lifted {
            for op in &insn.ops {
                match op.opcode {
                    OpCode::Call | OpCode::CallInd => {
                        // Only record this call site if we're
                        // actually walking the function that *owns*
                        // it. Without this gate, an earlier
                        // function whose lift_range bled past its
                        // own body would record the call with
                        // *its* tracker state (e.g. all
                        // unresolved), and `seen` would block the
                        // real owner from re-recording it with
                        // the correct seeded state.
                        let true_caller = program
                            .listing
                            .function_containing(insn.address)
                            .map(|f| f.entry_point);
                        let owns_this_call = true_caller == Some(func.entry_point);
                        if owns_this_call && seen.insert(insn.address) {
                            let target = direct_call_target(op);
                            let args = X86_64_SYSV_ARG_REGS
                                .iter()
                                .map(|&(offset, name)| ResolvedArg {
                                    reg_offset: offset,
                                    reg_name: name,
                                    value: tracker.const_regs.get(&offset).copied(),
                                })
                                .collect();
                            out.push(CallSite {
                                call_site: insn.address,
                                caller_function: func.entry_point,
                                call_target: target,
                                args,
                            });
                        }
                        tracker.clear_for_call();
                    }
                    _ => tracker.apply(op),
                }
            }
        }
    }
    Ok(out)
}

/// Iterate the propagator to fixpoint (or until `max_iters`). On
/// each round: rebuild parameter summaries from the previous
/// round's call sites, then re-resolve. Stops early when no new
/// per-param constants appear.
pub fn resolve_call_sites_iterative(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
    max_iters: usize,
) -> Result<Vec<CallSite>, AnalysisError> {
    let mut sites = resolve_call_sites(lifter, program)?;
    let mut prev_total_known = count_known_args(&sites);
    for _ in 0..max_iters {
        let summaries = build_param_summaries(&sites);
        let next = resolve_call_sites_with_summaries(lifter, program, &summaries)?;
        let next_known = count_known_args(&next);
        sites = next;
        if next_known == prev_total_known {
            break;
        }
        prev_total_known = next_known;
    }
    Ok(sites)
}

fn count_known_args(sites: &[CallSite]) -> usize {
    sites
        .iter()
        .map(|s| s.args.iter().filter(|a| a.value.is_some()).count())
        .sum()
}

/// Update `const_regs` for `op`'s output, if any. Wrapper around
/// `Tracker::apply` kept so the existing unit tests can drive a
/// single op without spinning up a full tracker.
#[cfg(test)]
fn apply_write(op: &reargo_core::pcode::PcodeOp, const_regs: &mut FxHashMap<u64, u64>) {
    let mut t = Tracker::new();
    t.const_regs = std::mem::take(const_regs);
    t.apply(op);
    *const_regs = t.const_regs;
}

/// REGISTER-space offset of `rbp` on x86_64. After the standard
/// `push rbp; mov rbp, rsp` prologue, this register is the
/// frame anchor for the rest of the function and stack slots are
/// addressed as `[rbp + signed_offset]`.
const X86_64_RBP_OFFSET: u64 = 0x28;
/// REGISTER-space offset of `rsp` on x86_64. Reserved for future
/// frame-omitted (-fomit-frame-pointer) tracking; currently the
/// tracker anchors stack slots on rbp only.
#[allow(dead_code)]
const X86_64_RSP_OFFSET: u64 = 0x20;

/// Mini abstract-interpreter that tracks enough state to thread
/// constants through gcc -O0's typical "spill to stack, reload"
/// pattern:
///
///   mov [rbp-8], rdi          ; param spill
///   ...
///   mov rax, [rbp-8]          ; reload to rax
///   mov rdi, rax              ; pass to next call
///
/// To follow the value across the spill/reload we have to track:
///
/// * `const_regs` -- known constants in REGISTER space.
/// * `const_uniques` -- known constants in UNIQUE space (the
///   lifter's temporaries between op steps).
/// * `frame_offsets` -- UNIQUE varnodes that hold an `rbp + N`
///   effective address.
/// * `stack` -- known values stored to a stack slot (signed offset
///   from rbp -> value).
///
/// This is deliberately NOT a full SSA / dataflow engine -- just
/// enough state to catch the typical -O0 call-argument flow. Loads
/// from memory not reachable from the frame pointer remain unknown;
/// non-COPY arithmetic over UNIQUE varnodes is conservatively
/// invalidated.
struct Tracker {
    const_regs: FxHashMap<u64, u64>,
    const_uniques: FxHashMap<u64, u64>,
    frame_offsets: FxHashMap<u64, i64>,
    stack: FxHashMap<i64, u64>,
}

impl Tracker {
    fn new() -> Self {
        Self {
            const_regs: FxHashMap::default(),
            const_uniques: FxHashMap::default(),
            frame_offsets: FxHashMap::default(),
            stack: FxHashMap::default(),
        }
    }

    /// Wipe per-call caller-saved state but keep what survives a
    /// call. Conservatively: clear every register and every UNIQUE
    /// temp; stack slots persist because the callee can't write to
    /// the caller's frame (modulo address-taken, which we don't
    /// model). frame_offsets are also wiped -- the lifter mints new
    /// UNIQUE addresses after each instruction.
    fn clear_for_call(&mut self) {
        self.const_regs.clear();
        self.const_uniques.clear();
        self.frame_offsets.clear();
        // self.stack is intentionally preserved.
    }

    /// Look up the value of a varnode if it is statically known.
    /// Handles CONST (literal), REGISTER (via const_regs), and
    /// UNIQUE (via const_uniques) spaces.
    fn read(&self, vn: &VarnodeData) -> Option<u64> {
        match vn.space {
            SpaceId::CONST => Some(vn.offset),
            SpaceId::REGISTER => self.const_regs.get(&vn.offset).copied(),
            SpaceId::UNIQUE => self.const_uniques.get(&vn.offset).copied(),
            _ => None,
        }
    }

    /// Apply one P-code op's effect to the tracker state.
    fn apply(&mut self, op: &reargo_core::pcode::PcodeOp) {
        // Handle stores first -- they have no output but do mutate
        // tracked state (stack slots).
        if op.opcode == OpCode::Store {
            // STORE space, addr, value -- inputs[0]=space-id,
            // inputs[1]=address, inputs[2]=value.
            if let (Some(addr), Some(value)) = (op.inputs.get(1), op.inputs.get(2))
                && addr.space == SpaceId::UNIQUE
                && let Some(&off) = self.frame_offsets.get(&addr.offset)
            {
                match self.read(value) {
                    Some(v) => {
                        self.stack.insert(off, v);
                    }
                    None => {
                        self.stack.remove(&off);
                    }
                }
            }
            return;
        }

        let Some(out) = op.output else { return };
        match out.space {
            SpaceId::REGISTER => self.write_register(op, &out),
            SpaceId::UNIQUE => self.write_unique(op, &out),
            _ => {}
        }
    }

    fn write_register(&mut self, op: &reargo_core::pcode::PcodeOp, out: &VarnodeData) {
        if op.opcode == OpCode::Copy
            && let Some(input) = op.inputs.first()
            && let Some(v) = self.read(input)
        {
            self.const_regs.insert(out.offset, v);
            return;
        }
        self.const_regs.remove(&out.offset);
    }

    fn write_unique(&mut self, op: &reargo_core::pcode::PcodeOp, out: &VarnodeData) {
        match op.opcode {
            OpCode::Copy => {
                if let Some(input) = op.inputs.first()
                    && let Some(v) = self.read(input)
                {
                    self.const_uniques.insert(out.offset, v);
                    return;
                }
                self.const_uniques.remove(&out.offset);
                self.frame_offsets.remove(&out.offset);
            }
            OpCode::Load => {
                // LOAD space, addr -- inputs[0]=space-id,
                // inputs[1]=address.
                if let Some(addr) = op.inputs.get(1)
                    && addr.space == SpaceId::UNIQUE
                    && let Some(&off) = self.frame_offsets.get(&addr.offset)
                    && let Some(&v) = self.stack.get(&off)
                {
                    self.const_uniques.insert(out.offset, v);
                    return;
                }
                self.const_uniques.remove(&out.offset);
                self.frame_offsets.remove(&out.offset);
            }
            OpCode::IntAdd | OpCode::IntSub => {
                // Recognise `unique = rbp + const` (frame
                // address). Match on either order of the addend.
                let mut is_frame_add = None;
                if op.inputs.len() >= 2 {
                    let a = &op.inputs[0];
                    let b = &op.inputs[1];
                    let frame_base = |vn: &VarnodeData| -> bool {
                        vn.space == SpaceId::REGISTER && vn.offset == X86_64_RBP_OFFSET
                    };
                    if frame_base(a) && b.space == SpaceId::CONST {
                        let mut off = b.offset as i64;
                        if op.opcode == OpCode::IntSub {
                            off = -off;
                        }
                        is_frame_add = Some(off);
                    } else if frame_base(b) && a.space == SpaceId::CONST {
                        // Sub isn't commutative; only Add takes
                        // either order. For Sub we already covered
                        // (rbp - const) above; (const - rbp)
                        // doesn't yield a meaningful frame offset.
                        if op.opcode == OpCode::IntAdd {
                            is_frame_add = Some(a.offset as i64);
                        }
                    }
                }
                if let Some(off) = is_frame_add {
                    self.frame_offsets.insert(out.offset, off);
                    self.const_uniques.remove(&out.offset);
                    return;
                }
                // Pure-constant fold for arithmetic over known
                // values. `unique = const + const` shows up after
                // the lifter folds rip-relative ops; cheap to handle.
                if op.inputs.len() >= 2
                    && let (Some(a), Some(b)) = (self.read(&op.inputs[0]), self.read(&op.inputs[1]))
                {
                    let v = match op.opcode {
                        OpCode::IntAdd => a.wrapping_add(b),
                        OpCode::IntSub => a.wrapping_sub(b),
                        _ => unreachable!(),
                    };
                    self.const_uniques.insert(out.offset, v);
                    self.frame_offsets.remove(&out.offset);
                    return;
                }
                self.const_uniques.remove(&out.offset);
                self.frame_offsets.remove(&out.offset);
            }
            _ => {
                self.const_uniques.remove(&out.offset);
                self.frame_offsets.remove(&out.offset);
            }
        }
    }

    /// Pre-seed register state from a function-entry summary built
    /// by the inter-procedural propagator.
    fn seed_from_summary(&mut self, summary: &[std::collections::HashSet<u64>]) {
        for (i, set) in summary.iter().enumerate() {
            if set.len() == 1
                && let Some(&v) = set.iter().next()
            {
                self.const_regs.insert(X86_64_SYSV_ARG_REGS[i].0, v);
            }
        }
    }

}

/// Extract the direct call target from a Call op. Returns `None`
/// for indirect calls (target is not a CONST or RAM varnode).
fn direct_call_target(op: &reargo_core::pcode::PcodeOp) -> Option<u64> {
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
    use reargo_core::pcode::{PcodeOp, SeqNum};
    use smallvec::SmallVec;

    fn const_vn(value: u64) -> VarnodeData {
        VarnodeData::new(SpaceId::CONST, value, 8)
    }
    fn reg_vn(offset: u64) -> VarnodeData {
        VarnodeData::new(SpaceId::REGISTER, offset, 8)
    }
    fn seq(addr: u64) -> SeqNum {
        SeqNum::new(reargo_core::address::Address::new(SpaceId::RAM, addr), 0)
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
