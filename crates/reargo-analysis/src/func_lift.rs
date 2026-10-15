//! Per-function lifting shared by the call-site passes.
//!
//! `callsite`, `cfg_const` and `vsa` all walk every function's lifted
//! P-code, lifted the same way: from the entry, `max(body bytes, 500)`
//! instructions. These helpers fix that budget and the function order
//! in one place so the passes can share one lift per function.

use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_program::Program;

/// Instruction budget used for a function: the sum of its body range
/// sizes in bytes, at least 500.
pub fn lift_budget(func: &reargo_program::Function) -> usize {
    func.body
        .ranges()
        .map(|r| r.size as usize)
        .sum::<usize>()
        .max(500)
}

/// `(entry, instruction budget)` of every function, in
/// `program.listing.functions()` order.
pub fn function_jobs(program: &Program) -> Vec<(u64, usize)> {
    program
        .listing
        .functions()
        .map(|f| (f.entry_point, lift_budget(f)))
        .collect()
}

/// Lift one function; `None` when the lift errors (the passes skip
/// such functions).
pub fn lift_function(
    lifter: &dyn PcodeLift,
    program: &Program,
    entry: u64,
    max_insns: usize,
) -> Option<Vec<LiftedInstruction>> {
    lifter
        .lift_range(&program.info.memory, entry, max_insns)
        .ok()
}
