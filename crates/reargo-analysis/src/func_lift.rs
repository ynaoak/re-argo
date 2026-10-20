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

/// Whether the instruction at `addr` belongs to the function at
/// `entry`. A lift runs linearly past the function's end (and a lift
/// from a bogus interior entry starts mid-function), so a pass that
/// records per-instruction results keeps only the ones of the function
/// it walked: another function's view of the code has the wrong
/// predecessors.
pub fn owns(program: &Program, entry: u64, addr: u64) -> bool {
    program.listing.function_containing(addr).map(|f| f.entry_point) == Some(entry)
}

/// [`owns`] for the function at one entry, its listing lookups done
/// once: the last function at or before an address is the one at
/// `entry` exactly when the address is in `[entry, next entry)`, and
/// [`reargo_program::listing::Listing::function_containing`] gives it
/// when its body holds the address.
pub struct Owner<'p> {
    entry: u64,
    next: Option<u64>,
    function: Option<&'p reargo_program::Function>,
}

impl<'p> Owner<'p> {
    pub fn new(program: &'p Program, entry: u64) -> Self {
        Self {
            entry,
            next: program.listing.next_function_after(entry).map(|f| f.entry_point),
            function: program.listing.get_function(entry),
        }
    }

    /// [`owns`]`(program, entry, addr)`.
    pub fn owns(&self, addr: u64) -> bool {
        addr >= self.entry
            && self.next.is_none_or(|n| addr < n)
            && self.function.is_some_and(|f| {
                f.body.contains(&reargo_core::address::Address::new(reargo_core::address::SpaceId::RAM, addr))
            })
    }
}

/// Instructions of `insns` that control can reach other than along
/// the jumps and fall-throughs of `insns` itself: the targets of a
/// recovered jump table (`IndirectJump` references) and of a jump from
/// code outside the lift (a `.cold` part jumping back, another
/// function's tail jump into the middle). A tracker must not assume
/// it knows the state on entry to them.
pub fn external_entries<I: std::borrow::Borrow<LiftedInstruction>>(
    program: &Program,
    insns: &[I],
) -> std::collections::BTreeSet<u64> {
    external_entries_at(program, &insns.iter().map(|i| i.borrow().address).collect::<Vec<_>>())
}

/// [`external_entries`] of a lift given by the addresses of its
/// instructions, in lift order.
pub fn external_entries_at(program: &Program, addrs: &[u64]) -> std::collections::BTreeSet<u64> {
    use reargo_program::RefType;
    // a linear lift: addresses increase
    let lifted = |a: u64| addrs.binary_search(&a).is_ok();
    addrs
        .iter()
        .copied()
        .filter(|&a| {
            program.references.get_refs_to(a).iter().any(|r| match r.ref_type {
                RefType::IndirectJump => true,
                RefType::UnconditionalJump | RefType::ConditionalJump => !lifted(r.from),
                _ => false,
            })
        })
        .collect()
}

/// The jump references of a program by target, to compute
/// [`external_entries`] of many lifts: a lift's are found among the
/// references into its address range instead of by a lookup per
/// lifted instruction.
pub struct JumpIndex {
    /// `(to, from, type)`, sorted by `to`.
    refs: Vec<(u64, u64, reargo_program::RefType)>,
}

impl JumpIndex {
    pub fn new(program: &Program) -> Self {
        // sorted by target already
        let refs = program.references.jump_refs_sorted_by_target().into_iter().map(|r| (r.to, r.from, r.ref_type)).collect();
        Self { refs }
    }

    /// [`external_entries`] of `insns`, while the program's references
    /// are those the index was built from.
    pub fn external_entries<I: std::borrow::Borrow<LiftedInstruction>>(
        &self,
        program: &Program,
        insns: &[I],
    ) -> std::collections::BTreeSet<u64> {
        self.external_entries_at(program, &insns.iter().map(|i| i.borrow().address).collect::<Vec<_>>())
    }

    /// [`JumpIndex::external_entries`] of a lift given by the addresses
    /// of its instructions, in lift order.
    pub fn external_entries_at(&self, program: &Program, addrs: &[u64]) -> std::collections::BTreeSet<u64> {
        use reargo_program::RefType;
        if !addrs.windows(2).all(|w| w[0] < w[1]) {
            return external_entries_at(program, addrs);
        }
        let mut out = std::collections::BTreeSet::new();
        let (Some(&first), Some(&last)) = (addrs.first(), addrs.last()) else {
            return out;
        };
        let lifted = |a: u64| a >= first && a <= last && addrs.binary_search(&a).is_ok();
        let start = self.refs.partition_point(|r| r.0 < first);
        // (the targets ascend: whether one is lifted is found by stepping through the
        // addresses alongside)
        let mut at = 0;
        let mut found = Vec::new();
        for &(to, from, ty) in self.refs[start..].iter().take_while(|r| r.0 <= last) {
            if !matches!(ty, RefType::IndirectJump | RefType::UnconditionalJump | RefType::ConditionalJump) {
                continue;
            }
            while addrs[at] < to {
                at += 1;
            }
            if addrs[at] != to || found.last() == Some(&to) {
                continue;
            }
            if ty == RefType::IndirectJump || !lifted(from) {
                found.push(to);
            }
        }
        out.extend(found);
        out
    }
}

/// Whether `addr` lies between the entry of the function at `entry`
/// and the next function's entry: its body, including the parts the
/// listing has not attributed to it (jump-table cases no discovery
/// followed).
pub fn in_extent(program: &Program, entry: u64, addr: u64) -> bool {
    addr >= entry && program.listing.next_function_after(entry).is_none_or(|f| addr < f.entry_point)
}
