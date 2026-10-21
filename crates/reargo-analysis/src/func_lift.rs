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
    let enters = |refs: &[reargo_program::Reference]| {
        refs.iter().any(|r| match r.ref_type {
            RefType::IndirectJump => true,
            RefType::UnconditionalJump | RefType::ConditionalJump => !lifted(r.from),
            _ => false,
        })
    };
    if let (Some(&first), Some(&last)) = (addrs.first(), addrs.last())
        && addrs.windows(2).all(|w| w[0] < w[1])
    {
        // (the addresses with references in the lift's span, stepped through beside the
        // lifted ones, instead of a lookup per lifted address)
        let mut at = 0;
        let mut out = std::collections::BTreeSet::new();
        for (to, refs) in program.references.refs_to_range(first, last.saturating_add(1)) {
            while addrs[at] < to {
                at += 1;
            }
            if addrs[at] == to && enters(refs) {
                out.insert(to);
            }
        }
        // (`last` is `u64::MAX`: its references are not in the range)
        if last == u64::MAX && enters(program.references.get_refs_to(last)) {
            out.insert(last);
        }
        return out;
    }
    addrs.iter().copied().filter(|&a| enters(program.references.get_refs_to(a))).collect()
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
        self.external_entries_ordered(program, addrs, addrs.windows(2).all(|w| w[0] < w[1]))
    }

    /// [`JumpIndex::external_entries_at`], `increasing` saying whether the addresses
    /// strictly increase.
    pub fn external_entries_ordered(
        &self,
        _program: &Program,
        addrs: &[u64],
        increasing: bool,
    ) -> std::collections::BTreeSet<u64> {
        if increasing {
            let mut found = Vec::new();
            self.external_entries_increasing(addrs, None, &mut found);
            return found.into_iter().collect();
        }
        self.external_entries_unordered(addrs)
    }

    /// [`JumpIndex::external_entries_ordered`] as an ascending list, put in
    /// `out` (emptied first). `finder`, when given, finds the position of an address among
    /// `addrs` (of an increasing lift borrowed from a lift cache:
    /// [`reargo_lift::RangeShapes::positions`]).
    pub fn external_entries_sorted_into(
        &self,
        program: &Program,
        addrs: &[u64],
        increasing: bool,
        finder: Option<&reargo_lift::PositionFinder>,
        out: &mut Vec<u64>,
    ) {
        out.clear();
        if increasing {
            self.external_entries_increasing(addrs, finder, out);
        } else {
            out.extend(self.external_entries_ordered(program, addrs, false));
        }
    }

    /// [`JumpIndex::external_entries_ordered`] of addresses that do not strictly increase.
    fn external_entries_unordered(&self, addrs: &[u64]) -> std::collections::BTreeSet<u64> {
        use reargo_program::RefType;
        // [`external_entries_at`] (the index holds exactly the jump references the
        // program's lists hold, in the order added for each target)
        let lifted = |a: u64| addrs.binary_search(&a).is_ok();
        addrs
            .iter()
            .copied()
            .filter(|&a| {
                let lo = self.refs.partition_point(|r| r.0 < a);
                self.refs[lo..].iter().take_while(|r| r.0 == a).any(|&(_, from, ty)| match ty {
                    RefType::IndirectJump => true,
                    RefType::UnconditionalJump | RefType::ConditionalJump => !lifted(from),
                    _ => false,
                })
            })
            .collect()
    }

    /// [`JumpIndex::external_entries_ordered`] of strictly increasing addresses, ascending
    /// (whether an address is lifted looked up through `finder` when given).
    fn external_entries_increasing(&self, addrs: &[u64], finder: Option<&reargo_lift::PositionFinder>, found: &mut Vec<u64>) {
        use reargo_program::RefType;
        let (Some(&first), Some(&last)) = (addrs.first(), addrs.last()) else {
            return;
        };
        if let Some(finder) = finder {
            let start = self.refs.partition_point(|r| r.0 < first);
            for &(to, from, ty) in self.refs[start..].iter().take_while(|r| r.0 <= last) {
                if !matches!(ty, RefType::IndirectJump | RefType::UnconditionalJump | RefType::ConditionalJump) {
                    continue;
                }
                if finder.find(to).is_none() || found.last() == Some(&to) {
                    continue;
                }
                if ty == RefType::IndirectJump || finder.find(from).is_none() {
                    found.push(to);
                }
            }
            return;
        }
        let lifted = |a: u64| a >= first && a <= last && addrs.binary_search(&a).is_ok();
        let start = self.refs.partition_point(|r| r.0 < first);
        // (the targets ascend: whether one is lifted is found by stepping through the
        // addresses alongside)
        let mut at = 0;
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
    }
}

/// Whether `addr` lies between the entry of the function at `entry`
/// and the next function's entry: its body, including the parts the
/// listing has not attributed to it (jump-table cases no discovery
/// followed).
pub fn in_extent(program: &Program, entry: u64, addr: u64) -> bool {
    addr >= entry && program.listing.next_function_after(entry).is_none_or(|f| addr < f.entry_point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_program::{RefType, Reference};

    /// The index gives what the program's reference lists give, for ascending lifts and
    /// others.
    #[test]
    fn jump_index_matches_reference_lookups() {
        let mut program = crate::testutil::helpers::make_x86_64_program(&[0xc3; 0x200], 0x1000);
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = |m: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % m
        };
        let types = [
            RefType::IndirectJump,
            RefType::UnconditionalJump,
            RefType::ConditionalJump,
            RefType::UnconditionalCall,
            RefType::FallThrough,
        ];
        for _ in 0..400 {
            let r = Reference::new(0x1000 + next(0x80), 0x1000 + next(0x80), types[next(5) as usize]);
            program.references.add(r);
        }
        let index = JumpIndex::new(&program);
        for round in 0..300 {
            let n = next(40) as usize;
            let mut addrs: Vec<u64> = Vec::with_capacity(n);
            let mut a = 0x1000 + next(16);
            for _ in 0..n {
                addrs.push(a);
                a += 1 + next(5);
            }
            if round % 3 == 0 && n > 2 {
                // (not ascending)
                let k = next(n as u64) as usize;
                addrs[k] = 0x1000 + next(0x80);
            }
            let increasing = addrs.windows(2).all(|w| w[0] < w[1]);
            // (a lookup per lifted address)
            let lifted = |a: u64| addrs.binary_search(&a).is_ok();
            let want: std::collections::BTreeSet<u64> = addrs
                .iter()
                .copied()
                .filter(|&a| {
                    program.references.get_refs_to(a).iter().any(|r| match r.ref_type {
                        RefType::IndirectJump => true,
                        RefType::UnconditionalJump | RefType::ConditionalJump => !lifted(r.from),
                        _ => false,
                    })
                })
                .collect();
            assert_eq!(external_entries_at(&program, &addrs), want, "{addrs:x?}");
            assert_eq!(index.external_entries_at(&program, &addrs), want, "{addrs:x?}");
            assert_eq!(index.external_entries_ordered(&program, &addrs, increasing), want);
        }
    }

    /// The external entries found through a lift cache's index of addresses (the shapes of a
    /// range borrowed from the cache: [`crate::blockflow::LiftShape::finder`]) are those the
    /// addresses give: random code and jump references (to instructions, into them and
    /// outside the ranges), ranges walked at ascending starts through one trimmed cache.
    #[test]
    fn external_entries_through_cache_index_match() {
        let mut seed = 0x6b8b_4567_327b_23c6_u64;
        let mut next = |m: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % m
        };
        let pieces: &[&[u8]] = &[
            &[0x48, 0x89, 0xc3],          // mov rbx, rax
            &[0x75, 0x04],                // jne
            &[0xeb, 0xf0],                // jmp back
            &[0xe8, 0x10, 0, 0, 0],       // call
            &[0xc3],                      // ret
            &[0x0f, 0x84, 0x10, 0, 0, 0], // je
        ];
        let types = [RefType::IndirectJump, RefType::UnconditionalJump, RefType::ConditionalJump, RefType::UnconditionalCall];
        let mut found = 0;
        for _ in 0..20 {
            let mut code = Vec::new();
            while code.len() < 3000 {
                code.extend_from_slice(pieces[next(pieces.len() as u64) as usize]);
            }
            let base = 0x40_1000 + next(0x800);
            let mut program = crate::testutil::helpers::make_x86_64_program(&code, base);
            let span = code.len() as u64 + 64;
            for _ in 0..1500 {
                let r = Reference::new(base + next(span) - 32, base + next(span) - 32, types[next(4) as usize]);
                program.references.add(r);
            }
            let index = JumpIndex::new(&program);
            let lifter = reargo_lift::x86::X86Lifter::new_64();
            let mut cache = reargo_lift::x86::LiftCache::lazy();
            let mut start = 0;
            while start < code.len() as u64 {
                let at = base + start;
                cache.trim(at, 64);
                let budget = 1 + next(300) as usize;
                lifter.lift_prefixes_lazy(&program.info.memory, at, &[budget], &mut cache, |_, insns, shapes| {
                    let shape = crate::blockflow::LiftShape::from_shapes(insns, shapes.unwrap());
                    let Some(finder) = shape.finder() else { return };
                    let (mut with, mut without) = (Vec::new(), Vec::new());
                    index.external_entries_sorted_into(&program, &shape.addrs, shape.increasing, Some(finder), &mut with);
                    index.external_entries_sorted_into(&program, &shape.addrs, shape.increasing, None, &mut without);
                    assert_eq!(with, without, "{at:#x}");
                    found += with.len();
                });
                start += 1 + next(40);
            }
        }
        assert!(found > 1000, "{found}");
    }
}
