use std::collections::BTreeMap;

use reargo_arch::DecodedInstruction;

use crate::function::Function;

/// A listing's instructions by address.
pub type InstructionMap = BTreeMap<u64, Box<DecodedInstruction>>;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Listing {
    instructions: Instructions,
    functions: BTreeMap<u64, Function>,
    /// The instructions in address order ([`Self::sorted_instructions`]): made when first
    /// asked for, dropped when an instruction is listed (not saved).
    #[serde(skip)]
    sorted: std::sync::OnceLock<Sorted>,
}

/// A listing's instructions in address order, with their addresses beside
/// them: what a walk of the map gives, read from two arrays.
struct Sorted {
    addrs: Box<[u64]>,
    /// Each points to the boxed instruction the map holds at `addrs[i]`.
    insns: Box<[std::ptr::NonNull<DecodedInstruction>]>,
}

// SAFETY: `Sorted` only reads, through shared references, the boxed
// instructions of the listing that holds it, which outlive it: they are
// neither dropped nor changed without `&mut Listing`, which drops it first
// (every method that lists an instruction does); `DecodedInstruction` is
// `Sync`.
unsafe impl Send for Sorted {}
unsafe impl Sync for Sorted {}

impl std::fmt::Debug for Sorted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sorted").field("len", &self.addrs.len()).finish()
    }
}

impl Sorted {
    fn of(instructions: &Instructions) -> Self {
        // (one walk of each map for both, each into its share of the two
        // arrays; with several maps, on threads of their own — not the
        // rayon pool's: this runs inside a `OnceLock` initialiser, which a
        // pool worker waiting on a job could enter again from a job it
        // took, waiting on itself)
        let n = instructions.len();
        let mut addrs: Vec<u64> = Vec::with_capacity(n);
        let mut insns: Vec<&DecodedInstruction> = Vec::with_capacity(n);
        {
            let (mut a, mut i) = (&mut addrs.spare_capacity_mut()[..n], &mut insns.spare_capacity_mut()[..n]);
            let mut shares = Vec::with_capacity(instructions.maps.len());
            for m in &instructions.maps {
                let (sa, ra) = std::mem::take(&mut a).split_at_mut(m.len());
                let (si, ri) = std::mem::take(&mut i).split_at_mut(m.len());
                shares.push((m, sa, si));
                (a, i) = (ra, ri);
            }
            type Share<'s, 'a> = (&'a InstructionMap, &'s mut [std::mem::MaybeUninit<u64>], &'s mut [std::mem::MaybeUninit<&'a DecodedInstruction>]);
            fn fill((m, sa, si): Share<'_, '_>) {
                for ((&k, b), (sa, si)) in m.iter().zip(sa.iter_mut().zip(si.iter_mut())) {
                    sa.write(k);
                    si.write(&**b);
                }
            }
            if shares.len() > 1 && n >= 1 << 16 {
                std::thread::scope(|s| {
                    let mut shares = shares.into_iter();
                    let last = shares.next_back();
                    let threads: Vec<_> = shares.map(|share| s.spawn(move || fill(share))).collect();
                    last.map(fill);
                    for t in threads {
                        t.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
                    }
                });
            } else {
                shares.into_iter().for_each(fill);
            }
        }
        // SAFETY: the shares cover the first `n` slots of each array (the
        // maps hold `n` instructions), and each map's walk wrote every
        // slot of its share.
        unsafe {
            addrs.set_len(n);
            insns.set_len(n);
        }
        // (collected in place: the same layout)
        let insns: Vec<std::ptr::NonNull<DecodedInstruction>> = insns.into_iter().map(std::ptr::NonNull::from).collect();
        Self { addrs: addrs.into_boxed_slice(), insns: insns.into_boxed_slice() }
    }

    /// The instructions, borrowed for as long as the listing is.
    fn insns(&self) -> &[&DecodedInstruction] {
        // SAFETY: `NonNull<T>` and `&T` have the same layout; each points
        // to an instruction of the listing, borrowed (see `Sorted`) for as
        // long as `self` is.
        unsafe { std::slice::from_raw_parts(self.insns.as_ptr().cast::<&DecodedInstruction>(), self.insns.len()) }
    }
}

/// Instructions with their addresses, for [`Listing::add_unlisted_instructions`].
pub type InstructionRun = Vec<(u64, Box<DecodedInstruction>)>;

/// A slot of the buffer [`Listing::add_unlisted_instructions_cut`] puts the
/// instructions in, in order: an instruction, or `None` (left by a repeat).
type Slot = Option<(u64, Box<DecodedInstruction>)>;

/// The listing's instructions by address: maps of ascending, disjoint
/// address ranges, read as one map — one map, or one for each part of the
/// bulk add that listed them last
/// ([`Listing::add_unlisted_instructions_cut`]: each part's map is built
/// on a thread of its own, std's `BTreeMap` having no way to join maps but
/// to build one again).
struct Instructions {
    maps: Vec<InstructionMap>,
    /// The lowest address each map may hold (the first 0), ascending:
    /// every address of `maps[k]` is below `starts[k + 1]`.
    starts: Vec<u64>,
}

impl Default for Instructions {
    fn default() -> Self {
        Self::of(InstructionMap::new())
    }
}

impl Instructions {
    fn of(map: InstructionMap) -> Self {
        Self { maps: vec![map], starts: vec![0] }
    }

    /// The index of the map that holds `address` (if any does).
    #[inline]
    fn map_of(&self, address: u64) -> usize {
        if self.starts.len() == 1 { 0 } else { self.starts.partition_point(|&s| s <= address) - 1 }
    }

    fn get(&self, address: u64) -> Option<&DecodedInstruction> {
        self.maps[self.map_of(address)].get(&address).map(|b| &**b)
    }

    fn contains_key(&self, address: u64) -> bool {
        self.maps[self.map_of(address)].contains_key(&address)
    }

    fn insert(&mut self, address: u64, insn: Box<DecodedInstruction>) {
        let k = self.map_of(address);
        self.maps[k].insert(address, insn);
    }

    fn entry(&mut self, address: u64) -> std::collections::btree_map::Entry<'_, u64, Box<DecodedInstruction>> {
        let k = self.map_of(address);
        self.maps[k].entry(address)
    }

    fn len(&self) -> usize {
        self.maps.iter().map(BTreeMap::len).sum()
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = (&u64, &Box<DecodedInstruction>)> {
        self.maps.iter().flat_map(|m| m.iter())
    }

    /// The instructions at `start..end` (a `BTreeMap::range`).
    fn range(&self, start: u64, end: u64) -> impl DoubleEndedIterator<Item = (&u64, &Box<DecodedInstruction>)> {
        let lo = self.map_of(start);
        let hi = if end > start { self.map_of(end - 1) } else { lo };
        self.maps[lo..=hi].iter().flat_map(move |m| m.range(start..end))
    }

    /// The instructions at `start..`.
    fn range_from(&self, start: u64) -> impl Iterator<Item = (&u64, &Box<DecodedInstruction>)> {
        self.maps[self.map_of(start)..].iter().flat_map(move |m| m.range(start..))
    }

    /// All the instructions, in address order.
    fn into_run(self) -> InstructionRun {
        if self.maps.len() == 1 {
            return self.maps.into_iter().flatten().collect();
        }
        let mut run = Vec::with_capacity(self.len());
        for m in self.maps {
            run.extend(m);
        }
        run
    }
}

impl std::fmt::Debug for Instructions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // (as the one map they read as)
        f.debug_map().entries(self.iter()).finish()
    }
}

impl serde::Serialize for Instructions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // (as the one map they read as)
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in self.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Instructions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        InstructionMap::deserialize(deserializer).map(Self::of)
    }
}

impl Listing {
    pub fn new() -> Self {
        Self::default()
    }

    /// The instruction and function maps, for the on-disk analysis cache
    /// (which stores them in chunks and rebuilds them with
    /// [`Self::from_cache_parts`]).
    pub fn cache_parts(
        &self,
    ) -> (impl ExactSizeIterator<Item = (&u64, &DecodedInstruction)> + '_, &BTreeMap<u64, Function>) {
        (ExactLen(self.instructions.iter().map(|(a, i)| (a, &**i)), self.instructions.len()), &self.functions)
    }

    /// A listing of the maps [`Self::cache_parts`] returned.
    pub fn from_cache_parts(instructions: InstructionMap, functions: BTreeMap<u64, Function>) -> Self {
        Self { instructions: Instructions::of(instructions), functions, sorted: std::sync::OnceLock::new() }
    }

    pub fn add_instruction(&mut self, insn: DecodedInstruction) {
        self.sorted.take();
        self.instructions.insert(insn.address, Box::new(insn));
    }

    /// The instructions in address order (what [`Self::instructions`]
    /// gives), as a slice: made once (a walk of the map) and kept until an
    /// instruction is listed. For the analyzers that run when no more are,
    /// which walk them often; [`Self::for_each_body_instruction`] reads it
    /// once it is made.
    pub fn sorted_instructions(&self) -> &[&DecodedInstruction] {
        self.sorted.get_or_init(|| Sorted::of(&self.instructions)).insns()
    }

    /// List each instruction of `parts` at its address unless one is
    /// listed there (as [`Self::instruction_or_insert_with`] does, in
    /// order: of an address that repeats the first is kept), in bulk: the
    /// map is built again in one pass from both when the new ones are many,
    /// each part placed on a thread of its own. The parts hold ascending,
    /// disjoint address ranges (every address of a part below every one of
    /// the next); each is a few runs, in any order.
    pub fn add_unlisted_instructions(&mut self, parts: Vec<Vec<InstructionRun>>) {
        // (each part from its lowest address)
        let parts: Vec<Vec<InstructionRun>> = parts.into_iter().filter(|p| p.iter().any(|r| !r.is_empty())).collect();
        let cuts: Vec<u64> =
            parts.iter().skip(1).map(|p| p.iter().flatten().map(|i| i.0).min().unwrap_or(u64::MAX)).collect();
        self.add_unlisted_instructions_cut(&cuts, parts);
    }

    /// [`Self::add_unlisted_instructions`] of parts cut at `cuts`
    /// (ascending): `parts[k]` holds addresses from `cuts[k - 1]` (the
    /// first, any below) up to `cuts[k]` (the last, any above).
    pub fn add_unlisted_instructions_cut(&mut self, cuts: &[u64], parts: Vec<Vec<InstructionRun>>) {
        type Run = InstructionRun;
        debug_assert!(cuts.windows(2).all(|w| w[0] <= w[1]));
        debug_assert!(parts.len() <= cuts.len() + 1);
        self.sorted.take();
        let total: usize = parts.iter().flatten().map(Vec::len).sum();
        if total < self.instructions.len() {
            for (a, i) in parts.into_iter().flatten().flatten() {
                self.instructions.entry(a).or_insert(i);
            }
            return;
        }
        // Each part with the listed ones of its range.
        let mut old: Run = std::mem::take(&mut self.instructions).into_run();
        let mut parts: Vec<(Run, Vec<Run>)> = parts.into_iter().map(|p| (Vec::new(), p)).collect();
        for k in (1..parts.len()).rev() {
            let at = old.partition_point(|o| o.0 < cuts[k - 1]);
            parts[k].0 = old.split_off(at);
        }
        match parts.first_mut() {
            Some(first) => first.0 = old,
            None => parts.push((old, Vec::new())),
        }
        // Each part put in order straight into a buffer (as many slots as
        // it has instructions, the ones a repeat leaves empty `None`) and
        // its map built from it, on a thread of its own: the maps of the
        // parts' ranges.
        let starts: Vec<u64> = std::iter::once(0).chain(cuts.iter().copied()).take(parts.len()).collect();
        let maps: Vec<InstructionMap> = if parts.len() > 1 && total >= 1 << 16 {
            std::thread::scope(|s| {
                let mut work = parts.into_iter();
                let last = work.next_back();
                let threads: Vec<_> = work.map(|part| s.spawn(move || part_map(part))).collect();
                let last = last.map(part_map);
                let mut maps: Vec<InstructionMap> =
                    threads.into_iter().map(|t| t.join().unwrap_or_else(|e| std::panic::resume_unwind(e))).collect();
                maps.extend(last);
                maps
            })
        } else {
            parts.into_iter().map(part_map).collect()
        };
        if std::env::var_os("REARGO_TRACE").is_some() && total > 100000 { eprintln!("TRACE        listing: maps {:?} built", maps.iter().map(|m| m.len()).collect::<Vec<_>>()); }
        self.instructions = Instructions { maps, starts };
    }

    /// The instruction at `address`: the one listed, else `decode()`'s,
    /// which is listed (`None` when there is none and it gives none).
    pub fn instruction_or_insert_with(
        &mut self,
        address: u64,
        decode: impl FnOnce() -> Option<DecodedInstruction>,
    ) -> Option<&DecodedInstruction> {
        match self.instructions.entry(address) {
            std::collections::btree_map::Entry::Occupied(e) => Some(&**e.into_mut()),
            std::collections::btree_map::Entry::Vacant(e) => {
                let insn = Box::new(decode()?);
                self.sorted.take();
                Some(&**e.insert(insn))
            }
        }
    }

    pub fn get_instruction(&self, address: u64) -> Option<&DecodedInstruction> {
        self.instructions.get(address)
    }

    pub fn has_instruction(&self, address: u64) -> bool {
        self.instructions.contains_key(address)
    }

    pub fn instructions(&self) -> impl Iterator<Item = &DecodedInstruction> {
        self.instructions.iter().map(|(_, b)| &**b)
    }

    /// `f` of the instructions in address order cut into parts (the
    /// listing's maps, see `Instructions`), on the rayon pool; the results
    /// in order. For a scan of every instruction whose result for the
    /// whole is the results of its parts in order.
    pub fn map_instruction_parts<'a, T: Send>(
        &'a self,
        f: impl Fn(&mut dyn Iterator<Item = &'a DecodedInstruction>) -> T + Sync,
    ) -> Vec<T> {
        use rayon::prelude::*;
        self.instructions.maps.par_iter().map(|m| f(&mut m.values().map(|b| &**b))).collect()
    }

    /// The addresses of the instructions listed in `start..end`, ascending.
    pub fn instruction_addresses_in_range(&self, start: u64, end: u64) -> impl Iterator<Item = u64> + '_ {
        self.instructions.range(start, end).map(|(&a, _)| a)
    }

    pub fn instructions_in_range(
        &self,
        start: u64,
        end: u64,
    ) -> impl DoubleEndedIterator<Item = &DecodedInstruction> {
        self.instructions.range(start, end).map(|(_, v)| &**v)
    }

    /// Calls `f(first, insn)` for the instructions of every range of
    /// `body`, in the order and with the repetitions of
    /// `for r in body.ranges() { for insn in instructions_in_range(r.start, r.end) { … } }`;
    /// `first` is true for the first instruction of each range.
    ///
    /// A body holds one range per instruction, so a range lookup per
    /// range costs a tree search per instruction. Here a run of ranges
    /// each starting where the one before ends is walked with one
    /// lookup: their instructions are those of the whole run, in order.
    pub fn for_each_body_instruction<'a>(
        &'a self,
        body: &reargo_core::address::AddressSet,
        mut f: impl FnMut(bool, &'a DecodedInstruction),
    ) {
        if let Some(sorted) = self.sorted.get() {
            return for_each_sorted_body_instruction(&sorted.addrs, sorted.insns(), body, f);
        }
        // (the ranges read as they come: no list of them is made)
        let mut ranges = body.ranges().map(|r| (r.start.offset, r.start.offset + r.size)).peekable();
        while let Some((start, mut end)) = ranges.next() {
            // the run of ranges from `start`: one lookup, read up to the
            // end of each in turn
            let mut it = self.instructions.range_from(start).peekable();
            loop {
                let mut first = true;
                while let Some((_, insn)) = it.next_if(|(a, _)| **a < end) {
                    f(first, insn);
                    first = false;
                }
                match ranges.next_if(|&(s, _)| s == end) {
                    Some((_, e)) => end = e,
                    None => break,
                }
            }
        }
    }

    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    pub fn add_function(&mut self, func: Function) {
        self.functions.insert(func.entry_point, func);
    }

    /// Remove the function whose entry point is `entry`. Returns the
    /// removed function if one existed. Used by the user-override
    /// layer to purge bogus auto-discovered functions (e.g. the
    /// pattern-matcher's false positives) without re-running the
    /// whole analysis.
    pub fn remove_function(&mut self, entry: u64) -> Option<Function> {
        self.functions.remove(&entry)
    }

    pub fn get_function(&self, entry: u64) -> Option<&Function> {
        self.functions.get(&entry)
    }

    pub fn get_function_mut(&mut self, entry: u64) -> Option<&mut Function> {
        self.functions.get_mut(&entry)
    }

    pub fn has_function(&self, entry: u64) -> bool {
        self.functions.contains_key(&entry)
    }

    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.functions.values()
    }

    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// The first function whose entry is above `address`.
    pub fn next_function_after(&self, address: u64) -> Option<&Function> {
        self.functions.range(address.saturating_add(1)..).next().map(|(_, f)| f)
    }

    pub fn function_containing(&self, address: u64) -> Option<&Function> {
        self.functions
            .range(..=address)
            .next_back()
            .map(|(_, f)| f)
            .filter(|f| f.body.contains(&reargo_core::address::Address::new(reargo_core::address::SpaceId::RAM, address)))
    }
}

/// [`Listing::for_each_body_instruction`] over the instructions `insns` at
/// the ascending addresses `addrs`: each run of ranges starting where the one
/// before ends is found by a binary search (from the run before's, when it
/// starts after it) and read in order.
fn for_each_sorted_body_instruction<'a>(
    addrs: &[u64],
    insns: &[&'a DecodedInstruction],
    body: &reargo_core::address::AddressSet,
    mut f: impl FnMut(bool, &'a DecodedInstruction),
) {
    let mut ranges = body.ranges().map(|r| (r.start.offset, r.start.offset + r.size)).peekable();
    // (the start and index of the run before)
    let mut last: (u64, usize) = (0, 0);
    while let Some((start, mut end)) = ranges.next() {
        let from = if start >= last.0 { last.1 } else { 0 };
        let mut i = from + addrs[from..].partition_point(|&a| a < start);
        last = (start, i);
        loop {
            let mut first = true;
            while i < addrs.len() && addrs[i] < end {
                f(first, insns[i]);
                first = false;
                i += 1;
            }
            match ranges.next_if(|&(s, _)| s == end) {
                Some((_, e)) => end = e,
                None => break,
            }
        }
    }
}

/// The map of a part's instructions: `old` (sorted, the listed ones) and
/// the runs, each address once ([`put_in_order`]).
fn part_map((old, runs): (InstructionRun, Vec<InstructionRun>)) -> InstructionMap {
    let n = old.len() + runs.iter().map(Vec::len).sum::<usize>();
    let mut all: Vec<Slot> = Vec::with_capacity(n);
    put_in_order(old, runs, &mut all.spare_capacity_mut()[..n]);
    // SAFETY: `put_in_order` wrote every one of the first `n` slots.
    unsafe { all.set_len(n) };
    // (`filter_map`, unlike `flatten`, collects in place: the buffer is
    // the one the map is built from)
    #[allow(clippy::filter_map_identity)]
    let listed = all.into_iter().filter_map(|slot| slot);
    listed.collect()
}

/// An iterator of a known length.
struct ExactLen<I>(I, usize);

impl<I: Iterator> Iterator for ExactLen<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<I::Item> {
        let item = self.0.next()?;
        self.1 -= 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.1, Some(self.1))
    }
}

impl<I: Iterator> ExactSizeIterator for ExactLen<I> {}

/// The instructions of `old` (sorted by address, the listed ones) and
/// `runs` (in any order), each address once — the first of it in that
/// order —, put in address order into the first slots of `share` (at
/// least as many as they hold); the slots after them `None`.
fn put_in_order(old: InstructionRun, runs: Vec<InstructionRun>, share: &mut [std::mem::MaybeUninit<Slot>]) {
    let (lo, hi) = std::iter::once(&old)
        .chain(&runs)
        .flatten()
        .fold((u64::MAX, 0), |(lo, hi), i| (lo.min(i.0), hi.max(i.0)));
    let count = old.len() + runs.iter().map(Vec::len).sum::<usize>();
    let filled = if lo > hi {
        0
    } else if ((hi - lo) >> 6) as usize <= count.saturating_mul(4).saturating_add(1024) && count < u32::MAX as usize {
        // (dense: each address's place is its rank among the addresses
        // there, from a bit per address)
        let words = ((hi - lo) >> 6) as usize + 1;
        let mut there = vec![0u64; words];
        for i in std::iter::once(&old).chain(&runs).flatten() {
            let at = i.0 - lo;
            there[(at >> 6) as usize] |= 1 << (at & 63);
        }
        // (the addresses in the words before each)
        let mut before: Vec<u32> = Vec::with_capacity(words);
        let mut n = 0u32;
        for w in &there {
            before.push(n);
            n += w.count_ones();
        }
        // (an address's bit cleared once its first instruction is placed)
        let mut open = there.clone();
        for i in std::iter::once(old).chain(runs).flatten() {
            let at = i.0 - lo;
            let (w, bit) = ((at >> 6) as usize, 1u64 << (at & 63));
            if open[w] & bit != 0 {
                open[w] &= !bit;
                let rank = before[w] + (there[w] & (bit - 1)).count_ones();
                share[rank as usize].write(Some(i));
            }
        }
        n as usize
    } else {
        // (sparse: sorted stably, the first of each address kept)
        let mut all: InstructionRun = Vec::with_capacity(count);
        all.extend(old);
        for r in runs {
            all.extend(r);
        }
        all.sort_by_key(|i| i.0);
        all.dedup_by(|later, first| later.0 == first.0);
        let n = all.len();
        for (slot, i) in share.iter_mut().zip(all) {
            slot.write(Some(i));
        }
        n
    };
    for slot in &mut share[filled..] {
        slot.write(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_arch::FlowType;
    use reargo_core::address::{Address, AddressRange, AddressSet, SpaceId};

    /// Instructions added in parts and runs (repeats in a run and across
    /// runs, some listed already) are listed once each, the listed ones
    /// kept, as one at a time would.
    #[test]
    fn add_unlisted_instructions_in_parts() {
        let insn = |a: u64, len: u32| {
            Box::new(DecodedInstruction::new(a, len, "nop".into(), String::new(), smallvec::smallvec![0x90; len as usize], FlowType::Fall, None))
        };
        for listed in [vec![(0x10u64, 7u32), (0x30, 7), (0x95, 7)], vec![]] {
            let parts = || {
                vec![
                    vec![vec![(0x10, insn(0x10, 1)), (0x20, insn(0x20, 1)), (0x20, insn(0x20, 1))], vec![(0x18, insn(0x18, 1)), (0x20, insn(0x20, 1))]],
                    vec![],
                    vec![vec![(0x80, insn(0x80, 1)), (0x95, insn(0x95, 1))], vec![(0x90, insn(0x90, 1))]],
                ]
            };
            let mut one = listing(&listed);
            for (a, i) in parts().into_iter().flatten().flatten() {
                one.instruction_or_insert_with(a, || Some(*i));
            }
            let mut bulk = listing(&listed);
            bulk.add_unlisted_instructions(parts());
            let state = |l: &Listing| l.instructions().map(|i| (i.address, i.length)).collect::<Vec<_>>();
            assert_eq!(state(&one), state(&bulk));
        }
    }

    /// Many instructions (the parts placed on threads of their own), in
    /// runs in any order, dense and sparse: listed as one at a time would
    /// list them, the listed ones and the first of each repeat kept (told
    /// apart by their lengths), with the parts cut at their lowest
    /// addresses or at given cuts.
    #[test]
    fn many_unlisted_instructions_in_parts_match_one_by_one() {
        let insn = |a: u64, len: u32| {
            Box::new(DecodedInstruction::new(a, len, "nop".into(), String::new(), smallvec::smallvec![0x90; len as usize], FlowType::Fall, None))
        };
        let mut seed = 0x2545f4914f6cdd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let listed: Vec<(u64, u32)> = (0..2000u64).map(|k| (k * 97 % 200_000, 9)).chain([(250_000, 9), (u64::MAX - 5, 9)]).collect();
        // (four parts: three of 50000 addresses, one spread over 2^40; each
        // a few runs with repeats, some sorted)
        let parts: Vec<Vec<Vec<(u64, u32)>>> = (0..4u64)
            .map(|p| {
                (0..3u32)
                    .map(|r| {
                        let mut run: Vec<(u64, u32)> = (0..12000)
                            .map(|_| if p == 3 { (300_000 + next() % (1 << 40), r + 1) } else { (p * 50_000 + next() % 50_000, r + 1) })
                            .collect();
                        if r == 0 {
                            run.sort_by_key(|x| x.0);
                        }
                        run
                    })
                    .collect()
            })
            .collect();
        let boxed = || -> Vec<Vec<InstructionRun>> {
            parts.iter().map(|p| p.iter().map(|r| r.iter().map(|&(a, len)| (a, insn(a, len))).collect()).collect()).collect()
        };
        let mut one = listing(&listed);
        for (a, i) in boxed().into_iter().flatten().flatten() {
            one.instruction_or_insert_with(a, || Some(*i));
        }
        let state = |l: &Listing| l.instructions().map(|i| (i.address, i.length)).collect::<Vec<_>>();
        let mut bulk = listing(&listed);
        bulk.add_unlisted_instructions(boxed());
        assert!(state(&bulk).len() > 1 << 16);
        assert_eq!(state(&one), state(&bulk));
        let mut cut = listing(&listed);
        cut.add_unlisted_instructions_cut(&[50_000, 100_000, 200_000], boxed());
        assert_eq!(state(&one), state(&cut));
    }

    /// A listing whose instructions are in several maps (a bulk add in
    /// parts) reads as one map: every lookup, walk and range, an
    /// instruction listed into any of them afterwards, its serialised and
    /// debug forms.
    #[test]
    fn maps_of_parts_read_as_one_map() {
        let insn = |a: u64, len: u32| Box::new(DecodedInstruction::new(a, len, "nop".into(), String::new(), smallvec::smallvec![0x90; len as usize], FlowType::Fall, None));
        let addrs = |p: u64| (0..30_000u64).map(move |k| p * 100_000 + k * 3);
        let parts: Vec<Vec<InstructionRun>> = (0..4u64).map(|p| vec![addrs(p).map(|a| (a, insn(a, 3))).collect()]).collect();
        let mut parted = listing(&[(5, 1), (250_001, 1)]);
        parted.add_unlisted_instructions_cut(&[100_000, 200_000, 300_000], parts);
        assert_eq!(parted.instructions.maps.len(), 4);
        let mut one = listing(&[(5, 1), (250_001, 1)]);
        for a in (0..4).flat_map(addrs) {
            one.instruction_or_insert_with(a, || Some(*insn(a, 3)));
        }
        // listed afterwards, into the first, a middle and the last map
        for l in [&mut parted, &mut one] {
            l.add_instruction(*insn(7, 2));
            l.instruction_or_insert_with(150_001, || Some(*insn(150_001, 2)));
            l.instruction_or_insert_with(150_000, || Some(*insn(150_000, 9)));
            l.add_instruction(*insn(u64::MAX - 1, 1));
        }
        let state = |l: &Listing| l.instructions().map(|i| (i.address, i.length)).collect::<Vec<_>>();
        assert_eq!(state(&parted), state(&one));
        assert_eq!(parted.instruction_count(), one.instruction_count());
        for a in [0u64, 3, 5, 6, 7, 99_999, 100_000, 100_002, 150_000, 150_001, 250_001, 389_997, 400_000, u64::MAX - 1, u64::MAX] {
            assert_eq!(parted.has_instruction(a), one.has_instruction(a), "{a}");
            assert_eq!(parted.get_instruction(a).map(|i| i.length), one.get_instruction(a).map(|i| i.length), "{a}");
        }
        for (s, e) in [(0u64, 10u64), (99_990, 100_010), (50_000, 350_000), (0, u64::MAX), (150_000, 150_000), (390_000, 400_000)] {
            let ranged = |l: &Listing| l.instructions_in_range(s, e).map(|i| i.address).collect::<Vec<_>>();
            assert_eq!(ranged(&parted), ranged(&one), "{s}..{e}");
            let back = |l: &Listing| l.instructions_in_range(s, e).rev().map(|i| i.address).collect::<Vec<_>>();
            assert_eq!(back(&parted), back(&one), "{s}..{e} reversed");
            let addrs = |l: &Listing| l.instruction_addresses_in_range(s, e).collect::<Vec<_>>();
            assert_eq!(addrs(&parted), addrs(&one), "{s}..{e} addresses");
        }
        // a body across the maps' bounds, walked through the maps (no
        // sorted copy made yet) and through the sorted copy
        let r = |off: u64, size: u64| AddressRange::new(Address::new(SpaceId::RAM, off), size);
        let mut body = AddressSet::new();
        for range in [r(99_000, 2_000), r(101_000, 50), r(199_990, 120_000), r(399_000, 5_000)] {
            body.add(range);
        }
        let walk = |l: &Listing| {
            let mut out = Vec::new();
            l.for_each_body_instruction(&body, |first, i| out.push((first, i.address)));
            out
        };
        assert!(parted.sorted.get().is_none());
        assert_eq!(walk(&parted), walk(&one));
        let sorted = |l: &Listing| l.sorted_instructions().iter().map(|i| i.address).collect::<Vec<_>>();
        assert_eq!(sorted(&parted), sorted(&one));
        assert_eq!(walk(&parted), walk(&one));
        let parts = parted.map_instruction_parts(|insns| insns.map(|i| i.address).collect::<Vec<_>>());
        assert_eq!(parts.len(), 4);
        assert_eq!(parts.concat(), state(&one).into_iter().map(|(a, _)| a).collect::<Vec<_>>());
        let cached = |l: &Listing| l.cache_parts().0.map(|(&a, i)| (a, i.length)).collect::<Vec<_>>();
        assert_eq!(cached(&parted), state(&one));
        assert_eq!(parted.cache_parts().0.len(), one.instruction_count());
        assert_eq!(format!("{parted:?}"), format!("{one:?}"));
        let json = |l: &Listing| serde_json::to_string(l).expect("serialises");
        assert_eq!(json(&parted), json(&one));
        let back: Listing = serde_json::from_str(&json(&parted)).expect("reads back");
        assert_eq!(state(&back), state(&one));
    }

    fn listing(insns: &[(u64, u32)]) -> Listing {
        let mut l = Listing::new();
        for &(a, len) in insns {
            l.add_instruction(DecodedInstruction::new(
                a,
                len,
                "nop".into(),
                String::new(),
                smallvec::smallvec![0x90; len as usize],
                FlowType::Fall,
                None,
            ));
        }
        l
    }

    /// The walk gives what a range lookup per range gives, with the
    /// first instruction of each range marked.
    #[test]
    fn body_walk_matches_range_lookups() {
        let l = listing(&[(0x10, 2), (0x12, 3), (0x15, 1), (0x16, 4), (0x20, 1), (0x21, 2), (0x22, 1), (0x30, 1)]);
        let r = |off: u64, size: u64| AddressRange::new(Address::new(SpaceId::RAM, off), size);
        let bodies: Vec<AddressSet> = vec![
            [r(0x10, 2), r(0x12, 3), r(0x15, 1)].into_iter().collect(),
            [r(0x10, 6), r(0x16, 4)].into_iter().collect(),
            [r(0x12, 3), r(0x20, 1), r(0x21, 2)].into_iter().collect(),
            // overlapping and empty ranges, and a range holding two instructions
            [r(0x20, 3), r(0x21, 2), r(0x22, 0), r(0x22, 1), r(0x30, 1)].into_iter().collect(),
            AddressSet::new(),
        ];
        for body in &bodies {
            let mut expected: Vec<(bool, u64)> = Vec::new();
            for range in body.ranges() {
                let start = range.start.offset;
                for (i, insn) in l.instructions_in_range(start, start + range.size).enumerate() {
                    expected.push((i == 0, insn.address));
                }
            }
            let mut walked: Vec<(bool, u64)> = Vec::new();
            l.for_each_body_instruction(body, |first, insn| walked.push((first, insn.address)));
            assert_eq!(walked, expected, "{body:?}");
        }
        // and so does the walk of the sorted instructions, once made
        let sorted: Vec<u64> = l.sorted_instructions().iter().map(|i| i.address).collect();
        assert_eq!(sorted, l.instructions().map(|i| i.address).collect::<Vec<_>>());
        for body in &bodies {
            let mut expected: Vec<(bool, u64)> = Vec::new();
            for range in body.ranges() {
                let start = range.start.offset;
                for (i, insn) in l.instructions_in_range(start, start + range.size).enumerate() {
                    expected.push((i == 0, insn.address));
                }
            }
            let mut walked: Vec<(bool, u64)> = Vec::new();
            l.for_each_body_instruction(body, |first, insn| walked.push((first, insn.address)));
            assert_eq!(walked, expected, "{body:?}");
        }
    }

    /// Random bodies (sorted and not, overlapping, empty and adjacent
    /// ranges) walk the same instructions through the sorted instructions as
    /// through the map, and listing an instruction drops the sorted ones.
    #[test]
    fn sorted_body_walk_matches_map_walk() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let r = |off: u64, size: u64| AddressRange::new(Address::new(SpaceId::RAM, off), size);
        for round in 0..300 {
            let mut insns: Vec<(u64, u32)> = Vec::new();
            let mut a = next(8);
            while a < 400 {
                let len = 1 + next(6) as u32;
                insns.push((a, len));
                a += u64::from(len) + if next(5) == 0 { next(20) } else { 0 };
            }
            let mut l = listing(&insns);
            for _ in 0..20 {
                let mut body = AddressSet::new();
                for _ in 0..next(12) {
                    let start = if next(2) == 0 && !insns.is_empty() { insns[next(insns.len() as u64) as usize].0 } else { next(420) };
                    body.add(r(start, next(30)));
                }
                if next(3) == 0 {
                    // a run of adjacent ranges, one per instruction
                    let k = next(insns.len().max(1) as u64) as usize;
                    for &(a, len) in insns.iter().skip(k).take(next(8) as usize) {
                        body.add(r(a, u64::from(len)));
                    }
                }
                let walk = |l: &Listing| {
                    let mut out: Vec<(bool, u64)> = Vec::new();
                    l.for_each_body_instruction(&body, |first, insn| out.push((first, insn.address)));
                    out
                };
                let fresh = Listing::from_cache_parts(
                    l.instructions().map(|i| (i.address, Box::new(i.clone()))).collect(),
                    BTreeMap::new(),
                );
                let by_map = walk(&fresh);
                l.sorted_instructions();
                assert_eq!(walk(&l), by_map, "round {round}: {body:?}");
            }
            // a new instruction is seen by the next walk
            l.add_instruction(DecodedInstruction::new(500, 1, "nop".into(), String::new(), smallvec::smallvec![0x90], FlowType::Fall, None));
            assert_eq!(l.sorted_instructions().last().map(|i| i.address), Some(500));
            l.instruction_or_insert_with(501, || {
                Some(DecodedInstruction::new(501, 1, "nop".into(), String::new(), smallvec::smallvec![0x90], FlowType::Fall, None))
            });
            assert_eq!(l.sorted_instructions().last().map(|i| i.address), Some(501));
        }
    }

    /// A set serializes as the `BTreeSet` of its ranges did (the
    /// on-disk analysis cache) and reads back sorted and deduplicated.
    #[test]
    fn address_set_serializes_as_a_btree_set() {
        let r = |off: u64, size: u64| AddressRange::new(Address::new(SpaceId::RAM, off), size);
        let ranges = [r(0x30, 1), r(0x10, 2), r(0x12, 3), r(0x10, 1)];
        let set: AddressSet = ranges.into_iter().collect();
        let tree: std::collections::BTreeSet<AddressRange> = ranges.into_iter().collect();
        assert_eq!(bincode::serialize(&set).unwrap(), bincode::serialize(&tree).unwrap());
        let unsorted: Vec<AddressRange> = vec![r(0x30, 1), r(0x10, 2), r(0x30, 1)];
        let back: AddressSet = bincode::deserialize(&bincode::serialize(&unsorted).unwrap()).unwrap();
        assert_eq!(back.ranges().copied().collect::<Vec<_>>(), [r(0x10, 2), r(0x30, 1)]);
        assert_eq!(format!("{set:?}"), format!("AddressSet {{ ranges: {tree:?} }}"));
    }
}

