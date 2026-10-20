use std::collections::BTreeMap;

use reargo_arch::DecodedInstruction;

use crate::function::Function;

/// A listing's instructions by address.
pub type InstructionMap = BTreeMap<u64, Box<DecodedInstruction>>;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Listing {
    instructions: BTreeMap<u64, Box<DecodedInstruction>>,
    functions: BTreeMap<u64, Function>,
}

impl Listing {
    pub fn new() -> Self {
        Self::default()
    }

    /// The instruction and function maps, for the on-disk analysis cache
    /// (which stores them in chunks and rebuilds them with
    /// [`Self::from_cache_parts`]).
    pub fn cache_parts(&self) -> (&InstructionMap, &BTreeMap<u64, Function>) {
        (&self.instructions, &self.functions)
    }

    /// A listing of the maps [`Self::cache_parts`] returned.
    pub fn from_cache_parts(instructions: InstructionMap, functions: BTreeMap<u64, Function>) -> Self {
        Self { instructions, functions }
    }

    pub fn add_instruction(&mut self, insn: DecodedInstruction) {
        self.instructions.insert(insn.address, Box::new(insn));
    }

    /// List each instruction of `runs` at its address unless one is listed
    /// there (as [`Self::instruction_or_insert_with`] does), in bulk: the
    /// map is built again in one pass from both when the new ones are
    /// many. Each run is sorted by address; an address may repeat, in a
    /// run or across runs, with the same instruction (the first kept).
    pub fn add_unlisted_instructions(&mut self, runs: Vec<Vec<(u64, Box<DecodedInstruction>)>>) {
        debug_assert!(runs.iter().all(|r| r.windows(2).all(|w| w[0].0 <= w[1].0)));
        let total: usize = runs.iter().map(Vec::len).sum();
        if total < self.instructions.len() {
            for (a, i) in runs.into_iter().flatten() {
                self.instructions.entry(a).or_insert(i);
            }
            return;
        }
        let old = std::mem::take(&mut self.instructions);
        let mut merged: Vec<(u64, Box<DecodedInstruction>)> = Vec::with_capacity(old.len() + total);
        let mut old = old.into_iter().peekable();
        let mut heads: Vec<_> = runs.into_iter().map(|r| r.into_iter().peekable()).collect();
        loop {
            // (the run whose next address is the lowest: few runs)
            let mut lowest: Option<(usize, u64)> = None;
            for (k, head) in heads.iter_mut().enumerate() {
                if let Some(&(a, _)) = head.peek()
                    && lowest.is_none_or(|(_, l)| a < l)
                {
                    lowest = Some((k, a));
                }
            }
            let Some((k, a)) = lowest else { break };
            let Some((_, i)) = heads[k].next() else { break };
            while let Some(o) = old.next_if(|(oa, _)| *oa < a) {
                merged.push(o);
            }
            // (a repeat: the one before kept)
            if merged.last().is_some_and(|(la, _)| *la == a) {
                continue;
            }
            // (the listed one kept)
            merged.push(old.next_if(|(oa, _)| *oa == a).unwrap_or((a, i)));
        }
        merged.extend(old);
        self.instructions = merged.into_iter().collect();
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
            std::collections::btree_map::Entry::Vacant(e) => Some(&**e.insert(Box::new(decode()?))),
        }
    }

    pub fn get_instruction(&self, address: u64) -> Option<&DecodedInstruction> {
        self.instructions.get(&address).map(|b| &**b)
    }

    pub fn has_instruction(&self, address: u64) -> bool {
        self.instructions.contains_key(&address)
    }

    pub fn instructions(&self) -> impl Iterator<Item = &DecodedInstruction> {
        self.instructions.values().map(|b| &**b)
    }

    pub fn instructions_in_range(
        &self,
        start: u64,
        end: u64,
    ) -> impl DoubleEndedIterator<Item = &DecodedInstruction> {
        self.instructions.range(start..end).map(|(_, v)| &**v)
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
        let ranges: Vec<(u64, u64)> =
            body.ranges().map(|r| (r.start.offset, r.start.offset + r.size)).collect();
        let mut i = 0;
        while i < ranges.len() {
            let mut j = i;
            while j + 1 < ranges.len() && ranges[j + 1].0 == ranges[j].1 {
                j += 1;
            }
            let mut it = self.instructions.range(ranges[i].0..ranges[j].1).peekable();
            for &(_, end) in &ranges[i..=j] {
                let mut first = true;
                while let Some((_, insn)) = it.next_if(|(a, _)| **a < end) {
                    f(first, insn);
                    first = false;
                }
            }
            i = j + 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_arch::FlowType;
    use reargo_core::address::{Address, AddressRange, AddressSet, SpaceId};

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
