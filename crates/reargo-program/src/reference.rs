use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RefType {
    UnconditionalCall,
    ConditionalCall,
    IndirectCall,
    UnconditionalJump,
    ConditionalJump,
    IndirectJump,
    DataRead,
    DataWrite,
    DataReadWrite,
    FallThrough,
}

impl RefType {
    pub fn is_call(&self) -> bool {
        matches!(
            self,
            Self::UnconditionalCall | Self::ConditionalCall | Self::IndirectCall
        )
    }

    pub fn is_jump(&self) -> bool {
        matches!(
            self,
            Self::UnconditionalJump | Self::ConditionalJump | Self::IndirectJump
        )
    }

    pub fn is_flow(&self) -> bool {
        self.is_call() || self.is_jump() || *self == Self::FallThrough
    }

    pub fn is_data(&self) -> bool {
        matches!(
            self,
            Self::DataRead | Self::DataWrite | Self::DataReadWrite
        )
    }
}

impl std::fmt::Display for RefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnconditionalCall => write!(f, "CALL"),
            Self::ConditionalCall => write!(f, "COND_CALL"),
            Self::IndirectCall => write!(f, "IND_CALL"),
            Self::UnconditionalJump => write!(f, "JUMP"),
            Self::ConditionalJump => write!(f, "COND_JUMP"),
            Self::IndirectJump => write!(f, "IND_JUMP"),
            Self::DataRead => write!(f, "READ"),
            Self::DataWrite => write!(f, "WRITE"),
            Self::DataReadWrite => write!(f, "RW"),
            Self::FallThrough => write!(f, "FALL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
    pub ref_type: RefType,
}

impl Reference {
    pub fn new(from: u64, to: u64, ref_type: RefType) -> Self {
        Self { from, to, ref_type }
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x} -> 0x{:x} [{}]", self.from, self.to, self.ref_type)
    }
}

/// A point in a [`ReferenceManager`]'s log of jump references (see
/// [`ReferenceManager::jump_mark`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JumpMark {
    manager: u64,
    len: usize,
}

/// The references from (or to) one address, in the order added.
pub type RefList = smallvec::SmallVec<[Reference; 2]>;

/// References by source (or target) address.
pub type RefMap = BTreeMap<u64, RefList>;

/// Append each of `refs` to `map`'s list at its `key`, in the order of
/// `refs` (a stable sort by key keeps each list's order).
/// Sort `order` (keys with their indices, the indices ascending) as
/// `sort_unstable` does: by key, then index. Many keys within 2^32 of each
/// other: by a radix sort on the key's bits (stable, so equal keys keep
/// their ascending indices), passes of up to 12 bits.
fn sort_keyed(order: &mut Vec<(u64, u32)>) {
    debug_assert!(order.windows(2).all(|w| w[0].1 < w[1].1));
    let (min, max) = order.iter().fold((u64::MAX, 0), |(lo, hi), &(k, _)| (lo.min(k), hi.max(k)));
    let span = max.wrapping_sub(min);
    if order.len() < 1 << 12 || min > max || span >> 32 != 0 {
        order.sort_unstable();
        return;
    }
    let bits = 64 - span.leading_zeros();
    let passes = bits.div_ceil(12);
    let digit = bits.div_ceil(passes.max(1));
    let mask = (1u64 << digit) - 1;
    // (each pass writes every slot)
    let mut buf: Vec<(u64, u32)> = vec![(0, 0); order.len()];
    let mut counts = vec![0usize; 1 << digit];
    for p in 0..passes {
        let shift = p * digit;
        counts.fill(0);
        for &(k, _) in order.iter() {
            counts[((k - min) >> shift & mask) as usize] += 1;
        }
        let mut at = 0;
        for c in counts.iter_mut() {
            let n = *c;
            *c = at;
            at += n;
        }
        for &e in order.iter() {
            let d = ((e.0 - min) >> shift & mask) as usize;
            buf[counts[d]] = e;
            counts[d] += 1;
        }
        std::mem::swap(order, &mut buf);
    }
}

/// The entries of a [`RefParts`] map from which a bulk add cuts it into
/// parts (a part of fewer is never cut).
const MIN_PART: usize = 1 << 12;

/// The number of parts a bulk add keeps a [`RefParts`] map in, about: a
/// part grown past twice its share (of the entries over this many parts,
/// at least [`MIN_PART`]) is cut into parts of that share when the add
/// changes it.
const PARTS: usize = 16;

/// References by source (or target) address, as a [`RefMap`] in parts:
/// maps of ascending, disjoint address ranges read as one map — the same
/// entries in the same order, serialized as one map. A bulk add
/// ([`ReferenceManager::add_all`]) merges into each part on its own (in
/// parallel) and cuts a part grown too large; the parts depend only on
/// the adds, not on the threads.
#[derive(Clone)]
pub struct RefParts {
    maps: Vec<RefMap>,
    /// The lowest address each map may hold (the first 0), ascending:
    /// every address of `maps[k]` is below `starts[k + 1]`.
    starts: Vec<u64>,
}

impl Default for RefParts {
    fn default() -> Self {
        Self::of(RefMap::new())
    }
}

impl RefParts {
    /// The parts of one map.
    pub fn of(map: RefMap) -> Self {
        Self { maps: vec![map], starts: vec![0] }
    }

    /// The index of the map that holds `address` (if any does).
    #[inline]
    fn part_of(&self, address: u64) -> usize {
        if self.starts.len() == 1 { 0 } else { self.starts.partition_point(|&s| s <= address) - 1 }
    }

    pub fn get(&self, address: &u64) -> Option<&RefList> {
        self.maps[self.part_of(*address)].get(address)
    }

    fn entry(&mut self, address: u64) -> std::collections::btree_map::Entry<'_, u64, RefList> {
        let k = self.part_of(address);
        self.maps[k].entry(address)
    }

    /// The entries in address order (as the one map's `iter`).
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &RefList)> {
        self.maps.iter().flatten()
    }

    pub fn values(&self) -> impl Iterator<Item = &RefList> {
        self.maps.iter().flat_map(|m| m.values())
    }

    /// The entries of the addresses in `start..end` (`start < end`), in
    /// address order.
    fn range(&self, start: u64, end: u64) -> impl Iterator<Item = (&u64, &RefList)> {
        let (a, b) = (self.part_of(start), self.part_of(end - 1));
        self.maps[a..=b].iter().flat_map(move |m| m.range(start..end))
    }

    /// The number of addresses (entries).
    pub fn len(&self) -> usize {
        self.maps.iter().map(|m| m.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.maps.iter().all(|m| m.is_empty())
    }

    /// Append each of `refs` to the list at its `key`, in the order of
    /// `refs` (as `entry(key).or_default().push` of each in turn): each
    /// part merged with the references in its range — in parallel on the
    /// rayon pool when `pooled` and there are many —, a part grown past
    /// twice its share cut into parts of that share.
    fn add_grouped(&mut self, refs: &[Reference], key: impl Fn(&Reference) -> u64, pooled: bool) {
        if refs.is_empty() {
            return;
        }
        // (sorted by key with their order, not by a stable sort through the
        // references: their keys read once, in order)
        let mut order: Vec<(u64, u32)> = refs.iter().enumerate().map(|(i, r)| (key(r), i as u32)).collect();
        sort_keyed(&mut order);
        // each part's share of them
        let mut slices = Vec::with_capacity(self.maps.len());
        let mut rest = &order[..];
        for &start in &self.starts[1..] {
            let (here, after) = rest.split_at(rest.partition_point(|e| e.0 < start));
            slices.push(here);
            rest = after;
        }
        slices.push(rest);
        // (an estimate: each new key counted, repeats too)
        let share = ((self.len() + order.len()) / PARTS).max(MIN_PART);
        if slices.iter().any(|s| s.len() > 2 * share) {
            // A part given more than twice its share (new keys close
            // together, or the first add): cut first at every share of
            // them, its old entries split off with them, so the pieces
            // merge in parallel.
            let (mut maps, mut starts, mut pieces) = (Vec::new(), Vec::new(), Vec::new());
            for ((mut map, start), slice) in std::mem::take(&mut self.maps).into_iter().zip(std::mem::take(&mut self.starts)).zip(slices) {
                let mut cuts = Vec::new();
                let mut at = share;
                while at < slice.len() {
                    // (at a key's first reference)
                    while at < slice.len() && slice[at].0 == slice[at - 1].0 {
                        at += 1;
                    }
                    if at < slice.len() {
                        cuts.push(at);
                    }
                    at += share;
                }
                let mut right = Vec::with_capacity(cuts.len());
                for &c in cuts.iter().rev() {
                    right.push((slice[c].0, map.split_off(&slice[c].0)));
                }
                maps.push(map);
                starts.push(start);
                for (s, m) in right.into_iter().rev() {
                    maps.push(m);
                    starts.push(s);
                }
                let mut from = 0;
                for &c in cuts.iter().chain(std::iter::once(&slice.len())) {
                    pieces.push(&slice[from..c]);
                    from = c;
                }
            }
            self.maps = maps;
            self.starts = starts;
            slices = pieces;
        }
        let merge = |(map, (start, slice)): (&mut RefMap, (u64, &[(u64, u32)]))| merge_part(map, start, slice, refs, share);
        let parallel = pooled && order.len() >= 1024 && self.maps.len() > 1;
        let parts = self.maps.iter_mut().zip(self.starts.iter().copied().zip(slices));
        let cut: Vec<Option<Vec<(u64, RefMap)>>> = if parallel {
            use rayon::prelude::*;
            parts.collect::<Vec<_>>().into_par_iter().map(merge).collect()
        } else {
            parts.map(merge).collect()
        };
        if cut.iter().any(|c| c.is_some()) {
            let (mut maps, mut starts) = (Vec::new(), Vec::new());
            for ((map, start), cut) in std::mem::take(&mut self.maps).into_iter().zip(std::mem::take(&mut self.starts)).zip(cut) {
                match cut {
                    Some(parts) => {
                        for (s, m) in parts {
                            starts.push(s);
                            maps.push(m);
                        }
                    }
                    None => {
                        starts.push(start);
                        maps.push(map);
                    }
                }
            }
            self.maps = maps;
            self.starts = starts;
        }
    }
}

/// Merge the references `order` gives (keys with their indices in `refs`,
/// sorted) into `map`, the part starting at `start`: the lists appended in
/// order. Returns the part cut into parts of about `share` entries (each
/// with its start; the first `start`) when it has grown past twice that.
fn merge_part(map: &mut RefMap, start: u64, order: &[(u64, u32)], refs: &[Reference], share: usize) -> Option<Vec<(u64, RefMap)>> {
    if order.is_empty() {
        return None;
    }
    let groups = order.chunk_by(|a, b| a.0 == b.0);
    let list = |g: &[(u64, u32)]| g.iter().map(|&(_, i)| refs[i as usize]).collect::<RefList>();
    let merged: Vec<(u64, RefList)> = if order.len() < map.len() {
        // (few: in address order, each lookup near the one before)
        for g in groups {
            map.entry(g[0].0).or_default().extend(g.iter().map(|&(_, i)| refs[i as usize]));
        }
        if map.len() <= 4 * share {
            return None;
        }
        std::mem::take(map).into_iter().collect()
    } else {
        // Many: both merged in address order into a map built in one pass.
        let mut old = std::mem::take(map).into_iter().peekable();
        let mut merged: Vec<(u64, RefList)> = Vec::with_capacity(old.len() + order.len());
        for g in groups {
            let k = g[0].0;
            while let Some(o) = old.next_if(|(ok, _)| *ok < k) {
                merged.push(o);
            }
            match old.next_if(|(ok, _)| *ok == k) {
                Some((_, mut l)) => {
                    l.extend(g.iter().map(|&(_, i)| refs[i as usize]));
                    merged.push((k, l));
                }
                None => merged.push((k, list(g))),
            }
        }
        merged.extend(old);
        merged
    };
    if merged.len() <= 2 * share {
        *map = merged.into_iter().collect();
        return None;
    }
    // (cut into parts of equal size, the first keeping the start)
    let n = merged.len().div_ceil(merged.len().div_ceil(share));
    let mut parts = Vec::with_capacity(merged.len().div_ceil(n));
    let mut entries = merged.into_iter().peekable();
    while let Some(&(first, _)) = entries.peek() {
        let s = if parts.is_empty() { start } else { first };
        parts.push((s, entries.by_ref().take(n).collect::<RefMap>()));
    }
    Some(parts)
}

impl PartialEq for RefParts {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl std::fmt::Debug for RefParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl serde::Serialize for RefParts {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        // (as the one map: its length, then its entries in order)
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in self.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for RefParts {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        RefMap::deserialize(deserializer).map(Self::of)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ReferenceManager {
    // Address-ordered so `all_refs()` yields references in the same
    // order on every run (a `HashMap` made it depend on the hash seed).
    // Most addresses have one or two references each way (a call or a
    // conditional jump: the target and the fall-through): kept inline,
    // without an allocation (serialized as a sequence, like a `Vec`).
    refs_from: RefParts,
    refs_to: RefParts,
    // Every jump reference (`RefType::is_jump`), in the order added:
    // lets a cache of per-function results tell which code gained a
    // jump into it since a mark (references are only ever added,
    // never removed).
    jumps: Vec<Reference>,
    // Identifies this manager, so a mark taken on another one (a
    // manager that replaced it) is never read against this log. Not
    // persisted: a manager read back from the on-disk analysis cache
    // gets a fresh id, like any new manager.
    #[serde(skip, default = "next_manager_id")]
    id: u64,
}

fn next_manager_id() -> u64 {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Default for ReferenceManager {
    fn default() -> Self {
        Self {
            refs_from: RefParts::default(),
            refs_to: RefParts::default(),
            jumps: Vec::new(),
            id: next_manager_id(),
        }
    }
}

impl ReferenceManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// The from / to maps and the jump log, for the on-disk analysis
    /// cache.
    pub fn cache_parts(&self) -> (&RefParts, &RefParts, &[Reference]) {
        (&self.refs_from, &self.refs_to, &self.jumps)
    }

    /// A manager of the parts [`Self::cache_parts`] returned, with a fresh
    /// id (like a manager deserialised whole).
    pub fn from_cache_parts(refs_from: RefMap, refs_to: RefMap, jumps: Vec<Reference>) -> Self {
        Self { refs_from: RefParts::of(refs_from), refs_to: RefParts::of(refs_to), jumps, id: next_manager_id() }
    }

    pub fn add(&mut self, reference: Reference) {
        if reference.ref_type.is_jump() {
            self.jumps.push(reference);
        }
        self.refs_from
            .entry(reference.from)
            .or_default()
            .push(reference);
        self.refs_to
            .entry(reference.to)
            .or_default()
            .push(reference);
    }

    /// [`Self::add`] of each of `refs`, in order — the same lists in the
    /// same order, the same jump log — in bulk: each source and target
    /// is looked up once, in address order.
    pub fn add_all(&mut self, refs: &[Reference]) {
        self.jumps.extend(refs.iter().filter(|r| r.ref_type.is_jump()).copied());
        // (the two maps at the same time, when there are many)
        let (from, to) = (&mut self.refs_from, &mut self.refs_to);
        if refs.len() >= 1024 {
            rayon::join(|| from.add_grouped(refs, |r| r.from, true), || to.add_grouped(refs, |r| r.to, true));
        } else {
            from.add_grouped(refs, |r| r.from, false);
            to.add_grouped(refs, |r| r.to, false);
        }
    }

    /// [`Self::add_all`] without the rayon pool, for a caller the pool's
    /// work must not hold up (the pool may be busy with other work, and a
    /// `join` from outside it waits for a worker): on this thread, with
    /// many the second map on a thread of its own.
    pub fn add_all_unpooled(&mut self, refs: &[Reference]) {
        self.jumps.extend(refs.iter().filter(|r| r.ref_type.is_jump()).copied());
        let (from, to) = (&mut self.refs_from, &mut self.refs_to);
        if refs.len() >= 1 << 14 {
            std::thread::scope(|s| {
                s.spawn(|| to.add_grouped(refs, |r| r.to, false));
                from.add_grouped(refs, |r| r.from, false);
            });
        } else {
            from.add_grouped(refs, |r| r.from, false);
            to.add_grouped(refs, |r| r.to, false);
        }
    }

    /// Add `reference` unless a reference from its source already
    /// satisfies `present` (as `get_refs_from(from).iter().any(present)`
    /// then `add`, with one lookup of the source). Returns whether it
    /// was added.
    pub fn add_unless(&mut self, reference: Reference, present: impl Fn(&Reference) -> bool) -> bool {
        let from = self.refs_from.entry(reference.from).or_default();
        if from.iter().any(present) {
            return false;
        }
        from.push(reference);
        if reference.ref_type.is_jump() {
            self.jumps.push(reference);
        }
        self.refs_to.entry(reference.to).or_default().push(reference);
        true
    }

    /// A mark for [`Self::jump_targets_since`]: the number of jump
    /// references (`RefType::is_jump`) added so far.
    pub fn jump_mark(&self) -> JumpMark {
        JumpMark { manager: self.id, len: self.jumps.len() }
    }

    /// The jump references added since `mark`, in the order added
    /// (with repeats); `None` when `mark` was not taken on this
    /// manager.
    pub fn jumps_since(&self, mark: JumpMark) -> Option<&[Reference]> {
        if mark.manager != self.id {
            return None;
        }
        self.jumps.get(mark.len..)
    }

    pub fn get_refs_from(&self, address: u64) -> &[Reference] {
        self.refs_from.get(&address).map_or(&[], |v| v.as_slice())
    }

    pub fn get_refs_to(&self, address: u64) -> &[Reference] {
        self.refs_to.get(&address).map_or(&[], |v| v.as_slice())
    }

    pub fn call_refs_from(&self, address: u64) -> Vec<&Reference> {
        self.get_refs_from(address)
            .iter()
            .filter(|r| r.ref_type.is_call())
            .collect()
    }

    pub fn call_refs_to(&self, address: u64) -> Vec<&Reference> {
        self.get_refs_to(address)
            .iter()
            .filter(|r| r.ref_type.is_call())
            .collect()
    }

    /// Every jump reference (`RefType::is_jump`), by target address.
    pub fn jump_refs_by_target(&self) -> impl Iterator<Item = &Reference> {
        self.refs_to.values().flatten().filter(|r| r.ref_type.is_jump())
    }

    /// The references [`Self::jump_refs_by_target`] yields, in that
    /// order (by target, those to one target in the order added), from
    /// the log of jumps instead of a walk over every reference.
    pub fn jump_refs_sorted_by_target(&self) -> Vec<Reference> {
        // stable: the references to one target stay in the order added
        // (by target, then index)
        let mut order: Vec<(u64, u32)> = self.jumps.iter().enumerate().map(|(i, r)| (r.to, i as u32)).collect();
        sort_keyed(&mut order);
        order.into_iter().map(|(_, i)| self.jumps[i as usize]).collect()
    }

    /// Each address in `start..end` with references to it, and those
    /// references (as `get_refs_to` gives them), in address order; nothing
    /// when `start >= end`.
    pub fn refs_to_range(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, &[Reference])> {
        let range = (start < end).then(|| self.refs_to.range(start, end));
        range.into_iter().flatten().map(|(&a, v)| (a, v.as_slice()))
    }

    /// The references from each address in `start..end` that has any,
    /// in address order (as `get_refs_from` of each address in turn
    /// gives them); nothing when `start >= end`.
    pub fn refs_from_range(&self, start: u64, end: u64) -> impl Iterator<Item = &[Reference]> {
        let range = (start < end).then(|| self.refs_from.range(start, end));
        range.into_iter().flatten().map(|(_, v)| v.as_slice())
    }

    pub fn all_refs(&self) -> impl Iterator<Item = &Reference> {
        self.refs_from.values().flat_map(|v| v.iter())
    }

    pub fn len(&self) -> usize {
        self.refs_from.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.refs_from.is_empty()
    }
}

#[cfg(test)]
mod tests {
    /// The radix sort orders as `sort_unstable` does (key, then index), for
    /// keys of every span: repeats, a span past 2^32, few and many.
    #[test]
    fn sort_keyed_matches_sort_unstable() {
        let mut seed = 0x2545f4914f6cdd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for (n, span) in [(10, 100u64), (5000, 1), (5000, 7), (9000, 1 << 12), (9000, 1 << 13), (20000, 1 << 24), (20000, 1 << 25), (20000, u32::MAX as u64), (20000, 1 << 33), (20000, u64::MAX)] {
            let base = next() % (u64::MAX - span.min(u64::MAX / 2));
            let mut order: Vec<(u64, u32)> =
                (0..n).map(|i| (if span == u64::MAX { next() } else { base + next() % (span + 1) }, i as u32)).collect();
            let mut expected = order.clone();
            expected.sort_unstable();
            super::sort_keyed(&mut order);
            assert_eq!(order, expected, "{n} {span}");
        }
    }

    use super::*;

        /// References added a batch at a time and all at once (the batches
    /// joined, as the discovery thread adds the batches waiting) give the
    /// same lists in the same order and the same jump log, through the few
    /// and the many path.
    #[test]
    fn batches_joined_match_batch_by_batch() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let kinds = [RefType::UnconditionalCall, RefType::ConditionalJump, RefType::DataRead, RefType::FallThrough];
        let batches: Vec<Vec<Reference>> = (0..12)
            .map(|b| {
                (0..if b % 4 == 0 { 20_000 } else { 700 })
                    .map(|_| {
                        let r = next();
                        Reference::new(0x1000 + r % 5_000, 0x1000 + (r >> 20) % 9_000, kinds[(r >> 40) as usize % 4])
                    })
                    .collect()
            })
            .collect();
        let state = |m: &ReferenceManager| (m.refs_from.clone(), m.refs_to.clone(), m.jumps.clone());
        let mut one = ReferenceManager::new();
        for b in &batches {
            one.add_all_unpooled(b);
        }
        for groups in [vec![12], vec![1, 11], vec![3, 3, 6], vec![1; 12]] {
            let mut joined = ReferenceManager::new();
            let mut at = 0;
            for n in groups {
                let together: Vec<Reference> = batches[at..at + n].concat();
                joined.add_all_unpooled(&together);
                at += n;
            }
            assert_eq!(state(&joined), state(&one));
        }
    }

/// Bulk adds into a map in parts (cut as it grows, merged per part — on
    /// the pool or not —, with single adds and `add_unless` between) read as
    /// one map built entry by entry: the same entries in the same order,
    /// lookups and ranges, length, and the same serialization; a map read
    /// back is the same.
    #[test]
    fn parted_maps_read_as_one_map() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let kinds = [RefType::UnconditionalCall, RefType::ConditionalJump, RefType::DataRead, RefType::FallThrough];
        let mut one_from = RefMap::new();
        let mut one_to = RefMap::new();
        let mut jumps = Vec::new();
        let mut plain = |r: Reference, from: &mut RefMap, to: &mut RefMap| {
            if r.ref_type.is_jump() {
                jumps.push(r);
            }
            from.entry(r.from).or_default().push(r);
            to.entry(r.to).or_default().push(r);
        };
        let mut mgr = ReferenceManager::new();
        for round in 0..24 {
            // (batches of every size: few into large parts, many, a dense
            // range of new keys that grows one part past its share)
            let n = [3usize, 700, 5_000, 40_000][round % 4];
            let span = if round % 5 == 4 { 1 << 12 } else { 1 << 22 };
            let base = 0x40_0000 + (next() % 4) * (1 << 22);
            let batch: Vec<Reference> = (0..n)
                .map(|_| {
                    let r = next();
                    Reference::new(base + r % span, 0x40_0000 + (r >> 24) % (span * 3), kinds[(r >> 50) as usize % 4])
                })
                .collect();
            for &r in &batch {
                plain(r, &mut one_from, &mut one_to);
            }
            match round % 3 {
                0 => mgr.add_all(&batch),
                1 => mgr.add_all_unpooled(&batch),
                _ => batch.iter().for_each(|&r| mgr.add(r)),
            }
            let r = Reference::new(base + next() % span, 0x40_0000 + next() % span, RefType::DataRead);
            let present = |e: &Reference| e.to == r.to;
            if !one_from.get(&r.from).is_some_and(|l| l.iter().any(present)) {
                plain(r, &mut one_from, &mut one_to);
            }
            mgr.add_unless(r, present);
        }
        assert!(mgr.refs_from.maps.len() > 4 && mgr.refs_to.maps.len() > 4, "cut into parts");
        assert!(mgr.refs_from.starts.windows(2).all(|w| w[0] < w[1]));
        for (parts, one) in [(&mgr.refs_from, &one_from), (&mgr.refs_to, &one_to)] {
            assert!(parts.iter().eq(one.iter()));
            assert!(parts.values().eq(one.values()));
            assert_eq!(parts.len(), one.len());
            assert_eq!(serde_json::to_string(parts).unwrap(), serde_json::to_string(one).unwrap());
            for _ in 0..200 {
                let (a, b) = (0x40_0000 + next() % (1 << 24), 0x40_0000 + next() % (1 << 24));
                assert_eq!(parts.get(&a), one.get(&a));
                if a < b {
                    assert!(parts.range(a, b).eq(one.range(a..b)));
                }
            }
            let back: RefParts = serde_json::from_str(&serde_json::to_string(parts).unwrap()).unwrap();
            assert!(back == *parts && back.maps.len() == 1);
        }
        assert_eq!(mgr.jumps, jumps);
        assert_eq!(mgr.len(), one_from.values().map(|l| l.len()).sum::<usize>());
        let back = ReferenceManager::from_cache_parts(one_from.clone(), one_to.clone(), jumps.clone());
        assert!(back.refs_from == mgr.refs_from && back.refs_to == mgr.refs_to);
    }

    #[test]
    fn add_and_query_refs() {
        let mut mgr = ReferenceManager::new();
        mgr.add(Reference::new(0x1000, 0x2000, RefType::UnconditionalCall));
        mgr.add(Reference::new(0x1004, 0x3000, RefType::ConditionalJump));
        mgr.add(Reference::new(0x1008, 0x2000, RefType::UnconditionalCall));

        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.get_refs_from(0x1000).len(), 1);
        assert_eq!(mgr.get_refs_to(0x2000).len(), 2);
        assert_eq!(mgr.call_refs_to(0x2000).len(), 2);
        assert!(mgr.get_refs_from(0x1004)[0].ref_type.is_jump());
        let mark = mgr.jump_mark();
        assert_eq!(mgr.jumps_since(mark), Some(&[][..]));
        mgr.add(Reference::new(0x100c, 0x4000, RefType::IndirectJump));
        mgr.add(Reference::new(0x1010, 0x5000, RefType::DataRead));
        assert_eq!(
            mgr.jumps_since(mark),
            Some(&[Reference::new(0x100c, 0x4000, RefType::IndirectJump)][..])
        );
        // a mark of another manager is not read against this one
        let other = ReferenceManager::new();
        assert_eq!(other.jumps_since(mark), None);
    }

    #[test]
    fn refs_from_range_walks_addresses_in_order() {
        let mut mgr = ReferenceManager::new();
        mgr.add(Reference::new(0x1008, 0x3000, RefType::DataRead));
        mgr.add(Reference::new(0x1000, 0x2000, RefType::UnconditionalCall));
        mgr.add(Reference::new(0x1000, 0x1005, RefType::FallThrough));
        mgr.add(Reference::new(0x1000, 0x2008, RefType::DataRead));
        mgr.add(Reference::new(0x1010, 0x3000, RefType::DataRead));
        let walk = |s: u64, e: u64| -> Vec<Reference> {
            mgr.refs_from_range(s, e).flatten().copied().collect()
        };
        let per_address = |s: u64, e: u64| -> Vec<Reference> {
            (s..e).flat_map(|a| mgr.get_refs_from(a).iter().copied()).collect()
        };
        for (s, e) in [(0x1000, 0x1010), (0x1001, 0x1011), (0x0, 0x2000), (0x1008, 0x1008), (0x1009, 0x1001)] {
            assert_eq!(walk(s, e), per_address(s, e), "{s:#x}..{e:#x}");
        }
        // three references from one address: kept in the order added
        assert_eq!(mgr.get_refs_from(0x1000).iter().map(|r| r.to).collect::<Vec<_>>(), [0x2000, 0x1005, 0x2008]);
        assert_eq!(mgr.get_refs_to(0x3000).len(), 2);
    }

    /// Many jumps (the radix sort's size): the log sorted by target gives
    /// the references the walk by target gives, in the same order.
    #[test]
    fn many_jumps_sorted_by_target_match_the_walk() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |m: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % m
        };
        let kinds = [RefType::UnconditionalJump, RefType::ConditionalJump, RefType::IndirectJump, RefType::DataRead];
        let mut mgr = ReferenceManager::new();
        for _ in 0..20_000 {
            let (from, to) = (0x40_0000 + next(1 << 20), 0x40_0000 + next(1 << 12));
            mgr.add(Reference::new(from, to, kinds[next(4) as usize]));
        }
        let by_target: Vec<Reference> = mgr.jump_refs_by_target().copied().collect();
        assert!(by_target.len() > 1 << 12);
        assert_eq!(mgr.jump_refs_sorted_by_target(), by_target);
    }

    #[test]
    fn add_unless_and_jumps_by_target_agree_with_the_plain_forms() {
        let refs = [
            Reference::new(0x1010, 0x3000, RefType::UnconditionalJump),
            Reference::new(0x1000, 0x3000, RefType::ConditionalJump),
            Reference::new(0x1004, 0x2000, RefType::DataRead),
            Reference::new(0x1008, 0x2000, RefType::IndirectJump),
            Reference::new(0x1000, 0x3000, RefType::ConditionalJump),
            Reference::new(0x1018, 0x1000, RefType::UnconditionalJump),
            Reference::new(0x1004, 0x2000, RefType::DataRead),
        ];
        let (mut plain, mut once) = (ReferenceManager::new(), ReferenceManager::new());
        for r in refs {
            let present = |e: &Reference| e.to == r.to && e.ref_type == r.ref_type;
            let added = !plain.get_refs_from(r.from).iter().any(present);
            if added {
                plain.add(r);
            }
            assert_eq!(once.add_unless(r, present), added);
        }
        assert_eq!(plain.all_refs().collect::<Vec<_>>(), once.all_refs().collect::<Vec<_>>());
        for to in [0x1000, 0x2000, 0x3000] {
            assert_eq!(plain.get_refs_to(to), once.get_refs_to(to));
        }
        let by_target: Vec<Reference> = once.jump_refs_by_target().copied().collect();
        assert_eq!(once.jump_refs_sorted_by_target(), by_target);
        assert_eq!(by_target.iter().map(|r| r.from).collect::<Vec<_>>(), [0x1018, 0x1008, 0x1010, 0x1000]);
    }
}
