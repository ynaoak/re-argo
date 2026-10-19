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
fn add_grouped(map: &mut RefMap, refs: &[Reference], key: impl Fn(&Reference) -> u64 + Sync) {
    let mut sorted = refs.to_vec();
    if sorted.len() >= 1 << 14 {
        use rayon::slice::ParallelSliceMut;
        sorted.par_sort_by_key(&key);
    } else {
        sorted.sort_by_key(&key);
    }
    let mut groups = sorted.chunk_by(|a, b| key(a) == key(b)).peekable();
    if groups.peek().is_none() {
        return;
    }
    if sorted.len() < map.len() / 8 {
        for g in groups {
            map.entry(key(&g[0])).or_default().extend_from_slice(g);
        }
        return;
    }
    // Many: both merged in address order into a new map, built in one pass.
    let old = std::mem::take(map).into_iter();
    let mut merged: Vec<(u64, RefList)> = Vec::with_capacity(old.len() + sorted.len());
    let mut old = old.peekable();
    for g in groups {
        let k = key(&g[0]);
        while let Some(o) = old.next_if(|(ok, _)| *ok < k) {
            merged.push(o);
        }
        match old.next_if(|(ok, _)| *ok == k) {
            Some((_, mut list)) => {
                list.extend_from_slice(g);
                merged.push((k, list));
            }
            None => merged.push((k, RefList::from_slice(g))),
        }
    }
    merged.extend(old);
    *map = merged.into_iter().collect();
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ReferenceManager {
    // Address-ordered so `all_refs()` yields references in the same
    // order on every run (a `HashMap` made it depend on the hash seed).
    // Most addresses have one or two references each way (a call or a
    // conditional jump: the target and the fall-through): kept inline,
    // without an allocation (serialized as a sequence, like a `Vec`).
    refs_from: BTreeMap<u64, RefList>,
    refs_to: BTreeMap<u64, RefList>,
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
            refs_from: BTreeMap::new(),
            refs_to: BTreeMap::new(),
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
    pub fn cache_parts(&self) -> (&RefMap, &RefMap, &[Reference]) {
        (&self.refs_from, &self.refs_to, &self.jumps)
    }

    /// A manager of the parts [`Self::cache_parts`] returned, with a fresh
    /// id (like a manager deserialised whole).
    pub fn from_cache_parts(refs_from: RefMap, refs_to: RefMap, jumps: Vec<Reference>) -> Self {
        Self { refs_from, refs_to, jumps, id: next_manager_id() }
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
        let (from, to) = (&mut self.refs_from, &mut self.refs_to);
        if refs.len() >= 1 << 12 {
            rayon::join(|| add_grouped(from, refs, |r| r.from), || add_grouped(to, refs, |r| r.to));
        } else {
            add_grouped(from, refs, |r| r.from);
            add_grouped(to, refs, |r| r.to);
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
        let mut jumps = self.jumps.clone();
        // stable: the references to one target stay in the order added
        jumps.sort_by_key(|r| r.to);
        jumps
    }

    /// The references from each address in `start..end` that has any,
    /// in address order (as `get_refs_from` of each address in turn
    /// gives them); nothing when `start >= end`.
    pub fn refs_from_range(&self, start: u64, end: u64) -> impl Iterator<Item = &[Reference]> {
        let range = (start < end).then(|| self.refs_from.range(start..end));
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
    use super::*;

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
