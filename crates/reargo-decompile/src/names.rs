//! Names by address, as the decompiler looks them up: the program's symbol map, with an
//! optional second map layered over it (the import thunks one function calls) — a lookup
//! instead of a copy of the whole symbol map per function.

use std::collections::BTreeMap;

/// The names of addresses: `base`, then `extra` for an address `base` does not name.
#[derive(Clone, Copy, Debug)]
pub struct Names<'a> {
    base: &'a BTreeMap<u64, String>,
    extra: Option<&'a BTreeMap<u64, String>>,
}

impl<'a> Names<'a> {
    /// Only the names of `base`.
    pub fn new(base: &'a BTreeMap<u64, String>) -> Self {
        Self { base, extra: None }
    }

    /// The names of `base`, and those of `extra` at the addresses `base` does not name.
    pub fn with_extra(base: &'a BTreeMap<u64, String>, extra: &'a BTreeMap<u64, String>) -> Self {
        Self { base, extra: (!extra.is_empty()).then_some(extra) }
    }

    /// The name of `addr`.
    #[inline]
    pub fn get(&self, addr: &u64) -> Option<&'a String> {
        match self.base.get(addr) {
            Some(n) => Some(n),
            None => self.extra?.get(addr),
        }
    }
}

impl<'a> From<&'a BTreeMap<u64, String>> for Names<'a> {
    fn from(base: &'a BTreeMap<u64, String>) -> Self {
        Self::new(base)
    }
}

impl Default for Names<'static> {
    fn default() -> Self {
        static EMPTY: BTreeMap<u64, String> = BTreeMap::new();
        Self::new(&EMPTY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_first_then_extra() {
        let base = BTreeMap::from([(1u64, "a".to_string()), (2, "b".to_string())]);
        let extra = BTreeMap::from([(2u64, "x".to_string()), (3, "c".to_string())]);
        let n = Names::with_extra(&base, &extra);
        assert_eq!(n.get(&1).map(String::as_str), Some("a"));
        assert_eq!(n.get(&2).map(String::as_str), Some("b"));
        assert_eq!(n.get(&3).map(String::as_str), Some("c"));
        assert_eq!(n.get(&4), None);
        assert_eq!(Names::new(&base).get(&3), None);
    }
}
