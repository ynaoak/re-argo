//! Scratch storage analyzers use to hand results to later analyzers.
//!
//! An analyzer that computes something expensive another analyzer
//! also needs (the per-function call-site walks, for one) can leave
//! it here; the later analyzer takes it back and decides itself
//! whether it still holds for the program as it is by then. Entries
//! are keyed by their Rust type, live only in memory and are never
//! exported or serialised.

use std::any::{Any, TypeId};
use std::collections::HashMap;

/// A map from a type to one value of that type.
#[derive(Default)]
pub struct AnalysisCache {
    slots: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl AnalysisCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove and return the stored `T`, if any.
    pub fn take<T: Any + Send + Sync>(&mut self) -> Option<T> {
        self.slots
            .remove(&TypeId::of::<T>())
            .and_then(|b| b.downcast::<T>().ok())
            .map(|b| *b)
    }

    /// Whether a `T` is stored.
    pub fn contains<T: Any + Send + Sync>(&self) -> bool {
        self.slots.contains_key(&TypeId::of::<T>())
    }

    /// Store `value`, replacing any `T` stored before.
    pub fn insert<T: Any + Send + Sync>(&mut self, value: T) {
        self.slots.insert(TypeId::of::<T>(), Box::new(value));
    }

    /// Drop every entry.
    pub fn clear(&mut self) {
        self.slots.clear();
    }
}

impl std::fmt::Debug for AnalysisCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisCache").field("entries", &self.slots.len()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_returns_what_was_inserted_once() {
        let mut c = AnalysisCache::new();
        c.insert(5u32);
        c.insert(String::from("x"));
        assert_eq!(c.take::<u32>(), Some(5));
        assert_eq!(c.take::<u32>(), None);
        assert_eq!(c.take::<String>().as_deref(), Some("x"));
    }
}
