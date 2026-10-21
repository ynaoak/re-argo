use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum CommentType {
    Eol,
    Pre,
    Post,
    Plate,
    Repeatable,
}

#[derive(Debug, Clone)]
pub struct Comment {
    pub address: u64,
    pub comment_type: CommentType,
    pub text: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CommentManager {
    comments: BTreeMap<(u64, CommentType), String>,
}

impl CommentManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// The comment map, for the on-disk analysis cache.
    pub fn cache_parts(&self) -> &BTreeMap<(u64, CommentType), String> {
        &self.comments
    }

    /// A manager of the map [`Self::cache_parts`] returned.
    pub fn from_cache_parts(comments: BTreeMap<(u64, CommentType), String>) -> Self {
        Self { comments }
    }

    pub fn set(&mut self, address: u64, comment_type: CommentType, text: impl Into<String>) {
        self.comments.insert((address, comment_type), text.into());
    }

    /// Set the comment unless one of this type is there already (as
    /// `get(..).is_none()` then `set`, with one lookup). Returns whether
    /// it was set.
    pub fn set_if_absent(&mut self, address: u64, comment_type: CommentType, text: impl Into<String>) -> bool {
        match self.comments.entry((address, comment_type)) {
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(text.into());
                true
            }
            std::collections::btree_map::Entry::Occupied(_) => false,
        }
    }

    /// [`Self::set_if_absent`] of each item in turn; returns how many
    /// were set. Many items are merged into the map in one pass over it
    /// instead of a lookup each.
    pub fn set_all_if_absent<S: Into<String>>(&mut self, items: impl IntoIterator<Item = (u64, CommentType, S)>) -> usize {
        let mut new: Vec<((u64, CommentType), S)> = items.into_iter().map(|(a, t, s)| ((a, t), s)).collect();
        if new.len() < 64 || new.len() * 8 < self.comments.len() {
            return new.into_iter().map(|((a, t), s)| usize::from(self.set_if_absent(a, t, s))).sum();
        }
        // the first item of each key (a stable sort keeps their order) …
        new.sort_by_key(|(k, _)| *k);
        new.dedup_by(|later, earlier| later.0 == earlier.0);
        // … whose key the map does not hold (the map's keys from the
        // first item's on, read along)
        {
            let mut keys = self.comments.range(new[0].0..).map(|(k, _)| *k).peekable();
            new.retain(|(k, _)| {
                while keys.next_if(|e| e < k).is_some() {}
                keys.peek() != Some(k)
            });
        }
        let set = new.len();
        let mut added: BTreeMap<(u64, CommentType), String> = new.into_iter().map(|(k, s)| (k, s.into())).collect();
        self.comments.append(&mut added);
        set
    }

    /// [`Self::set_all_if_absent`] of the items a [`CommentBatch`] was
    /// made from (made beforehand, off the program: the items sorted and
    /// their map built). Returns how many were set.
    pub fn set_batch_if_absent(&mut self, batch: CommentBatch) -> usize {
        let mut added = batch.0;
        if self.comments.len() > added.len() {
            return added.into_iter().map(|((a, t), s)| usize::from(self.set_if_absent(a, t, s))).sum();
        }
        // (the map held has fewer: its comments put into the batch's,
        // over the batch's own where both have a key)
        let mut set = added.len();
        for (k, s) in std::mem::take(&mut self.comments) {
            if added.insert(k, s).is_some() {
                set -= 1;
            }
        }
        self.comments = added;
        set
    }

    pub fn get(&self, address: u64, comment_type: CommentType) -> Option<&str> {
        self.comments.get(&(address, comment_type)).map(|s| s.as_str())
    }

    pub fn remove(&mut self, address: u64, comment_type: CommentType) -> bool {
        self.comments.remove(&(address, comment_type)).is_some()
    }

    pub fn all_at(&self, address: u64) -> Vec<(&CommentType, &str)> {
        self.comments
            .range((address, CommentType::Eol)..=(address, CommentType::Repeatable))
            .map(|((_, ct), text)| (ct, text.as_str()))
            .collect()
    }

    /// Every comment as `iter` gives them (same order), borrowed.
    pub fn iter_refs(&self) -> impl Iterator<Item = (u64, CommentType, &str)> + '_ {
        self.comments.iter().map(|((addr, ct), text)| (*addr, *ct, text.as_str()))
    }

    pub fn iter(&self) -> impl Iterator<Item = Comment> + '_ {
        self.comments.iter().map(|((addr, ct), text)| Comment {
            address: *addr,
            comment_type: *ct,
            text: text.clone(),
        })
    }

    pub fn len(&self) -> usize {
        self.comments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.comments.is_empty()
    }
}

/// Comments to set where absent ([`CommentManager::set_batch_if_absent`]),
/// made before: the first item of each key, by key.
#[derive(Debug, Default)]
pub struct CommentBatch(BTreeMap<(u64, CommentType), String>);

impl CommentBatch {
    pub fn new<S: Into<String>>(items: impl IntoIterator<Item = (u64, CommentType, S)>) -> Self {
        let mut new: Vec<((u64, CommentType), S)> = items.into_iter().map(|(a, t, s)| ((a, t), s)).collect();
        // the first item of each key (a stable sort keeps their order)
        new.sort_by_key(|(k, _)| *k);
        new.dedup_by(|later, earlier| later.0 == earlier.0);
        Self(new.into_iter().map(|(k, s)| (k, s.into())).collect())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Bookmark {
    pub address: u64,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Default)]
pub struct BookmarkManager {
    bookmarks: Vec<Bookmark>,
}

impl BookmarkManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, address: u64, category: impl Into<String>, description: impl Into<String>) {
        self.bookmarks.push(Bookmark {
            address,
            category: category.into(),
            description: description.into(),
        });
    }

    pub fn at(&self, address: u64) -> Vec<&Bookmark> {
        self.bookmarks.iter().filter(|b| b.address == address).collect()
    }

    pub fn all(&self) -> &[Bookmark] {
        &self.bookmarks
    }

    pub fn len(&self) -> usize {
        self.bookmarks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bookmarks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bulk set gives the map and count `set_if_absent` of each item
    /// in turn gives (repeated keys, keys already there, few and many).
    #[test]
    fn set_all_if_absent_matches_one_by_one() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let types = [CommentType::Eol, CommentType::Post, CommentType::Plate];
        for (existing, items) in [(0usize, 10usize), (5, 100), (300, 100), (1000, 20), (50, 2000), (400, 400), (0, 0)] {
            let mut base = CommentManager::new();
            for _ in 0..existing {
                let k = next();
                base.set(k % 512, types[(k >> 20) as usize % 3], format!("old {k}"));
            }
            let list: Vec<(u64, CommentType, String)> = (0..items)
                .map(|i| {
                    let k = next();
                    (k % 512, types[(k >> 20) as usize % 3], format!("new {i}"))
                })
                .collect();
            let mut one = CommentManager::from_cache_parts(base.cache_parts().clone());
            let n_one: usize = list.iter().map(|(a, t, s)| usize::from(one.set_if_absent(*a, *t, s.clone()))).sum();
            let mut bulk = CommentManager::from_cache_parts(base.cache_parts().clone());
            let mut batched = CommentManager::from_cache_parts(base.cache_parts().clone());
            let n_batch = batched.set_batch_if_absent(CommentBatch::new(list.clone()));
            let n_bulk = bulk.set_all_if_absent(list);
            assert_eq!(n_bulk, n_one);
            assert_eq!(bulk.cache_parts(), one.cache_parts());
            assert_eq!(n_batch, n_one);
            assert_eq!(batched.cache_parts(), one.cache_parts());
        }
    }

    #[test]
    fn comment_manager() {
        let mut mgr = CommentManager::new();
        mgr.set(0x1000, CommentType::Eol, "end of line comment");
        mgr.set(0x1000, CommentType::Pre, "before instruction");
        assert_eq!(mgr.get(0x1000, CommentType::Eol), Some("end of line comment"));
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.all_at(0x1000).len(), 2);
    }

    #[test]
    fn bookmark_manager() {
        let mut mgr = BookmarkManager::new();
        mgr.add(0x1000, "Analysis", "Interesting function");
        mgr.add(0x1000, "Error", "Potential bug");
        assert_eq!(mgr.at(0x1000).len(), 2);
        assert_eq!(mgr.len(), 2);
    }
}
