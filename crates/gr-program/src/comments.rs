use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Debug, Default)]
pub struct CommentManager {
    comments: BTreeMap<(u64, CommentType), String>,
}

impl CommentManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, address: u64, comment_type: CommentType, text: impl Into<String>) {
        self.comments.insert((address, comment_type), text.into());
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
