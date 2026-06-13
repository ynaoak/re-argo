// Undo/Redo transaction system for program modifications.

use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub enum ProgramChange {
    SymbolAdded { address: u64, name: String },
    SymbolRemoved { address: u64, name: String },
    CommentSet { address: u64, old: Option<String>, new: String },
    FunctionCreated { entry: u64, name: String },
    FunctionRemoved { entry: u64, name: String },
    ReferenceAdded { from: u64, to: u64 },
    BookmarkAdded { address: u64, category: String },
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: u32,
    pub description: String,
    pub changes: Vec<ProgramChange>,
}

#[derive(Debug)]
pub struct TransactionManager {
    undo_stack: VecDeque<Transaction>,
    redo_stack: Vec<Transaction>,
    next_id: u32,
    max_undo: usize,
    current: Option<Transaction>,
}

impl TransactionManager {
    pub fn new(max_undo: usize) -> Self {
        Self {
            undo_stack: VecDeque::new(),
            redo_stack: Vec::new(),
            next_id: 0,
            max_undo,
            current: None,
        }
    }

    pub fn begin(&mut self, description: impl Into<String>) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.current = Some(Transaction {
            id,
            description: description.into(),
            changes: Vec::new(),
        });
        id
    }

    pub fn record(&mut self, change: ProgramChange) {
        if let Some(ref mut txn) = self.current {
            txn.changes.push(change);
        }
    }

    pub fn commit(&mut self) {
        if let Some(txn) = self.current.take()
            && !txn.changes.is_empty() {
                if self.undo_stack.len() >= self.max_undo {
                    self.undo_stack.pop_front();
                }
                self.undo_stack.push_back(txn);
                self.redo_stack.clear();
            }
    }

    pub fn rollback(&mut self) {
        self.current = None;
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn undo(&mut self) -> Option<&Transaction> {
        if let Some(txn) = self.undo_stack.pop_back() {
            self.redo_stack.push(txn);
            self.redo_stack.last()
        } else {
            None
        }
    }

    pub fn redo(&mut self) -> Option<&Transaction> {
        if let Some(txn) = self.redo_stack.pop() {
            self.undo_stack.push_back(txn);
            self.undo_stack.back()
        } else {
            None
        }
    }

    pub fn undo_count(&self) -> usize {
        self.undo_stack.len()
    }

    pub fn redo_count(&self) -> usize {
        self.redo_stack.len()
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_lifecycle() {
        let mut mgr = TransactionManager::new(10);
        mgr.begin("add symbol");
        mgr.record(ProgramChange::SymbolAdded { address: 0x1000, name: "test".into() });
        mgr.commit();
        assert!(mgr.can_undo());
        assert!(!mgr.can_redo());
    }

    #[test]
    fn undo_redo() {
        let mut mgr = TransactionManager::new(10);
        mgr.begin("change 1");
        mgr.record(ProgramChange::FunctionCreated { entry: 0x1000, name: "fn1".into() });
        mgr.commit();
        mgr.begin("change 2");
        mgr.record(ProgramChange::FunctionCreated { entry: 0x2000, name: "fn2".into() });
        mgr.commit();

        assert_eq!(mgr.undo_count(), 2);
        mgr.undo();
        assert_eq!(mgr.undo_count(), 1);
        assert!(mgr.can_redo());
        mgr.redo();
        assert_eq!(mgr.undo_count(), 2);
    }

    #[test]
    fn rollback() {
        let mut mgr = TransactionManager::new(10);
        mgr.begin("aborted");
        mgr.record(ProgramChange::SymbolAdded { address: 0, name: "x".into() });
        mgr.rollback();
        assert!(!mgr.can_undo());
    }

    #[test]
    fn max_undo() {
        let mut mgr = TransactionManager::new(3);
        for i in 0..5 {
            mgr.begin(format!("change {}", i));
            mgr.record(ProgramChange::SymbolAdded { address: i as u64, name: format!("s{}", i) });
            mgr.commit();
        }
        assert_eq!(mgr.undo_count(), 3);
    }
}
