// System call emulation stubs.

use std::collections::BTreeMap;
use crate::state::EmulatorState;

pub type SyscallHandler = Box<dyn Fn(u64, &mut EmulatorState) -> SyscallResult + Send + Sync>;

#[derive(Debug)]
pub enum SyscallResult {
    Ok(u64),
    Error(i64),
    Exit(i32),
    NotImplemented,
}

pub struct SyscallTable {
    handlers: BTreeMap<u64, SyscallHandler>,
    name_map: BTreeMap<u64, String>,
}

impl SyscallTable {
    pub fn new() -> Self {
        Self { handlers: BTreeMap::new(), name_map: BTreeMap::new() }
    }

    pub fn register(&mut self, number: u64, name: impl Into<String>, handler: SyscallHandler) {
        self.name_map.insert(number, name.into());
        self.handlers.insert(number, handler);
    }

    pub fn handle(&self, number: u64, state: &mut EmulatorState) -> SyscallResult {
        match self.handlers.get(&number) {
            Some(handler) => handler(number, state),
            None => SyscallResult::NotImplemented,
        }
    }

    pub fn name(&self, number: u64) -> Option<&str> {
        self.name_map.get(&number).map(|s| s.as_str())
    }

    pub fn build_linux_x86_64() -> Self {
        let mut table = Self::new();
        table.register(0, "read", Box::new(|_, state| {
            let _fd = state.read_register(0x38, 8);
            state.write_register(0x00, 8, 0);
            SyscallResult::Ok(0)
        }));
        table.register(1, "write", Box::new(|_, state| {
            let _fd = state.read_register(0x38, 8);
            let count = state.read_register(0x10, 8);
            state.write_register(0x00, 8, count);
            SyscallResult::Ok(count)
        }));
        table.register(9, "mmap", Box::new(|_, state| {
            let _len = state.read_register(0x30, 8);
            state.write_register(0x00, 8, 0x7F000000);
            SyscallResult::Ok(0x7F000000)
        }));
        table.register(60, "exit", Box::new(|_, state| {
            let code = state.read_register(0x38, 8) as i32;
            SyscallResult::Exit(code)
        }));
        table.register(231, "exit_group", Box::new(|_, state| {
            let code = state.read_register(0x38, 8) as i32;
            SyscallResult::Exit(code)
        }));
        table
    }

    pub fn len(&self) -> usize { self.handlers.len() }
    pub fn is_empty(&self) -> bool { self.handlers.is_empty() }
}

impl Default for SyscallTable {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_syscall_table() {
        let table = SyscallTable::build_linux_x86_64();
        assert!(table.len() >= 5);
        assert_eq!(table.name(60), Some("exit"));
        assert_eq!(table.name(0), Some("read"));
    }

    #[test]
    fn syscall_not_implemented() {
        let table = SyscallTable::new();
        let mut state = EmulatorState::new();
        assert!(matches!(table.handle(999, &mut state), SyscallResult::NotImplemented));
    }

    #[test]
    fn exit_syscall() {
        let table = SyscallTable::build_linux_x86_64();
        let mut state = EmulatorState::new();
        state.write_register(0x38, 8, 42);
        match table.handle(60, &mut state) {
            SyscallResult::Exit(code) => assert_eq!(code, 42),
            _ => panic!("expected Exit"),
        }
    }
}
