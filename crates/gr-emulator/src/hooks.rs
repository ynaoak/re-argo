use std::collections::BTreeMap;

pub type HookFn = Box<dyn Fn(u64, &mut crate::state::EmulatorState) -> HookAction + Send + Sync>;

pub enum HookAction {
    Continue,
    Skip,
    Stop,
}

pub struct HookManager {
    address_hooks: BTreeMap<u64, Vec<HookFn>>,
    syscall_hooks: BTreeMap<u64, HookFn>,
}

impl HookManager {
    pub fn new() -> Self {
        Self {
            address_hooks: BTreeMap::new(),
            syscall_hooks: BTreeMap::new(),
        }
    }

    pub fn add_hook(&mut self, address: u64, hook: HookFn) {
        self.address_hooks.entry(address).or_default().push(hook);
    }

    pub fn add_syscall_hook(&mut self, number: u64, hook: HookFn) {
        self.syscall_hooks.insert(number, hook);
    }

    pub fn check(&self, address: u64, state: &mut crate::state::EmulatorState) -> HookAction {
        if let Some(hooks) = self.address_hooks.get(&address) {
            for hook in hooks {
                match hook(address, state) {
                    HookAction::Continue => {}
                    action => return action,
                }
            }
        }
        HookAction::Continue
    }

    pub fn has_hook(&self, address: u64) -> bool {
        self.address_hooks.contains_key(&address)
    }
}

impl Default for HookManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn create_libc_stubs() -> Vec<(String, HookFn)> {
    vec![
        ("puts".into(), Box::new(|_addr, state| {
            let _ = state.read_register(0x38, 8);
            state.write_register(0x00, 8, 0);
            HookAction::Skip
        })),
        ("printf".into(), Box::new(|_addr, state| {
            let _ = state.read_register(0x38, 8);
            state.write_register(0x00, 8, 0);
            HookAction::Skip
        })),
        ("malloc".into(), Box::new(|_addr, state| {
            let size = state.read_register(0x38, 8);
            state.write_register(0x00, 8, 0x1_0000_0000 + size);
            HookAction::Skip
        })),
        ("free".into(), Box::new(|_addr, _state| {
            HookAction::Skip
        })),
        ("exit".into(), Box::new(|_addr, _state| {
            HookAction::Stop
        })),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::EmulatorState;

    #[test]
    fn hook_manager_basic() {
        let mut mgr = HookManager::new();
        mgr.add_hook(0x1000, Box::new(|_addr, _state| HookAction::Stop));
        assert!(mgr.has_hook(0x1000));
        assert!(!mgr.has_hook(0x2000));
    }

    #[test]
    fn libc_stubs() {
        let stubs = create_libc_stubs();
        assert!(stubs.len() >= 5);
    }

    #[test]
    fn hook_execution() {
        let mut mgr = HookManager::new();
        mgr.add_hook(0x1000, Box::new(|_addr, state| {
            state.write_register(0x00, 8, 42);
            HookAction::Continue
        }));
        let mut state = EmulatorState::new();
        mgr.check(0x1000, &mut state);
        assert_eq!(state.read_register(0x00, 8), 42);
    }
}
