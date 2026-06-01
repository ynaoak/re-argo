use std::collections::BTreeMap;

use crate::state::EmulatorState;

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: u32,
    pub address: u64,
    pub enabled: bool,
    pub hit_count: u64,
    pub condition: Option<BreakCondition>,
}

#[derive(Debug, Clone)]
pub enum BreakCondition {
    HitCount(u64),
    RegisterEquals { offset: u64, value: u64 },
}

impl Breakpoint {
    pub fn new(id: u32, address: u64) -> Self {
        Self {
            id,
            address,
            enabled: true,
            hit_count: 0,
            condition: None,
        }
    }

    pub fn with_condition(mut self, condition: BreakCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    /// `state` is consulted only by conditions that need to inspect the
    /// emulator (e.g. `RegisterEquals`). Other conditions ignore it,
    /// so callers without a state can pass `None` and still get
    /// HitCount semantics.
    pub fn should_break(&self, state: Option<&EmulatorState>) -> bool {
        if !self.enabled {
            return false;
        }
        match &self.condition {
            None => true,
            Some(BreakCondition::HitCount(n)) => self.hit_count >= *n,
            Some(BreakCondition::RegisterEquals { offset, value }) => {
                // Pre-fix this arm just returned `true`, so a
                // RegisterEquals breakpoint fired on every hit
                // regardless of the register's actual value. Now
                // read the register at the given offset (8 bytes,
                // since that's the canonical size on the supported
                // host architectures) and gate the break on equality.
                state.is_some_and(|s| s.read_register(*offset, 8) == *value)
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct BreakpointManager {
    breakpoints: BTreeMap<u64, Vec<Breakpoint>>,
    next_id: u32,
}

impl BreakpointManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, address: u64) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints
            .entry(address)
            .or_default()
            .push(Breakpoint::new(id, address));
        id
    }

    pub fn add_conditional(&mut self, address: u64, condition: BreakCondition) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints
            .entry(address)
            .or_default()
            .push(Breakpoint::new(id, address).with_condition(condition));
        id
    }

    pub fn remove(&mut self, id: u32) -> bool {
        for bps in self.breakpoints.values_mut() {
            if let Some(pos) = bps.iter().position(|b| b.id == id) {
                bps.remove(pos);
                return true;
            }
        }
        false
    }

    pub fn enable(&mut self, id: u32, enabled: bool) {
        for bps in self.breakpoints.values_mut() {
            for bp in bps.iter_mut() {
                if bp.id == id {
                    bp.enabled = enabled;
                    return;
                }
            }
        }
    }

    pub fn check(&mut self, address: u64) -> bool {
        self.check_with_state(address, None)
    }

    /// Like `check` but consults `state` so condition variants that
    /// need to look at registers (e.g. `RegisterEquals`) can actually
    /// fire. Pass `None` when no state is available and the
    /// register-equality breakpoints will never trigger.
    pub fn check_with_state(&mut self, address: u64, state: Option<&EmulatorState>) -> bool {
        if let Some(bps) = self.breakpoints.get_mut(&address) {
            for bp in bps.iter_mut() {
                bp.hit_count += 1;
                if bp.should_break(state) {
                    return true;
                }
            }
        }
        false
    }

    pub fn list(&self) -> Vec<&Breakpoint> {
        self.breakpoints.values().flat_map(|v| v.iter()).collect()
    }

    pub fn clear(&mut self) {
        self.breakpoints.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_check() {
        let mut mgr = BreakpointManager::new();
        mgr.add(0x1000);
        assert!(mgr.check(0x1000));
        assert!(!mgr.check(0x2000));
    }

    #[test]
    fn enable_disable() {
        let mut mgr = BreakpointManager::new();
        let id = mgr.add(0x1000);
        mgr.enable(id, false);
        assert!(!mgr.check(0x1000));
        mgr.enable(id, true);
        assert!(mgr.check(0x1000));
    }

    #[test]
    fn remove_breakpoint() {
        let mut mgr = BreakpointManager::new();
        let id = mgr.add(0x1000);
        assert!(mgr.remove(id));
        assert!(!mgr.check(0x1000));
    }

    #[test]
    fn hit_count_condition() {
        let mut mgr = BreakpointManager::new();
        mgr.add_conditional(0x1000, BreakCondition::HitCount(3));
        assert!(!mgr.check(0x1000));
        assert!(!mgr.check(0x1000));
        assert!(mgr.check(0x1000));
    }

    /// RegisterEquals must actually consult the register, not break
    /// unconditionally. Pre-fix `should_break` returned `true` for any
    /// RegisterEquals condition, so the breakpoint always fired.
    #[test]
    fn register_equals_condition_only_breaks_on_match() {
        let mut mgr = BreakpointManager::new();
        // Break only when rax (offset 0x00) holds 0x42.
        mgr.add_conditional(0x1000, BreakCondition::RegisterEquals { offset: 0x00, value: 0x42 });

        let mut state = EmulatorState::new();
        state.write_register(0x00, 8, 0x10);
        assert!(!mgr.check_with_state(0x1000, Some(&state)),
            "rax = 0x10 -> must not break: condition value is 0x42");

        state.write_register(0x00, 8, 0x42);
        assert!(mgr.check_with_state(0x1000, Some(&state)),
            "rax = 0x42 -> must break");
    }

    /// Without state, RegisterEquals never fires (defensive default
    /// rather than breaking on every hit).
    #[test]
    fn register_equals_without_state_does_not_fire() {
        let mut mgr = BreakpointManager::new();
        mgr.add_conditional(0x1000, BreakCondition::RegisterEquals { offset: 0x00, value: 0x42 });
        assert!(!mgr.check(0x1000));
    }
}
