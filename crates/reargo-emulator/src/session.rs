use crate::breakpoint::BreakpointManager;
use crate::emulator::Emulator;
use crate::trace::TraceLog;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Running,
    Stopped,
    Breakpoint(u64),
    Exited(u64),
    Error,
}

pub struct DebugSession {
    pub emulator: Emulator,
    pub breakpoints: BreakpointManager,
    pub trace: TraceLog,
    pub state: SessionState,
    pub current_address: u64,
    pub step_count: u64,
}

impl DebugSession {
    pub fn new() -> Self {
        Self {
            emulator: Emulator::new(),
            breakpoints: BreakpointManager::new(),
            trace: TraceLog::new(10000),
            state: SessionState::Idle,
            current_address: 0,
            step_count: 0,
        }
    }

    pub fn set_entry(&mut self, address: u64) {
        self.current_address = address;
        self.state = SessionState::Stopped;
    }

    pub fn add_breakpoint(&mut self, address: u64) -> u32 {
        self.breakpoints.add(address)
    }

    pub fn remove_breakpoint(&mut self, id: u32) -> bool {
        self.breakpoints.remove(id)
    }

    pub fn is_running(&self) -> bool {
        self.state == SessionState::Running
    }

    pub fn is_stopped(&self) -> bool {
        matches!(self.state, SessionState::Stopped | SessionState::Breakpoint(_))
    }

    pub fn register_dump(&self) -> Vec<(String, u64)> {
        self.emulator.state.dump_registers()
    }

    pub fn read_memory(&self, address: u64, size: u32) -> u64 {
        self.emulator.state.read_memory(address, size)
    }

    pub fn write_memory(&mut self, address: u64, size: u32, value: u64) {
        self.emulator.state.write_memory(address, size, value);
    }

    pub fn backtrace(&self) -> Vec<u64> {
        let rsp = self.emulator.state.read_register(0x20, 8);
        let mut frames = vec![self.current_address];
        for i in 0..16u64 {
            let ret_addr = self.emulator.state.read_memory(rsp + i * 8, 8);
            if ret_addr > 0x1000 && ret_addr < 0x7FFF_FFFF_FFFF {
                frames.push(ret_addr);
            }
        }
        frames
    }
}

impl Default for DebugSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lifecycle() {
        let mut session = DebugSession::new();
        assert_eq!(session.state, SessionState::Idle);
        session.set_entry(0x1000);
        assert!(session.is_stopped());
        assert_eq!(session.current_address, 0x1000);
    }

    #[test]
    fn session_breakpoints() {
        let mut session = DebugSession::new();
        let id = session.add_breakpoint(0x2000);
        assert!(session.breakpoints.check(0x2000));
        assert!(session.remove_breakpoint(id));
    }

    #[test]
    fn session_memory() {
        let mut session = DebugSession::new();
        session.write_memory(0x1000, 4, 0xDEADBEEF);
        assert_eq!(session.read_memory(0x1000, 4), 0xDEADBEEF);
    }
}
