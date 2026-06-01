use crate::session::{DebugSession, SessionState};

pub struct ProcessEmulator {
    pub session: DebugSession,
    pub exit_code: Option<i32>,
    pub arguments: Vec<String>,
    pub environment: Vec<(String, String)>,
}

impl ProcessEmulator {
    pub fn new() -> Self {
        Self {
            session: DebugSession::new(),
            exit_code: None,
            arguments: Vec::new(),
            environment: Vec::new(),
        }
    }

    pub fn set_args(&mut self, args: Vec<String>) {
        self.arguments = args;
    }

    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.environment.push((key.into(), value.into()));
    }

    pub fn load_binary(&mut self, data: &[u8], base: u64, entry: u64) {
        self.session.emulator.state.load_memory_bytes(base, data);
        self.session.set_entry(entry);
        self.session.emulator.state.write_register(0x20, 8, 0x7FFF_FFFF_FFF0);
    }

    pub fn step(&mut self) -> StepResult {
        if !self.session.is_stopped() {
            return StepResult::Error("not stopped".into());
        }
        self.session.state = SessionState::Running;
        let addr = self.session.current_address;

        if self.session.breakpoints.check_with_state(addr, Some(&self.session.emulator.state)) {
            self.session.state = SessionState::Breakpoint(addr);
            return StepResult::Breakpoint(addr);
        }

        self.session.step_count += 1;
        self.session.state = SessionState::Stopped;
        StepResult::Ok(addr)
    }

    pub fn continue_until(&mut self, max_steps: u64) -> StepResult {
        for _ in 0..max_steps {
            match self.step() {
                StepResult::Ok(_) => {}
                other => return other,
            }
        }
        StepResult::MaxSteps
    }

    pub fn is_exited(&self) -> bool {
        matches!(self.session.state, SessionState::Exited(_))
    }
}

impl Default for ProcessEmulator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum StepResult {
    Ok(u64),
    Breakpoint(u64),
    Exit(i32),
    MaxSteps,
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_emulator_basic() {
        let mut proc = ProcessEmulator::new();
        proc.load_binary(&[0x90; 16], 0x1000, 0x1000);
        assert!(proc.session.is_stopped());
        assert_eq!(proc.session.current_address, 0x1000);
    }

    #[test]
    fn process_args_env() {
        let mut proc = ProcessEmulator::new();
        proc.set_args(vec!["./test".into(), "--flag".into()]);
        proc.set_env("PATH", "/usr/bin");
        assert_eq!(proc.arguments.len(), 2);
        assert_eq!(proc.environment.len(), 1);
    }
}
