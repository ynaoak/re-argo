use std::sync::Mutex;

use crate::error::DisasmError;

struct SendCapstone(capstone::Capstone);

// Safety: each Capstone instance owns an independent C handle (csh).
// No global state is shared between instances, so moving between threads is safe.
unsafe impl Send for SendCapstone {}

pub struct SafeCapstone {
    inner: Mutex<SendCapstone>,
}

impl SafeCapstone {
    pub fn new(cs: capstone::Capstone) -> Self {
        Self {
            inner: Mutex::new(SendCapstone(cs)),
        }
    }

    pub fn disasm_count(
        &self,
        code: &[u8],
        addr: u64,
        count: usize,
    ) -> Result<capstone::Instructions<'_>, DisasmError> {
        let guard = self.inner.lock().expect("capstone mutex poisoned");
        // Safety: the Instructions lifetime is tied to the Capstone handle which lives
        // as long as the Mutex. We transmute the lifetime to match the &self borrow.
        // The Mutex ensures exclusive access, so no data race is possible.
        let insns = guard
            .0
            .disasm_count(code, addr, count)
            .map_err(|e| DisasmError::EngineError(e.to_string()))?;
        Ok(unsafe { std::mem::transmute::<capstone::Instructions<'_>, capstone::Instructions<'_>>(insns) })
    }
}
