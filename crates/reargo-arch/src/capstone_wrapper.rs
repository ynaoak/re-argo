use std::sync::Mutex;

use crate::error::DisasmError;

struct SendCapstone(capstone::Capstone);

// Safety: each Capstone instance owns an independent C handle (csh).
// No global state is shared between instances, so moving between threads is safe.
unsafe impl Send for SendCapstone {}

pub struct SafeCapstone {
    inner: Mutex<SendCapstone>,
    /// Builds another instance configured as `inner`, for a thread that
    /// finds `inner` in use ([`Self::with_builder`]); without, it waits.
    build: Option<fn() -> Option<capstone::Capstone>>,
    /// The instances built so far and not in use.
    spare: Mutex<Vec<SendCapstone>>,
}

impl SafeCapstone {
    pub fn new(cs: capstone::Capstone) -> Self {
        Self { inner: Mutex::new(SendCapstone(cs)), build: None, spare: Mutex::new(Vec::new()) }
    }

    /// Like [`Self::new`], with `build` making more instances configured
    /// the same (each decode is a pure function of the bytes, address and
    /// configuration): threads decoding at the same time each use their
    /// own instead of waiting for one.
    pub fn with_builder(cs: capstone::Capstone, build: fn() -> Option<capstone::Capstone>) -> Self {
        Self { inner: Mutex::new(SendCapstone(cs)), build: Some(build), spare: Mutex::new(Vec::new()) }
    }

    fn disasm_with(
        cs: &capstone::Capstone,
        code: &[u8],
        addr: u64,
        count: usize,
    ) -> Result<capstone::Instructions<'static>, DisasmError> {
        let insns = cs.disasm_count(code, addr, count).map_err(|e| DisasmError::EngineError(e.to_string()))?;
        // Safety: as in `disasm_count`: the decoded instructions are their
        // own allocation, freed without the handle.
        Ok(unsafe { std::mem::transmute::<capstone::Instructions<'_>, capstone::Instructions<'static>>(insns) })
    }

    pub fn disasm_count(
        &self,
        code: &[u8],
        addr: u64,
        count: usize,
    ) -> Result<capstone::Instructions<'_>, DisasmError> {
        if let Some(build) = self.build {
            let guard = match self.inner.try_lock() {
                Ok(g) => Some(g),
                Err(std::sync::TryLockError::WouldBlock) => None,
                Err(std::sync::TryLockError::Poisoned(_)) => panic!("capstone mutex poisoned"),
            };
            if let Some(guard) = guard {
                return Self::disasm_with(&guard.0, code, addr, count);
            }
            let spare = self.spare.lock().expect("capstone mutex poisoned").pop();
            let cs = match spare {
                Some(cs) => cs,
                None => SendCapstone(
                    build().ok_or_else(|| DisasmError::EngineError("capstone init failed".into()))?,
                ),
            };
            let r = Self::disasm_with(&cs.0, code, addr, count);
            self.spare.lock().expect("capstone mutex poisoned").push(cs);
            return r;
        }
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
