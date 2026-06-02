use gr_core::pcode::PcodeOp;
use gr_loader::Memory;

#[derive(Debug, Clone)]
pub struct LiftedInstruction {
    pub address: u64,
    pub length: u32,
    pub mnemonic: String,
    pub ops: Vec<PcodeOp>,
}

impl LiftedInstruction {
    pub fn display_pcode(&self) -> String {
        let mut out = format!("-- 0x{:08x}: {} ({}B)\n", self.address, self.mnemonic, self.length);
        for op in &self.ops {
            out.push_str(&format!("   {}\n", op));
        }
        out
    }
}

impl std::fmt::Display for LiftedInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x} [{:>2} ops] {}", self.address, self.ops.len(), self.mnemonic)
    }
}

pub trait PcodeLift: Send + Sync {
    fn lift_instruction(
        &self,
        memory: &Memory,
        address: u64,
    ) -> Result<LiftedInstruction, LiftError>;

    /// Context-aware lift. The default ignores `ctx` and calls
    /// [`PcodeLift::lift_instruction`]. Lifters with cross-instruction decode
    /// state (e.g. ARM Thumb IT blocks) override this; consumers lifting a
    /// contiguous stream should call it with a `LiftContext` persisted across
    /// the stream.
    fn lift_instruction_ctx(
        &self,
        memory: &Memory,
        address: u64,
        _ctx: &mut LiftContext,
    ) -> Result<LiftedInstruction, LiftError> {
        self.lift_instruction(memory, address)
    }

    fn lift_range(
        &self,
        memory: &Memory,
        start: u64,
        count: usize,
    ) -> Result<Vec<LiftedInstruction>, LiftError> {
        // Pre-size the result Vec to the requested count. The caller's
        // `count` is an upper bound on the number of instructions
        // returned (we may stop early on a decode error), so this
        // either lands exactly or slightly overshoots -- both cheap
        // and both better than the default Vec growth schedule, which
        // would re-allocate O(log count) times as the lift filled it.
        let mut results = Vec::with_capacity(count);
        let mut addr = start;
        let mut ctx = LiftContext::default();
        for _ in 0..count {
            match self.lift_instruction_ctx(memory, addr, &mut ctx) {
                Ok(lifted) => {
                    addr += lifted.length as u64;
                    results.push(lifted);
                }
                Err(_) => break,
            }
        }
        Ok(results)
    }
}

/// Cross-instruction decode state threaded through a contiguous lift. Reset at
/// the start of each independent instruction stream. Carries the ARM Thumb
/// IT-block state and a pending SPARC delay-slot control transfer; the
/// per-instruction lifter validates each against the expected address so
/// random-access lifting never misapplies stale state.
#[derive(Debug, Default, Clone)]
pub struct LiftContext {
    pub it: Option<ItBlock>,
    pub delay: Option<DelaySlot>,
}

/// A control-transfer P-code op deferred to the following (delay-slot)
/// instruction, used to model SPARC's branch delay slots: the transfer is
/// appended after the delay-slot instruction's own effects.
#[derive(Debug, Clone)]
pub struct DelaySlot {
    /// The control-transfer op to emit after the delay-slot instruction.
    pub op: PcodeOp,
    /// Address of the delay-slot instruction this transfer follows.
    pub addr: u64,
    /// For an annulling conditional branch the delay slot executes only when
    /// the branch is taken, so its register writes are predicated on the
    /// branch condition (`op.inputs[1]`).
    pub annul: bool,
}

/// ARM Thumb IT (If-Then) block state.
#[derive(Debug, Clone, Copy)]
pub struct ItBlock {
    /// 8-bit ITSTATE (`firstcond:mask`), advanced after each guarded instruction.
    pub state: u8,
    /// Address the current `state` applies to.
    pub addr: u64,
}

impl ItBlock {
    /// The condition code (0-15) guarding the current instruction.
    pub fn current_cond(&self) -> u32 {
        (self.state >> 4) as u32 & 0xF
    }

    /// Whether an instruction is still being guarded (mask not exhausted).
    pub fn active(&self) -> bool {
        self.state & 0x0F != 0
    }

    /// Advance ITSTATE after a guarded instruction. Returns the next state, or
    /// `None` when the block has ended.
    pub fn advanced(self) -> Option<u8> {
        if self.state & 0x07 == 0 {
            None
        } else {
            Some((self.state & 0xE0) | ((self.state << 1) & 0x1F))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LiftError {
    #[error("cannot read at 0x{0:x}")]
    UnreadableAddress(u64),
    #[error("decode failed at 0x{address:x}: {reason}")]
    DecodeFailed { address: u64, reason: String },
    #[error("unsupported instruction at 0x{address:x}: {mnemonic}")]
    Unsupported { address: u64, mnemonic: String },
}
