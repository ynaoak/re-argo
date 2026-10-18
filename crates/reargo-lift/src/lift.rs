use reargo_core::pcode::PcodeOp;
use reargo_loader::Memory;

#[derive(Debug, Clone)]
pub struct LiftedInstruction {
    pub address: u64,
    pub length: u32,
    /// The instruction's text (x86: Intel syntax with its operands), read as a `&str`.
    pub mnemonic: InsnText,
    pub ops: Vec<PcodeOp>,
}

/// What the block structure of a lift reads of one instruction's P-code
/// (its address, calls, jumps and their targets), read once: a pass
/// that lifts each address once keeps it beside the lift, and the walks
/// over many overlapping lifts read it instead of every op again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InsnShape {
    pub address: u64,
    /// The jump target when [`InsnShape::TARGET`] is set.
    pub target: u64,
    pub flags: u8,
}

impl InsnShape {
    /// It has a `Call` / `CallInd` op.
    pub const CALL: u8 = 1;
    /// It has a `Branch`, `CBranch`, `Return` or `BranchInd` op (it ends
    /// its block).
    pub const ENDS: u8 = 2;
    /// It has a `Branch`, `Return` or `BranchInd` op (no fall-through).
    pub const STOPS: u8 = 4;
    /// It has exactly one `Branch` / `CBranch` with a target in the RAM
    /// space ([`InsnShape::branch_target`]): `target`.
    pub const TARGET: u8 = 8;
    /// It has several: read them from the ops.
    pub const TARGETS: u8 = 16;
    /// It has a `CallInd` op.
    pub const CALLIND: u8 = 32;

    /// The jump target of a `Branch` / `CBranch` op, when it is an
    /// address in the RAM space.
    pub fn branch_target(op: &PcodeOp) -> Option<u64> {
        op.inputs.first().filter(|t| t.space == reargo_core::address::SpaceId::RAM).map(|t| t.offset)
    }

    pub fn of(insn: &LiftedInstruction) -> InsnShape {
        use reargo_core::pcode::OpCode;
        let mut shape = InsnShape { address: insn.address, target: 0, flags: 0 };
        for op in &insn.ops {
            match op.opcode {
                OpCode::Call => shape.flags |= Self::CALL,
                OpCode::CallInd => shape.flags |= Self::CALL | Self::CALLIND,
                OpCode::Branch | OpCode::CBranch => {
                    if let Some(t) = Self::branch_target(op) {
                        if shape.flags & (Self::TARGET | Self::TARGETS) == 0 {
                            shape.flags |= Self::TARGET;
                            shape.target = t;
                        } else {
                            shape.flags = (shape.flags & !Self::TARGET) | Self::TARGETS;
                        }
                    }
                    shape.flags |= Self::ENDS;
                    if op.opcode == OpCode::Branch {
                        shape.flags |= Self::STOPS;
                    }
                }
                OpCode::Return | OpCode::BranchInd => shape.flags |= Self::ENDS | Self::STOPS,
                _ => {}
            }
        }
        shape
    }
}

/// The text of a [`LiftedInstruction`]: given, or for x86 formatted from the
/// decoded instruction when it is first read — the analysis passes lift far
/// more than they print, and formatting was a large part of each lift.
/// Reads as a `str` (`Deref`), so `l.mnemonic.starts_with("pop ")` works as on
/// a `String`.
#[derive(Clone)]
pub struct InsnText {
    cell: std::sync::OnceLock<String>,
    src: TextSource,
}

/// What an [`InsnText`] not given is formatted from.
#[derive(Clone)]
enum TextSource {
    Given,
    X86(iced_x86::Instruction),
    /// An ARM / Thumb instruction's bytes (as read from memory, `len` of them) at `address`,
    /// formatted by Capstone ([`crate::arm32::format_text`]).
    Arm { bytes: [u8; 4], len: u8, thumb: bool, word: u32, address: u64 },
}

impl InsnText {
    /// The text of `insn`, formatted when first read.
    pub fn x86_lazy(insn: iced_x86::Instruction) -> Self {
        Self { cell: std::sync::OnceLock::new(), src: TextSource::X86(insn) }
    }

    /// The text of the ARM (`thumb`: Thumb) instruction `bytes[..len]` (read as `word`) at
    /// `address`, formatted when first read.
    pub(crate) fn arm_lazy(bytes: [u8; 4], len: u8, thumb: bool, word: u32, address: u64) -> Self {
        Self { cell: std::sync::OnceLock::new(), src: TextSource::Arm { bytes, len, thumb, word, address } }
    }

    /// The decoded x86 instruction the text is formatted from, if any.
    pub fn x86_instruction(&self) -> Option<&iced_x86::Instruction> {
        match &self.src {
            TextSource::X86(i) => Some(i),
            _ => None,
        }
    }

    /// Whether the text may start with `ud2` or `hlt` (the trap instructions' texts): `false`
    /// only when the decoded instruction, or for ARM the encoding, says it does not, without
    /// formatting the text.
    pub fn may_be_trap_text(&self) -> bool {
        match &self.src {
            TextSource::Given => true,
            TextSource::X86(i) => matches!(i.mnemonic(), iced_x86::Mnemonic::Ud2 | iced_x86::Mnemonic::Hlt),
            TextSource::Arm { len, thumb, word, .. } => crate::arm32::may_be_hlt(*word, *len, *thumb),
        }
    }

    pub fn as_str(&self) -> &str {
        self.cell.get_or_init(|| match &self.src {
            TextSource::Given => String::new(),
            TextSource::X86(i) => crate::x86::format_instruction(i),
            TextSource::Arm { bytes, len, thumb, word, address } => crate::arm32::format_text(&bytes[..usize::from(*len)], *thumb, *word, *address),
        })
    }
}

impl From<String> for InsnText {
    fn from(text: String) -> Self {
        let cell = std::sync::OnceLock::new();
        let _ = cell.set(text);
        Self { cell, src: TextSource::Given }
    }
}

impl From<&str> for InsnText {
    fn from(text: &str) -> Self {
        Self::from(text.to_string())
    }
}

impl std::ops::Deref for InsnText {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for InsnText {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for InsnText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.as_str(), f)
    }
}

impl std::fmt::Debug for InsnText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl PartialEq<str> for InsnText {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for InsnText {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
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

/// The registers a call passes arguments in and returns its result in, for the
/// decompiler (which otherwise sees a call as reading and writing nothing).
/// Each register is given at its widest view; the lifter keeps the narrower
/// views coherent with it.
#[derive(Debug, Clone)]
pub struct CallConvention {
    /// Argument registers in parameter order (integer class first, then float).
    pub args: Vec<reargo_core::pcode::VarnodeData>,
    /// Registers a call defines on return, each followed by the narrower views to refresh
    /// from it (`(full, [views])`).
    pub returns: Vec<(reargo_core::pcode::VarnodeData, Vec<u32>)>,
    /// Caller-saved registers that do not carry the result: after a call they hold nothing the
    /// caller set (`(full, [views])`, like `returns`).
    pub clobbers: Vec<(reargo_core::pcode::VarnodeData, Vec<u32>)>,
}

pub trait PcodeLift: Send + Sync {
    /// The calling convention calls follow, if the lifter knows it (x86-64: System V).
    fn call_convention(&self) -> Option<CallConvention> {
        None
    }

    /// This lifter as the x86 lifter, when it is one: its
    /// [`crate::x86::X86Lifter::lift_range_cached`] gives exactly what its
    /// `lift_range` does, sharing the lifts of overlapping ranges.
    fn as_x86(&self) -> Option<&crate::x86::X86Lifter> {
        None
    }

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

#[cfg(test)]
mod size_tests {
    /// The lazily formatted ARM text shares the room of the x86 instruction: a lift stays
    /// 112 bytes.
    #[test]
    fn lifted_instruction_size() {
        assert_eq!(std::mem::size_of::<super::LiftedInstruction>(), 112);
    }
}
