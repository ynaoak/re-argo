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
        let mut shape = InsnShape { address: insn.address, target: 0, flags: 0 };
        for op in &insn.ops {
            shape.add(op);
        }
        shape
    }

    /// The shape with the next op of the instruction, `op`.
    #[inline]
    pub(crate) fn add(&mut self, op: &PcodeOp) {
        use reargo_core::pcode::OpCode;
        match op.opcode {
            OpCode::Call => self.flags |= Self::CALL,
            OpCode::CallInd => self.flags |= Self::CALL | Self::CALLIND,
            OpCode::Branch | OpCode::CBranch => {
                if let Some(t) = Self::branch_target(op) {
                    if self.flags & (Self::TARGET | Self::TARGETS) == 0 {
                        self.flags |= Self::TARGET;
                        self.target = t;
                    } else {
                        self.flags = (self.flags & !Self::TARGET) | Self::TARGETS;
                    }
                }
                self.flags |= Self::ENDS;
                if op.opcode == OpCode::Branch {
                    self.flags |= Self::STOPS;
                }
            }
            OpCode::Return | OpCode::BranchInd => self.flags |= Self::ENDS | Self::STOPS,
            _ => {}
        }
    }
}

/// The [`InsnShape`]s of a range lifted through a [`crate::x86::LiftCache`]
/// ([`crate::x86::X86Lifter::lift_prefixes_cached`]), kept by the cache in
/// arrays by instruction: borrowed from them when the range's instructions
/// are consecutive entries of the cache (a function's lift continuing the
/// lift of the one before it), copied otherwise. The walks over many
/// overlapping lifts read them in place instead of copying each shape.
#[derive(Debug, Clone)]
pub struct RangeShapes<'c> {
    /// Each instruction's address.
    pub addrs: std::borrow::Cow<'c, [u64]>,
    /// Each instruction's [`InsnShape`] flags.
    pub flags: std::borrow::Cow<'c, [u8]>,
    /// The [`InsnShape`] target of each instruction of `special`, in its order (an
    /// instruction without flags has none: 0).
    special_targets: std::borrow::Cow<'c, [u64]>,
    /// The positions plus `base` of the instructions with flags,
    /// ascending (the others have none).
    special: std::borrow::Cow<'c, [u32]>,
    base: u32,
    /// The addresses strictly increase.
    pub increasing: bool,
    /// The cache's index of each address, when borrowed from a cache: the
    /// instruction at an address is found there ([`Self::positions`]).
    index: Option<&'c crate::x86::AddrIndex>,
}

impl<'c> RangeShapes<'c> {
    /// Shapes borrowed from arrays by cache index: the entries
    /// `start..start + n`, `special` the cache indices of those with flags
    /// in that range and `special_targets` their targets.
    /// (a range's instructions follow each other: each address is the one before plus its
    /// length, so they strictly increase unless they wrap around, when the last is below the
    /// first)
    pub(crate) fn borrowed(
        addrs: &'c [u64],
        flags: &'c [u8],
        special_targets: &'c [u64],
        special: &'c [u32],
        start: u32,
        index: &'c crate::x86::AddrIndex,
    ) -> Self {
        use std::borrow::Cow::Borrowed;
        let increasing = chain_increasing(addrs);
        RangeShapes {
            addrs: Borrowed(addrs),
            flags: Borrowed(flags),
            special_targets: Borrowed(special_targets),
            special: Borrowed(special),
            base: start,
            increasing,
            index: Some(index),
        }
    }

    /// Shapes copied out by instruction, of a range (`increasing` as
    /// [`Self::borrowed`] finds it).
    pub(crate) fn owned(addrs: Vec<u64>, flags: Vec<u8>, targets: Vec<u64>) -> RangeShapes<'static> {
        let increasing = chain_increasing(&addrs);
        Self::owned_with(addrs, flags, targets, increasing)
    }

    /// [`Self::owned`] with the targets of the instructions with flags only, in order.
    pub(crate) fn owned_special(addrs: Vec<u64>, flags: Vec<u8>, special_targets: Vec<u64>) -> RangeShapes<'static> {
        let increasing = chain_increasing(&addrs);
        let special = flags.iter().enumerate().filter(|(_, f)| **f != 0).map(|(i, _)| i as u32).collect::<Vec<_>>();
        debug_assert_eq!(special.len(), special_targets.len());
        use std::borrow::Cow::Owned;
        RangeShapes {
            addrs: Owned(addrs),
            flags: Owned(flags),
            special_targets: Owned(special_targets),
            special: Owned(special),
            base: 0,
            increasing,
            index: None,
        }
    }

    fn owned_with(addrs: Vec<u64>, flags: Vec<u8>, targets: Vec<u64>, increasing: bool) -> RangeShapes<'static> {
        let special = flags.iter().enumerate().filter(|(_, f)| **f != 0).map(|(i, _)| i as u32).collect::<Vec<_>>();
        let special_targets = special.iter().map(|&i| targets[i as usize]).collect();
        use std::borrow::Cow::Owned;
        RangeShapes {
            addrs: Owned(addrs),
            flags: Owned(flags),
            special_targets: Owned(special_targets),
            special: Owned(special),
            base: 0,
            increasing,
            index: None,
        }
    }

    /// The shapes of `insns`, read from their ops.
    pub fn of<I: std::borrow::Borrow<LiftedInstruction>>(insns: &[I]) -> RangeShapes<'static> {
        let shapes: Vec<InsnShape> = insns.iter().map(|i| InsnShape::of(i.borrow())).collect();
        let addrs: Vec<u64> = shapes.iter().map(|s| s.address).collect();
        let increasing = addrs.windows(2).all(|w| w[0] < w[1]);
        Self::owned_with(addrs, shapes.iter().map(|s| s.flags).collect(), shapes.iter().map(|s| s.target).collect(), increasing)
    }

    /// How many instructions.
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// The shapes of the first `n` instructions.
    pub fn prefix(&self, n: usize) -> RangeShapes<'_> {
        use std::borrow::Cow::Borrowed;
        let n = n.min(self.len());
        let end = self.base as u64 + n as u64;
        let k = self.special.partition_point(|&p| u64::from(p) < end);
        RangeShapes {
            addrs: Borrowed(&self.addrs[..n]),
            flags: Borrowed(&self.flags[..n]),
            special_targets: Borrowed(&self.special_targets[..k]),
            special: Borrowed(&self.special[..k]),
            base: self.base,
            // (a prefix of an increasing range increases; of one wrapping around, may)
            increasing: self.increasing || chain_increasing(&self.addrs[..n]),
            index: self.index,
        }
    }

    /// The position of each address among the instructions, looked up in the cache's index
    /// of addresses, when the shapes are borrowed from a cache and their addresses
    /// strictly increase (`None` otherwise).
    pub fn positions(&self) -> Option<AddrPositions<'c>> {
        let index = self.index?;
        let (&lo, &hi) = (self.addrs.first()?, self.addrs.last()?);
        self.increasing.then(|| AddrPositions { index, base: self.base, len: self.addrs.len() as u32, lo, hi })
    }

    /// The positions of the instructions with flags (a call, a jump, a
    /// return), ascending.
    pub fn special(&self) -> impl ExactSizeIterator<Item = usize> + DoubleEndedIterator + '_ {
        let base = self.base;
        self.special.iter().map(move |&p| (p - base) as usize)
    }

    /// The [`InsnShape`] of instruction `i` (its target searched among the flagged ones).
    pub fn shape(&self, i: usize) -> InsnShape {
        let target = match self.special.binary_search(&(self.base + i as u32)) {
            Ok(k) => self.special_targets[k],
            Err(_) => 0,
        };
        InsnShape { address: self.addrs[i], target, flags: self.flags[i] }
    }

    /// The positions plus a base of the instructions with flags, ascending, and that base
    /// ([`Self::special`] without the subtraction).
    pub fn special_raw(&self) -> (&[u32], u32) {
        (&self.special, self.base)
    }

    /// The position, [`InsnShape`] flags and target of each instruction with flags,
    /// ascending.
    pub fn special_shapes(&self) -> impl ExactSizeIterator<Item = (usize, u8, u64)> + '_ {
        let base = self.base;
        self.special.iter().zip(self.special_targets.iter()).map(move |(&p, &target)| {
            let i = (p - base) as usize;
            (i, self.flags[i], target)
        })
    }
}

/// The position of each address among the instructions of a [`RangeShapes`] borrowed from a
/// cache ([`RangeShapes::positions`]): the cache's index gives each address held its entry,
/// and the range's instructions are the entries `base..base + len`, so the position of an
/// address is its entry less `base` when that is below `len` (what a binary search of the
/// increasing addresses finds), without searching.
#[derive(Clone, Copy)]
pub struct AddrPositions<'c> {
    index: &'c crate::x86::AddrIndex,
    base: u32,
    len: u32,
    /// The first and last addresses.
    lo: u64,
    hi: u64,
}

impl<'c> AddrPositions<'c> {
    /// A finder of the positions (the index's pages over the range's addresses looked up once).
    pub fn finder(&self) -> PositionFinder<'c> {
        let (first_page, pages) = self.index.pages_over(self.lo, self.hi);
        PositionFinder { at: *self, first_page, pages }
    }
}

/// Looks up positions for [`AddrPositions`]: what `addrs.binary_search(&t).ok()` gives.
pub struct PositionFinder<'c> {
    at: AddrPositions<'c>,
    first_page: u64,
    /// The index's page of each page of addresses from `first_page` (none where it has none).
    pages: Vec<Option<&'c [u32; crate::x86::INDEX_PAGE as usize]>>,
}

impl PositionFinder<'_> {
    /// The position of the instruction at `t`, when one is.
    #[inline]
    pub fn find(&self, t: u64) -> Option<usize> {
        if t < self.at.lo || t > self.at.hi {
            return None;
        }
        let page = self.pages[((t / crate::x86::INDEX_PAGE) - self.first_page) as usize]?;
        // (an entry outside the range, none ([`u32::MAX`]) or an older one wraps past `len`)
        let k = page[(t % crate::x86::INDEX_PAGE) as usize].wrapping_sub(self.at.base);
        (k < self.at.len).then_some(k as usize)
    }
}

/// Whether the addresses of a range's instructions (each the one before plus
/// its length) strictly increase: they do unless they wrap around the address
/// space, and then the last is below the first.
fn chain_increasing(addrs: &[u64]) -> bool {
    match (addrs.first(), addrs.last()) {
        (Some(first), Some(last)) => addrs.len() == 1 || last > first,
        _ => true,
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

    /// Whether the text may start with `pop `: `false` only when the decoded instruction, or
    /// for ARM the encoding, says it does not, without formatting the text.
    pub fn may_be_pop_text(&self) -> bool {
        match &self.src {
            TextSource::Given => true,
            TextSource::X86(i) => i.mnemonic() == iced_x86::Mnemonic::Pop,
            TextSource::Arm { len, thumb, word, .. } => crate::arm32::may_be_pop(*word, *len, *thumb),
        }
    }

    /// Whether the text may be that of a frame-restoring instruction (it may start with `pop `,
    /// `ret`, `add rsp,`, `lea rsp,` or `mov rsp,`, or be `leave` / `vzeroupper`): `false` only
    /// when the decoded instruction, or for ARM the encoding (of those, only a `pop` prints so),
    /// says it is not, without formatting the text.
    pub fn may_be_epilogue_text(&self) -> bool {
        use iced_x86::Mnemonic::*;
        match &self.src {
            TextSource::Given => true,
            TextSource::X86(i) => matches!(i.mnemonic(), Pop | Add | Lea | Mov | Ret | Retf | Leave | Vzeroupper),
            TextSource::Arm { len, thumb, word, .. } => crate::arm32::may_be_pop(*word, *len, *thumb),
        }
    }

    /// Whether the text may start with `jmp`: `false` only when the decoded instruction says it
    /// does not (x86), or it is an ARM / Thumb instruction's (no ARM text starts so), without
    /// formatting the text.
    pub fn may_be_jmp_text(&self) -> bool {
        match &self.src {
            TextSource::Given => true,
            TextSource::X86(i) => matches!(i.mnemonic(), iced_x86::Mnemonic::Jmp | iced_x86::Mnemonic::Jmpe),
            TextSource::Arm { .. } => false,
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

    /// The longest instruction this lifter lifts (the most `length` of a lift), when it is
    /// known: a stream of `n` lifts from `a` then starts its instructions below `a + n * max`.
    fn max_instruction_length(&self) -> Option<u32> {
        None
    }

    /// The `length` of the instruction a successful [`PcodeLift::lift_instruction_ctx`] at
    /// `address` gives (whatever the context; its `address` is the one asked for), when it is
    /// known without the lift: a stream of lifts from `a` then starts its instructions at the
    /// addresses these lengths step through, as far as its lifts succeed. `None`: not known.
    fn instruction_length(&self, _memory: &Memory, _address: u64) -> Option<u32> {
        None
    }

    /// Extend `starts` (its last entry the start of an instruction of a stream) with the starts
    /// of the stream's next instructions by [`PcodeLift::instruction_length`], until it holds
    /// `len` entries or its last is above `until`. `false` when a length is not known at its
    /// last entry (it is then not extended past it).
    fn extend_instruction_starts(&self, memory: &Memory, starts: &mut Vec<u64>, len: usize, until: u64) -> bool {
        while starts.len() < len {
            let Some(&a) = starts.last() else { return false };
            if a > until {
                break;
            }
            match self.instruction_length(memory, a).filter(|&l| l > 0).and_then(|l| a.checked_add(u64::from(l))) {
                Some(b) => starts.push(b),
                None => return false,
            }
        }
        true
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
