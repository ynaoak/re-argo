//! Calls that never return (WS81).
//!
//! A call to `_Unwind_Resume`, `abort`, `__cxa_throw`, … does not come back, so the code
//! after it is not its continuation: compilers put the next block (a landing pad, a cold
//! path, or the next function) right behind it. Taken as a fall-through, that edge glues
//! unrelated code into the function and makes bogus joins for the structurer.
//!
//! [`NoReturn`] answers "does the function at `target` never return?":
//! * by name, for imports whose contract is `noreturn` ([`NORETURN_NAMES`], exact match of the
//!   symbol without its `@plt` / `@GLIBC_…` suffix);
//! * by its code: lifted from `target`, no path from the entry reaches a `ret`, an indirect
//!   jump, a tail jump to a function that returns, or the end of what was lifted — every path
//!   ends in a trap (`int3` / `ud2` / `hlt`) or in a call to a function that never returns
//!   (decided the same way, depth-limited). An unknown answer counts as "returns", so a
//!   mistake can only leave a fall-through in, never cut real code out.
//!
//! The search is a 0-1 BFS over the instructions where passing a call costs 1: an exit
//! reachable with fewer calls is found first, and only the calls in front of it are looked
//! into. Results are cached per function.
//!
//! [`mark_noreturn_calls`] appends a [`NORETURN_MARK`] op to each such call instruction;
//! [`crate::cfg::is_trap`] treats it like a trap (control does not fall through) and the
//! emitters print nothing for it.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use reargo_core::address::{Address, SpaceId};
use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_loader::Memory;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

/// `CALLOTHER` tag of the marker appended to a call that never returns.
pub const NORETURN_MARK: u64 = reargo_core::pcode::intrinsic::NORETURN;

/// Imports that never return (C, C++ runtime, unwinder).
pub const NORETURN_NAMES: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "pthread_exit",
    "thrd_exit",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "err",
    "errx",
    "verr",
    "verrx",
    "__stack_chk_fail",
    "__fortify_fail",
    "__chk_fail",
    "__assert_fail",
    "__assert_perror_fail",
    "__assert_rtn",
    "__libc_fatal",
    "_Unwind_Resume",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_pure_virtual",
    "__cxa_deleted_virtual",
    "__cxa_call_unexpected",
    "__cxa_throw_bad_array_new_length",
    "_ZSt9terminatev",
    "std::terminate()",
    "_ZSt17__throw_bad_allocv",
    "_ZSt20__throw_length_errorPKc",
    "_ZSt20__throw_out_of_rangePKc",
    "_ZSt24__throw_out_of_range_fmtPKcz",
    "_ZSt19__throw_logic_errorPKc",
    "_ZSt20__throw_bad_array_new_lengthv",
    "_ZSt25__throw_bad_function_callv",
    "_ZSt16__throw_bad_castv",
    "_ZSt21__throw_runtime_errorPKc",
    "_ZSt20__throw_system_errori",
    "_ZSt24__throw_invalid_argumentPKc",
];

/// Is `name` (a symbol, possibly `foo@plt` / `foo@GLIBC_2.2.5`) a function that never returns?
pub fn is_noreturn_name(name: &str) -> bool {
    let base = name.split('@').next().unwrap_or(name);
    NORETURN_NAMES.contains(&base)
}

/// Instructions lifted per function looked into.
const MAX_INSNS: usize = 512;
/// Call levels followed below the function asked about.
const MAX_DEPTH: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    NoReturn,
    Returns,
    /// The search was cut short (depth limit, recursion): treated as "returns".
    Unsure,
}

/// "Does this function never return?" with a cache shared by every lookup.
pub struct NoReturn<'a> {
    lifter: &'a dyn PcodeLift,
    memory: &'a Memory,
    symbols: Option<&'a BTreeMap<u64, String>>,
    /// target -> verdict (and, for `Unsure`, the depth it was computed with)
    memo: Mutex<FxHashMap<u64, (Verdict, u32)>>,
}

impl<'a> NoReturn<'a> {
    pub fn new(lifter: &'a dyn PcodeLift, memory: &'a Memory, symbols: Option<&'a BTreeMap<u64, String>>) -> Self {
        Self { lifter, memory, symbols, memo: Mutex::new(FxHashMap::default()) }
    }

    /// Does the function at `target` never return?
    pub fn is_noreturn(&self, target: u64) -> bool {
        self.verdict(target, MAX_DEPTH, &mut Vec::new()) == Verdict::NoReturn
    }

    fn named(&self, target: u64) -> bool {
        self.symbols.and_then(|s| s.get(&target)).is_some_and(|n| is_noreturn_name(n))
    }

    fn verdict(&self, target: u64, depth: u32, stack: &mut Vec<u64>) -> Verdict {
        if self.named(target) {
            return Verdict::NoReturn;
        }
        if let Some(&(v, d)) = self.memo.lock().ok().and_then(|m| m.get(&target).copied()).as_ref()
            && (v != Verdict::Unsure || d >= depth)
        {
            return v;
        }
        if depth == 0 || stack.contains(&target) {
            return Verdict::Unsure;
        }
        stack.push(target);
        let v = self.analyze(target, depth, stack);
        stack.pop();
        if let Ok(mut m) = self.memo.lock() {
            m.insert(target, (v, depth));
        }
        v
    }

    fn analyze(&self, target: u64, depth: u32, stack: &mut Vec<u64>) -> Verdict {
        let Ok(insns) = self.lifter.lift_range(self.memory, target, MAX_INSNS) else {
            return Verdict::Returns;
        };
        if insns.first().map(|i| i.address) != Some(target) {
            return Verdict::Returns;
        }
        let mut unsure = false;
        let exit = search(&insns, |t, s: &mut Vec<u64>| {
            match self.verdict(t, depth - 1, s) {
                Verdict::NoReturn => true,
                Verdict::Returns => false,
                Verdict::Unsure => {
                    unsure = true;
                    false
                }
            }
        }, stack);
        match (exit, unsure) {
            (false, _) => Verdict::NoReturn,
            (true, false) => Verdict::Returns,
            (true, true) => Verdict::Unsure,
        }
    }
}

enum Item {
    Insn(usize),
    /// A direct call (`fall` = the instruction after it) or, with `tail`, a jump out of the
    /// lifted code.
    Call { target: u64, fall: Option<usize>, tail: bool },
}

/// Can control leave the function (see the module doc) from `insns[0]`? `stops(t)` answers
/// whether a call to `t` never returns.
fn search(
    insns: &[LiftedInstruction],
    mut stops: impl FnMut(u64, &mut Vec<u64>) -> bool,
    stack: &mut Vec<u64>,
) -> bool {
    let index: FxHashMap<u64, usize> = insns.iter().enumerate().map(|(i, x)| (x.address, i)).collect();
    let mut seen = vec![false; insns.len()];
    let mut queue: VecDeque<Item> = VecDeque::from([Item::Insn(0)]);
    while let Some(item) = queue.pop_front() {
        let i = match item {
            Item::Insn(i) => i,
            Item::Call { target, fall, tail } => {
                if stops(target, stack) {
                    continue;
                }
                match (tail, fall) {
                    (false, Some(f)) => {
                        queue.push_front(Item::Insn(f));
                        continue;
                    }
                    _ => return true,
                }
            }
        };
        if std::mem::replace(&mut seen[i], true) {
            continue;
        }
        let insn = &insns[i];
        if crate::cfg::is_trap(insn) {
            continue;
        }
        let fall = index.get(&(insn.address + insn.length as u64)).copied();
        let ram = |op: &PcodeOp| op.inputs.first().filter(|t| t.space == SpaceId::RAM).map(|t| t.offset);
        let mut falls = true;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Return | OpCode::BranchInd => return true,
                OpCode::Branch | OpCode::CBranch => {
                    if op.opcode == OpCode::Branch {
                        falls = false;
                    }
                    match ram(op) {
                        Some(t) => match index.get(&t) {
                            Some(&j) => queue.push_front(Item::Insn(j)),
                            None => queue.push_back(Item::Call { target: t, fall: None, tail: true }),
                        },
                        // a branch inside the instruction's own p-code (rep, cmov): carry on
                        None => {}
                    }
                }
                OpCode::Call => {
                    if let Some(t) = ram(op) {
                        queue.push_back(Item::Call { target: t, fall, tail: false });
                        falls = false;
                    }
                }
                _ => {}
            }
        }
        if falls {
            match fall {
                Some(f) => queue.push_front(Item::Insn(f)),
                None => return true,
            }
        }
    }
    false
}

/// Append a [`NORETURN_MARK`] op to every direct call in `insns` whose callee never returns.
/// Returns how many calls were marked.
pub fn mark_noreturn_calls(insns: &mut [LiftedInstruction], oracle: &NoReturn<'_>) -> usize {
    let mut marked = 0;
    for insn in insns.iter_mut() {
        if crate::cfg::is_trap(insn) {
            continue;
        }
        let target = insn
            .ops
            .iter()
            .find(|op| op.opcode == OpCode::Call)
            .and_then(|op| op.inputs.first())
            .filter(|t| t.space == SpaceId::RAM)
            .map(|t| t.offset);
        if let Some(t) = target
            && oracle.is_noreturn(t)
        {
            insn.ops.push(marker(insn.address, insn.ops.len() as u32));
            marked += 1;
        }
    }
    marked
}

fn marker(addr: u64, seq: u32) -> PcodeOp {
    PcodeOp {
        opcode: OpCode::CallOther,
        seq: SeqNum::new(Address::new(SpaceId::RAM, addr), seq),
        output: None,
        inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId::CONST, NORETURN_MARK, 4)]),
    }
}

/// Is `op` the marker of a call that never returns?
pub fn is_marker(op: &PcodeOp) -> bool {
    op.opcode == OpCode::CallOther
        && op.inputs.first().is_some_and(|c| c.space == SpaceId::CONST && c.offset == NORETURN_MARK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Endian;
    use reargo_lift::x86::X86Lifter;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn mem(parts: &[(u64, &[u8])]) -> Memory {
        let mut m = Memory::new(SpaceId(1), Endian::Little);
        for (i, (addr, data)) in parts.iter().enumerate() {
            m.add_block(MemoryBlock {
                name: format!(".text{i}"),
                start: *addr,
                size: data.len() as u64,
                flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
                data: Some(Arc::from(*data)),
            });
        }
        m
    }

    #[test]
    fn names() {
        assert!(is_noreturn_name("_Unwind_Resume@plt"));
        assert!(is_noreturn_name("abort@GLIBC_2.2.5"));
        assert!(is_noreturn_name("__cxa_throw"));
        assert!(!is_noreturn_name("abort_message"));
        assert!(!is_noreturn_name("malloc@plt"));
    }

    #[test]
    fn import_by_name() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[(0x2000, &[0xff, 0x25, 0, 0, 0, 0])]); // jmp [rip] (a PLT stub)
        let syms = BTreeMap::from([(0x2000u64, "abort@plt".to_string())]);
        assert!(NoReturn::new(&lifter, &m, Some(&syms)).is_noreturn(0x2000));
        assert!(!NoReturn::new(&lifter, &m, None).is_noreturn(0x2000), "a PLT stub is unknown");
    }

    #[test]
    fn trap_and_returning_functions() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[
            // 0x2000: test edi, edi ; je 0x2006 ; ud2 ; 0x2006: ud2  (both paths trap)
            (0x2000, &[0x85, 0xff, 0x74, 0x02, 0x0f, 0x0b, 0x0f, 0x0b]),
            // 0x3000: test edi, edi ; je 0x3006 ; ud2 ; 0x3006: ret  (one path returns)
            (0x3000, &[0x85, 0xff, 0x74, 0x02, 0x0f, 0x0b, 0xc3]),
            // 0x4000: test edi, edi ; je 0x4006 ; ud2 ; (end of the code: nothing at 0x4006)
            (0x4000, &[0x85, 0xff, 0x74, 0x02, 0x0f, 0x0b]),
        ]);
        let o = NoReturn::new(&lifter, &m, None);
        assert!(o.is_noreturn(0x2000));
        assert!(!o.is_noreturn(0x3000));
        // a branch off the end of what could be lifted is not proof
        assert!(!o.is_noreturn(0x4000));
    }

    #[test]
    fn calls_into_noreturn_functions_propagate() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[
            // 0x2000: mov edi, 1 ; call 0x3000 ; 0x200a: ret (never reached)
            (0x2000, &[0xbf, 0x01, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0xc3]),
            // 0x3000: call 0x4000 ; 0x3005 ud2
            (0x3000, &[0xe8, 0xfb, 0x0f, 0, 0, 0x0f, 0x0b]),
            // 0x4000: ud2
            (0x4000, &[0x0f, 0x0b]),
            // 0x5000: call 0x6000 ; ret      0x6000: ret
            (0x5000, &[0xe8, 0xfb, 0x0f, 0, 0, 0xc3]),
            (0x6000, &[0xc3]),
        ]);
        let o = NoReturn::new(&lifter, &m, None);
        assert!(o.is_noreturn(0x4000));
        assert!(o.is_noreturn(0x3000));
        assert!(o.is_noreturn(0x2000));
        assert!(!o.is_noreturn(0x5000));
        assert!(!o.is_noreturn(0x6000));
    }

    #[test]
    fn recursion() {
        let lifter = X86Lifter::new_64();
        let m = mem(&[
            // 0x2000: call 0x2000 ; ud2  (recursion or a trap: never returns)
            (0x2000, &[0xe8, 0xfb, 0xff, 0xff, 0xff, 0x0f, 0x0b]),
            // 0x3000: test edi, edi ; je 0x300b ; call 0x3000 ; ud2 ; 0x300b: ret
            (0x3000, &[0x85, 0xff, 0x74, 0x07, 0xe8, 0xf7, 0xff, 0xff, 0xff, 0x0f, 0x0b, 0xc3]),
        ]);
        let o = NoReturn::new(&lifter, &m, None);
        assert!(o.is_noreturn(0x2000));
        assert!(!o.is_noreturn(0x3000));
    }
}
