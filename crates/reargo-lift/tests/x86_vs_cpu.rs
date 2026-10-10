//! Lifted x86 integer semantics checked against the CPU running the test (WS84).
//!
//! Each case is one instruction written as inline asm. The test runs it natively (flags in via
//! `popfq`, out via `pushfq`), takes the very bytes it executed, lifts them, runs the p-code in
//! the p-code emulator from the same registers and flags, and compares the result registers and
//! every flag the Intel SDM defines for that instruction and input (flags it leaves unaffected
//! count as defined: they must keep their input value). PF is not modelled for integer ops and
//! is never compared.
//!
//! Registers: `a` = rax, `b` = rcx (also the `cl` count), `c` = rdx.
#![cfg(target_arch = "x86_64")]

use reargo_core::address::{Endian, SpaceId};
use reargo_core::pcode::PcodeOp;
use reargo_emulator::emulator::{Emulator, EmulatorError};
use reargo_lift::PcodeLift;
use reargo_lift::x86::X86Lifter;
use reargo_loader::memory::{Memory, MemoryBlock, MemoryFlags};
use std::sync::Arc;

const CF: u64 = 0x1;
const ZF: u64 = 0x40;
const SF: u64 = 0x80;
const OF: u64 = 0x800;
const ARITH: u64 = CF | ZF | SF | OF;
/// (EFLAGS bit, register offset of the lifter's 1-byte flag).
const FLAGS: [(u64, u64); 5] = [(CF, 0x201), (0x4, 0x202), (ZF, 0x206), (SF, 0x207), (OF, 0x20b)];

const RAX: u8 = 1;
const RCX: u8 = 2;
const RDX: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq)]
struct Out {
    rax: u64,
    rcx: u64,
    rdx: u64,
    flags: u64,
}

/// Run natively: (result, start of the instruction's bytes, end of them).
type Native = fn(u64, u64, u64, u64) -> (Out, usize, usize);
/// The flags (EFLAGS bits) and registers (`RAX | RCX | RDX`) the SDM defines for these inputs.
type Defined = fn(u64, u64, u64) -> (u64, u8);

/// One instruction (several template pieces form one line) between the labels `2:` and `3:`.
macro_rules! cpu {
    ($($ins:expr),+ $(,)?) => {{
        fn run(a: u64, b: u64, c: u64, fl: u64) -> (Out, usize, usize) {
            let (mut ra, mut rc, mut rd) = (a, b, c);
            let (s, e, fo): (usize, usize, u64);
            unsafe {
                core::arch::asm!(
                    "lea {s}, [rip + 2f]",
                    "lea {e}, [rip + 3f]",
                    "push {fi}",
                    "popfq",
                    "2:",
                    concat!($($ins),+),
                    "3:",
                    "pushfq",
                    "pop {fo}",
                    s = out(reg) s,
                    e = out(reg) e,
                    fi = in(reg) fl,
                    fo = lateout(reg) fo,
                    inout("rax") ra,
                    inout("rcx") rc,
                    inout("rdx") rd,
                );
            }
            (Out { rax: ra, rcx: rc, rdx: rd, flags: fo }, s, e)
        }
        run as Native
    }};
}

/// The conditional jump `j<cc>`: rax = 1 when taken, else 0 (`b`/`c` unused).
macro_rules! cpu_jcc {
    ($j:literal) => {{
        fn run(a: u64, b: u64, c: u64, fl: u64) -> (Out, usize, usize) {
            let (mut ra, mut rc, mut rd) = (a, b, c);
            let (s, e, fo): (usize, usize, u64);
            unsafe {
                core::arch::asm!(
                    "lea {s}, [rip + 2f]",
                    "lea {e}, [rip + 3f]",
                    "push {fi}",
                    "popfq",
                    "2:",
                    concat!("j", $j, " 4f"),
                    "3:",
                    "mov eax, 0",
                    "jmp 5f",
                    "4:",
                    "mov eax, 1",
                    "5:",
                    "pushfq",
                    "pop {fo}",
                    s = out(reg) s,
                    e = out(reg) e,
                    fi = in(reg) fl,
                    fo = lateout(reg) fo,
                    inout("rax") ra,
                    inout("rcx") rc,
                    inout("rdx") rd,
                );
            }
            (Out { rax: ra, rcx: rc, rdx: rd, flags: fo }, s, e)
        }
        run as Native
    }};
}

struct Case {
    asm: &'static str,
    f: Native,
    defined: Defined,
    inputs: Inputs,
    /// a CPU feature the instruction needs (`is_x86_feature_detected!`)
    needs: Option<fn() -> bool>,
}

#[derive(Clone, Copy, PartialEq)]
enum Inputs {
    /// a, b from edge values x edge values, plus random triples
    Values,
    /// a from edge values, b = a count 0..=70 (and random), c random
    Counts,
    /// every combination of CF/PF/ZF/SF/OF, random registers
    Flags,
    /// a jump: compare "taken" (the emulator stops at a taken CBRANCH)
    Jump,
}

const EDGE: [u64; 20] = [
    0,
    1,
    2,
    3,
    0x7f,
    0x80,
    0xff,
    0x100,
    0x7fff,
    0x8000,
    0xffff,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    u64::MAX,
    0x0123_4567_89ab_cdef,
    0xfedc_ba98_7654_3210,
];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// A value with a random width class, so small and sign-boundary values are common.
    fn value(&mut self) -> u64 {
        let v = self.next();
        match self.next() % 5 {
            0 => v & 0xff,
            1 => v & 0xffff,
            2 => v & 0xffff_ffff,
            3 => (v as i8) as i64 as u64,
            _ => v,
        }
    }
}

/// The flag inputs to try: none set, all set, and a random mix.
fn flag_inputs(rng: &mut Rng) -> [u64; 3] {
    let mix = rng.next() & (ARITH | 0x4);
    [0x2, 0x2 | ARITH | 0x4, 0x2 | mix]
}

fn inputs(kind: Inputs, rng: &mut Rng) -> Vec<(u64, u64, u64, u64)> {
    let mut v = Vec::new();
    match kind {
        Inputs::Values => {
            for &a in &EDGE {
                for &b in &EDGE {
                    let c = rng.value();
                    for fl in flag_inputs(rng) {
                        v.push((a, b, c, fl));
                    }
                }
            }
            for _ in 0..400 {
                let (a, b, c) = (rng.value(), rng.value(), rng.value());
                let b = if rng.next() % 4 == 0 { a } else { b };
                for fl in flag_inputs(rng) {
                    v.push((a, b, c, fl));
                }
            }
        }
        Inputs::Counts => {
            for &a in &EDGE {
                for n in 0..=70u64 {
                    let b = n | (rng.next() & !0xff); // only cl counts
                    let fl = flag_inputs(rng)[(n % 3) as usize];
                    v.push((a, b, rng.value(), fl));
                }
            }
            for _ in 0..400 {
                let (a, b, c) = (rng.value(), rng.next(), rng.value());
                for fl in flag_inputs(rng) {
                    v.push((a, b, c, fl));
                }
            }
        }
        Inputs::Flags | Inputs::Jump => {
            for bits in 0..32u64 {
                let fl = 0x2
                    | (bits & 1) * CF
                    | (bits >> 1 & 1) * 0x4
                    | (bits >> 2 & 1) * ZF
                    | (bits >> 3 & 1) * SF
                    | (bits >> 4 & 1) * OF;
                for _ in 0..4 {
                    v.push((rng.value(), rng.value(), rng.value(), fl));
                }
            }
        }
    }
    v
}

fn lift(start: usize, end: usize) -> (Vec<PcodeOp>, String) {
    let bytes = unsafe { std::slice::from_raw_parts(start as *const u8, end - start) }.to_vec();
    let mut mem = Memory::new(SpaceId(1), Endian::Little);
    mem.add_block(MemoryBlock {
        name: ".text".into(),
        start: start as u64,
        size: bytes.len() as u64,
        flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
        data: Some(Arc::from(bytes.as_slice())),
    });
    let l = X86Lifter::new_64()
        .lift_instruction(&mem, start as u64)
        .unwrap_or_else(|e| panic!("lift {bytes:02x?}: {e:?}"));
    assert_eq!(l.length as usize, bytes.len(), "{}: one instruction expected", l.mnemonic);
    (l.ops, l.mnemonic)
}

/// Run the lifted ops: (registers and flags after, whether a CBRANCH was taken).
fn emulate(ops: &[PcodeOp], a: u64, b: u64, c: u64, fl: u64) -> (Out, bool) {
    let mut emu = Emulator::new();
    emu.state.write_register(0x00, 8, a);
    emu.state.write_register(0x08, 8, b);
    emu.state.write_register(0x10, 8, c);
    for (bit, off) in FLAGS {
        emu.state.write_register(off, 1, u64::from(fl & bit != 0));
    }
    let taken = match emu.execute_ops(ops) {
        Ok(()) => false,
        Err(EmulatorError::Branch(_)) => true,
        Err(e) => panic!("emulator: {e:?}"),
    };
    let mut flags = 0x2;
    for (bit, off) in FLAGS {
        if emu.state.read_register(off, 1) != 0 {
            flags |= bit;
        }
    }
    let r = |off| emu.state.read_register(off, 8);
    (Out { rax: r(0x00), rcx: r(0x08), rdx: r(0x10), flags }, taken)
}

fn flag_names(mask: u64) -> String {
    [(CF, "CF"), (ZF, "ZF"), (SF, "SF"), (OF, "OF")]
        .iter()
        .filter(|(b, _)| mask & b != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join("|")
}

/// Run every case; panic with all the mismatches (a few per case).
fn check(cases: &[Case]) {
    let mut failures = Vec::new();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for case in cases {
        if case.needs.is_some_and(|f| !f()) {
            eprintln!("skip {} (CPU feature missing)", case.asm);
            continue;
        }
        let (_, s, e) = (case.f)(0, 0, 0, 0x2);
        let (ops, mnemonic) = lift(s, e);
        let mut shown = 0;
        for (a, b, c, fl) in inputs(case.inputs, &mut rng) {
            let (cpu, _, _) = (case.f)(a, b, c, fl);
            let (emu, taken) = emulate(&ops, a, b, c, fl);
            let mut bad = Vec::new();
            if case.inputs == Inputs::Jump {
                if taken != (cpu.rax == 1) {
                    bad.push(format!("taken cpu {} lifted {}", cpu.rax == 1, taken));
                }
            } else {
                let (fmask, regs) = (case.defined)(a, b, c);
                let diff = (cpu.flags ^ emu.flags) & fmask;
                if diff != 0 {
                    bad.push(format!(
                        "flags {} cpu {} lifted {}",
                        flag_names(diff),
                        flag_names(cpu.flags & diff),
                        flag_names(emu.flags & diff)
                    ));
                }
                for (bit, name, x, y) in
                    [(RAX, "rax", cpu.rax, emu.rax), (RCX, "rcx", cpu.rcx, emu.rcx), (RDX, "rdx", cpu.rdx, emu.rdx)]
                {
                    if regs & bit != 0 && x != y {
                        bad.push(format!("{name} cpu {x:#x} lifted {y:#x}"));
                    }
                }
            }
            if !bad.is_empty() {
                if shown < 3 {
                    failures.push(format!(
                        "{} [{}] a={a:#x} b={b:#x} c={c:#x} flags={}: {}",
                        case.asm,
                        mnemonic,
                        flag_names(fl),
                        bad.join(", ")
                    ));
                }
                shown += 1;
            }
        }
        if shown > 3 {
            failures.push(format!("{}: {} mismatching inputs in all", case.asm, shown));
        }
    }
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
}

// ---- defined flags / registers -------------------------------------------------------------

fn d_arith(_: u64, _: u64, _: u64) -> (u64, u8) {
    (ARITH, RAX)
}
fn d_arith_all_regs(_: u64, _: u64, _: u64) -> (u64, u8) {
    (ARITH, RAX | RCX | RDX)
}
/// `imul` / `mul`: only CF and OF are defined (SF/ZF/AF/PF undefined).
fn d_mul(_: u64, _: u64, _: u64) -> (u64, u8) {
    (CF | OF, RAX | RDX)
}
/// A 64-bit `imul`: its CF/OF come from a 128-bit product, beyond the u64 emulator.
fn d_mul64(_: u64, _: u64, _: u64) -> (u64, u8) {
    (0, RAX | RDX)
}

const SHL: u8 = 0;
const SHR: u8 = 1;
const SAR: u8 = 2;
const ROL: u8 = 3;
const ROR: u8 = 4;

/// Shifts and rotates of a `W`-bit operand by `cl` (`IMM < 0`) or by the immediate `IMM`.
fn d_shift<const W: u32, const IMM: i64, const K: u8>(_: u64, b: u64, _: u64) -> (u64, u8) {
    let raw = if IMM < 0 { b & 0xff } else { IMM as u64 };
    let n = raw & if W == 64 { 63 } else { 31 };
    if n == 0 {
        return (ARITH, RAX);
    }
    let of = if n == 1 { OF } else { 0 };
    match K {
        // rotates leave SF/ZF unaffected
        ROL | ROR => (CF | ZF | SF | of, RAX),
        // CF is undefined for SHL/SHR by >= the operand width
        SHL | SHR if n >= u64::from(W) => (ZF | SF | of, RAX),
        _ => (CF | ZF | SF | of, RAX),
    }
}

/// `shld`/`shrd` of a `W`-bit operand by `cl` (`IMM < 0`) or `IMM`.
fn d_dshift<const W: u32, const IMM: i64>(_: u64, b: u64, _: u64) -> (u64, u8) {
    let raw = if IMM < 0 { b & 0xff } else { IMM as u64 };
    let n = raw & if W == 64 { 63 } else { 31 };
    if n == 0 {
        return (ARITH, RAX);
    }
    if n > u64::from(W) {
        return (0, 0); // result and flags undefined
    }
    (CF | ZF | SF | if n == 1 { OF } else { 0 }, RAX)
}

/// `bt`/`bts`/`btr`/`btc`: CF = the bit, ZF unaffected, OF/SF undefined.
fn d_bt(_: u64, _: u64, _: u64) -> (u64, u8) {
    (CF | ZF, RAX)
}

/// `bsf`/`bsr eax, ecx`-style of a `W`-bit source in rcx: ZF defined; the destination only when
/// the source is not zero.
fn d_bscan<const W: u32>(_: u64, b: u64, _: u64) -> (u64, u8) {
    let src = if W == 64 { b } else { b & ((1u64 << W) - 1) };
    (ZF, if src != 0 { RAX } else { 0 })
}

/// `tzcnt`/`lzcnt`: CF and ZF defined.
fn d_cnt(_: u64, _: u64, _: u64) -> (u64, u8) {
    (CF | ZF, RAX)
}

fn bmi1() -> bool {
    std::is_x86_feature_detected!("bmi1")
}
fn lzcnt() -> bool {
    std::is_x86_feature_detected!("lzcnt")
}
fn popcnt() -> bool {
    std::is_x86_feature_detected!("popcnt")
}

macro_rules! case {
    ($asm:expr, $d:expr, $inputs:expr) => {
        Case { asm: $asm, f: cpu!($asm), defined: $d, inputs: $inputs, needs: None }
    };
    ($asm:expr, $d:expr, $inputs:expr, $needs:expr) => {
        Case { asm: $asm, f: cpu!($asm), defined: $d, inputs: $inputs, needs: Some($needs) }
    };
}

/// A two-operand instruction at every width: `op al, cl` … `op rax, rcx`.
macro_rules! widths {
    ($op:literal, $d:expr) => {
        [
            case!(concat!($op, " al, cl"), $d, Inputs::Values),
            case!(concat!($op, " ax, cx"), $d, Inputs::Values),
            case!(concat!($op, " eax, ecx"), $d, Inputs::Values),
            case!(concat!($op, " rax, rcx"), $d, Inputs::Values),
        ]
    };
}

/// A one-operand instruction at every width.
macro_rules! widths1 {
    ($op:literal, $d:expr) => {
        [
            case!(concat!($op, " al"), $d, Inputs::Values),
            case!(concat!($op, " ax"), $d, Inputs::Values),
            case!(concat!($op, " eax"), $d, Inputs::Values),
            case!(concat!($op, " rax"), $d, Inputs::Values),
        ]
    };
}

#[test]
fn arithmetic_and_logic_match_the_cpu() {
    let cases: Vec<Case> = [
        widths!("add", d_arith),
        widths!("sub", d_arith),
        widths!("cmp", d_arith),
        widths!("and", d_arith),
        widths!("or", d_arith),
        widths!("xor", d_arith),
        widths!("test", d_arith),
        widths1!("inc", d_arith),
        widths1!("dec", d_arith),
        widths1!("neg", d_arith),
        widths1!("not", d_arith),
    ]
    .into_iter()
    .flatten()
    .chain([
        case!("add eax, 0x7fffffff", d_arith, Inputs::Values),
        case!("sub rax, -8", d_arith, Inputs::Values),
        case!("xchg eax, ecx", d_arith_all_regs, Inputs::Values),
        case!("movzx eax, cl", d_arith, Inputs::Values),
        case!("movsx rax, cx", d_arith, Inputs::Values),
        case!("movsxd rax, ecx", d_arith, Inputs::Values),
        case!("cdqe", d_arith, Inputs::Values),
        case!("cwde", d_arith, Inputs::Values),
        case!("cbw", d_arith, Inputs::Values),
        case!("cdq", d_arith_all_regs, Inputs::Values),
        case!("cqo", d_arith_all_regs, Inputs::Values),
        case!("lea eax, [rcx + rdx*4 + 7]", d_arith, Inputs::Values),
        case!("mov al, cl", d_arith, Inputs::Values),
        case!("mov ax, cx", d_arith, Inputs::Values),
        case!("mov eax, ecx", d_arith, Inputs::Values),
    ])
    .collect();
    check(&cases);
}

#[test]
fn conditions_match_the_cpu() {
    macro_rules! cc {
        ($($c:literal),+) => {
            vec![$(
                Case { asm: concat!("j", $c), f: cpu_jcc!($c), defined: d_arith, inputs: Inputs::Jump, needs: None },
                case!(concat!("set", $c, " al"), d_arith, Inputs::Flags),
                case!(concat!("cmov", $c, " eax, ecx"), d_arith, Inputs::Flags),
                case!(concat!("cmov", $c, " ax, cx"), d_arith, Inputs::Flags),
            )+]
        };
    }
    // (parity conditions are not modelled: PF is not tracked for integer ops)
    let cases = cc!("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "l", "ge", "le", "g");
    check(&cases);
}

#[test]
fn carry_chains_match_the_cpu() {
    let cases: Vec<Case> = [widths!("adc", d_arith), widths!("sbb", d_arith)]
        .into_iter()
        .flatten()
        .chain([
            case!("sbb eax, eax", d_arith, Inputs::Values),
            case!("adc rax, 0", d_arith, Inputs::Values),
            case!("xadd eax, ecx", d_arith_all_regs, Inputs::Values),
            case!("xadd al, cl", d_arith_all_regs, Inputs::Values),
            case!("cmpxchg ecx, edx", d_arith_all_regs, Inputs::Values),
            case!("cmpxchg rcx, rdx", d_arith_all_regs, Inputs::Values),
            case!("cmpxchg cx, dx", d_arith_all_regs, Inputs::Values),
        ])
        .collect();
    check(&cases);
}

#[test]
fn multiplies_match_the_cpu() {
    // (one-operand 64-bit `mul`/`imul` need a 128-bit product, beyond the u64 emulator)
    let cases = vec![
        case!("imul ax, cx", d_mul, Inputs::Values),
        case!("imul eax, ecx", d_mul, Inputs::Values),
        case!("imul rax, rcx", d_mul64, Inputs::Values),
        case!("imul eax, ecx, 0x6c078965", d_mul, Inputs::Values),
        case!("imul eax, ecx, -3", d_mul, Inputs::Values),
        case!("imul rax, rcx, 0x7fffffff", d_mul64, Inputs::Values),
        case!("imul ax, cx, 300", d_mul, Inputs::Values),
        case!("mul cl", d_mul, Inputs::Values),
        case!("mul cx", d_mul, Inputs::Values),
        case!("mul ecx", d_mul, Inputs::Values),
        case!("imul cl", d_mul, Inputs::Values),
        case!("imul cx", d_mul, Inputs::Values),
        case!("imul ecx", d_mul, Inputs::Values),
    ];
    check(&cases);
}

/// A shift or rotate at every width, by `cl`, by 1 and by 3.
macro_rules! shifts {
    ($op:literal, $k:expr) => {
        [
            case!(concat!($op, " al, cl"), d_shift::<8, -1, $k>, Inputs::Counts),
            case!(concat!($op, " ax, cl"), d_shift::<16, -1, $k>, Inputs::Counts),
            case!(concat!($op, " eax, cl"), d_shift::<32, -1, $k>, Inputs::Counts),
            case!(concat!($op, " rax, cl"), d_shift::<64, -1, $k>, Inputs::Counts),
            case!(concat!($op, " al, 1"), d_shift::<8, 1, $k>, Inputs::Values),
            case!(concat!($op, " eax, 1"), d_shift::<32, 1, $k>, Inputs::Values),
            case!(concat!($op, " rax, 1"), d_shift::<64, 1, $k>, Inputs::Values),
            case!(concat!($op, " al, 3"), d_shift::<8, 3, $k>, Inputs::Values),
            case!(concat!($op, " ax, 9"), d_shift::<16, 9, $k>, Inputs::Values),
            case!(concat!($op, " eax, 3"), d_shift::<32, 3, $k>, Inputs::Values),
            case!(concat!($op, " rax, 0x22"), d_shift::<64, 0x22, $k>, Inputs::Values),
        ]
    };
}

#[test]
fn shifts_match_the_cpu() {
    let cases: Vec<Case> = [shifts!("shl", SHL), shifts!("shr", SHR), shifts!("sar", SAR)]
        .into_iter()
        .flatten()
        .collect();
    check(&cases);
}

#[test]
fn rotates_match_the_cpu() {
    let cases: Vec<Case> = [shifts!("rol", ROL), shifts!("ror", ROR)].into_iter().flatten().collect();
    check(&cases);
}

#[test]
fn double_shifts_match_the_cpu() {
    let cases = vec![
        case!("shld eax, edx, cl", d_dshift::<32, -1>, Inputs::Counts),
        case!("shld rax, rdx, cl", d_dshift::<64, -1>, Inputs::Counts),
        case!("shld ax, dx, cl", d_dshift::<16, -1>, Inputs::Counts),
        case!("shrd eax, edx, cl", d_dshift::<32, -1>, Inputs::Counts),
        case!("shrd rax, rdx, cl", d_dshift::<64, -1>, Inputs::Counts),
        case!("shrd ax, dx, cl", d_dshift::<16, -1>, Inputs::Counts),
        case!("shld eax, edx, 1", d_dshift::<32, 1>, Inputs::Values),
        case!("shld rax, rdx, 0x11", d_dshift::<64, 0x11>, Inputs::Values),
        case!("shrd eax, edx, 7", d_dshift::<32, 7>, Inputs::Values),
        case!("shrd rax, rdx, 1", d_dshift::<64, 1>, Inputs::Values),
    ];
    check(&cases);
}

#[test]
fn bit_ops_match_the_cpu() {
    let cases = vec![
        case!("bt eax, ecx", d_bt, Inputs::Counts),
        case!("bt rax, rcx", d_bt, Inputs::Counts),
        case!("bt ax, cx", d_bt, Inputs::Counts),
        case!("bt eax, 5", d_bt, Inputs::Values),
        case!("bt rax, 0x3f", d_bt, Inputs::Values),
        case!("bts eax, ecx", d_bt, Inputs::Counts),
        case!("bts rax, 0x28", d_bt, Inputs::Values),
        case!("btr eax, ecx", d_bt, Inputs::Counts),
        case!("btr rax, rcx", d_bt, Inputs::Counts),
        case!("btc eax, 3", d_bt, Inputs::Values),
        case!("btc rax, rcx", d_bt, Inputs::Counts),
        case!("bsf eax, ecx", d_bscan::<32>, Inputs::Values),
        case!("bsf rax, rcx", d_bscan::<64>, Inputs::Values),
        case!("bsr eax, ecx", d_bscan::<32>, Inputs::Values),
        case!("bsr rax, rcx", d_bscan::<64>, Inputs::Values),
        case!("bsr ax, cx", d_bscan::<16>, Inputs::Values),
        case!("tzcnt eax, ecx", d_cnt, Inputs::Values, bmi1),
        case!("tzcnt rax, rcx", d_cnt, Inputs::Values, bmi1),
        case!("tzcnt ax, cx", d_cnt, Inputs::Values, bmi1),
        case!("lzcnt eax, ecx", d_cnt, Inputs::Values, lzcnt),
        case!("lzcnt rax, rcx", d_cnt, Inputs::Values, lzcnt),
        case!("lzcnt ax, cx", d_cnt, Inputs::Values, lzcnt),
        case!("popcnt eax, ecx", d_arith, Inputs::Values, popcnt),
        case!("popcnt rax, rcx", d_arith, Inputs::Values, popcnt),
        case!("popcnt ax, cx", d_arith, Inputs::Values, popcnt),
        case!("bswap eax", d_arith, Inputs::Values),
        case!("bswap rax", d_arith, Inputs::Values),
    ];
    check(&cases);
}
