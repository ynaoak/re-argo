//! Lifted x86 integer semantics checked against the CPU running the test (WS84).
//!
//! Each case is one instruction written as inline asm. The test runs it natively (flags in via
//! `popfq`, out via `pushfq`), takes the very bytes it executed, lifts them, runs the p-code in
//! the p-code emulator from the same registers and flags, and compares the result registers and
//! every flag the Intel SDM defines for that instruction and input (flags it leaves unaffected
//! count as defined: they must keep their input value).
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
const PF: u64 = 0x4;
const ARITH: u64 = CF | PF | ZF | SF | OF;
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
                    out("xmm0") _,
                    out("xmm1") _,
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
                    out("xmm0") _,
                    out("xmm1") _,
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
    /// inputs the instruction accepts (a `div` that would fault is not run)
    valid: Option<fn(u64, u64, u64) -> bool>,
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
    /// a, b = f64 bit patterns (an f32 in the low half for `…ss`): zeros, infinities, NaN,
    /// denormals, and random values
    Floats,
    /// a, c from edge values, b = a bit offset -130..=130
    BitOffsets,
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
    let mix = rng.next() & ARITH;
    [0x2, 0x2 | ARITH, 0x2 | mix]
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
                let b = if rng.next().is_multiple_of(4) { a } else { b };
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
        Inputs::Floats => {
            let edge = [0.0f64, -0.0, 1.0, -1.0, 0.5, 3.75, -2.5, 1e30, -1e-30, f64::INFINITY, f64::NEG_INFINITY, f64::NAN, 1e-310, 2147483647.0, -2147483648.0];
            let mut vals: Vec<f64> = edge.to_vec();
            for _ in 0..30 {
                vals.push((rng.next() % 2_000_001) as f64 / 1000.0 - 1000.0);
            }
            for &x in &vals {
                for &y in &vals {
                    let (a, b) = if rng.next().is_multiple_of(2) {
                        (x.to_bits(), y.to_bits())
                    } else {
                        (u64::from((x as f32).to_bits()), u64::from((y as f32).to_bits()))
                    };
                    v.push((a, b, rng.value(), flag_inputs(rng)[(rng.next() % 3) as usize]));
                }
            }
        }
        Inputs::BitOffsets => {
            for (i, &a) in EDGE.iter().enumerate() {
                for b in -130i64..=130 {
                    let c = EDGE[(i * 7 + b.unsigned_abs() as usize) % EDGE.len()];
                    v.push((a, b as u64, c, flag_inputs(rng)[b.unsigned_abs() as usize % 3]));
                }
            }
        }
        Inputs::Flags | Inputs::Jump => {
            for bits in 0..32u64 {
                let bit = |k: u64, flag: u64| ((bits >> k) & 1) * flag;
                let fl = 0x2 | bit(0, CF) | bit(1, 0x4) | bit(2, ZF) | bit(3, SF) | bit(4, OF);
                for _ in 0..4 {
                    v.push((rng.value(), rng.value(), rng.value(), fl));
                }
            }
        }
    }
    v
}

/// Lift the instructions between `start` and `end` (usually one).
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
    let (mut ops, mut text) = (Vec::new(), Vec::new());
    let mut at = start as u64;
    while at < end as u64 {
        let l = X86Lifter::new_64()
            .lift_instruction(&mem, at)
            .unwrap_or_else(|e| panic!("lift {bytes:02x?}: {e:?}"));
        at += u64::from(l.length);
        ops.extend(l.ops);
        text.push(l.mnemonic);
    }
    assert_eq!(at, end as u64, "{text:?}: instruction boundaries");
    (ops, text.join("; "))
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
    [(CF, "CF"), (PF, "PF"), (ZF, "ZF"), (SF, "SF"), (OF, "OF")]
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
        let (_, s, e) = (case.f)(0, 1, 0, 0x2); // (where its code is; 1 does not divide by 0)
        let (ops, mnemonic) = lift(s, e);
        let mut shown = 0;
        for (a, b, c, fl) in inputs(case.inputs, &mut rng) {
            if case.valid.is_some_and(|v| !v(a, b, c)) {
                continue;
            }
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
        // rotates leave SF/ZF/PF unaffected
        ROL | ROR => (CF | PF | ZF | SF | of, RAX),
        // CF is undefined for SHL/SHR by >= the operand width
        SHL | SHR if n >= u64::from(W) => (PF | ZF | SF | of, RAX),
        _ => (CF | PF | ZF | SF | of, RAX),
    }
}

/// `rcl`/`rcr` of a `W`-bit operand by `cl` (`IMM < 0`) or `IMM`: CF (and OF for a count of
/// 1) change, the other flags are unaffected; nothing changes for a zero count.
fn d_rc<const W: u32, const IMM: i64>(_: u64, b: u64, _: u64) -> (u64, u8) {
    let raw = if IMM < 0 { b & 0xff } else { IMM as u64 };
    let n = raw & if W == 64 { 63 } else { 31 };
    (if n == 1 || n == 0 { ARITH } else { ARITH & !OF }, RAX)
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
    (CF | PF | ZF | SF | if n == 1 { OF } else { 0 }, RAX)
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
        Case { asm: $asm, f: cpu!($asm), defined: $d, inputs: $inputs, needs: None, valid: None }
    };
    ($asm:expr, $d:expr, $inputs:expr, $needs:expr) => {
        Case { asm: $asm, f: cpu!($asm), defined: $d, inputs: $inputs, needs: Some($needs), valid: None }
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
                Case { asm: concat!("j", $c), f: cpu_jcc!($c), defined: d_arith, inputs: Inputs::Jump, needs: None, valid: None },
                case!(concat!("set", $c, " al"), d_arith, Inputs::Flags),
                case!(concat!("cmov", $c, " eax, ecx"), d_arith, Inputs::Flags),
                case!(concat!("cmov", $c, " ax, cx"), d_arith, Inputs::Flags),
            )+]
        };
    }
    let mut cases = cc!("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "l", "ge", "le", "g", "p", "np");
    cases.extend([
        case!("clc", d_arith, Inputs::Flags),
        case!("stc", d_arith, Inputs::Flags),
        case!("cmc", d_arith, Inputs::Flags),
    ]);
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

/// A rotate through carry at every width, by `cl`, by 1 and by a constant.
macro_rules! rotates_through_carry {
    ($op:literal) => {
        [
            case!(concat!($op, " al, cl"), d_rc::<8, -1>, Inputs::Counts),
            case!(concat!($op, " ax, cl"), d_rc::<16, -1>, Inputs::Counts),
            case!(concat!($op, " eax, cl"), d_rc::<32, -1>, Inputs::Counts),
            case!(concat!($op, " rax, cl"), d_rc::<64, -1>, Inputs::Counts),
            case!(concat!($op, " al, 1"), d_rc::<8, 1>, Inputs::Values),
            case!(concat!($op, " eax, 1"), d_rc::<32, 1>, Inputs::Values),
            case!(concat!($op, " rax, 1"), d_rc::<64, 1>, Inputs::Values),
            case!(concat!($op, " al, 9"), d_rc::<8, 9>, Inputs::Values),
            case!(concat!($op, " al, 5"), d_rc::<8, 5>, Inputs::Values),
            case!(concat!($op, " ax, 16"), d_rc::<16, 16>, Inputs::Values),
            case!(concat!($op, " eax, 31"), d_rc::<32, 31>, Inputs::Values),
            case!(concat!($op, " rax, 0x22"), d_rc::<64, 0x22>, Inputs::Values),
        ]
    };
}

#[test]
fn rotates_through_carry_match_the_cpu() {
    let cases: Vec<Case> =
        [rotates_through_carry!("rcl"), rotates_through_carry!("rcr")].into_iter().flatten().collect();
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

/// `bt`… on memory with a register bit offset (the bit string: the offset may leave the
/// operand). rax and rdx are the 16 bytes at `[rsp]`; the case's address leaves room for the
/// offsets it accepts.
fn d_bt_mem(_: u64, _: u64, _: u64) -> (u64, u8) {
    (CF | ZF, RAX | RDX)
}

macro_rules! bt_mem {
    ($asm:expr, $valid:expr) => {
        Case {
            asm: $asm,
            f: cpu!("push rdx
 push rax
 ", $asm, "
 pop rax
 pop rdx"),
            defined: d_bt_mem,
            inputs: Inputs::BitOffsets,
            needs: None,
            valid: Some($valid),
        }
    };
}

#[test]
fn bit_string_ops_match_the_cpu() {
    let low = |_: u64, b: u64, _: u64| (0..128).contains(&(b as i64));
    let mid = |_: u64, b: u64, _: u64| (-64..64).contains(&(b as i64));
    let cases = vec![
        bt_mem!("bt qword ptr [rsp], rcx", low),
        bt_mem!("bt qword ptr [rsp+8], rcx", mid),
        bt_mem!("bt dword ptr [rsp+8], ecx", mid),
        bt_mem!("bt word ptr [rsp+8], cx", mid),
        bt_mem!("bts qword ptr [rsp+8], rcx", mid),
        bt_mem!("btr dword ptr [rsp], ecx", low),
        bt_mem!("btc word ptr [rsp+8], cx", mid),
        bt_mem!("bts dword ptr [rsp], 37", low),
    ];
    check(&cases);
}

fn d_div(_: u64, _: u64, _: u64) -> (u64, u8) {
    (0, RAX | RDX) // all flags undefined
}

/// A division and the inputs it does not fault on.
macro_rules! div {
    ($asm:expr, $valid:expr) => {
        Case { asm: $asm, f: cpu!($asm), defined: d_div, inputs: Inputs::Values, needs: None, valid: Some($valid) }
    };
}

#[test]
fn divisions_match_the_cpu() {
    let cases = vec![
        // byte form: AX / cl -> AL, remainder AH
        div!("div cl", |a, b, _| b as u8 != 0 && (a as u16) / u16::from(b as u8) <= 0xff),
        div!("idiv cl", |a, b, _| {
            let d = i16::from(b as u8 as i8);
            (a as u16 as i16).checked_div(d).is_some_and(|q| (-128..=127).contains(&q))
        }),
        // wider forms with the dividend's high half set up the way compilers do
        div!("xor edx, edx
 div ecx", |_, b, _| b as u32 != 0),
        div!("cdq
 idiv ecx", |a, b, _| b as u32 != 0 && !(a as u32 == 0x8000_0000 && b as u32 == u32::MAX)),
        div!("xor edx, edx
 div rcx", |_, b, _| b != 0),
        div!("cqo
 idiv rcx", |a, b, _| b != 0 && !(a == 1 << 63 && b == u64::MAX)),
        div!("xor edx, edx
 div cx", |_, b, _| b as u16 != 0),
    ];
    check(&cases);
}

#[test]
fn high_byte_registers_match_the_cpu() {
    let cases = vec![
        case!("mov ah, cl", d_arith, Inputs::Values),
        case!("mov ch, al", d_arith_all_regs, Inputs::Values),
        case!("movzx eax, ch", d_arith, Inputs::Values),
        case!("movzx ecx, ah", d_arith_all_regs, Inputs::Values),
        case!("add ah, cl", d_arith, Inputs::Values),
        case!("xor ah, ah", d_arith, Inputs::Values),
        case!("test ah, 0x41", d_arith, Inputs::Values),
        case!("cmp dh, ch", d_arith, Inputs::Values),
        case!("mov ah, 1
 mov al, ah", d_arith, Inputs::Values),
        case!("mov dh, cl
 add eax, edx", d_arith_all_regs, Inputs::Values),
        case!("xchg ah, al", d_arith, Inputs::Values),
    ];
    check(&cases);
}

/// Scalar SSE via general registers: `a`/`b` go into xmm0/xmm1 (movq), the result comes back
/// in rax. The xmm upper halves are not compared.
macro_rules! sse {
    ($op:literal) => {
        case!(concat!("movq xmm0, rax
 movq xmm1, rcx
 ", $op, " xmm0, xmm1
 movq rax, xmm0"), d_arith, Inputs::Floats)
    };
}

/// `cvtt…2si` of a value that fits (out of range is the "integer indefinite" 0x80000000…,
/// which p-code FLOAT_TRUNC does not define).
fn fits_i32_f32(a: u64, _: u64, _: u64) -> bool {
    let x = f32::from_bits(a as u32);
    x.is_finite() && x > -2147483648.0 && x < 2147483647.0
}
fn fits_i32_f64(a: u64, _: u64, _: u64) -> bool {
    let x = f64::from_bits(a);
    x.is_finite() && x > -2147483648.0 && x < 2147483647.0
}

/// `comis…`/`ucomis…` of an `N`-byte float: OF/SF cleared, PF = unordered, CF = below or
/// unordered. (Unordered also sets ZF = 1 on the CPU; the lifter keeps ZF as the plain `==`,
/// so ZF is only compared for ordered inputs.)
fn d_fcmp<const N: u32>(a: u64, b: u64, _: u64) -> (u64, u8) {
    let nan = |x: u64| if N == 4 { f32::from_bits(x as u32).is_nan() } else { f64::from_bits(x).is_nan() };
    (if nan(a) || nan(b) { ARITH & !ZF } else { ARITH }, RAX)
}

#[test]
fn scalar_float_matches_the_cpu() {
    let mut cases = vec![
        sse!("addss"),
        sse!("subss"),
        sse!("mulss"),
        sse!("divss"),
        sse!("sqrtss"),
        sse!("minss"),
        sse!("maxss"),
        sse!("addsd"),
        sse!("subsd"),
        sse!("mulsd"),
        sse!("divsd"),
        sse!("sqrtsd"),
        sse!("minsd"),
        sse!("maxsd"),
        sse!("cvtss2sd"),
        sse!("cvtsd2ss"),
        case!("movq xmm0, rax
 ucomiss xmm0, xmm0", d_fcmp::<4>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 ucomiss xmm0, xmm1", d_fcmp::<4>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 comisd xmm0, xmm1", d_fcmp::<8>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 ucomiss xmm0, xmm1
 seta al", d_fcmp::<4>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 ucomisd xmm0, xmm1
 setae al", d_fcmp::<8>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 ucomiss xmm0, xmm1
 setb al", d_fcmp::<4>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 ucomisd xmm0, xmm1
 setbe al", d_fcmp::<8>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 ucomisd xmm0, xmm1
 setnp al
 sete cl
 and al, cl", d_fcmp::<8>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 ucomiss xmm0, xmm1
 setp al
 setne cl
 or al, cl", d_fcmp::<4>, Inputs::Floats),
        case!("movq xmm0, rax
 movq xmm1, rcx
 ucomiss xmm0, xmm1
 cmovne eax, edx
 cmovp eax, edx", d_fcmp::<4>, Inputs::Floats),
        case!("cvtsi2ss xmm0, ecx
 movd eax, xmm0", d_arith, Inputs::Values),
        case!("cvtsi2sd xmm0, rcx
 movq rax, xmm0", d_arith, Inputs::Values),
        case!("cvtsi2sd xmm0, ecx
 movq rax, xmm0", d_arith, Inputs::Values),
    ];
    cases.push(Case { valid: Some(fits_i32_f32), ..case!("movq xmm0, rax
 cvttss2si eax, xmm0", d_arith, Inputs::Floats) });
    cases.push(Case { valid: Some(fits_i32_f64), ..case!("movq xmm0, rax
 cvttsd2si eax, xmm0", d_arith, Inputs::Floats) });
    check(&cases);
}
