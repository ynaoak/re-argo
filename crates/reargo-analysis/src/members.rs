//! Object-layout mapper: list the `[reg + offset]` member accesses in a
//! function. A C++ constructor / method touches its object through a stable
//! base register (`this`, usually rbx/rdi/r13); enumerating the distinct
//! `[base+offset]` accesses reconstructs the object's member layout — the key
//! to resolving "what type is at obj+0x1B0?" that a decompiler's incomplete
//! struct recovery misses on large functions. Loader-only; no full analysis.

use iced_x86::{Decoder, DecoderOptions, Instruction as IcedInsn, OpKind, Register};
use reargo_loader::BinaryInfo;

#[derive(Debug, Clone)]
pub struct MemberAccess {
    pub base: String,
    pub offset: u64,
    pub count: u32,
    pub writes: u32,
    pub lea: u32,
    pub sample: String,
}

/// Scan `max_insns` instructions from `start` (or until a `ret`) and group all
/// `[base + displacement]` memory accesses by (base register, displacement).
/// RIP-relative and pure-displacement operands are skipped (those are globals,
/// not object members). Stack frame access via rsp/rbp is included but tagged
/// by its register so callers can filter.
pub fn member_accesses(info: &BinaryInfo, start: u64, max_insns: usize) -> Vec<MemberAccess> {
    use std::collections::BTreeMap;
    if !matches!(
        info.arch,
        reargo_loader::Architecture::X86_64 | reargo_loader::Architecture::X86
    ) {
        return Vec::new();
    }
    let bits = info.bits;
    // Read a window of bytes covering the scan.
    let cap = max_insns.saturating_mul(15).max(64);
    let mut buf = vec![0u8; cap];
    for (i, b) in buf.iter_mut().enumerate() {
        if let Some(v) = info.memory.read_byte(start + i as u64) {
            *b = v;
        }
    }
    let mut dec = Decoder::with_ip(bits, &buf, start, DecoderOptions::NONE);
    let mut ii = IcedInsn::default();
    let mut fmt = iced_x86::IntelFormatter::new();
    use iced_x86::Formatter;

    let mut map: BTreeMap<(String, u64), MemberAccess> = BTreeMap::new();
    let mut n = 0;
    while dec.can_decode() && n < max_insns {
        dec.decode_out(&mut ii);
        if ii.is_invalid() {
            break;
        }
        n += 1;
        let base = ii.memory_base();
        if base != Register::None
            && base != Register::RIP
            && base != Register::EIP
            && (0..ii.op_count()).any(|i| ii.op_kind(i) == OpKind::Memory)
        {
            let disp = ii.memory_displacement64();
            // Skip the displacement-is-effective-address (absolute) case.
            if disp != 0 || base != Register::None {
                let reg = format!("{:?}", base).to_lowercase();
                let is_lea = ii.mnemonic() == iced_x86::Mnemonic::Lea;
                // A write = the memory operand is operand 0 of a store-style
                // op (mov/and/or/add/... [mem], reg/imm). Heuristic: op0 is
                // Memory and the instruction isn't a pure load/compare.
                let is_write = ii.op0_kind() == OpKind::Memory
                    && !matches!(
                        ii.mnemonic(),
                        iced_x86::Mnemonic::Cmp | iced_x86::Mnemonic::Test
                    );
                let e = map.entry((reg.clone(), disp)).or_insert_with(|| {
                    let mut s = String::new();
                    fmt.format(&ii, &mut s);
                    MemberAccess { base: reg, offset: disp, count: 0, writes: 0, lea: 0, sample: s }
                });
                e.count += 1;
                if is_write {
                    e.writes += 1;
                }
                if is_lea {
                    e.lea += 1;
                }
            }
        }
        if ii.flow_control() == iced_x86::FlowControl::Return {
            break;
        }
    }
    let mut out: Vec<MemberAccess> = map.into_values().collect();
    out.sort_by(|a, b| a.base.cmp(&b.base).then(a.offset.cmp(&b.offset)));
    out
}

/// Heuristic: does the function at `addr` look like a C++ constructor — i.e.
/// does it write a vtable pointer (a rip-relative `lea`) to `[this + 0]` in its
/// first few instructions? This distinguishes a real sub-object *constructor*
/// from any other method called via the same `lea rdi,[this+off]; call`
/// pattern (the key ambiguity in `subobject_ctors`).
pub fn sets_vptr_early(info: &BinaryInfo, addr: u64) -> bool {
    let mut buf = [0u8; 160];
    for (i, b) in buf.iter_mut().enumerate() {
        if let Some(v) = info.memory.read_byte(addr + i as u64) {
            *b = v;
        }
    }
    let mut dec = Decoder::with_ip(info.bits, &buf, addr, DecoderOptions::NONE);
    let mut ii = IcedInsn::default();
    // Registers currently holding a rip-relative lea (a candidate vtable addr),
    // and registers that alias `this` (rdi on entry, plus copies of it).
    let mut rip_lea: std::collections::HashSet<Register> = std::collections::HashSet::new();
    let mut this_regs: std::collections::HashSet<Register> = std::collections::HashSet::new();
    this_regs.insert(Register::RDI);
    let mut n = 0;
    while dec.can_decode() && n < 16 {
        dec.decode_out(&mut ii);
        if ii.is_invalid() {
            break;
        }
        n += 1;
        match ii.mnemonic() {
            iced_x86::Mnemonic::Lea if ii.memory_base() == Register::RIP => {
                rip_lea.insert(ii.op0_register());
            }
            iced_x86::Mnemonic::Mov => {
                // `mov this2, rdi` — propagate the this alias.
                if ii.op1_register() != Register::None && this_regs.contains(&ii.op1_register()) {
                    this_regs.insert(ii.op0_register());
                }
                // `mov [this + 0], rip_lea_reg` — the vtable store ⇒ ctor.
                if ii.op0_kind() == OpKind::Memory
                    && ii.memory_displacement64() == 0
                    && this_regs.contains(&ii.memory_base())
                    && rip_lea.contains(&ii.op1_register())
                {
                    return true;
                }
                // A non-lea write to a tracked reg clears its lea status.
                if ii.op0_register() != Register::None {
                    rip_lea.remove(&ii.op0_register());
                }
            }
            _ => {}
        }
        if ii.flow_control() == iced_x86::FlowControl::Return {
            break;
        }
    }
    false
}

/// Sub-object constructor map: detect `lea rdi, [base + offset]` (the SysV
/// `this` argument) shortly followed by a `call <target>` — the canonical C++
/// "construct a member/base sub-object at `offset`" pattern. Returns
/// `(offset, ctor_target)` pairs, which reconstruct the composition tree and
/// let you find which sub-constructor owns a deep field (e.g. `obj+0x1B0`).
/// With `verify_ctor`, only targets that set a vtable pointer (real ctors) are
/// kept — filtering out plain method calls on the sub-object.
pub fn subobject_ctors(info: &BinaryInfo, start: u64, max_insns: usize) -> Vec<(u64, u64)> {
    subobject_ctors_opt(info, start, max_insns, false)
}

/// As [`subobject_ctors`], but `verify_ctor` keeps only call targets whose
/// prologue writes a vtable pointer (see [`sets_vptr_early`]).
pub fn subobject_ctors_opt(
    info: &BinaryInfo,
    start: u64,
    max_insns: usize,
    verify_ctor: bool,
) -> Vec<(u64, u64)> {
    let mut v = subobject_ctors_raw(info, start, max_insns);
    if verify_ctor {
        v.retain(|(_, ctor)| sets_vptr_early(info, *ctor));
    }
    v
}

fn subobject_ctors_raw(info: &BinaryInfo, start: u64, max_insns: usize) -> Vec<(u64, u64)> {
    if !matches!(
        info.arch,
        reargo_loader::Architecture::X86_64 | reargo_loader::Architecture::X86
    ) {
        return Vec::new();
    }
    let cap = max_insns.saturating_mul(15).max(64);
    let mut buf = vec![0u8; cap];
    for (i, b) in buf.iter_mut().enumerate() {
        if let Some(v) = info.memory.read_byte(start + i as u64) {
            *b = v;
        }
    }
    let mut dec = Decoder::with_ip(info.bits, &buf, start, DecoderOptions::NONE);
    let mut ii = IcedInsn::default();
    // Pending `lea rdi, [base+off]` not yet consumed by a call (in-place ctor).
    let mut pending: Option<u64> = None;
    // Last call target, for the factory pattern `call; mov [base+off], rax`.
    let mut last_call: Option<u64> = None;
    let mut out = Vec::new();
    let mut n = 0;
    while dec.can_decode() && n < max_insns {
        dec.decode_out(&mut ii);
        if ii.is_invalid() {
            break;
        }
        n += 1;
        let m = ii.mnemonic();
        // Factory pattern: a pointer member assigned the result of a call —
        // `call make_X(); mov [base+off], rax`. Catches members like
        // `obj+0x1B0 = makeSubObject()` that aren't constructed in place.
        if m == iced_x86::Mnemonic::Mov
            && ii.op0_kind() == OpKind::Memory
            && ii.op1_register() == Register::RAX
            && ii.memory_base() != Register::RIP
            && ii.memory_base() != Register::RSP
            && let Some(ctor) = last_call
        {
            out.push((ii.memory_displacement64(), ctor));
        }
        match m {
            iced_x86::Mnemonic::Lea
                if ii.op0_register() == Register::RDI
                    && ii.memory_base() != Register::RIP =>
            {
                pending = Some(ii.memory_displacement64());
            }
            iced_x86::Mnemonic::Call => {
                last_call = if ii.near_branch_target() != 0 {
                    Some(ii.near_branch_target())
                } else {
                    None
                };
                if let Some(off) = pending.take()
                    && let Some(t) = last_call
                {
                    out.push((off, t));
                }
            }
            _ => {
                if ii.op0_register() == Register::RDI {
                    pending = None;
                }
                // rax clobbered by a non-call write ends the factory window.
                if ii.op0_register() == Register::RAX && m != iced_x86::Mnemonic::Mov {
                    last_call = None;
                }
            }
        }
        if ii.flow_control() == iced_x86::FlowControl::Return {
            break;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::helpers::make_x86_64_program;

    #[test]
    fn finds_subobject_ctors() {
        // lea rdi, [rbx+0x40]   = 48 8d 7b 40
        // call +0 (0x100c)      = e8 00 00 00 00
        // ret
        // lea rdi,[rbx+0x40] (4 bytes @0x1000) ; call rel32=0 (5 bytes @0x1004,
        // target = 0x1004+5 = 0x1009) ; ret
        let code = vec![
            0x48, 0x8d, 0x7b, 0x40, // lea rdi,[rbx+0x40]
            0xe8, 0x00, 0x00, 0x00, 0x00, // call 0x1009
            0xc3,
        ];
        let prog = make_x86_64_program(&code, 0x1000);
        let subs = subobject_ctors(&prog.info, 0x1000, 16);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].0, 0x40); // offset
        assert_eq!(subs[0].1, 0x1009); // ctor target
    }

    #[test]
    fn detects_ctor_by_vptr_store() {
        // A ctor: mov rax,[rip+x]? no — lea rax,[rip+vtable]; mov [rdi],rax; ret
        // lea rax,[rip+0]   = 48 8d 05 00 00 00 00   (vtable at 0x1007)
        // mov [rdi], rax    = 48 89 07
        // ret
        let ctor = vec![0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x07, 0xc3];
        let prog = make_x86_64_program(&ctor, 0x2000);
        assert!(sets_vptr_early(&prog.info, 0x2000));

        // A non-ctor method: just does arithmetic, no vptr store.
        // xor eax,eax; ret  = 31 c0 c3
        let method = make_x86_64_program(&[0x31, 0xc0, 0xc3], 0x3000);
        assert!(!sets_vptr_early(&method.info, 0x3000));
    }

    #[test]
    fn finds_member_writes_and_lea() {
        // mov [rbx+0x10], rax  = 48 89 43 10
        // lea  rax, [rbx+0x28] = 48 8d 43 28
        // mov  rcx, [rbx+0x10] = 48 8b 4b 10   (read of same member)
        // ret
        let code = vec![
            0x48, 0x89, 0x43, 0x10, // mov [rbx+0x10], rax
            0x48, 0x8d, 0x43, 0x28, // lea rax, [rbx+0x28]
            0x48, 0x8b, 0x4b, 0x10, // mov rcx, [rbx+0x10]
            0xc3,
        ];
        let prog = make_x86_64_program(&code, 0x1000);
        let m = member_accesses(&prog.info, 0x1000, 32);
        let at10 = m.iter().find(|x| x.offset == 0x10 && x.base == "rbx").unwrap();
        assert_eq!(at10.count, 2); // one write, one read
        assert_eq!(at10.writes, 1);
        let at28 = m.iter().find(|x| x.offset == 0x28 && x.base == "rbx").unwrap();
        assert_eq!(at28.lea, 1);
    }
}
