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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::helpers::make_x86_64_program;

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
