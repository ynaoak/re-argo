//! Indirect calls whose target can be known (WS79).
//!
//! * [`devirtualize_constant_calls`]: the target is a compile-time constant — a function
//!   pointer or a vtable slot read from read-only data — so the call becomes a direct call.
//! * [`this_vtables`] / [`resolve_this_vcalls`]: a virtual call on the function's own
//!   `this` (`mov rax, [rdi]; call [rax+0x18]`) inside a method found in a vtable. The object
//!   is at least of that class, so the slot's entry in its vtable is an implementation of the
//!   called method: every override takes the same parameters, which gives the call's
//!   argument set (`callee_params`) instead of the set-up heuristic, and the slot's function
//!   is named in the call's comment. The call stays indirect (a derived class may override).
//!
//! In a PIE binary the pointers in `.data.rel.ro` are zero in the file and live in
//! `R_X86_64_RELATIVE` relocations: [`pointer_at`] reads them from the dynamic relocation
//! table the loader keeps beside the memory (`Memory::dynamic_relocations`; binary search,
//! `lld` sorts the relative relocations by offset).

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_lift::LiftedInstruction;
use reargo_loader::memory::MemoryFlags;
use reargo_loader::Memory;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::callee_params::CalleeParams;
use crate::ssa::{SsaFunction, VarId};

const RELA_SIZE: u64 = 24;
const R_X86_64_RELATIVE: u64 = 8;
const R_AARCH64_RELATIVE: u64 = 1027;

/// Entry `i` of a raw `Elf64_Rela` table: `(r_offset, r_info, r_addend)`.
fn rela_entry(table: &[u8], i: usize) -> (u64, u64, u64) {
    let w = |k: usize| u64::from_le_bytes(table[i * 24 + k * 8..i * 24 + k * 8 + 8].try_into().unwrap());
    (w(0), w(1), w(2))
}

fn is_relative(info: u64) -> bool {
    let t = info & 0xffff_ffff;
    t == R_X86_64_RELATIVE || t == R_AARCH64_RELATIVE
}

/// The pointer stored at `addr` once the loader applied the relative relocations: the
/// relocation's addend when one targets `addr`, else the bytes in the file (`None` for 0).
pub fn pointer_at(memory: &Memory, addr: u64) -> Option<u64> {
    if let Some(table) = memory.dynamic_relocations() {
        let (mut lo, mut hi) = (0usize, table.len() / RELA_SIZE as usize);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (off, info, addend) = rela_entry(table, mid);
            if off == addr {
                if is_relative(info) {
                    return Some(addend);
                }
                break;
            }
            if off < addr {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
    }
    memory.read_u64(addr).ok().filter(|&v| v != 0)
}

fn is_code(memory: &Memory, addr: u64) -> bool {
    memory.find_block(addr).is_some_and(|b| b.flags.contains(MemoryFlags::EXECUTE))
}

/// A pointer read from data the program does not change: non-writable, or relocated
/// read-only after start-up (`.data.rel.ro`); not the `.got` (filled by the dynamic linker).
fn read_only_pointer(memory: &Memory, addr: u64) -> Option<u64> {
    let block = memory.find_block(addr)?;
    let ro = !block.flags.contains(MemoryFlags::WRITE)
        || block.name.starts_with(".data.rel.ro")
        || block.name.starts_with(".rodata");
    if !ro || block.name.starts_with(".got") {
        return None;
    }
    pointer_at(memory, addr)
}

/// An indirect call whose target is a compile-time constant — a function pointer or vtable
/// slot read from read-only data (`lea rax, [vtbl]; call [rax+0x18]`, `call [rip+fnptr]`) —
/// becomes a direct call to that function, so it gets its name, its parameters
/// (`callee_params`) and its return register. A light constant tracker per basic block:
/// `COPY` / `INT_ADD` / `INT_SUB` of known values and 8-byte `LOAD`s of read-only pointers;
/// a call or a block start forgets everything. The target must lie in executable memory.
pub fn devirtualize_constant_calls(mut instructions: Vec<LiftedInstruction>, memory: &Memory) -> Vec<LiftedInstruction> {
    let leaders: FxHashSet<u64> = instructions
        .iter()
        .flat_map(|i| i.ops.iter())
        .filter(|o| matches!(o.opcode, OpCode::Branch | OpCode::CBranch))
        .filter_map(|o| o.inputs.first().filter(|t| t.space == SpaceId::RAM).map(|t| t.offset))
        .collect();
    let key = |v: &VarnodeData| (v.space, v.offset, v.size);
    let mut known: FxHashMap<(SpaceId, u64, u32), u64> = FxHashMap::default();
    for insn in &mut instructions {
        if leaders.contains(&insn.address) {
            known.clear();
        }
        let mut ends_block = false;
        for op in insn.ops.iter_mut() {
            let val = |v: &VarnodeData, known: &FxHashMap<_, u64>| {
                if v.space == SpaceId::CONST { Some(v.offset) } else { known.get(&key(v)).copied() }
            };
            match op.opcode {
                OpCode::CallInd => {
                    if let Some(t) = op.inputs.first().and_then(|v| val(v, &known))
                        && is_code(memory, t)
                    {
                        op.opcode = OpCode::Call;
                        op.inputs[0] = VarnodeData::new(SpaceId::RAM, t, 8);
                    }
                    known.clear();
                    continue;
                }
                OpCode::Call => {
                    known.clear();
                    continue;
                }
                OpCode::Branch | OpCode::CBranch | OpCode::BranchInd | OpCode::Return => {
                    ends_block = true;
                    continue;
                }
                _ => {}
            }
            let Some(out) = op.output else { continue };
            let v = match op.opcode {
                OpCode::Copy => op.inputs.first().and_then(|a| val(a, &known)),
                OpCode::IntAdd if op.inputs.len() == 2 => {
                    val(&op.inputs[0], &known).zip(val(&op.inputs[1], &known)).map(|(a, b)| a.wrapping_add(b))
                }
                OpCode::IntSub if op.inputs.len() == 2 => {
                    val(&op.inputs[0], &known).zip(val(&op.inputs[1], &known)).map(|(a, b)| a.wrapping_sub(b))
                }
                OpCode::Load if out.size == 8 && op.inputs.len() == 2 => {
                    val(&op.inputs[1], &known).and_then(|a| read_only_pointer(memory, a))
                }
                _ => None,
            };
            // a write ends what was known about every overlapping view of the location — but
            // the lifter's view sync (`eax = SUBPIECE(rax, 0)`) leaves the register it reads alone
            let sync = op.opcode == OpCode::Subpiece
                && op.inputs.first().is_some_and(|r| r.space == out.space && r.offset == out.offset && r.size > out.size);
            if sync {
                known.remove(&key(&out));
            } else {
                known.retain(|k, _| !(k.0 == out.space && k.1 < out.offset + out.size as u64 && out.offset < k.1 + k.2 as u64));
            }
            if let Some(v) = v {
                known.insert(key(&out), v);
            }
        }
        if ends_block {
            known.clear();
        }
    }
    instructions
}

/// At most this many vtables are looked at for one method.
const MAX_VTABLES: usize = 8;

/// The vtables (address points: the address of slot 0) that list `entry` as a slot: the
/// classes `entry` is a virtual method of. A slot is found through the relative relocations
/// whose addend is `entry` (a PIE), or as the pointer itself in `.data.rel.ro` / `.rodata`;
/// the address point is where the run of code pointers before it starts, behind the
/// type_info pointer and an offset-to-top of 0 or a small negative number.
pub fn this_vtables(memory: &Memory, entry: u64) -> Vec<u64> {
    let mut slots = Vec::new();
    if let Some(data) = memory.dynamic_relocations() {
        for e in data.chunks_exact(RELA_SIZE as usize) {
            let word = |i: usize| u64::from_le_bytes(e[i * 8..i * 8 + 8].try_into().unwrap());
            if word(2) == entry && is_relative(word(1)) {
                slots.push(word(0));
            }
        }
    } else {
        for b in memory.blocks() {
            if !(b.name.starts_with(".data.rel.ro") || b.name.starts_with(".rodata")) {
                continue;
            }
            let Some(data) = &b.data else { continue };
            let skip = ((8 - b.start % 8) % 8) as usize;
            for (i, w) in data.get(skip..).unwrap_or(&[]).chunks_exact(8).enumerate() {
                if u64::from_le_bytes(w.try_into().unwrap()) == entry {
                    slots.push(b.start + skip as u64 + i as u64 * 8);
                }
            }
        }
    }
    let mut points = Vec::new();
    for s in slots {
        let mut p = s;
        let mut steps = 0;
        while steps < 4096 && pointer_at(memory, p - 8).is_some_and(|v| is_code(memory, v)) {
            p -= 8;
            steps += 1;
        }
        let type_info = pointer_at(memory, p - 8);
        let offset_to_top = memory.read_u64(p - 16).ok().map(|v| v as i64);
        let looks_like_vtable = type_info.is_some_and(|t| memory.find_block(t).is_some() && !is_code(memory, t))
            && offset_to_top.is_some_and(|o| (-0x10_0000..=0).contains(&o));
        if looks_like_vtable && !points.contains(&p) {
            points.push(p);
            if points.len() >= MAX_VTABLES {
                break;
            }
        }
    }
    points
}

/// `v` with register / temporary copies looked through.
fn strip_copies(ssa: &SsaFunction, mut v: VarId) -> VarId {
    for _ in 0..16 {
        match ssa.varnodes[v as usize].def_op.map(|d| &ssa.ops[d]) {
            Some(op) if op.opcode == OpCode::Copy && op.inputs.len() == 1
                && ssa.varnodes[op.inputs[0] as usize].data.space != SpaceId::CONST => v = op.inputs[0],
            _ => break,
        }
    }
    v
}

/// The vtable byte offset of an indirect call through the vtable of the object `this`
/// points to on entry (`*(*this + off)`), if `target` is such a slot load.
fn this_slot(ssa: &SsaFunction, target: VarId, this_reg: &VarnodeData) -> Option<u64> {
    let def = |v: VarId| ssa.varnodes[v as usize].def_op.map(|d| &ssa.ops[d]);
    let load = def(strip_copies(ssa, target)).filter(|o| o.opcode == OpCode::Load && o.inputs.len() == 2)?;
    let addr = strip_copies(ssa, load.inputs[1]);
    let (vt, off) = match def(addr) {
        Some(o) if o.opcode == OpCode::IntAdd && o.inputs.len() == 2 => {
            let c = |v: VarId| {
                let d = &ssa.varnodes[v as usize].data;
                (d.space == SpaceId::CONST).then_some(d.offset)
            };
            match (c(o.inputs[0]), c(o.inputs[1])) {
                (None, Some(k)) => (strip_copies(ssa, o.inputs[0]), k),
                (Some(k), None) => (strip_copies(ssa, o.inputs[1]), k),
                _ => return None,
            }
        }
        _ => (addr, 0),
    };
    let vload = def(vt).filter(|o| o.opcode == OpCode::Load && o.inputs.len() == 2)?;
    let obj = &ssa.varnodes[strip_copies(ssa, vload.inputs[1]) as usize];
    (obj.def_op.is_none()
        && obj.data.space == this_reg.space
        && obj.data.offset == this_reg.offset
        && obj.data.size == this_reg.size
        && off % 8 == 0
        && off < 0x10000)
        .then_some(off)
}

/// Virtual calls on `this` resolved through the vtables of the classes the function is a
/// method of: the call's slot in each of those vtables holds an implementation of the called
/// method (the class's own or an override). The first is named in the call's comment
/// (`SsaFunction::vcall_targets`). When `oracle` analyses them, the call gets the union of
/// their parameter sets (`SsaFunction::call_params`): every implementation takes the same
/// parameters, but one may ignore some (a base class's `return false;`), so the union is
/// the closest to the method's real arity.
pub fn resolve_this_vcalls(
    ssa: &mut SsaFunction,
    memory: &Memory,
    vtables: &[u64],
    this_reg: &VarnodeData,
    oracle: Option<&CalleeParams<'_>>,
) {
    let mut found = Vec::new();
    for op in &ssa.ops {
        if op.opcode != OpCode::CallInd {
            continue;
        }
        let Some(&t) = op.inputs.first() else { continue };
        let Some(off) = this_slot(ssa, t, this_reg) else { continue };
        let mut targets: Vec<u64> = Vec::new();
        for &p in vtables {
            if let Some(f) = pointer_at(memory, p + off).filter(|&f| is_code(memory, f))
                && !targets.contains(&f)
            {
                targets.push(f);
            }
        }
        if !targets.is_empty() {
            found.push((op.address, targets));
        }
    }
    for (at, targets) in found {
        ssa.vcall_targets.insert(at, targets[0]);
        if let Some(o) = oracle {
            let infos: Vec<_> = targets.iter().filter_map(|&f| o.params(f)).collect();
            if !infos.is_empty() {
                let info = crate::callee_params::ParamInfo {
                    mask: infos.iter().fold(0, |m, i| m | i.mask),
                    complete: infos.len() == targets.len() && infos.iter().all(|i| i.complete),
                };
                ssa.call_params.insert(at, info);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Endian;
    use reargo_lift::x86::X86Lifter;
    use reargo_lift::PcodeLift;
    use reargo_loader::memory::MemoryBlock;
    use std::sync::Arc;

    fn block(name: &str, start: u64, data: Vec<u8>, flags: MemoryFlags) -> MemoryBlock {
        MemoryBlock { name: name.into(), start, size: data.len() as u64, flags, data: Some(Arc::from(data.as_slice())) }
    }

    fn rela(entries: &[(u64, u64, u64)]) -> Vec<u8> {
        entries.iter().flat_map(|&(o, i, a)| [o.to_le_bytes(), i.to_le_bytes(), a.to_le_bytes()].concat()).collect()
    }

    /// A PIE: `.data.rel.ro` is zero in the file, its pointers are relative relocations.
    fn pie(code: &[u8]) -> Memory {
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.set_dynamic_relocations(Arc::from(rela(&[(0x2008, 8, 0x1100), (0x2010, 8, 0x1200)])));
        let mut text = code.to_vec();
        text.resize(0x300, 0xcc);
        mem.add_block(block(".text", 0x1000, text, MemoryFlags::READ | MemoryFlags::EXECUTE));
        mem.add_block(block(".data.rel.ro", 0x2000, vec![0; 0x20], MemoryFlags::READ | MemoryFlags::WRITE));
        mem.add_block(block(".data", 0x3000, vec![0x00, 0x11, 0, 0, 0, 0, 0, 0], MemoryFlags::READ | MemoryFlags::WRITE));
        mem
    }

    #[test]
    fn pointer_at_reads_the_relative_relocation() {
        let mem = pie(&[]);
        assert_eq!(pointer_at(&mem, 0x2008), Some(0x1100));
        assert_eq!(pointer_at(&mem, 0x2010), Some(0x1200));
        assert_eq!(pointer_at(&mem, 0x2018), None, "no relocation and zero in the file");
    }

    fn lift(mem: &Memory, n: usize) -> Vec<LiftedInstruction> {
        X86Lifter::new_64().lift_range(mem, 0x1000, n).unwrap()
    }

    #[test]
    fn call_through_relocated_vtable_slot_becomes_direct() {
        // lea rax, [0x2000] ; call [rax+8]
        let mem = pie(&[0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0xff, 0x50, 0x08]);
        let insns = devirtualize_constant_calls(lift(&mem, 2), &mem);
        let call = insns[1].ops.iter().find(|o| matches!(o.opcode, OpCode::Call | OpCode::CallInd)).unwrap();
        assert_eq!(call.opcode, OpCode::Call);
        assert_eq!(call.inputs[0], VarnodeData::new(SpaceId::RAM, 0x1100, 8));
    }

    #[test]
    fn pointer_in_writable_data_is_not_trusted() {
        // call [rip+0x1ff4] -> [0x3000] in .data (the program may change it)
        let mem = pie(&[0xff, 0x15, 0xfa, 0x1f, 0x00, 0x00]);
        let insns = devirtualize_constant_calls(lift(&mem, 1), &mem);
        assert!(insns[0].ops.iter().any(|o| o.opcode == OpCode::CallInd));
    }

    /// A class with vtable at 0x2010: slot 0 = the method at 0x1000, slot 1 = 0x1200.
    fn class_binary() -> Memory {
        let mut text = vec![0xccu8; 0x300];
        let m: &[u8] = &[
            0x48, 0x8b, 0x07, // 0x1000 mov rax, [rdi]
            0xba, 0x05, 0x00, 0x00, 0x00, // mov edx, 5 (a leftover, not an argument)
            0xff, 0x50, 0x08, // call [rax+8]
            0xc3,
        ];
        let f1: &[u8] = &[0x89, 0xf0, 0x01, 0xf8, 0xc3]; // 0x1200 mov eax, esi ; add eax, edi ; ret
        text[..m.len()].copy_from_slice(m);
        text[0x200..0x200 + f1.len()].copy_from_slice(f1);
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.set_dynamic_relocations(Arc::from(rela(&[(0x2008, 8, 0x2100), (0x2010, 8, 0x1000), (0x2018, 8, 0x1200)])));
        mem.add_block(block(".text", 0x1000, text, MemoryFlags::READ | MemoryFlags::EXECUTE));
        mem.add_block(block(".data.rel.ro", 0x2000, vec![0; 0x120], MemoryFlags::READ | MemoryFlags::WRITE));
        mem
    }

    #[test]
    fn method_finds_its_class_vtable() {
        assert_eq!(this_vtables(&class_binary(), 0x1000), vec![0x2010]);
        assert_eq!(this_vtables(&class_binary(), 0x1200), vec![0x2010]);
        assert!(this_vtables(&class_binary(), 0x1100).is_empty());
    }

    #[test]
    fn virtual_call_on_this_takes_the_slot_functions_parameters() {
        let mem = class_binary();
        let c = crate::pipeline::decompile(&X86Lifter::new_64(), &mem, 0x1000, "m", 100).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("(*")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("(rdi, rsi)"), "{c}");
        assert!(call.contains("e.g. 0x1200"), "{c}");
    }

    /// A derived class (vtable at 0x2050) inherits the method and overrides slot 1 with a
    /// function that also reads `rdx`: the call's arguments are the union.
    #[test]
    fn virtual_call_arguments_are_the_union_over_overrides() {
        let mut mem = class_binary();
        let mut text = vec![0xccu8; 0x400];
        let m: &[u8] = &[0x48, 0x8b, 0x07, 0xba, 0x05, 0x00, 0x00, 0x00, 0xff, 0x50, 0x08, 0xc3];
        text[..m.len()].copy_from_slice(m);
        text[0x200..0x205].copy_from_slice(&[0x89, 0xf0, 0x01, 0xf8, 0xc3]);
        text[0x300..0x303].copy_from_slice(&[0x89, 0xd0, 0xc3]); // 0x1300 mov eax, edx ; ret
        mem.add_block(block(".text", 0x1000, text, MemoryFlags::READ | MemoryFlags::EXECUTE));
        mem.set_dynamic_relocations(Arc::from(rela(&[
            (0x2008, 8, 0x2100),
            (0x2010, 8, 0x1000),
            (0x2018, 8, 0x1200),
            (0x2048, 8, 0x2100),
            (0x2050, 8, 0x1000),
            (0x2058, 8, 0x1300),
        ])));
        assert_eq!(this_vtables(&mem, 0x1000), vec![0x2010, 0x2050]);
        let c = crate::pipeline::decompile(&X86Lifter::new_64(), &mem, 0x1000, "m", 100).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("(*")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("(rdi, rsi, "), "{c}");
    }
}
