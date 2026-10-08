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
//! `R_X86_64_RELATIVE` relocations: [`pointer_at`] reads them from `.rela.dyn` (binary
//! search, `lld` sorts the relative relocations by offset).

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_lift::LiftedInstruction;
use reargo_loader::memory::MemoryFlags;
use reargo_loader::Memory;
use rustc_hash::{FxHashMap, FxHashSet};

const RELA_SIZE: u64 = 24;
const R_X86_64_RELATIVE: u64 = 8;
const R_AARCH64_RELATIVE: u64 = 1027;

/// The `.rela.dyn` table, when the binary has one in memory: `(start, entries)`.
fn rela_table(memory: &Memory) -> Option<(u64, u64)> {
    let block = memory.blocks().find(|b| b.name == ".rela.dyn" && b.data.is_some())?;
    Some((block.start, block.size / RELA_SIZE))
}

fn rela_entry(memory: &Memory, start: u64, i: u64) -> Option<(u64, u64, u64)> {
    let at = start + i * RELA_SIZE;
    Some((memory.read_u64(at).ok()?, memory.read_u64(at + 8).ok()?, memory.read_u64(at + 16).ok()?))
}

fn is_relative(info: u64) -> bool {
    let t = info & 0xffff_ffff;
    t == R_X86_64_RELATIVE || t == R_AARCH64_RELATIVE
}

/// The pointer stored at `addr` once the loader applied the relative relocations: the
/// relocation's addend when one targets `addr`, else the bytes in the file (`None` for 0).
pub fn pointer_at(memory: &Memory, addr: u64) -> Option<u64> {
    if let Some((start, n)) = rela_table(memory) {
        let (mut lo, mut hi) = (0u64, n);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (off, info, addend) = rela_entry(memory, start, mid)?;
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
        mem.add_block(block(".rela.dyn", 0x100, rela(&[(0x2008, 8, 0x1100), (0x2010, 8, 0x1200)]), MemoryFlags::READ));
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
}
