//! The classes of the objects a C++ class holds in its pointer fields (WS92), from its
//! constructors: `this->field_8 = new C(…)` makes `field_8` a `C*` in every method of the
//! class, so a virtual call on `this->field_8` names the slot's function there too.
//!
//! A class's constructors are the functions that store its vtable into `this`: its address
//! is referenced from code (`lea rax, [vtable]` rip-relative, or an `imm32` in a non-PIE
//! binary), found by a byte scan of the executable blocks (no analysis, like
//! `callers::direct_call_sites`), and the function covering each reference comes from the
//! `.eh_frame_hdr` table. Each such function is followed with a forward data flow of "holds
//! `this` + k" / "holds the object call `c` returned + k": the objects it stores the vtable
//! into are of the class (`this` in a constructor, a new object where the constructor is
//! inlined into a factory), and an object stored at `object + k` whose constructor the
//! function called on it (a callee storing a vtable into its first argument) or into which it
//! stored a vtable itself is of that class. The functions it calls on `this` (a base class's
//! constructor) are followed one level down for their fields too. A field whose objects
//! disagree (no class derives from all the others) is left out.

use std::sync::Arc;

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use reargo_loader::{Memory, MemoryFlags};
use rustc_hash::FxHashMap;

use crate::callee_params::{kill, CalleeParams, ClassFields, Held, SmallMap};
use crate::cfg::ControlFlowGraph;

/// Most code references of a vtable followed (constructors, destructors, other uses).
const MAX_REFS: usize = 8;
/// A tag for "the object the call at this address returned" (args are small indices).
const FRESH: usize = 1 << 62;
/// Field offsets past this are no fields.
const MAX_FIELD: i64 = 0x10_0000;

/// What one function does with `this` (tag 0) and the objects calls return to it (`FRESH`
/// tags): the class's constructor may be inlined into a factory that allocates the object.
#[derive(Default)]
struct CtorFacts {
    /// `(object, vtable)`: a vtable stored at offset 0 of the object
    vtables: Vec<(usize, u64)>,
    /// `(object, k, value)`: a returned object stored at `object + k`
    stored: Vec<(usize, u64, usize)>,
    /// `(object, callee)`: a call with the object as its first argument
    calls_on: Vec<(usize, u64)>,
}

impl CalleeParams<'_> {
    /// The fields of the class whose vtable (address point) is `vt` that its constructors set
    /// to an object of a known class: `(offset, the object's vtable)`, by offset (WS92).
    pub fn class_fields(&self, vt: u64) -> ClassFields {
        if let Some(r) = self.class_fields_memo.lock().ok().and_then(|m| m.get(&vt).cloned()) {
            return r;
        }
        let r = Arc::new(self.find_class_fields(vt));
        if let Ok(mut m) = self.class_fields_memo.lock() {
            m.insert(vt, r.clone());
        }
        r
    }

    fn find_class_fields(&self, vt: u64) -> Vec<(u64, u64)> {
        let mem = self.memory;
        let mut funcs: Vec<u64> = Vec::new();
        for site in code_refs(mem, vt, MAX_REFS) {
            if let Some(f) = function_of(mem, self.unwind_table, site)
                && !funcs.contains(&f)
            {
                funcs.push(f);
            }
        }
        let mut by_off: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
        let mut add = |k: u64, obj: u64| {
            let e = by_off.entry(k).or_default();
            if !e.contains(&obj) {
                e.push(obj);
            }
        };
        for f in funcs {
            let Some(facts) = self.ctor_facts(f) else { continue };
            // the objects the function makes of the class: it stores the vtable into them
            // (`this` in a constructor or destructor, a new object where one is inlined)
            for obj in facts.vtables.iter().filter(|o| o.1 == vt).map(|o| o.0) {
                for (k, v) in self.object_classes(&facts, obj) {
                    add(k, v);
                }
                // a base class's constructor called on `this` sets its fields
                if obj == 0 {
                    for &(_, c) in facts.calls_on.iter().filter(|c| c.0 == 0).take(4) {
                        if let Some(base) = self.ctor_facts(c) {
                            for (k, v) in self.object_classes(&base, 0) {
                                add(k, v);
                            }
                        }
                    }
                }
            }
        }
        let mut out: Vec<(u64, u64)> = by_off
            .into_iter()
            .filter_map(|(k, vts)| {
                let classes: Vec<(String, u64)> = vts.iter().filter_map(|&v| Some((crate::vcall::vtable_class(mem, v)?, v))).collect();
                (classes.len() == vts.len()).then(|| crate::vcall::most_derived(mem, &classes)).flatten().map(|(_, v)| (k, v))
            })
            .collect();
        out.sort_unstable();
        out
    }

    /// `(k, vtable)`: the objects of known class the function stores at `base + k`.
    fn object_classes(&self, facts: &CtorFacts, base: usize) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for &(_, k, obj) in facts.stored.iter().filter(|s| s.0 == base) {
            let mut vts: Vec<u64> = facts.vtables.iter().filter(|o| o.0 == obj).map(|o| o.1).collect();
            for &(_, callee) in facts.calls_on.iter().filter(|c| c.0 == obj) {
                if let Some(pu) = self.param_use(callee) {
                    vts.extend(pu.vtable_stores.iter().filter(|s| s.0 == 0).map(|s| s.1));
                }
            }
            vts.retain(|&v| crate::vcall::is_vtable_point(self.memory, v));
            vts.sort_unstable();
            vts.dedup();
            let classes: Vec<(String, u64)> = vts.iter().filter_map(|&v| Some((crate::vcall::vtable_class(self.memory, v)?, v))).collect();
            if let Some((_, v)) = crate::vcall::most_derived(self.memory, &classes) {
                out.push((k, v));
            }
        }
        out
    }

    fn ctor_facts(&self, f: u64) -> Option<CtorFacts> {
        let cfg = self.body_cfg(f)?;
        Some(ctor_facts(&cfg, self))
    }
}

/// The forward data flow of [`CtorFacts`] over one body (see the module documentation).
fn ctor_facts(cfg: &ControlFlowGraph, cp: &CalleeParams<'_>) -> CtorFacts {
    let (args, caller_saved) = (&cp.args, &cp.caller_saved);
    let ret = cp.returns.first().copied();
    let n = cfg.blocks.len();
    let mut facts = CtorFacts::default();
    let Some(this) = args.first().copied() else { return facts };
    let mut inn: Vec<Option<Held>> = vec![None; n];
    let mut entry = Held::default();
    entry.insert((this.space, this.offset, this.size), (0, 0));
    inn[cfg.entry_block] = Some(entry);
    let rpo = crate::dominator::reverse_post_order(cfg);
    fn push<T: PartialEq>(v: &mut Vec<T>, x: T) {
        if !v.contains(&x) {
            v.push(x);
        }
    }
    for _ in 0..4 {
        let mut changed = false;
        for &b in &rpo {
            let Some(mut st) = inn[b].clone() else { continue };
            let mut consts: SmallMap<(SpaceId, u64, u32), u64> = SmallMap::default();
            for insn in &cfg.blocks[b].instructions {
                for op in &insn.ops {
                    let held = |st: &Held, v: &reargo_core::pcode::VarnodeData| st.get(&(v.space, v.offset, v.size)).copied();
                    match op.opcode {
                        OpCode::Store => {
                            let (Some(a), Some(v)) = (op.inputs.get(1).and_then(|v| held(&st, v)), op.inputs.get(2)) else { continue };
                            if v.size != 8 {
                                continue;
                            }
                            let konst = if v.space == SpaceId::CONST { Some(v.offset) } else { consts.get(&(v.space, v.offset, v.size)).copied() };
                            let object = |t: usize| t == 0 || t & FRESH != 0;
                            match (a, held(&st, v), konst) {
                                ((b, k), Some((obj, 0)), _) if object(b) && obj & FRESH != 0 && (0..MAX_FIELD).contains(&k) => push(&mut facts.stored, (b, k as u64, obj)),
                                ((b, 0), _, Some(c)) if object(b) => push(&mut facts.vtables, (b, c)),
                                _ => {}
                            }
                            continue;
                        }
                        OpCode::Call | OpCode::CallInd => {
                            let callee = (op.opcode == OpCode::Call).then(|| op.inputs.first()).flatten().filter(|t| t.space == SpaceId::RAM).map(|t| t.offset);
                            if let Some(t) = callee {
                                match held(&st, &this) {
                                    Some((obj, 0)) if obj == 0 || obj & FRESH != 0 => push(&mut facts.calls_on, (obj, t)),
                                    _ => {}
                                }
                            }
                            for r in caller_saved {
                                kill(&mut st, r);
                            }
                            st.retain(|k, _| k.0 != SpaceId::UNIQUE);
                            consts.clear();
                            // the call's result: a fresh object (`operator new`)
                            if let Some(r) = ret {
                                st.insert((r.space, r.offset, r.size), (FRESH | insn.address as usize, 0));
                            }
                            continue;
                        }
                        _ => {}
                    }
                    let Some(out) = op.output else { continue };
                    let konst = |v: &reargo_core::pcode::VarnodeData| (v.space == SpaceId::CONST).then_some(v.offset as i64);
                    let v = match (op.opcode, op.inputs.as_slice()) {
                        (OpCode::Copy, [a]) => held(&st, a),
                        (OpCode::IntAdd, [a, b]) => held(&st, a).zip(konst(b)).or_else(|| held(&st, b).zip(konst(a))).map(|((i, d), k)| (i, d.wrapping_add(k))),
                        (OpCode::IntSub, [a, b]) => held(&st, a).zip(konst(b)).map(|((i, d), k)| (i, d.wrapping_sub(k))),
                        _ => None,
                    };
                    let c = match (op.opcode, op.inputs.first()) {
                        (OpCode::Copy, Some(c)) if out.size == 8 && c.space == SpaceId::CONST => Some(c.offset),
                        (OpCode::Copy, Some(c)) if out.size == 8 => consts.get(&(c.space, c.offset, c.size)).copied(),
                        _ => None,
                    };
                    // (the lifter's view sync, `eax = SUBPIECE(rax, 0)`, leaves the register it reads)
                    let sync = op.opcode == OpCode::Subpiece && op.inputs.first().is_some_and(|r| r.space == out.space && r.offset == out.offset && r.size > out.size);
                    if sync {
                        st.remove(&(out.space, out.offset, out.size));
                    } else {
                        kill(&mut st, &out);
                        consts.retain(|r, _| !(r.0 == out.space && r.1 < out.offset + u64::from(out.size) && out.offset < r.1 + u64::from(r.2)));
                    }
                    if let Some(v) = v.filter(|_| out.size == 8) {
                        st.insert((out.space, out.offset, out.size), v);
                    }
                    if let Some(c) = c {
                        consts.insert((out.space, out.offset, out.size), c);
                    }
                }
            }
            for &succ in &cfg.blocks[b].successors {
                let new = match &inn[succ] {
                    None => st.clone(),
                    Some(old) => old.iter().filter(|(k, v)| st.get(k) == Some(v)).map(|(k, v)| (*k, *v)).collect(),
                };
                if succ != cfg.entry_block && inn[succ].as_ref() != Some(&new) {
                    inn[succ] = Some(new);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    facts
}

/// The instructions that reference `target` as a constant, at most `cap`: a rip-relative
/// `lea r64, [target]` (`48|4c 8d modrm disp32`, mod 00, r/m 101), or `target` as a 32-bit
/// immediate (`mov r32, imm32`, `mov qword [reg], imm32`) when it fits.
pub(crate) fn code_refs(memory: &Memory, target: u64, cap: usize) -> Vec<u64> {
    let mut out = Vec::new();
    for block in memory.blocks() {
        if !block.flags.contains(MemoryFlags::EXECUTE) {
            continue;
        }
        let Some(data) = block.data.as_ref() else { continue };
        if data.len() < 7 {
            continue;
        }
        let start = block.start;
        // rip-relative: disp32 = target - (site + 7), at site + 3; its upper 16 bits are the same
        // for every site in a run of up to 64 KiB (as `callers::direct_call_sites`)
        let last = data.len() - 6; // sites i < last
        let mut i = 0usize;
        while i < last {
            let site = start + i as u64;
            let rel = (target as i64).wrapping_sub(site as i64 + 7);
            let low = (rel & 0xffff) as usize;
            let run = (low + 1).min(last - i);
            if i32::try_from(rel).is_ok() && i32::try_from(rel - run as i64 + 1).is_ok() {
                let needle = [(rel >> 16) as u8, (rel >> 24) as u8];
                let finder = memchr::memmem::Finder::new(&needle);
                let hay = &data[i + 5..i + 5 + run + 1];
                let mut from = 0;
                while let Some(q) = finder.find(&hay[from..]) {
                    let p = from + q;
                    from = p + 1;
                    let k = i + p;
                    if k >= i + run || !matches!(data[k], 0x48 | 0x4c) || data[k + 1] != 0x8d || data[k + 2] & 0xc7 != 0x05 {
                        continue;
                    }
                    let d = i32::from_le_bytes([data[k + 3], data[k + 4], data[k + 5], data[k + 6]]);
                    let at = start + k as u64;
                    if (at as i64).wrapping_add(7).wrapping_add(d as i64) as u64 == target {
                        out.push(at);
                        if out.len() >= cap {
                            return out;
                        }
                    }
                }
            }
            i += run;
        }
        // an absolute 32-bit immediate
        if let Ok(imm) = u32::try_from(target).map(|t| t.to_le_bytes()) {
            for p in memchr::memmem::find_iter(data, &imm) {
                let at = |back: usize| p.checked_sub(back).map(|q| start + q as u64);
                let site = if p >= 1 && (0xb8..=0xbf).contains(&data[p - 1]) {
                    // mov r32, imm32 (a REX.B prefix before it for r8d..r15d)
                    if p >= 2 && data[p - 2] == 0x41 { at(2) } else { at(1) }
                } else if p >= 3 && data[p - 2] == 0xc7 && data[p - 1] & 0xc0 == 0 && !matches!(data[p - 1] & 7, 4 | 5) && matches!(data[p - 3], 0x48 | 0x49) {
                    at(3) // mov qword [reg], imm32
                } else {
                    None
                };
                if let Some(s) = site {
                    out.push(s);
                    if out.len() >= cap {
                        return out;
                    }
                }
            }
        }
    }
    out
}

/// The entry of the function covering `addr`: its FDE in the `.eh_frame_hdr` table `hdr`; with
/// no table, the code after the `int3` padding before it (at most 4 KiB back).
pub(crate) fn function_of(memory: &Memory, hdr: Option<u64>, addr: u64) -> Option<u64> {
    if let Some(h) = hdr {
        return reargo_loader::fde_function(memory, h, addr).map(|(s, _)| s);
    }
    let block = memory.find_block(addr)?;
    let data = block.data.as_ref()?;
    let mut i = (addr - block.start) as usize;
    for _ in 0..0x1000 {
        if i == 0 {
            return Some(block.start);
        }
        if data[i - 1] == 0xcc {
            return Some(block.start + i as u64);
        }
        i -= 1;
    }
    None
}
