//! Resolve `call rax` / `call qword ptr [rip+got]` indirect calls
//! by walking lifted P-code backwards from the call site.
//!
//! The existing `IndirectCallAnalyzer` (indirect.rs) uses a coarse
//! "first import within 1 MiB" heuristic that's right often enough
//! to add some value but wrong often enough that downstream analyzers
//! had to filter its output out (see filters in anti_debug / exception).
//!
//! Modern compilers actually make this resolution easy: a
//! representative pattern is
//!
//! ```asm
//!   mov rax, qword ptr [rip + got_printf]   ; rax = *got_printf = printf
//!   ...
//!   call rax
//! ```
//!
//! And our lifter is already folding the `[rip + got_printf]`
//! displacement into a CONST varnode at lift time. So we just need
//! to walk back through the lifted P-code from each CallInd and
//! find the most recent op that wrote the call-target varnode.
//! If that write resolves to a CONST that lands on a known GOT
//! slot (i.e., on a name in the import table), the call is
//! actually a direct call to the named import.
//!
//! We add an `UnconditionalCall` reference (so downstream analyzers
//! see it the same way as a static call) but stop short of
//! mutating the listing — the call instruction is still an
//! IndirectCall at the disasm level; we just augment the
//! reference graph.

use std::collections::BTreeMap;

use gr_core::address::SpaceId;
use gr_core::pcode::OpCode;
use gr_lift::PcodeLift;
use gr_program::reference::{RefType, Reference};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct IndirectCallResolver;

impl Analyzer for IndirectCallResolver {
    fn name(&self) -> &str {
        "Indirect Call Resolver"
    }
    fn description(&self) -> &str {
        "Resolves call <reg> by walking lifted P-code back to find the constant load"
    }
    fn priority(&self) -> u32 {
        // BEFORE the legacy IndirectCallAnalyzer (580). The legacy
        // analyzer's "nearest import within 1 MiB" heuristic
        // pollutes `references` with low-confidence guesses; by
        // running first we lay down high-confidence resolutions
        // that the legacy analyzer's dedup check then skips.
        575
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, gr_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        // Build a GOT-address → import name map.
        let by_got: BTreeMap<u64, &str> = program
            .info
            .imports
            .iter()
            .map(|imp| (imp.got_address, imp.name.as_str()))
            .collect();
        if by_got.is_empty() {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        // (1) Bytewise pass over decoded instructions for the dominant
        // `call qword ptr [rip+disp32]` and `jmp qword ptr [rip+disp32]`
        // shapes. Lifter currently folds these into plain `Call` /
        // `Branch` placeholders so the P-code walk below would miss
        // them; resolving at the instruction-byte level here catches
        // the common case while staying provably correct.
        let mut resolved: Vec<(u64, u64)> = Vec::new();
        for insn in program.listing.instructions() {
            if let Some(target_got) = parse_call_rip_disp32(insn.address, insn.length, &insn.bytes)
                && by_got.contains_key(&target_got)
                && let Some(name) = by_got.get(&target_got)
                && let Some(imp) = program.info.imports.iter().find(|i| i.name == *name)
            {
                resolved.push((insn.address, imp.plt_address));
            }
        }

        let lifter: Box<dyn PcodeLift> = Box::new(gr_lift::x86::X86Lifter::new_64());

        // (2) P-code walk for `call <reg>` patterns where the lifter
        // does emit `CallInd` — caller-saved-aware constness map per
        // varnode `(space, offset)` key. Size is ignored so 4-byte
        // and 8-byte writes both kill the prior constant; good
        // enough for the GOT-load pattern.
        for func in program.listing.functions() {
            let max_insns = func
                .body
                .ranges()
                .map(|r| r.size as usize)
                .sum::<usize>()
                .max(200);
            let Ok(lifted) = lifter.lift_range(&program.info.memory, func.entry_point, max_insns)
            else {
                continue;
            };

            let mut const_for: BTreeMap<(SpaceId, u64), u64> = BTreeMap::new();
            for insn in &lifted {
                for op in &insn.ops {
                    match op.opcode {
                        OpCode::Copy => {
                            // `dst = src` — propagate constness if
                            // the source is a CONST or an alias of a
                            // known constant register.
                            if let Some(dst) = op.output.as_ref()
                                && let Some(src) = op.inputs.first()
                            {
                                let v = if src.space == SpaceId::CONST {
                                    Some(src.offset)
                                } else {
                                    const_for.get(&(src.space, src.offset)).copied()
                                };
                                let dst_key = (dst.space, dst.offset);
                                match v {
                                    Some(val) => {
                                        const_for.insert(dst_key, val);
                                    }
                                    None => {
                                        const_for.remove(&dst_key);
                                    }
                                }
                            }
                        }
                        OpCode::Load => {
                            // `dst = LOAD(space, addr)` — when addr
                            // is a CONST we know to be a GOT slot,
                            // tag dst with the *import's plt
                            // address* (the eventual call target).
                            if let Some(dst) = op.output.as_ref()
                                && op.inputs.len() == 2
                            {
                                let addr_vn = &op.inputs[1];
                                let v = if addr_vn.space == SpaceId::CONST {
                                    Some(addr_vn.offset)
                                } else {
                                    const_for.get(&(addr_vn.space, addr_vn.offset)).copied()
                                };
                                if let Some(addr_val) = v
                                    && let Some(name) = by_got.get(&addr_val)
                                {
                                    // Resolve to the matching PLT
                                    // address from `imports` — that's
                                    // what `IndirectCallAnalyzer`
                                    // emits and what the symbol table
                                    // already names as `<name>@plt`.
                                    if let Some(imp) =
                                        program.info.imports.iter().find(|i| i.name == *name)
                                    {
                                        const_for.insert(
                                            (dst.space, dst.offset),
                                            imp.plt_address,
                                        );
                                        continue;
                                    }
                                }
                                const_for.remove(&(dst.space, dst.offset));
                            }
                        }
                        OpCode::Call | OpCode::CallInd => {
                            // Find the call-target varnode. For
                            // CALLIND it's input[0] (the indirect
                            // target); for CALL the input is usually
                            // already a CONST and gets handled by the
                            // direct call resolver.
                            if op.opcode == OpCode::CallInd
                                && let Some(t) = op.inputs.first()
                            {
                                let v = if t.space == SpaceId::CONST {
                                    Some(t.offset)
                                } else {
                                    const_for.get(&(t.space, t.offset)).copied()
                                };
                                if let Some(target) = v
                                    && target != 0
                                {
                                    resolved.push((insn.address, target));
                                }
                            }
                            // Per SysV every caller-saved register
                            // is clobbered across a call. Be
                            // conservative and drop the whole map —
                            // the alternative is hard-coding a
                            // preserved-register set we'd have to
                            // keep in sync with the call-conv DB.
                            const_for.clear();
                        }
                        _ => {
                            // Any other write kills the constness
                            // of its output (we don't model arithmetic).
                            if let Some(dst) = op.output.as_ref() {
                                const_for.remove(&(dst.space, dst.offset));
                            }
                        }
                    }
                }
            }
        }

        // Dedupe against existing references from each call site.
        let mut added = 0usize;
        for (from, to) in resolved {
            let already = program
                .references
                .get_refs_from(from)
                .iter()
                .any(|r| r.to == to);
            if already {
                continue;
            }
            program
                .references
                .add(Reference::new(from, to, RefType::UnconditionalCall));
            added += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: added,
            instructions_decoded: 0,
        })
    }
}

/// Decode `ff 15 disp32` (CALL m64) and `ff 25 disp32` (JMP m64)
/// — both are RIP-relative memory-operand transfers and the most
/// common shape for "indirect call through GOT". Returns the target
/// memory address the instruction will dereference: the GOT slot we
/// then map back to the import.
fn parse_call_rip_disp32(addr: u64, length: u32, bytes: &[u8]) -> Option<u64> {
    // Optional REX.B (0x41) prefix doesn't change the effective
    // address calculation but does shift the opcode byte index.
    let off = if bytes.first() == Some(&0x41) { 1 } else { 0 };
    if bytes.len() < off + 6 {
        return None;
    }
    if bytes[off] != 0xff {
        return None;
    }
    // ModR/M: mod=00, r/m=101 selects RIP-relative; reg field is
    // /2 (CALL m64) or /4 (JMP m64).
    let modrm = bytes[off + 1];
    let mod_ = modrm >> 6;
    let rm = modrm & 0x07;
    let reg = (modrm >> 3) & 0x07;
    if mod_ != 0 || rm != 5 {
        return None;
    }
    if reg != 2 && reg != 4 {
        return None;
    }
    let disp = i32::from_le_bytes([
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
    ]) as i64;
    let fall = addr + length as u64;
    Some((fall as i64).wrapping_add(disp) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_compiles() {
        let _ = IndirectCallResolver;
    }

    #[test]
    fn parse_call_rip_basic() {
        // ff 15 disp32 — call qword ptr [rip+0x40]
        let bytes = [0xff, 0x15, 0x40, 0x00, 0x00, 0x00];
        let target = parse_call_rip_disp32(0x1000, 6, &bytes).unwrap();
        assert_eq!(target, 0x1000 + 6 + 0x40);
    }

    #[test]
    fn parse_jmp_rip_basic() {
        // ff 25 disp32 — jmp qword ptr [rip+disp32]
        let bytes = [0xff, 0x25, 0x10, 0x00, 0x00, 0x00];
        let target = parse_call_rip_disp32(0x2000, 6, &bytes).unwrap();
        assert_eq!(target, 0x2000 + 6 + 0x10);
    }

    #[test]
    fn parse_call_rip_negative() {
        let bytes = [0xff, 0x15, 0xf0, 0xff, 0xff, 0xff];
        let target = parse_call_rip_disp32(0x3000, 6, &bytes).unwrap();
        assert_eq!(target, 0x3000 + 6 - 0x10);
    }

    #[test]
    fn parse_call_register_rejected() {
        // ff d0 — call rax — register operand, not memory
        assert!(parse_call_rip_disp32(0x1000, 2, &[0xff, 0xd0]).is_none());
    }

    #[test]
    fn parse_non_call_rejected() {
        // 48 89 e5 — mov rbp, rsp
        assert!(parse_call_rip_disp32(0x1000, 3, &[0x48, 0x89, 0xe5]).is_none());
    }
}
