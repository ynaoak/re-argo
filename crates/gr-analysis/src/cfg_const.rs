//! Multi-block constant register tracker over the lifted P-code CFG.
//!
//! The existing `callsite::resolve_call_sites` walks the lifted
//! instruction stream **linearly**, so a constant established before
//! a branch is carried through the post-branch fall-through but a
//! constant flowing in along *any other* predecessor is lost. That's
//! enough for prologue → call patterns but misses the dominant
//! "format-string set in one block, used in the next" shape:
//!
//! ```asm
//!   .L_set:                  ; this block sets rdi = &fmt
//!     lea rdi, [rip + fmt]
//!     jmp .L_call
//!   .L_call:
//!     ...                    ; merge from multiple preds
//!     call printf
//! ```
//!
//! This module is the CFG-aware version: it builds basic blocks from
//! the lifted instructions, runs intra-block per-varnode constant
//! tracking, and joins predecessor states at each block entry by
//! per-key intersection (a varnode is "constant on entry" only if
//! every predecessor's exit pinned it to the same value).
//!
//! Output is a `BTreeMap<call_site_address, BTreeMap<reg_offset, u64>>`
//! of resolved register values at each call instruction. The
//! `CallSiteAnnotator` can layer this on top of the existing
//! resolver to fill in `?` args.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use gr_core::address::SpaceId;
use gr_core::pcode::OpCode;
use gr_lift::{LiftedInstruction, PcodeLift};
use gr_program::Program;
use gr_loader::Memory;

/// Constants observed on entry to each call instruction.
/// Outer key = instruction address of the Call; inner key = REGISTER
/// space offset; value = the proven constant.
pub type CallConstants = BTreeMap<u64, BTreeMap<u64, u64>>;

/// Run multi-block constant propagation across every function the
/// program knows about. Returns the merged map across functions.
pub fn build_call_constants(lifter: &dyn PcodeLift, program: &Program) -> CallConstants {
    let mut out = CallConstants::new();
    for func in program.listing.functions() {
        let max = func
            .body
            .ranges()
            .map(|r| r.size as usize)
            .sum::<usize>()
            .max(500);
        let Ok(lifted) = lifter.lift_range(&program.info.memory, func.entry_point, max) else {
            continue;
        };
        if lifted.is_empty() {
            continue;
        }
        propagate_one(&lifted, &program.info.memory, &mut out);
    }
    out
}

/// State at a P-code-op boundary: (space-id, offset) → constant.
type State = BTreeMap<(SpaceId, u64), u64>;

fn propagate_one(insns: &[LiftedInstruction], _mem: &Memory, out: &mut CallConstants) {
    if insns.is_empty() {
        return;
    }

    // Build a flat `address -> index` map up front so we can walk
    // edges in O(1).
    let mut addr_to_idx: BTreeMap<u64, usize> = BTreeMap::new();
    for (idx, insn) in insns.iter().enumerate() {
        addr_to_idx.insert(insn.address, idx);
    }

    // Determine block starts: function entry + every branch target +
    // every instruction immediately after a branch / return.
    let mut block_starts: BTreeSet<u64> = BTreeSet::new();
    block_starts.insert(insns[0].address);
    let mut prev_terminator = false;
    for insn in insns {
        if prev_terminator {
            block_starts.insert(insn.address);
        }
        prev_terminator = false;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Branch | OpCode::CBranch => {
                    if let Some(t) = op.inputs.first()
                        && t.space == SpaceId::RAM
                    {
                        block_starts.insert(t.offset);
                    }
                    if op.opcode == OpCode::Branch {
                        prev_terminator = true;
                    }
                }
                OpCode::Return | OpCode::BranchInd => prev_terminator = true,
                _ => {}
            }
        }
    }

    // Map every instruction address to its containing block start.
    // The block ends at the next block-start (exclusive).
    let starts_vec: Vec<u64> = block_starts.iter().copied().collect();
    let block_of = |addr: u64| -> u64 {
        // Largest start ≤ addr
        starts_vec
            .iter()
            .rev()
            .find(|&&s| s <= addr)
            .copied()
            .unwrap_or(addr)
    };

    // Predecessor map: block_start → set of predecessor block_starts.
    let mut preds: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (i, insn) in insns.iter().enumerate() {
        let cur_block = block_of(insn.address);
        let mut terminator = false;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Branch => {
                    if let Some(t) = op.inputs.first()
                        && t.space == SpaceId::RAM
                        && block_starts.contains(&t.offset)
                    {
                        preds.entry(t.offset).or_default().insert(cur_block);
                    }
                    terminator = true;
                }
                OpCode::CBranch => {
                    if let Some(t) = op.inputs.first()
                        && t.space == SpaceId::RAM
                        && block_starts.contains(&t.offset)
                    {
                        preds.entry(t.offset).or_default().insert(cur_block);
                    }
                }
                OpCode::Return | OpCode::BranchInd => terminator = true,
                _ => {}
            }
        }
        // Fall-through edge: if not a terminator op, the next
        // instruction in stream order — when it sits in a *different*
        // block — is a successor.
        if !terminator
            && let Some(next) = insns.get(i + 1)
        {
            let next_block = block_of(next.address);
            if next_block != cur_block {
                preds.entry(next_block).or_default().insert(cur_block);
            }
        }
    }

    // Per-block in / out states. Fixpoint until convergence (capped
    // at 8 rounds — by reducible-CFG induction we should converge
    // far sooner, but cap for safety).
    let entry = insns[0].address;
    let mut in_state: BTreeMap<u64, State> = BTreeMap::new();
    let mut out_state: BTreeMap<u64, State> = BTreeMap::new();
    in_state.insert(entry, State::new());

    for _round in 0..8 {
        let mut changed = false;
        let mut worklist: VecDeque<u64> = VecDeque::from_iter(starts_vec.iter().copied());
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        while let Some(b) = worklist.pop_front() {
            if !seen.insert(b) {
                continue;
            }
            // Join all predecessors' out states.
            let joined = if let Some(ps) = preds.get(&b) {
                if ps.is_empty() && b == entry {
                    State::new()
                } else {
                    intersect_all(ps.iter().filter_map(|p| out_state.get(p)))
                }
            } else if b == entry {
                State::new()
            } else {
                // Unreachable block — leave alone.
                continue;
            };

            let prior = in_state.get(&b).cloned();
            if prior.as_ref() != Some(&joined) {
                in_state.insert(b, joined.clone());
                changed = true;
            }

            // Walk the block's instructions to compute out.
            let block_end = starts_vec
                .iter()
                .find(|&&s| s > b)
                .copied()
                .unwrap_or(u64::MAX);
            let mut st = joined;
            let mut block_call_consts: Vec<(u64, BTreeMap<u64, u64>)> = Vec::new();
            let start_idx = match addr_to_idx.get(&b) {
                Some(&i) => i,
                None => continue,
            };
            for insn in &insns[start_idx..] {
                if insn.address >= block_end {
                    break;
                }
                for op in &insn.ops {
                    match op.opcode {
                        OpCode::Call | OpCode::CallInd => {
                            // Snapshot the REGISTER-space subset.
                            let mut regs: BTreeMap<u64, u64> = BTreeMap::new();
                            for ((sp, off), v) in &st {
                                if *sp == SpaceId::REGISTER {
                                    regs.insert(*off, *v);
                                }
                            }
                            block_call_consts.push((insn.address, regs));
                            // SysV: caller-saved registers clobbered.
                            st.retain(|(sp, _), _| *sp != SpaceId::REGISTER);
                        }
                        OpCode::Copy => {
                            apply_copy(&mut st, op);
                        }
                        OpCode::Load => {
                            // For our purposes we conservatively
                            // drop the destination's constness.
                            if let Some(dst) = op.output.as_ref() {
                                st.remove(&(dst.space, dst.offset));
                            }
                        }
                        _ => {
                            // Any other write kills constness.
                            if let Some(dst) = op.output.as_ref() {
                                st.remove(&(dst.space, dst.offset));
                            }
                        }
                    }
                }
            }
            // Record this block's call snapshots into the global map.
            for (addr, regs) in block_call_consts {
                let entry = out.entry(addr).or_default();
                // Merge — keep only values that agree with what's
                // already there (this is the same intersection rule
                // we apply at block joins).
                if entry.is_empty() {
                    *entry = regs;
                } else {
                    entry.retain(|k, v| regs.get(k) == Some(v));
                }
            }

            let prev_out = out_state.get(&b).cloned();
            if prev_out.as_ref() != Some(&st) {
                out_state.insert(b, st);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn apply_copy(st: &mut State, op: &gr_core::pcode::PcodeOp) {
    let Some(dst) = op.output.as_ref() else {
        return;
    };
    let Some(src) = op.inputs.first() else {
        st.remove(&(dst.space, dst.offset));
        return;
    };
    let v = if src.space == SpaceId::CONST {
        Some(src.offset)
    } else {
        st.get(&(src.space, src.offset)).copied()
    };
    match v {
        Some(val) => {
            st.insert((dst.space, dst.offset), val);
        }
        None => {
            st.remove(&(dst.space, dst.offset));
        }
    }
}

/// Per-key intersection — a key survives iff every input has it AND
/// every input maps it to the same value.
fn intersect_all<'a>(states: impl Iterator<Item = &'a State>) -> State {
    let collected: Vec<&State> = states.collect();
    if collected.is_empty() {
        return State::new();
    }
    let mut out = collected[0].clone();
    for other in &collected[1..] {
        out.retain(|k, v| other.get(k) == Some(v));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersect_keeps_agreeing_keys() {
        let mut a = State::new();
        a.insert((SpaceId::REGISTER, 0x38), 0xaa);
        a.insert((SpaceId::REGISTER, 0x30), 0xbb);
        let mut b = State::new();
        b.insert((SpaceId::REGISTER, 0x38), 0xaa);
        b.insert((SpaceId::REGISTER, 0x30), 0xcc); // disagrees
        let out = intersect_all([&a, &b].into_iter());
        assert_eq!(out.get(&(SpaceId::REGISTER, 0x38)), Some(&0xaa));
        assert_eq!(out.get(&(SpaceId::REGISTER, 0x30)), None);
    }

    #[test]
    fn intersect_empty_singleton() {
        let states: Vec<&State> = Vec::new();
        let out = intersect_all(states.into_iter());
        assert!(out.is_empty());
    }
}
