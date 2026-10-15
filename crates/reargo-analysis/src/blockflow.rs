//! Forward data flow over the basic blocks of one function's lifted
//! P-code, shared by `cfg_const` (point constants) and `vsa` (value
//! sets). Records the state at every call instruction.
//!
//! Blocks start at the function entry, at every jump target inside the
//! lift and after every instruction that jumps or returns; each edge
//! carries the state at its jump: a conditional jump's taken edge the
//! state when it jumps, the fall-through the state at the end of the
//! block. (Edges taken from the end of the block would give
//! `je L; …; mov ecx, 0xe0; jmp M` an `ecx = 0xe0` at `L`.) A block's
//! entry state joins the states of the edges into it that have been
//! computed; blocks no edge reaches (jump-table cases, code past the
//! function) are not walked.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, PcodeOp};
use reargo_lift::LiftedInstruction;

/// Per-block visit cap, so an irreducible / cycle-heavy CFG cannot
/// loop forever; reducible CFGs converge in a few visits. A block
/// visited this often is walked a last time from the empty state
/// (nothing known), which stays sound whatever its inputs become.
const MAX_VISITS_PER_BLOCK: usize = 8;

/// A data-flow state.
pub trait FlowState: Clone + PartialEq + Default {
    /// Join at a control-flow merge.
    fn join(&self, other: &Self) -> Self;
    /// Apply a non-call, non-branch op.
    fn apply(&mut self, op: &PcodeOp);
    /// Clobber what a call clobbers.
    fn after_call(&mut self);
}

/// Jump target of a `Branch` / `CBranch` inside the lift.
fn target(op: &PcodeOp) -> Option<u64> {
    op.inputs
        .first()
        .filter(|t| t.space == SpaceId::RAM)
        .map(|t| t.offset)
}

/// Run the flow over `insns` (one function's lift, entry first) and
/// return `(call address, snapshot(state at the call))` for every
/// visit of every call.
///
/// Blocks starting at an address of `external` (entered by a jump the
/// lift does not show, see [`crate::func_lift::external_entries`]) and
/// blocks of the function's extent (`in_body`) that no jump or
/// fall-through from the entry reaches (unrecovered jump-table cases)
/// start from the empty state: what reaches them is unknown. Other
/// unreached blocks (code past the function's end) are not walked.
pub fn propagate<S: FlowState, T>(
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
    in_body: impl Fn(u64) -> bool,
    snapshot: impl Fn(&S) -> T,
) -> Vec<(u64, T)> {
    let mut snaps = Vec::new();
    let Some(first) = insns.first() else {
        return snaps;
    };
    let entry = first.address;
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn)| (insn.address, i))
        .collect();

    let mut starts: BTreeSet<u64> = BTreeSet::new();
    starts.insert(entry);
    starts.extend(external.iter().filter(|a| index.contains_key(a)));
    let mut ends_block = false;
    for insn in insns {
        if ends_block {
            starts.insert(insn.address);
        }
        ends_block = false;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Branch | OpCode::CBranch => {
                    if let Some(t) = target(op)
                        && index.contains_key(&t)
                    {
                        starts.insert(t);
                    }
                    ends_block = true;
                }
                OpCode::Return | OpCode::BranchInd => ends_block = true,
                _ => {}
            }
        }
    }
    let starts_vec: Vec<u64> = starts.iter().copied().collect();
    let block_end = |b: u64| {
        starts_vec
            .get(starts_vec.partition_point(|&s| s <= b))
            .copied()
            .unwrap_or(u64::MAX)
    };

    // Static successors, to find the blocks the entry reaches.
    let mut succs: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &b in &starts_vec {
        let end = block_end(b);
        let mut out = Vec::new();
        let mut falls = true;
        for insn in insns[index[&b]..].iter().take_while(|i| i.address < end) {
            for op in &insn.ops {
                match op.opcode {
                    OpCode::CBranch | OpCode::Branch => {
                        out.extend(target(op).filter(|t| starts.contains(t)));
                        if op.opcode == OpCode::Branch {
                            falls = false;
                        }
                    }
                    OpCode::Return | OpCode::BranchInd => falls = false,
                    _ => {}
                }
            }
            if !falls {
                break;
            }
        }
        if falls && index.contains_key(&end) {
            out.push(end);
        }
        succs.insert(b, out);
    }
    let mut reached: BTreeSet<u64> = BTreeSet::from([entry]);
    let mut stack = vec![entry];
    while let Some(b) = stack.pop() {
        for s in succs.get(&b).into_iter().flatten() {
            if reached.insert(*s) {
                stack.push(*s);
            }
        }
    }
    // Blocks entered from somewhere unknown: walked from the empty state.
    let unknown_entry: BTreeSet<u64> = starts_vec
        .iter()
        .copied()
        .filter(|b| *b != entry && (external.contains(b) || (!reached.contains(b) && in_body(*b))))
        .collect();

    // edge (from, to) -> state on it
    let mut edges: BTreeMap<(u64, u64), S> = BTreeMap::new();
    let mut preds: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut visits: BTreeMap<u64, usize> = BTreeMap::new();
    let mut saturated: BTreeSet<u64> = BTreeSet::new();
    let mut worklist: VecDeque<u64> = VecDeque::from([entry]);
    worklist.extend(unknown_entry.iter().copied());
    let mut queued: BTreeSet<u64> = worklist.iter().copied().collect();

    while let Some(b) = worklist.pop_front() {
        queued.remove(&b);
        if saturated.contains(&b) {
            continue;
        }
        let v = visits.entry(b).or_insert(0);
        *v += 1;

        let mut st = if b == entry || unknown_entry.contains(&b) {
            S::default()
        } else if *v > MAX_VISITS_PER_BLOCK {
            // Not converged: walk it once more from "nothing known",
            // which every later input refines, and stop.
            saturated.insert(b);
            S::default()
        } else {
            let mut incoming = preds
                .get(&b)
                .into_iter()
                .flatten()
                .filter_map(|p| edges.get(&(*p, b)));
            let Some(first) = incoming.next() else {
                continue;
            };
            incoming.fold(first.clone(), |acc, s| acc.join(s))
        };

        let end = block_end(b);
        let Some(&start_idx) = index.get(&b) else {
            continue;
        };
        let mut out: BTreeMap<u64, S> = BTreeMap::new();
        let add_edge = |out: &mut BTreeMap<u64, S>, to: u64, s: &S| {
            let joined = match out.get(&to) {
                Some(prev) => prev.join(s),
                None => s.clone(),
            };
            out.insert(to, joined);
        };
        let mut falls_through = true;
        for insn in insns[start_idx..].iter().take_while(|i| i.address < end) {
            for op in &insn.ops {
                match op.opcode {
                    OpCode::Call | OpCode::CallInd => {
                        snaps.push((insn.address, snapshot(&st)));
                        st.after_call();
                    }
                    OpCode::CBranch => {
                        if let Some(t) = target(op).filter(|t| starts.contains(t)) {
                            add_edge(&mut out, t, &st);
                        }
                    }
                    OpCode::Branch => {
                        if let Some(t) = target(op).filter(|t| starts.contains(t)) {
                            add_edge(&mut out, t, &st);
                        }
                        falls_through = false;
                    }
                    OpCode::Return | OpCode::BranchInd => falls_through = false,
                    _ => st.apply(op),
                }
            }
            if !falls_through {
                break;
            }
        }
        if falls_through && end != u64::MAX && index.contains_key(&end) {
            add_edge(&mut out, end, &st);
        }
        for (to, s) in out {
            preds.entry(to).or_default().insert(b);
            if edges.get(&(b, to)) != Some(&s) {
                edges.insert((b, to), s);
                if queued.insert(to) {
                    worklist.push_back(to);
                }
            }
        }
    }
    snaps
}
