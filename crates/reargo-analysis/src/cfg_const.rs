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

use std::collections::{BTreeMap, BTreeSet};

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, PcodeOp, VarnodeData};
use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_program::Program;
use rayon::prelude::*;

use crate::blockflow::{self, FlowState};
use crate::byteconst::{eval, is_unmodeled, is_view_refresh, ByteConst, ByteMem, RegFile};
use crate::func_lift::{external_entries, function_jobs, in_extent, lift_function, owns};

/// Constants observed on entry to each call instruction.
/// Outer key = instruction address of the Call; inner key = REGISTER
/// space offset; value = the proven constant.
pub type CallConstants = BTreeMap<u64, BTreeMap<u64, u64>>;

/// One function's call-site register snapshots, in the order its
/// worklist records them (a site may appear once per visit).
pub type CallSnapshots = Vec<(u64, BTreeMap<u64, u64>)>;

/// Run multi-block constant propagation across every function the
/// program knows about. Returns the merged map across functions.
pub fn build_call_constants(lifter: &dyn PcodeLift, program: &Program) -> CallConstants {
    // Lift + propagate each function in parallel (a function's
    // propagation reads only its own lift), then merge the snapshots
    // in listing order, exactly as the sequential walk would.
    let per_func: Vec<Option<CallSnapshots>> = function_jobs(program)
        .par_iter()
        .map(|&(entry, max)| {
            lift_function(lifter, program, entry, max).map(|insns| function_snapshots(program, entry, &insns))
        })
        .collect();
    let mut out = CallConstants::new();
    for snaps in per_func.into_iter().flatten() {
        merge_snapshots(&mut out, snaps);
    }
    out
}

/// Propagate the lifted instructions of the function at `entry`
/// (empty for an empty lift), keeping the call sites that function
/// owns. Merge the results of every function, in listing order, with
/// [`merge_snapshots`] to get [`build_call_constants`].
pub fn function_snapshots(program: &Program, entry: u64, insns: &[LiftedInstruction]) -> CallSnapshots {
    function_snapshots_with(program, entry, insns, &external_entries(program, insns))
}

/// [`function_snapshots`] with the lift's [`external_entries`] already
/// computed.
pub(crate) fn function_snapshots_with(
    program: &Program,
    entry: u64,
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    let mut snaps = function_snapshots_unowned(program, entry, insns, external);
    snaps.retain(|(addr, _)| owns(program, entry, *addr));
    snaps
}

/// [`function_snapshots_with`] before it drops the call sites the
/// function at `entry` does not own.
pub(crate) fn function_snapshots_unowned(
    program: &Program,
    entry: u64,
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
) -> CallSnapshots {
    if insns.is_empty() {
        return Vec::new();
    }
    propagate_with(insns, external, |a| in_extent(program, entry, a))
}

/// Fold one function's call snapshots into the program-wide map.
pub fn merge_snapshots(out: &mut CallConstants, snaps: CallSnapshots) {
    for (addr, regs) in snaps {
        let entry = out.entry(addr).or_default();
        // Merge — keep only values that agree with what's already
        // there (this is the same intersection rule we apply at block
        // joins).
        if entry.is_empty() {
            *entry = regs;
        } else {
            entry.retain(|k, v| regs.get(k) == Some(v));
        }
    }
}

/// State at a P-code-op boundary: known register bytes (x86
/// sub-register semantics, see [`crate::byteconst`]) and known
/// non-register varnodes (UNIQUE temporaries, …) with their size.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    regs: RegFile,
    temps: ByteMem<SpaceId>,
}

impl State {
    #[cfg(test)]
    fn new() -> Self {
        Self::default()
    }

    fn read(&self, vn: &VarnodeData) -> ByteConst {
        match vn.space {
            SpaceId::CONST => ByteConst::konst(vn.offset, vn.size),
            SpaceId::REGISTER => self.regs.read(vn.offset, vn.size),
            s => self.temps.read(s, vn.offset as i64, vn.size),
        }
    }

    fn write(&mut self, out: &VarnodeData, v: ByteConst) {
        match out.space {
            SpaceId::REGISTER => self.regs.write(out.offset, out.size, v),
            s => self.temps.write(s, out.offset as i64, out.size, v),
        }
    }

    /// Apply one non-call op: view refreshes change nothing, the
    /// ops [`eval`] models compute their output, anything else
    /// (loads included) makes it unknown.
    fn apply(&mut self, op: &PcodeOp) {
        if is_unmodeled(op) {
            *self = State::default();
            return;
        }
        let Some(out) = op.output.as_ref() else {
            return;
        };
        if is_view_refresh(op) {
            return;
        }
        let v = if op.opcode == OpCode::Load {
            // The IndirectCallResolver picks up the (Load of CONST
            // RAM address → GOT slot → import) chain in its own pass.
            ByteConst::UNKNOWN
        } else {
            eval(op, |vn| self.read(vn)).unwrap_or(ByteConst::UNKNOWN)
        };
        self.write(out, v);
    }

    /// Per-byte intersection (a CFG join).
    fn intersect(&self, other: &State) -> State {
        State { regs: self.regs.intersect(&other.regs), temps: self.temps.intersect(&other.temps) }
    }
}

#[cfg(test)]
fn propagate_one(insns: &[LiftedInstruction]) -> CallSnapshots {
    propagate_with(insns, &BTreeSet::new(), |_| true)
}

fn propagate_with(
    insns: &[LiftedInstruction],
    external: &BTreeSet<u64>,
    in_body: impl Fn(u64) -> bool,
) -> CallSnapshots {
    blockflow::propagate::<State, _>(insns, external, in_body, |st| st.regs.full_values().collect())
}

impl FlowState for State {
    /// Per-byte intersection: a byte survives iff both inputs know it
    /// with the same value.
    fn join(&self, other: &Self) -> Self {
        self.intersect(other)
    }
    fn apply(&mut self, op: &PcodeOp) {
        State::apply(self, op);
    }
    /// SysV: caller-saved registers clobbered (conservatively every
    /// register); temporaries are kept.
    fn after_call(&mut self) {
        self.regs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersect_keeps_agreeing_keys() {
        let mut a = State::new();
        a.regs.set64(0x38, 0xaa);
        a.regs.set64(0x30, 0xbb);
        let mut b = State::new();
        b.regs.set64(0x38, 0xaa);
        b.regs.set64(0x30, 0xcc); // disagrees
        let out = FlowState::join(&a, &b);
        assert_eq!(out.regs.get64(0x38), Some(0xaa));
        assert_eq!(out.regs.get64(0x30), None);
    }

    /// The lifter's sub-register sequences, each followed by a call:
    /// the snapshot holds the full 8-byte register values.
    #[test]
    fn sub_register_sequences_resolve() {
        use crate::byteconst::testseq::*;
        let snap = |ops: Vec<PcodeOp>| {
            let mut ops = ops;
            ops.push(op(OpCode::Call, None, &[k(0xdead, 8)]));
            let insn = LiftedInstruction { address: 0x1000, length: 4, mnemonic: "x".into(), ops };
            let mut result = CallConstants::new();
            merge_snapshots(&mut result, propagate_one(&[insn]));
            result.remove(&0x1000).expect("call snapshot")
        };
        assert_eq!(snap(mov_esi_imm32()).get(&0x30), Some(&0x2a));
        let s = snap(lea_rax_mov_rdi());
        assert_eq!((s.get(&0), s.get(&0x38)), (Some(&0x402004), Some(&0x402004)));
        assert_eq!(snap(mov_rax_then_al()).get(&0), Some(&0x7fff_1234_5605));
        let s = snap(ah_write_read());
        assert_eq!((s.get(&0), s.get(&0x08)), (Some(&0x0734), Some(&7)));
        let s = snap(movsx_movzx());
        assert_eq!(s.get(&0x38), Some(&0xffff_ff80));
        assert_eq!(s.get(&0x30), Some(&0x80));
        assert_eq!(s.get(&0x80), Some(&0xffff_ffff_ffff_ff80));
        assert_eq!(s.get(&0x10), None);
    }

    // Helpers shared by the propagate tests.
    use reargo_core::address::Address;
    use reargo_core::pcode::SeqNum;

    fn vn_reg(off: u64) -> VarnodeData {
        VarnodeData { space: SpaceId::REGISTER, offset: off, size: 8 }
    }
    fn vn_const(v: u64) -> VarnodeData {
        VarnodeData { space: SpaceId::CONST, offset: v, size: 8 }
    }
    fn vn_ram(addr: u64) -> VarnodeData {
        VarnodeData { space: SpaceId::RAM, offset: addr, size: 8 }
    }
    fn op(opcode: OpCode, inputs: Vec<VarnodeData>, output: Option<VarnodeData>) -> PcodeOp {
        let mut o = PcodeOp::new(opcode, SeqNum::new(Address::new(SpaceId::RAM, 0), 0));
        o.inputs = inputs.into_iter().collect();
        o.output = output;
        o
    }

    /// Constant set in entry block must reach a Call in a fall-
    /// through successor block. Regression for the worklist fix.
    #[test]
    fn propagate_carries_const_across_branch() {
        let rdi = 0x38u64;
        let block_a = LiftedInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "a".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0xaa)], Some(vn_reg(rdi))),
                op(OpCode::Branch, vec![vn_ram(0x2000)], None),
            ],
        };
        let block_b = LiftedInstruction {
            address: 0x2000,
            length: 4,
            mnemonic: "b".into(),
            ops: vec![
                op(OpCode::Call, vec![vn_const(0xdead)], None),
                op(OpCode::Return, vec![vn_const(0)], None),
            ],
        };
        let mut result = CallConstants::new();
        merge_snapshots(&mut result, propagate_one(&[block_a, block_b]));
        let snap = result.get(&0x2000).expect("call snapshot");
        assert_eq!(snap.get(&rdi).copied(), Some(0xaa));
    }

    /// Disagreement at a join must intersect-out — a key only survives
    /// when every predecessor agrees on the value.
    #[test]
    fn propagate_disagreeing_preds_drop_key() {
        let rdi = 0x38u64;
        let entry = LiftedInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "entry".into(),
            ops: vec![op(OpCode::CBranch, vec![vn_ram(0x2000)], None)],
        };
        // fall-through: rdi = 0x42, jmp call
        let ft = LiftedInstruction {
            address: 0x1010,
            length: 4,
            mnemonic: "ft".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0x42)], Some(vn_reg(rdi))),
                op(OpCode::Branch, vec![vn_ram(0x3000)], None),
            ],
        };
        // taken: rdi = 0x43, jmp call
        let taken = LiftedInstruction {
            address: 0x2000,
            length: 4,
            mnemonic: "taken".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0x43)], Some(vn_reg(rdi))),
                op(OpCode::Branch, vec![vn_ram(0x3000)], None),
            ],
        };
        let call = LiftedInstruction {
            address: 0x3000,
            length: 4,
            mnemonic: "call".into(),
            ops: vec![
                op(OpCode::Call, vec![vn_const(0xdead)], None),
                op(OpCode::Return, vec![vn_const(0)], None),
            ],
        };
        let mut result = CallConstants::new();
        merge_snapshots(&mut result, propagate_one(&[entry, ft, taken, call]));
        let snap = result.get(&0x3000).expect("call snapshot");
        // Point-tracker drops the key entirely at the disagreement.
        assert!(snap.get(&rdi).is_none(), "got: {:?}", snap);
    }

    /// Caller-saved registers (any REGISTER-space slot, in this
    /// model) are cleared across Call. Pins the SysV caller-saved
    /// behaviour the resolver downstream depends on: the second
    /// call inside the same block must NOT inherit constants set
    /// before the first call.
    #[test]
    fn propagate_clears_register_state_across_call() {
        let rdi = 0x38u64;
        // First instruction: set rdi = 0xaa, then call.
        let setup_and_call = LiftedInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "setup+call".into(),
            ops: vec![
                op(OpCode::Copy, vec![vn_const(0xaa)], Some(vn_reg(rdi))),
                op(OpCode::Call, vec![vn_const(0xdead)], None),
            ],
        };
        // Second instruction (different address): another call without
        // re-setting rdi. The earlier `Call` should have cleared
        // REGISTER-space state, so this site's snapshot must NOT see
        // rdi=0xaa.
        let second_call = LiftedInstruction {
            address: 0x1010,
            length: 4,
            mnemonic: "second call".into(),
            ops: vec![
                op(OpCode::Call, vec![vn_const(0xbeef)], None),
                op(OpCode::Return, vec![vn_const(0)], None),
            ],
        };
        let mut result = CallConstants::new();
        merge_snapshots(&mut result, propagate_one(&[setup_and_call, second_call]));

        let first = result.get(&0x1000).expect("first call");
        assert_eq!(first.get(&rdi).copied(), Some(0xaa));

        let second = result.get(&0x1010).expect("second call");
        assert!(
            second.get(&rdi).is_none(),
            "register state must be cleared across the first call; got: {:?}",
            second
        );
    }

    /// The taken edge of a conditional jump carries the state at the
    /// jump, not at the end of its block: `je L; mov ecx, 0xe0; jmp M`
    /// must not reach `L` with `ecx = 0xe0`.
    #[test]
    fn conditional_edge_uses_state_at_the_jump() {
        let rcx = 0x08u64;
        let insns = [
            LiftedInstruction {
                address: 0x1000,
                length: 4,
                mnemonic: "je".into(),
                ops: vec![op(OpCode::CBranch, vec![vn_ram(0x2000), vn_reg(0x206)], None)],
            },
            LiftedInstruction {
                address: 0x1004,
                length: 4,
                mnemonic: "mov".into(),
                ops: vec![op(OpCode::Copy, vec![vn_const(0xe0)], Some(vn_reg(rcx)))],
            },
            LiftedInstruction {
                address: 0x1008,
                length: 4,
                mnemonic: "jmp".into(),
                ops: vec![op(OpCode::Branch, vec![vn_ram(0x3000)], None)],
            },
            LiftedInstruction {
                address: 0x2000,
                length: 4,
                mnemonic: "call".into(),
                ops: vec![
                    op(OpCode::Call, vec![vn_const(0xdead)], None),
                    op(OpCode::Return, vec![vn_const(0)], None),
                ],
            },
            LiftedInstruction {
                address: 0x3000,
                length: 4,
                mnemonic: "call".into(),
                ops: vec![
                    op(OpCode::Call, vec![vn_const(0xbeef)], None),
                    op(OpCode::Return, vec![vn_const(0)], None),
                ],
            },
        ];
        let mut result = CallConstants::new();
        merge_snapshots(&mut result, propagate_one(&insns));
        assert_eq!(result.get(&0x2000).expect("taken").get(&rcx), None);
        assert_eq!(result.get(&0x3000).expect("fall-through").get(&rcx), Some(&0xe0));
    }
}
