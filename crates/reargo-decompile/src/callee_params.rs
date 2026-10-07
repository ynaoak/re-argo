//! Which argument registers does a callee read? (WS78)
//!
//! The pipeline gives every call all of the calling convention's argument
//! registers and `optimize::prune_call_args` decides which of them are the
//! call's arguments. Looking only at the caller has two failure modes:
//!
//! * an argument the caller passes straight through from its own incoming
//!   registers (`f(this, 5)` with `this` still in `rdi`) has no setup
//!   instruction, so it looked like "not an argument";
//! * a register left over from earlier work (`rcx` of a loop counter,
//!   `xmm3..6` of an earlier computation) looked like one.
//!
//! For a direct call the callee's code answers the question: an argument
//! register the callee reads before writing it on some path from its entry is
//! a parameter. This module lifts the callee and runs that "read before
//! written" (must-defined) analysis over its CFG.
//!
//! Details that keep the answer honest on compiled x86-64:
//! * a register counts as read only when the read covers its low byte, so the
//!   lifter's view-sync ops (`SUBPIECE(xmm0, 8)` to rebuild the upper lanes
//!   after a scalar write, `SUBPIECE(rdi, 1)` after `mov dil, ..`) are not
//!   reads of a parameter;
//! * `xor esi, esi` / `sub esi, esi` (zero idioms) do not read `esi`;
//! * a call inside the callee clobbers every argument register; the
//!   arguments *it* passes through are the callee's reads too, found by
//!   analysing that inner callee (depth-limited). An inner call whose
//!   callee is unknown (indirect, past the depth limit, or itself only a
//!   lower bound such as a PLT stub) is assumed to take the contiguous
//!   prefix of each register class up to the highest register the callee
//!   has set up — the System V rule;
//! * a tail `jmp` out of the lifted body is treated as such a call;
//! * an indirect jump (jump table, PLT stub) or a body longer than the lift
//!   limit makes the answer a lower bound (`complete == false`): reads may
//!   be missing, so the caller must not drop arguments on its strength.

use std::sync::Mutex;

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, PcodeOp, VarnodeData};
use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_loader::Memory;
use rustc_hash::FxHashMap;

use crate::cfg::ControlFlowGraph;

/// Parameters of a callee as a bit set over the convention's argument
/// registers (`bit i` = `CallConvention::args[i]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParamInfo {
    pub mask: u32,
    /// `false` when the analysis could not see the whole body: `mask` is then
    /// a lower bound.
    pub complete: bool,
}

/// Instruction limit for one callee body.
const MAX_INSNS: usize = 3000;
/// How many call levels below the analysed callee are followed to find
/// pass-through arguments.
const MAX_DEPTH: u32 = 2;

/// Callee parameter oracle with a memo shared by every lookup (safe to share
/// across threads, e.g. by `decompile_all`).
pub struct CalleeParams<'a> {
    lifter: &'a dyn PcodeLift,
    memory: &'a Memory,
    args: Vec<VarnodeData>,
    /// Register class of each argument (index into `class_members`).
    class_of: Vec<usize>,
    /// Arguments of each class, in parameter order.
    class_members: Vec<Vec<usize>>,
    memo: Mutex<FxHashMap<(u64, u32), Option<ParamInfo>>>,
}

impl<'a> CalleeParams<'a> {
    /// `None` when the lifter has no calling convention.
    pub fn new(lifter: &'a dyn PcodeLift, memory: &'a Memory) -> Option<Self> {
        let cc = lifter.call_convention()?;
        let (class_of, class_members) = arg_classes(&cc.args);
        Some(Self { lifter, memory, args: cc.args, class_of, class_members, memo: Mutex::new(FxHashMap::default()) })
    }

    pub fn args(&self) -> &[VarnodeData] {
        &self.args
    }

    /// Parameters of the function at `target`, or `None` when it cannot be
    /// lifted.
    pub fn params(&self, target: u64) -> Option<ParamInfo> {
        self.params_at(target, MAX_DEPTH)
    }

    fn params_at(&self, target: u64, depth_left: u32) -> Option<ParamInfo> {
        if let Some(r) = self.memo.lock().ok().and_then(|m| m.get(&(target, depth_left)).copied()) {
            return r;
        }
        // no "in progress" marker: the depth limit already bounds recursion
        // (f -> g -> f), and a marker would let a concurrent lookup see a
        // half-done answer
        let r = self.analyze(target, depth_left);
        if let Ok(mut m) = self.memo.lock() {
            m.insert((target, depth_left), r);
        }
        r
    }

    fn analyze(&self, target: u64, depth_left: u32) -> Option<ParamInfo> {
        let lifted = self.lifter.lift_range(self.memory, target, MAX_INSNS).ok()?;
        if lifted.is_empty() || lifted[0].address != target {
            return None;
        }
        let last = lifted.last().map(|i| i.address);
        let hit_limit = lifted.len() >= MAX_INSNS;
        let insns = crate::pipeline::trim_to_return(lifted);
        // the body runs past the lift limit (its last lifted instruction is live)
        let truncated = hit_limit && insns.last().map(|i| i.address) == last;
        let cfg = ControlFlowGraph::build_owned(insns);
        let n = cfg.blocks.len();
        let rpo = crate::dominator::reverse_post_order(&cfg);

        // must-defined (by low byte) sets at block entry; None = not reached yet
        let mut inn: Vec<Option<u32>> = vec![None; n];
        inn[cfg.entry_block] = Some(0);
        let mut acc = Acc { reads: 0, complete: !truncated };
        loop {
            let mut changed = false;
            for &b in &rpo {
                let Some(state) = inn[b] else { continue };
                let out = self.run_block(&cfg, b, state, depth_left, None);
                for &s in &cfg.blocks[b].successors {
                    let new = match inn[s] {
                        None => out,
                        Some(old) => old & out,
                    };
                    if s != cfg.entry_block && inn[s] != Some(new) {
                        inn[s] = Some(new);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        for &b in &rpo {
            if let Some(state) = inn[b] {
                self.run_block(&cfg, b, state, depth_left, Some(&mut acc));
            }
        }
        Some(ParamInfo { mask: acc.reads, complete: acc.complete })
    }

    /// Transfer function of one block; with `acc`, records the reads.
    fn run_block(
        &self,
        cfg: &ControlFlowGraph,
        b: usize,
        mut defined: u32,
        depth_left: u32,
        mut acc: Option<&mut Acc>,
    ) -> u32 {
        let all = (1u32 << self.args.len()) - 1;
        for insn in &cfg.blocks[b].instructions {
            let zeroed = zero_idiom_operands(insn);
            for op in &insn.ops {
                match op.opcode {
                    OpCode::Call | OpCode::CallInd => {
                        if let Some(a) = acc.as_deref_mut() {
                            let direct = (op.opcode == OpCode::Call)
                                .then(|| op.inputs.first())
                                .flatten()
                                .filter(|t| t.space == SpaceId::RAM)
                                .map(|t| t.offset);
                            a.reads |= self.inner_call_reads(direct, defined, depth_left) & !defined;
                        }
                        defined = all; // every argument register is caller-saved
                        continue;
                    }
                    OpCode::Branch => {
                        // a tail call out of the lifted body
                        if let Some(t) = op.inputs.first().filter(|t| t.space == SpaceId::RAM)
                            && cfg.block_at(t.offset).is_none()
                            && let Some(a) = acc.as_deref_mut()
                        {
                            a.reads |= self.inner_call_reads(Some(t.offset), defined, depth_left) & !defined;
                        }
                        continue;
                    }
                    OpCode::BranchInd => {
                        if let Some(a) = acc.as_deref_mut() {
                            a.complete = false;
                        }
                        continue;
                    }
                    _ => {}
                }
                if let Some(a) = acc.as_deref_mut() {
                    for (k, inp) in op.inputs.iter().enumerate() {
                        if inp.space == SpaceId::CONST || zeroed.contains(inp) {
                            continue;
                        }
                        let (lo, hi) = read_range(op, k, inp);
                        a.reads |= self.covering(inp.space, lo, hi) & !defined;
                    }
                }
                if let Some(out) = &op.output {
                    defined |= self.covering(out.space, out.offset, out.offset + out.size as u64);
                }
            }
        }
        defined
    }

    /// The argument registers an inner call reads (before masking by what the
    /// caller already defined).
    fn inner_call_reads(&self, target: Option<u64>, defined: u32, depth_left: u32) -> u32 {
        if let Some(t) = target
            && depth_left > 0
            && let Some(info) = self.params_at(t, depth_left - 1)
        {
            if info.complete {
                return info.mask;
            }
            // a lower bound (e.g. a PLT stub): add the prefix rule rather than give up on
            // the whole answer
            return info.mask | self.prefix_reads(defined);
        }
        self.prefix_reads(defined)
    }

    /// Unknown callee: each class's prefix up to the highest register set up.
    fn prefix_reads(&self, defined: u32) -> u32 {
        let mut reads = 0;
        for members in &self.class_members {
            if let Some(top) = members.iter().rposition(|&i| defined & (1 << i) != 0) {
                for &i in &members[..=top] {
                    reads |= 1 << i;
                }
            }
        }
        reads
    }

    /// Arguments whose low byte lies in `[lo, hi)` of `space`.
    fn covering(&self, space: SpaceId, lo: u64, hi: u64) -> u32 {
        let mut m = 0;
        for (i, a) in self.args.iter().enumerate() {
            if a.space == space && lo <= a.offset && a.offset < hi {
                m |= 1 << i;
            }
        }
        m
    }

    /// Register class (index) of argument `i`.
    pub fn class_of(&self, i: usize) -> usize {
        self.class_of[i]
    }
}

struct Acc {
    reads: u32,
    complete: bool,
}

/// Group the argument registers into classes (System V: integer, vector) by
/// their size; members keep parameter order.
pub fn arg_classes(args: &[VarnodeData]) -> (Vec<usize>, Vec<Vec<usize>>) {
    let mut sizes: Vec<u32> = Vec::new();
    let mut class_of = Vec::with_capacity(args.len());
    let mut members: Vec<Vec<usize>> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let c = match sizes.iter().position(|&s| s == a.size) {
            Some(c) => c,
            None => {
                sizes.push(a.size);
                members.push(Vec::new());
                sizes.len() - 1
            }
        };
        class_of.push(c);
        members[c].push(i);
    }
    (class_of, members)
}

/// Bytes `[lo, hi)` (in the input's space) that input `k` of `op` reads:
/// `SUBPIECE(x, c)` reads only the bytes it extracts.
fn read_range(op: &PcodeOp, k: usize, inp: &VarnodeData) -> (u64, u64) {
    if op.opcode == OpCode::Subpiece
        && k == 0
        && let (Some(c), Some(out)) = (op.inputs.get(1), op.output.as_ref())
        && c.space == SpaceId::CONST
    {
        let lo = inp.offset + c.offset;
        return (lo, (lo + out.size as u64).min(inp.offset + inp.size as u64));
    }
    (inp.offset, inp.offset + inp.size as u64)
}

/// Operands of `xor r, r` / `sub r, r` in this instruction: their old value is
/// not read.
fn zero_idiom_operands(insn: &LiftedInstruction) -> smallvec::SmallVec<[VarnodeData; 1]> {
    insn.ops
        .iter()
        .filter(|o| {
            matches!(o.opcode, OpCode::IntXor | OpCode::IntSub)
                && o.inputs.len() == 2
                && o.inputs[0] == o.inputs[1]
                && o.inputs[0].space != SpaceId::CONST
        })
        .map(|o| o.inputs[0])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Endian;
    use reargo_lift::x86::X86Lifter;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    /// Code blobs placed at their addresses inside one `0xcc`-filled block.
    fn memory(parts: &[(u64, &[u8])]) -> Memory {
        let base = parts.iter().map(|p| p.0).min().unwrap();
        let end = parts.iter().map(|p| p.0 + p.1.len() as u64).max().unwrap();
        let mut data = vec![0xccu8; (end - base) as usize + 16];
        for (a, bytes) in parts {
            let o = (a - base) as usize;
            data[o..o + bytes.len()].copy_from_slice(bytes);
        }
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: base,
            size: data.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(data.as_slice())),
        });
        mem
    }

    const RDI: u32 = 1 << 0;
    const RSI: u32 = 1 << 1;
    const RDX: u32 = 1 << 2;
    const XMM0: u32 = 1 << 6;
    const XMM1: u32 = 1 << 7;

    fn params(parts: &[(u64, &[u8])], at: u64) -> ParamInfo {
        let lifter = X86Lifter::new_64();
        let mem = memory(parts);
        CalleeParams::new(&lifter, &mem).unwrap().params(at).unwrap()
    }

    #[test]
    fn reads_before_writes_are_parameters() {
        // mov eax, edi ; add eax, esi ; mov edx, 1 ; add eax, edx ; ret
        let code = [0x89, 0xf8, 0x01, 0xf0, 0xba, 0x01, 0, 0, 0, 0x01, 0xd0, 0xc3];
        let p = params(&[(0x2000, &code)], 0x2000);
        assert_eq!(p, ParamInfo { mask: RDI | RSI, complete: true });
    }

    #[test]
    fn zero_idiom_is_not_a_read() {
        // xor esi, esi ; mov eax, esi ; ret
        let code = [0x31, 0xf6, 0x89, 0xf0, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, 0);
    }

    #[test]
    fn scalar_sse_write_does_not_read_the_upper_lanes() {
        // cvtsi2ss xmm0, edi ; addss xmm0, xmm1 ; ret
        let code = [0xf3, 0x0f, 0x2a, 0xc7, 0xf3, 0x0f, 0x58, 0xc1, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, RDI | XMM1);
        // movss xmm0, [rdi] ; ret  — reads rdi, writes xmm0
        let code = [0xf3, 0x0f, 0x10, 0x07, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, RDI);
        // addss xmm0, xmm0 ; ret — a real float parameter
        let code = [0xf3, 0x0f, 0x58, 0xc0, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, XMM0);
    }

    #[test]
    fn arguments_passed_through_to_an_inner_call_are_parameters() {
        // 0x2000: mov edx, 3 ; call 0x3000 ; ret      (rdi, rsi pass through)
        // 0x3000: mov eax, edi ; add eax, esi ; add eax, edx ; ret
        let outer = [0xba, 0x03, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0xc3];
        let inner = [0x89, 0xf8, 0x01, 0xf0, 0x01, 0xd0, 0xc3];
        let p = params(&[(0x2000, &outer), (0x3000, &inner)], 0x2000);
        assert_eq!(p, ParamInfo { mask: RDI | RSI, complete: true });
    }

    #[test]
    fn registers_read_after_an_inner_call_are_not_parameters() {
        // call 0x3000 ; mov eax, edi ; ret   (0x3000: ret)
        let outer = [0xe8, 0xfb, 0x0f, 0, 0, 0x89, 0xf8, 0xc3];
        let p = params(&[(0x2000, &outer), (0x3000, &[0xc3])], 0x2000);
        assert_eq!(p, ParamInfo { mask: 0, complete: true });
    }

    #[test]
    fn unknown_inner_call_takes_the_set_up_prefix() {
        // mov edx, 1 ; call rax ; ret  — rdx set up, so rdi/rsi pass through
        let code = [0xba, 0x01, 0, 0, 0, 0xff, 0xd0, 0xc3];
        let p = params(&[(0x2000, &code)], 0x2000);
        assert_eq!(p.mask, RDI | RSI, "rdx is set up here, rdi/rsi come from the caller");
        assert!(p.complete);
    }

    #[test]
    fn indirect_jump_makes_the_answer_a_lower_bound() {
        // jmp [rip+0x1000]  (a PLT stub)
        let code = [0xff, 0x25, 0x00, 0x10, 0, 0];
        let p = params(&[(0x2000, &code)], 0x2000);
        assert_eq!(p, ParamInfo { mask: 0, complete: false });
    }

    #[test]
    fn read_on_one_path_only_is_a_parameter() {
        // test eax, eax ; je L ; mov esi, 1 ; L: mov eax, esi ; ret
        let code = [0x85, 0xc0, 0x74, 0x05, 0xbe, 0x01, 0, 0, 0, 0x89, 0xf0, 0xc3];
        assert_eq!(params(&[(0x2000, &code)], 0x2000).mask, RSI);
        let _ = RDX;
    }
}
