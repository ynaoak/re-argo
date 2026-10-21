//! How a single lift's ops were finished before the high-byte pre-check and the in-place
//! moves of [`super::zero_extend_gpr32_writes`] (`finish_ops` / `zero_extend_gpr32_writes`
//! as they were), for the test that the lifts are exactly the same (`finish_matches_old`).

use super::{OpFacts, PcodeOp, REG_SPACE, VarnodeData, X86Lifter, constant, gpr_view, high_byte, is_pf, reg, scratch, sync_xmm_views, unique, xmm_view, xmm_write_zeroes_upper};
use reargo_core::pcode::{OpCode, SeqNum};
use smallvec::SmallVec;

impl X86Lifter {
    pub(super) fn old_finish_ops<const FACTS: bool>(&self, mut ops: Vec<PcodeOp>, insn: &iced_x86::Instruction, facts: &mut OpFacts) -> Vec<PcodeOp> {
        let (mut xmm, mut extra) = (false, 0usize);
        let mut touch = 0u64;
        let mut shape = crate::lift::InsnShape::default();
        let (mut pf_read, mut pf_written) = (None, false);
        for (k, op) in ops.iter().enumerate() {
            let bit = 1u64 << k.min(63);
            let mut reads = 0;
            let mut last: Option<VarnodeData> = None;
            let mut reads_pf = false;
            for v in op.inputs.iter() {
                if FACTS {
                    reads_pf |= is_pf(v);
                }
                if high_byte(v) {
                    if last != Some(*v) {
                        reads += 1;
                    }
                    last = Some(*v);
                }
            }
            if FACTS {
                if reads_pf && pf_read.is_none() {
                    pf_read = Some(!pf_written);
                }
                shape.add(op);
            }
            if reads > 0 {
                touch |= bit;
            }
            extra += reads;
            let Some(w) = op.output else { continue };
            if FACTS {
                pf_written |= is_pf(&w);
            }
            if w.space != REG_SPACE {
                continue;
            }
            xmm |= xmm_view(&w).is_some();
            if high_byte(&w) {
                touch |= bit;
                extra += 4;
            } else if gpr_view(&w) {
                touch |= bit;
                let is_rsp = w.offset == 0x20;
                extra += match w.size {
                    8 if !is_rsp => 3,
                    8 => 0,
                    4 => 1 + if is_rsp { 0 } else { 2 },
                    _ if !is_rsp => 4,
                    _ => 0,
                };
            }
        }
        if FACTS {
            facts.reads_outside_pf = pf_read == Some(true);
            facts.flags = shape.flags;
            facts.target = shape.target;
        }
        if self.is_64 && touch != 0 {
            if extra == 0 {
                for (i, op) in ops.iter_mut().enumerate() {
                    op.seq.order = i as u32;
                }
            } else {
                let touch = if ops.len() > 64 { touch | !0u64 << 63 } else { touch };
                let out = if xmm { scratch::take() } else { Vec::with_capacity(ops.len() + extra) };
                let out = old_zero_extend_gpr32_writes(&mut ops, out, touch);
                scratch::give(std::mem::replace(&mut ops, out));
                if !xmm {
                    return ops;
                }
            }
        }
        if xmm {
            ops = sync_xmm_views(ops, xmm_write_zeroes_upper(insn));
        }
        scratch::finish(ops)
    }
}

fn old_zero_extend_gpr32_writes(ops: &mut Vec<PcodeOp>, mut out: Vec<PcodeOp>, touch: u64) -> Vec<PcodeOp> {
    let gpr = |v: &VarnodeData| gpr_view(v).then_some(*v);
    let high = high_byte;
    let mut tmp = 0x7e00u64;
    let mut ops = ops.drain(..);
    let mut k = 0u32;
    loop {
        let next = if k >= 63 { k } else { (touch >> k << k).trailing_zeros().min(63) };
        out.extend(ops.by_ref().take((next - k) as usize));
        k = next;
        let Some(op) = ops.next() else { break };
        k = (k + 1).min(63);
        let at = op.seq.addr;
        let mk = |opcode: OpCode, output: VarnodeData, inputs: &[VarnodeData]| PcodeOp {
            opcode,
            seq: SeqNum::new(at, 0),
            output: Some(output),
            inputs: SmallVec::from_slice(inputs),
        };
        let mut read_high: Vec<VarnodeData> = op.inputs.iter().copied().filter(high).collect();
        read_high.dedup();
        for h in read_high {
            out.push(mk(OpCode::Subpiece, h, &[reg(h.offset - 1, 8), constant(1, 4)]));
        }
        let wrote_high = op.output.filter(high);
        let w = op.output.as_ref().and_then(gpr);
        out.push(op);
        if let Some(h) = wrote_high {
            let base = h.offset - 1;
            out.push(mk(OpCode::Piece, reg(base, 2), &[h, reg(base, 1)]));
            let hi = unique(tmp, 6);
            tmp += 0x10;
            out.push(mk(OpCode::Subpiece, hi, &[reg(base, 8), constant(2, 4)]));
            out.push(mk(OpCode::Piece, reg(base, 8), &[hi, reg(base, 2)]));
            out.push(mk(OpCode::Subpiece, reg(base, 4), &[reg(base, 8), constant(0, 4)]));
            continue;
        }
        let Some(w) = w else { continue };
        let r = |sz: u32| reg(w.offset, sz);
        let low = |out: &mut Vec<PcodeOp>, from: u32, sizes: &[u32]| {
            for &sz in sizes {
                out.push(mk(OpCode::Subpiece, r(sz), &[r(from), constant(0, 4)]));
            }
        };
        let is_rsp = w.offset == 0x20;
        match w.size {
            8 if !is_rsp => low(&mut out, 8, &[4, 2, 1]),
            8 => {}
            4 => {
                out.push(mk(OpCode::IntZExt, r(8), &[r(4)]));
                if !is_rsp {
                    low(&mut out, 4, &[2, 1]);
                }
            }
            n if !is_rsp => {
                let hi = unique(tmp, 8 - n);
                tmp += 0x10;
                out.push(mk(OpCode::Subpiece, hi, &[r(8), constant(n as u64, 4)]));
                out.push(mk(OpCode::Piece, r(8), &[hi, r(n)]));
                low(&mut out, 8, if n == 2 { &[4, 1] } else { &[4, 2] });
            }
            _ => {}
        }
    }
    for (i, op) in out.iter_mut().enumerate() {
        op.seq.order = i as u32;
    }
    out
}
