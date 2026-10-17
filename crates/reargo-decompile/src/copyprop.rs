//! A temporary copied into a register prints as the register's own statement (WS85).
//!
//! The x86 lifter computes a source operand into a temporary and copies it into the
//! destination: `mov rdi, [rbx]` is `tmp_500 = LOAD rbx; rdi = COPY tmp_500`, `lea rcx,
//! [rsp+0x30]` is `tmp_600 = rsp + 0x30; rcx = COPY tmp_600` — two lines each. When the copy
//! is the temporary's only reader, in the same block, and nothing between the two reads or
//! writes the register, the computing op writes the register itself (`rdi = *(uint64_t*)rbx;`)
//! and the copy goes. The value is computed where it was; only its name changes, and the
//! register's old value is not read past that point.

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use rustc_hash::FxHashMap;

use crate::condition::{value_key, ValueKey};
use crate::ssa::SsaFunction;

fn overlaps(x: &reargo_core::pcode::VarnodeData, w: &reargo_core::pcode::VarnodeData) -> bool {
    x.space == w.space && x.offset < w.offset + w.size as u64 && w.offset < x.offset + x.size as u64
}

/// Merge the copies; returns how many.
pub fn propagate_register_copies(func: &mut SsaFunction) -> usize {
    let mut readers: FxHashMap<ValueKey, u32> = FxHashMap::default();
    for o in func.ops.iter().filter(|o| !o.dead) {
        for &i in &o.inputs {
            *readers.entry(value_key(func, i)).or_default() += 1;
        }
    }
    // the ops of each block in order (op indices grow along a block)
    let mut merged = 0;
    for c in 0..func.ops.len() {
        let op = &func.ops[c];
        if op.dead || op.opcode != OpCode::Copy || op.inputs.len() != 1 {
            continue;
        }
        let (Some(r), t) = (op.output, op.inputs[0]) else { continue };
        let (rd, td) = (func.varnodes[r as usize].data, func.varnodes[t as usize].data);
        if rd.space != SpaceId::REGISTER || td.space != SpaceId::UNIQUE || rd.size != td.size {
            continue;
        }
        let Some(d) = func.varnodes[t as usize].def_op else { continue };
        let dop = &func.ops[d];
        if dop.dead
            || dop.block != op.block
            || d >= c
            || dop.output != Some(t)
            || matches!(dop.opcode, OpCode::MultiEqual | OpCode::Indirect | OpCode::Call | OpCode::CallInd | OpCode::CallOther)
            || readers.get(&value_key(func, t)).copied() != Some(1)
        {
            continue;
        }
        // nothing between reads or writes the register
        let block = op.block;
        let clash = func.ops[d + 1..c].iter().filter(|o| !o.dead && o.block == block).any(|o| {
            o.inputs.iter().any(|&i| overlaps(&func.varnodes[i as usize].data, &rd))
                || o.output.is_some_and(|w| overlaps(&func.varnodes[w as usize].data, &rd))
        });
        // (an op of another block between the two in index order: give up)
        if clash || func.ops[d + 1..c].iter().any(|o| !o.dead && o.block != block) {
            continue;
        }
        func.ops[d].output = Some(r);
        func.varnodes[r as usize].def_op = Some(d);
        func.varnodes[t as usize].def_op = None;
        func.varnodes[t as usize].uses.retain(|&mut u| u != c);
        func.ops[c].dead = true;
        merged += 1;
    }
    merged
}
