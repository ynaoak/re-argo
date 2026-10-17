//! Rotates as `rotl(x, n)` / `rotr(x, n)` (WS85).
//!
//! p-code has no rotate: the x86 lifter writes `rol x, n` as `a = x << n; b = x >> (w - n);
//! x = a | b` (`ror` with the shifts the other way round), which printed as three lines. This
//! pass, run on the optimized SSA, turns such an `|` of two shifts of the same value by
//! amounts adding up to its width into the named intrinsic `rotl` / `rotr` (by which shift
//! comes first, as the instruction did) and drops the shifts when nothing else reads them.

use reargo_core::address::SpaceId;
use reargo_core::pcode::{intrinsic, OpCode, VarnodeData};
use rustc_hash::FxHashMap;

use crate::condition::{value_key, ValueKey};
use crate::ssa::{OpIdx, SsaFunction, VarId};

fn const_of(func: &SsaFunction, v: VarId) -> Option<u64> {
    let d = &func.varnodes[v as usize].data;
    (d.space == SpaceId::CONST).then_some(d.offset)
}

/// Rewrite the rotates; returns how many.
pub fn recover_rotates(func: &mut SsaFunction) -> usize {
    if !func.ops.iter().any(|o| !o.dead && o.opcode == OpCode::IntOr) {
        return 0;
    }
    // the live op defining each value, and how many live ops read it
    let mut defs: FxHashMap<ValueKey, OpIdx> = FxHashMap::default();
    let mut readers: FxHashMap<ValueKey, u32> = FxHashMap::default();
    for o in func.ops.iter().filter(|o| !o.dead) {
        if let Some(out) = o.output {
            defs.insert(value_key(func, out), o.index);
        }
        for &i in &o.inputs {
            *readers.entry(value_key(func, i)).or_default() += 1;
        }
    }
    let def = |func: &SsaFunction, v: VarId| defs.get(&value_key(func, v)).copied();
    let single = |func: &SsaFunction, v: VarId| readers.get(&value_key(func, v)).copied() == Some(1);
    let mut found = Vec::new();
    for o in func.ops.iter().filter(|o| !o.dead && o.opcode == OpCode::IntOr && o.inputs.len() == 2) {
        let Some(out) = o.output else { continue };
        let (Some(d0), Some(d1)) = (def(func, o.inputs[0]), def(func, o.inputs[1])) else { continue };
        let (first, second) = (&func.ops[d0], &func.ops[d1]);
        let left_first = match (first.opcode, second.opcode) {
            (OpCode::IntLeft, OpCode::IntRight) => true,
            (OpCode::IntRight, OpCode::IntLeft) => false,
            _ => continue,
        };
        if first.inputs.len() != 2 || second.inputs.len() != 2 || !single(func, o.inputs[0]) || !single(func, o.inputs[1]) {
            continue;
        }
        let x = first.inputs[0];
        let w = u64::from(func.varnodes[x as usize].data.size) * 8;
        if value_key(func, x) != value_key(func, second.inputs[0]) || func.varnodes[out as usize].data.size != func.varnodes[x as usize].data.size {
            continue;
        }
        let (n, m) = (first.inputs[1], second.inputs[1]);
        // the second shift's amount: `w - n`, a constant or computed
        let mut dead = vec![d0, d1];
        let ok = match (const_of(func, n), const_of(func, m)) {
            (Some(a), Some(b)) => a > 0 && b > 0 && a + b == w,
            _ => match def(func, m) {
                Some(s) if func.ops[s].opcode == OpCode::IntSub
                    && func.ops[s].inputs.len() == 2
                    && const_of(func, func.ops[s].inputs[0]) == Some(w)
                    && value_key(func, func.ops[s].inputs[1]) == value_key(func, n)
                    && single(func, m) =>
                {
                    dead.push(s);
                    true
                }
                _ => false,
            },
        };
        if ok {
            let tag = if left_first { intrinsic::ROTL } else { intrinsic::ROTR };
            found.push((o.index, tag, x, n, dead));
        }
    }
    let count = found.len();
    for (o, tag, x, n, dead) in found {
        for d in dead {
            func.ops[d].dead = true;
            for i in func.ops[d].inputs.clone() {
                func.varnodes[i as usize].uses.retain(|&mut u| u != d);
            }
        }
        for i in func.ops[o].inputs.clone() {
            func.varnodes[i as usize].uses.retain(|&mut u| u != o);
        }
        let t = func.varnodes.len() as VarId;
        func.varnodes.push(crate::ssa::SsaVarnode {
            id: t,
            data: VarnodeData::new(SpaceId::CONST, tag, 8),
            version: 0,
            def_op: None,
            uses: smallvec::smallvec![o],
        });
        func.varnodes[x as usize].uses.push(o);
        func.varnodes[n as usize].uses.push(o);
        let op = &mut func.ops[o];
        op.opcode = OpCode::CallOther;
        op.inputs = smallvec::smallvec![t, x, n];
    }
    count
}
