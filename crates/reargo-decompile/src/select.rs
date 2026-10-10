//! `cmovcc` as a select (WS83).
//!
//! The x86 lifter has no select op and lifts `cmovcc dst, src` branch-free:
//! `mask = -zext(c); dst = dst ^ ((dst ^ src) & mask)`. Printed as is that is
//! `tmp_4b4 = -tmp_4b0; tmp_4b8 = r12 ^ rsi; tmp_4bc = tmp_4b8 & tmp_4b4; r12 = r12 ^ tmp_4bc;`.
//! This pass rewrites the final xor into [`OpCode::Select`] `dst = c ? src : dst`; the mask
//! ops lose their reader and dead code elimination drops them. When `c` is the negation of a
//! flag (`cmovae` reads `!CF`) the select takes the flag and swaps its arms.

use reargo_core::pcode::OpCode;

use rustc_hash::FxHashMap;

use crate::condition::{value_key, ValueKey};
use crate::ssa::{OpIdx, SsaFunction, VarId};

/// The live op computing each value. Common subexpression elimination renames a removed op's
/// result to the earlier value but leaves the reader's `def_op` on the dead op (two `cmov`s
/// on one condition share the mask).
type Defs = FxHashMap<ValueKey, OpIdx>;

/// The live op defining `v` when its opcode is `opcode`.
fn def_of(func: &SsaFunction, defs: &Defs, v: VarId, opcode: OpCode) -> Option<OpIdx> {
    let d = match func.varnodes[v as usize].def_op {
        Some(d) if !func.ops[d].dead => d,
        _ => *defs.get(&value_key(func, v))?,
    };
    (func.ops[d].opcode == opcode).then_some(d)
}

/// `c` when `mask` is `-zext(c)` (or `-c` for a byte) with `c` a boolean.
fn mask_condition(func: &SsaFunction, defs: &Defs, mask: VarId) -> Option<VarId> {
    let neg = def_of(func, defs, mask, OpCode::Int2Comp)?;
    let x = *func.ops[neg].inputs.first()?;
    let c = match def_of(func, defs, x, OpCode::IntZExt) {
        Some(z) => *func.ops[z].inputs.first()?,
        None => x,
    };
    let d = match func.varnodes[c as usize].def_op {
        Some(d) if !func.ops[d].dead => d,
        _ => *defs.get(&value_key(func, c))?,
    };
    (func.varnodes[c as usize].data.size == 1 && func.ops[d].opcode.is_boolean_output()).then_some(c)
}

/// Rewrite every `dst ^ ((dst ^ src) & -zext(c))` into `Select(c, src, dst)`. Returns how
/// many; run dead code elimination afterwards.
pub fn recover_selects(func: &mut SsaFunction) -> usize {
    if !func.ops.iter().any(|o| !o.dead && o.opcode == OpCode::Int2Comp) {
        return 0;
    }
    let defs: Defs = func
        .ops
        .iter()
        .filter(|o| !o.dead)
        .filter_map(|o| Some((value_key(func, o.output?), o.index)))
        .collect();
    let mut n = 0;
    for i in 0..func.ops.len() {
        let op = &func.ops[i];
        if op.dead || op.opcode != OpCode::IntXor || op.inputs.len() != 2 || op.output.is_none() {
            continue;
        }
        let found = (0..2).find_map(|k| {
            let (x, m) = (op.inputs[k], op.inputs[1 - k]);
            let and = def_of(func, &defs, m, OpCode::IntAnd)?;
            let a = &func.ops[and].inputs;
            if a.len() != 2 {
                return None;
            }
            (0..2).find_map(|j| {
                let (diff, mask) = (a[j], a[1 - j]);
                let c = mask_condition(func, &defs, mask)?;
                let dx = def_of(func, &defs, diff, OpCode::IntXor)?;
                let d = &func.ops[dx].inputs;
                if d.len() != 2 {
                    return None;
                }
                let src = if value_key(func, d[0]) == value_key(func, x) {
                    d[1]
                } else if value_key(func, d[1]) == value_key(func, x) {
                    d[0]
                } else {
                    return None;
                };
                Some((c, src, x))
            })
        });
        let Some((mut c, mut src, mut dst)) = found else { continue };
        // `!f ? src : dst` is `f ? dst : src`
        if let Some(neg) = def_of(func, &defs, c, OpCode::BoolNegate) {
            c = func.ops[neg].inputs[0];
            std::mem::swap(&mut src, &mut dst);
        }
        let old = std::mem::replace(&mut func.ops[i].inputs, smallvec::smallvec![c, src, dst]);
        func.ops[i].opcode = OpCode::Select;
        for v in old {
            if !func.ops[i].inputs.contains(&v) {
                func.varnodes[v as usize].uses.retain(|&u| u != i);
            }
        }
        for v in [c, src, dst] {
            let uses = &mut func.varnodes[v as usize].uses;
            if !uses.contains(&i) {
                uses.push(i);
            }
        }
        n += 1;
    }
    n
}
