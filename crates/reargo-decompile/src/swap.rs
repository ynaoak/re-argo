//! `fxch` as one swap (WS90).
//!
//! The x87 lifter names the stack slots by their place from the bottom (`st0` = the first value
//! pushed), so `fxch st(i)` exchanges two slots' values through a temporary: `t = st1; st1 =
//! st0; st0 = t`, printed as three statements. [`find`] recognises the three copies of one
//! instruction and the emitters print them as `swap(st1, st0);` (C) /
//! `core::mem::swap(&mut st1, &mut st0);` (Rust) at the last one, the other two hidden.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::condition::value_key;
use crate::ssa::{OpIdx, SsaFunction, VarId};
use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

fn x87_slot(func: &SsaFunction, v: VarId) -> bool {
    let d = &func.varnodes[v as usize].data;
    d.space == SpaceId::REGISTER && d.size == 10 && (0x1100..0x1180).contains(&d.offset)
}

/// The swaps: the op printing each (`(a, b)`: the two slots' new values, named as the slots)
/// and the ops not printed.
pub(crate) fn find(func: &SsaFunction, noise: &FxHashSet<OpIdx>) -> (FxHashMap<OpIdx, (VarId, VarId)>, FxHashSet<OpIdx>) {
    let mut swaps = FxHashMap::default();
    let mut hidden = FxHashSet::default();
    if !func.varnodes.iter().any(|v| v.data.size == 10) {
        return (swaps, hidden);
    }
    let readers = crate::condition::Readers::new(func);
    let live = |i: OpIdx| !func.ops[i].dead && !noise.contains(&i);
    for (i, op) in func.ops.iter().enumerate() {
        // t = COPY a
        if !live(i) || op.opcode != OpCode::Copy || op.inputs.len() != 1 || !x87_slot(func, op.inputs[0]) {
            continue;
        }
        let Some(t) = op.output.filter(|&t| func.varnodes[t as usize].data.space == SpaceId::UNIQUE && func.varnodes[t as usize].data.size == 10)
        else {
            continue;
        };
        // the next two live ops of the instruction: a' = COPY b; b' = COPY t
        let mut next = func.ops[i + 1..].iter().filter(|o| o.address == op.address && o.block == op.block && live(o.index));
        let (Some(o2), Some(o3)) = (next.next(), next.next()) else { continue };
        let a = func.varnodes[op.inputs[0] as usize].data;
        let ok = o2.opcode == OpCode::Copy
            && o3.opcode == OpCode::Copy
            && o2.inputs.len() == 1
            && o3.inputs.len() == 1
            && x87_slot(func, o2.inputs[0])
            && o2.output.is_some_and(|w| func.varnodes[w as usize].data == a)
            && o3.output.is_some_and(|w| func.varnodes[w as usize].data == func.varnodes[o2.inputs[0] as usize].data)
            && value_key(func, o3.inputs[0]) == value_key(func, t)
            && readers.of(func, t) == [o3.index];
        if ok {
            swaps.insert(o3.index, (o3.output.expect("checked"), o2.output.expect("checked")));
            hidden.insert(i);
            hidden.insert(o2.index);
        }
    }
    (swaps, hidden)
}
