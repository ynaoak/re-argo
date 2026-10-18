//! Array indexing (WS97): an access `*(T*)(base + (i << k))` whose scale `1 << k` is the size
//! of `T` prints as `((T*)base)[i]` — C's pointer arithmetic computes the same address
//! (`base + i * sizeof(T)`, modulo 2^64). A constant added after the scaled index that is a
//! multiple of the size moves the element: `*(uint32_t*)((rbx + (rax << 2)) - 4)` is
//! `((uint32_t*)rbx)[rax - 1]`.
//!
//! A byte `*(uint8_t*)(p + i)` is `((uint8_t*)p)[i]` when `i` is a loop counter (a phi stepped
//! by one, or its stepped value) and `p` is not: any order is the same address.
//!
//! Only an address printed in place counts (the `+` and the shift inlined into the access): a
//! register holding the address prints by its name as before.

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

use crate::ssa::{SsaFunction, VarId};

/// An access `((T*)base)[index + offset]`: the operands as `(op, input)` to print them from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Indexed {
    pub base: (usize, usize),
    pub index: (usize, usize),
    /// The constant added, in elements.
    pub offset: i64,
}

/// The access of `size` bytes at `addr` as an array element, when its address prints in place
/// as `base + (i << k)` (or that plus a constant) with `1 << k == size`. `inlined(v)`: the op
/// printed in place of value `v` (`None`: it prints as its name).
pub(crate) fn indexed(func: &SsaFunction, addr: VarId, size: u32, inlined: &dyn Fn(VarId) -> Option<usize>, counters: &Counters) -> Option<Indexed> {
    if !matches!(size, 1 | 2 | 4 | 8 | 16) {
        return None;
    }
    let vn = |v: VarId| &func.varnodes[v as usize].data;
    let d = inlined(addr)?;
    let add = &func.ops[d];
    if add.opcode != OpCode::IntAdd || add.inputs.len() != 2 || vn(addr).size != 8 {
        return None;
    }
    // `(base + (i << k)) + c`
    let c = vn(add.inputs[1]);
    if c.space == SpaceId::CONST {
        let off = c.offset as i64;
        if off == 0 || off % size as i64 != 0 || off.unsigned_abs() >= 1 << 31 {
            return None;
        }
        let mut e = scaled(func, d, add.inputs[0], size, inlined, counters)?;
        e.offset = off / size as i64;
        return Some(e);
    }
    scaled(func, d, addr, size, inlined, counters)
}

/// `addr` (printed by op `outer`'s input or as `outer`'s own text) is `base + (i << k)`.
fn scaled(func: &SsaFunction, outer: usize, addr: VarId, size: u32, inlined: &dyn Fn(VarId) -> Option<usize>, counters: &Counters) -> Option<Indexed> {
    let vn = |v: VarId| &func.varnodes[v as usize].data;
    let d = if func.ops[outer].output == Some(addr) { outer } else { inlined(addr)? };
    let add = &func.ops[d];
    if add.opcode != OpCode::IntAdd || add.inputs.len() != 2 || vn(add.output?).size != 8 {
        return None;
    }
    for (b, s) in [(0, 1), (1, 0)] {
        let Some(sh) = inlined(add.inputs[s]) else { continue };
        let shift = &func.ops[sh];
        if shift.opcode != OpCode::IntLeft || shift.inputs.len() != 2 {
            continue;
        }
        let k = vn(shift.inputs[1]);
        let i = vn(shift.inputs[0]);
        if k.space != SpaceId::CONST || k.offset >= 8 || 1u32 << k.offset != size || i.size != 8 || i.space == SpaceId::CONST {
            continue;
        }
        return Some(Indexed { base: (d, b), index: (sh, 0), offset: 0 });
    }
    // a byte at `p + i`, `i` a loop counter
    if size == 1 {
        let is = |i: usize| counters.contains(func, add.inputs[i]);
        let konst = |i: usize| vn(add.inputs[i]).space == SpaceId::CONST;
        for (b, i) in [(0, 1), (1, 0)] {
            if is(i) && !is(b) && !konst(b) && vn(add.inputs[i]).size == 8 {
                return Some(Indexed { base: (d, b), index: (d, i), offset: 0 });
            }
        }
    }
    None
}

/// The loop counters of a function: the values of the phis an add of 1 or -1 steps (the phi
/// and the stepped value).
#[derive(Default)]
pub(crate) struct Counters(rustc_hash::FxHashSet<crate::condition::ValueKey>);

impl Counters {
    pub(crate) fn new(func: &SsaFunction) -> Self {
        let mut set = rustc_hash::FxHashSet::default();
        for op in func.ops.iter().filter(|o| !o.dead && o.opcode == OpCode::IntAdd && o.inputs.len() == 2) {
            let k = &func.varnodes[op.inputs[1] as usize].data;
            let Some(out) = op.output else { continue };
            let size = func.varnodes[out as usize].data.size;
            if k.space != SpaceId::CONST || !(k.offset == 1 || crate::emit::sign_extend(k.offset, k.size.min(size)) == -1) {
                continue;
            }
            let Some(phi) = func.varnodes[op.inputs[0] as usize].def_op.map(|d| &func.ops[d]) else { continue };
            let ok = crate::condition::value_key(func, out);
            if phi.opcode == OpCode::MultiEqual && !phi.dead && phi.inputs.iter().any(|&i| crate::condition::value_key(func, i) == ok) {
                set.insert(crate::condition::value_key(func, op.inputs[0]));
                set.insert(ok);
            }
        }
        Self(set)
    }

    fn contains(&self, func: &SsaFunction, v: VarId) -> bool {
        !self.0.is_empty() && self.0.contains(&crate::condition::value_key(func, v))
    }
}

/// The element index text: `i`, `i + 1`, `i - 2` (`index` printed as an operand).
pub(crate) fn index_text(index: &str, offset: i64) -> String {
    match offset {
        0 => crate::emit::strip_outer_parens(index).to_string(),
        o if o > 0 => cat!(index, " + ", o.to_string()),
        o => cat!(index, " - ", o.unsigned_abs().to_string()),
    }
}
