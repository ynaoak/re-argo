//! Array indexing (WS97): an access `*(T*)(base + (i << k))` whose scale `1 << k` is the size
//! of `T` prints as `((T*)base)[i]` — C's pointer arithmetic computes the same address
//! (`base + i * sizeof(T)`, modulo 2^64). A constant added after the scaled index that is a
//! multiple of the size moves the element: `*(uint32_t*)((rbx + (rax << 2)) - 4)` is
//! `((uint32_t*)rbx)[rax - 1]`.
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
pub(crate) fn indexed(func: &SsaFunction, addr: VarId, size: u32, inlined: &dyn Fn(VarId) -> Option<usize>) -> Option<Indexed> {
    if !matches!(size, 2 | 4 | 8 | 16) {
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
        let mut e = scaled(func, d, add.inputs[0], size, inlined)?;
        e.offset = off / size as i64;
        return Some(e);
    }
    scaled(func, d, addr, size, inlined)
}

/// `addr` (printed by op `outer`'s input or as `outer`'s own text) is `base + (i << k)`.
fn scaled(func: &SsaFunction, outer: usize, addr: VarId, size: u32, inlined: &dyn Fn(VarId) -> Option<usize>) -> Option<Indexed> {
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
    None
}

/// The element index text: `i`, `i + 1`, `i - 2` (`index` printed as an operand).
pub(crate) fn index_text(index: &str, offset: i64) -> String {
    match offset {
        0 => crate::emit::strip_outer_parens(index).to_string(),
        o if o > 0 => cat!(index, " + ", o.to_string()),
        o => cat!(index, " - ", o.unsigned_abs().to_string()),
    }
}
