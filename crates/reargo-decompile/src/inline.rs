//! Temporaries printed inside the expression that reads them (WS86).
//!
//! The x86 lifter computes a memory operand's address, and the value a memory source operand
//! loads, into temporaries: `mov [rsp+0xa0], rsi` is `tmp_600 = rsp + 0xa0; STORE tmp_600,
//! rsi`, `add eax, [rbx+0x350]` is `tmp_600 = rbx + 0x350; tmp_710 = LOAD tmp_600; eax = eax +
//! tmp_710`. Printed as statements that is three lines for one instruction. [`candidates`]
//! picks the temporaries whose readers can print the defining expression in place of the name
//! — `*(uint64_t*)(rsp + 0xa0) = rsi;`, `eax = eax + *(uint32_t*)(rbx + 0x350);` — so the
//! definition is not printed:
//!
//! * the value is a temporary (`unique` space) computed by a pure op or a load;
//! * every reader is in the same block, after it, with nothing of another block in between, and
//!   is a load, a store, a pure op or a copy (not a call: a call site may print from a
//!   rendering that names its arguments; not a branch, a select or a `switch`: their conditions
//!   fold on their own);
//! * one reader, or up to [`MAX_SHARED`] when the expression is a register plus a constant (the
//!   address a read-modify-write instruction loads from and stores to: `add dword [rax+8], 1`
//!   is `*(uint32_t*)(rax + 8) = *(uint32_t*)(rax + 8) + 1;`);
//! * the registers it reads are not written between the definition and the last reader (a name
//!   in an expression means its value at that point), and a load has no store or call between
//!   it and its reader (the value read would differ).
//!
//! Inside one instruction both always hold; across instructions they are checked.

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use rustc_hash::FxHashMap;

use crate::condition::{value_key, ValueKey};
use crate::ssa::{OpIdx, SsaFunction};

/// Most readers of one expression printed in each of them (a register plus a constant).
pub(crate) const MAX_SHARED: usize = 2;

fn overlaps(x: &VarnodeData, w: &VarnodeData) -> bool {
    x.space != SpaceId::CONST && x.space == w.space && x.offset < w.offset + w.size as u64 && w.offset < x.offset + x.size as u64
}

fn pure(op: OpCode) -> bool {
    use OpCode::*;
    matches!(
        op,
        Copy | IntAdd
            | IntSub
            | IntMult
            | IntLeft
            | IntRight
            | IntSRight
            | IntAnd
            | IntOr
            | IntXor
            | IntNegate
            | Int2Comp
            | IntZExt
            | IntSExt
            | Subpiece
            | FloatAdd
            | FloatSub
            | FloatMult
            | FloatDiv
            | FloatNeg
            | FloatAbs
            | FloatInt2Float
            | FloatFloat2Float
            | FloatTrunc
    )
}

/// An op that may print a temporary's expression in place of its name.
fn reader_ok(op: OpCode) -> bool {
    op == OpCode::Load || op == OpCode::Store || pure(op)
}

/// A store, call or opaque op: memory may differ after it.
fn writes_memory(op: OpCode) -> bool {
    matches!(op, OpCode::Store | OpCode::Call | OpCode::CallInd | OpCode::CallOther)
}

/// What an inlined value depends on.
#[derive(Clone, Default)]
struct Deps {
    /// the first op of its definition chain
    first: OpIdx,
    /// the storage it reads by name (registers, temporaries still printed)
    leaves: Vec<VarnodeData>,
    /// a load is part of it
    loads: bool,
    /// a register plus a constant (or a register), cheap to print twice
    simple: bool,
}

/// The temporaries to print inline, in op order: `(definition, readers)`. The caller renders
/// each definition's expression (its earlier inlined inputs already in place).
pub(crate) fn candidates(func: &SsaFunction, skip: &dyn Fn(OpIdx) -> bool) -> Vec<(OpIdx, Vec<OpIdx>)> {
    let readers = crate::condition::Readers::new(func);
    let mut deps: FxHashMap<ValueKey, Deps> = FxHashMap::default();
    let mut out = Vec::new();
    for (d, op) in func.ops.iter().enumerate() {
        if op.dead || skip(d) {
            continue;
        }
        let Some(v) = op.output else { continue };
        let vd = func.varnodes[v as usize].data;
        if vd.space != SpaceId::UNIQUE || !(pure(op.opcode) || op.opcode == OpCode::Load) {
            continue;
        }
        let rs = readers.of(func, v);
        if rs.is_empty() || rs.len() > MAX_SHARED {
            continue;
        }
        // the dependencies: its inputs, through the inlined ones
        let mut dep = Deps { first: d, loads: op.opcode == OpCode::Load, ..Default::default() };
        let mut regs = 0;
        let mut consts = 0;
        for &x in &op.inputs {
            let xd = func.varnodes[x as usize].data;
            if xd.space == SpaceId::CONST {
                consts += 1;
                continue;
            }
            if let Some(inner) = deps.get(&value_key(func, x)) {
                dep.first = dep.first.min(inner.first);
                dep.leaves.extend(inner.leaves.iter().copied());
                dep.loads |= inner.loads;
                regs += 2; // not simple
            } else {
                dep.leaves.push(xd);
                regs += 1;
            }
        }
        // (a load's first input is its address space)
        dep.simple = matches!(op.opcode, OpCode::IntAdd | OpCode::IntSub | OpCode::Copy) && regs == 1 && consts <= 1;
        if rs.len() > 1 && !dep.simple {
            continue;
        }
        let last = *rs.iter().max().expect("non-empty");
        let ok = rs.iter().all(|&u| {
            let r = &func.ops[u];
            u > d && r.block == op.block && reader_ok(r.opcode) && r.inputs.iter().filter(|&&i| value_key(func, i) == value_key(func, v)).count() == 1
        }) && func.ops[dep.first + 1..last].iter().all(|o| {
            o.dead
                || (o.block == op.block
                    && !(dep.loads && writes_memory(o.opcode))
                    && !o.output.is_some_and(|w| dep.leaves.iter().any(|l| overlaps(l, &func.varnodes[w as usize].data))))
        });
        if !ok {
            continue;
        }
        deps.insert(value_key(func, v), dep);
        out.push((d, rs.to_vec()));
    }
    out
}
