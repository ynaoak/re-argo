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
//!   is a load, a store, a pure op or a copy — or (WS87) a call whose site prints its own
//!   operands (not from a rendering that names the arguments: `(**(uint64_t*)(rax + 0x30))(rdi)`),
//!   a named intrinsic (`cvttps2dq(*(uint128_t*)(rsp + 0x30))`) or an arm of a select
//!   (`rsi = c ? rsi : *(uint64_t*)(rsp + 0x18)`); not a branch, a select's condition or a
//!   `switch`: conditions fold on their own;
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

/// An op that may print a temporary's expression in place of its name (WS88: also a
/// division, `eax = eax / ebx;`, and a comparison, see [`comparison`]).
fn reader_ok(op: OpCode) -> bool {
    op == OpCode::Load
        || op == OpCode::Store
        || pure(op)
        || comparison(op)
        || matches!(op, OpCode::IntDiv | OpCode::IntSDiv | OpCode::IntRem | OpCode::IntSRem)
}

/// A comparison or boolean op (WS88): a flag kept as a statement prints its operands
/// (`var_206 = rcx == *(uint64_t*)0xdfbea80;`); one folded into its block's branch or a select
/// prints them there, later in the block — so the value must hold to the block's end when the
/// comparison is read later in its block.
fn comparison(op: OpCode) -> bool {
    use OpCode::*;
    matches!(
        op,
        IntEqual | IntNotEqual | IntLess | IntSLess | IntLessEqual | IntSLessEqual | BoolNegate | BoolAnd | BoolOr | BoolXor | FloatEqual
            | FloatNotEqual | FloatLess | FloatLessEqual | FloatNan
    )
}

/// A named intrinsic (`pmovmskb(x)`, `mulps(a, b)`): prints its operands as `name(…)`.
fn named_intrinsic(func: &SsaFunction, op: &crate::ssa::SsaOp) -> bool {
    op.inputs.first().map(|&t| func.varnodes[t as usize].data).is_some_and(|t| {
        t.space == SpaceId::CONST && t.offset != reargo_core::pcode::intrinsic::NORETURN && reargo_core::pcode::intrinsic::name(t.offset).is_some()
    })
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
/// each definition's expression (its earlier inlined inputs already in place); `prints_operands`
/// says whether a call prints its operands itself (no rendering from elsewhere).
pub(crate) fn candidates(
    func: &SsaFunction,
    skip: &dyn Fn(OpIdx) -> bool,
    prints_operands: &dyn Fn(OpIdx) -> bool,
) -> Vec<(OpIdx, Vec<OpIdx>)> {
    let readers = crate::condition::Readers::new(func);
    // the last op of each block (a comparison's value is printed up to there)
    let mut block_end: FxHashMap<usize, OpIdx> = FxHashMap::default();
    for o in &func.ops {
        block_end.insert(o.block, o.index);
    }
    let mut deps: FxHashMap<ValueKey, Deps> = FxHashMap::default();
    let mut out = Vec::new();
    for (d, op) in func.ops.iter().enumerate() {
        if op.dead || skip(d) {
            continue;
        }
        let Some(v) = op.output else { continue };
        let vd = func.varnodes[v as usize].data;
        // (a call's `INDIRECT`s name its target only to say whose result / clobber they are)
        let rs: smallvec::SmallVec<[OpIdx; 2]> = readers.of(func, v).iter().copied().filter(|&u| func.ops[u].opcode != OpCode::Indirect).collect();
        // WS90: a flag's integer comparison read only by the extension that turns it into a
        // number (`cmp; sbb rdx, -1`, `adc`): `rdx = (rdx + 1) - (uint64_t)(rdi < 0x1f4);`
        let counted = crate::flags::is_flag_storage(&vd)
            && matches!(op.opcode, OpCode::IntEqual | OpCode::IntNotEqual | OpCode::IntLess | OpCode::IntSLess | OpCode::IntLessEqual | OpCode::IntSLessEqual)
            && matches!(rs.as_slice(), [u] if func.ops[*u].opcode == OpCode::IntZExt);
        if !counted && (vd.space != SpaceId::UNIQUE || !(pure(op.opcode) || op.opcode == OpCode::Load)) {
            continue;
        }
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
        // (a load's first input is its address space; WS88: an indexed address, `rax + (rcx << 2)`,
        // is cheap too)
        let scaled = |x: crate::ssa::VarId| {
            func.varnodes[x as usize].def_op.is_some_and(|i| {
                let o = &func.ops[i];
                o.opcode == OpCode::IntLeft
                    && deps.get(&value_key(func, x)).is_some_and(|dx| dx.simple)
                    && o.inputs.get(1).is_some_and(|&c| func.varnodes[c as usize].data.space == SpaceId::CONST)
            })
        };
        dep.simple = (matches!(op.opcode, OpCode::IntAdd | OpCode::IntSub | OpCode::Copy) && regs == 1 && consts <= 1)
            || (op.opcode == OpCode::IntLeft && regs == 1 && consts == 1)
            || (op.opcode == OpCode::IntAdd && consts == 0 && op.inputs.iter().all(|&x| !deps.contains_key(&value_key(func, x)) || scaled(x)));
        if rs.len() > 1 && !dep.simple {
            continue;
        }
        let mut last = *rs.iter().max().expect("non-empty");
        // (a comparison read later in its block may fold into a condition printed there; one
        // read elsewhere only is a statement of its own)
        let folds_later = |u: OpIdx| {
            func.ops[u].output.is_some_and(|w| readers.of(func, w).iter().any(|&r| r > u && func.ops[r].block == func.ops[u].block))
        };
        if rs.iter().any(|&u| comparison(func.ops[u].opcode) && folds_later(u)) {
            last = last.max(block_end.get(&op.block).map_or(last, |&e| e + 1));
        }
        let key = value_key(func, v);
        let ok = rs.iter().all(|&u| {
            let r = &func.ops[u];
            let at = r.inputs.iter().position(|&i| value_key(func, i) == key);
            let reads = match r.opcode {
                // (WS87: a call's target or argument, an intrinsic's operand, a select's arm)
                OpCode::Call | OpCode::CallInd => prints_operands(u),
                OpCode::CallOther => named_intrinsic(func, r),
                OpCode::Select => at.is_some_and(|i| i > 0),
                o => reader_ok(o),
            };
            u > d && r.block == op.block && reads && r.inputs.iter().filter(|&&i| value_key(func, i) == key).count() == 1
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

/// Temporaries copied to a register and read again by stores (WS88): `lock xadd` / a reference
/// count's `tmp_510 = *(m); rax = tmp_510; *(m) = tmp_510 - 1;`. The definition prints as the
/// copy's register (`rax = *(m); *(m) = rax - 1;`) and the copy prints nothing. Returns
/// `(definition, copy)`; `inlined` says which definitions print inside their readers.
///
/// The register takes the value at the definition instead of at the copy, so between the two
/// nothing reads or writes it; up to the last store reading the value (directly, or through a
/// pure op printed inside the store) nothing but the copy writes it.
pub(crate) fn coalesced(func: &SsaFunction, skip: &dyn Fn(OpIdx) -> bool, inlined: &dyn Fn(OpIdx) -> bool) -> Vec<(OpIdx, OpIdx)> {
    let readers = crate::condition::Readers::new(func);
    let live = |v: crate::ssa::VarId| -> smallvec::SmallVec<[OpIdx; 2]> {
        readers.of(func, v).iter().copied().filter(|&u| func.ops[u].opcode != OpCode::Indirect).collect()
    };
    let mut out = Vec::new();
    for (d, op) in func.ops.iter().enumerate() {
        if op.dead || skip(d) || inlined(d) || !(op.opcode == OpCode::Load || pure(op.opcode)) {
            continue;
        }
        let Some(v) = op.output else { continue };
        let vd = func.varnodes[v as usize].data;
        if vd.space != SpaceId::UNIQUE {
            continue;
        }
        let rs = live(v);
        let same = |u: OpIdx| u > d && func.ops[u].block == op.block;
        let copies: Vec<OpIdx> = rs
            .iter()
            .copied()
            .filter(|&u| {
                let r = &func.ops[u];
                r.opcode == OpCode::Copy
                    && same(u)
                    && r.output.is_some_and(|w| {
                        let wd = func.varnodes[w as usize].data;
                        wd.space == SpaceId::REGISTER && wd.size == vd.size
                    })
            })
            .collect();
        let [c] = copies.as_slice() else { continue };
        let c = *c;
        let reg = func.varnodes[func.ops[c].output.expect("filtered") as usize].data;
        // the other readers: stores, or pure ops printed inside stores
        let mut ends = Vec::new();
        let ok = rs.iter().filter(|&&u| u != c).all(|&u| {
            let r = &func.ops[u];
            if !same(u) {
                return false;
            }
            if r.opcode == OpCode::Store {
                ends.push(u);
                return true;
            }
            let Some(w) = r.output.filter(|&w| func.varnodes[w as usize].data.space == SpaceId::UNIQUE) else { return false };
            let ws = live(w);
            let stores = pure(r.opcode) && inlined(u) && !ws.is_empty() && ws.iter().all(|&s| same(s) && func.ops[s].opcode == OpCode::Store);
            ends.extend(ws.iter().copied());
            stores
        });
        if !ok || ends.is_empty() {
            continue;
        }
        let last = ends.iter().copied().max().expect("non-empty").max(c);
        let touches = |o: &crate::ssa::SsaOp, reads: bool| {
            o.output.is_some_and(|w| overlaps(&reg, &func.varnodes[w as usize].data))
                || (reads && o.inputs.iter().any(|&i| overlaps(&reg, &func.varnodes[i as usize].data)))
        };
        let clear = func.ops[d + 1..c].iter().all(|o| o.dead || !touches(o, true))
            && func.ops[c + 1..=last].iter().all(|o| o.dead || !touches(o, false));
        if clear {
            out.push((d, c));
        }
    }
    out
}
