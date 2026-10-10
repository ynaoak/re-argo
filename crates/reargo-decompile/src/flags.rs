//! Flags read away from their `cmp` become the comparison (WS82).
//!
//! x86 lifts `cmp a, b` into `t = a - b; ZF = t == 0; SF = t s< 0; CF = a < b;
//! OF = SBORROW(a, b)` and a `jl` into `SF != OF`. When the `jl` sits in the same block as the
//! `cmp` the condition folding of [`crate::condition`] prints `a < b`; when it does not (`cmp;
//! je L; jl M` puts the `jl` in the next block) the flags stay variables and `INT_SBORROW`
//! stays alive. This pass rewrites, in the SSA, an op that combines the flags of one `a - b`
//! into the comparison they test (`SF != OF` -> `a s< b`, `ZF || SF != OF` -> `a s<= b`,
//! `CF || ZF` -> `a <= b`, `t == 0` -> `a == b`), so the flag ops lose their readers and dead
//! code elimination drops them.
//!
//! The rewritten op reads `a` and `b` by name where it is (the C output names a value by its
//! register, not its SSA version), so it is rewritten only when no op writes over the storage
//! of `a` or `b` on any path from the flags' computation to it. A negated relation is left to
//! the `BoolNegate` that reads it (the printer turns `!(a < b)` into `a >= b`).

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

use crate::condition::{value_key, ValueKey};
use crate::ssa::{OpIdx, SsaFunction, VarId};

/// What a value computes from the flags of `a - b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rel {
    /// `a - b`
    Sub(VarId, VarId),
    /// the sign flag of `a - b`
    Sf(VarId, VarId),
    /// the signed-overflow flag of `a - b`
    Of(VarId, VarId),
    /// `a <op> b`, an integer comparison (`IntEqual`, `IntNotEqual`, `IntLess`,
    /// `IntLessEqual`, `IntSLess`, `IntSLessEqual`)
    Cmp(OpCode, VarId, VarId),
}

/// A relation and the ops that read `a` and `b` to compute it.
type Found = (Rel, SmallVec<[OpIdx; 2]>);

const MAX_DEPTH: u32 = 6;
/// Blocks searched backwards from a use for a write over an operand.
const MAX_BLOCKS: usize = 64;

fn is_zero(func: &SsaFunction, v: VarId) -> bool {
    let d = &func.varnodes[v as usize].data;
    d.space == SpaceId::CONST && d.offset == 0
}

fn relation(func: &SsaFunction, v: VarId, depth: u32, memo: &mut FxHashMap<ValueKey, Option<Found>>) -> Option<Found> {
    let key = value_key(func, v);
    if let Some(r) = memo.get(&key) {
        return r.clone();
    }
    let r = relation_uncached(func, v, depth, memo);
    memo.insert(key, r.clone());
    r
}

fn relation_uncached(
    func: &SsaFunction,
    v: VarId,
    depth: u32,
    memo: &mut FxHashMap<ValueKey, Option<Found>>,
) -> Option<Found> {
    use OpCode::*;
    if depth > MAX_DEPTH {
        return None;
    }
    let d = func.varnodes[v as usize].def_op?;
    let op = &func.ops[d];
    if op.dead {
        return None;
    }
    let same = |x: VarId, y: VarId| value_key(func, x) == value_key(func, y);
    let pair = |(a, b): (VarId, VarId), (c, e): (VarId, VarId)| same(a, c) && same(b, e);
    let (in0, in1) = (op.inputs.first().copied(), op.inputs.get(1).copied());
    let sub_of = |x: VarId, memo: &mut FxHashMap<ValueKey, Option<Found>>| match relation(func, x, depth + 1, memo) {
        Some((Rel::Sub(a, b), an)) => Some((a, b, an)),
        _ => None,
    };
    let leaf = |r: Rel| Some((r, smallvec::smallvec![d]));
    match op.opcode {
        IntSub if op.inputs.len() == 2 => leaf(Rel::Sub(in0?, in1?)),
        IntSBorrow if op.inputs.len() == 2 => leaf(Rel::Of(in0?, in1?)),
        IntEqual | IntNotEqual if is_zero(func, in1?) && sub_of(in0?, memo).is_some() => {
            let (a, b, an) = sub_of(in0?, memo)?;
            Some((Rel::Cmp(op.opcode, a, b), an))
        }
        IntSLess if is_zero(func, in1?) && sub_of(in0?, memo).is_some() => {
            let (a, b, an) = sub_of(in0?, memo)?;
            Some((Rel::Sf(a, b), an))
        }
        IntEqual | IntNotEqual | IntLess | IntLessEqual | IntSLess | IntSLessEqual if op.inputs.len() == 2 => {
            // the flags of `test r, r` compare `r & r`, which is `r`
            let a = match func.varnodes[in0? as usize].def_op.map(|t| &func.ops[t]) {
                Some(t) if t.opcode == IntAnd && t.inputs.len() == 2 && same(t.inputs[0], t.inputs[1]) && !t.dead => t.inputs[0],
                _ => in0?,
            };
            leaf(Rel::Cmp(op.opcode, a, in1?))
        }
        // `SF != 0`: after `test` / `and`, which clear OF, `jl` is the sign flag
        BoolXor if is_zero(func, in1?) => relation(func, in0?, depth + 1, memo),
        BoolXor if is_zero(func, in0?) => relation(func, in1?, depth + 1, memo),
        // SF != OF: signed less
        BoolXor => {
            let (x, ax) = relation(func, in0?, depth + 1, memo)?;
            let (y, ay) = relation(func, in1?, depth + 1, memo)?;
            let ((Rel::Sf(a, b), Rel::Of(c, e)) | (Rel::Of(c, e), Rel::Sf(a, b))) = (x, y) else { return None };
            if !pair((a, b), (c, e)) {
                return None;
            }
            Some((Rel::Cmp(IntSLess, a, b), ax.into_iter().chain(ay).collect()))
        }
        // a < b || a == b: a <= b
        BoolOr => {
            let (x, ax) = relation(func, in0?, depth + 1, memo)?;
            let (y, ay) = relation(func, in1?, depth + 1, memo)?;
            let (Rel::Cmp(p, a, b), Rel::Cmp(q, c, e)) = (x, y) else { return None };
            if !pair((a, b), (c, e)) {
                return None;
            }
            let le = match (p, q) {
                (IntLess, IntEqual) | (IntEqual, IntLess) => IntLessEqual,
                (IntSLess, IntEqual) | (IntEqual, IntSLess) => IntSLessEqual,
                _ => return None,
            };
            Some((Rel::Cmp(le, a, b), ax.into_iter().chain(ay).collect()))
        }
        _ => None,
    }
}

fn overlaps(x: &reargo_core::pcode::VarnodeData, w: &reargo_core::pcode::VarnodeData) -> bool {
    x.space == w.space && x.offset < w.offset + w.size as u64 && w.offset < x.offset + x.size as u64
}

/// Does every path from the anchors (the ops that read `a` and `b`) to `at` leave the storage
/// of `operands` untouched, so their names still mean the values at `at`?
fn operands_hold(func: &SsaFunction, block_start: &[usize], anchors: &[OpIdx], at: OpIdx, operands: &[VarId]) -> bool {
    let mut stores: SmallVec<[&reargo_core::pcode::VarnodeData; 2]> = SmallVec::new();
    for &v in operands {
        let d = &func.varnodes[v as usize].data;
        match d.space {
            SpaceId::CONST => {}
            SpaceId::REGISTER | SpaceId::UNIQUE => stores.push(d),
            _ => return false,
        }
    }
    let writes = |range: std::ops::Range<usize>| {
        func.ops[range].iter().any(|o| {
            !o.dead
                && o.output.is_some_and(|out| {
                    let w = &func.varnodes[out as usize].data;
                    stores.iter().any(|s| overlaps(s, w))
                })
        })
    };
    let anchor_blocks: SmallVec<[usize; 2]> = anchors.iter().map(|&a| func.ops[a].block).collect();
    // the anchors' own block: what runs from the first of them on counts (an anchor may
    // itself write over an operand: `sub eax, esi` reads `eax` and writes it)
    let after_anchor = |b: usize| anchors.iter().filter(|&&a| func.ops[a].block == b).copied().min();
    let end_of = |b: usize| block_start.get(b + 1).copied().unwrap_or(func.ops.len());
    let bx = func.ops[at].block;
    if let Some(from) = after_anchor(bx)
        && from <= at
    {
        // in the same block, after the anchor: only the ops in between
        return !writes(from..at);
    }
    if writes(block_start[bx]..at) {
        return false;
    }
    // every block on a path from the anchors' block to `bx`: the anchors dominate `at`
    let mut seen = vec![false; func.cfg.blocks.len()];
    let mut work: Vec<usize> = func.cfg.blocks[bx].predecessors.clone();
    let mut visited = 0;
    while let Some(b) = work.pop() {
        if seen[b] {
            continue;
        }
        seen[b] = true;
        visited += 1;
        if visited > MAX_BLOCKS {
            return false;
        }
        if anchor_blocks.contains(&b) {
            let Some(from) = after_anchor(b) else { return false };
            if writes(from..end_of(b)) {
                return false;
            }
            continue;
        }
        if writes(block_start[b]..end_of(b)) {
            return false;
        }
        if func.cfg.blocks[b].predecessors.is_empty() {
            // reached the entry without passing the anchors: they do not dominate
            return false;
        }
        work.extend(func.cfg.blocks[b].predecessors.iter().copied());
    }
    true
}

/// Rewrite the ops that combine the flags of one `a - b` into the comparison of `a` and `b`
/// (see the module doc). Returns how many ops were rewritten; run dead code elimination
/// afterwards to drop the flag ops nothing reads any more.
pub fn recover_flag_compares(func: &mut SsaFunction) -> usize {
    use OpCode::*;
    let n = func.cfg.blocks.len();
    let mut block_start = vec![func.ops.len(); n + 1];
    for op in func.ops.iter().rev() {
        if op.block < n {
            block_start[op.block] = op.index;
        }
    }
    // a block with no ops starts where the next one does
    for b in (0..n).rev() {
        block_start[b] = block_start[b].min(block_start[b + 1]);
    }
    let mut memo: FxHashMap<ValueKey, Option<Found>> = FxHashMap::default();
    let readers = crate::condition::Readers::new(func);
    let mut saved = 0u64;
    let mut rewritten = 0;
    // the outermost combination first (it comes last): `ZF || SF != OF` becomes one `a <= b`
    // before its `SF != OF` is looked at
    for i in (0..func.ops.len()).rev() {
        let op = &func.ops[i];
        if op.dead {
            continue;
        }
        let combines = match op.opcode {
            BoolXor | BoolOr => true,
            // `(a - b) == 0` -> `a == b`, `(r & r) == 0` (`test r, r`) -> `r == 0`; a zero test of
            // anything else is already the comparison
            IntEqual | IntNotEqual => {
                op.inputs.get(1).is_some_and(|&z| is_zero(func, z))
                    && func.varnodes[op.inputs[0] as usize].def_op.is_some_and(|d| {
                        let t = &func.ops[d];
                        t.opcode == IntSub || (t.opcode == IntAnd && t.inputs.len() == 2 && t.inputs[0] == t.inputs[1])
                    })
            }
            _ => false,
        };
        let Some(out) = op.output else { continue };
        if !combines {
            continue;
        }
        let Some((Rel::Cmp(cmp, a, b), anchors)) = relation(func, out, 0, &mut memo) else { continue };
        let holds = |func: &SsaFunction, v: VarId| operands_hold(func, &block_start, &anchors, i, &[v]);
        let (mut a, mut b) = (a, b);
        let mut save: Option<(OpIdx, VarId)> = None;
        for k in 0..2 {
            let v = if k == 0 { a } else { b };
            if holds(func, v) {
                continue;
            }
            // `mov rcx, rbp; sub rcx, r12`: the copied register may still hold the value
            if let Some(src) = copy_source(func, v)
                && holds(func, src)
            {
                if k == 0 { a = src } else { b = src }
                continue;
            }
            // `dec dword [m]; jle`: the operand is overwritten by the result. Keep its value
            // under a new name, set where the flags were computed (WS82): the overflow flag's
            // op, which nothing else will read
            match (save, saving_slot(func, &readers, &anchors, i, a, b)) {
                (None, Some(o)) => {
                    save = Some((o, v));
                }
                _ => {
                    save = None;
                    a = VarId::MAX;
                    break;
                }
            }
        }
        if a == VarId::MAX {
            continue;
        }
        if let Some((o, v)) = save {
            let s = save_value(func, o, v, saved);
            saved += 1;
            if v == a { a = s } else { b = s }
        }
        let old: SmallVec<[VarId; 3]> = func.ops[i].inputs.clone();
        func.ops[i].opcode = cmp;
        func.ops[i].inputs = smallvec::smallvec![a, b];
        for v in old {
            if !func.ops[i].inputs.contains(&v) {
                func.varnodes[v as usize].uses.retain(|&u| u != i);
            }
        }
        for v in [a, b] {
            let uses = &mut func.varnodes[v as usize].uses;
            if !uses.contains(&i) {
                uses.push(i);
            }
        }
        // what was cached for this value still holds (the same comparison)
        rewritten += 1;
    }
    rewritten
}

/// The value `v` copies (`v = COPY src`), if it is a copy.
fn copy_source(func: &SsaFunction, v: VarId) -> Option<VarId> {
    let d = func.varnodes[v as usize].def_op?;
    let op = &func.ops[d];
    (op.opcode == OpCode::Copy && !op.dead && op.inputs.len() == 1).then(|| op.inputs[0])
}

/// The overflow-flag op among `anchors` that reads `a` and `b` and whose result only reaches
/// op `at` (directly or through the `SF != OF` it feeds): rewriting `at` leaves it dead, so it
/// can keep an operand's value instead.
fn saving_slot(
    func: &SsaFunction,
    readers: &crate::condition::Readers,
    anchors: &[OpIdx],
    at: OpIdx,
    a: VarId,
    b: VarId,
) -> Option<OpIdx> {
    let same = |x: VarId, y: VarId| value_key(func, x) == value_key(func, y);
    anchors.iter().copied().find(|&o| {
        let op = &func.ops[o];
        if op.dead || op.opcode != OpCode::IntSBorrow || op.inputs.len() != 2 || !same(op.inputs[0], a) || !same(op.inputs[1], b) {
            return false;
        }
        let Some(of) = op.output else { return false };
        let r = readers.of(func, of);
        let live: SmallVec<[OpIdx; 2]> = r.iter().copied().filter(|&u| !func.ops[u].dead).collect();
        match live.as_slice() {
            [x] if *x == at => true,
            [x] => {
                let xo = &func.ops[*x];
                xo.opcode == OpCode::BoolXor
                    && xo.output.is_some_and(|xv| {
                        let r = readers.of(func, xv);
                        r.iter().all(|&u| u == at || func.ops[u].dead) && r.contains(&at)
                    })
            }
            _ => false,
        }
    })
}

/// Base of the unique-space offsets of the values [`save_value`] creates; printed `old_N`.
pub const SAVED_BASE: u64 = 0x5a7e_0000_0000;

/// Turn op `o` (an overflow flag nothing else needs) into `old_N = COPY v` and return `old_N`.
fn save_value(func: &mut SsaFunction, o: OpIdx, v: VarId, n: u64) -> VarId {
    let size = func.varnodes[v as usize].data.size;
    let id = func.varnodes.len() as VarId;
    func.varnodes.push(crate::ssa::SsaVarnode {
        id,
        data: reargo_core::pcode::VarnodeData::new(SpaceId::UNIQUE, SAVED_BASE + n * 0x10, size),
        version: 1,
        def_op: Some(o),
        uses: Vec::new(),
    });
    let old_inputs = func.ops[o].inputs.clone();
    for x in old_inputs {
        func.varnodes[x as usize].uses.retain(|&u| u != o);
    }
    if let Some(of) = func.ops[o].output {
        func.varnodes[of as usize].def_op = None;
    }
    let op = &mut func.ops[o];
    op.opcode = OpCode::Copy;
    op.inputs = smallvec::smallvec![v];
    op.output = Some(id);
    func.varnodes[v as usize].uses.push(o);
    id
}
