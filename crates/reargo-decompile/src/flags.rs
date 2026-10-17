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
pub(crate) fn operands_hold(func: &SsaFunction, block_start: &[usize], anchors: &[OpIdx], at: OpIdx, operands: &[VarId]) -> bool {
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
    let block_start = block_starts(func);
    let mut memo: FxHashMap<ValueKey, Option<Found>> = FxHashMap::default();
    // (the readers before any rewrite: built at the first op that combines flags, which comes
    // before the first rewrite; most functions have none)
    let mut readers: Option<crate::condition::Readers> = None;
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
        let readers = &*readers.get_or_insert_with(|| crate::condition::Readers::new(func));
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
            match (save, saving_slot(func, readers, &anchors, i, a, b)) {
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
                func.varnodes[v as usize].uses.retain(|&mut u| u != i);
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
    rewritten + compare_at_the_cmp(func)
}

/// WS90: `cmp esi, ecx; cmovl …; mov ecx, [m]; cmovge …` — the second `cmov` reads `SF != OF`
/// after `ecx` changed, so it cannot print `esi < ecx` where it is (it printed
/// `(!((int32_t)tmp_100 < (int32_t)0) != !var_20b)` with `var_20b = INT_SBORROW(...)`). When every
/// reader of an overflow flag left combines it with the sign flag of the same `a - b` into
/// `a s< b`, the overflow flag's op becomes that comparison — computed once, at the `cmp`,
/// where `a` and `b` are what it reads — and each `SF != OF` a copy of it.
///
/// The same through phis: `cmp a1, b1; jne L; cmp a2, b2; L: jl M` (a lexicographic compare)
/// reads `SF != OF` of whichever `cmp` ran last. When the sign-flag phi and the overflow-flag
/// phi join the flags of the same `cmp` on every edge, each `cmp`'s overflow flag becomes its
/// `a s< b` and the join reads their phi.
fn compare_at_the_cmp(func: &mut SsaFunction) -> usize {
    use OpCode::*;
    let def = |func: &SsaFunction, v: VarId| func.varnodes[v as usize].def_op.filter(|&d| !func.ops[d].dead);
    // does (`sf`, `of`) hold the sign and overflow flags of one `a - b` (through phis that join
    // them edge by edge)? Collects the overflow values (leaves and phis) on the way.
    fn pairs(func: &SsaFunction, sf: VarId, of: VarId, depth: u32, seen: &mut Vec<(ValueKey, ValueKey)>, ofs: &mut Vec<ValueKey>) -> bool {
        use OpCode::*;
        let key = (value_key(func, sf), value_key(func, of));
        if seen.contains(&key) {
            return true;
        }
        if depth > MAX_DEPTH * 2 || seen.len() > 64 {
            return false;
        }
        seen.push(key);
        let (Some(ds), Some(dof)) = (func.varnodes[sf as usize].def_op, func.varnodes[of as usize].def_op) else { return false };
        let (s, o) = (&func.ops[ds], &func.ops[dof]);
        if s.dead || o.dead {
            return false;
        }
        let same = |x: VarId, y: VarId| value_key(func, x) == value_key(func, y);
        match (s.opcode, o.opcode) {
            (MultiEqual, MultiEqual) => {
                if s.block != o.block || s.inputs.len() != o.inputs.len() {
                    return false;
                }
                ofs.push(key.1);
                s.inputs.iter().zip(&o.inputs).all(|(&a, &b)| pairs(func, a, b, depth + 1, seen, ofs))
            }
            // `test x, x` / `and`: OF is 0, `SF != OF` is the sign of the result (in the same
            // instruction, where the result is what SF reads)
            (IntSLess, Copy) if s.inputs.len() == 2 && is_zero(func, s.inputs[1]) && o.inputs.len() == 1 && is_zero(func, o.inputs[0]) && s.address == o.address => {
                ofs.push(key.1);
                true
            }
            (IntSLess, IntSBorrow) if s.inputs.len() == 2 && o.inputs.len() == 2 && is_zero(func, s.inputs[1]) => {
                let Some(t) = func.varnodes[s.inputs[0] as usize].def_op.map(|t| &func.ops[t]) else { return false };
                let ok = !t.dead && t.opcode == IntSub && t.inputs.len() == 2 && same(t.inputs[0], o.inputs[0]) && same(t.inputs[1], o.inputs[1]);
                if ok {
                    ofs.push(key.1);
                }
                ok
            }
            _ => false,
        }
    }
    // every `SF != OF` that pairs, with its overflow input and the overflow values it reaches
    let mut xors: Vec<(OpIdx, VarId, Vec<ValueKey>)> = Vec::new();
    for x in 0..func.ops.len() {
        let op = &func.ops[x];
        if op.dead || op.opcode != BoolXor || op.inputs.len() != 2 {
            continue;
        }
        for (sf, of) in [(op.inputs[0], op.inputs[1]), (op.inputs[1], op.inputs[0])] {
            let (mut seen, mut ofs) = (Vec::new(), Vec::new());
            if def(func, of).is_some() && pairs(func, sf, of, 0, &mut seen, &mut ofs) {
                xors.push((x, of, ofs));
                break;
            }
        }
    }
    if xors.is_empty() {
        return 0;
    }
    // (nothing changed the function above)
    let readers = crate::condition::Readers::new(func);
    // the overflow values to turn into comparisons: each read only by phis of the set and by
    // those `SF != OF` (a value read otherwise — `jo`, a phi with another input — drops out,
    // and with it every xor and phi reaching it)
    let mut set: rustc_hash::FxHashSet<ValueKey> = xors.iter().flat_map(|(_, _, o)| o.iter().copied()).collect();
    let mut live_xors: Vec<bool> = vec![true; xors.len()];
    let mut def_of: FxHashMap<ValueKey, OpIdx> = FxHashMap::default();
    for v in 0..func.varnodes.len() {
        if let Some(d) = func.varnodes[v].def_op {
            let k = value_key(func, v as VarId);
            if set.contains(&k) {
                def_of.entry(k).or_insert(d);
            }
        }
    }
    loop {
        let xor_ops: rustc_hash::FxHashSet<OpIdx> = xors.iter().zip(&live_xors).filter(|(_, l)| **l).map(|((x, _, _), _)| *x).collect();
        let mut drop: Vec<ValueKey> = Vec::new();
        for &k in &set {
            let rs = readers.of_key(&k);
            let ok = rs.iter().all(|&u| {
                let uo = &func.ops[u];
                uo.dead
                    || xor_ops.contains(&u)
                    || (uo.opcode == MultiEqual && uo.output.is_some_and(|o| set.contains(&value_key(func, o))))
            });
            if !ok {
                drop.push(k);
            }
        }
        // a phi of the set with an input outside it
        for &k in &set {
            let Some(&d) = def_of.get(&k) else { continue };
            if func.ops[d].opcode == MultiEqual && func.ops[d].inputs.iter().any(|&i| !set.contains(&value_key(func, i))) {
                drop.push(k);
            }
        }
        let mut changed = false;
        for k in drop {
            changed |= set.remove(&k);
        }
        for (i, (_, _, ofs)) in xors.iter().enumerate() {
            if live_xors[i] && ofs.iter().any(|k| !set.contains(k)) {
                live_xors[i] = false;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut rewritten = 0;
    for o in 0..func.ops.len() {
        let op = &func.ops[o];
        if op.dead || !op.output.is_some_and(|v| set.contains(&value_key(func, v))) {
            continue;
        }
        match op.opcode {
            IntSBorrow => {
                func.ops[o].opcode = IntSLess;
                rewritten += 1;
            }
            // the `OF = 0` of a `test`: its instruction's sign flag, `t < 0`
            Copy => {
                let near = &func.ops[o.saturating_sub(16)..(o + 16).min(func.ops.len())];
                let sign = near.iter().find(|s| {
                    !s.dead && s.address == op.address && s.block == op.block && s.opcode == IntSLess && s.inputs.len() == 2 && is_zero(func, s.inputs[1])
                });
                let Some(inputs) = sign.map(|s| s.inputs.clone()) else { continue };
                let old = std::mem::replace(&mut func.ops[o].inputs, inputs.clone());
                for v in old {
                    func.varnodes[v as usize].uses.retain(|&mut u| u != o);
                }
                for v in inputs {
                    func.varnodes[v as usize].uses.push(o);
                }
                func.ops[o].opcode = IntSLess;
                rewritten += 1;
            }
            _ => {}
        }
    }
    for ((x, of, _), live) in xors.iter().zip(&live_xors) {
        if !live {
            continue;
        }
        let inputs = func.ops[*x].inputs.clone();
        for &i in &inputs {
            if i != *of {
                func.varnodes[i as usize].uses.retain(|&mut u| u != *x);
            }
        }
        func.ops[*x].opcode = Copy;
        func.ops[*x].inputs = smallvec::smallvec![*of];
        rewritten += 1;
    }
    rewritten
}

/// The first op of each block (a block with no ops starts where the next one does), and the
/// end of the ops last.
pub(crate) fn block_starts(func: &SsaFunction) -> Vec<usize> {
    let n = func.cfg.blocks.len();
    let mut block_start = vec![func.ops.len(); n + 1];
    for op in func.ops.iter().rev() {
        if op.block < n {
            block_start[op.block] = op.index;
        }
    }
    for b in (0..n).rev() {
        block_start[b] = block_start[b].min(block_start[b + 1]);
    }
    block_start
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
        uses: crate::ssa::UseVec::new(),
    });
    let old_inputs = func.ops[o].inputs.clone();
    for x in old_inputs {
        func.varnodes[x as usize].uses.retain(|&mut u| u != o);
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

/// Base of the register-space offsets [`name_flag_webs`] gives the flags it names (WS90).
pub const NAMED_FLAG_BASE: u64 = 0x6f00_0000;
/// The names' prefixes, by kind: the offset is `NAMED_FLAG_BASE + kind * 0x10000 + n`.
const FLAG_KINDS: [&str; 8] = ["lt", "le", "eq", "ne", "neg", "carry", "ovf", "cond"];

/// The machine flags (CF..OF) and the flags [`name_flag_webs`] named.
pub(crate) fn is_flag_storage(d: &reargo_core::pcode::VarnodeData) -> bool {
    d.space == SpaceId::REGISTER && ((0x200..0x210).contains(&d.offset) || (NAMED_FLAG_BASE..NAMED_FLAG_BASE + 0x0100_0000).contains(&d.offset))
}

/// The name of a flag [`name_flag_webs`] named (`lt_3`), by its register offset.
pub(crate) fn named_flag(offset: u64) -> Option<String> {
    let k = offset.checked_sub(NAMED_FLAG_BASE)?;
    let kind = FLAG_KINDS.get((k >> 16) as usize)?;
    Some(format!("{kind}_{}", k & 0xffff))
}

/// WS90: each flag value the output may name becomes a boolean of its own. A machine flag is
/// one register written by every compare (`var_201` is the carry flag of whichever `cmp` ran
/// last), so a flag kept as a statement read like a register, and any later compare counted as
/// overwriting it. The versions of a flag joined by phis (a web) are one variable; each web whose
/// every version is computed in the function gets a register of its own, named by what it
/// computes — `lt_0 = a < b;` (`IntLess` / `IntSLess` / `FloatLess`), `le`, `eq`, `ne`, `neg`
/// (`x < 0`, the sign flag), `carry`, `ovf`, else `cond`. Every name of a value moves together
/// (common subexpression elimination leaves several varnodes per value), so the program is the
/// same; the numbers are made dense later, in the order the output names them
/// ([`renumber_named_flags`]).
pub fn name_flag_webs(func: &mut SsaFunction) {
    use OpCode::*;
    let machine = |d: &reargo_core::pcode::VarnodeData| d.space == SpaceId::REGISTER && (0x200..0x210).contains(&d.offset);
    // (a wider access over the flags — none is lifted — would have to move with them)
    // the versions of the machine flags (by value key), each varnode's (`usize::MAX`: no flag),
    // and the definition of each version (any of its varnodes that has one): one walk
    let mut index: FxHashMap<ValueKey, usize> = FxHashMap::default();
    let mut keys: Vec<ValueKey> = Vec::new();
    let mut version_of: Vec<usize> = vec![usize::MAX; func.varnodes.len()];
    let mut def_of: Vec<Option<OpIdx>> = Vec::new();
    for (v, version) in version_of.iter_mut().enumerate() {
        let vn = &func.varnodes[v];
        if machine(&vn.data) {
            if vn.data.size != 1 {
                return;
            }
            let k = value_key(func, v as VarId);
            let n = *index.entry(k).or_insert_with(|| {
                keys.push(k);
                def_of.push(None);
                keys.len() - 1
            });
            *version = n;
            if let Some(d) = vn.def_op {
                def_of[n].get_or_insert(d);
            }
        }
    }
    if keys.is_empty() {
        return;
    }
    let mut parent: Vec<usize> = (0..keys.len()).collect();
    fn find(p: &mut [usize], mut x: usize) -> usize {
        while p[x] != x {
            p[x] = p[p[x]];
            x = p[x];
        }
        x
    }
    // the web's kind (`usize::MAX` = not yet known), and whether a version has no definition
    let mut kind = vec![usize::MAX; keys.len()];
    let mut open = vec![false; keys.len()];
    let mut first_def = vec![usize::MAX; keys.len()];
    for op in &func.ops {
        if op.dead || op.opcode != MultiEqual {
            continue;
        }
        let Some(out) = op.output else { continue };
        // (only the machine flags are indexed)
        let indexed = |v: VarId| Some(version_of[v as usize]).filter(|&n| n != usize::MAX);
        let Some(o) = indexed(out) else { continue };
        for &i in &op.inputs {
            match indexed(i) {
                Some(x) => {
                    let (a, b) = (find(&mut parent, o), find(&mut parent, x));
                    parent[a] = b;
                }
                None => open[o] = true,
            }
        }
    }
    let is_zero = |func: &SsaFunction, v: VarId| {
        let d = &func.varnodes[v as usize].data;
        d.space == SpaceId::CONST && d.offset == 0
    };
    for (n, &def) in def_of.iter().enumerate() {
        let r = find(&mut parent, n);
        let Some(d) = def else {
            open[r] = true;
            continue;
        };
        let op = &func.ops[d];
        if op.opcode == MultiEqual {
            continue;
        }
        first_def[r] = first_def[r].min(d);
        let this = match op.opcode {
            IntSLess if op.inputs.len() == 2 && is_zero(func, op.inputs[1]) => 4,
            IntLess | IntSLess | FloatLess => 0,
            IntLessEqual | IntSLessEqual | FloatLessEqual => 1,
            IntEqual | FloatEqual => 2,
            IntNotEqual | FloatNotEqual => 3,
            IntCarry => 5,
            IntSCarry | IntSBorrow => 6,
            _ => 7,
        };
        kind[r] = if kind[r] == usize::MAX || kind[r] == this { this } else { 7 };
    }
    // a web is open when any version in it is
    for n in 0..keys.len() {
        if open[n] {
            let r = find(&mut parent, n);
            open[r] = true;
        }
    }
    let mut roots: Vec<usize> = (0..keys.len()).filter(|&n| find(&mut parent, n) == n && !open[n] && kind[n] != usize::MAX).collect();
    roots.sort_by_key(|&r| first_def[r]);
    let mut count = [0u64; FLAG_KINDS.len()];
    let mut offset_of: FxHashMap<usize, u64> = FxHashMap::default();
    for r in roots {
        let k = kind[r];
        if count[k] >= 0x10000 {
            continue;
        }
        offset_of.insert(r, NAMED_FLAG_BASE + ((k as u64) << 16) + count[k]);
        count[k] += 1;
    }
    for (v, &n) in version_of.iter().enumerate() {
        if n == usize::MAX {
            continue;
        }
        let r = find(&mut parent, n);
        if let Some(&off) = offset_of.get(&r) {
            func.varnodes[v].data.offset = off;
        }
    }
}

/// Make the numbers of the named flags dense in `text` (WS90): per kind, in the order the text
/// first names them (`lt_4`, `lt_9` -> `lt_0`, `lt_1`); a folded flag the output never names
/// leaves no gap. (In place: a text naming no flag is left as it is.)
pub(crate) fn renumber_named_flags(text: &mut String, func: &SsaFunction) {
    let named: rustc_hash::FxHashSet<u64> = func
        .varnodes
        .iter()
        .filter(|v| {
            v.data.space == SpaceId::REGISTER
                && v.data.offset.checked_sub(NAMED_FLAG_BASE).is_some_and(|k| ((k >> 16) as usize) < FLAG_KINDS.len())
        })
        .map(|v| v.data.offset - NAMED_FLAG_BASE)
        .collect();
    if named.is_empty() {
        return;
    }
    use std::fmt::Write as _;
    let bytes = text.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    // (the first letters of the kinds: a word starting otherwise names no flag)
    let starts = |c: u8| FLAG_KINDS.iter().any(|k| k.as_bytes()[0] == c);
    let mut map: FxHashMap<(usize, u64), u64> = FxHashMap::default();
    let mut next = [0u64; FLAG_KINDS.len()];
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    // each word holding a `_` (a flag name holds one): from the `_`, back to its start and on
    // to its end
    let mut pos = 0;
    while let Some(off) = text[pos..].find('_') {
        let under = pos + off;
        let mut start = under;
        while start > 0 && ident(bytes[start - 1]) {
            start -= 1;
        }
        let mut i = under + 1;
        while i < bytes.len() && ident(bytes[i]) {
            i += 1;
        }
        pos = i;
        if start == under || !starts(bytes[start]) {
            continue;
        }
        let word = &text[start..i];
        if let Some((kind, num)) = word.split_once('_')
            && let Some(k) = FLAG_KINDS.iter().position(|&p| p == kind)
            && !num.is_empty()
            && num.bytes().all(|c| c.is_ascii_digit())
            && let Ok(n) = num.parse::<u64>()
            && named.contains(&(((k as u64) << 16) + n))
        {
            let m = *map.entry((k, n)).or_insert_with(|| {
                next[k] += 1;
                next[k] - 1
            });
            out.push_str(&text[copied..start]);
            let _ = write!(out, "{kind}_{m}");
            copied = i;
        }
    }
    if copied == 0 {
        return;
    }
    out.push_str(&text[copied..]);
    *text = out;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_flags_by_kind() {
        assert_eq!(named_flag(NAMED_FLAG_BASE + 3).as_deref(), Some("lt_3"));
        assert_eq!(named_flag(NAMED_FLAG_BASE + (2 << 16)).as_deref(), Some("eq_0"));
        assert_eq!(named_flag(NAMED_FLAG_BASE + (7 << 16) + 1).as_deref(), Some("cond_1"));
        assert_eq!(named_flag(0x201), None);
        let d = |o| reargo_core::pcode::VarnodeData::new(SpaceId::REGISTER, o, 1);
        assert!(is_flag_storage(&d(0x206)) && is_flag_storage(&d(NAMED_FLAG_BASE + 5)) && !is_flag_storage(&d(0x10)));
    }
}
