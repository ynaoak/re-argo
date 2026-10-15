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
    rewritten + compare_at_the_cmp(func)
}

/// WS90: `cmp esi, ecx; cmovl …; mov ecx, [m]; cmovge …` — the second `cmov` reads `SF != OF`
/// after `ecx` changed, so it cannot print `esi < ecx` where it is (it printed
/// `(!((int32_t)tmp_100 < (int32_t)0) != !var_20b)` with `var_20b = INT_SBORROW(...)`). When every
/// reader of an overflow flag left combines it with the sign flag of the same `a - b` into
/// `a s< b`, the overflow flag's op becomes that comparison — computed once, at the `cmp`,
/// where `a` and `b` are what it reads — and each `SF != OF` a copy of it.
fn compare_at_the_cmp(func: &mut SsaFunction) -> usize {
    use OpCode::*;
    let readers = crate::condition::Readers::new(func);
    let mut memo: FxHashMap<ValueKey, Option<Found>> = FxHashMap::default();
    let mut rewritten = 0;
    for o in 0..func.ops.len() {
        let op = &func.ops[o];
        if op.dead || op.opcode != IntSBorrow || op.inputs.len() != 2 {
            continue;
        }
        let Some(of) = op.output else { continue };
        let (a, b) = (op.inputs[0], op.inputs[1]);
        let same = |x: VarId, y: VarId| value_key(func, x) == value_key(func, y);
        let live: SmallVec<[OpIdx; 4]> = readers.of(func, of).iter().copied().filter(|&u| !func.ops[u].dead).collect();
        if live.is_empty() {
            continue;
        }
        // each reader: `SF != OF` of this `a - b`
        let all_lt = live.iter().all(|&x| {
            let xo = &func.ops[x];
            xo.opcode == BoolXor
                && xo.inputs.len() == 2
                && xo.output.is_some_and(|xv| match relation(func, xv, 0, &mut memo) {
                    Some((Rel::Cmp(IntSLess, c, e), anchors)) => same(a, c) && same(b, e) && anchors.contains(&o),
                    _ => false,
                })
        });
        if !all_lt {
            continue;
        }
        func.ops[o].opcode = IntSLess;
        for &x in &live {
            let inputs = func.ops[x].inputs.clone();
            let ofk = value_key(func, of);
            let Some(&ofv) = inputs.iter().find(|&&i| value_key(func, i) == ofk) else { continue };
            for &i in &inputs {
                if i != ofv {
                    func.varnodes[i as usize].uses.retain(|&u| u != x);
                }
            }
            func.ops[x].opcode = Copy;
            func.ops[x].inputs = smallvec::smallvec![ofv];
        }
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
    if func.varnodes.iter().any(|v| machine(&v.data) && v.data.size != 1) {
        return;
    }
    let mut index: FxHashMap<ValueKey, usize> = FxHashMap::default();
    let mut keys: Vec<ValueKey> = Vec::new();
    for v in 0..func.varnodes.len() {
        if machine(&func.varnodes[v].data) {
            let k = value_key(func, v as VarId);
            index.entry(k).or_insert_with(|| {
                keys.push(k);
                keys.len() - 1
            });
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
        let Some(&o) = index.get(&value_key(func, out)) else { continue };
        for &i in &op.inputs {
            match index.get(&value_key(func, i)) {
                Some(&x) => {
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
    // the definition of each version (any of its varnodes that has one)
    let mut def_of: Vec<Option<OpIdx>> = vec![None; keys.len()];
    for v in 0..func.varnodes.len() {
        if let Some(d) = func.varnodes[v].def_op
            && let Some(&n) = index.get(&value_key(func, v as VarId))
        {
            def_of[n].get_or_insert(d);
        }
    }
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
    for v in 0..func.varnodes.len() {
        if !machine(&func.varnodes[v].data) {
            continue;
        }
        let n = index[&value_key(func, v as VarId)];
        let r = find(&mut parent, n);
        if let Some(&off) = offset_of.get(&r) {
            func.varnodes[v].data.offset = off;
        }
    }
}

/// Make the numbers of the named flags dense in `text` (WS90): per kind, in the order the text
/// first names them (`lt_4`, `lt_9` -> `lt_0`, `lt_1`); a folded flag the output never names
/// leaves no gap.
pub(crate) fn renumber_named_flags(text: &str, func: &SsaFunction) -> String {
    let named: rustc_hash::FxHashSet<u64> = func
        .varnodes
        .iter()
        .filter(|v| v.data.space == SpaceId::REGISTER && v.data.offset >= NAMED_FLAG_BASE && named_flag(v.data.offset).is_some())
        .map(|v| v.data.offset - NAMED_FLAG_BASE)
        .collect();
    if named.is_empty() {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut map: FxHashMap<(usize, u64), u64> = FxHashMap::default();
    let mut next = [0u64; FLAG_KINDS.len()];
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        if ident(bytes[i]) && (i == 0 || !ident(bytes[i - 1])) {
            let start = i;
            while i < bytes.len() && ident(bytes[i]) {
                i += 1;
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
                out.push_str(&format!("{kind}_{m}"));
                copied = i;
            }
            continue;
        }
        i += 1;
    }
    out.push_str(&text[copied..]);
    out
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
