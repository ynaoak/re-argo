//! Short-circuit conditions: `if (a) goto X; if (b) goto X;` -> `if (a || b) goto X;`.
//!
//! A compiler lowers `if (a || b) S else Y` to two conditional jumps: block `A` tests `a` and
//! jumps to `S`, else falls into block `B`, which tests `b` and jumps to `S` or `Y`. Structured
//! as is, `S` is printed in one arm and the other test needs a `goto` to it. When `B` holds
//! nothing but its test (every other op of the block feeds the branch condition and nothing
//! else — see [`condition_ops`]), the pair is one decision: [`merge_short_circuits`] collapses
//! `B` into `A` on a copy of the CFG (`A`'s successors become `[S, Y]`) and records the
//! condition `A` now branches on as a [`Cond`] tree. `&&` is the same shape seen from the other
//! successor (`!(a' || b')`), so one rule covers both. Chains (`a || b || c`) collapse to a
//! fixpoint.
//!
//! The emitters print `A`'s own statements, then the tree: `A`'s leaf is its condition
//! variable, every other leaf is the folded expression of its block's ops.

use rustc_hash::FxHashMap;

use crate::cfg::{BlockId, ControlFlowGraph};
use crate::ssa::{OpIdx, SsaFunction, VarId};
use reargo_core::pcode::OpCode;

/// The condition a (merged) block branches to its first successor on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    /// The original branch condition of `block` (to its first CFG successor), `!` when
    /// `negated`.
    Leaf { block: BlockId, negated: bool },
    Or(Vec<Cond>),
    And(Vec<Cond>),
}

impl Cond {
    /// `!self`, pushed down to the leaves (De Morgan).
    pub fn negate(self) -> Cond {
        match self {
            Cond::Leaf { block, negated } => Cond::Leaf { block, negated: !negated },
            Cond::Or(v) => Cond::And(v.into_iter().map(Cond::negate).collect()),
            Cond::And(v) => Cond::Or(v.into_iter().map(Cond::negate).collect()),
        }
    }

    fn or(a: Cond, b: Cond) -> Cond {
        let mut v = Vec::new();
        for c in [a, b] {
            match c {
                Cond::Or(xs) => v.extend(xs),
                c => v.push(c),
            }
        }
        Cond::Or(v)
    }

    /// Print the tree. `leaf(block, negated)` is the text of `block`'s own condition (to its
    /// first successor), inverted when `negated`.
    pub fn render(&self, negated: bool, leaf: &mut dyn FnMut(BlockId, bool) -> String) -> String {
        if negated {
            return self.clone().negate().render(false, leaf);
        }
        match self {
            Cond::Leaf { block, negated } => leaf(*block, *negated),
            Cond::Or(v) | Cond::And(v) => {
                let op = if matches!(self, Cond::Or(_)) { " || " } else { " && " };
                let parts: Vec<String> = v
                    .iter()
                    .map(|c| {
                        let s = c.render(false, leaf);
                        if is_atomic(&s) { s } else { format!("({s})") }
                    })
                    .collect();
                parts.join(op)
            }
        }
    }
}

/// An expression that needs no parentheses as an operand: a name / number, a parenthesised
/// whole, a call-like `f(…)`, or `!` before one of these.
pub fn is_atomic(s: &str) -> bool {
    let word = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if word(s) {
        return true;
    }
    if let Some(rest) = s.strip_prefix('!') {
        return is_atomic(rest);
    }
    // `(…)` / `f(…)` whose first `(` closes at the very end
    let Some(open) = s.find('(') else { return false };
    if !(open == 0 || word(&s[..open])) || !s.ends_with(')') {
        return false;
    }
    let mut depth = 0i32;
    for (i, c) in s.char_indices().skip(open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i == s.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}

/// Ops of a pure computation (no memory write, no call): they can be folded into an
/// expression that is evaluated later, or not at all.
fn is_pure(op: OpCode) -> bool {
    use OpCode::*;
    matches!(
        op,
        Copy | Load
            | IntEqual | IntNotEqual | IntSLess | IntSLessEqual | IntLess | IntLessEqual
            | IntZExt | IntSExt | IntAdd | IntSub | IntCarry | IntSCarry | IntSBorrow
            | Int2Comp | IntNegate | IntXor | IntAnd | IntOr | IntLeft | IntRight | IntSRight
            | IntMult
            | BoolNegate | BoolXor | BoolAnd | BoolOr
            | FloatEqual | FloatNotEqual | FloatLess | FloatLessEqual | FloatNan
            | FloatAdd | FloatDiv | FloatMult | FloatSub | FloatNeg | FloatAbs | FloatSqrt
            | FloatInt2Float | FloatFloat2Float | FloatTrunc | FloatCeil | FloatFloor | FloatRound
            | Piece | Subpiece | PopCount | LzCount
    )
}

/// The live ops of every block, in order.
pub fn ops_by_block(func: &SsaFunction) -> Vec<Vec<OpIdx>> {
    let mut v = vec![Vec::new(); func.cfg.blocks.len()];
    for op in &func.ops {
        if !op.dead && op.block < v.len() {
            v[op.block].push(op.index);
        }
    }
    v
}

/// Longest expression folded into a condition; a longer one stays a statement.
const MAX_FOLDED_LEN: usize = 240;

/// The identity of an SSA value: `(space, offset, size, version)`. Common subexpression
/// elimination renames a removed op's result to the earlier value instead of rewriting its
/// readers, so two varnode ids can name one value; their `uses` lists are separate.
pub type ValueKey = (u32, u64, u32, u32);

pub fn value_key(func: &SsaFunction, v: VarId) -> ValueKey {
    let vn = &func.varnodes[v as usize];
    (vn.data.space.0, vn.data.offset, vn.data.size, vn.version)
}

/// The live ops reading each value (by [`ValueKey`], so every name of a value counts).
pub struct Readers(FxHashMap<ValueKey, smallvec::SmallVec<[OpIdx; 2]>>);

impl Readers {
    pub fn new(func: &SsaFunction) -> Self {
        let mut m: FxHashMap<ValueKey, smallvec::SmallVec<[OpIdx; 2]>> = FxHashMap::default();
        for op in func.ops.iter().filter(|o| !o.dead) {
            for &i in &op.inputs {
                if func.varnodes[i as usize].data.space == reargo_core::address::SpaceId::CONST {
                    continue;
                }
                let r = m.entry(value_key(func, i)).or_default();
                if r.last() != Some(&op.index) {
                    r.push(op.index);
                }
            }
        }
        Readers(m)
    }

    /// The live ops reading `v`.
    pub fn of(&self, func: &SsaFunction, v: VarId) -> &[OpIdx] {
        self.0.get(&value_key(func, v)).map_or(&[], |r| r.as_slice())
    }

    /// The live ops reading the value `k`.
    pub fn of_key(&self, k: &ValueKey) -> &[OpIdx] {
        self.0.get(k).map_or(&[], |r| r.as_slice())
    }
}

/// When `block` holds nothing but its test, the ops computing the condition (in order, the
/// `CBRANCH` excluded): every live op but the branch is pure and its result is read only by
/// later ops of the same block — so the ops fold into one expression, nothing else
/// sees their results and nothing is lost by not printing them as statements.
pub fn condition_ops(func: &SsaFunction, ops: &[OpIdx], readers: &Readers) -> Option<Vec<OpIdx>> {
    let tail = condition_tail(func, ops, readers);
    (tail.len() + 1 == ops.len()).then_some(tail)
}

/// The ops of `ops` (a block's live ops) that only compute its branch condition (WS81), in
/// order: pure ops whose result is read only by later ops of the set or the branch (by one of
/// them, or — `a - b` / `a & b` of a `cmp` / `test` — by the flags computed from it). They fold
/// into the condition expression (`var_201 = edi < 6; if (var_201)` -> `if (edi < 6)`), which
/// is evaluated at the branch: WS89 — not only the run right before the `CBRANCH` but also an
/// op further up when the statements between it and the branch write nothing it reads (no
/// register / temporary of its inputs; no memory, when it loads): `var_206 = rax == 0;
/// rcx = *(uint64_t*)rsp; if (!var_206)` -> `rcx = *(uint64_t*)rsp; if (rax != 0)`. Empty when
/// the block does not end in a `CBRANCH`.
pub fn condition_tail(func: &SsaFunction, ops: &[OpIdx], readers: &Readers) -> Vec<OpIdx> {
    let Some((&last, body)) = ops.split_last() else { return Vec::new() };
    let br = &func.ops[last];
    if br.opcode != OpCode::CBranch || br.inputs.len() < 2 {
        return Vec::new();
    }
    let mut chain: Vec<OpIdx> = vec![last];
    // what the ops left out (printed between a folded op and the branch) write
    let mut written: Vec<reargo_core::pcode::VarnodeData> = Vec::new();
    let mut memory_written = false;
    for &o in body.iter().rev() {
        let op = &func.ops[o];
        let folds = op.output.is_some_and(|out| {
            if !is_pure(op.opcode) {
                return false;
            }
            // read by several ops only when it is what a compare's flags are computed from
            let r = readers.of(func, out);
            let shared_ok = r.len() == 1 || matches!(op.opcode, OpCode::IntSub | OpCode::IntAnd);
            if r.is_empty() || !shared_ok || !r.iter().all(|u| chain.contains(u)) {
                return false;
            }
            // nothing printed after it changes what it reads — also through the definitions of
            // its inputs in the block that may print inside it (a `setcc`'s folded comparison,
            // an inlined temporary: `cl = rax == rbx; rbx = rax; if (… | cl)` must keep `cl`)
            let mut leaves = Vec::new();
            let mut loads = op.opcode == OpCode::Load;
            for &i in &op.inputs {
                collect_leaves(func, readers, i, op.block, 0, &mut leaves, &mut loads);
            }
            let reads_changed = leaves.iter().any(|d| written.iter().any(|w| w.overlaps(d)));
            !(reads_changed || (loads && memory_written))
        });
        if folds {
            chain.push(o);
            continue;
        }
        // (a phi is no statement: it is first in the block, nothing folds above it)
        if op.opcode == OpCode::MultiEqual {
            break;
        }
        if let Some(out) = op.output {
            written.push(func.varnodes[out as usize].data);
        }
        if matches!(op.opcode, OpCode::Store | OpCode::Call | OpCode::CallInd | OpCode::CallOther) {
            memory_written = true;
        }
        // (a call also writes the registers its INDIRECTs name, listed as ops of their own)
    }
    chain.remove(0);
    chain.reverse();
    chain
}

/// The storage `v` reads, and — through its pure definition in `block` — what that reads (up
/// to a depth); `loads` when a load is among them. A temporary copied to a register may print
/// as that register (`emit::Coalesced`): the register counts too.
fn collect_leaves(
    func: &SsaFunction,
    readers: &Readers,
    v: VarId,
    block: BlockId,
    depth: u32,
    out: &mut Vec<reargo_core::pcode::VarnodeData>,
    loads: &mut bool,
) {
    let d = func.varnodes[v as usize].data;
    if d.space == reargo_core::address::SpaceId::CONST {
        return;
    }
    out.push(d);
    if d.space == reargo_core::address::SpaceId::UNIQUE {
        for &r in readers.of(func, v) {
            let op = &func.ops[r];
            if op.opcode == OpCode::Copy && let Some(o) = op.output {
                out.push(func.varnodes[o as usize].data);
            }
        }
    }
    let Some(def) = func.varnodes[v as usize].def_op.map(|o| &func.ops[o]) else { return };
    // (only a temporary or a flag may print inside its reader — an inlined temporary, a `setcc`'s
    // folded comparison; a register is assigned by a statement and stands for its value)
    let inlinable = d.space == reargo_core::address::SpaceId::UNIQUE
        || crate::flags::is_flag_storage(&d);
    if def.dead || def.block != block || !is_pure(def.opcode) || depth >= 6 || !inlinable {
        return;
    }
    *loads |= def.opcode == OpCode::Load;
    for &i in &def.inputs {
        collect_leaves(func, readers, i, block, depth + 1, out, loads);
    }
}

/// The CFG with short-circuit tests merged, and the condition of each merged block.
pub struct ShortCircuits {
    pub cfg: ControlFlowGraph,
    pub conds: FxHashMap<BlockId, Cond>,
}

/// Collapse `A -> {S, B}, B -> {S, Y}` into `A -> {S, Y}` when `B` is reached only from `A`
/// and holds nothing but its test (see the module doc). `None` when nothing merges.
pub fn merge_short_circuits(func: &SsaFunction) -> Option<ShortCircuits> {
    let src = &func.cfg;
    let n = src.blocks.len();
    let by_block = ops_by_block(func);
    let readers = Readers::new(func);
    let pure: Vec<bool> = by_block.iter().map(|ops| condition_ops(func, ops, &readers).is_some()).collect();
    let two = |s: &[BlockId]| s.len() == 2 && s[0] != s[1];
    // a block that prints nothing and goes on to one other block (a lone `jmp`)
    let empty: Vec<bool> = (0..n)
        .map(|b| {
            b != src.entry_block
                && matches!(src.blocks[b].successors.as_slice(), [s] if *s != b)
                && by_block[b].iter().all(|&o| matches!(func.ops[o].opcode, OpCode::Branch | OpCode::MultiEqual))
        })
        .collect();
    // quick check before copying the CFG
    let any = empty.iter().any(|&e| e)
        || (0..n).any(|b| {
            pure[b]
                && b != src.entry_block
                && src.blocks[b].predecessors.len() == 1
                && two(&src.blocks[b].successors)
                && two(&src.blocks[src.blocks[b].predecessors[0]].successors)
        });
    if !any {
        return None;
    }

    let mut cfg = src.clone();
    thread_empty_blocks(&mut cfg, &empty);
    let mut conds: FxHashMap<BlockId, Cond> = FxHashMap::default();
    let cond_of = |conds: &FxHashMap<BlockId, Cond>, b: BlockId| {
        conds.get(&b).cloned().unwrap_or(Cond::Leaf { block: b, negated: false })
    };
    let mut changed = true;
    while changed {
        changed = false;
        for (b, &pure_b) in pure.iter().enumerate() {
            // `b` is the inner test `B`
            if !pure_b || b == cfg.entry_block || cfg.blocks[b].predecessors.len() != 1 {
                continue;
            }
            let a = cfg.blocks[b].predecessors[0];
            let (sa, sb) = (cfg.blocks[a].successors.clone(), cfg.blocks[b].successors.clone());
            // (a jump table's successors are its cases, WS83)
            if a == b || !two(&sa) || !two(&sb) || cfg.switches.contains_key(&a) || cfg.switches.contains_key(&b) {
                continue;
            }
            // S: the successor both share; A's other one is B
            let Some(ia) = sa.iter().position(|&x| x != b) else { continue };
            let s = sa[ia];
            if sa[1 - ia] != b {
                continue;
            }
            let Some(ib) = sb.iter().position(|&x| x == s) else { continue };
            let y = sb[1 - ib];
            // condition of A / B for going to S (`succs[0]` is the branch's "true" target)
            let ca = if ia == 0 { cond_of(&conds, a) } else { cond_of(&conds, a).negate() };
            let cb = if ib == 0 { cond_of(&conds, b) } else { cond_of(&conds, b).negate() };
            conds.insert(a, Cond::or(ca, cb));
            conds.remove(&b);
            cfg.blocks[a].successors = vec![s, y];
            cfg.blocks[b].successors.clear();
            cfg.blocks[b].predecessors.clear();
            // S was reached from both A and B: A stays its predecessor
            cfg.blocks[s].predecessors.retain(|&p| p != b);
            for p in &mut cfg.blocks[y].predecessors {
                if *p == b {
                    *p = a;
                }
            }
            changed = true;
        }
    }
    Some(ShortCircuits { cfg, conds })
}

/// Jump threading of the blocks that print nothing (`empty`, a lone `jmp`): every edge into
/// one goes straight to where it leads. Printing such a block is free, but as a block it is
/// a join of its own — shared by two arms without being their join, it needs a `goto`.
/// Blocks no longer reachable lose their edges; predecessor lists are rebuilt.
fn thread_empty_blocks(cfg: &mut ControlFlowGraph, empty: &[bool]) {
    let n = cfg.blocks.len();
    let resolve = |cfg: &ControlFlowGraph, mut b: BlockId| {
        let mut steps = 0;
        while empty[b] && steps < n {
            b = cfg.blocks[b].successors[0];
            steps += 1;
        }
        b
    };
    let mut changed = false;
    for b in 0..n {
        // a jump table's successors stay its cases (WS83: `switches` names them)
        if cfg.switches.contains_key(&b) {
            continue;
        }
        let succs = cfg.blocks[b].successors.clone();
        let mut new: Vec<BlockId> = succs.iter().map(|&s| resolve(cfg, s)).collect();
        if new != succs {
            // both arms reach the same block now: the test decides nothing
            if new.len() == 2 && new[0] == new[1] {
                new.pop();
            }
            cfg.blocks[b].successors = new;
            changed = true;
        }
    }
    if !changed {
        return;
    }
    let mut reach = vec![false; n];
    let mut stack = vec![cfg.entry_block];
    while let Some(b) = stack.pop() {
        if std::mem::replace(&mut reach[b], true) {
            continue;
        }
        stack.extend(cfg.blocks[b].successors.iter().copied().filter(|&s| !reach[s]));
    }
    for (block, &r) in cfg.blocks.iter_mut().zip(&reach) {
        if !r {
            block.successors.clear();
        }
        block.predecessors.clear();
    }
    for b in 0..n {
        for i in 0..cfg.blocks[b].successors.len() {
            let s = cfg.blocks[b].successors[i];
            if !cfg.blocks[s].predecessors.contains(&b) {
                cfg.blocks[s].predecessors.push(b);
            }
        }
    }
}

/// What a flag computation of a condition stands for (WS81), so `cmp a, b; jbe` prints
/// `a <= b` rather than the flags' formula `a < b || (a - b) == 0`.
#[derive(Debug, Clone, Copy)]
enum Rel {
    /// `a - b`
    Sub(VarId, VarId),
    /// the sign flag of `a - b`
    Sf(VarId, VarId),
    /// the signed-overflow flag of `a - b`
    Of(VarId, VarId),
    /// `a <op> b` (an integer comparison), inverted when `negated`
    Cmp { op: OpCode, a: VarId, b: VarId, negated: bool },
}

/// The relation `op` computes from the relations of its inputs (`rels`), if it is one.
fn relation(func: &SsaFunction, op: &crate::ssa::SsaOp, rels: &FxHashMap<ValueKey, Rel>) -> Option<Rel> {
    use OpCode::*;
    // a relation of the condition's ops, or `a - b` computed earlier in the block (a `cmp`
    // whose result several flags read) when `a` and `b` still hold their values at the end
    let rel = |i: usize| {
        let v = *op.inputs.get(i)?;
        rels.get(&value_key(func, v)).copied().or_else(|| earlier_sub(func, v, op.block))
    };
    let zero = |i: usize| {
        op.inputs.get(i).is_some_and(|&v| {
            let d = &func.varnodes[v as usize].data;
            d.space == reargo_core::address::SpaceId::CONST && d.offset == 0
        })
    };
    let same = |x: VarId, y: VarId| value_key(func, x) == value_key(func, y);
    let pair = |a1: VarId, b1: VarId, a2: VarId, b2: VarId| same(a1, a2) && same(b1, b2);
    let (in0, in1) = (op.inputs.first().copied(), op.inputs.get(1).copied());
    Some(match op.opcode {
        IntSub => Rel::Sub(in0?, in1?),
        IntEqual | IntNotEqual if zero(1) && matches!(rel(0), Some(Rel::Sub(..))) => {
            let Some(Rel::Sub(a, b)) = rel(0) else { return None };
            Rel::Cmp { op: op.opcode, a, b, negated: false }
        }
        IntSLess if zero(1) && matches!(rel(0), Some(Rel::Sub(..))) => {
            let Some(Rel::Sub(a, b)) = rel(0) else { return None };
            Rel::Sf(a, b)
        }
        IntSBorrow => Rel::Of(in0?, in1?),
        IntEqual | IntNotEqual | IntLess | IntLessEqual | IntSLess | IntSLessEqual | FloatEqual | FloatNotEqual
        | FloatLess | FloatLessEqual => Rel::Cmp { op: op.opcode, a: in0?, b: in1?, negated: false },
        // SF != OF: signed less
        BoolXor => match (rel(0)?, rel(1)?) {
            (Rel::Sf(a, b), Rel::Of(c, d)) | (Rel::Of(c, d), Rel::Sf(a, b)) if pair(a, b, c, d) => {
                Rel::Cmp { op: IntSLess, a, b, negated: false }
            }
            _ => return None,
        },
        // a < b || a == b: a <= b
        BoolOr => {
            // a float compare's CF is "below or unordered" = !(b <= a) (WS84); with ZF's
            // a == b it is `jbe`: !(b < a), true for a NaN like the CPU
            for (i, j) in [(0, 1), (1, 0)] {
                if let (Some(Rel::Cmp { op: FloatLessEqual, a: b0, b: a0, negated: true }), Some(Rel::Cmp { op: FloatEqual, a: c, b: d, negated: false })) =
                    (rel(i), rel(j))
                    && (pair(a0, b0, c, d) || pair(b0, a0, c, d))
                {
                    return Some(Rel::Cmp { op: FloatLess, a: b0, b: a0, negated: true });
                }
            }
            let (Rel::Cmp { op: x, a, b, negated: false }, Rel::Cmp { op: y, a: c, b: d, negated: false }) = (rel(0)?, rel(1)?) else {
                return None;
            };
            if !pair(a, b, c, d) {
                return None;
            }
            let le = match (x, y) {
                (IntLess, IntEqual) | (IntEqual, IntLess) => IntLessEqual,
                (IntSLess, IntEqual) | (IntEqual, IntSLess) => IntSLessEqual,
                (FloatLess, FloatEqual) | (FloatEqual, FloatLess) => FloatLessEqual,
                _ => return None,
            };
            Rel::Cmp { op: le, a, b, negated: false }
        }
        BoolNegate => match rel(0)? {
            Rel::Cmp { op, a, b, negated } => Rel::Cmp { op, a, b, negated: !negated },
            _ => return None,
        },
        _ => return None,
    })
}

/// `Sub(a, b)` when `v` is `a - b` computed in `block` and nothing from it on in the block
/// writes over `a` or `b` (so their names, printed later in the condition, still mean them).
///
/// The sub itself counts (WS83): it is printed as a statement (it is not one of the folded
/// ops), and `dec ebx` / `sub eax, esi` write their result over `a`. `dec ebx; jne L` used to
/// print `ebx = ebx - 1; … while (ebx != 1)` — the flags' `old - 1 != 0` read with `ebx`
/// already decremented.
fn earlier_sub(func: &SsaFunction, v: VarId, block: BlockId) -> Option<Rel> {
    let d = func.varnodes[v as usize].def_op?;
    let sub = &func.ops[d];
    if sub.dead || sub.opcode != OpCode::IntSub || sub.block != block || sub.inputs.len() != 2 {
        return None;
    }
    let (a, b) = (sub.inputs[0], sub.inputs[1]);
    let overlaps = |x: VarId, w: &reargo_core::pcode::VarnodeData| {
        let x = &func.varnodes[x as usize].data;
        x.space != reargo_core::address::SpaceId::CONST
            && x.space == w.space
            && x.offset < w.offset + w.size as u64
            && w.offset < x.offset + x.size as u64
    };
    for later in func.ops[d..].iter().take_while(|o| o.block == block) {
        if let Some(out) = later.output
            && !later.dead
            && (overlaps(a, &func.varnodes[out as usize].data) || overlaps(b, &func.varnodes[out as usize].data))
        {
            return None;
        }
    }
    Some(Rel::Sub(a, b))
}

/// A float value that is never a NaN: a constant that is not one, or an integer converted.
fn not_nan(func: &SsaFunction, v: VarId, depth: u32) -> bool {
    let d = &func.varnodes[v as usize].data;
    if d.space == reargo_core::address::SpaceId::CONST {
        return match d.size {
            4 => !f32::from_bits(d.offset as u32).is_nan(),
            8 => !f64::from_bits(d.offset).is_nan(),
            _ => false,
        };
    }
    let Some(o) = func.varnodes[v as usize].def_op.map(|o| &func.ops[o]) else { return false };
    match o.opcode {
        OpCode::FloatInt2Float => true,
        OpCode::Copy | OpCode::FloatFloat2Float if depth < 4 => o.inputs.first().is_some_and(|&i| not_nan(func, i, depth + 1)),
        _ => false,
    }
}

fn is_const(func: &SsaFunction, v: VarId) -> bool {
    func.varnodes[v as usize].data.space == reargo_core::address::SpaceId::CONST
}

/// The text of a negated float comparison `!(a OP b)` (`rhs` = `a OP b`, `swapped` = `b OP a`)
/// (WS85): equality negates exactly (`a != b`); an order comparison negates exactly only for
/// operands that are never NaN (`!(a < b)` = `a >= b`), else it stays negated, with a constant
/// operand put on the right: `!(0.0f < x)` reads `!(x > 0.0f)`.
fn negated_float_compare(func: &SsaFunction, cmp: OpCode, a: VarId, b: VarId, rhs: &str, swapped: Option<String>) -> String {
    let ordered = not_nan(func, a, 0) && not_nan(func, b, 0);
    let mirror = |s: &str, from: &str, to: &str| s.rsplit_once(from).map(|(l, r)| format!("{l}{to}{r}"));
    let text = match cmp {
        OpCode::FloatEqual => mirror(rhs, " == ", " != "),
        OpCode::FloatNotEqual => mirror(rhs, " != ", " == "),
        // !(a < b): `a >= b` when ordered (`b <= a` with a constant `a`)
        OpCode::FloatLess | OpCode::FloatLessEqual => {
            let (op, rev, ord, ord_rev) = if cmp == OpCode::FloatLess { (" < ", " > ", " >= ", " <= ") } else { (" <= ", " >= ", " > ", " < ") };
            let constant_left = is_const(func, a) && !is_const(func, b);
            match (ordered, constant_left) {
                (true, false) => mirror(rhs, op, ord),
                (true, true) => swapped.as_deref().and_then(|s| mirror(s, op, ord_rev)),
                (false, true) => swapped.as_deref().and_then(|s| mirror(s, op, rev)).map(|t| format!("!({t})")),
                (false, false) => None,
            }
        }
        _ => None,
    };
    text.unwrap_or_else(|| format!("!({rhs})"))
}

/// A condition folded into one expression.
#[derive(Debug, Clone)]
pub struct Folded {
    pub text: String,
    /// The text is an integer comparison `a OP b`: its negation flips `OP`.
    pub int_cmp: bool,
}

impl Folded {
    pub fn plain(text: String) -> Self {
        Folded { text, int_cmp: false }
    }

    /// The text, inverted when `negated` (`a < b` -> `a >= b` for an integer comparison).
    pub fn render(&self, negated: bool) -> String {
        if negated
            && self.int_cmp
            && let Some(t) = crate::emit::flip_comparison(&self.text)
        {
            return t;
        }
        crate::emit::negate_condition(self.text.clone(), negated)
    }
}

/// The ops folded into a block's own branch condition, and the condition.
pub type OwnCondition = (Vec<OpIdx>, Folded);

/// Prints the leaves of merged conditions: the ops of a test block are emitted in order and
/// each result's right-hand side is substituted where it is read (`input_expr` asks
/// [`Inliner::get`]), so the block's statements collapse into its condition expression.
#[derive(Default)]
pub struct Inliner {
    exprs: std::cell::RefCell<FxHashMap<ValueKey, String>>,
    by_block: std::cell::OnceCell<Vec<Vec<OpIdx>>>,
    readers: std::cell::OnceCell<Readers>,
    /// the first op of each block (`flags::block_starts`)
    starts: std::cell::OnceCell<Vec<usize>>,
    /// block -> (the ops folded into its own condition, the condition's text)
    own: std::cell::RefCell<FxHashMap<BlockId, Option<OwnCondition>>>,
}

impl Inliner {
    /// The folded expression of `v` (parenthesised unless atomic), while a leaf is printed.
    pub fn get(&self, func: &SsaFunction, v: VarId) -> Option<String> {
        let exprs = self.exprs.borrow();
        if exprs.is_empty() {
            return None;
        }
        let s = exprs.get(&value_key(func, v))?;
        Some(if is_atomic(s) { s.clone() } else { format!("({s})") })
    }

    fn parts(&self, func: &SsaFunction) -> (&Vec<Vec<OpIdx>>, &Readers) {
        (self.by_block.get_or_init(|| ops_by_block(func)), self.readers.get_or_init(|| Readers::new(func)))
    }

    /// WS89: a flag a block's branch reads that another block computed — `cmp r12, r13; je L`
    /// leaves the `jb` reading `CF` in the next block, which printed `var_201 = r12 < r13;` there
    /// and `if (!var_201)` here. The comparison (of registers / constants only) folds into this
    /// condition, before `chain` (the block's own folded ops), when nothing but the condition
    /// reads it and its operands keep their values on every path from it to here
    /// (`flags::operands_hold`, which also needs it to dominate this block).
    fn with_cross_block(&self, func: &SsaFunction, block: BlockId, chain: Vec<OpIdx>) -> Vec<OpIdx> {
        let (by_block, readers) = self.parts(func);
        let Some(&br) = by_block[block].last() else { return chain };
        if func.ops[br].opcode != OpCode::CBranch || func.ops[br].inputs.len() < 2 {
            return chain;
        }
        let starts = self.starts.get_or_init(|| crate::flags::block_starts(func));
        let mut readers_ok: Vec<OpIdx> = chain.clone();
        readers_ok.push(br);
        let mut cross: Vec<OpIdx> = Vec::new();
        for &r in readers_ok.iter() {
            for &v in &func.ops[r].inputs {
                let Some(d) = func.varnodes[v as usize].def_op else { continue };
                let def = &func.ops[d];
                let compare = matches!(
                    def.opcode,
                    OpCode::IntEqual | OpCode::IntNotEqual | OpCode::IntLess | OpCode::IntLessEqual | OpCode::IntSLess | OpCode::IntSLessEqual
                );
                if def.dead || def.block == block || !compare || cross.contains(&d) {
                    continue;
                }
                let plain = def.inputs.iter().all(|&i| {
                    matches!(func.varnodes[i as usize].data.space, reargo_core::address::SpaceId::REGISTER | reargo_core::address::SpaceId::CONST)
                });
                let only_here = def.output.is_some_and(|o| readers.of(func, o).iter().all(|u| readers_ok.contains(u)));
                if plain && only_here && crate::flags::operands_hold(func, starts, &[d], r, &def.inputs) {
                    cross.push(d);
                }
            }
        }
        cross.sort_unstable();
        cross.extend(chain);
        cross
    }

    /// A block's own branch condition with its [`condition_tail`] folded in (WS81): the ops
    /// not to print as statements and the condition's text, or `None` when nothing folds (or
    /// an op of the tail does not print as `dst = rhs;`). Cached: the statements and the
    /// condition are printed separately.
    pub fn own_condition(
        &self,
        func: &SsaFunction,
        block: BlockId,
        name: &dyn Fn(VarId) -> String,
        emit: &dyn Fn(&crate::ssa::SsaOp) -> Option<String>,
    ) -> Option<OwnCondition> {
        if let Some(r) = self.own.borrow().get(&block) {
            return r.clone();
        }
        let (by_block, readers) = self.parts(func);
        let ops = &by_block[block];
        let tail = self.with_cross_block(func, block, condition_tail(func, ops, readers));
        let r = if tail.is_empty() {
            None
        } else {
            let cv = func.ops[*ops.last().unwrap()].inputs[1];
            self.fold_ops(func, &tail, cv, name, emit, Some(MAX_FOLDED_LEN)).map(|f| (tail, f))
        };
        self.own.borrow_mut().insert(block, r.clone());
        r
    }

    /// Fold `ops` (each read only by later ones or the condition `cv`) into `cv`'s
    /// expression; `None` when an op does not print as `dst = rhs;` or an expression grows
    /// past `max_len`.
    fn fold_ops(
        &self,
        func: &SsaFunction,
        ops: &[OpIdx],
        cv: VarId,
        name: &dyn Fn(VarId) -> String,
        emit: &dyn Fn(&crate::ssa::SsaOp) -> Option<String>,
        max_len: Option<usize>,
    ) -> Option<Folded> {
        let mut ok = true;
        let mut rels: FxHashMap<ValueKey, Rel> = FxHashMap::default();
        let mut int_cmp: rustc_hash::FxHashSet<ValueKey> = rustc_hash::FxHashSet::default();
        for &o in ops {
            let op = &func.ops[o];
            let Some(out) = op.output else {
                ok = false;
                break;
            };
            let key = value_key(func, out);
            if let Some(rel) = relation(func, op, &rels) {
                rels.insert(key, rel);
                if let Rel::Cmp { op: cmp, a, b, negated } = rel {
                    let int = !matches!(cmp, OpCode::FloatEqual | OpCode::FloatNotEqual | OpCode::FloatLess | OpCode::FloatLessEqual);
                    // print the comparison the flags test (`a <= b`, not `a < b || a - b == 0`)
                    let fake = crate::ssa::SsaOp {
                        index: op.index,
                        opcode: cmp,
                        output: Some(out),
                        inputs: smallvec::smallvec![a, b],
                        block: op.block,
                        address: op.address,
                        dead: false,
                    };
                    let prefix = format!("{} = ", name(out));
                    let rhs_of = |x: VarId, y: VarId| {
                        let f = crate::ssa::SsaOp { inputs: smallvec::smallvec![x, y], ..fake.clone() };
                        emit(&f).and_then(|l| l.strip_prefix(&prefix).and_then(|r| r.strip_suffix(';')).map(str::to_string))
                    };
                    if let Some(rhs) = rhs_of(a, b) {
                        // (`!(a < b)` is not `a >= b` for a NaN)
                        let text = match (negated, int) {
                            (false, _) => Some(rhs),
                            (true, true) => crate::emit::flip_comparison(&rhs),
                            (true, false) => Some(negated_float_compare(func, cmp, a, b, &rhs, rhs_of(b, a))),
                        };
                        if let Some(text) = text {
                            self.exprs.borrow_mut().insert(key, text);
                            if int {
                                int_cmp.insert(key);
                            }
                            continue;
                        }
                    }
                }
            }
            if op.opcode == OpCode::BoolNegate
                && let Some(inner) = op.inputs.first().and_then(|&i| self.exprs.borrow().get(&value_key(func, i)).cloned())
            {
                // `!(a == b)` reads better as `a != b`
                self.exprs.borrow_mut().insert(key, crate::emit::negate_condition(inner, true));
                continue;
            }
            let Some(line) = emit(op) else {
                ok = false;
                break;
            };
            let prefix = format!("{} = ", name(out));
            match line.strip_prefix(&prefix).and_then(|r| r.strip_suffix(';')) {
                // (a value read twice is printed twice: keep the expression readable)
                Some(rhs) if max_len.is_none_or(|m| rhs.len() <= m) => {
                    self.exprs.borrow_mut().insert(key, rhs.to_string());
                }
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        let cvk = value_key(func, cv);
        let folded = ok.then(|| Folded {
            text: self.exprs.borrow().get(&cvk).cloned().unwrap_or_else(|| name(cv)),
            int_cmp: int_cmp.contains(&cvk),
        });
        self.exprs.borrow_mut().clear();
        folded
    }

    /// `cv` with `ops` (its definition chain, in order) folded in, as for a branch condition
    /// (WS84: a `cmov`'s condition).
    pub fn fold_value(
        &self,
        func: &SsaFunction,
        ops: &[OpIdx],
        cv: VarId,
        name: &dyn Fn(VarId) -> String,
        emit: &dyn Fn(&crate::ssa::SsaOp) -> Option<String>,
    ) -> Option<Folded> {
        self.fold_ops(func, ops, cv, name, emit, Some(MAX_FOLDED_LEN))
    }

    /// The condition of `block` (to its first CFG successor) as one expression. `name` prints
    /// a variable, `emit` an op as the emitter does (`dst = rhs;`).
    pub fn fold(
        &self,
        func: &SsaFunction,
        block: BlockId,
        name: &dyn Fn(VarId) -> String,
        emit: &dyn Fn(&crate::ssa::SsaOp) -> Option<String>,
    ) -> Folded {
        let (by_block, readers) = self.parts(func);
        let ops = &by_block[block];
        let Some(&br) = ops.last() else { return Folded::plain("cond".into()) };
        let Some(&cv) = func.ops[br].inputs.get(1) else { return Folded::plain("cond".into()) };
        let body = self.with_cross_block(func, block, condition_ops(func, ops, readers).unwrap_or_default());
        if let Some(f) = self.fold_ops(func, &body, cv, name, emit, None) {
            return f;
        }
        // an op printed in another shape: keep the statements, as a statement expression
        let lines: Vec<String> = body.iter().filter_map(|&o| emit(&func.ops[o])).collect();
        Folded::plain(format!("({{ {} {}; }})", lines.join(" "), name(cv)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negate_pushes_down() {
        let c = Cond::Or(vec![Cond::Leaf { block: 1, negated: false }, Cond::Leaf { block: 2, negated: true }]);
        assert_eq!(
            c.negate(),
            Cond::And(vec![Cond::Leaf { block: 1, negated: true }, Cond::Leaf { block: 2, negated: false }])
        );
    }

    #[test]
    fn render_parenthesises_compound_operands() {
        let c = Cond::Or(vec![
            Cond::Leaf { block: 1, negated: false },
            Cond::And(vec![Cond::Leaf { block: 2, negated: false }, Cond::Leaf { block: 3, negated: true }]),
        ]);
        let leaf_text = |b: BlockId| match b {
            1 => "x".to_string(),
            2 => "y == 0".to_string(),
            _ => "z".to_string(),
        };
        let mut leaf = |b: BlockId, neg: bool| crate::emit::negate_condition(leaf_text(b), neg);
        assert_eq!(c.render(false, &mut leaf), "x || ((y == 0) && !z)");
        assert_eq!(c.render(true, &mut leaf), "!x && ((y != 0) || z)");
    }

    #[test]
    fn atomic_expressions() {
        assert!(is_atomic("tmp_410"));
        assert!(is_atomic("!var_206"));
        assert!(is_atomic("(a + b)"));
        assert!(is_atomic("fabs(x)"));
        assert!(!is_atomic("(a) + (b)"));
        assert!(!is_atomic("a == 0"));
        assert!(!is_atomic("*(uint32_t*)tmp"));
    }
}
