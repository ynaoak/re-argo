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

    /// Print the tree. `leaf(block)` is the text of `block`'s own condition (to its first
    /// successor, not negated).
    pub fn render(&self, negated: bool, leaf: &mut dyn FnMut(BlockId) -> String) -> String {
        if negated {
            return self.clone().negate().render(false, leaf);
        }
        match self {
            Cond::Leaf { block, negated } => crate::emit::negate_condition(leaf(*block), *negated),
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

/// When `block` holds nothing but its test, the ops computing the condition (in order, the
/// `CBRANCH` excluded): every live op but the branch is pure and its result is read exactly
/// once, by a later op of the same block — so the ops fold into one expression, nothing else
/// sees their results and nothing is lost by not printing them as statements.
pub fn condition_ops(func: &SsaFunction, ops: &[OpIdx]) -> Option<Vec<OpIdx>> {
    let (&last, body) = ops.split_last()?;
    let br = &func.ops[last];
    if br.opcode != OpCode::CBranch || br.inputs.len() < 2 {
        return None;
    }
    for (i, &o) in body.iter().enumerate() {
        let op = &func.ops[o];
        if !is_pure(op.opcode) {
            return None;
        }
        let out = op.output?;
        let mut uses = func.varnodes[out as usize].uses.iter().filter(|&&u| !func.ops[u].dead);
        let (Some(&u), None) = (uses.next(), uses.next()) else { return None };
        if !ops[i + 1..].contains(&u) {
            return None;
        }
    }
    Some(body.to_vec())
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
    let pure: Vec<bool> = by_block.iter().map(|ops| condition_ops(func, ops).is_some()).collect();
    let two = |s: &[BlockId]| s.len() == 2 && s[0] != s[1];
    // quick check before copying the CFG
    let any = (0..n).any(|b| {
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
    let mut conds: FxHashMap<BlockId, Cond> = FxHashMap::default();
    let cond_of = |conds: &FxHashMap<BlockId, Cond>, b: BlockId| {
        conds.get(&b).cloned().unwrap_or(Cond::Leaf { block: b, negated: false })
    };
    let mut changed = true;
    while changed {
        changed = false;
        for b in 0..n {
            // `b` is the inner test `B`
            if !pure[b] || b == cfg.entry_block || cfg.blocks[b].predecessors.len() != 1 {
                continue;
            }
            let a = cfg.blocks[b].predecessors[0];
            let (sa, sb) = (cfg.blocks[a].successors.clone(), cfg.blocks[b].successors.clone());
            if a == b || !two(&sa) || !two(&sb) {
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

/// Prints the leaves of merged conditions: the ops of a test block are emitted in order and
/// each result's right-hand side is substituted where it is read (`input_expr` asks
/// [`Inliner::get`]), so the block's statements collapse into its condition expression.
#[derive(Default)]
pub struct Inliner {
    exprs: std::cell::RefCell<FxHashMap<VarId, String>>,
    by_block: std::cell::OnceCell<Vec<Vec<OpIdx>>>,
}

impl Inliner {
    /// The folded expression of `v` (parenthesised unless atomic), while a leaf is printed.
    pub fn get(&self, v: VarId) -> Option<String> {
        let exprs = self.exprs.borrow();
        let s = exprs.get(&v)?;
        Some(if is_atomic(s) { s.clone() } else { format!("({s})") })
    }

    /// The condition of `block` (to its first CFG successor) as one expression. `name` prints
    /// a variable, `emit` an op as the emitter does (`dst = rhs;`).
    pub fn fold(
        &self,
        func: &SsaFunction,
        block: BlockId,
        name: &dyn Fn(VarId) -> String,
        emit: &dyn Fn(&crate::ssa::SsaOp) -> Option<String>,
    ) -> String {
        let by_block = self.by_block.get_or_init(|| ops_by_block(func));
        let ops = &by_block[block];
        let Some(&br) = ops.last() else { return "cond".into() };
        let Some(&cv) = func.ops[br].inputs.get(1) else { return "cond".into() };
        let mut lines = Vec::new();
        let mut folded = true;
        for o in condition_ops(func, ops).unwrap_or_default() {
            let op = &func.ops[o];
            let Some(line) = emit(op) else { continue };
            let (Some(out), true) = (op.output, folded) else {
                lines.push(line);
                continue;
            };
            let prefix = format!("{} = ", name(out));
            match line.strip_prefix(&prefix).and_then(|r| r.strip_suffix(';')) {
                Some(rhs) => {
                    self.exprs.borrow_mut().insert(out, rhs.to_string());
                }
                None => folded = false,
            }
            lines.push(line);
        }
        let text = if folded {
            self.exprs.borrow().get(&cv).cloned().unwrap_or_else(|| name(cv))
        } else {
            // an op printed in another shape: keep the statements, as a statement expression
            format!("({{ {} {}; }})", lines.join(" "), name(cv))
        };
        self.exprs.borrow_mut().clear();
        text
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
        let mut leaf = |b: BlockId| match b {
            1 => "x".to_string(),
            2 => "y == 0".to_string(),
            _ => "z".to_string(),
        };
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
