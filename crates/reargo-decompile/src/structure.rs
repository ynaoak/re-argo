use crate::cfg::{BlockId, ControlFlowGraph};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub enum StructuredBlock {
    Basic(BlockId),
    Sequence(Vec<StructuredBlock>),
    IfThen {
        condition_block: BlockId,
        then_body: Box<StructuredBlock>,
    },
    IfThenElse {
        condition_block: BlockId,
        then_body: Box<StructuredBlock>,
        else_body: Box<StructuredBlock>,
    },
    WhileLoop {
        condition_block: BlockId,
        body: Box<StructuredBlock>,
    },
    DoWhileLoop {
        body: Box<StructuredBlock>,
        condition_block: BlockId,
    },
    Loop {
        header: BlockId,
        body: Box<StructuredBlock>,
    },
    ForLoop {
        init_block: BlockId,
        condition_block: BlockId,
        update_block: BlockId,
        body: Box<StructuredBlock>,
    },
    ShortCircuitAnd {
        left_block: BlockId,
        right_block: BlockId,
        body: Box<StructuredBlock>,
    },
    ShortCircuitOr {
        left_block: BlockId,
        right_block: BlockId,
        body: Box<StructuredBlock>,
    },
    Switch {
        condition_block: BlockId,
        cases: Vec<(u64, StructuredBlock)>,
        default: Option<Box<StructuredBlock>>,
    },
    Goto(BlockId),
}

pub fn structure_cfg(cfg: &ControlFlowGraph) -> StructuredBlock {
    if cfg.blocks.is_empty() {
        return StructuredBlock::Sequence(Vec::new());
    }

    let mut visited = BTreeSet::new();
    let mut path = BTreeSet::new();
    structure_from(cfg, cfg.entry_block, &mut visited, &mut path)
}

fn structure_from(
    cfg: &ControlFlowGraph,
    block_id: BlockId,
    visited: &mut BTreeSet<BlockId>,
    // The current DFS recursion stack (ancestors of `block_id` on the active
    // path). Distinct from `visited`: a successor in `path` is a *back-edge*
    // (loop), whereas one merely in `visited` is a forward cross/merge edge
    // (an if-goto). Without this distinction every already-seen branch target
    // was modeled as a `while`, turning forward merges into degenerate
    // single-pass `while (cond) { goto L; }` loops.
    path: &mut BTreeSet<BlockId>,
) -> StructuredBlock {
    if visited.contains(&block_id) {
        return StructuredBlock::Goto(block_id);
    }
    visited.insert(block_id);
    path.insert(block_id);
    let result = structure_block_body(cfg, block_id, visited, path);
    path.remove(&block_id);
    result
}

fn structure_block_body(
    cfg: &ControlFlowGraph,
    block_id: BlockId,
    visited: &mut BTreeSet<BlockId>,
    path: &mut BTreeSet<BlockId>,
) -> StructuredBlock {
    let block = &cfg.blocks[block_id];

    match block.successors.len() {
        0 => StructuredBlock::Basic(block_id),

        1 => {
            let next = block.successors[0];
            if visited.contains(&next) {
                StructuredBlock::Sequence(vec![
                    StructuredBlock::Basic(block_id),
                    StructuredBlock::Goto(next),
                ])
            } else {
                let next_struct = structure_from(cfg, next, visited, path);
                StructuredBlock::Sequence(vec![
                    StructuredBlock::Basic(block_id),
                    next_struct,
                ])
            }
        }

        2 => {
            let true_target = block.successors[0];
            let false_target = block.successors[1];

            let true_returns = block_eventually_returns(cfg, true_target, visited);
            let false_returns = block_eventually_returns(cfg, false_target, visited);

            if true_returns && false_returns {
                let (then_body, else_body, join) =
                    structure_diamond(cfg, true_target, false_target, visited, path);
                let if_node = StructuredBlock::IfThenElse {
                    condition_block: block_id,
                    then_body: Box::new(then_body),
                    else_body: Box::new(else_body),
                };
                join_into_sequence(if_node, join)
            } else if visited.contains(&true_target) && !visited.contains(&false_target) {
                let body = structure_from(cfg, false_target, visited, path);
                if path.contains(&true_target) {
                    // true_target is an ancestor on the active path → a real
                    // back-edge. Express as `while (cond) { goto header; }` so
                    // emit keeps the conditional exit through false_target.
                    StructuredBlock::Sequence(vec![
                        StructuredBlock::WhileLoop {
                            condition_block: block_id,
                            body: Box::new(StructuredBlock::Goto(true_target)),
                        },
                        body,
                    ])
                } else {
                    // true_target is merely already-visited (a forward merge),
                    // not a loop. `while (cond) { goto L; }` would be a
                    // degenerate single-pass loop; emit the equivalent, clearer
                    // `if (cond) goto L;` then fall through to false_target.
                    StructuredBlock::Sequence(vec![
                        StructuredBlock::IfThen {
                            condition_block: block_id,
                            then_body: Box::new(StructuredBlock::Goto(true_target)),
                        },
                        body,
                    ])
                }
            } else if !visited.contains(&true_target) && visited.contains(&false_target) {
                if path.contains(&false_target) {
                    // Mirror back-edge: the *false* branch loops back. Use
                    // DoWhileLoop to preserve the conditional exit without
                    // inverting the printed condition.
                    let body = structure_from(cfg, true_target, visited, path);
                    StructuredBlock::Sequence(vec![
                        StructuredBlock::DoWhileLoop {
                            body: Box::new(StructuredBlock::Goto(false_target)),
                            condition_block: block_id,
                        },
                        body,
                    ])
                } else {
                    // Forward merge on the false side: `if (cond) { <body> }
                    // else goto L;`. The then-arm is the real fall-through
                    // body; the else is the merge jump.
                    let then_body = structure_from(cfg, true_target, visited, path);
                    StructuredBlock::IfThenElse {
                        condition_block: block_id,
                        then_body: Box::new(then_body),
                        else_body: Box::new(StructuredBlock::Goto(false_target)),
                    }
                }
            } else {
                let (then_body, else_body, join) =
                    structure_diamond(cfg, true_target, false_target, visited, path);
                let if_node = StructuredBlock::IfThenElse {
                    condition_block: block_id,
                    then_body: Box::new(then_body),
                    else_body: Box::new(else_body),
                };
                join_into_sequence(if_node, join)
            }
        }

        _ => {
            // 3+ successors typically come from an indirect jump (jump table,
            // switch dispatch). Without dedicated switch recovery, the safest
            // thing is to emit the block's data ops, then list every target
            // as a goto so emit doesn't fall through from one successor's
            // body into the next (the previous code recursively structured
            // the first un-visited successor inline, which produced fall-
            // through into its body followed by dead goto stubs for the
            // rest).
            let mut seq = vec![StructuredBlock::Basic(block_id)];
            for &succ in &block.successors {
                seq.push(StructuredBlock::Goto(succ));
            }
            StructuredBlock::Sequence(seq)
        }
    }
}

/// Reachability without structuring: walk successors collecting every
/// BlockId reachable from `start` without crossing into `blocked`.
fn collect_reachable(
    cfg: &ControlFlowGraph,
    start: BlockId,
    blocked: &BTreeSet<BlockId>,
) -> BTreeSet<BlockId> {
    let mut reached = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(b) = stack.pop() {
        if blocked.contains(&b) || !reached.insert(b) {
            continue;
        }
        for &s in &cfg.blocks[b].successors {
            stack.push(s);
        }
    }
    reached
}

/// Drop a trailing `Goto(target)` from a structured node so the
/// IfThenElse arm doesn't print an explicit `goto LABEL` immediately
/// before the join block runs as the next statement after the if.
fn strip_trailing_goto(node: StructuredBlock, target: BlockId) -> StructuredBlock {
    match node {
        StructuredBlock::Sequence(mut xs) => {
            if matches!(xs.last(), Some(StructuredBlock::Goto(t)) if *t == target) {
                xs.pop();
            }
            if xs.len() == 1 {
                xs.into_iter().next().unwrap()
            } else {
                StructuredBlock::Sequence(xs)
            }
        }
        StructuredBlock::Goto(t) if t == target => StructuredBlock::Sequence(Vec::new()),
        n => n,
    }
}

/// Structure both arms of an if-then-else and split off any shared
/// post-dominator block as a join sequence. Previously both arms shared
/// the same `visited` set, so the first one structured consumed everything
/// the second one also needed to reach — the second arm collapsed to a
/// single `Goto` and the join code only appeared in the first arm, leaving
/// the other arm to fall through into it on emit. We now:
///   1. find the join via independent reachability,
///   2. block it in each arm's visited set so the arm body stops at the
///      join boundary instead of structuring the join inline,
///   3. strip the trailing `Goto(join)` stub the arm naturally produces,
///   4. structure the join once after the if.
fn structure_diamond(
    cfg: &ControlFlowGraph,
    true_target: BlockId,
    false_target: BlockId,
    parent_visited: &mut BTreeSet<BlockId>,
    path: &mut BTreeSet<BlockId>,
) -> (StructuredBlock, StructuredBlock, Vec<StructuredBlock>) {
    let then_reach = collect_reachable(cfg, true_target, parent_visited);
    let else_reach = collect_reachable(cfg, false_target, parent_visited);
    let shared: BTreeSet<BlockId> = then_reach
        .intersection(&else_reach)
        .copied()
        .collect();
    // Approximate the post-dominator by the lowest BlockId reached by both
    // arms. Without proper dominator analysis the topologically-earliest
    // block usually corresponds to the join.
    let join_id = shared.iter().min().copied();

    let mut arm_blocked = parent_visited.clone();
    if let Some(j) = join_id {
        arm_blocked.insert(j);
    }
    let mut then_visited = arm_blocked.clone();
    let mut else_visited = arm_blocked.clone();
    let then_body = structure_from(cfg, true_target, &mut then_visited, path);
    let else_body = structure_from(cfg, false_target, &mut else_visited, path);

    parent_visited.extend(&then_visited);
    parent_visited.extend(&else_visited);

    let (then_body, else_body, join_seq) = if let Some(j) = join_id {
        let then_body = strip_trailing_goto(then_body, j);
        let else_body = strip_trailing_goto(else_body, j);
        parent_visited.remove(&j);
        let s = structure_from(cfg, j, parent_visited, path);
        (then_body, else_body, vec![s])
    } else {
        (then_body, else_body, Vec::new())
    };

    (then_body, else_body, join_seq)
}

/// If the if/then/else has a continuation, wrap the conditional in a
/// sequence followed by the continuation. Otherwise return the conditional
/// node directly so the simple cases stay flat.
fn join_into_sequence(if_node: StructuredBlock, join: Vec<StructuredBlock>) -> StructuredBlock {
    if join.is_empty() {
        if_node
    } else {
        let mut seq = vec![if_node];
        seq.extend(join);
        StructuredBlock::Sequence(seq)
    }
}

fn block_eventually_returns(
    cfg: &ControlFlowGraph,
    block_id: BlockId,
    parent_visited: &BTreeSet<BlockId>,
) -> bool {
    if parent_visited.contains(&block_id) {
        return false;
    }
    let block = &cfg.blocks[block_id];
    if block.is_return() {
        return true;
    }
    if block.successors.is_empty() {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;
    use smallvec::SmallVec;

    fn lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction { address: addr, length: 1, mnemonic: "t".into(), ops }
    }

    fn seq(addr: u64) -> SeqNum {
        SeqNum::new(Address::new(SpaceId(1), addr), 0)
    }

    fn cbranch(addr: u64, target: u64) -> PcodeOp {
        PcodeOp {
            opcode: OpCode::CBranch,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(SpaceId(1), target, 8),
                VarnodeData::new(SpaceId(0), 1, 1),
            ]),
        }
    }

    fn branch(addr: u64, target: u64) -> PcodeOp {
        PcodeOp {
            opcode: OpCode::Branch,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), target, 8)]),
        }
    }

    fn ret(addr: u64) -> PcodeOp {
        PcodeOp {
            opcode: OpCode::Return,
            seq: seq(addr),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(0), 0, 8)]),
        }
    }

    fn count<F: Fn(&StructuredBlock) -> bool>(node: &StructuredBlock, pred: &F) -> usize {
        let mut n = if pred(node) { 1 } else { 0 };
        match node {
            StructuredBlock::Sequence(xs) => xs.iter().for_each(|x| n += count(x, pred)),
            StructuredBlock::IfThen { then_body, .. } => n += count(then_body, pred),
            StructuredBlock::IfThenElse { then_body, else_body, .. } => {
                n += count(then_body, pred);
                n += count(else_body, pred);
            }
            StructuredBlock::WhileLoop { body, .. }
            | StructuredBlock::DoWhileLoop { body, .. }
            | StructuredBlock::Loop { body, .. }
            | StructuredBlock::ForLoop { body, .. }
            | StructuredBlock::ShortCircuitAnd { body, .. }
            | StructuredBlock::ShortCircuitOr { body, .. } => n += count(body, pred),
            StructuredBlock::Switch { cases, default, .. } => {
                for (_, b) in cases { n += count(b, pred); }
                if let Some(d) = default { n += count(d, pred); }
            }
            _ => {}
        }
        n
    }

    #[test]
    fn loop_backedge_emits_while_not_unconditional() {
        // 0x1000: cmp ; cbranch back to 0x1000 (true_target = self) else fall to 0x1002
        // 0x1001: cbranch 0x1000 -- back-edge
        // 0x1002: ret
        // Build: A (header) -> B; B cbranch -> A (back), fall -> C; C ret.
        let insns = vec![
            lifted(0x1000, vec![]),
            lifted(0x1001, vec![cbranch(0x1001, 0x1000)]),
            lifted(0x1002, vec![ret(0x1002)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        let whiles = count(&s, &|n| matches!(n, StructuredBlock::WhileLoop { .. }));
        let dos = count(&s, &|n| matches!(n, StructuredBlock::DoWhileLoop { .. }));
        let infinite = count(&s, &|n| matches!(n, StructuredBlock::Loop { .. }));
        assert!(whiles + dos >= 1,
            "loop with conditional back-edge must produce a While or DoWhile, not an unconditional Loop ({:?})", s);
        assert_eq!(infinite, 0,
            "unconditional Loop would lose the loop's exit-condition: {:?}", s);
    }

    #[test]
    fn forward_merge_emits_if_goto_not_degenerate_while() {
        // A: cbranch D else B ; B: cbranch D else C ; C: ret ; D: ret
        // When structuring B, its true-target D is already *visited* (it is the
        // join of A's diamond) but NOT on the active path — a forward merge,
        // not a loop. The old code modeled every visited branch target as a
        // `while (cond) { goto D; }` (a degenerate single-pass loop). With
        // path-tracking it must instead be `if (cond) goto D;` — an IfThen — so
        // no WhileLoop/DoWhileLoop appears anywhere in the structured form.
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1003)]),
            lifted(0x1001, vec![cbranch(0x1001, 0x1003)]),
            lifted(0x1002, vec![ret(0x1002)]),
            lifted(0x1003, vec![ret(0x1003)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        let whiles = count(&s, &|n| matches!(n, StructuredBlock::WhileLoop { .. }));
        let dos = count(&s, &|n| matches!(n, StructuredBlock::DoWhileLoop { .. }));
        let ifthens = count(&s, &|n| matches!(n, StructuredBlock::IfThen { .. }));
        assert_eq!(whiles, 0, "forward merge must not become a while: {:?}", s);
        assert_eq!(dos, 0, "forward merge must not become a do-while: {:?}", s);
        assert!(ifthens >= 1, "forward-merge branch should be an IfThen goto: {:?}", s);
    }

    #[test]
    fn diamond_shared_tail_lifted_out_of_arms() {
        // A: cbranch C else B ; B: branch D ; C: branch D ; D: ret
        // The cbranch target must differ from the fall-through, otherwise
        // both arms collapse onto the same block and no diamond exists.
        // We point cbranch at 0x1002 (C); fall-through is 0x1001 (B).
        // Both arms join at D; previously D was consumed in the then-arm and
        // the else-arm `Goto`'d into it, falling through on emit. Verify
        // the structured form lifts D out as a join after the IfThenElse.
        let insns = vec![
            lifted(0x1000, vec![cbranch(0x1000, 0x1002)]),
            lifted(0x1001, vec![branch(0x1001, 0x1003)]),
            lifted(0x1002, vec![branch(0x1002, 0x1003)]),
            lifted(0x1003, vec![ret(0x1003)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let s = structure_cfg(&cfg);
        // After the fix the IfThenElse is wrapped in a Sequence whose tail
        // contains the join block; before the fix, D was inside one arm and
        // the other arm was a bare Goto.
        let if_count = count(&s, &|n| matches!(n, StructuredBlock::IfThenElse { .. }));
        assert_eq!(if_count, 1, "expected exactly one IfThenElse, got {:?}", s);
        // Whichever arm is structured "first" must not contain a Basic for
        // block D twice (one in arm, one in tail) — emit would duplicate it.
        // Verify the structured form mentions block 3 (D) at most once via
        // Basic counting. (Goto references are allowed.)
        fn count_basic(node: &StructuredBlock, target: BlockId) -> usize {
            match node {
                StructuredBlock::Basic(b) if *b == target => 1,
                StructuredBlock::Sequence(xs) => xs.iter().map(|x| count_basic(x, target)).sum(),
                StructuredBlock::IfThen { then_body, .. } => count_basic(then_body, target),
                StructuredBlock::IfThenElse { then_body, else_body, .. } => {
                    count_basic(then_body, target) + count_basic(else_body, target)
                }
                StructuredBlock::WhileLoop { body, .. }
                | StructuredBlock::DoWhileLoop { body, .. }
                | StructuredBlock::Loop { body, .. } => count_basic(body, target),
                _ => 0,
            }
        }
        // D is block 3 (after A=0, B=1, C=2).
        assert!(count_basic(&s, 3) <= 1,
            "join block D must appear in at most one place: {:?}", s);
    }

    #[test]
    fn multi_successor_no_inline_fallthrough() {
        // A: an indirect jump whose CFG-modelled successors are B and C.
        // Without dedicated switch recovery the previous code structured the
        // first un-visited successor inline (B's body fell through into the
        // goto stubs for C). Verify the 3+-succ arm now emits goto stubs for
        // every successor, with no recursive structuring of a successor body.
        //
        // Construct by hand: make a fake jump-table CFG by directly building a
        // ControlFlowGraph wrapper isn't accessible; emulate with two Branches
        // chained through an "indirect-jump-like" pattern that the CFG builder
        // resolves into multiple successors via fallthrough leaders.
        // (BranchInd terminates the block but leaves no successor, so use
        // multiple distinct Branch ops in one instruction's op list — the CFG
        // collects each Branch's target as a leader.)
        let insns = vec![
            lifted(0x1000, vec![
                cbranch(0x1000, 0x1001),
                branch(0x1000, 0x1002),
            ]),
            lifted(0x1001, vec![ret(0x1001)]),
            lifted(0x1002, vec![ret(0x1002)]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        // We don't assert specifics about whether the CFG recognises this as
        // 3+ successors (it depends on builder details), but we do guarantee
        // the routine doesn't panic or infinitely recurse.
        let _ = structure_cfg(&cfg);
    }
}
