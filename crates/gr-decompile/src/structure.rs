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
    structure_from(cfg, cfg.entry_block, &mut visited)
}

fn structure_from(
    cfg: &ControlFlowGraph,
    block_id: BlockId,
    visited: &mut BTreeSet<BlockId>,
) -> StructuredBlock {
    if visited.contains(&block_id) {
        return StructuredBlock::Goto(block_id);
    }
    visited.insert(block_id);

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
                let next_struct = structure_from(cfg, next, visited);
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
                let then_body = structure_from(cfg, true_target, visited);
                let else_body = structure_from(cfg, false_target, visited);
                StructuredBlock::IfThenElse {
                    condition_block: block_id,
                    then_body: Box::new(then_body),
                    else_body: Box::new(else_body),
                }
            } else if visited.contains(&true_target) && !visited.contains(&false_target) {
                let body = structure_from(cfg, false_target, visited);
                StructuredBlock::Sequence(vec![
                    StructuredBlock::Loop {
                        header: block_id,
                        body: Box::new(StructuredBlock::Goto(true_target)),
                    },
                    body,
                ])
            } else if !visited.contains(&true_target) && visited.contains(&false_target) {
                let body = structure_from(cfg, true_target, visited);
                StructuredBlock::Sequence(vec![
                    StructuredBlock::Loop {
                        header: block_id,
                        body: Box::new(StructuredBlock::Goto(false_target)),
                    },
                    body,
                ])
            } else {
                let then_body = structure_from(cfg, true_target, visited);
                let else_body = structure_from(cfg, false_target, visited);
                StructuredBlock::IfThenElse {
                    condition_block: block_id,
                    then_body: Box::new(then_body),
                    else_body: Box::new(else_body),
                }
            }
        }

        _ => {
            let mut seq = vec![StructuredBlock::Basic(block_id)];
            for &succ in &block.successors {
                if !visited.contains(&succ) {
                    seq.push(structure_from(cfg, succ, visited));
                } else {
                    seq.push(StructuredBlock::Goto(succ));
                }
            }
            StructuredBlock::Sequence(seq)
        }
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
