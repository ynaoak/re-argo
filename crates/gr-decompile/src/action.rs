use crate::ssa::SsaFunction;

pub trait Action: Send + Sync {
    fn name(&self) -> &str;
    fn apply(&self, func: &mut SsaFunction) -> ActionResult;
}

#[derive(Debug, Default)]
pub struct ActionResult {
    pub changes: usize,
}

impl ActionResult {
    pub fn changed(n: usize) -> Self {
        Self { changes: n }
    }
    pub fn none() -> Self {
        Self { changes: 0 }
    }
}

pub trait Rule: Send + Sync {
    fn name(&self) -> &str;
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool;
}

pub struct ActionGroup {
    pub name: String,
    pub actions: Vec<Box<dyn Action>>,
}

impl ActionGroup {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            actions: Vec::new(),
        }
    }

    pub fn add(&mut self, action: Box<dyn Action>) {
        self.actions.push(action);
    }

    pub fn run(&self, func: &mut SsaFunction) -> usize {
        let mut total = 0;
        for action in &self.actions {
            let result = action.apply(func);
            total += result.changes;
        }
        total
    }

    pub fn run_until_fixed_point(&self, func: &mut SsaFunction, max_iterations: usize) -> usize {
        let mut total = 0;
        for _ in 0..max_iterations {
            let changes = self.run(func);
            total += changes;
            if changes == 0 {
                break;
            }
        }
        total
    }
}

pub struct RulePool {
    pub rules: Vec<Box<dyn Rule>>,
}

impl RulePool {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn apply_all(&self, func: &mut SsaFunction) -> usize {
        let mut changes = 0;
        let op_count = func.ops.len();
        for i in 0..op_count {
            if func.ops[i].dead {
                continue;
            }
            for rule in &self.rules {
                if rule.apply_op(func, i) {
                    changes += 1;
                }
            }
        }
        changes
    }
}

impl Default for RulePool {
    fn default() -> Self {
        Self::new()
    }
}

use gr_core::address::SpaceId;
use gr_core::pcode::OpCode;

pub struct RuleXorSelfZero;

impl Rule for RuleXorSelfZero {
    fn name(&self) -> &str {
        "XorSelfZero"
    }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::IntXor || op.inputs.len() != 2 {
            return false;
        }
        let a = op.inputs[0];
        let b = op.inputs[1];
        let vn_a = &func.varnodes[a as usize];
        let vn_b = &func.varnodes[b as usize];
        if vn_a.data.space == vn_b.data.space
            && vn_a.data.offset == vn_b.data.offset
            && vn_a.data.size == vn_b.data.size
            && vn_a.data.space != SpaceId::CONST
            && let Some(out_id) = func.ops[op_idx].output {
                let size = func.varnodes[out_id as usize].data.size;
                let const_id = func.varnodes.len() as u32;
                func.varnodes.push(crate::ssa::SsaVarnode {
                    id: const_id,
                    data: gr_core::pcode::VarnodeData::new(SpaceId::CONST, 0, size),
                    version: 0,
                    def_op: None,
                    uses: vec![op_idx],
                });
                func.ops[op_idx].opcode = OpCode::Copy;
                func.ops[op_idx].inputs = vec![const_id];
                return true;
            }
        false
    }
}

pub struct RuleAddZero;

impl Rule for RuleAddZero {
    fn name(&self) -> &str {
        "AddZero"
    }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::IntAdd || op.inputs.len() != 2 {
            return false;
        }
        for i in 0..2 {
            let inp = &func.varnodes[op.inputs[i] as usize];
            if inp.data.space == SpaceId::CONST && inp.data.offset == 0 {
                let other = op.inputs[1 - i];
                func.ops[op_idx].opcode = OpCode::Copy;
                func.ops[op_idx].inputs = vec![other];
                return true;
            }
        }
        false
    }
}

pub struct RuleMultOne;

impl Rule for RuleMultOne {
    fn name(&self) -> &str {
        "MultOne"
    }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::IntMult || op.inputs.len() != 2 {
            return false;
        }
        for i in 0..2 {
            let inp = &func.varnodes[op.inputs[i] as usize];
            if inp.data.space == SpaceId::CONST && inp.data.offset == 1 {
                let other = op.inputs[1 - i];
                func.ops[op_idx].opcode = OpCode::Copy;
                func.ops[op_idx].inputs = vec![other];
                return true;
            }
        }
        false
    }
}

pub fn create_default_rule_pool() -> RulePool {
    let mut pool = RulePool::new();
    pool.add(Box::new(RuleXorSelfZero));
    pool.add(Box::new(RuleAddZero));
    pool.add(Box::new(RuleMultOne));
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_group_empty() {
        let group = ActionGroup::new("test");
        assert_eq!(group.actions.len(), 0);
    }

    #[test]
    fn rule_pool_default() {
        let pool = create_default_rule_pool();
        assert_eq!(pool.rules.len(), 3);
    }
}
