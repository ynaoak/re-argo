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

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

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
                    data: reargo_core::pcode::VarnodeData::new(SpaceId::CONST, 0, size),
                    version: 0,
                    def_op: None,
                    uses: vec![op_idx],
                });
                func.ops[op_idx].opcode = OpCode::Copy;
                func.ops[op_idx].inputs = smallvec::smallvec![const_id];
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
                func.ops[op_idx].inputs = smallvec::smallvec![other];
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
                func.ops[op_idx].inputs = smallvec::smallvec![other];
                return true;
            }
        }
        false
    }
}

pub struct RuleDoubleNeg;

impl Rule for RuleDoubleNeg {
    fn name(&self) -> &str { "DoubleNeg" }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::Int2Comp || op.inputs.len() != 1 {
            return false;
        }
        let inner_id = op.inputs[0];
        let inner_def = func.varnodes[inner_id as usize].def_op;
        if let Some(def_idx) = inner_def
            && func.ops[def_idx].opcode == OpCode::Int2Comp && func.ops[def_idx].inputs.len() == 1 {
                let original = func.ops[def_idx].inputs[0];
                func.ops[op_idx].opcode = OpCode::Copy;
                func.ops[op_idx].inputs = smallvec::smallvec![original];
                return true;
            }
        false
    }
}

pub struct RuleAndSelf;

impl Rule for RuleAndSelf {
    fn name(&self) -> &str { "AndSelf" }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::IntAnd || op.inputs.len() != 2 {
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
        {
            func.ops[op_idx].opcode = OpCode::Copy;
            func.ops[op_idx].inputs = smallvec::smallvec![a];
            return true;
        }
        false
    }
}

pub struct RuleOrSelf;

impl Rule for RuleOrSelf {
    fn name(&self) -> &str { "OrSelf" }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::IntOr || op.inputs.len() != 2 {
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
        {
            func.ops[op_idx].opcode = OpCode::Copy;
            func.ops[op_idx].inputs = smallvec::smallvec![a];
            return true;
        }
        false
    }
}

pub struct RuleShiftZero;

impl Rule for RuleShiftZero {
    fn name(&self) -> &str { "ShiftZero" }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if !matches!(op.opcode, OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight) || op.inputs.len() != 2 {
            return false;
        }
        let shift = &func.varnodes[op.inputs[1] as usize];
        if shift.data.space == SpaceId::CONST && shift.data.offset == 0 {
            let src = op.inputs[0];
            func.ops[op_idx].opcode = OpCode::Copy;
            func.ops[op_idx].inputs = smallvec::smallvec![src];
            return true;
        }
        false
    }
}

pub struct RuleSubZero;
impl Rule for RuleSubZero {
    fn name(&self) -> &str { "SubZero" }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::IntSub || op.inputs.len() != 2 { return false; }
        let b = &func.varnodes[op.inputs[1] as usize];
        if b.data.space == SpaceId::CONST && b.data.offset == 0 {
            let src = op.inputs[0];
            func.ops[op_idx].opcode = OpCode::Copy;
            func.ops[op_idx].inputs = smallvec::smallvec![src];
            return true;
        }
        false
    }
}

pub struct RuleAndAllOnes;
impl Rule for RuleAndAllOnes {
    fn name(&self) -> &str { "AndAllOnes" }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::IntAnd || op.inputs.len() != 2 { return false; }
        for i in 0..2 {
            let inp = &func.varnodes[op.inputs[i] as usize];
            if inp.data.space == SpaceId::CONST {
                let size = func.ops[op_idx].output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                let all_ones = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
                if inp.data.offset == all_ones {
                    let other = op.inputs[1 - i];
                    func.ops[op_idx].opcode = OpCode::Copy;
                    func.ops[op_idx].inputs = smallvec::smallvec![other];
                    return true;
                }
            }
        }
        false
    }
}

pub struct RuleOrZero;
impl Rule for RuleOrZero {
    fn name(&self) -> &str { "OrZero" }
    fn apply_op(&self, func: &mut SsaFunction, op_idx: usize) -> bool {
        let op = &func.ops[op_idx];
        if op.opcode != OpCode::IntOr || op.inputs.len() != 2 { return false; }
        for i in 0..2 {
            let inp = &func.varnodes[op.inputs[i] as usize];
            if inp.data.space == SpaceId::CONST && inp.data.offset == 0 {
                let other = op.inputs[1 - i];
                func.ops[op_idx].opcode = OpCode::Copy;
                func.ops[op_idx].inputs = smallvec::smallvec![other];
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
    pool.add(Box::new(RuleDoubleNeg));
    pool.add(Box::new(RuleAndSelf));
    pool.add(Box::new(RuleOrSelf));
    pool.add(Box::new(RuleShiftZero));
    pool.add(Box::new(RuleSubZero));
    pool.add(Box::new(RuleAndAllOnes));
    pool.add(Box::new(RuleOrZero));
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
        assert_eq!(pool.rules.len(), 10);
    }
}
