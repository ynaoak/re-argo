//! Taint analysis over the SSA form.
//!
//! Tracks how attacker-controlled ("tainted") values — typically function
//! parameters or the results of input routines — propagate through a function,
//! and reports when tainted data reaches a dangerous *sink*: a memory address
//! in a load/store, or the target of an indirect branch/call.
//!
//! Values are identified by SSA value identity `(space, offset, size, version)`
//! because the simplified SSA allocates a fresh varnode per read.

use std::collections::BTreeSet;

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

use crate::ssa::SsaFunction;

/// SSA value identity used for taint tracking.
type ValueKey = (u32, u64, u32, u32);

fn value_key(func: &SsaFunction, var_id: u32) -> ValueKey {
    let vn = &func.varnodes[var_id as usize];
    (vn.data.space.0, vn.data.offset, vn.data.size, vn.version)
}

/// A place where tainted data reaches a security-relevant operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSink {
    /// Op index in the SSA function.
    pub op_index: usize,
    /// Instruction address the op came from.
    pub address: u64,
    /// What kind of dangerous flow this is.
    pub kind: TaintSinkKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintSinkKind {
    /// Tainted pointer used as a load address.
    LoadAddress,
    /// Tainted pointer used as a store address.
    StoreAddress,
    /// Tainted value stored to memory.
    StoredValue,
    /// Tainted target of an indirect branch.
    IndirectBranch,
    /// Tainted target of an indirect call.
    IndirectCall,
}

impl TaintSinkKind {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::LoadAddress => "tainted load address (attacker-controlled read)",
            Self::StoreAddress => "tainted store address (attacker-controlled write)",
            Self::StoredValue => "tainted value written to memory",
            Self::IndirectBranch => "tainted indirect branch target (control-flow hijack)",
            Self::IndirectCall => "tainted indirect call target (control-flow hijack)",
        }
    }
}

/// Taint propagation engine.
#[derive(Default)]
pub struct TaintEngine {
    sources: BTreeSet<ValueKey>,
    tainted: BTreeSet<ValueKey>,
}

impl TaintEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a function-input register (version 0, no defining op) as a taint
    /// source. `offset` is the REGISTER-space offset; matches any access size.
    pub fn add_source_register(&mut self, func: &SsaFunction, offset: u64) {
        for vn in &func.varnodes {
            if vn.data.space == SpaceId::REGISTER
                && vn.data.offset == offset
                && vn.version == 0
            {
                self.sources.insert((vn.data.space.0, vn.data.offset, vn.data.size, vn.version));
            }
        }
    }

    /// Mark the output of a specific op (e.g. a call to an input routine) as a
    /// taint source.
    pub fn add_source_op_output(&mut self, func: &SsaFunction, op_index: usize) {
        if let Some(out_id) = func.ops.get(op_index).and_then(|op| op.output) {
            self.sources.insert(value_key(func, out_id));
        }
    }

    /// Propagate taint to a fixed point. An op's output becomes tainted if any
    /// non-constant input is tainted; a load through a tainted address also
    /// taints the loaded value (attacker-controlled pointer).
    pub fn propagate(&mut self, func: &SsaFunction) {
        self.tainted = self.sources.clone();

        // SSA values have single definitions, so iterating in op order to a
        // fixed point converges in at most O(ops) rounds even with back-edges.
        let max_rounds = func.ops.len() + 1;
        for _ in 0..max_rounds {
            let mut changed = false;
            for op in &func.ops {
                if op.dead {
                    continue;
                }
                let Some(out_id) = op.output else { continue };

                let any_input_tainted = op.inputs.iter().any(|&id| {
                    let vn = &func.varnodes[id as usize];
                    vn.data.space != SpaceId::CONST && self.tainted.contains(&value_key(func, id))
                });

                if any_input_tainted {
                    let out_key = value_key(func, out_id);
                    if self.tainted.insert(out_key) {
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Whether a given SSA varnode currently carries taint.
    pub fn is_tainted(&self, func: &SsaFunction, var_id: u32) -> bool {
        let vn = &func.varnodes[var_id as usize];
        if vn.data.space == SpaceId::CONST {
            return false;
        }
        self.tainted.contains(&value_key(func, var_id))
    }

    /// Number of distinct tainted SSA values.
    pub fn tainted_count(&self) -> usize {
        self.tainted.len()
    }

    /// Find all sinks where tainted data reaches a dangerous operation.
    pub fn find_sinks(&self, func: &SsaFunction) -> Vec<TaintSink> {
        let mut sinks = Vec::new();
        for (idx, op) in func.ops.iter().enumerate() {
            if op.dead {
                continue;
            }
            let tainted_in = |i: usize| -> bool {
                op.inputs.get(i).is_some_and(|&id| self.is_tainted(func, id))
            };

            // inputs: Load [space, address]; Store [space, address, value]
            match op.opcode {
                OpCode::Load if tainted_in(1) => {
                    sinks.push(TaintSink { op_index: idx, address: op.address, kind: TaintSinkKind::LoadAddress });
                }
                OpCode::Store => {
                    if tainted_in(1) {
                        sinks.push(TaintSink { op_index: idx, address: op.address, kind: TaintSinkKind::StoreAddress });
                    }
                    if tainted_in(2) {
                        sinks.push(TaintSink { op_index: idx, address: op.address, kind: TaintSinkKind::StoredValue });
                    }
                }
                OpCode::BranchInd if tainted_in(0) => {
                    sinks.push(TaintSink { op_index: idx, address: op.address, kind: TaintSinkKind::IndirectBranch });
                }
                OpCode::CallInd if tainted_in(0) => {
                    sinks.push(TaintSink { op_index: idx, address: op.address, kind: TaintSinkKind::IndirectCall });
                }
                _ => {}
            }
        }
        sinks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use reargo_core::address::{Address, SpaceId as CoreSpace};
    use reargo_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;
    use smallvec::SmallVec;

    fn lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction { address: addr, length: 1, mnemonic: "t".into(), ops }
    }

    fn build(ops: Vec<PcodeOp>) -> SsaFunction {
        let insns: Vec<LiftedInstruction> = ops
            .into_iter()
            .enumerate()
            .map(|(i, op)| lifted(0x1000 + i as u64, vec![op]))
            .collect();
        let cfg = ControlFlowGraph::build(&insns);
        SsaFunction::from_cfg("t".into(), 0x1000, cfg)
    }

    #[test]
    fn taint_propagates_through_arithmetic() {
        // rax = rdi + 1   (rdi is a parameter / taint source)
        let seq = |a, o| SeqNum::new(Address::new(CoreSpace::RAM, a), o);
        let rdi = VarnodeData::new(CoreSpace::REGISTER, 0x38, 8);
        let rax = VarnodeData::new(CoreSpace::REGISTER, 0x00, 8);
        let one = VarnodeData::new(CoreSpace::CONST, 1, 8);

        let func = build(vec![PcodeOp {
            opcode: OpCode::IntAdd,
            seq: seq(0x1000, 0),
            output: Some(rax),
            inputs: SmallVec::from_slice(&[rdi, one]),
        }]);

        let mut engine = TaintEngine::new();
        engine.add_source_register(&func, 0x38);
        engine.propagate(&func);

        // The output rax should be tainted.
        let rax_id = func.varnodes.iter()
            .find(|v| v.data.space == CoreSpace::REGISTER && v.data.offset == 0x00 && v.version >= 1)
            .map(|v| v.id)
            .unwrap();
        assert!(engine.is_tainted(&func, rax_id));
    }

    #[test]
    fn constant_is_never_tainted() {
        let seq = |a, o| SeqNum::new(Address::new(CoreSpace::RAM, a), o);
        let rax = VarnodeData::new(CoreSpace::REGISTER, 0x00, 8);
        let five = VarnodeData::new(CoreSpace::CONST, 5, 8);

        let func = build(vec![PcodeOp {
            opcode: OpCode::Copy,
            seq: seq(0x1000, 0),
            output: Some(rax),
            inputs: SmallVec::from_slice(&[five]),
        }]);

        let mut engine = TaintEngine::new();
        engine.add_source_register(&func, 0x38); // rdi, not used here
        engine.propagate(&func);
        assert_eq!(engine.tainted_count(), 0);
    }

    #[test]
    fn detects_tainted_store_address() {
        // tmp = rdi + 8; store [tmp], rsi   (tainted pointer -> store address sink)
        let seq = |a, o| SeqNum::new(Address::new(CoreSpace::RAM, a), o);
        let rdi = VarnodeData::new(CoreSpace::REGISTER, 0x38, 8);
        let rsi = VarnodeData::new(CoreSpace::REGISTER, 0x30, 8);
        let tmp = VarnodeData::new(CoreSpace::UNIQUE, 0x100, 8);
        let eight = VarnodeData::new(CoreSpace::CONST, 8, 8);
        let space = VarnodeData::new(CoreSpace::CONST, CoreSpace::RAM.0 as u64, 4);

        let func = build(vec![
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 0),
                output: Some(tmp),
                inputs: SmallVec::from_slice(&[rdi, eight]),
            },
            PcodeOp {
                opcode: OpCode::Store,
                seq: seq(0x1001, 0),
                output: None,
                inputs: SmallVec::from_slice(&[space, tmp, rsi]),
            },
        ]);

        let mut engine = TaintEngine::new();
        engine.add_source_register(&func, 0x38); // rdi tainted
        engine.propagate(&func);
        let sinks = engine.find_sinks(&func);
        assert!(sinks.iter().any(|s| s.kind == TaintSinkKind::StoreAddress));
    }

    #[test]
    fn detects_tainted_indirect_call() {
        // callind rdi  (tainted call target)
        let seq = |a, o| SeqNum::new(Address::new(CoreSpace::RAM, a), o);
        let rdi = VarnodeData::new(CoreSpace::REGISTER, 0x38, 8);

        let func = build(vec![PcodeOp {
            opcode: OpCode::CallInd,
            seq: seq(0x1000, 0),
            output: None,
            inputs: SmallVec::from_slice(&[rdi]),
        }]);

        let mut engine = TaintEngine::new();
        engine.add_source_register(&func, 0x38);
        engine.propagate(&func);
        let sinks = engine.find_sinks(&func);
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].kind, TaintSinkKind::IndirectCall);
    }

    #[test]
    fn untainted_has_no_sinks() {
        // store [rax], rbx with nothing tainted
        let seq = |a, o| SeqNum::new(Address::new(CoreSpace::RAM, a), o);
        let rax = VarnodeData::new(CoreSpace::REGISTER, 0x00, 8);
        let rbx = VarnodeData::new(CoreSpace::REGISTER, 0x18, 8);
        let space = VarnodeData::new(CoreSpace::CONST, CoreSpace::RAM.0 as u64, 4);

        let func = build(vec![PcodeOp {
            opcode: OpCode::Store,
            seq: seq(0x1000, 0),
            output: None,
            inputs: SmallVec::from_slice(&[space, rax, rbx]),
        }]);

        let mut engine = TaintEngine::new();
        engine.add_source_register(&func, 0x38); // rdi, not present
        engine.propagate(&func);
        assert!(engine.find_sinks(&func).is_empty());
    }
}
