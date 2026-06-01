use rustc_hash::FxHashMap;

use gr_core::pcode::{OpCode, VarnodeData};

use crate::cfg::{BlockId, ControlFlowGraph};

pub type VarId = u32;
pub type OpIdx = usize;

#[derive(Debug, Clone)]
pub struct SsaVarnode {
    pub id: VarId,
    pub data: VarnodeData,
    pub version: u32,
    pub def_op: Option<OpIdx>,
    pub uses: Vec<OpIdx>,
}

#[derive(Debug, Clone)]
pub struct SsaOp {
    pub index: OpIdx,
    pub opcode: OpCode,
    pub output: Option<VarId>,
    pub inputs: Vec<VarId>,
    pub block: BlockId,
    pub address: u64,
    pub dead: bool,
}

#[derive(Debug)]
pub struct SsaFunction {
    pub name: String,
    pub entry: u64,
    pub varnodes: Vec<SsaVarnode>,
    pub ops: Vec<SsaOp>,
    pub cfg: ControlFlowGraph,
    next_var_id: VarId,
    /// FxHashMap rather than BTreeMap: keys are integer triples and
    /// every read/write of a register or RAM slot in `build_ssa` hits
    /// these maps, so a constant-time hash (FxHash specialises well on
    /// integer-only keys) beats BTreeMap's per-step comparison for
    /// any function with more than a handful of distinct slots.
    var_versions: FxHashMap<(u32, u64, u32), u32>,
    /// Canonical varnode id for the *current* version of each
    /// (space, offset, size). Set by `create_new_version` whenever a
    /// register/RAM slot is rewritten, and read by `get_or_create_var`
    /// so every read of the same SSA value shares a single SsaVarnode
    /// entry. Without this, every read minted a fresh varnode and the
    /// def's `uses` list was never populated — DCE then dropped any
    /// op whose output was actually live (because uses had been pushed
    /// onto the unrelated read-side varnodes), and copy_propagation
    /// couldn't match `*inp == out_id` because the ids never coincided.
    current_var: FxHashMap<(u32, u64, u32), VarId>,
}

impl SsaFunction {
    pub fn from_cfg(name: String, entry: u64, cfg: ControlFlowGraph) -> Self {
        let mut func = Self {
            name,
            entry,
            varnodes: Vec::new(),
            ops: Vec::new(),
            cfg,
            next_var_id: 0,
            var_versions: FxHashMap::default(),
            current_var: FxHashMap::default(),
        };
        func.build_ssa();
        func
    }

    fn build_ssa(&mut self) {
        #[allow(clippy::type_complexity)]
        let all_ops: Vec<(BlockId, u64, gr_core::pcode::OpCode, Option<VarnodeData>, Vec<VarnodeData>)> = {
            let mut ops = Vec::new();
            for (block_id, block) in self.cfg.blocks.iter().enumerate() {
                for insn in &block.instructions {
                    for pcode_op in &insn.ops {
                        let inputs: Vec<VarnodeData> = pcode_op.inputs.iter().copied().collect();
                        ops.push((block_id, insn.address, pcode_op.opcode, pcode_op.output, inputs));
                    }
                }
            }
            ops
        };

        for (block_id, address, opcode, output, inputs) in &all_ops {
            let mut input_ids = Vec::new();
            for inp in inputs {
                let var_id = self.get_or_create_var(inp);
                input_ids.push(var_id);
            }

            let output_id = output.as_ref().map(|out| {
                self.create_new_version(out)
            });

            let op_idx = self.ops.len();
            self.ops.push(SsaOp {
                index: op_idx,
                opcode: *opcode,
                output: output_id,
                inputs: input_ids.clone(),
                block: *block_id,
                address: *address,
                dead: false,
            });

            if let Some(out_id) = output_id {
                self.varnodes[out_id as usize].def_op = Some(op_idx);
            }
            for &inp_id in &input_ids {
                self.varnodes[inp_id as usize].uses.push(op_idx);
            }
        }
    }

    fn get_or_create_var(&mut self, vn: &VarnodeData) -> VarId {
        let key = (vn.space.0, vn.offset, vn.size);
        if vn.space == gr_core::address::SpaceId::CONST {
            // Constants stay fresh-per-use: each literal in the P-code
            // is its own occurrence, and downstream passes compare
            // constants by data, not by VarId.
            let id = self.next_var_id;
            self.next_var_id += 1;
            self.varnodes.push(SsaVarnode {
                id,
                data: *vn,
                version: 0,
                def_op: None,
                uses: Vec::new(),
            });
            return id;
        }
        // For register/RAM/UNIQUE slots: reuse the canonical varnode for
        // the current version so every read points at the same entry as
        // the corresponding def. Without this, def_op was set on one
        // SsaVarnode and uses landed on a different one, breaking
        // def-use entirely.
        if let Some(&existing) = self.current_var.get(&key) {
            return existing;
        }
        // First reference to this slot in the function — model it as a
        // version-0 "incoming" value (function parameter, callee-saved
        // register on entry, etc.) with no defining op.
        let version = self.var_versions.get(&key).copied().unwrap_or(0);
        let id = self.next_var_id;
        self.next_var_id += 1;
        self.varnodes.push(SsaVarnode {
            id,
            data: *vn,
            version,
            def_op: None,
            uses: Vec::new(),
        });
        self.current_var.insert(key, id);
        id
    }

    fn create_new_version(&mut self, vn: &VarnodeData) -> VarId {
        let key = (vn.space.0, vn.offset, vn.size);
        let version = self.var_versions.entry(key).or_insert(0);
        *version += 1;
        let cur_version = *version;

        let id = self.next_var_id;
        self.next_var_id += 1;
        self.varnodes.push(SsaVarnode {
            id,
            data: *vn,
            version: cur_version,
            def_op: None,
            uses: Vec::new(),
        });
        // Subsequent reads of this slot resolve to this varnode until
        // the next def rotates `current_var` again.
        self.current_var.insert(key, id);
        id
    }

    pub fn op_count(&self) -> usize {
        self.ops.len()
    }

    pub fn live_op_count(&self) -> usize {
        self.ops.iter().filter(|op| !op.dead).count()
    }

    pub fn varnode_count(&self) -> usize {
        self.varnodes.len()
    }

    pub fn display_ssa(&self) -> String {
        let mut out = format!("// SSA for {} (0x{:x})\n", self.name, self.entry);
        let mut current_block: Option<BlockId> = None;

        for op in &self.ops {
            if op.dead {
                continue;
            }
            if current_block != Some(op.block) {
                current_block = Some(op.block);
                out.push_str(&format!(
                    "\nblock_{}:  // 0x{:x}\n",
                    op.block,
                    self.cfg.blocks[op.block].start_addr
                ));
            }

            out.push_str("  ");
            if let Some(out_id) = op.output {
                let vn = &self.varnodes[out_id as usize];
                out.push_str(&format!("v{}_{} = ", vn.data.offset, vn.version));
            }
            out.push_str(op.opcode.name());
            for (i, &inp_id) in op.inputs.iter().enumerate() {
                let vn = &self.varnodes[inp_id as usize];
                if vn.data.space == gr_core::address::SpaceId::CONST {
                    out.push_str(&format!(
                        "{}0x{:x}",
                        if i == 0 { " " } else { ", " },
                        vn.data.offset
                    ));
                } else {
                    out.push_str(&format!(
                        "{}v{}_{}",
                        if i == 0 { " " } else { ", " },
                        vn.data.offset,
                        vn.version
                    ));
                }
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use gr_core::address::{Address, SpaceId};
    use gr_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use gr_lift::LiftedInstruction;
    use smallvec::SmallVec;

    fn make_lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "test".into(),
            ops,
        }
    }

    #[test]
    fn basic_ssa_construction() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm_42 = VarnodeData::new(SpaceId(0), 42, 8);
        let imm_10 = VarnodeData::new(SpaceId(0), 10, 8);

        let insns = vec![
            make_lifted(0x1000, vec![
                PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x1000),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[imm_42]),
                },
            ]),
            make_lifted(0x1001, vec![
                PcodeOp {
                    opcode: OpCode::IntAdd,
                    seq: seq(0x1001),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[reg_rax, imm_10]),
                },
            ]),
            make_lifted(0x1002, vec![
                PcodeOp {
                    opcode: OpCode::Return,
                    seq: seq(0x1002),
                    output: None,
                    inputs: SmallVec::from_slice(&[reg_rax]),
                },
            ]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);

        assert_eq!(ssa.op_count(), 3);
        assert!(ssa.varnode_count() > 0);

        // RAX should have multiple versions
        let rax_versions: Vec<u32> = ssa
            .varnodes
            .iter()
            .filter(|v| v.data.space == SpaceId(2) && v.data.offset == 0)
            .map(|v| v.version)
            .collect();
        assert!(rax_versions.len() >= 2);
    }

    #[test]
    fn ssa_display() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 99, 8);

        let insns = vec![make_lifted(0x1000, vec![PcodeOp {
            opcode: OpCode::Copy,
            seq: seq(0x1000),
            output: Some(reg),
            inputs: SmallVec::from_slice(&[imm]),
        }])];

        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let display = ssa.display_ssa();
        assert!(display.contains("COPY"));
        assert!(display.contains("0x63")); // 99 in hex
    }
}
