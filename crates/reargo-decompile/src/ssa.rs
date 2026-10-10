use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use reargo_core::pcode::{OpCode, VarnodeData};

use crate::cfg::{BlockId, ControlFlowGraph};

pub type VarId = u32;
pub type OpIdx = usize;

/// Inline-friendly Vec of input varnode ids. Most P-code ops have
/// 1-3 inputs (lift.rs uses the same `[VarnodeData; 3]` inline cap),
/// so `SmallVec<[VarId; 3]>` skips the per-op heap allocation in
/// `build_ssa` that `Vec<VarId>` paid for every op. Spills to the
/// heap transparently for the rare 4+ input ops (e.g. wide PHI
/// joins).
pub type InputVec = SmallVec<[VarId; 3]>;

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
    pub inputs: InputVec,
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
    /// Calls carry the calling convention's argument registers as inputs
    /// `1..` (added by the pipeline); `optimize::prune_call_args` trims them
    /// to the ones actually set up for the call.
    pub implicit_call_args: bool,
    /// Parameters of the callee of each direct call, keyed by the call
    /// instruction's address (WS78, `callee_params`). Used by
    /// `optimize::prune_call_args`; empty when unknown.
    pub call_params: FxHashMap<u64, crate::callee_params::ParamInfo>,
    /// The function's own parameter registers in convention order (WS78), when the
    /// calling convention is known; the emitters' signature. `None`: use the old guess.
    pub signature_params: Option<Vec<VarnodeData>>,
    /// The function returns a float in `xmm0` of this many bytes (4 = `float`, 8 =
    /// `double`) rather than an integer in `rax` (WS79, `pipeline::choose_return_register`).
    pub return_float: Option<u32>,
    /// Virtual calls on `this` whose slot was found in the vtable of the class the function
    /// is a method of: call address -> the function in that slot (WS79, `vcall`).
    pub vcall_targets: FxHashMap<u64, u64>,
}

impl SsaFunction {
    pub fn from_cfg(name: String, entry: u64, cfg: ControlFlowGraph) -> Self {
        // Pre-size the FxHashMaps used by get_or_create_var /
        // create_new_version. Each distinct (space, offset, size) slot
        // gets one entry, which for x86/ARM bodies is closer to N/4
        // than N. Reserving up-front kills the rehash cycle that
        // would otherwise fire during build_ssa.
        let approx_slots = cfg
            .blocks
            .iter()
            .flat_map(|b| b.instructions.iter())
            .map(|i| i.ops.len())
            .sum::<usize>()
            / 4
            + 16;
        let mut func = Self {
            name,
            entry,
            varnodes: Vec::new(),
            ops: Vec::new(),
            cfg,
            next_var_id: 0,
            var_versions: FxHashMap::with_capacity_and_hasher(approx_slots, Default::default()),
            current_var: FxHashMap::with_capacity_and_hasher(approx_slots, Default::default()),
            implicit_call_args: false,
            call_params: FxHashMap::default(),
            signature_params: None,
            return_float: None,
            vcall_targets: FxHashMap::default(),
        };
        func.build_ssa();
        func
    }

    fn build_ssa(&mut self) {
        // Count ops once so the arenas can be sized correctly. Without
        // this the inner pushes triggered Vec re-allocations as the
        // ops/varnodes lists grew through their default doubling
        // schedule; for a function with N ops we'd reallocate
        // O(log N) times for each arena, copying every entry.
        let total_ops: usize = self
            .cfg
            .blocks
            .iter()
            .flat_map(|b| b.instructions.iter())
            .map(|i| i.ops.len())
            .sum();
        self.ops.reserve(total_ops);
        // Heuristic: ~2 varnodes per op (inputs + output). The actual
        // ratio on x86_64 bodies is ~1.8 (measured empirically against
        // a 956-op synthetic, which produced 1711 varnodes); the
        // previous 3x heuristic over-reserved by ~70% which both
        // wasted memory and forced the Vec backing into a larger
        // allocation tier with worse cache behaviour. 2x lands tight
        // on x86 and still avoids per-op re-growth; if a later
        // architecture needs more headroom we can raise it again.
        self.varnodes.reserve(total_ops * 2);

        // Temporarily move the CFG out of `self` so the inner loop can
        // hold an immutable borrow of `cfg.blocks` *and* call the
        // `&mut self` helpers (get_or_create_var / create_new_version)
        // at the same time. Without this the borrow checker forced an
        // intermediate `all_ops: Vec<tuple>` snapshot, which on a
        // ~1000-op function cost ~100KB of allocation and a per-op
        // SmallVec clone -- both pure overhead. `mem::take` here is
        // O(1) (just moves the Vec headers) thanks to Default on
        // ControlFlowGraph, and the trailing `self.cfg = cfg` puts
        // the same CFG back; no observable change to the public state.
        let cfg = std::mem::take(&mut self.cfg);

        // SSA with phi nodes (`MULTIEQUAL`, WS75).
        //
        // Earlier revisions renamed in linear block order with no phi nodes,
        // so a value carried round a loop (`freq *= 0.5`, `add r14, 0x818`,
        // a running minimum) was read at the loop head as the *last version
        // defined in address order*, and its real definition at the latch had
        // no use and was deleted as dead code.
        //
        // Textbook construction: semi-pruned phi placement (only names read
        // before being written in some block get phis) on the iterated
        // dominance frontier, then renaming along the dominator tree. Ops
        // keep their linear block order in `self.ops` (phis first in each
        // block); only the renaming walks the tree. Blocks the dominator tree
        // does not reach are renamed afterwards with no incoming definitions.
        use reargo_core::address::SpaceId;
        type Key = (u32, u64, u32);
        let key_of = |vn: &VarnodeData| (vn.space.0, vn.offset, vn.size);
        let n = cfg.blocks.len();
        self.ops.reserve(total_ops / 8);

        // 1. global names (read before written in some block) and their def blocks
        let mut globals: rustc_hash::FxHashSet<Key> = Default::default();
        let mut defsites: FxHashMap<Key, Vec<usize>> = Default::default();
        for (b, block) in cfg.blocks.iter().enumerate() {
            let mut killed: rustc_hash::FxHashSet<Key> = Default::default();
            for op in block.instructions.iter().flat_map(|i| i.ops.iter()) {
                for inp in &op.inputs {
                    if inp.space != SpaceId::CONST && !killed.contains(&key_of(inp)) {
                        globals.insert(key_of(inp));
                    }
                }
                if let Some(out) = op.output {
                    let k = key_of(&out);
                    if killed.insert(k) {
                        defsites.entry(k).or_default().push(b);
                    }
                }
            }
        }

        // 2. phi placement on the iterated dominance frontier
        // WS82: landing pads are roots too, so their values reach the code after them
        let idom = if n > 0 { crate::dominator::compute_idom_forest(&cfg) } else { Vec::new() };
        let df = if n > 0 {
            crate::dominator::compute_dominance_frontier(&cfg, &idom)
        } else {
            Vec::new()
        };
        let mut phis: Vec<Vec<Key>> = vec![Vec::new(); n];
        let mut keys: Vec<Key> = globals.iter().copied().collect();
        keys.sort_unstable(); // deterministic phi order
        for k in keys {
            let Some(sites) = defsites.get(&k) else { continue };
            let mut has_phi = vec![false; n];
            let mut queued = vec![false; n];
            let mut work: Vec<usize> = sites.clone();
            for &b in sites {
                queued[b] = true;
            }
            while let Some(b) = work.pop() {
                for &f in &df[b] {
                    if !has_phi[f] {
                        has_phi[f] = true;
                        phis[f].push(k);
                        if !queued[f] {
                            queued[f] = true;
                            work.push(f);
                        }
                    }
                }
            }
        }

        // 3. lay the ops out in linear block order (phis first); renaming fills them in
        let mut block_start = vec![0usize; n];
        for (b, block) in cfg.blocks.iter().enumerate() {
            block_start[b] = self.ops.len();
            for _ in &phis[b] {
                let idx = self.ops.len();
                self.ops.push(SsaOp {
                    index: idx,
                    opcode: OpCode::MultiEqual,
                    output: None,
                    inputs: smallvec::smallvec![VarId::MAX; block.predecessors.len()],
                    block: b,
                    address: block.start_addr,
                    dead: false,
                });
            }
            for insn in &block.instructions {
                for pcode_op in &insn.ops {
                    let idx = self.ops.len();
                    self.ops.push(SsaOp {
                        index: idx,
                        opcode: pcode_op.opcode,
                        output: None,
                        inputs: InputVec::new(),
                        block: b,
                        address: insn.address,
                        dead: false,
                    });
                }
            }
        }

        // 4. rename along the dominator tree
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        for b in 0..n {
            if let Some(d) = idom[b]
                && d != b
            {
                children[d].push(b);
            }
        }
        let mut stacks: FxHashMap<Key, Vec<VarId>> = Default::default();
        let mut visited = vec![false; n];
        let mut roots: Vec<usize> = Vec::new();
        if n > 0 {
            roots.push(cfg.entry_block);
        }
        roots.extend((0..n).filter(|&b| b != cfg.entry_block && idom[b].is_none_or(|d| d == b)));
        let mut pushed_by: Vec<Vec<Key>> = vec![Vec::new(); n];
        for root in roots {
            // explicit DFS; on exit pop the names the block pushed
            let mut dfs: Vec<(usize, bool)> = vec![(root, false)];
            while let Some((b, exiting)) = dfs.pop() {
                if exiting {
                    for k in pushed_by[b].drain(..) {
                        if let Some(st) = stacks.get_mut(&k) {
                            st.pop();
                        }
                    }
                    continue;
                }
                if visited[b] {
                    continue;
                }
                visited[b] = true;
                dfs.push((b, true));
                let block = &cfg.blocks[b];
                let mut idx = block_start[b];
                for &k in &phis[b] {
                    let vn = VarnodeData::new(SpaceId(k.0), k.1, k.2);
                    let out = self.new_version_var(&vn);
                    self.varnodes[out as usize].def_op = Some(idx);
                    self.ops[idx].output = Some(out);
                    stacks.entry(k).or_default().push(out);
                    pushed_by[b].push(k);
                    idx += 1;
                }
                for insn in &block.instructions {
                    for pcode_op in &insn.ops {
                        let mut input_ids: InputVec = InputVec::with_capacity(pcode_op.inputs.len());
                        for inp in &pcode_op.inputs {
                            let top = if inp.space == SpaceId::CONST {
                                None
                            } else {
                                stacks.get(&key_of(inp)).and_then(|st| st.last().copied())
                            };
                            let id = match top {
                                Some(id) => id,
                                None => self.get_or_create_var(inp),
                            };
                            self.varnodes[id as usize].uses.push(idx);
                            input_ids.push(id);
                        }
                        self.ops[idx].inputs = input_ids;
                        if let Some(out) = pcode_op.output {
                            let id = self.new_version_var(&out);
                            self.varnodes[id as usize].def_op = Some(idx);
                            self.ops[idx].output = Some(id);
                            stacks.entry(key_of(&out)).or_default().push(id);
                            pushed_by[b].push(key_of(&out));
                        }
                        idx += 1;
                    }
                }
                // the successors' phi operands for the edges out of b
                for &s in &block.successors {
                    for (j, &p) in cfg.blocks[s].predecessors.iter().enumerate() {
                        if p != b {
                            continue;
                        }
                        for (pi, &k) in phis[s].iter().enumerate() {
                            let phi_idx = block_start[s] + pi;
                            if self.ops[phi_idx].inputs[j] != VarId::MAX {
                                continue;
                            }
                            let top = stacks.get(&k).and_then(|st| st.last().copied());
                            let id = match top {
                                Some(id) => id,
                                None => self.get_or_create_var(&VarnodeData::new(SpaceId(k.0), k.1, k.2)),
                            };
                            self.varnodes[id as usize].uses.push(phi_idx);
                            self.ops[phi_idx].inputs[j] = id;
                        }
                    }
                }
                for &c in children[b].iter().rev() {
                    dfs.push((c, false));
                }
            }
        }
        // phi operands on edges from blocks nothing reached: the incoming value
        for b in 0..n {
            for (pi, &k) in phis[b].iter().enumerate() {
                let phi_idx = block_start[b] + pi;
                for j in 0..self.ops[phi_idx].inputs.len() {
                    if self.ops[phi_idx].inputs[j] == VarId::MAX {
                        let id = self.get_or_create_var(&VarnodeData::new(SpaceId(k.0), k.1, k.2));
                        self.varnodes[id as usize].uses.push(phi_idx);
                        self.ops[phi_idx].inputs[j] = id;
                    }
                }
            }
        }

        self.cfg = cfg;
    }

    /// A fresh version of a register / RAM / unique slot (its def is set by the caller).
    fn new_version_var(&mut self, vn: &VarnodeData) -> VarId {
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
        id
    }

    fn get_or_create_var(&mut self, vn: &VarnodeData) -> VarId {
        let key = (vn.space.0, vn.offset, vn.size);
        if vn.space == reargo_core::address::SpaceId::CONST {
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
                if vn.data.space == reargo_core::address::SpaceId::CONST {
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
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;
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
