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

/// The ops reading a value: most values have one or two readers, kept inline (the same 24
/// bytes as a `Vec`, without its allocation).
pub type UseVec = SmallVec<[OpIdx; 2]>;

#[derive(Debug, Clone)]
pub struct SsaVarnode {
    pub id: VarId,
    pub data: VarnodeData,
    pub version: u32,
    pub def_op: Option<OpIdx>,
    pub uses: UseVec,
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

/// On a renaming stack of [`SsaFunction::build_ssa`]: a version left out ([`PhantomDefs`]),
/// `PHANTOM - version` (the ids of real values stay far below).
const PHANTOM: VarId = VarId::MAX - 1;
const PHANTOM_MIN: VarId = 1 << 31;

/// Per slot (dense id) of [`SsaFunction::build_ssa`]: how many versions it has, and its
/// incoming value (`VarId::MAX` until read).
struct Slots {
    versions: Vec<u32>,
    incoming: Vec<VarId>,
}

#[derive(Debug)]
pub struct SsaFunction {
    pub name: String,
    pub entry: u64,
    pub varnodes: Vec<SsaVarnode>,
    pub ops: Vec<SsaOp>,
    pub cfg: ControlFlowGraph,
    next_var_id: VarId,
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
    /// The phis the left-out definitions would have caused ([`PhantomDefs`]; numbered, not
    /// made): for the statistics, which count them as removed dead code.
    pub phantom_phis: usize,
}

/// Definitions a pass left out of the P-code because nothing can read them
/// (`pipeline::apply_call_convention`'s omitted call clobbers): by the address of the
/// instruction holding the call, the registers it would have defined right after its first
/// `CALL` / `CALLIND`. [`SsaFunction::from_cfg_with_phantoms`] numbers the versions of those
/// registers as if they were there (and places the phis they would have caused), so every
/// version that is printed keeps its number.
#[derive(Debug, Default)]
pub struct PhantomDefs {
    /// The registers (at most 32).
    pub regs: Vec<VarnodeData>,
    /// By the address of the instruction holding the call: bit `i` = `regs[i]` left out.
    pub at: FxHashMap<u64, u32>,
}

impl SsaFunction {
    pub fn from_cfg(name: String, entry: u64, cfg: ControlFlowGraph) -> Self {
        Self::from_cfg_with_phantoms(name, entry, cfg, &PhantomDefs::default())
    }

    /// [`Self::from_cfg`] of P-code with definitions left out ([`PhantomDefs`]).
    pub fn from_cfg_with_phantoms(name: String, entry: u64, cfg: ControlFlowGraph, phantoms: &PhantomDefs) -> Self {
        let mut func = Self {
            name,
            entry,
            varnodes: Vec::new(),
            ops: Vec::new(),
            cfg,
            next_var_id: 0,
            implicit_call_args: false,
            call_params: FxHashMap::default(),
            signature_params: None,
            return_float: None,
            vcall_targets: FxHashMap::default(),
            phantom_phis: 0,
        };
        func.build_ssa(phantoms);
        func
    }

    fn build_ssa(&mut self, phantoms: &PhantomDefs) {
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
        // (the arenas are sized once the phis are placed: below)

        // Temporarily move the CFG out of `self` so the inner loop can
        // hold an immutable borrow of `cfg.blocks` *and* call the
        // `&mut self` helpers (new_version_var / incoming_var)
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

        // 0. the slots (space, offset, size) as dense ids, and the slot of each non-constant
        // input / output in op order (`kids`, from `kid_start[b]` for block `b`)
        const NO_SLOT: u32 = u32::MAX;
        let mut slot_of: FxHashMap<Key, u32> = FxHashMap::with_capacity_and_hasher(total_ops / 4 + 16, Default::default());
        let mut slots: Vec<Key> = Vec::new();
        let mut kids: Vec<u32> = Vec::with_capacity(total_ops * 3);
        let mut kid_start = vec![0usize; n];
        // (the constants read and the values written: a varnode each)
        let (mut n_consts, mut n_outputs) = (0usize, 0usize);
        let mut intern = |k: Key| -> u32 {
            *slot_of.entry(k).or_insert_with(|| {
                slots.push(k);
                (slots.len() - 1) as u32
            })
        };
        for (b, block) in cfg.blocks.iter().enumerate() {
            kid_start[b] = kids.len();
            for op in block.instructions.iter().flat_map(|i| i.ops.iter()) {
                for inp in &op.inputs {
                    kids.push(if inp.space == SpaceId::CONST {
                        n_consts += 1;
                        NO_SLOT
                    } else {
                        intern(key_of(inp))
                    });
                }
                if let Some(out) = op.output {
                    n_outputs += 1;
                    kids.push(intern(key_of(&out)));
                }
            }
        }
        let n_slots = slots.len();
        let slot_vn = |k: u32| {
            let (sp, off, sz) = slots[k as usize];
            VarnodeData::new(SpaceId(sp), off, sz)
        };

        // the slot of each register left out somewhere, when the P-code reads or writes it
        // elsewhere (the others have no versions to number); the left-out registers with a
        // slot of an instruction (`regs` bits), looked up at its first call
        let reg_slot: SmallVec<[u32; 16]> =
            phantoms.regs.iter().map(|v| slot_of.get(&key_of(v)).copied().unwrap_or(NO_SLOT)).collect();
        let with_slot = reg_slot.iter().enumerate().fold(0u32, |a, (i, &k)| if k != NO_SLOT && i < 32 { a | (1 << i) } else { a });
        let any_phantom = with_slot != 0 && !phantoms.at.is_empty();
        let phantoms_at = |insn: &reargo_lift::LiftedInstruction, op: &reargo_core::pcode::PcodeOp, seen_call: &mut bool| -> u32 {
            if !any_phantom || *seen_call || !matches!(op.opcode, OpCode::Call | OpCode::CallInd) {
                return 0;
            }
            *seen_call = true;
            phantoms.at.get(&insn.address).map_or(0, |&m| m & with_slot)
        };
        let bits = |mut m: u32| {
            std::iter::from_fn(move || {
                (m != 0).then(|| {
                    let i = m.trailing_zeros();
                    m &= m - 1;
                    i as usize
                })
            })
        };

        // 1. global names (read before written in some block) and their def blocks
        let mut global = vec![false; n_slots];
        let mut defsites: Vec<Vec<usize>> = vec![Vec::new(); n_slots];
        // the def blocks with the left-out definitions, by register
        let mut phantom_sites: Vec<Vec<usize>> = vec![Vec::new(); if any_phantom { phantoms.regs.len() } else { 0 }];
        // the block (+ 1) that last wrote each slot
        let mut killed_in = vec![0usize; n_slots];
        for (b, block) in cfg.blocks.iter().enumerate() {
            let mut at = kid_start[b];
            for insn in &block.instructions {
                let mut seen_call = false;
                for op in &insn.ops {
                    for _ in &op.inputs {
                        let k = kids[at];
                        at += 1;
                        if k != NO_SLOT && killed_in[k as usize] != b + 1 {
                            global[k as usize] = true;
                        }
                    }
                    if op.output.is_some() {
                        let k = kids[at] as usize;
                        at += 1;
                        if killed_in[k] != b + 1 {
                            killed_in[k] = b + 1;
                            defsites[k].push(b);
                        }
                    }
                    for r in bits(phantoms_at(insn, op, &mut seen_call)) {
                        let k = reg_slot[r] as usize;
                        if killed_in[k] != b + 1 {
                            killed_in[k] = b + 1;
                            phantom_sites[r].push(b);
                        }
                    }
                }
            }
        }

        // 2. phi placement on the iterated dominance frontier
        // WS82: landing pads are roots too, so their values reach the code after them
        let idom = if n > 0 { crate::dominator::compute_idom_forest(&cfg) } else { Vec::new() };
        let mut df = if n > 0 {
            crate::dominator::compute_dominance_frontier(&cfg, &idom)
        } else {
            Vec::new()
        };
        // WS92: a loop whose header is the entry block. The function's entry is an edge into
        // that block too (from a virtual block before it), so the block is a join: it is in
        // the frontier of every block on the dominator path from a predecessor up to itself,
        // and its phis take one input more than it has predecessors — the last, the value on
        // entry. (Without it, `0x1000: … add rdi, 8; cmp rdi, rsi; jne 0x1000` read the
        // incoming `rdi` at the top of every iteration.)
        let entry_is_join = n > 0 && !cfg.blocks[cfg.entry_block].predecessors.is_empty();
        if entry_is_join {
            let e = cfg.entry_block;
            for &p in &cfg.blocks[e].predecessors {
                if p != e && idom[p].is_none() {
                    continue; // not reached from the entry
                }
                let mut runner = p;
                loop {
                    if !df[runner].contains(&e) {
                        df[runner].push(e);
                    }
                    match idom[runner] {
                        Some(up) if up != runner && runner != e => runner = up,
                        _ => break,
                    }
                }
            }
        }
        let mut phis: Vec<Vec<u32>> = vec![Vec::new(); n];
        // the phis only the left-out definitions would have caused: numbered, not made
        let mut phantom_phis: Vec<Vec<u32>> = vec![Vec::new(); n];
        let mut keys: Vec<u32> = (0..n_slots as u32).filter(|&k| global[k as usize]).collect();
        keys.sort_unstable_by_key(|&k| slots[k as usize]); // deterministic phi order
        // (per block, the key (+ 1) that put a phi there / queued it last)
        let mut has_phi = vec![0u32; n];
        let mut queued = vec![0u32; n];
        let mut work: Vec<usize> = Vec::new();
        // the iterated dominance frontier of `sites`, each block once (`mark` in `has_phi`)
        fn place(
            df: &[Vec<usize>],
            work: &mut Vec<usize>,
            sites: &[usize],
            mark: u32,
            has_phi: &mut [u32],
            queued: &mut [u32],
            mut out: impl FnMut(usize),
        ) {
            work.clear();
            work.extend_from_slice(sites);
            for &b in sites {
                queued[b] = mark;
            }
            while let Some(b) = work.pop() {
                for &f in &df[b] {
                    if has_phi[f] != mark {
                        has_phi[f] = mark;
                        out(f);
                        if queued[f] != mark {
                            queued[f] = mark;
                            work.push(f);
                        }
                    }
                }
            }
        }
        // (the marks of the second placement of a slot with left-out definitions: above all
        // the first ones)
        let mut base_has_phi = vec![0u32; if any_phantom { n } else { 0 }];
        let mut base_queued = base_has_phi.clone();
        for k in keys {
            let extra = if any_phantom {
                reg_slot.iter().position(|&s| s == k).map(|r| &phantom_sites[r]).filter(|v| !v.is_empty())
            } else {
                None
            };
            let sites = &defsites[k as usize];
            if !sites.is_empty() {
                place(&df, &mut work, sites, k + 1, &mut has_phi, &mut queued, |f| phis[f].push(k));
            }
            if let Some(extra) = extra {
                // every def site, the left-out ones too: the phis not placed above are phantoms
                let mut all = sites.clone();
                all.extend(extra.iter().copied().filter(|b| !sites.contains(b)));
                place(&df, &mut work, &all, k + 1, &mut base_has_phi, &mut base_queued, |f| {
                    if has_phi[f] != k + 1 {
                        phantom_phis[f].push(k);
                    }
                });
            }
        }

        // The arenas, sized once: an op per P-code op and phi; a varnode per constant read,
        // value written (phis too) and slot read on entry — and some room for the constants
        // and ops the passes add. (A guess of twice the ops was too small for half the
        // functions, and each growth copied the whole arena.)
        let n_phis: usize = phis.iter().map(Vec::len).sum();
        let new_values = n_consts + n_outputs + n_phis;
        self.ops.reserve(total_ops + n_phis + total_ops / 16 + 8);
        self.varnodes.reserve(new_values + n_slots + new_values / 16 + 16);

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
                    inputs: smallvec::smallvec![VarId::MAX; block.predecessors.len() + usize::from(entry_is_join && b == cfg.entry_block)],
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
        for (b, &d) in idom.iter().enumerate().take(n) {
            if let Some(d) = d
                && d != b
            {
                children[d].push(b);
            }
        }
        // per slot: the version count, the incoming value (`incoming_var`), the stack of
        // the versions in scope
        let mut vars = Slots { versions: vec![0; n_slots], incoming: vec![VarId::MAX; n_slots] };
        let mut stacks: Vec<Vec<VarId>> = vec![Vec::new(); n_slots];
        let mut visited = vec![false; n];
        let mut roots: Vec<usize> = Vec::new();
        if n > 0 {
            roots.push(cfg.entry_block);
        }
        roots.extend((0..n).filter(|&b| b != cfg.entry_block && idom[b].is_none_or(|d| d == b)));
        let mut pushed_by: Vec<Vec<u32>> = vec![Vec::new(); n];
        // (the phantom phis' operands set so far, per block and predecessor: only the first
        // sets one)
        self.phantom_phis = phantom_phis.iter().map(Vec::len).sum();
        let mut phantom_filled: Vec<Vec<bool>> = phantom_phis.iter().enumerate().map(|(b, ks)| vec![false; ks.len() * cfg.blocks[b].predecessors.len()]).collect();
        for root in roots {
            // explicit DFS; on exit pop the names the block pushed
            let mut dfs: Vec<(usize, bool)> = vec![(root, false)];
            while let Some((b, exiting)) = dfs.pop() {
                if exiting {
                    for k in pushed_by[b].drain(..) {
                        stacks[k as usize].pop();
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
                // (the phis in slot order, the phantom ones numbered and named but not made)
                let (real, ghost) = (&phis[b], &phantom_phis[b]);
                let (mut ri, mut gi) = (0, 0);
                while ri < real.len() || gi < ghost.len() {
                    let take_real = gi == ghost.len() || (ri < real.len() && slots[real[ri] as usize] < slots[ghost[gi] as usize]);
                    let k = if take_real { real[ri] } else { ghost[gi] };
                    let vn = slot_vn(k);
                    if !take_real {
                        gi += 1;
                        if entry_is_join && b == cfg.entry_block {
                            self.incoming_var(&mut vars, k, &vn);
                        }
                        vars.versions[k as usize] += 1;
                        stacks[k as usize].push(PHANTOM - vars.versions[k as usize]);
                        pushed_by[b].push(k);
                        continue;
                    }
                    ri += 1;
                    if entry_is_join && b == cfg.entry_block {
                        // the value on entry (read before any version is pushed)
                        let incoming = self.incoming_var(&mut vars, k, &vn);
                        self.varnodes[incoming as usize].uses.push(idx);
                        *self.ops[idx].inputs.last_mut().expect("the entry input") = incoming;
                    }
                    let out = self.new_version_var(&mut vars, k, &vn);
                    self.varnodes[out as usize].def_op = Some(idx);
                    self.ops[idx].output = Some(out);
                    stacks[k as usize].push(out);
                    pushed_by[b].push(k);
                    idx += 1;
                }
                let mut at = kid_start[b];
                for insn in &block.instructions {
                    let mut seen_call = false;
                    for pcode_op in &insn.ops {
                        let mut input_ids: InputVec = InputVec::with_capacity(pcode_op.inputs.len());
                        for inp in &pcode_op.inputs {
                            let k = kids[at];
                            at += 1;
                            let id = if k == NO_SLOT {
                                self.const_var(inp)
                            } else {
                                match stacks[k as usize].last() {
                                    // (never read: the values left out are those nothing reads)
                                    Some(&id) if id >= PHANTOM_MIN => self.push_var(*inp, PHANTOM - id),
                                    Some(&id) => id,
                                    None => self.incoming_var(&mut vars, k, inp),
                                }
                            };
                            self.varnodes[id as usize].uses.push(idx);
                            input_ids.push(id);
                        }
                        self.ops[idx].inputs = input_ids;
                        if let Some(out) = pcode_op.output {
                            let k = kids[at];
                            at += 1;
                            let id = self.new_version_var(&mut vars, k, &out);
                            self.varnodes[id as usize].def_op = Some(idx);
                            self.ops[idx].output = Some(id);
                            stacks[k as usize].push(id);
                            pushed_by[b].push(k);
                        }
                        idx += 1;
                        for r in bits(phantoms_at(insn, pcode_op, &mut seen_call)) {
                            // the definitions left out after the call, numbered
                            {
                                let k = reg_slot[r];
                                vars.versions[k as usize] += 1;
                                stacks[k as usize].push(PHANTOM - vars.versions[k as usize]);
                                pushed_by[b].push(k);
                            }
                        }
                    }
                }
                // the successors' phi operands for the edges out of b
                for &s in &block.successors {
                    for (j, &p) in cfg.blocks[s].predecessors.iter().enumerate() {
                        if p != b {
                            continue;
                        }
                        // (a phantom phi's operand: the value on entry is made where it was)
                        let n_preds = cfg.blocks[s].predecessors.len();
                        for (g, &k) in phantom_phis[s].iter().enumerate() {
                            let filled = &mut phantom_filled[s][g * n_preds + j];
                            if !std::mem::replace(filled, true) && stacks[k as usize].is_empty() {
                                self.incoming_var(&mut vars, k, &slot_vn(k));
                            }
                        }
                        for (pi, &k) in phis[s].iter().enumerate() {
                            let phi_idx = block_start[s] + pi;
                            if self.ops[phi_idx].inputs[j] != VarId::MAX {
                                continue;
                            }
                            let id = match stacks[k as usize].last() {
                                // (a phi reached from a value left out is read by nothing either)
                                Some(&id) if id >= PHANTOM_MIN => self.push_var(slot_vn(k), PHANTOM - id),
                                Some(&id) => id,
                                None => self.incoming_var(&mut vars, k, &slot_vn(k)),
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
                        let id = self.incoming_var(&mut vars, k, &slot_vn(k));
                        self.varnodes[id as usize].uses.push(phi_idx);
                        self.ops[phi_idx].inputs[j] = id;
                    }
                }
            }
        }

        self.cfg = cfg;
    }

    /// A fresh version of the register / RAM / unique slot `k` (its def is set by the caller).
    fn new_version_var(&mut self, vars: &mut Slots, k: u32, vn: &VarnodeData) -> VarId {
        let version = &mut vars.versions[k as usize];
        *version += 1;
        let cur_version = *version;
        self.push_var(*vn, cur_version)
    }

    /// A constant: fresh per use (each literal in the P-code is its own occurrence, and
    /// downstream passes compare constants by data, not by `VarId`).
    fn const_var(&mut self, vn: &VarnodeData) -> VarId {
        self.push_var(*vn, 0)
    }

    /// The value of slot `k` read where no version of it is in scope: the canonical
    /// "incoming" varnode of the slot (a parameter, a callee-saved register on entry, …) with
    /// no defining op, created at the first such read (every later one shares it).
    fn incoming_var(&mut self, vars: &mut Slots, k: u32, vn: &VarnodeData) -> VarId {
        let existing = vars.incoming[k as usize];
        if existing != VarId::MAX {
            return existing;
        }
        let id = self.push_var(*vn, vars.versions[k as usize]);
        vars.incoming[k as usize] = id;
        id
    }

    fn push_var(&mut self, data: VarnodeData, version: u32) -> VarId {
        let id = self.next_var_id;
        self.next_var_id += 1;
        self.varnodes.push(SsaVarnode { id, data, version, def_op: None, uses: UseVec::new() });
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

    /// A definition left out (a call's clobber nothing reads) still numbers the versions after
    /// it: the value on entry read on another path keeps the version it had with the
    /// definition there.
    #[test]
    fn phantom_definitions_keep_the_version_numbers() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let ram = |a| VarnodeData::new(SpaceId::RAM, a, 8);
        let xmm1 = VarnodeData::new(SpaceId::REGISTER, 0x1210, 16);
        let flag = VarnodeData::new(SpaceId::REGISTER, 0x200, 1);
        let op = |opcode, at, output, inputs: &[VarnodeData]| PcodeOp { opcode, seq: seq(at), output, inputs: SmallVec::from_slice(inputs) };
        let build = |with_clobber: bool| {
            let mut call = vec![op(OpCode::Call, 0x1001, None, &[ram(0x5000)])];
            if with_clobber {
                call.push(op(OpCode::Indirect, 0x1001, Some(xmm1), &[ram(0x5000), VarnodeData::new(SpaceId::CONST, 1, 1)]));
            }
            let insns = vec![
                make_lifted(0x1000, vec![op(OpCode::CBranch, 0x1000, None, &[ram(0x1003), flag])]),
                make_lifted(0x1001, call),
                make_lifted(0x1002, vec![op(OpCode::Return, 0x1002, None, &[VarnodeData::new(SpaceId::CONST, 0, 8)])]),
                make_lifted(0x1003, vec![op(OpCode::Call, 0x1003, None, &[ram(0x6000), xmm1])]),
                make_lifted(0x1004, vec![op(OpCode::Return, 0x1004, None, &[VarnodeData::new(SpaceId::CONST, 0, 8)])]),
            ];
            let mut phantoms = PhantomDefs { regs: vec![xmm1], ..Default::default() };
            if !with_clobber {
                phantoms.at.insert(0x1001, 1);
            }
            SsaFunction::from_cfg_with_phantoms("f".into(), 0x1000, ControlFlowGraph::build(&insns), &phantoms)
        };
        let read_version = |f: &SsaFunction| {
            let call = f.ops.iter().find(|o| o.opcode == OpCode::Call && o.address == 0x1003).expect("the call");
            f.varnodes[call.inputs[1] as usize].version
        };
        let (real, phantom) = (build(true), build(false));
        assert_eq!(read_version(&real), read_version(&phantom));
        assert!(phantom.ops.iter().all(|o| o.opcode != OpCode::Indirect));
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
