use reargo_lift::{LiftedInstruction, PcodeLift};
use reargo_loader::Memory;
use reargo_program::Program;
use rayon::prelude::*;

use crate::callee_params::{CalleeParams, ParamInfo};
use crate::cfg::ControlFlowGraph;
use crate::emit::CEmitter;
use crate::rust_emit::RustEmitter;
use crate::optimize::{run_optimization_passes, OptimizationStats};
use crate::ssa::SsaFunction;
use crate::structure::structure_cfg_with_handlers;

pub struct DecompileResult {
    pub c_code: String,
    pub rust_code: String,
    pub ssa_dump: String,
    /// C definitions of structs recovered from memory access patterns.
    pub recovered_structs: Vec<String>,
    pub stats: DecompileStats,
}

pub struct DecompileStats {
    pub instructions_lifted: usize,
    pub pcode_ops: usize,
    pub basic_blocks: usize,
    pub optimization: OptimizationStats,
    pub live_ops_after: usize,
}

pub fn decompile(
    lifter: &dyn PcodeLift,
    memory: &Memory,
    entry: u64,
    func_name: &str,
    max_instructions: usize,
) -> Result<DecompileResult, String> {
    decompile_with_symbols(lifter, memory, entry, func_name, max_instructions, &std::collections::BTreeMap::new())
}

/// [`decompile`] with the names of other addresses (imports get their known prototypes).
pub fn decompile_with_symbols(
    lifter: &dyn PcodeLift,
    memory: &Memory,
    entry: u64,
    func_name: &str,
    max_instructions: usize,
    symbols: &std::collections::BTreeMap<u64, String>,
) -> Result<DecompileResult, String> {
    let mut lifted = lifter
        .lift_range(memory, entry, max_instructions)
        .map_err(|e| e.to_string())?;

    if lifted.is_empty() {
        return Err(format!("no instructions at 0x{:x}", entry));
    }
    crate::noreturn::mark_noreturn_calls(&mut lifted, &crate::noreturn::NoReturn::new(lifter, memory, None));
    let switches = crate::switch::recover_jump_tables(&mut lifted, memory);

    let mut trimmed = trim_to_return(lifted);
    rewrite_tail_calls(&mut trimmed);
    let trimmed = crate::vcall::devirtualize_constant_calls(trimmed, memory);
    let oracle = CalleeParams::new(lifter, memory);
    let imports = Imports { symbols, code: Some((lifter, memory)) };
    let call_params = callee_param_map(&trimmed, oracle.as_ref(), &imports);
    let own = own_params(oracle.as_ref(), entry);
    let call_returns = callee_return_map(&trimmed, oracle.as_ref(), &imports);
    let symbols = &with_thunk_names(symbols, imports.thunk_names(&trimmed));
    let terminated = apply_call_convention(trimmed, lifter, &call_returns);
    let empty: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    let vcalls = ThisVcalls::new(lifter, memory, entry, &terminated, oracle.as_ref());
    build_decompile_result(terminated, func_name, entry, symbols, &empty, None, None, call_params, own, vcalls, Some((lifter, memory)), &[], &switches)
}

/// What resolving virtual calls on `this` needs (WS79, `vcall::resolve_this_vcalls`).
struct ThisVcalls<'a> {
    memory: &'a Memory,
    vtables: Vec<u64>,
    this_reg: reargo_core::pcode::VarnodeData,
    oracle: Option<&'a CalleeParams<'a>>,
}

impl<'a> ThisVcalls<'a> {
    /// `None` when the function makes no indirect call or is no virtual method of a class.
    fn new(
        lifter: &dyn PcodeLift,
        memory: &'a Memory,
        entry: u64,
        instructions: &[LiftedInstruction],
        oracle: Option<&'a CalleeParams<'a>>,
    ) -> Option<Self> {
        let has_vcall = instructions
            .iter()
            .any(|i| i.ops.iter().any(|o| o.opcode == reargo_core::pcode::OpCode::CallInd));
        if !has_vcall {
            return None;
        }
        let this_reg = *lifter.call_convention()?.args.first()?;
        let vtables = crate::vcall::this_vtables(memory, entry);
        (!vtables.is_empty()).then_some(Self { memory, vtables, this_reg, oracle })
    }
}

/// The function's own parameters (WS78): what the callee analysis finds for its entry,
/// with the convention's argument registers.
fn own_params(
    oracle: Option<&CalleeParams<'_>>,
    entry: u64,
) -> Option<(ParamInfo, Vec<reargo_core::pcode::VarnodeData>)> {
    let oracle = oracle?;
    Some((oracle.params(entry)?, oracle.args().to_vec()))
}

/// `symbols` with the names of import thunks added (borrowed when there are none).
fn with_thunk_names(
    symbols: &std::collections::BTreeMap<u64, String>,
    extra: std::collections::BTreeMap<u64, String>,
) -> std::borrow::Cow<'_, std::collections::BTreeMap<u64, String>> {
    if extra.is_empty() {
        return std::borrow::Cow::Borrowed(symbols);
    }
    let mut all = symbols.clone();
    all.extend(extra);
    std::borrow::Cow::Owned(all)
}

/// Parameters of every direct call's callee in `instructions`, keyed by the
/// call instruction's address (WS78).
/// The callee of a direct call is a known import (WS82): its prototype.
fn import_proto(imports: &Imports<'_>, target: u64) -> Option<crate::prototypes::Proto> {
    crate::prototypes::import_prototype(&imports.name(target)?)
}

/// Names of call targets that are imports (WS82): an import's own name, or — for a thunk
/// whose only instruction is `jmp import@plt` (`0x3a60420: jmp pthread_cond_destroy@plt`) —
/// the import's.
struct Imports<'a> {
    symbols: &'a std::collections::BTreeMap<u64, String>,
    code: Option<(&'a dyn PcodeLift, &'a Memory)>,
}

impl Imports<'_> {
    fn name(&self, target: u64) -> Option<String> {
        if let Some(n) = self.symbols.get(&target) {
            return Some(n.clone());
        }
        let n = self.symbols.get(&self.thunk_target(target)?)?;
        crate::prototypes::import_prototype(n).is_some().then(|| n.clone())
    }

    /// `jmp t` as the first instruction of `target`: `t`.
    fn thunk_target(&self, target: u64) -> Option<u64> {
        let (lifter, memory) = self.code?;
        let insn = lifter.lift_instruction(memory, target).ok()?;
        match insn.ops.as_slice() {
            [op] if op.opcode == reargo_core::pcode::OpCode::Branch => {
                op.inputs.first().filter(|t| t.space == reargo_core::address::SpaceId::RAM).map(|t| t.offset)
            }
            _ => None,
        }
    }

    /// The names of the thunks to imports that `instructions` call, for the call rendering.
    fn thunk_names(&self, instructions: &[LiftedInstruction]) -> std::collections::BTreeMap<u64, String> {
        let mut out = std::collections::BTreeMap::new();
        for op in instructions.iter().flat_map(|i| i.ops.iter()) {
            if op.opcode == reargo_core::pcode::OpCode::Call
                && let Some(t) = op.inputs.first()
                && t.space == reargo_core::address::SpaceId::RAM
                && !self.symbols.contains_key(&t.offset)
                && !out.contains_key(&t.offset)
                && let Some(n) = self.name(t.offset)
            {
                out.insert(t.offset, n);
            }
        }
        out
    }
}

fn callee_param_map(
    instructions: &[LiftedInstruction],
    oracle: Option<&CalleeParams<'_>>,
    imports: &Imports<'_>,
) -> rustc_hash::FxHashMap<u64, ParamInfo> {
    use reargo_core::pcode::OpCode;
    let mut out = rustc_hash::FxHashMap::default();
    let Some(oracle) = oracle else { return out };
    for insn in instructions {
        for op in &insn.ops {
            if op.opcode == OpCode::Call
                && let Some(t) = op.inputs.first()
                && t.space == reargo_core::address::SpaceId::RAM
            {
                // an import's code is not in the binary: its known prototype, if any
                let info = match import_proto(imports, t.offset) {
                    Some(p) => Some(p.params(oracle.args())),
                    None => oracle.params(t.offset),
                };
                if let Some(info) = info {
                    out.insert(insn.address, info);
                }
            }
        }
    }
    out
}

/// The return register of every direct call's callee, keyed by the call instruction's
/// address (WS79); calls whose callee is not known are left out.
fn callee_return_map(
    instructions: &[LiftedInstruction],
    oracle: Option<&CalleeParams<'_>>,
    imports: &Imports<'_>,
) -> rustc_hash::FxHashMap<u64, crate::callee_params::ReturnKind> {
    use reargo_core::pcode::OpCode;
    let mut out = rustc_hash::FxHashMap::default();
    let Some(oracle) = oracle else { return out };
    for insn in instructions {
        for op in &insn.ops {
            if op.opcode == OpCode::Call
                && let Some(t) = op.inputs.first()
                && t.space == reargo_core::address::SpaceId::RAM
            {
                let k = match import_proto(imports, t.offset) {
                    Some(p) => p.return_kind().unwrap_or(crate::callee_params::ReturnKind::Unknown),
                    None => oracle.return_kind(t.offset),
                };
                if k != crate::callee_params::ReturnKind::Unknown {
                    out.insert(insn.address, k);
                }
            }
        }
    }
    out
}

pub fn decompile_function(
    lifter: &dyn PcodeLift,
    program: &Program,
    func_entry: u64,
) -> Result<DecompileResult, String> {
    let (symbols, string_literals) = build_program_maps(program);
    let annotations = build_annotations(program);
    decompile_function_with_maps(
        lifter,
        program,
        func_entry,
        &symbols,
        &string_literals,
        Some(&annotations),
        Some(&program.call_renderings),
    )
}

/// Roll up every `program.comments` entry into the per-address vector
/// the C / Rust emitters want. One BTreeMap per program; passed by
/// reference into every decompile call so the cost is paid once.
pub fn build_annotations(program: &Program) -> std::collections::BTreeMap<u64, Vec<String>> {
    let mut out: std::collections::BTreeMap<u64, Vec<String>> =
        std::collections::BTreeMap::new();
    for c in program.comments.iter() {
        out.entry(c.address).or_default().push(c.text);
    }
    out
}

/// Iterate `program.symbol_table` once and return the two
/// per-program lookup maps the emitter needs: `address -> symbol
/// name`, and the subset where names follow Ghidra's `s_<text>_<id>`
/// string-literal convention. Pulled out of `decompile_function` so
/// `decompile_all` can build them once and share them across the
/// entire function batch instead of rebuilding per call.
pub fn build_program_maps(
    program: &Program,
) -> (
    std::collections::BTreeMap<u64, String>,
    std::collections::BTreeMap<u64, String>,
) {
    let mut symbols = std::collections::BTreeMap::new();
    let mut string_literals = std::collections::BTreeMap::new();
    for sym in program.symbol_table.iter() {
        symbols.insert(sym.address, sym.name.clone());
        if let Some(rest) = sym.name.strip_prefix("s_")
            && let Some((text, _)) = rest.rsplit_once('_')
        {
            let lit = text.replace('_', " ");
            if !lit.is_empty() {
                string_literals.insert(sym.address, lit);
            }
        }
    }
    (symbols, string_literals)
}

/// Decompile a single function reusing program-level lookup maps
/// built by the caller (see `build_program_maps`).
///
/// `decompile_function` is the convenience entry point that builds
/// the maps itself; `decompile_all` builds them once for the whole
/// program and calls this directly so the per-function fan-out
/// doesn't re-iterate `program.symbol_table` N times.
pub fn decompile_function_with_maps(
    lifter: &dyn PcodeLift,
    program: &Program,
    func_entry: u64,
    symbols: &std::collections::BTreeMap<u64, String>,
    string_literals: &std::collections::BTreeMap<u64, String>,
    annotations: Option<&std::collections::BTreeMap<u64, Vec<String>>>,
    call_renderings: Option<&std::collections::BTreeMap<u64, String>>,
) -> Result<DecompileResult, String> {
    let oracle = CalleeParams::new(lifter, &program.info.memory);
    decompile_function_inner(
        lifter,
        program,
        func_entry,
        symbols,
        string_literals,
        annotations,
        call_renderings,
        oracle.as_ref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn decompile_function_inner(
    lifter: &dyn PcodeLift,
    program: &Program,
    func_entry: u64,
    symbols: &std::collections::BTreeMap<u64, String>,
    string_literals: &std::collections::BTreeMap<u64, String>,
    annotations: Option<&std::collections::BTreeMap<u64, Vec<String>>>,
    call_renderings: Option<&std::collections::BTreeMap<u64, String>>,
    oracle: Option<&CalleeParams<'_>>,
) -> Result<DecompileResult, String> {
    let func = program.listing.get_function(func_entry);
    let func_name = func
        .map(|f| f.name.clone())
        .unwrap_or_else(|| program.function_name_at(func_entry));

    // Lift far enough past the function entry that the trim's
    // reachability DFS has something to walk. The body's byte size
    // is a lower bound (we get one instruction per byte at worst);
    // floor at 500 so functions whose body discovery only reached
    // the entry block still get enough lifted instructions to
    // reach the real Return / end-of-function.
    let max_insns = func
        .map(|f| {
            f.body
                .ranges()
                .map(|r| r.size as usize)
                .sum::<usize>()
                .max(500)
        })
        .unwrap_or(500);

    let mut lifted = lifter
        .lift_range(&program.info.memory, func_entry, max_insns)
        .map_err(|e| e.to_string())?;

    if lifted.is_empty() {
        return Err(format!("no instructions at 0x{:x}", func_entry));
    }
    // WS81: a call that never returns ends the flow (before the trim, so the code behind it is
    // not reached through it)
    let noreturn = crate::noreturn::NoReturn::new(lifter, &program.info.memory, Some(symbols));
    crate::noreturn::mark_noreturn_calls(&mut lifted, &noreturn);
    // WS83: jump tables become the `jmp`'s successors (before the trim, which follows them)
    let switches = crate::switch::recover_jump_tables(&mut lifted, &program.info.memory);

    let terminated = if func.is_some() {
        trim_to_function_body(lifted, func_entry, func)
    } else {
        trim_to_return(lifted)
    };
    let mut terminated = terminated;
    rewrite_tail_calls(&mut terminated);
    let terminated = crate::vcall::devirtualize_constant_calls(terminated, &program.info.memory);
    let imports = Imports { symbols, code: Some((lifter, &program.info.memory)) };
    let call_params = callee_param_map(&terminated, oracle, &imports);
    let own = own_params(oracle, func_entry);
    let call_returns = callee_return_map(&terminated, oracle, &imports);
    let symbols = &with_thunk_names(symbols, imports.thunk_names(&terminated));
    let terminated = apply_call_convention(terminated, lifter, &call_returns);
    let vcalls = ThisVcalls::new(lifter, &program.info.memory, func_entry, &terminated, oracle);
    // WS82: the exception landing pads, printed after the body
    let handlers = crate::exception::handlers(&program.info.memory, &program.info.sections, symbols, func_entry);

    build_decompile_result(
        terminated,
        &func_name,
        func_entry,
        symbols,
        string_literals,
        annotations,
        call_renderings,
        call_params,
        own,
        vcalls,
        Some((lifter, &program.info.memory)),
        &handlers,
        &switches,
    )
}

/// Address of the stub [`rewrite_tail_calls`] makes for a conditional jump out of the code to
/// `target`: far from any real code, so nothing keyed by address (annotations, call
/// renderings) matches it.
pub const TAIL_STUB_BASE: u64 = 0xffff_0000_0000_0000;

/// A `jmp` out of the code being decompiled is a tail call (WS81): rewrite its `BRANCH` into
/// `CALL target; RETURN`, so it prints as `return f(…);` with the call's arguments instead of
/// vanishing (a `BRANCH` prints nothing) with the argument setup left dead.
///
/// WS82: a conditional jump out of the code (`jne free@plt` before the prologue) used to lose
/// its condition (the CFG only kept the fall-through); it now jumps to a stub `CALL target;
/// RETURN` at [`TAIL_STUB_BASE`]` + target`, so it prints as `if (c) { return f(…); }`. An
/// indirect `jmp` that is not a jump-table dispatch (`jmp [rax+0x20]`, a vtable slot) is a
/// tail call too: `CALLIND; RETURN` instead of `goto *tmp;`.
pub(crate) fn rewrite_tail_calls(instructions: &mut Vec<LiftedInstruction>) {
    use reargo_core::address::SpaceId;
    use reargo_core::pcode::{OpCode, PcodeOp, VarnodeData};
    let inside: rustc_hash::FxHashSet<u64> = instructions.iter().map(|i| i.address).collect();
    let ret = |seq| PcodeOp { opcode: OpCode::Return, seq, output: None, inputs: smallvec::smallvec![VarnodeData::new(SpaceId::CONST, 0, 8)] };
    let outside = |t: &VarnodeData| t.space == SpaceId::RAM && !inside.contains(&t.offset) && t.offset < TAIL_STUB_BASE;
    let mut stubs: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for k in 0..instructions.len() {
        let table = jump_table_dispatch(instructions, k);
        let insn = &mut instructions[k];
        for op in insn.ops.iter_mut() {
            if op.opcode == OpCode::CBranch
                && let Some(t) = op.inputs.first_mut()
                && outside(t)
            {
                stubs.insert(t.offset);
                t.offset += TAIL_STUB_BASE;
            }
        }
        let Some(pos) = insn.ops.iter().position(|o| {
            (o.opcode == OpCode::Branch && o.inputs.first().is_some_and(outside))
                || (o.opcode == OpCode::BranchInd && !table)
        }) else {
            continue;
        };
        let seq = insn.ops[pos].seq;
        insn.ops[pos].opcode = if insn.ops[pos].opcode == OpCode::BranchInd { OpCode::CallInd } else { OpCode::Call };
        insn.ops.insert(pos + 1, ret(seq));
        for (i, op) in insn.ops.iter_mut().enumerate() {
            op.seq.order = i as u32;
        }
    }
    // the stubs go after the code (their addresses are above it), in address order
    for t in stubs {
        let at = TAIL_STUB_BASE + t;
        let seq = |order| reargo_core::pcode::SeqNum::new(reargo_core::address::Address::new(SpaceId::RAM, at), order);
        let call = PcodeOp { opcode: OpCode::Call, seq: seq(0), output: None, inputs: smallvec::smallvec![VarnodeData::new(SpaceId::RAM, t, 8)] };
        let pos = instructions.partition_point(|i| i.address < at);
        instructions.insert(
            pos,
            LiftedInstruction { address: at, length: 1, mnemonic: format!("jmp 0x{t:x}"), ops: vec![call, ret(seq(1))] },
        );
    }
}

/// Is the indirect `jmp` of `instructions[k]` a jump-table dispatch (`jmp [table + i*8]`, or
/// `movsxd rax, [rcx + rax*4]; add rax, rcx; jmp rax`) rather than a tail call? A scaled
/// index in the `jmp` or in the instructions right before it marks a table.
fn jump_table_dispatch(instructions: &[LiftedInstruction], k: usize) -> bool {
    let scaled = |m: &str| m.contains("*2]") || m.contains("*4]") || m.contains("*8]") || m.contains("*2+") || m.contains("*4+") || m.contains("*8+");
    let insn = &instructions[k];
    if !insn.ops.iter().any(|o| o.opcode == reargo_core::pcode::OpCode::BranchInd) {
        return false;
    }
    if scaled(&insn.mnemonic) {
        return true;
    }
    // `jmp [mem]` reads its target from memory: a table only with a scaled index
    if insn.mnemonic.contains('[') {
        return false;
    }
    instructions[..k].iter().rev().take(6).any(|i| scaled(&i.mnemonic))
}

/// Second input of a call's `INDIRECT` that marks a clobbered (not returned) register.
pub const CLOBBER_MARK: u64 = 1;

/// Is `op` the `INDIRECT` of a register a call clobbers (as opposed to one it returns)?
pub fn is_call_clobber(op: &reargo_core::pcode::OpCode, inputs: &[reargo_core::pcode::VarnodeData]) -> bool {
    *op == reargo_core::pcode::OpCode::Indirect
        && inputs.len() == 2
        && inputs[1].space == reargo_core::address::SpaceId::CONST
        && inputs[1].offset == CLOBBER_MARK
}

/// Give every call the calling convention's argument registers as inputs and
/// define its return registers right after it (`INDIRECT(target)`, with the
/// narrower views refreshed), so argument setup is not dead code and a use of
/// the result does not read the value from before the call (WS75).
/// `optimize::prune_call_args` later keeps only the arguments set up for the
/// call. No-op when the lifter has no convention.
fn apply_call_convention(
    mut instructions: Vec<LiftedInstruction>,
    lifter: &dyn PcodeLift,
    call_returns: &rustc_hash::FxHashMap<u64, crate::callee_params::ReturnKind>,
) -> Vec<LiftedInstruction> {
    use reargo_core::pcode::{OpCode, PcodeOp, VarnodeData};
    let Some(cc) = lifter.call_convention() else {
        return instructions;
    };
    // WS77: a `ret` lifts to `RETURN(target)` — the popped return address, not the value. Give
    // it the convention's return registers (`rax`, then `xmm0`) as further inputs so the value
    // reaching the `ret` is live and the emitter can print it (`emit::return_value`);
    // `choose_return_register` keeps the one the function returns in (WS79).
    if !cc.returns.is_empty() {
        for op in instructions.iter_mut().flat_map(|i| i.ops.iter_mut()) {
            if op.opcode == OpCode::Return && op.inputs.len() == 1 {
                op.inputs.extend(cc.returns.iter().map(|(r, _)| *r));
            }
        }
    }
    for insn in &mut instructions {
        let Some(pos) = insn
            .ops
            .iter()
            .position(|o| matches!(o.opcode, OpCode::Call | OpCode::CallInd))
        else {
            continue;
        };
        let insn_addr = insn.address;
        let call = &mut insn.ops[pos];
        let at = call.seq;
        let target = call.inputs.first().copied();
        for a in &cc.args {
            call.inputs.push(*a);
        }
        let mut after: Vec<PcodeOp> = Vec::new();
        // returns: `INDIRECT(target)`; clobbers: `INDIRECT(target, 1)` (WS76: a caller-saved
        // register read after a call no longer shows the value it had before the call)
        let clobber_mark = VarnodeData::new(reargo_core::address::SpaceId::CONST, CLOBBER_MARK, 1);
        // WS79: a callee known to return in one register only clobbers the other
        let returned = |i: usize| match call_returns.get(&insn_addr) {
            Some(crate::callee_params::ReturnKind::Int) => i == 0,
            Some(crate::callee_params::ReturnKind::Float) => i == 1,
            _ => true,
        };
        let defs = cc
            .returns
            .iter()
            .enumerate()
            .map(|(i, r)| (r, !returned(i)))
            .chain(cc.clobbers.iter().map(|r| (r, true)));
        for ((full, views), clobber) in defs {
            let mut inputs = smallvec::SmallVec::new();
            match target {
                Some(t) => inputs.push(t),
                None if clobber => inputs.push(VarnodeData::new(reargo_core::address::SpaceId::CONST, 0, 8)),
                None => {}
            }
            if clobber {
                inputs.push(clobber_mark);
            }
            after.push(PcodeOp { opcode: OpCode::Indirect, seq: at, output: Some(*full), inputs });
            for &sz in views {
                after.push(PcodeOp {
                    opcode: OpCode::Subpiece,
                    seq: at,
                    output: Some(VarnodeData::new(full.space, full.offset, sz)),
                    inputs: smallvec::smallvec![*full, VarnodeData::new(reargo_core::address::SpaceId::CONST, 0, 4)],
                });
            }
        }
        let tail = insn.ops.split_off(pos + 1);
        insn.ops.extend(after);
        insn.ops.extend(tail);
        for (i, op) in insn.ops.iter_mut().enumerate() {
            op.seq.order = i as u32;
        }
    }
    instructions
}

/// Is `v` read by something other than a call it is handed to as an (implicit) argument?
/// Looks through the lifter's register-view syncs (a `SUBPIECE` of the low bytes, a zero
/// extension, the low half of a `PIECE`); the upper lanes a later scalar write carries over
/// (`SUBPIECE(xmm0, 4)`) and a φ-node (which merges other paths' values too) are not
/// evidence of a read.
fn read_beyond_call_args(ssa: &SsaFunction, v: crate::ssa::VarId, depth: u32) -> bool {
    use reargo_core::pcode::OpCode;
    if depth > 6 {
        return true;
    }
    ssa.varnodes[v as usize].uses.iter().any(|&u| {
        let op = &ssa.ops[u];
        let deeper = |o: Option<crate::ssa::VarId>| o.is_some_and(|o| read_beyond_call_args(ssa, o, depth + 1));
        match op.opcode {
            _ if op.dead => false,
            OpCode::Call | OpCode::CallInd => op.inputs.first() == Some(&v),
            OpCode::Subpiece => {
                let k = op.inputs.get(1).map(|&c| ssa.varnodes[c as usize].data);
                match k {
                    Some(k) if k.space == reargo_core::address::SpaceId::CONST && k.offset > 0 => false,
                    _ => deeper(op.output),
                }
            }
            // the upper lanes a `PIECE` keeps; a φ also merges other paths' values: no evidence
            OpCode::Piece if op.inputs.first() == Some(&v) => false,
            OpCode::MultiEqual => false,
            OpCode::Piece | OpCode::IntZExt => deeper(op.output),
            _ => true,
        }
    })
}

/// A call whose return register is unknown (an import, an indirect call nobody resolved)
/// defines both `rax` and `xmm0` as its result. When the caller really reads one of them and
/// only hands the other on to later calls as a guessed argument, the callee returned in the
/// one read (WS80): the other becomes a clobber, so it is neither printed as a second
/// `__ret` nor passed to the next call.
fn settle_unknown_returns(ssa: &mut SsaFunction) {
    use reargo_core::pcode::OpCode;
    let mut to_clobber = Vec::new();
    for call in ssa.ops.iter().filter(|o| matches!(o.opcode, OpCode::Call | OpCode::CallInd)) {
        let rets: Vec<usize> = ssa.ops[call.index + 1..]
            .iter()
            .take_while(|o| o.address == call.address && o.block == call.block)
            .filter(|o| {
                o.opcode == OpCode::Indirect
                    && o.output.is_some()
                    && !is_call_clobber(&o.opcode, &o.inputs.iter().map(|&i| ssa.varnodes[i as usize].data).collect::<Vec<_>>())
            })
            .map(|o| o.index)
            .collect();
        let [a, b] = rets[..] else { continue };
        let read = |i: usize| read_beyond_call_args(ssa, ssa.ops[i].output.unwrap(), 0);
        match (read(a), read(b)) {
            (true, false) => to_clobber.push(b),
            (false, true) => to_clobber.push(a),
            _ => {}
        }
    }
    for i in to_clobber {
        let add_const = |ssa: &mut SsaFunction, value: u64, size: u32| {
            let id = ssa.varnodes.len() as crate::ssa::VarId;
            ssa.varnodes.push(crate::ssa::SsaVarnode {
                id,
                data: reargo_core::pcode::VarnodeData::new(reargo_core::address::SpaceId::CONST, value, size),
                version: 0,
                def_op: None,
                uses: vec![i],
            });
            ssa.ops[i].inputs.push(id);
        };
        if ssa.ops[i].inputs.is_empty() {
            add_const(ssa, 0, 8);
        }
        add_const(ssa, CLOBBER_MARK, 1);
    }
}

/// What the function last wrote into a return register before a `ret` (WS79).
#[derive(Debug, Clone, Copy, Default)]
struct RetEvidence {
    /// The function itself computed the value (not the entry value, a call's result or a
    /// call's clobber).
    written: bool,
    /// Address of the latest such write.
    addr: u64,
    /// Size of that write once the register views are looked through (`xmm0_d` = 4).
    size: u32,
    /// The value is a call's result (its return `INDIRECT`, not a clobber).
    call_result: bool,
}

/// The value `v` holds at a `ret`, looking through the lifter's view syncs (`xmm0 =
/// PIECE(hi, xmm0_q)`), register copies (`movaps xmm0, xmm1`) and φ-nodes.
fn return_evidence(ssa: &SsaFunction, v: crate::ssa::VarId, seen: &mut Vec<crate::ssa::VarId>) -> RetEvidence {
    use reargo_core::pcode::OpCode;
    if seen.contains(&v) || seen.len() > 64 {
        return RetEvidence::default();
    }
    seen.push(v);
    let vn = &ssa.varnodes[v as usize];
    let Some(d) = vn.def_op else { return RetEvidence::default() };
    let op = &ssa.ops[d];
    let reg = |x: crate::ssa::VarId| ssa.varnodes[x as usize].data.space == reargo_core::address::SpaceId::REGISTER;
    match op.opcode {
        OpCode::Indirect => RetEvidence {
            call_result: !is_call_clobber(&op.opcode, &op.inputs.iter().map(|&i| ssa.varnodes[i as usize].data).collect::<Vec<_>>()),
            ..RetEvidence::default()
        },
        OpCode::MultiEqual => {
            let mut best = RetEvidence::default();
            for &i in &op.inputs {
                let e = return_evidence(ssa, i, seen);
                if e.written && (!best.written || e.addr > best.addr) {
                    best = e;
                }
                best.call_result |= e.call_result;
            }
            best
        }
        OpCode::Piece if op.inputs.len() == 2 && {
            let lo = &ssa.varnodes[op.inputs[1] as usize].data;
            lo.space == vn.data.space && lo.offset == vn.data.offset && lo.size < vn.data.size
        } => return_evidence(ssa, op.inputs[1], seen),
        OpCode::Copy if op.inputs.len() == 1 && reg(op.inputs[0]) && {
            let src = &ssa.varnodes[op.inputs[0] as usize].data;
            src.size == vn.data.size && src.offset != vn.data.offset
        } => {
            let e = return_evidence(ssa, op.inputs[0], seen);
            RetEvidence { addr: e.addr.max(op.address), ..e }
        }
        _ => RetEvidence { written: true, addr: op.address, size: vn.data.size, call_result: false },
    }
}

/// Which register does the function return its value in (WS79)? Every `RETURN` carries the
/// convention's return registers (`RETURN(target, rax, xmm0)`, see `apply_call_convention`).
/// A `ret` votes for `xmm0` when the function wrote a scalar float into it (a 4- or 8-byte
/// `xmm0_d` / `xmm0_q` value — a full-width `xorps xmm0, xmm0` or `movups` of memory is no
/// evidence) later than it last wrote `rax`; for `rax` when it wrote `rax` last. `xmm0`
/// wins only when some `ret` votes for it and none for `rax`. The losing register is
/// removed from every `RETURN`, so its computation is not kept alive. Returns the float
/// size when `xmm0` won.
fn choose_return_register(
    ssa: &mut SsaFunction,
    callers: &mut dyn FnMut() -> Option<crate::callers::ReturnHint>,
) -> Option<u32> {
    use reargo_core::pcode::OpCode;
    let rets: Vec<usize> = ssa
        .ops
        .iter()
        .filter(|o| o.opcode == OpCode::Return && o.inputs.len() == 3)
        .map(|o| o.index)
        .collect();
    if rets.is_empty() {
        return None;
    }
    let (mut float_votes, mut int_votes, mut size) = (0, 0, 0u32);
    let mut passes_call_result = false;
    for &r in &rets {
        let (iv, fv) = (ssa.ops[r].inputs[1], ssa.ops[r].inputs[2]);
        let i = return_evidence(ssa, iv, &mut Vec::new());
        let f = return_evidence(ssa, fv, &mut Vec::new());
        let f_scalar = f.written && (f.size == 4 || f.size == 8);
        if f_scalar && (!i.written || f.addr > i.addr) {
            float_votes += 1;
            size = size.max(f.size);
        } else if i.written {
            int_votes += 1;
        } else if f.call_result && !i.call_result {
            // `call g; ret` with `g` known to return a float (its `rax` is only clobbered)
            float_votes += 1;
        } else if i.call_result {
            passes_call_result = true;
        }
    }
    // WS80: `return g();` with `g`'s return register unknown: ask what the callers read
    let mut float = float_votes > 0 && int_votes == 0;
    if float_votes == 0 && int_votes == 0 && passes_call_result {
        match callers() {
            Some(crate::callers::ReturnHint::Float(s)) => {
                float = true;
                size = s;
            }
            Some(crate::callers::ReturnHint::Void) => {
                for &r in &rets {
                    for v in ssa.ops[r].inputs.drain(1..).collect::<Vec<_>>() {
                        unuse(ssa, v, r);
                    }
                }
                return None;
            }
            _ => {}
        }
    }
    if size == 0 {
        size = 8; // only call results: the width is not known, print it as a double
    }
    let drop = if float { 1 } else { 2 };
    for &r in &rets {
        let v = ssa.ops[r].inputs.remove(drop);
        unuse(ssa, v, r);
        if float {
            // return the scalar view (`xmm0_d`) the value was computed in, not the
            // whole register rebuilt from it
            let mut x = ssa.ops[r].inputs[1];
            while let Some(d) = ssa.varnodes[x as usize].def_op
                && ssa.ops[d].opcode == OpCode::Piece
                && ssa.ops[d].inputs.len() == 2
                && ssa.varnodes[x as usize].data.size > size
            {
                let lo = ssa.ops[d].inputs[1];
                let (lv, xv) = (&ssa.varnodes[lo as usize].data, &ssa.varnodes[x as usize].data);
                if lv.space != xv.space || lv.offset != xv.offset {
                    break;
                }
                x = lo;
            }
            if ssa.varnodes[x as usize].data.size == size && x != ssa.ops[r].inputs[1] {
                let old = std::mem::replace(&mut ssa.ops[r].inputs[1], x);
                unuse(ssa, old, r);
                ssa.varnodes[x as usize].uses.push(r);
            }
        }
    }
    float.then_some(size)
}

/// Drop one use of `v` by op `r`.
fn unuse(ssa: &mut SsaFunction, v: crate::ssa::VarId, r: usize) {
    let uses = &mut ssa.varnodes[v as usize].uses;
    if let Some(p) = uses.iter().position(|&u| u == r) {
        uses.remove(p);
    }
}

/// The argument registers that are the function's parameters: those the analysis of its
/// entry found it reads, plus — when that answer is only a lower bound — those the
/// decompiled body still reads on entry. WS79: each register class keeps its whole prefix
/// up to the highest parameter read (System V passes `f(a, b)` in `rdi, rsi` even when
/// the body only reads `b`), so the signature shows the real arity and position.
fn signature_params(
    ssa: &SsaFunction,
    info: ParamInfo,
    args: &[reargo_core::pcode::VarnodeData],
) -> Vec<reargo_core::pcode::VarnodeData> {
    let used: Vec<bool> = args
        .iter()
        .enumerate()
        .map(|(i, a)| {
            info.mask & (1 << i) != 0
                || (!info.complete
                    && ssa.varnodes.iter().any(|vn| {
                        vn.def_op.is_none()
                            && vn.data.space == a.space
                            && vn.data.offset == a.offset
                            && vn.uses.iter().any(|&u| !ssa.ops[u].dead)
                    }))
        })
        .collect();
    let (class_of, members) = crate::callee_params::arg_classes(args);
    let arity: Vec<usize> = members
        .iter()
        .map(|m| m.iter().rposition(|&i| used[i]).map_or(0, |p| p + 1))
        .collect();
    args.iter()
        .enumerate()
        .filter(|&(i, _)| {
            let c = class_of[i];
            members[c].iter().position(|&m| m == i).is_some_and(|p| p < arity[c])
        })
        .map(|(_, a)| *a)
        .collect()
}

/// Decompile every function the program knows about, in parallel.
///
/// Each function decompiles independently (no shared mutable state
/// between functions), so the work fans out to rayon's thread pool
/// and the wall-clock cost is ~`sum / threads` rather than `sum`.
/// Results come back in (entry_point, Result) pairs so a single
/// failed function doesn't abort the whole batch.
pub fn decompile_all(
    lifter: &(dyn PcodeLift + Sync),
    program: &Program,
) -> Vec<(u64, Result<DecompileResult, String>)> {
    let entries: Vec<u64> = program
        .listing
        .functions()
        .map(|f| f.entry_point)
        .collect();

    // Build the program-wide lookup maps once and share them across
    // every function decompile. Previously each parallel
    // `decompile_function` call rebuilt the same maps from
    // `program.symbol_table` -- O(N) per call, where N is the symbol
    // count, multiplied by M parallel functions == O(N*M) redundant
    // work. `decompile_function_with_maps` is the same code path
    // minus the rebuild.
    let (symbols, string_literals) = build_program_maps(program);
    let annotations = build_annotations(program);
    // one callee-parameter memo for the whole batch
    let oracle = CalleeParams::new(lifter, &program.info.memory);

    entries
        .par_iter()
        .map(|&entry| {
            (
                entry,
                decompile_function_inner(
                    lifter,
                    program,
                    entry,
                    &symbols,
                    &string_literals,
                    Some(&annotations),
                    Some(&program.call_renderings),
                    oracle.as_ref(),
                ),
            )
        })
        .collect()
}

/// Result of taint-tracking a function from its parameters.
pub struct TaintReport {
    pub tainted_values: usize,
    pub sinks: Vec<crate::taint::TaintSink>,
}

/// Lift a function, build SSA, mark the given parameter registers as tainted,
/// and report where tainted data reaches dangerous sinks.
///
/// `param_offsets` are REGISTER-space offsets of the parameter registers in
/// calling-convention order.
pub fn analyze_taint(
    lifter: &dyn PcodeLift,
    program: &Program,
    func_entry: u64,
    param_offsets: &[u64],
) -> Result<TaintReport, String> {
    let func = program.listing.get_function(func_entry);
    let max_insns = func
        .map(|f| f.body.ranges().map(|r| r.size as usize).sum::<usize>().max(100))
        .unwrap_or(500);

    let lifted = lifter
        .lift_range(&program.info.memory, func_entry, max_insns)
        .map_err(|e| e.to_string())?;
    if lifted.is_empty() {
        return Err(format!("no instructions at 0x{:x}", func_entry));
    }

    let terminated = if func.is_some() {
        trim_to_function_body(lifted, func_entry, func)
    } else {
        trim_to_return(lifted)
    };

    let cfg = ControlFlowGraph::build(&terminated);
    let ssa = SsaFunction::from_cfg("taint".to_string(), func_entry, cfg);

    let mut engine = crate::taint::TaintEngine::new();
    for &off in param_offsets {
        engine.add_source_register(&ssa, off);
    }
    engine.propagate(&ssa);
    let sinks = engine.find_sinks(&ssa);

    Ok(TaintReport {
        tainted_values: engine.tainted_count(),
        sinks,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_decompile_result(
    instructions: Vec<LiftedInstruction>,
    func_name: &str,
    entry: u64,
    symbols: &std::collections::BTreeMap<u64, String>,
    string_literals: &std::collections::BTreeMap<u64, String>,
    annotations: Option<&std::collections::BTreeMap<u64, Vec<String>>>,
    call_renderings: Option<&std::collections::BTreeMap<u64, String>>,
    call_params: rustc_hash::FxHashMap<u64, ParamInfo>,
    own_params: Option<(ParamInfo, Vec<reargo_core::pcode::VarnodeData>)>,
    vcalls: Option<ThisVcalls<'_>>,
    caller_hint: Option<(&dyn PcodeLift, &Memory)>,
    handlers: &[crate::exception::Handler],
    switches: &[crate::switch::JumpTable],
) -> Result<DecompileResult, String> {
    if instructions.is_empty() {
        return Err(format!("no instructions at 0x{:x}", entry));
    }

    // Collect summary metrics *before* moving `instructions` into the
    // CFG, since `build_owned` consumes them.
    let total_pcode: usize = instructions.iter().map(|i| i.ops.len()).sum();
    let instructions_lifted = instructions.len();
    let mut cfg = ControlFlowGraph::build_owned(instructions);
    cfg.attach_switches(switches);
    let block_count = cfg.block_count();

    let mut ssa = SsaFunction::from_cfg(func_name.to_string(), entry, cfg);
    ssa.call_params = call_params;
    if let Some(v) = &vcalls {
        crate::vcall::resolve_this_vcalls(&mut ssa, v.memory, &v.vtables, &v.this_reg, v.oracle);
    }
    // `apply_call_convention` ran: calls carry the convention's argument registers.
    ssa.implicit_call_args = ssa
        .ops
        .iter()
        .any(|o| o.opcode == reargo_core::pcode::OpCode::Indirect)
        && ssa
            .ops
            .iter()
            .any(|o| matches!(o.opcode, reargo_core::pcode::OpCode::Call | reargo_core::pcode::OpCode::CallInd) && o.inputs.len() > 1);

    let mut hint = || caller_hint.and_then(|(lifter, memory)| crate::callers::return_hint(lifter, memory, entry));
    ssa.return_float = choose_return_register(&mut ssa, &mut hint);
    settle_unknown_returns(&mut ssa);
    let mut opt_stats = run_optimization_passes(&mut ssa);
    // WS82: flags read away from their `cmp` (`cmp; je; jl`) become the comparison
    // WS83: `cmovcc`'s branch-free mask becomes `dst = c ? src : dst` (after the flags: `c`
    // may be a flag combination they rewrote into a comparison)
    let flags = crate::flags::recover_flag_compares(&mut ssa);
    if crate::select::recover_selects(&mut ssa) + flags > 0 {
        opt_stats.dead_ops_removed += crate::optimize::dead_code_elimination(&mut ssa);
    }
    let live_ops = ssa.live_op_count();
    if let Some((info, args)) = own_params {
        ssa.signature_params = Some(signature_params(&ssa, info, &args));
    }

    // Render the SSA dump AFTER optimization. The previous call site
    // sat between `from_cfg` and `run_optimization_passes`, so it
    // serialized every still-live op in the raw pre-opt IR -- a
    // ~1000-op function dumped here cost ~270 us on a typical x86
    // body, ~20% of the whole `decompile_function`. After
    // `run_optimization_passes` most ops are flagged dead and skipped
    // by `display_ssa`'s `if op.dead { continue }` guard, so the same
    // function dumps in ~2 us.
    //
    // The dump's purpose is to show the SSA used by the C/Rust
    // emitter (which also runs against the optimized form), so the
    // post-opt view is also the more useful debug output.
    let ssa_dump = ssa.display_ssa();

    // Run type inference / structurer / emitters sequentially.
    //
    // An earlier revision wrapped this block in nested rayon::join,
    // but the stages are tiny (typeinfer ~2 us, structure_cfg ~30 ns,
    // each emitter ~20 us on a typical body) and the join's fork/park
    // cost ended up outweighing the parallel saving -- end-to-end
    // decompile got *slower*, not faster, by roughly 300 us per call.
    // Keep them sequential.
    let mut type_engine = crate::typeinfer::TypeInferenceEngine::new();
    type_engine.infer(&ssa);
    type_engine.recover_aggregates(&ssa);
    let recovered_structs: Vec<String> = type_engine
        .structs()
        .values()
        .enumerate()
        .map(|(i, s)| s.to_c_definition(&format!("recovered_{}", i)))
        .collect();

    // `if (a) goto X; if (b) goto X;` -> `if (a || b) goto X;` (on a copy of the CFG)
    let short = crate::condition::merge_short_circuits(&ssa);
    let cfg = short.as_ref().map_or(&ssa.cfg, |s| &s.cfg);
    let handler_blocks: Vec<(usize, String)> =
        handlers.iter().filter_map(|(a, note)| Some((cfg.block_at(*a).filter(|b| b.start_addr == *a)?.id, note.clone()))).collect();
    let structured = structure_cfg_with_handlers(cfg, &handler_blocks);
    // Both emitters borrow the same two maps -- the previous API took
    // owned BTreeMaps and forced four clones per decompile call (two
    // maps * two emitters). The borrow-based `with_maps` API is
    // zero-clone.
    let mut c_emitter = CEmitter::with_maps(symbols, string_literals);
    if let Some(ann) = annotations {
        c_emitter = c_emitter.with_annotations(ann);
    }
    if let Some(rend) = call_renderings {
        c_emitter = c_emitter.with_call_renderings(rend);
    }
    if let Some(s) = &short {
        c_emitter = c_emitter.with_conditions(&s.conds);
    }
    let c_code = c_emitter.emit_function(&ssa, &structured);

    let mut rust_emitter = RustEmitter::with_maps(symbols, string_literals);
    if let Some(ann) = annotations {
        rust_emitter = rust_emitter.with_annotations(ann);
    }
    if let Some(rend) = call_renderings {
        rust_emitter = rust_emitter.with_call_renderings(rend);
    }
    if let Some(s) = &short {
        rust_emitter = rust_emitter.with_conditions(&s.conds);
    }
    let rust_code = rust_emitter.emit_function(&ssa, &structured);

    Ok(DecompileResult {
        c_code,
        rust_code,
        ssa_dump,
        recovered_structs,
        stats: DecompileStats {
            instructions_lifted,
            pcode_ops: total_pcode,
            basic_blocks: block_count,
            optimization: opt_stats,
            live_ops_after: live_ops,
        },
    })
}

fn trim_to_function_body(
    instructions: Vec<LiftedInstruction>,
    entry: u64,
    func: Option<&reargo_program::Function>,
) -> Vec<LiftedInstruction> {
    let Some(f) = func else {
        return trim_to_return(instructions);
    };
    let body_addrs = &f.body;

    // The previous trim only kept instructions present in the
    // pre-existing discovered body (`f.body`). On stripped binaries
    // discovery often stops at the first Call -- it only walked the
    // entry block, so `body` contained ~5-20 addresses and the
    // decompiler would print ~20 instructions and quit, ignoring the
    // entire post-call function body that the lifter had already
    // produced.
    //
    // Fix: union the body set with reachability over the lifted
    // instructions. Anything discovery found stays in (so we don't
    // accidentally drop unreachable-but-recorded slots like
    // exception-handler landing pads); anything statically reachable
    // from `entry` along Branch / CBranch / fall-through edges also
    // stays in, even if discovery missed it. The DFS is the same
    // one used by `trim_to_return`, so the two trims now agree on
    // what "reachable" means.
    let reach = reachability(&instructions);
    // Pre-compute body membership; the AddressSet's `contains`
    // walks an interval tree per call, so caching the bool per
    // instruction keeps the inner loop hot.
    let in_body: Vec<bool> = instructions
        .iter()
        .map(|insn| {
            body_addrs.contains(&reargo_core::address::Address::new(
                reargo_core::address::SpaceId::RAM,
                insn.address,
            )) || insn.address == entry
        })
        .collect();
    let keep: Vec<bool> = in_body
        .iter()
        .zip(reach.iter().copied().chain(std::iter::repeat(false)))
        .map(|(&b, r)| b || r)
        .collect();
    // Sanity: at least the entry must be kept. If neither body nor
    // reachability matched anything (e.g. the lifted Vec covers a
    // completely different region than expected), fall back to the
    // pure reachability trim so we at least return *something*.
    if keep.iter().all(|&k| !k) {
        return trim_to_return(instructions);
    }
    instructions
        .into_iter()
        .zip(keep)
        .filter_map(|(insn, k)| k.then_some(insn))
        .collect()
}

/// Trim the lifted-instruction stream to just the part reachable from
/// the entry instruction along statically-known control flow.
///
/// The previous implementation cut at the *first* Return op encountered
/// in address order. That dropped every function with an early return:
/// in the canonical `if cond return; ... return;` shape, the branch
/// target lives at a higher address than the early `ret`, so cutting
/// at the early ret discarded the JE-reached half of the function and
/// the decompiler emitted only one of the two return paths.
///
/// CFG reachability is the right boundary: an instruction is in the
/// function if it's reachable from entry along Branch / CBranch /
/// fall-through edges. Instructions the lifter included but that no
/// in-range edge reaches (padding, the next function's prelude) are
/// dropped.
///
/// An earlier version of this function called `ControlFlowGraph::build`
/// just for the reachability traversal and then threw the CFG away,
/// only for `build_decompile_result` to rebuild the same CFG seconds
/// later. That doubled the CFG construction cost on every decompile
/// call (the build clones every LiftedInstruction into its block).
///
/// Walk reachability directly over the instruction array instead:
/// build a flat `addr -> idx` map, DFS through it following each
/// instruction's Branch / CBranch / fall-through targets, and filter.
/// No CFG, no per-instruction clones for the traversal itself; the
/// only clones we still pay are the `cloned()` in the final filter
/// (the caller needs an owned Vec).
pub(crate) fn trim_to_return(instructions: Vec<LiftedInstruction>) -> Vec<LiftedInstruction> {
    let visited = reachability(&instructions);
    if visited.is_empty() {
        return instructions;
    }
    // Move the reachable instructions out of the input Vec by index.
    // The borrow form of this function used `.cloned()` to materialise
    // an owned Vec, paying a String + Vec<PcodeOp> clone per kept
    // instruction. By consuming `instructions` and filtering with
    // `into_iter().zip(...)` we move each kept LiftedInstruction
    // straight into the result -- zero clones.
    instructions
        .into_iter()
        .zip(visited)
        .filter_map(|(insn, keep)| keep.then_some(insn))
        .collect()
}

fn reachability(instructions: &[LiftedInstruction]) -> Vec<bool> {
    use rustc_hash::FxHashMap;
    use reargo_core::pcode::OpCode;

    if instructions.is_empty() {
        return Vec::new();
    }

    let n = instructions.len();
    let addr_to_idx: FxHashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(idx, insn)| (insn.address, idx))
        .collect();

    let mut visited = vec![false; n];
    let mut stack = vec![0usize];

    while let Some(idx) = stack.pop() {
        if visited[idx] {
            continue;
        }
        visited[idx] = true;
        let insn = &instructions[idx];

        let mut has_unconditional_transfer = false;
        let mut has_return_or_indjmp = false;
        for op in &insn.ops {
            match op.opcode {
                OpCode::Branch => {
                    has_unconditional_transfer = true;
                    if let Some(tgt) = op.inputs.first()
                        && tgt.space == reargo_core::address::SpaceId::RAM
                        && let Some(&t_idx) = addr_to_idx.get(&tgt.offset)
                    {
                        stack.push(t_idx);
                    }
                }
                OpCode::CBranch => {
                    if let Some(tgt) = op.inputs.first()
                        && tgt.space == reargo_core::address::SpaceId::RAM
                        && let Some(&t_idx) = addr_to_idx.get(&tgt.offset)
                    {
                        stack.push(t_idx);
                    }
                }
                OpCode::Return | OpCode::BranchInd => {
                    has_return_or_indjmp = true;
                    // a recovered jump table's cases (WS83, `switch`)
                    for t in op.inputs.iter().skip(1).filter(|t| op.opcode == OpCode::BranchInd && t.space == reargo_core::address::SpaceId::RAM) {
                        if let Some(&t_idx) = addr_to_idx.get(&t.offset) {
                            stack.push(t_idx);
                        }
                    }
                }
                _ => {}
            }
        }

        if !has_return_or_indjmp && !has_unconditional_transfer && !crate::cfg::is_trap(insn) {
            let fall = insn.address + insn.length as u64;
            if let Some(&f_idx) = addr_to_idx.get(&fall) {
                stack.push(f_idx);
            }
        }
    }

    visited
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::{Endian, SpaceId};
    use reargo_lift::x86::X86Lifter;
    use reargo_loader::memory::{Memory, MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn make_memory(data: &[u8], addr: u64) -> Memory {
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: addr,
            size: data.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(data)),
        });
        mem
    }

    /// WS75: a call shows the arguments set up for it and its result is the
    /// call's return value, not the register's value from before the call.
    #[test]
    fn decompile_call_carries_args_and_return() {
        let lifter = X86Lifter::new_64();
        // 0x1000 mov edi, 5 ; 0x1005 call 0x2000 ; 0x100a mov [rip+0x1ff0], eax (= [0x3000]) ; ret
        let code = [
            0xbf, 0x05, 0x00, 0x00, 0x00, // mov edi, 5
            0xe8, 0xf6, 0x0f, 0x00, 0x00, // call 0x2000
            0x89, 0x05, 0xf0, 0x1f, 0x00, 0x00, // mov [0x3000], eax
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let r = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap();
        let c = &r.c_code;
        // the argument survives (it used to be dead code) and is the only one shown; WS83: a
        // constant is printed in the call, its register's assignment is dropped
        let call_line = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call_line.contains("0x2000(5)"), "{call_line}");
        assert!(!c.contains("edi = 5"), "{c}");
        // the store reads the call's result (WS79: printed as the call's assignment)
        assert!(call_line.trim_start().starts_with("rax = "), "{c}");
        assert!(!c.contains("__ret"), "{c}");
    }

    /// WS79: an unknown callee whose `xmm0` is only carried over by a later scalar write
    /// (the lifter's upper-lane sync) returns in `rax`, the register the caller reads.
    #[test]
    fn indirect_call_result_is_the_register_really_read() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xff, 0x17, // 0x1000 call [rdi]
            0xf3, 0x0f, 0x2a, 0xc0, // 0x1002 cvtsi2ss xmm0, eax (keeps xmm0's upper lanes)
            0xff, 0x15, 0x04, 0x20, 0x00, 0x00, // 0x1006 call [0x3010] (xmm0 is its argument)
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call_line = c.lines().find(|l| l.contains("(*tmp_500)")).unwrap_or_else(|| panic!("{c}"));
        assert!(call_line.trim_start().starts_with("rax = "), "{c}");
    }

    /// WS79: a call to a function that returns a float assigns `xmm0`; `rax` is only
    /// clobbered by it.
    #[test]
    fn call_to_float_function_assigns_xmm0() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xe8, 0x0b, 0x00, 0x00, 0x00, // 0x1000 call 0x1010
            0xf3, 0x0f, 0x11, 0x05, 0xf3, 0x1f, 0x00, 0x00, // 0x1005 movss [0x3000], xmm0
            0xc3, // 0x100d ret
            0x90, 0x90, // pad
            0xf3, 0x0f, 0x2a, 0xc7, // 0x1010 cvtsi2ss xmm0, edi
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call_line = c.lines().find(|l| l.contains("0x1010(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call_line.trim_start().starts_with("xmm0 = "), "{c}");
        assert!(!c.contains("rax = __ret"), "{c}");
    }

    /// WS76: a caller-saved register read after a call is the call's clobber, not the value it
    /// held before the call.
    #[test]
    fn call_clobbers_caller_saved_registers() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xb9, 0x07, 0x00, 0x00, 0x00, // mov ecx, 7
            0xe8, 0xf6, 0x0f, 0x00, 0x00, // call 0x2000
            0x89, 0x0d, 0xf0, 0x1f, 0x00, 0x00, // mov [0x3000], ecx
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(c.contains("__clobbered"), "{c}");
        assert!(!c.contains("0x3000 = 7"), "the pre-call constant must not reach the store: {c}");
        let store = c.find("*(uint32_t*)0x3000").unwrap_or_else(|| panic!("{c}"));
        assert!(c[..store].contains("rcx = __clobbered"), "{c}");
    }

    /// WS76: an argument set up in a block that dominates the call is the call's argument,
    /// even though a branch separates the two.
    #[test]
    fn call_args_cross_blocks_from_a_dominator() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xbf, 0x05, 0x00, 0x00, 0x00, // mov edi, 5
            0x85, 0xc0, // test eax, eax
            0x74, 0x01, // je 0x100a
            0x90, // nop
            0xe8, 0xf1, 0x0f, 0x00, 0x00, // 0x100a: call 0x2000
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call_line = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call_line.contains("0x2000(5)"), "{call_line}\n{c}");
    }

    /// WS76: an argument register left over from before an earlier call is not an argument.
    #[test]
    fn stale_argument_after_a_call_is_dropped() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xbf, 0x05, 0x00, 0x00, 0x00, // mov edi, 5
            0xe8, 0xf6, 0x0f, 0x00, 0x00, // call 0x2000
            0xe8, 0xf1, 0x10, 0x00, 0x00, // call 0x2100
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let first = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        let second = c.lines().find(|l| l.contains("0x2100(")).unwrap_or_else(|| panic!("{c}"));
        assert!(first.contains("0x2000(5)"), "{first}");
        assert!(!second.contains("rdi") && !second.contains("(5"), "{second}\n{c}");
    }

    /// Code blobs at their addresses inside one `0xcc`-filled block.
    /// WS79: `lea rax, [vtbl]; call [rax+8]` calls the function in the vtable's slot: a
    /// direct call with that callee's parameters and return register.
    #[test]
    fn call_through_constant_vtable_becomes_direct() {
        let lifter = X86Lifter::new_64();
        let code: &[u8] = &[
            0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, // 0x1000 lea rax, [0x2000]
            0xbf, 0x07, 0x00, 0x00, 0x00, // 0x1007 mov edi, 7
            0xff, 0x50, 0x08, // 0x100c call [rax+8]
            0xf3, 0x0f, 0x11, 0x05, 0xe9, 0x1f, 0x00, 0x00, // 0x100f movss [0x3000], xmm0
            0xc3, // 0x1017
        ];
        let callee: &[u8] = &[0xf3, 0x0f, 0x2a, 0xc7, 0xc3]; // cvtsi2ss xmm0, edi ; ret
        let vtbl: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x11, 0, 0, 0, 0, 0, 0];
        let mem = make_memory_parts(&[(0x1000, code), (0x1100, callee), (0x2000, vtbl)]);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call_line = c.lines().find(|l| l.contains("0x1100(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call_line.trim_start().starts_with("xmm0 = 0x1100(7)"), "{c}");
    }

    fn make_memory_parts(parts: &[(u64, &[u8])]) -> Memory {
        let base = parts.iter().map(|p| p.0).min().unwrap();
        let end = parts.iter().map(|p| p.0 + p.1.len() as u64).max().unwrap();
        let mut data = vec![0xccu8; (end - base) as usize + 16];
        for (a, bytes) in parts {
            let o = (a - base) as usize;
            data[o..o + bytes.len()].copy_from_slice(bytes);
        }
        make_memory(&data, base)
    }

    /// WS78: an argument passed straight through from the function's own incoming register
    /// (`rdi` here) is an argument when the callee reads it.
    #[test]
    fn pass_through_argument_is_kept() {
        let lifter = X86Lifter::new_64();
        let f = [
            0xbe, 0x05, 0x00, 0x00, 0x00, // mov esi, 5
            0xe8, 0xf6, 0x0f, 0x00, 0x00, // call 0x2000
            0xc3,
        ];
        let g = [0x89, 0xf8, 0x01, 0xf0, 0xc3]; // mov eax, edi ; add eax, esi ; ret
        let mem = make_memory_parts(&[(0x1000, &f), (0x2000, &g)]);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("(rdi, 5)") || call.contains("(param_1, 5)"), "{call}
{c}");
    }

    /// WS78: a register left over from other work is not an argument when the callee does not
    /// read it.
    #[test]
    fn leftover_register_the_callee_ignores_is_dropped() {
        let lifter = X86Lifter::new_64();
        let f = [
            0xb9, 0x09, 0x00, 0x00, 0x00, // mov ecx, 9
            0xbf, 0x05, 0x00, 0x00, 0x00, // mov edi, 5
            0xe8, 0xf1, 0x0f, 0x00, 0x00, // call 0x2000
            0xc3,
        ];
        let g = [0x89, 0xf8, 0xc3]; // mov eax, edi ; ret
        let mem = make_memory_parts(&[(0x1000, &f), (0x2000, &g)]);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("0x2000(5)"), "{call}
{c}");
    }

    fn call_line(c: &str, needle: &str) -> String {
        c.lines().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("{c}")).trim().to_string()
    }

    /// WS78: a virtual call on the function's own `this` (`rdi`, never redefined) passes it.
    #[test]
    fn vcall_on_incoming_this_passes_it() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x48, 0x8b, 0x07, // mov rax, [rdi]
            0xff, 0x50, 0x10, // call [rax+0x10]
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call = call_line(&c, "vfn[2]");
        assert!(call.contains(")(rdi);"), "{call}\n{c}");
    }

    /// WS78: with an unknown callee, a set-up `rsi` means `rdi` is an argument too (System V
    /// fills the integer registers in order) — here passed through unchanged.
    #[test]
    fn unknown_callee_takes_the_register_prefix() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xbe, 0x05, 0x00, 0x00, 0x00, // mov esi, 5
            0xff, 0xd0, // call rax
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call = call_line(&c, "(*rax)(");
        assert!(call.contains("(rdi, 5)"), "{call}\n{c}");
    }

    /// WS78: with an unknown callee, a register computed in an earlier block and used by other
    /// code is a leftover, not an argument.
    #[test]
    fn unknown_callee_drops_a_leftover_from_an_earlier_block() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xb9, 0x09, 0x00, 0x00, 0x00, // 0x1000 mov ecx, 9
            0x89, 0x0d, 0xf5, 0x1f, 0x00, 0x00, // 0x1005 mov [0x3000], ecx
            0x85, 0xc0, // 0x100b test eax, eax
            0x74, 0x01, // 0x100d je 0x1010
            0x90, // 0x100f nop
            0xbf, 0x05, 0x00, 0x00, 0x00, // 0x1010 mov edi, 5
            0xff, 0xd0, // 0x1015 call rax
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call = call_line(&c, "(*rax)(");
        assert!(call.contains("(5);"), "{call}\n{c}");
    }

    /// WS78: the 8/16-bit views of rbp/rsi/... have register names, not `var_<off>` (which
    /// declared `bp` and `bpl` as two variables both called `var_28`).
    #[test]
    fn low_byte_registers_are_named() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x40, 0x88, 0xfe, // mov sil, dil (WS83: not a constant, which the store would take)
            0x40, 0x88, 0x35, 0xf7, 0x1f, 0x00, 0x00, // mov [0x3000], sil
            0x66, 0x89, 0x2d, 0xf0, 0x1f, 0x00, 0x00, // mov [0x3001], bp
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let r = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap();
        for c in [&r.c_code, &r.rust_code] {
            assert!(!c.contains("var_30") && !c.contains("var_28"), "{c}");
            assert!(c.contains("sil") && c.contains("bp"), "{c}");
        }
    }

    /// WS78: locals are declared only for registers the body assigns, and a 16-byte value
    /// has a type (`void xmm1;` / `*(void*)p` were invalid C).
    #[test]
    fn declarations_are_live_and_typed() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x0f, 0x28, 0x0f, // movaps xmm1, [rdi]
            0x0f, 0x29, 0x0e, // movaps [rsi], xmm1
            0xe8, 0xf5, 0x0f, 0x00, 0x00, // call 0x2000
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let r = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap();
        let c = &r.c_code;
        assert!(!c.contains("void xmm") && !c.contains("(void*)"), "{c}");
        assert!(c.contains("uint128_t xmm1;"), "{c}");
        // the call's clobbers nobody reads are not declared
        assert!(!c.contains("xmm15") && !c.contains("r11"), "{c}");
        let rs = &r.rust_code;
        assert!(rs.contains("xmm1: u128") && !rs.contains("xmm15"), "{rs}");
    }

    /// WS78: the signature lists the System V registers the function reads on entry, named
    /// like the body names them (it used Windows-x64 offsets and only 8-byte reads, so
    /// `mov eax, edi; add eax, esi` came out as `f(void)`).
    #[test]
    fn signature_lists_the_registers_read_on_entry() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x89, 0xf8, // mov eax, edi
            0x01, 0xf0, // add eax, esi
            0xf3, 0x0f, 0x11, 0x05, 0xf4, 0x1f, 0x00, 0x00, // movss [0x3000], xmm0
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let r = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap();
        assert!(r.c_code.contains("uint64_t f(uint64_t rdi, uint64_t rsi, uint128_t xmm0)"), "{}", r.c_code);
        assert!(r.rust_code.contains("fn f(rdi: u64, rsi: u64, xmm0: u128) -> u64"), "{}", r.rust_code);
    }

    /// WS79: an unused leading parameter keeps its slot (`f(rdi, rsi)` when only `rsi` and
    /// `xmm1` are read: `xmm0` too).
    #[test]
    fn signature_keeps_the_unused_leading_parameters() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x89, 0xf0, // mov eax, esi
            0xf3, 0x0f, 0x11, 0x0d, 0xf6, 0x1f, 0x00, 0x00, // movss [0x3000], xmm1
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let r = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap();
        assert!(
            r.c_code.contains("uint64_t f(uint64_t rdi, uint64_t rsi, uint128_t xmm0, uint128_t xmm1)"),
            "{}",
            r.c_code
        );
        assert!(!r.c_code.contains("rdx"), "{}", r.c_code);
    }

    /// WS78: a parameter the body also assigns is not declared again as a local.
    #[test]
    fn parameter_is_not_redeclared() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x48, 0x89, 0x3d, 0xf9, 0x1f, 0x00, 0x00, // mov [0x3000], rdi
            0xbf, 0x05, 0x00, 0x00, 0x00, // mov edi, 5
            0xff, 0xd0, // call rax
            0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(c.contains("f(uint64_t rdi)"), "{c}");
        assert!(!c.contains("    uint64_t rdi;"), "{c}");
    }

    /// WS78: `jmp [rax+0x18]` (a tail call through a vtable) is a jump on the loaded slot,
    /// not a silent `goto 0x0`.
    #[test]
    fn indirect_jmp_is_rendered() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x48, 0x8b, 0x07, // mov rax, [rdi]
            0xff, 0x60, 0x18, // jmp [rax+0x18]
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        // WS82: printed as the tail call it is, `rax = (*tmp)(rdi); // vfn[3]; return rax;`
        let j = c.lines().find(|l| l.contains("(*")).unwrap_or_else(|| panic!("{c}"));
        assert!(j.contains("vfn[3]"), "{j}
{c}");
        assert!(!c.contains("BRANCHIND") && !c.contains("goto"), "{c}");
    }

    /// WS77: a `ret` returns what `rax` holds, not the popped return address.
    #[test]
    fn ret_returns_rax_not_the_return_address() {
        let lifter = X86Lifter::new_64();
        let code = [0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3]; // mov eax, 7 ; ret
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(c.contains("uint64_t f("), "{c}");
        let ret = c.lines().find(|l| l.trim_start().starts_with("return")).unwrap_or_else(|| panic!("{c}"));
        assert!(ret.contains("rax") || ret.contains('7'), "{ret}
{c}");
        assert!(!ret.contains("tmp_"), "the return address is not the value: {ret}
{c}");
    }

    fn c_of(code: &[u8]) -> String {
        let lifter = X86Lifter::new_64();
        let mem = make_memory(code, 0x1000);
        decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code
    }

    /// WS79: a scalar float computed into `xmm0` last is the return value.
    #[test]
    fn float_return_in_xmm0() {
        // mov eax, 5 (scratch) ; cvtsi2ss xmm0, edi ; addss xmm0, xmm0 ; ret
        let c = c_of(&[0xb8, 0x05, 0, 0, 0, 0xf3, 0x0f, 0x2a, 0xc7, 0xf3, 0x0f, 0x58, 0xc0, 0xc3]);
        assert!(c.contains("float f("), "{c}");
        let ret = c.lines().find(|l| l.trim_start().starts_with("return")).unwrap();
        assert!(ret.contains("xmm0_d"), "{ret}
{c}");
        assert!(!c.contains("rax ="), "the scratch rax write is dead: {c}");
    }

    #[test]
    fn double_return_in_xmm0() {
        // cvtsi2sd xmm0, edi ; mulsd xmm0, xmm0 ; ret
        let c = c_of(&[0xf2, 0x0f, 0x2a, 0xc7, 0xf2, 0x0f, 0x59, 0xc0, 0xc3]);
        assert!(c.contains("double f("), "{c}");
        assert!(c.contains("return xmm0_q;"), "{c}");
    }

    /// `call g; ret` with `g` returning a float returns that float.
    #[test]
    fn tail_call_result_of_float_function_is_float_return() {
        let c = c_of(&[
            0xe8, 0x0b, 0x00, 0x00, 0x00, // 0x1000 call 0x1010
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // pad to 0x1010
            0xf3, 0x0f, 0x2a, 0xc7, // 0x1010 cvtsi2ss xmm0, edi
            0xc3,
        ]);
        assert!(c.contains("double f(") || c.contains("float f("), "{c}");
        assert!(c.contains("return xmm0"), "{c}");
    }

    /// An integer written after the last float write is the return value.
    #[test]
    fn int_written_after_float_returns_int() {
        // cvtsi2ss xmm0, edi ; mov eax, 1 ; ret
        let c = c_of(&[0xf3, 0x0f, 0x2a, 0xc7, 0xb8, 0x01, 0, 0, 0, 0xc3]);
        assert!(c.contains("uint64_t f("), "{c}");
    }

    /// Zeroing memory through `xmm0` (`xorps` + `movups`) does not make a float return.
    #[test]
    fn xmm0_zeroing_is_not_a_float_return() {
        // xorps xmm0, xmm0 ; movups [rdi], xmm0 ; ret
        let c = c_of(&[0x0f, 0x57, 0xc0, 0x0f, 0x11, 0x07, 0xc3]);
        assert!(c.contains("void f("), "{c}");
    }

    /// WS79: control does not fall through the `int3` padding after a `noreturn` call into
    /// the code behind it (often the next function).
    #[test]
    fn int3_after_noreturn_call_ends_the_flow() {
        let c = c_of(&[
            0x85, 0xff, // 0x1000 test edi, edi
            0x74, 0x0d, // je 0x1011
            0xe8, 0xf7, 0x0f, 0x00, 0x00, // 0x1004 call 0x2000 (noreturn)
            0xcc, // 0x1009 int3
            0xb8, 0x2a, 0x00, 0x00, 0x00, // 0x100a mov eax, 0x2a (another function)
            0xc3, // 0x100f
            0xcc, // 0x1010
            0x31, 0xc0, // 0x1011 xor eax, eax
            0xc3,
        ]);
        assert!(!c.contains("0x2a"), "{c}");
        assert!(c.contains("__builtin_trap();"), "{c}");
    }

    /// WS81: a call to a function that never returns (here: it only traps) ends the flow —
    /// the code behind it is not its continuation.
    #[test]
    fn call_to_noreturn_function_ends_the_flow() {
        let lifter = X86Lifter::new_64();
        let mem = make_memory_parts(&[
            (0x1000, &[
                0x85, 0xff, // 0x1000 test edi, edi
                0x74, 0x0b, // 0x1002 je 0x100f
                0xe8, 0xf7, 0x0f, 0x00, 0x00, // 0x1004 call 0x2000 (never returns)
                0xb8, 0x2a, 0x00, 0x00, 0x00, // 0x1009 mov eax, 0x2a (not reached)
                0xc3, // 0x100e
                0x31, 0xc0, // 0x100f xor eax, eax
                0xc3,
            ]),
            (0x2000, &[0x0f, 0x0b]), // ud2
        ]);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("0x2a"), "{c}");
        assert!(c.contains("0x2000("), "{c}");
        assert!(!c.contains("goto"), "{c}");
    }

    /// WS81: the temporaries that only compute an `if` condition fold into it.
    #[test]
    fn condition_temporaries_fold_into_the_if() {
        let c = c_of(&[
            0x83, 0xff, 0x06, // 0x1000 cmp edi, 6
            0x72, 0x06, // 0x1003 jb 0x100b
            0xb8, 0x01, 0x00, 0x00, 0x00, // 0x1005 mov eax, 1
            0xc3, // 0x100a
            0x31, 0xc0, // 0x100b xor eax, eax
            0xc3,
        ]);
        let cond = c.lines().find(|l| l.trim_start().starts_with("if (")).unwrap_or_else(|| panic!("{c}"));
        assert!(cond.contains("edi") && cond.contains('6'), "{c}");
        assert!(!c.contains("var_") && !c.contains("tmp_"), "{c}");
    }

    /// `test r, r` reads as `r`, not `r & r`.
    #[test]
    fn test_of_a_register_with_itself_is_the_register() {
        let c = c_of(&[
            0x85, 0xff, // 0x1000 test edi, edi
            0x74, 0x06, // 0x1002 je 0x100a
            0xb8, 0x01, 0x00, 0x00, 0x00, // 0x1004 mov eax, 1
            0xc3, // 0x1009
            0x31, 0xc0, // 0x100a xor eax, eax
            0xc3,
        ]);
        assert!(!c.contains("edi & edi"), "{c}");
        assert!(c.contains("edi == 0") || c.contains("edi != 0"), "{c}");
    }

    /// Readers are counted by value: one op reading a value twice (`test r, r`) is one reader,
    /// and a value common subexpression elimination merged has readers under two names, so it
    /// is not folded away while the other name still reads it.
    #[test]
    fn readers_are_counted_by_value() {
        let c = c_of(&[
            0x8d, 0x4f, 0x01, // 0x1000 lea ecx, [rdi + 1]
            0x8d, 0x57, 0x01, // 0x1003 lea edx, [rdi + 1]   (the same sum: merged)
            0x01, 0xd1, // 0x1006 add ecx, edx
            0x85, 0xc9, // 0x1008 test ecx, ecx
            0x74, 0x06, // 0x100a je 0x1012
            0xb8, 0x01, 0x00, 0x00, 0x00, // 0x100c mov eax, 1
            0xc3, // 0x1011
            0x31, 0xc0, // 0x1012 xor eax, eax
            0xc3,
        ]);
        let cond = c.lines().find(|l| l.trim_start().starts_with("if (")).unwrap_or_else(|| panic!("{c}"));
        assert!(cond.contains('+'), "the sum folds into the test: {c}");
        for name in ["tmp_600", "ecx", "edx"] {
            if cond.contains(name) {
                assert!(c.contains(&format!("{name} = ")), "{name} is read but never set:
{c}");
            }
        }
    }

    /// WS81: the flags a conditional jump tests read as the comparison of `cmp`'s operands.
    #[test]
    fn flags_of_cmp_read_as_the_comparison() {
        let cond_of = |jcc: u8| {
            // cmp edi, 5 ; jcc +6 ; mov eax, 1 ; ret ; xor eax, eax ; ret
            let c = c_of(&[0x83, 0xff, 0x05, jcc, 0x06, 0xb8, 0x01, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3]);
            let l = c.lines().find(|l| l.trim_start().starts_with("if (")).unwrap_or_else(|| panic!("{c}")).trim().to_string();
            assert!(!c.contains("var_") && !c.contains("tmp_"), "{c}");
            l
        };
        // the `if` holds the fall-through arm or the jump's arm, so accept either sense
        let either = |l: &str, a: &str, b: &str| l.contains(a) || l.contains(b);
        assert!(either(&cond_of(0x76), "edi <= 5", "edi > 5"), "jbe: {}", cond_of(0x76));
        assert!(either(&cond_of(0x77), "edi > 5", "edi <= 5"), "ja: {}", cond_of(0x77));
        assert!(either(&cond_of(0x7c), "(int32_t)edi < (int32_t)5", "(int32_t)edi >= (int32_t)5"), "jl: {}", cond_of(0x7c));
        assert!(either(&cond_of(0x7e), "(int32_t)edi <= (int32_t)5", "(int32_t)edi > (int32_t)5"), "jle: {}", cond_of(0x7e));
        assert!(either(&cond_of(0x7f), "(int32_t)edi > (int32_t)5", "(int32_t)edi <= (int32_t)5"), "jg: {}", cond_of(0x7f));
    }

    /// WS81: a `jmp` to another function is a tail call: `return f(…);` with its argument.
    #[test]
    fn tail_jump_is_a_call_and_return() {
        let lifter = X86Lifter::new_64();
        let mem = make_memory_parts(&[
            (0x1000, &[
                0x53, // 0x1000 push rbx
                0xbf, 0x05, 0x00, 0x00, 0x00, // 0x1001 mov edi, 5
                0x5b, // 0x1006 pop rbx
                0xe9, 0xf4, 0x0f, 0x00, 0x00, // 0x1007 jmp 0x2000
            ]),
            (0x2000, &[0x8d, 0x47, 0x01, 0xc3]), // lea eax, [rdi + 1] ; ret
        ]);
        let c = decompile(&lifter, &mem, 0x1000, "f", 4).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("rdi") || call.contains('5'), "{c}");
        assert!(c.contains("return"), "{c}");
        assert!(!c.contains("rbx = "), "the epilogue before the jump is not printed: {c}");
    }

    /// WS81: a negated integer comparison in a merged condition flips its operator.
    #[test]
    fn negated_comparison_flips_its_operator() {
        let c = c_of(&[
            0x83, 0xff, 0x01, // 0x1000 cmp edi, 1
            0x74, 0x0b, // 0x1003 je 0x1010
            0x83, 0xfe, 0x05, // 0x1005 cmp esi, 5
            0x7e, 0x06, // 0x1008 jle 0x1010
            0xb8, 0x03, 0x00, 0x00, 0x00, // 0x100a mov eax, 3
            0xc3, // 0x100f
            0xb8, 0x07, 0x00, 0x00, 0x00, // 0x1010 mov eax, 7
            0xc3,
        ]);
        let cond = c.lines().find(|l| l.trim_start().starts_with("if (")).unwrap_or_else(|| panic!("{c}"));
        assert!(cond.contains("(int32_t)esi > (int32_t)5") || cond.contains("(int32_t)esi <= (int32_t)5"), "{c}");
        assert!(!cond.contains("!("), "{c}");
    }

    /// WS77: a function that never sets `rax` returns nothing.
    #[test]
    fn ret_without_rax_write_is_void() {
        let lifter = X86Lifter::new_64();
        let code = [0x89, 0x3d, 0xfa, 0x1f, 0x00, 0x00, 0xc3]; // mov [0x3000], edi ; ret
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(c.contains("void f("), "{c}");
        assert!(c.contains("return;"), "{c}");
    }

    /// WS79: a chain of compares jumping to one exit nests at the post-dominator (the exit)
    /// instead of jumping there: no `goto`, no empty `if` arm. WS80: the tests that hold
    /// nothing but the compare merge into one `&&` condition.
    #[test]
    fn compare_chain_to_one_exit_needs_no_goto() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x83, 0xff, 0x01, 0x74, 0x0f, // cmp edi, 1 ; je exit
            0x83, 0xff, 0x02, 0x74, 0x0a, // cmp edi, 2 ; je exit
            0x83, 0xff, 0x03, 0x74, 0x05, // cmp edi, 3 ; je exit
            0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
            0xc3, // exit: ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("goto"), "{c}");
        assert!(!c.contains("} else {"), "{c}");
        assert_eq!(c.matches("if (").count(), 1, "{c}");
        assert_eq!(c.matches(" && ").count(), 2, "{c}");
        // (WS81: the flags of `cmp` read as the comparison itself)
        assert!(c.contains("edi != 2") && c.contains("edi != 3"), "{c}");
        assert_eq!(c.matches("return").count(), 1, "{c}");
    }

    /// WS79: an arm whose only instruction is folded away (a dead register write) prints
    /// no `if (c) { }`.
    #[test]
    fn arm_without_statements_prints_no_if() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x85, 0xff, // test edi, edi
            0x74, 0x05, // je skip
            0xb9, 0x05, 0x00, 0x00, 0x00, // mov ecx, 5 (dead)
            0xb8, 0x01, 0x00, 0x00, 0x00, // skip: mov eax, 1
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let r = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap();
        assert!(!r.c_code.contains("if ("), "{}", r.c_code);
        assert!(!r.rust_code.contains("if "), "{}", r.rust_code);
    }

    /// WS77: every `goto label_X;` has its `label_X:` (an irreducible loop entered at two
    /// blocks cannot be nested).
    #[test]
    fn goto_targets_get_labels() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x83, 0xff, 0x01, // cmp edi, 1
            0x74, 0x02, // je l2
            0xff, 0xc0, // l1: inc eax
            0xff, 0xc0, // l2: inc eax
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x7c, 0xf7, // jl l1
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let gotos: Vec<&str> = c.lines().filter_map(|l| l.trim().strip_prefix("goto ")).collect();
        assert!(!gotos.is_empty(), "test needs a goto: {c}");
        for g in gotos {
            let label = format!("{}:", g.trim_end_matches(';'));
            assert!(c.lines().any(|l| l.trim() == label), "missing {label}
{c}");
        }
    }

    #[test]
    fn decompile_simple_function() {
        let lifter = X86Lifter::new_64();
        // push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let mem = make_memory(&code, 0x1000);

        let result = decompile(&lifter, &mem, 0x1000, "simple", 100).unwrap();
        // `xor eax, eax` before the `ret`: the function returns 0 (WS77; it used to print `void`)
        assert!(result.c_code.contains("uint64_t simple(void)"), "{}", result.c_code);
        assert!(result.c_code.contains("return"));
        assert!(result.stats.instructions_lifted > 0);
        assert!(result.stats.basic_blocks >= 1);
    }

    #[test]
    fn decompile_add_function() {
        let lifter = X86Lifter::new_64();
        // sub rsp, 0x28; add rsp, 0x28; ret
        let code = [0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xc4, 0x28, 0xc3];
        let mem = make_memory(&code, 0x1000);

        let result = decompile(&lifter, &mem, 0x1000, "stack_func", 100).unwrap();
        assert!(result.c_code.contains("void stack_func(void)"));
        assert!(result.stats.instructions_lifted == 3);
    }

    /// Pre-fix `trim_to_return` cut at the first Return op in address
    /// order, so functions with an early return lost every instruction
    /// after that early `ret` -- including the JE target and the second
    /// return path. Now the trim follows CFG reachability and both
    /// halves of the function are preserved.
    #[test]
    fn decompile_keeps_je_target_past_early_return() {
        let lifter = X86Lifter::new_64();
        // 0x1000: cmp eax, 0       (83 f8 00)
        // 0x1003: je +6            (74 06)  -> 0x100B
        // 0x1005: mov eax, 1       (b8 01 00 00 00)
        // 0x100A: ret              (c3)
        // 0x100B: mov eax, 2       (b8 02 00 00 00)
        // 0x1010: ret              (c3)
        let code = [
            0x83, 0xf8, 0x00, 0x74, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
            0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,
        ];
        let mem = make_memory(&code, 0x1000);
        let result = decompile(&lifter, &mem, 0x1000, "early_ret", 100).unwrap();
        // Six instructions, three basic blocks (header / then / else).
        // Pre-fix this was 4 instructions, 2 blocks because the JE target
        // (0x100B onwards) was dropped.
        assert_eq!(result.stats.instructions_lifted, 6,
            "all reachable instructions must survive trim: {:?}", result.stats.basic_blocks);
        assert_eq!(result.stats.basic_blocks, 3);
    }

    /// `if (a || b)`: the second test's block holds nothing but the test, so the two jumps to
    /// the shared target are one condition (WS80) instead of the target printed twice.
    #[test]
    fn decompile_merges_or_condition() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x83, 0xff, 0x01, // cmp edi, 1
            0x74, 0x0b, // je L
            0x83, 0xfe, 0x02, // cmp esi, 2
            0x74, 0x06, // je L
            0xb8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
            0xc3, // ret
            0xb8, 0x07, 0x00, 0x00, 0x00, // L: mov eax, 7
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let cond = c.lines().find(|l| l.trim_start().starts_with("if (")).unwrap_or_default();
        assert!(cond.contains(" || ") || cond.contains(" && "), "{c}");
        assert!(cond.contains("esi") && cond.contains('2'), "the second test folds into the condition: {c}");
        assert_eq!(c.matches("if (").count(), 1, "{c}");
        assert!(!c.contains("goto"), "{c}");
        assert_eq!(c.matches("7;").count(), 1, "{c}");
    }


    /// A lone `jmp` shared by two arms (not their join) is threaded through (WS80): both
    /// arms go straight to where it leads, so no `goto` to the empty block is needed.
    #[test]
    fn shared_lone_jmp_needs_no_goto() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x83, 0xff, 0x01, // 1000: cmp edi, 1
            0x75, 0x07, // 1003: jne 100c
            0xb8, 0x05, 0x00, 0x00, 0x00, // 1005: mov eax, 5
            0xeb, 0x0e, // 100a: jmp T (101a)
            0xb8, 0x06, 0x00, 0x00, 0x00, // 100c: mov eax, 6
            0x83, 0xfe, 0x03, // 1011: cmp esi, 3
            0x74, 0x04, // 1014: je T (101a)
            0xff, 0xc0, // 1016: inc eax
            0xeb, 0x02, // 1018: jmp J (101c)
            0xeb, 0x00, // 101a: T: jmp J
            0xe8, 0xdf, 0x0f, 0x00, 0x00, // 101c: J: call 0x2000
            0xc3, // 1021: ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("goto"), "{c}");
        assert_eq!(c.matches("0x2000(").count(), 1, "{c}");
    }

    /// The epilogue's frame restore prints nothing (WS80): no `rsp = rsp + 8` from the `pop`,
    /// no load of the return address for the `ret`.
    #[test]
    fn epilogue_frame_restore_is_not_printed() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x53, // push rbx
            0x89, 0xfb, // mov ebx, edi
            0xe8, 0xf8, 0x0f, 0x00, 0x00, // call 0x2000
            0x89, 0xd8, // mov eax, ebx
            0x5b, // pop rbx
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("rsp = rsp + 8"), "{c}");
        assert!(!c.contains("= *(uint64_t*)rsp;"), "{c}");
        assert!(c.contains("return rax;"), "{c}");
        assert!(c.contains("rsp = rsp - 8"), "the prologue is kept: {c}");
    }


    /// After a call whose return register is unknown (an import, an unresolved indirect
    /// call), `rax` tested and `xmm0` only handed on to the next call: the call returned in
    /// `rax` (WS80) — one `rax = f()`, no `xmm0 = __ret`, no `xmm0` argument.
    #[test]
    fn unknown_callee_returns_in_the_register_really_read() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xe8, 0xfb, 0x0f, 0x00, 0x00, // 1000: call 0x2000
            0x85, 0xc0, // 1005: test eax, eax
            0x74, 0x05, // 1007: je 100e
            0xe8, 0xfd, 0x0f, 0x00, 0x00, // 1009: call 0x200b
            0xc3, // 100e: ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("__ret"), "{c}");
        assert!(c.contains("rax = 0x2000("), "{c}");
        assert!(!c.contains("xmm0"), "{c}");
    }


    /// `return g();` with `g` unknown: the function's own code cannot tell what it returns,
    /// its callers can (WS80) — one that ignores the result makes it `void`, one that tests
    /// `eax` keeps `uint64_t`.
    #[test]
    fn return_type_from_what_callers_read() {
        let lifter = X86Lifter::new_64();
        let f = |after: &[u8]| {
            let mut code = vec![
                0xe8, 0xfb, 0x0f, 0x00, 0x00, // 1000: call 0x2000
                0xc3, // 1005: ret
                0xe8, 0xf5, 0xff, 0xff, 0xff, // 1006: caller: call 0x1000
            ];
            code.extend_from_slice(after);
            let mem = make_memory(&code, 0x1000);
            decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code
        };
        let ignored = f(&[0x31, 0xc0, 0xc3]); // xor eax, eax ; ret
        assert!(ignored.contains("void f("), "{ignored}");
        assert!(!ignored.contains("return rax"), "{ignored}");
        let tested = f(&[0x85, 0xc0, 0xc3]); // test eax, eax ; ret
        assert!(tested.contains("uint64_t f("), "{tested}");
    }


    /// A folded `jne` test reads `a != b`, not `!(a == b)` (WS80).
    #[test]
    fn folded_jne_reads_not_equal() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x83, 0xff, 0x01, // cmp edi, 1
            0x74, 0x0b, // je L
            0x83, 0xfe, 0x02, // cmp esi, 2
            0x75, 0x06, // jne L
            0xb8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
            0xc3, // ret
            0xb8, 0x07, 0x00, 0x00, 0x00, // L: mov eax, 7
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let cond = c.lines().find(|l| l.trim_start().starts_with("if (")).unwrap_or_default();
        assert!(cond.contains("esi != 2") || cond.contains("esi == 2"), "{c}");
        assert!(!cond.contains("!(esi"), "{c}");
    }


    /// `cmp a, b; je L1; jl L2`: the second block reads the SF / OF the first block's `cmp`
    /// set (WS82); it prints `a < b`, not `!var_207 != !var_20b` with `INT_SBORROW` kept alive.
    #[test]
    fn flags_read_in_next_block_are_a_comparison() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x39, 0xf7, // cmp edi, esi
            0x74, 0x08, // je L1 (100c)
            0x7c, 0x0c, // jl L2 (1012)
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xc3, // ret
            0xb8, 0x02, 0x00, 0x00, 0x00, // L1: mov eax, 2
            0xc3, // ret
            0xb8, 0x03, 0x00, 0x00, 0x00, // L2: mov eax, 3
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("SBORROW"), "{c}");
        assert!(!c.contains("var_2"), "no flag variable is left: {c}");
        assert!(
            c.contains("(int32_t)edi < (int32_t)esi") || c.contains("(int32_t)edi >= (int32_t)esi"),
            "{c}"
        );
        assert!(c.contains("edi == esi") || c.contains("edi != esi"), "{c}");
    }

    /// The flags of a `cmp` read in a later block whose operand was overwritten in between
    /// stay flags (WS82): `edi` no longer holds the compared value.
    #[test]
    fn flags_read_after_operand_changes_are_kept() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x39, 0xf7, // cmp edi, esi
            0x74, 0x0a, // je L1 (100e)
            0x8d, 0x7f, 0x01, // lea edi, [rdi+1] (no flags)
            0x7c, 0x0b, // jl L2 (1014)
            0x89, 0xf8, // mov eax, edi
            0xc3, // ret
            0x90, 0x90, // pad
            0xb8, 0x02, 0x00, 0x00, 0x00, // L1: mov eax, 2
            0xc3, // ret
            0xb8, 0x03, 0x00, 0x00, 0x00, // L2: mov eax, 3
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("(int32_t)edi < (int32_t)esi") && !c.contains("(int32_t)edi >= (int32_t)esi"), "{c}");
    }

    /// `mov eax, edi; sub eax, esi; jl`: the compared register is overwritten by the result,
    /// but the register it was copied from still holds the value (WS82).
    #[test]
    fn flags_of_a_copied_operand_compare_the_source() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x89, 0xf8, // mov eax, edi
            0x29, 0xf0, // sub eax, esi
            0x7c, 0x01, // jl L
            0xc3, // ret
            0x31, 0xc0, // L: xor eax, eax
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("SBORROW"), "{c}");
        assert!(c.contains("(int32_t)edi < (int32_t)esi") || c.contains("(int32_t)edi >= (int32_t)esi"), "{c}");
    }

    /// `sub dword [rdi], 1; jle`: the old value is kept as `old_1` where the flags were
    /// computed, and the condition compares it (WS82).
    #[test]
    fn flags_of_an_overwritten_operand_keep_its_value() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x83, 0x2f, 0x01, // sub dword [rdi], 1
            0x7e, 0x01, // jle L
            0xc3, // ret
            0x31, 0xc0, // L: xor eax, eax
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("SBORROW"), "{c}");
        assert!(c.contains("old_1 = "), "{c}");
        assert!(c.contains("(int32_t)old_1 <= (int32_t)1") || c.contains("(int32_t)old_1 > (int32_t)1"), "{c}");
    }

    /// `sub edi, esi; jl; jo`: the overflow flag is read twice, so `edi`'s old value cannot
    /// be kept; the `jl` must not read as `edi < esi` with `edi` already the difference.
    #[test]
    fn flags_of_a_sub_into_its_operand_do_not_compare_the_result() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x29, 0xf7, // sub edi, esi
            0x7c, 0x05, // jl 1009
            0x70, 0x06, // jo 100c
            0x89, 0xf8, // mov eax, edi
            0xc3, // ret
            0x31, 0xc0, // 1009: xor eax, eax
            0xc3, // ret
            0xb8, 0x01, 0x00, 0x00, 0x00, // 100c: mov eax, 1
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        for bad in ["(int32_t)edi < (int32_t)esi", "(int32_t)edi >= (int32_t)esi"] {
            assert!(!c.contains(bad), "{c}");
        }
    }

    /// `test edi, edi; jne f` jumps out of the function: a conditional tail call (WS82). The
    /// CFG used to keep only the fall-through, so the test and the call vanished.
    #[test]
    fn conditional_jump_out_is_a_conditional_tail_call() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x85, 0xff, // test edi, edi
            0x0f, 0x85, 0xf8, 0x0f, 0x00, 0x00, // jne 0x2000
            0x31, 0xc0, // xor eax, eax
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let cond = c.lines().find(|l| l.trim_start().starts_with("if (")).unwrap_or_default();
        assert!(cond.contains("edi"), "{c}");
        assert!(c.contains("0x2000("), "{c}");
        assert!(c.matches("return").count() >= 2, "{c}");
        assert!(!c.contains("label_"), "{c}");
    }

    /// `jmp [rax+0x20]` through a vtable is a tail call (WS82): `return (*f)(rdi);`, not
    /// `goto *tmp;`.
    #[test]
    fn indirect_tail_jump_is_a_call() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x48, 0x8b, 0x07, // mov rax, [rdi]
            0xff, 0x60, 0x20, // jmp qword ptr [rax+0x20]
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("goto"), "{c}");
        assert!(c.contains("return"), "{c}");
        assert!(c.contains("(*"), "{c}");
    }

    /// A jump-table dispatch (`jmp [table + rax*8]`) stays an indirect jump.
    #[test]
    fn jump_table_dispatch_is_no_tail_call() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xff, 0x24, 0xc5, 0x00, 0x20, 0x00, 0x00, // jmp qword ptr [rax*8 + 0x2000]
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(c.contains("goto *"), "{c}");
    }

    /// `dec dword [rdi]; mov ecx, [rdi]; test ecx, ecx; jg`: `test` clears OF, so the `jg`
    /// reads `ecx > 0`, not the `dec`'s overflow flag (WS82, a lifter fix).
    #[test]
    fn jg_after_test_reads_no_stale_overflow() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xf0, 0xff, 0x0f, // lock dec dword ptr [rdi]
            0x8b, 0x0f, // mov ecx, [rdi]
            0x85, 0xc9, // test ecx, ecx
            0x7f, 0x01, // jg L
            0xc3, // ret
            0x31, 0xc0, // L: xor eax, eax
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(!c.contains("SBORROW") && !c.contains("var_20b"), "{c}");
        // (`ecx` is read only by the test: its load folds into the condition)
        let cond = c.lines().find(|l| l.trim_start().starts_with("if (")).unwrap_or_default();
        assert!(cond.contains(" > (int32_t)0") || cond.contains(" <= (int32_t)0"), "{c}");
        assert!(!cond.contains("!0") && !cond.contains("||"), "{c}");
    }

    /// `setne sil; and al, sil; mov edi, 5; call f`: the byte `sil` holds is a flag the
    /// function computes for itself, not an argument for `f`.
    fn setcc_leftover_code() -> Vec<u8> {
        vec![
            0x85, 0xc9, // test ecx, ecx
            0x40, 0x0f, 0x95, 0xc6, // setne sil
            0x40, 0x20, 0xf0, // and al, sil
            0xbf, 0x05, 0x00, 0x00, 0x00, // mov edi, 5
            0xe8, 0xed, 0x0f, 0x00, 0x00, // call 0x2000
            0x88, 0x05, 0xe9, 0x1f, 0x00, 0x00, // mov [0x3000], al
            0xc3, // ret
        ]
    }

    /// A known import takes the parameters of its prototype (WS82):
    /// `pthread_mutex_unlock(rdi)`, not `(rdi, rsi)` because `sil` was written.
    #[test]
    fn import_prototype_sets_the_arguments() {
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&setcc_leftover_code(), 0x1000);
        let symbols = std::collections::BTreeMap::from([(0x2000u64, "pthread_mutex_unlock@plt".to_string())]);
        let c = decompile_with_symbols(&lifter, &mem, 0x1000, "f", 100, &symbols).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("pthread_mutex_unlock@plt(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("(5)"), "{c}");
    }

    /// An unknown callee: a register only partly written (`setne sil`) whose byte the
    /// function reads itself is no argument (WS82), though only the call reads the full `rsi`.
    #[test]
    fn partial_register_write_used_locally_is_no_argument() {
        let lifter = X86Lifter::new_64();
        let mem = make_memory(&setcc_leftover_code(), 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("(5)"), "{c}");
    }

    /// `setne sil; call f`: a byte written only to be passed is still an argument.
    #[test]
    fn setcc_into_an_argument_register_is_an_argument() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x85, 0xc9, // test ecx, ecx
            0x40, 0x0f, 0x95, 0xc6, // setne sil
            0xbf, 0x05, 0x00, 0x00, 0x00, // mov edi, 5
            0xe8, 0xf0, 0x0f, 0x00, 0x00, // call 0x2000
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("(5, rsi)"), "{c}");
    }

    /// A thunk whose only instruction is `jmp import@plt` is that import (WS82): its name and
    /// its prototype (`pthread_cond_destroy@plt(rdi)`, not `0x1010()`).
    #[test]
    fn call_to_an_import_thunk_takes_the_import() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x48, 0x8d, 0x7b, 0x10, // lea rdi, [rbx+0x10]
            0xe8, 0x07, 0x00, 0x00, 0x00, // call 0x1010
            0xc3, // ret
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // pad
            0xe9, 0xeb, 0x0f, 0x00, 0x00, // 0x1010: jmp 0x2000
        ];
        let mem = make_memory(&code, 0x1000);
        let symbols = std::collections::BTreeMap::from([(0x2000u64, "pthread_cond_destroy@plt".to_string())]);
        let c = decompile_with_symbols(&lifter, &mem, 0x1000, "f", 4, &symbols).unwrap().c_code;
        let call = c.lines().find(|l| l.contains("pthread_cond_destroy@plt(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call.contains("(rdi)"), "{c}");
    }

    /// `dec ebx; jne L` in a loop (WS83, BDS 0xc226df0): `ebx`'s new value is printed as the
    /// statement `ebx = ebx - 1;`, so the condition must test it (`ebx != 0`), not the flags'
    /// `old - 1 == 0` folded to `ebx == 1` with `ebx` already decremented.
    #[test]
    fn dec_in_a_loop_tests_the_new_value() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x89, 0xfb, // 0x1000 mov ebx, edi
            0x31, 0xc0, // 0x1002 xor eax, eax
            0x01, 0xd8, // 0x1004 L: add eax, ebx
            0xff, 0xcb, // 0x1006 dec ebx
            0x75, 0xfa, // 0x1008 jne L
            0xc3, // 0x100a ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(c.contains("ebx = ebx - 1;"), "{c}");
        assert!(!c.contains("ebx == 1") && !c.contains("ebx != 1"), "{c}");
        assert!(c.contains("ebx != 0") || c.contains("ebx == 0"), "{c}");
    }

    /// `cmovl` prints as a select, not the lifter's branch-free mask (WS83).
    #[test]
    fn cmov_is_a_select() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x39, 0xf7, // cmp edi, esi
            0x0f, 0x4c, 0xfe, // cmovl edi, esi
            0x48, 0x39, 0xd1, // cmp rcx, rdx
            0x48, 0x0f, 0x43, 0xca, // cmovae rcx, rdx
            0x01, 0xcf, // add edi, ecx
            0x89, 0xf8, // mov eax, edi
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let r = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap();
        let c = &r.c_code;
        assert!(c.contains("edi = ((int32_t)edi < (int32_t)esi) ? esi : edi;"), "{c}");
        // `cmovae`: moves when `!(rcx < rdx)`
        assert!(c.contains("rcx = (rcx < rdx) ? rcx : rdx;"), "{c}");
        assert!(!c.contains("tmp_4b") && !c.contains("var_201"), "{c}");
        assert!(r.rust_code.contains("if ") && !r.rust_code.contains("tmp_4bc"), "{}", r.rust_code);
    }

    /// A constant copy whose reader took the constant dies (WS83): copy propagation used to
    /// leave the reader in the copy's use list, so `ecx = 7;` stayed printed (and died only
    /// in functions with a phi, in a second round of dead code elimination).
    #[test]
    fn propagated_constant_copy_is_dropped() {
        let lifter = X86Lifter::new_64();
        let code = [
            0xb9, 0x07, 0x00, 0x00, 0x00, // mov ecx, 7
            0x89, 0x0f, // mov [rdi], ecx
            0x31, 0xc0, // xor eax, eax
            0xc3, // ret
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        assert!(c.contains("*(uint32_t*)rdi = 7;"), "{c}");
        assert!(!c.contains("ecx"), "{c}");
    }

    /// A PIE jump table (`cmp; ja default; lea rcx, [table]; movsxd rax, [rcx+rax*4]; add rax,
    /// rcx; jmp rax`) is a `switch` with its cases (WS83); the cases used to be unreachable,
    /// so their code was not printed at all (`goto *rax;`).
    #[test]
    fn jump_table_is_a_switch() {
        let lifter = X86Lifter::new_64();
        let code: &[u8] = &[
            0x83, 0xff, 0x03, // 0x1000 cmp edi, 3
            0x77, 0x24, // 0x1003 ja 0x1029
            0x89, 0xf8, // 0x1005 mov eax, edi
            0x48, 0x8d, 0x0d, 0xf2, 0x00, 0x00, 0x00, // 0x1007 lea rcx, [0x1100]
            0x48, 0x63, 0x04, 0x81, // 0x100e movsxd rax, [rcx+rax*4]
            0x48, 0x01, 0xc8, // 0x1012 add rax, rcx
            0xff, 0xe0, // 0x1015 jmp rax
            0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3, // 0x1017 mov eax, 10; ret
            0xb8, 0x14, 0x00, 0x00, 0x00, 0xc3, // 0x101d mov eax, 20; ret
            0xb8, 0x1e, 0x00, 0x00, 0x00, 0xc3, // 0x1023 mov eax, 30; ret (no case)
            0x31, 0xc0, 0xc3, // 0x1029 xor eax, eax; ret
        ];
        // case 0 -> 0x1017, 1 -> 0x101d, 2 -> default, 3 -> 0x101d (relative to the table)
        let rel = |t: u64| ((t as i64 - 0x1100) as i32).to_le_bytes();
        let table: Vec<u8> = [0x1017u64, 0x101d, 0x1029, 0x101d].iter().flat_map(|&t| rel(t)).collect();
        let mem = make_memory_parts(&[(0x1000, code), (0x1100, &table)]);
        let r = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap();
        let c = &r.c_code;
        assert!(c.contains("switch (edi) {"), "{c}");
        assert!(!c.contains("goto *"), "{c}");
        let at = |s: &str| c.find(s).unwrap_or_else(|| panic!("{s}: {c}"));
        assert!(at("case 0:") < at("return 0xa;"), "{c}");
        assert!(at("case 1:") < at("case 3:") && at("case 3:") < at("return 0x14;"), "{c}");
        assert!(!c.contains("case 2:") && at("default:") < at("return 0;"), "{c}");
        assert!(!c.contains("0x1100") && !c.contains("0x1e"), "the table computation is gone: {c}");
        assert!(r.rust_code.contains("match edi {") && r.rust_code.contains("1 | 3 =>"), "{}", r.rust_code);
    }

    /// A `switch` in a loop whose case leaves the loop (WS83): `break` inside the `switch`
    /// would only leave the `switch`, so the exit is a `goto` and the other cases `break`.
    #[test]
    fn switch_case_leaving_a_loop_is_no_break() {
        let lifter = X86Lifter::new_64();
        let code: &[u8] = &[
            0x31, 0xc0, // 0x1000 xor eax, eax
            0x83, 0xff, 0x01, // 0x1002 L: cmp edi, 1
            0x77, 0x19, // 0x1005 ja 0x1020
            0x89, 0xf9, // 0x1007 mov ecx, edi
            0x48, 0x8d, 0x15, 0xf0, 0x00, 0x00, 0x00, // 0x1009 lea rdx, [0x1100]
            0x48, 0x63, 0x0c, 0x8a, // 0x1010 movsxd rcx, [rdx+rcx*4]
            0x48, 0x01, 0xd1, // 0x1014 add rcx, rdx
            0xff, 0xe1, // 0x1017 jmp rcx
            0x83, 0xc0, 0x01, // 0x1019 case 0: add eax, 1
            0xeb, 0x05, // 0x101c jmp 0x1023
            0xeb, 0x07, // 0x101e case 1: jmp 0x1027 (out of the loop)
            0x83, 0xc0, 0x02, // 0x1020 default: add eax, 2
            0xff, 0xcf, // 0x1023 dec edi
            0x79, 0xdb, // 0x1025 jns L
            0xc3, // 0x1027 ret
        ];
        let rel = |t: u64| ((t as i64 - 0x1100) as i32).to_le_bytes();
        let table: Vec<u8> = [0x1019u64, 0x101e].iter().flat_map(|&t| rel(t)).collect();
        let mem = make_memory_parts(&[(0x1000, code), (0x1100, &table)]);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let sw = c.find("switch (edi) {").unwrap_or_else(|| panic!("{c}"));
        let case1 = c[sw..].find("case 1:").unwrap_or_else(|| panic!("{c}")) + sw;
        let next = c[case1..].find("default:").map_or(c.len(), |d| d + case1);
        let arm = &c[case1..next];
        assert!(!arm.contains("break;"), "case 1 leaves the loop, not the switch: {c}");
        assert!(arm.contains("goto ") || arm.contains("return"), "{c}");
        assert!(c.contains("eax = eax + 2"), "{c}");
        assert!(!c.contains("label_"), "the cases join inside the loop: {c}");
    }

}
