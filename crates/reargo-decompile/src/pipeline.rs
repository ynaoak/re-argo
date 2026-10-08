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
use crate::structure::structure_cfg;

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
    let lifted = lifter
        .lift_range(memory, entry, max_instructions)
        .map_err(|e| e.to_string())?;

    if lifted.is_empty() {
        return Err(format!("no instructions at 0x{:x}", entry));
    }

    let trimmed = trim_to_return(lifted);
    let oracle = CalleeParams::new(lifter, memory);
    let call_params = callee_param_map(&trimmed, oracle.as_ref());
    let own = own_params(oracle.as_ref(), entry);
    let call_returns = callee_return_map(&trimmed, oracle.as_ref());
    let terminated = apply_call_convention(trimmed, lifter, &call_returns);
    let empty: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    build_decompile_result(terminated, func_name, entry, &empty, &empty, None, None, call_params, own)
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

/// Parameters of every direct call's callee in `instructions`, keyed by the
/// call instruction's address (WS78).
fn callee_param_map(
    instructions: &[LiftedInstruction],
    oracle: Option<&CalleeParams<'_>>,
) -> rustc_hash::FxHashMap<u64, ParamInfo> {
    use reargo_core::pcode::OpCode;
    let mut out = rustc_hash::FxHashMap::default();
    let Some(oracle) = oracle else { return out };
    for insn in instructions {
        for op in &insn.ops {
            if op.opcode == OpCode::Call
                && let Some(t) = op.inputs.first()
                && t.space == reargo_core::address::SpaceId::RAM
                && let Some(info) = oracle.params(t.offset)
            {
                out.insert(insn.address, info);
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
                let k = oracle.return_kind(t.offset);
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
    let call_params = callee_param_map(&terminated, oracle);
    let own = own_params(oracle, func_entry);
    let call_returns = callee_return_map(&terminated, oracle);
    let terminated = apply_call_convention(terminated, lifter, &call_returns);

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
    )
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
fn choose_return_register(ssa: &mut SsaFunction) -> Option<u32> {
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
        }
    }
    let float = float_votes > 0 && int_votes == 0;
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
/// decompiled body still reads on entry.
fn signature_params(
    ssa: &SsaFunction,
    info: ParamInfo,
    args: &[reargo_core::pcode::VarnodeData],
) -> Vec<reargo_core::pcode::VarnodeData> {
    args.iter()
        .enumerate()
        .filter(|&(i, a)| {
            info.mask & (1 << i) != 0
                || (!info.complete
                    && ssa.varnodes.iter().any(|vn| {
                        vn.def_op.is_none()
                            && vn.data.space == a.space
                            && vn.data.offset == a.offset
                            && vn.uses.iter().any(|&u| !ssa.ops[u].dead)
                    }))
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
) -> Result<DecompileResult, String> {
    if instructions.is_empty() {
        return Err(format!("no instructions at 0x{:x}", entry));
    }

    // Collect summary metrics *before* moving `instructions` into the
    // CFG, since `build_owned` consumes them.
    let total_pcode: usize = instructions.iter().map(|i| i.ops.len()).sum();
    let instructions_lifted = instructions.len();
    let cfg = ControlFlowGraph::build_owned(instructions);
    let block_count = cfg.block_count();

    let mut ssa = SsaFunction::from_cfg(func_name.to_string(), entry, cfg);
    ssa.call_params = call_params;
    // `apply_call_convention` ran: calls carry the convention's argument registers.
    ssa.implicit_call_args = ssa
        .ops
        .iter()
        .any(|o| o.opcode == reargo_core::pcode::OpCode::Indirect)
        && ssa
            .ops
            .iter()
            .any(|o| matches!(o.opcode, reargo_core::pcode::OpCode::Call | reargo_core::pcode::OpCode::CallInd) && o.inputs.len() > 1);

    ssa.return_float = choose_return_register(&mut ssa);
    let opt_stats = run_optimization_passes(&mut ssa);
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

    let structured = structure_cfg(&ssa.cfg);
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
    let c_code = c_emitter.emit_function(&ssa, &structured);

    let mut rust_emitter = RustEmitter::with_maps(symbols, string_literals);
    if let Some(ann) = annotations {
        rust_emitter = rust_emitter.with_annotations(ann);
    }
    if let Some(rend) = call_renderings {
        rust_emitter = rust_emitter.with_call_renderings(rend);
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
                }
                _ => {}
            }
        }

        if !has_return_or_indjmp && !has_unconditional_transfer {
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
        // the argument survives (it used to be dead code) and is the only one shown
        let call_line = c.lines().find(|l| l.contains("0x2000(")).unwrap_or_else(|| panic!("{c}"));
        assert!(call_line.contains("rdi") && !call_line.contains("rsi"), "{call_line}");
        assert!(c.contains("edi = 5"), "{c}");
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
        assert!(call_line.contains("rdi"), "{call_line}\n{c}");
        assert!(c.contains("edi = 5"), "{c}");
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
        assert!(first.contains("rdi"), "{first}");
        assert!(!second.contains("rdi"), "{second}\n{c}");
    }

    /// Code blobs at their addresses inside one `0xcc`-filled block.
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
        assert!(call.contains("(rdi, rsi)") || call.contains("(param_1, rsi)"), "{call}
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
        assert!(call.contains("rdi") && !call.contains("rcx"), "{call}
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
        assert!(call.contains("(rdi, rsi)"), "{call}\n{c}");
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
        assert!(call.contains("(rdi);"), "{call}\n{c}");
    }

    /// WS78: the 8/16-bit views of rbp/rsi/... have register names, not `var_<off>` (which
    /// declared `bp` and `bpl` as two variables both called `var_28`).
    #[test]
    fn low_byte_registers_are_named() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x40, 0xb6, 0x01, // mov sil, 1
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

    /// WS78: `jmp [rax+0x18]` (a tail call through a vtable) is an indirect jump on the
    /// loaded slot, not a silent `goto 0x0`.
    #[test]
    fn indirect_jmp_is_rendered() {
        let lifter = X86Lifter::new_64();
        let code = [
            0x48, 0x8b, 0x07, // mov rax, [rdi]
            0xff, 0x60, 0x18, // jmp [rax+0x18]
        ];
        let mem = make_memory(&code, 0x1000);
        let c = decompile(&lifter, &mem, 0x1000, "f", 100).unwrap().c_code;
        let j = c.lines().find(|l| l.contains("goto *")).unwrap_or_else(|| panic!("{c}"));
        assert!(j.contains("vfn[3]"), "{j}
{c}");
        assert!(!c.contains("BRANCHIND"), "{c}");
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
    /// instead of jumping there: no `goto`, no empty `if` arm.
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
        assert_eq!(c.matches("if (!").count(), 3, "{c}");
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
}
