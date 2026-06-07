use gr_lift::{LiftedInstruction, PcodeLift};
use gr_loader::Memory;
use gr_program::Program;
use rayon::prelude::*;

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

    let terminated = trim_to_return(lifted);
    let empty: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    build_decompile_result(terminated, func_name, entry, &empty, &empty)
}

pub fn decompile_function(
    lifter: &dyn PcodeLift,
    program: &Program,
    func_entry: u64,
) -> Result<DecompileResult, String> {
    let (symbols, string_literals) = build_program_maps(program);
    decompile_function_with_maps(lifter, program, func_entry, &symbols, &string_literals)
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

    build_decompile_result(terminated, &func_name, func_entry, symbols, string_literals)
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

    entries
        .par_iter()
        .map(|&entry| {
            (
                entry,
                decompile_function_with_maps(
                    lifter,
                    program,
                    entry,
                    &symbols,
                    &string_literals,
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

fn build_decompile_result(
    instructions: Vec<LiftedInstruction>,
    func_name: &str,
    entry: u64,
    symbols: &std::collections::BTreeMap<u64, String>,
    string_literals: &std::collections::BTreeMap<u64, String>,
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

    let opt_stats = run_optimization_passes(&mut ssa);
    let live_ops = ssa.live_op_count();

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
    let c_code = c_emitter.emit_function(&ssa, &structured);

    let mut rust_emitter = RustEmitter::with_maps(symbols, string_literals);
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
    func: Option<&gr_program::Function>,
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
            body_addrs.contains(&gr_core::address::Address::new(
                gr_core::address::SpaceId::RAM,
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
fn trim_to_return(instructions: Vec<LiftedInstruction>) -> Vec<LiftedInstruction> {
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
    use gr_core::pcode::OpCode;

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
                        && tgt.space == gr_core::address::SpaceId::RAM
                        && let Some(&t_idx) = addr_to_idx.get(&tgt.offset)
                    {
                        stack.push(t_idx);
                    }
                }
                OpCode::CBranch => {
                    if let Some(tgt) = op.inputs.first()
                        && tgt.space == gr_core::address::SpaceId::RAM
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
    use gr_core::address::{Endian, SpaceId};
    use gr_lift::x86::X86Lifter;
    use gr_loader::memory::{Memory, MemoryBlock, MemoryFlags};
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

    #[test]
    fn decompile_simple_function() {
        let lifter = X86Lifter::new_64();
        // push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let mem = make_memory(&code, 0x1000);

        let result = decompile(&lifter, &mem, 0x1000, "simple", 100).unwrap();
        assert!(result.c_code.contains("void simple(void)"));
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
