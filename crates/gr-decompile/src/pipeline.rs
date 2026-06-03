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

    let terminated = trim_to_return(&lifted);
    let empty_u64: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    let empty_i64: std::collections::BTreeMap<i64, String> = std::collections::BTreeMap::new();
    build_decompile_result(terminated, func_name, entry, &empty_u64, &empty_u64, &empty_i64)
}

pub fn decompile_function(
    lifter: &dyn PcodeLift,
    program: &Program,
    func_entry: u64,
) -> Result<DecompileResult, String> {
    let func = program.listing.get_function(func_entry);
    let func_name = func
        .map(|f| f.name.clone())
        .unwrap_or_else(|| program.function_name_at(func_entry));

    let max_insns = func
        .map(|f| {
            f.body
                .ranges()
                .map(|r| r.size as usize)
                .sum::<usize>()
                .max(100)
        })
        .unwrap_or(500);

    let lifted = lifter
        .lift_range(&program.info.memory, func_entry, max_insns)
        .map_err(|e| e.to_string())?;

    if lifted.is_empty() {
        return Err(format!("no instructions at 0x{:x}", func_entry));
    }

    let terminated = if func.is_some() {
        trim_to_function_body(&lifted, func_entry, func)
    } else {
        trim_to_return(&lifted)
    };

    let symbols: std::collections::BTreeMap<u64, String> = program
        .symbol_table
        .iter()
        .map(|s| (s.address, s.name.clone()))
        .collect();

    let mut string_literals = std::collections::BTreeMap::new();
    for sym in program.symbol_table.iter() {
        if sym.name.starts_with("s_") {
            let lit = sym.name
                .strip_prefix("s_")
                .and_then(|s| s.rsplit_once('_'))
                .map(|(text, _)| text.replace('_', " "))
                .unwrap_or_default();
            if !lit.is_empty() {
                string_literals.insert(sym.address, lit);
            }
        }
    }

    let stack_vars: std::collections::BTreeMap<i64, String> = func
        .map(|f| {
            f.stack_frame
                .variables
                .iter()
                .map(|(offset, var)| (*offset, var.name.clone()))
                .collect()
        })
        .unwrap_or_default();

    build_decompile_result(terminated, &func_name, func_entry, &symbols, &string_literals, &stack_vars)
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

    entries
        .par_iter()
        .map(|&entry| (entry, decompile_function(lifter, program, entry)))
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
        trim_to_function_body(&lifted, func_entry, func)
    } else {
        trim_to_return(&lifted)
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
    stack_vars: &std::collections::BTreeMap<i64, String>,
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
    let mut c_emitter = CEmitter::with_symbols(symbols.clone());
    c_emitter.set_string_literals(string_literals.clone());
    c_emitter.set_stack_vars(stack_vars.clone());
    let c_code = c_emitter.emit_function(&ssa, &structured);

    let mut rust_emitter = RustEmitter::with_symbols(symbols.clone());
    rust_emitter.set_string_literals(string_literals.clone());
    rust_emitter.set_stack_vars(stack_vars.clone());
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
    instructions: &[LiftedInstruction],
    entry: u64,
    func: Option<&gr_program::Function>,
) -> Vec<LiftedInstruction> {
    if let Some(f) = func {
        let body_addrs = &f.body;
        let filtered: Vec<LiftedInstruction> = instructions
            .iter()
            .filter(|insn| {
                body_addrs.contains(&gr_core::address::Address::new(
                    gr_core::address::SpaceId::RAM,
                    insn.address,
                )) || insn.address == entry
            })
            .cloned()
            .collect();
        if filtered.is_empty() {
            trim_to_return(instructions)
        } else {
            filtered
        }
    } else {
        trim_to_return(instructions)
    }
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
fn trim_to_return(instructions: &[LiftedInstruction]) -> Vec<LiftedInstruction> {
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

        // Push statically-known branch targets.
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

        // Fall-through edge unless terminated by Return / indirect
        // branch / unconditional Branch (whose target we already
        // pushed). CBranch and "normal" instructions both fall
        // through.
        if !has_return_or_indjmp && !has_unconditional_transfer {
            let fall = insn.address + insn.length as u64;
            if let Some(&f_idx) = addr_to_idx.get(&fall) {
                stack.push(f_idx);
            }
        }
    }

    instructions
        .iter()
        .enumerate()
        .filter(|(idx, _)| visited[*idx])
        .map(|(_, insn)| insn.clone())
        .collect()
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
