use gr_lift::{LiftedInstruction, PcodeLift};
use gr_loader::Memory;
use gr_program::Program;

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
    build_decompile_result(&terminated, func_name, entry, &empty_u64, &empty_u64, &empty_i64)
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

    build_decompile_result(&terminated, &func_name, func_entry, &symbols, &string_literals, &stack_vars)
}

fn build_decompile_result(
    instructions: &[LiftedInstruction],
    func_name: &str,
    entry: u64,
    symbols: &std::collections::BTreeMap<u64, String>,
    string_literals: &std::collections::BTreeMap<u64, String>,
    stack_vars: &std::collections::BTreeMap<i64, String>,
) -> Result<DecompileResult, String> {
    if instructions.is_empty() {
        return Err(format!("no instructions at 0x{:x}", entry));
    }

    let total_pcode: usize = instructions.iter().map(|i| i.ops.len()).sum();
    let cfg = ControlFlowGraph::build(instructions);
    let block_count = cfg.block_count();

    let mut ssa = SsaFunction::from_cfg(func_name.to_string(), entry, cfg);
    let ssa_dump = ssa.display_ssa();

    let opt_stats = run_optimization_passes(&mut ssa);
    let live_ops = ssa.live_op_count();

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
        stats: DecompileStats {
            instructions_lifted: instructions.len(),
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

fn trim_to_return(instructions: &[LiftedInstruction]) -> Vec<LiftedInstruction> {
    let mut result = Vec::new();
    for insn in instructions {
        let is_ret = insn
            .ops
            .iter()
            .any(|op| op.opcode == gr_core::pcode::OpCode::Return);
        result.push(insn.clone());
        if is_ret {
            break;
        }
    }
    result
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
}
