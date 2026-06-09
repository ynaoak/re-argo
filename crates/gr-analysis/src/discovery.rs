use std::collections::{BTreeSet, VecDeque};

use gr_arch::FlowType;
use gr_core::address::{Address, AddressRange, AddressSet, SpaceId};
use gr_program::function::Function;
use gr_program::reference::{RefType, Reference};
use gr_program::symbol::SymbolType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct FunctionDiscoveryAnalyzer;

impl Analyzer for FunctionDiscoveryAnalyzer {
    fn name(&self) -> &str {
        "Function Discovery"
    }

    fn description(&self) -> &str {
        "Recursive descent disassembly to discover functions and build cross-references"
    }

    fn priority(&self) -> u32 {
        100
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut work_queue: VecDeque<u64> = VecDeque::new();
        let mut visited: BTreeSet<u64> = BTreeSet::new();
        let mut functions_found = 0;
        let mut references_found = 0;
        let mut instructions_decoded = 0;

        work_queue.push_back(program.entry_point());

        for sym in program.symbol_table.function_symbols() {
            if sym.address != 0 && matches!(sym.symbol_type, SymbolType::Function) {
                work_queue.push_back(sym.address);
            }
        }

        const MAX_FUNCTIONS: usize = 50_000;
        const MAX_INSTRUCTIONS: usize = 5_000_000;

        while let Some(func_entry) = work_queue.pop_front() {
            if functions_found >= MAX_FUNCTIONS || instructions_decoded >= MAX_INSTRUCTIONS {
                break;
            }
            if visited.contains(&func_entry) {
                continue;
            }
            // A pre-existing function with an empty body (added by
            // EhFrameAnalyzer, EntryPointAnalyzer, or by Symbols
            // pre-seeding) still needs its body discovered — without
            // it `function_containing` rejects every address inside
            // and every downstream analyzer (callsite resolver,
            // boundary checker, coverage…) treats those bytes as
            // un-owned. Re-run discovery, then merge results in.
            let needs_body = program
                .listing
                .get_function(func_entry)
                .is_some_and(|f| f.body.is_empty());
            if program.listing.has_function(func_entry) && !needs_body {
                continue;
            }

            let result = disassemble_function(
                program,
                func_entry,
                &mut visited,
            );

            match result {
                Ok(discovery) => {
                    instructions_decoded += discovery.instruction_count;
                    references_found += discovery.references.len();

                    for r in &discovery.references {
                        program.references.add(*r);
                    }

                    if needs_body {
                        if let Some(existing) = program.listing.get_function_mut(func_entry) {
                            existing.body = discovery.body;
                            existing.call_targets = discovery.call_targets.clone();
                        }
                    } else {
                        let mut func =
                            if let Some(sym) = program.symbol_table.primary_at(func_entry) {
                                Function::new(func_entry, sym.name.clone())
                            } else {
                                Function::new(func_entry, format!("FUN_{:08x}", func_entry))
                            };
                        func.body = discovery.body;
                        func.call_targets = discovery.call_targets.clone();
                        program.listing.add_function(func);
                        functions_found += 1;
                    }

                    for call_target in &discovery.call_targets {
                        if !visited.contains(call_target)
                            && !program.listing.has_function(*call_target)
                        {
                            work_queue.push_back(*call_target);
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found,
            references_found,
            instructions_decoded,
        })
    }
}

struct FunctionDiscovery {
    body: AddressSet,
    call_targets: BTreeSet<u64>,
    references: Vec<Reference>,
    instruction_count: usize,
}

fn disassemble_function(
    program: &mut Program,
    entry: u64,
    global_visited: &mut BTreeSet<u64>,
) -> Result<FunctionDiscovery, AnalysisError> {
    let mut block_queue: VecDeque<u64> = VecDeque::new();
    let mut block_visited: BTreeSet<u64> = BTreeSet::new();
    let mut body = AddressSet::new();
    let mut call_targets: BTreeSet<u64> = BTreeSet::new();
    let mut references = Vec::new();
    let mut instruction_count = 0;

    block_queue.push_back(entry);

    while let Some(block_start) = block_queue.pop_front() {
        if block_visited.contains(&block_start) {
            continue;
        }
        block_visited.insert(block_start);

        let mut addr = block_start;
        let max_insns = 10_000;

        for _ in 0..max_insns {
            if global_visited.contains(&addr) && addr != block_start {
                break;
            }

            let insn = match program
                .arch
                .decode_instruction(&program.info.memory, addr)
            {
                Ok(insn) => insn,
                Err(_) => break,
            };

            let insn_addr = insn.address;
            let insn_len = insn.length as u64;
            let flow = insn.flow_type;
            let branch_target = insn.branch_target;

            global_visited.insert(insn_addr);
            body.add(AddressRange::new(
                Address::new(SpaceId::RAM, insn_addr),
                insn_len,
            ));
            instruction_count += 1;

            program.listing.add_instruction(insn);

            match flow {
                FlowType::Call => {
                    if let Some(target) = branch_target {
                        references.push(Reference::new(
                            insn_addr,
                            target,
                            RefType::UnconditionalCall,
                        ));
                        call_targets.insert(target);
                    }
                    let fall_through = insn_addr + insn_len;
                    references.push(Reference::new(
                        insn_addr,
                        fall_through,
                        RefType::FallThrough,
                    ));
                    addr = fall_through;
                }
                FlowType::IndirectCall => {
                    references.push(Reference::new(insn_addr, 0, RefType::IndirectCall));
                    let fall_through = insn_addr + insn_len;
                    addr = fall_through;
                }
                FlowType::UnconditionalJump => {
                    if let Some(target) = branch_target {
                        references.push(Reference::new(
                            insn_addr,
                            target,
                            RefType::UnconditionalJump,
                        ));
                        if !block_visited.contains(&target) {
                            block_queue.push_back(target);
                        }
                    }
                    break;
                }
                FlowType::ConditionalJump => {
                    if let Some(target) = branch_target {
                        references.push(Reference::new(
                            insn_addr,
                            target,
                            RefType::ConditionalJump,
                        ));
                        if !block_visited.contains(&target) {
                            block_queue.push_back(target);
                        }
                    }
                    let fall_through = insn_addr + insn_len;
                    references.push(Reference::new(
                        insn_addr,
                        fall_through,
                        RefType::FallThrough,
                    ));
                    if !block_visited.contains(&fall_through) {
                        block_queue.push_back(fall_through);
                    }
                    break;
                }
                FlowType::IndirectJump => {
                    references.push(Reference::new(insn_addr, 0, RefType::IndirectJump));
                    break;
                }
                FlowType::Return => {
                    break;
                }
                FlowType::Fall => {
                    addr = insn_addr + insn_len;
                }
            }
        }
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    if instruction_count == 0 {
        return Err(AnalysisError::Disassembly(format!(
            "no instructions at 0x{:x}",
            entry
        )));
    }

    Ok(FunctionDiscovery {
        body,
        call_targets,
        references,
        instruction_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::helpers::make_x86_64_program;

    #[test]
    fn discover_simple_function() {
        // push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
        let mut program = make_x86_64_program(&code, 0x1000);
        let analyzer = FunctionDiscoveryAnalyzer;
        let result = analyzer.analyze(&mut program).unwrap();
        assert!(result.functions_found >= 1);
        assert!(result.instructions_decoded >= 4);
        assert!(program.listing.has_function(0x1000));
    }

    #[test]
    fn discover_with_call() {
        // func1: call +5; ret
        // func2: xor eax,eax; ret
        let code = [
            0xe8, 0x01, 0x00, 0x00, 0x00, // call 0x1006
            0xc3,                           // ret
            0x31, 0xc0,                     // xor eax,eax
            0xc3,                           // ret
        ];
        let mut program = make_x86_64_program(&code, 0x1001);
        let analyzer = FunctionDiscoveryAnalyzer;
        let result = analyzer.analyze(&mut program).unwrap();
        assert!(result.functions_found >= 1);
        assert!(result.references_found > 0);
    }

    #[test]
    fn empty_program_no_crash() {
        let code = [0x00u8; 0]; // empty
        let mut program = make_x86_64_program(&code, 0x1000);
        let analyzer = FunctionDiscoveryAnalyzer;
        let _result = analyzer.analyze(&mut program);
    }
}
