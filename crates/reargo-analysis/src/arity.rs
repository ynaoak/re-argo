//! Infer argument arity for functions without a known signature.
//!
//! On x86_64 SysV the first six integer / pointer parameters live in
//! RDI, RSI, RDX, RCX, R8, R9 in that order. A function uses exactly
//! the prefix of those registers it actually reads before writing to
//! them — if RDI and RSI are read but RDX is overwritten before any
//! read, the function has two parameters.
//!
//! We compute this per-function by scanning the lifted P-code:
//!
//! 1. For each ARG register, classify the *first* operation that
//!    touches its varnode:
//!      * READ before WRITE → argument
//!      * WRITE before READ → scratch (not an argument)
//!      * neither           → not an argument
//! 2. Argument count = highest-indexed register classified as
//!    "argument" + 1 (`if RDX is used but R8 / R9 aren't, arity = 3`).
//!
//! Only runs on functions that are `FUN_*` (no signature known) and
//! `!is_thunk`. The inferred arity is recorded as
//! `metadata.func_<addr>_arity = N` and surfaced as an EOL comment
//! at the function entry.
//!
//! Tracker scope: intra-function P-code walk through the linear lifted
//! range — same scope as `callsite::resolve_call_sites`. This catches
//! the common case where the compiler reads each arg register early
//! (usually in the prologue) and is more than good enough for IDA-
//! Pro-equivalent surface annotation.

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;
use reargo_lift::PcodeLift;
use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

/// SysV arg-register offsets in REGISTER space, in declaration order.
/// Identical to the table in `callsite.rs` — kept inline so this
/// analyzer is independent of the resolver.
const ARG_REGS: [(u64, &str); 6] = [
    (0x38, "rdi"),
    (0x30, "rsi"),
    (0x10, "rdx"),
    (0x08, "rcx"),
    (0x80, "r8"),
    (0x88, "r9"),
];

pub struct ArgumentArityAnalyzer;

impl Analyzer for ArgumentArityAnalyzer {
    fn name(&self) -> &str {
        "Argument Arity"
    }
    fn description(&self) -> &str {
        "Infers parameter count for FUN_* functions from SysV arg-register read-before-write"
    }
    fn priority(&self) -> u32 {
        // After Signatures (700) + CrtAnalyzer (710) so we skip
        // anything that just got a name; before Complexity (900).
        780
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let lifter: Box<dyn PcodeLift> = Box::new(reargo_lift::x86::X86Lifter::new_64());

        let candidates: Vec<u64> = program
            .listing
            .functions()
            .filter(|f| f.name.starts_with("FUN_") && !f.is_thunk)
            .map(|f| f.entry_point)
            .collect();

        let mut annotated = 0usize;
        for entry in candidates {
            let max_insns = program
                .listing
                .get_function(entry)
                .map(|f| f.body.ranges().map(|r| r.size as usize).sum::<usize>().max(200))
                .unwrap_or(200);
            let Ok(lifted) = lifter.lift_range(&program.info.memory, entry, max_insns) else {
                continue;
            };
            let arity = infer_arity(&lifted);
            program.metadata.set_property(
                format!("func_{:x}_arity", entry),
                arity.to_string(),
            );
            if program.comments.get(entry, CommentType::Eol).is_none() {
                program.comments.set(
                    entry,
                    CommentType::Eol,
                    format!("inferred arity: {}", arity),
                );
                annotated += 1;
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: annotated,
        })
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum RegState {
    #[default]
    Untouched,
    ReadBeforeWrite,
    WrittenFirst,
}

/// Walk the lifted P-code in linear order and classify each SysV arg
/// register's first usage. Returns the number of leading registers
/// classified as `ReadBeforeWrite` — i.e., the inferred SysV arity.
fn infer_arity(lifted: &[reargo_lift::LiftedInstruction]) -> usize {
    let mut state: [RegState; 6] = [RegState::Untouched; 6];

    for insn in lifted {
        for op in &insn.ops {
            // Reads: every input that targets a SysV register.
            for input in op.inputs.iter() {
                if input.space == SpaceId::REGISTER
                    && let Some(idx) = ARG_REGS.iter().position(|&(off, _)| off == input.offset)
                    && state[idx] == RegState::Untouched
                {
                    state[idx] = RegState::ReadBeforeWrite;
                }
            }
            // Write: the output, if any, targets a register.
            if let Some(out) = op.output.as_ref()
                && out.space == SpaceId::REGISTER
                && let Some(idx) = ARG_REGS.iter().position(|&(off, _)| off == out.offset)
                && state[idx] == RegState::Untouched
            {
                // Pure Copy of a CONST into a register on entry is
                // a "set up the zero-page argument area" pattern in
                // some glibc helpers; it's still a write-first.
                state[idx] = RegState::WrittenFirst;
            }
            // A CALL clobbers everything (per SysV) — bail so the
            // post-call usage doesn't pollute the per-arg classification.
            if matches!(op.opcode, OpCode::Call | OpCode::CallInd | OpCode::Return) {
                let highest = (0..6)
                    .rev()
                    .find(|&i| state[i] == RegState::ReadBeforeWrite);
                return highest.map(|i| i + 1).unwrap_or(0);
            }
        }
    }

    let highest = (0..6)
        .rev()
        .find(|&i| state[i] == RegState::ReadBeforeWrite);
    highest.map(|i| i + 1).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;

    fn vn_reg(offset: u64) -> VarnodeData {
        VarnodeData {
            space: SpaceId::REGISTER,
            offset,
            size: 8,
        }
    }
    fn vn_const(v: u64) -> VarnodeData {
        VarnodeData {
            space: SpaceId::CONST,
            offset: v,
            size: 8,
        }
    }

    fn make_op(opcode: OpCode, inputs: Vec<VarnodeData>, output: Option<VarnodeData>) -> PcodeOp {
        let mut op = PcodeOp::new(opcode, SeqNum::new(reargo_core::address::Address::new(SpaceId::RAM, 0), 0));
        op.inputs = inputs.into_iter().collect();
        op.output = output;
        op
    }

    fn insn(ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction {
            address: 0x1000,
            length: 4,
            mnemonic: "test".into(),
            ops,
        }
    }

    #[test]
    fn rdi_read_first_means_arity_one() {
        // Copy rax = rdi  → reads rdi.
        let op = make_op(OpCode::Copy, vec![vn_reg(0x38)], Some(vn_reg(0)));
        assert_eq!(infer_arity(&[insn(vec![op])]), 1);
    }

    #[test]
    fn rdi_written_first_is_not_arg() {
        // Copy rdi = CONST(0)  → rdi written first (so it's scratch).
        let op = make_op(OpCode::Copy, vec![vn_const(0)], Some(vn_reg(0x38)));
        assert_eq!(infer_arity(&[insn(vec![op])]), 0);
    }

    #[test]
    fn rdi_rsi_rdx_read_first_means_arity_three() {
        let ops = vec![
            make_op(OpCode::Copy, vec![vn_reg(0x38)], Some(vn_reg(0))), // read rdi
            make_op(OpCode::Copy, vec![vn_reg(0x30)], Some(vn_reg(0))), // read rsi
            make_op(OpCode::Copy, vec![vn_reg(0x10)], Some(vn_reg(0))), // read rdx
        ];
        assert_eq!(infer_arity(&[insn(ops)]), 3);
    }

    #[test]
    fn gap_uses_highest_read() {
        // RDI written first, RSI read first — highest read is index
        // 1, so arity = 2 (treating RDI as written-but-still-an-arg).
        // We deliberately don't try to be smarter here; the
        // SysV rule is "an arg has to be read before it's clobbered",
        // and a function that writes RDI before reading it just has
        // never observed its first arg — but the *caller* still
        // passed one. The conservative thing is to report 2.
        let ops = vec![
            make_op(OpCode::Copy, vec![vn_const(0)], Some(vn_reg(0x38))), // write rdi
            make_op(OpCode::Copy, vec![vn_reg(0x30)], Some(vn_reg(0))),    // read rsi
        ];
        assert_eq!(infer_arity(&[insn(ops)]), 2);
    }

    #[test]
    fn call_stops_classification() {
        // Reads of args before a call count; reads after don't (the
        // call clobbers everything per SysV).
        let ops = vec![
            make_op(OpCode::Copy, vec![vn_reg(0x38)], Some(vn_reg(0))), // read rdi
            make_op(OpCode::Call, vec![vn_const(0xdeadbeef)], None),
            // After call: would otherwise count rsi too, but we bail.
            make_op(OpCode::Copy, vec![vn_reg(0x30)], Some(vn_reg(0))),
        ];
        assert_eq!(infer_arity(&[insn(ops)]), 1);
    }
}
