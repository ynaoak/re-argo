use gr_core::address::SpaceId;
use gr_core::pcode::OpCode;

use crate::ssa::SsaFunction;
use crate::structure::StructuredBlock;

pub struct RustEmitter {
    indent: usize,
    output: String,
    symbol_names: std::collections::BTreeMap<u64, String>,
    string_literals: std::collections::BTreeMap<u64, String>,
    stack_var_names: std::collections::BTreeMap<i64, String>,
}

impl RustEmitter {
    pub fn new() -> Self {
        Self {
            indent: 0,
            output: String::new(),
            symbol_names: std::collections::BTreeMap::new(),
            string_literals: std::collections::BTreeMap::new(),
            stack_var_names: std::collections::BTreeMap::new(),
        }
    }

    pub fn with_symbols(symbols: std::collections::BTreeMap<u64, String>) -> Self {
        Self {
            indent: 0,
            output: String::new(),
            symbol_names: symbols,
            string_literals: std::collections::BTreeMap::new(),
            stack_var_names: std::collections::BTreeMap::new(),
        }
    }

    pub fn set_string_literals(&mut self, strings: std::collections::BTreeMap<u64, String>) {
        self.string_literals = strings;
    }

    pub fn set_stack_vars(&mut self, vars: std::collections::BTreeMap<i64, String>) {
        self.stack_var_names = vars;
    }

    pub fn emit_function(
        &mut self,
        func: &SsaFunction,
        structured: &StructuredBlock,
    ) -> String {
        self.output.clear();
        let sig = infer_signature(func);
        self.line(&sig.to_rust_declaration(&func.name));
        self.line("{");
        self.indent += 1;
        self.emit_var_declarations(func);
        self.emit_block(func, structured);
        self.indent -= 1;
        self.line("}");
        self.output.clone()
    }

    fn emit_var_declarations(&mut self, func: &SsaFunction) {
        let mut declared = std::collections::BTreeSet::new();
        for vn in &func.varnodes {
            if vn.data.space == SpaceId::REGISTER && vn.def_op.is_some() {
                let key = (vn.data.offset, vn.data.size);
                if declared.insert(key) {
                    let type_name = size_to_rust_type(vn.data.size);
                    let var_name = reg_name(vn.data.offset, vn.data.size);
                    self.line(&format!("let mut {}: {};", var_name, type_name));
                }
            }
        }
        if !declared.is_empty() {
            self.output.push('\n');
        }
    }

    fn emit_block(&mut self, func: &SsaFunction, block: &StructuredBlock) {
        match block {
            StructuredBlock::Basic(block_id) => {
                self.emit_basic_block(func, *block_id);
            }
            StructuredBlock::Sequence(blocks) => {
                for b in blocks {
                    self.emit_block(func, b);
                }
            }
            StructuredBlock::IfThen {
                condition_block,
                then_body,
            } => {
                self.emit_basic_block_no_branch(func, *condition_block);
                self.line(&format!(
                    "if {} {{",
                    self.get_branch_condition(func, *condition_block)
                ));
                self.indent += 1;
                self.emit_block(func, then_body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::IfThenElse {
                condition_block,
                then_body,
                else_body,
            } => {
                self.emit_basic_block_no_branch(func, *condition_block);
                self.line(&format!(
                    "if {} {{",
                    self.get_branch_condition(func, *condition_block)
                ));
                self.indent += 1;
                self.emit_block(func, then_body);
                self.indent -= 1;
                self.line("} else {");
                self.indent += 1;
                self.emit_block(func, else_body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::WhileLoop {
                condition_block,
                body,
            } => {
                self.emit_basic_block_no_branch(func, *condition_block);
                self.line(&format!(
                    "while {} {{",
                    self.get_branch_condition(func, *condition_block)
                ));
                self.indent += 1;
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::DoWhileLoop {
                body,
                condition_block,
            } => {
                // Rust has no do-while; emulate with loop + break
                self.line("loop {");
                self.indent += 1;
                self.emit_block(func, body);
                self.emit_basic_block_no_branch(func, *condition_block);
                self.line(&format!(
                    "if !({}) {{ break; }}",
                    self.get_branch_condition(func, *condition_block)
                ));
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::ForLoop {
                init_block,
                condition_block,
                update_block,
                body,
            } => {
                // Rust has no C-style for-loop; emit as while
                self.emit_basic_block_no_branch(func, *init_block);
                self.line(&format!(
                    "while {} {{",
                    self.get_branch_condition(func, *condition_block)
                ));
                self.indent += 1;
                self.emit_block(func, body);
                self.emit_basic_block_no_branch(func, *update_block);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::ShortCircuitAnd {
                left_block,
                right_block,
                body,
            } => {
                self.emit_basic_block_no_branch(func, *left_block);
                self.line(&format!(
                    "if {} && {} {{",
                    self.get_branch_condition(func, *left_block),
                    self.get_branch_condition(func, *right_block)
                ));
                self.indent += 1;
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::ShortCircuitOr {
                left_block,
                right_block,
                body,
            } => {
                self.emit_basic_block_no_branch(func, *left_block);
                self.line(&format!(
                    "if {} || {} {{",
                    self.get_branch_condition(func, *left_block),
                    self.get_branch_condition(func, *right_block)
                ));
                self.indent += 1;
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Switch {
                condition_block,
                cases,
                default,
            } => {
                self.emit_basic_block_no_branch(func, *condition_block);
                self.line(&format!(
                    "match {} {{",
                    self.get_branch_condition(func, *condition_block)
                ));
                self.indent += 1;
                for (val, body) in cases {
                    self.line(&format!("0x{:x} => {{", val));
                    self.indent += 1;
                    self.emit_block(func, body);
                    self.indent -= 1;
                    self.line("}");
                }
                if let Some(def) = default {
                    self.line("_ => {");
                    self.indent += 1;
                    self.emit_block(func, def);
                    self.indent -= 1;
                    self.line("}");
                }
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Loop { header, body } => {
                self.line("loop {");
                self.indent += 1;
                self.emit_basic_block(func, *header);
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Goto(target) => {
                // Rust does not have goto; emit as a comment-annotated break/continue placeholder
                self.line(&format!(
                    "// goto label_{:x}; (unsupported in Rust)",
                    func.cfg.blocks[*target].start_addr
                ));
            }
        }
    }

    fn emit_basic_block(&mut self, func: &SsaFunction, block_id: usize) {
        for op in &func.ops {
            if op.dead || op.block != block_id {
                continue;
            }
            if let Some(line) = self.emit_op(func, op) {
                self.line(&line);
            }
        }
    }

    fn emit_basic_block_no_branch(&mut self, func: &SsaFunction, block_id: usize) {
        for op in &func.ops {
            if op.dead || op.block != block_id {
                continue;
            }
            if matches!(op.opcode, OpCode::Branch | OpCode::CBranch) {
                continue;
            }
            if let Some(line) = self.emit_op(func, op) {
                self.line(&line);
            }
        }
    }

    fn emit_op(&self, func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<String> {
        let out_name = op.output.map(|id| varnode_name(&func.varnodes[id as usize]));

        match op.opcode {
            OpCode::Copy => {
                let dst = out_name?;
                let src = self.input_expr(func, op, 0);
                Some(format!("{} = {};", dst, src))
            }
            OpCode::IntAdd => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {}.wrapping_add({});", dst, a, b))
            }
            OpCode::IntSub => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {}.wrapping_sub({});", dst, a, b))
            }
            OpCode::IntMult => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {}.wrapping_mul({});", dst, a, b))
            }
            OpCode::IntAnd => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} & {};", dst, a, b))
            }
            OpCode::IntOr => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} | {};", dst, a, b))
            }
            OpCode::IntXor => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} ^ {};", dst, a, b))
            }
            OpCode::IntLeft => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} << {};", dst, a, b))
            }
            OpCode::IntRight => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} >> {};", dst, a, b))
            }
            OpCode::IntNegate => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = !{};", dst, a))
            }
            OpCode::Int2Comp => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {}.wrapping_neg();", dst, a))
            }
            OpCode::IntEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} == {};", dst, a, b))
            }
            OpCode::IntNotEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} != {};", dst, a, b))
            }
            OpCode::IntSLess => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = ({} as i64) < ({} as i64);", dst, a, b))
            }
            OpCode::IntLess => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} < {};", dst, a, b))
            }
            OpCode::IntZExt => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {} as u64;", dst, a))
            }
            OpCode::IntSExt => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {} as i64 as u64;", dst, a))
            }
            OpCode::Load => {
                let dst = out_name?;
                let addr = self.input_expr(func, op, 1);
                let out_size = func.varnodes[op.output.unwrap() as usize].data.size;
                let ty = size_to_rust_type(out_size);
                Some(format!(
                    "{} = unsafe {{ *({} as *const {}) }};",
                    dst, addr, ty
                ))
            }
            OpCode::Store => {
                let addr = self.input_expr(func, op, 1);
                let val = self.input_expr(func, op, 2);
                let size = if op.inputs.len() > 2 {
                    func.varnodes[op.inputs[2] as usize].data.size
                } else {
                    8
                };
                let ty = size_to_rust_type(size);
                Some(format!(
                    "unsafe {{ *({} as *mut {}) = {}; }}",
                    addr, ty, val
                ))
            }
            OpCode::Call => {
                let target_expr = self.input_expr(func, op, 0);
                let call_name = if let Some(target_vn) = op.inputs.first() {
                    let addr = func.varnodes[*target_vn as usize].data.offset;
                    self.symbol_names
                        .get(&addr)
                        .cloned()
                        .unwrap_or(target_expr)
                } else {
                    target_expr
                };
                Some(format!("{}();", call_name))
            }
            OpCode::Return => {
                let val = self.input_expr(func, op, 0);
                Some(format!("return {};", val))
            }
            OpCode::Branch => None,
            OpCode::CBranch => None,
            OpCode::CallOther => Some("core::intrinsics::abort();".into()),
            _ => {
                let dst = out_name.unwrap_or_else(|| "???".into());
                Some(format!("{} = {}(...);", dst, op.opcode.name()))
            }
        }
    }

    fn input_expr(&self, func: &SsaFunction, op: &crate::ssa::SsaOp, idx: usize) -> String {
        if idx >= op.inputs.len() {
            return "???".into();
        }
        let vn = &func.varnodes[op.inputs[idx] as usize];
        if vn.data.space == SpaceId::CONST && vn.data.offset > 0x1000 {
            if let Some(s) = self.string_literals.get(&vn.data.offset) {
                return format!("\"{}\"", s.escape_default());
            }
            if let Some(name) = self.symbol_names.get(&vn.data.offset) {
                return name.clone();
            }
        }
        varnode_name(vn)
    }

    fn get_branch_condition(&self, func: &SsaFunction, block_id: usize) -> String {
        for op in func.ops.iter().rev() {
            if op.block != block_id || op.dead {
                continue;
            }
            if op.opcode == OpCode::CBranch && op.inputs.len() >= 2 {
                let cond_vn = &func.varnodes[op.inputs[1] as usize];
                return varnode_name(cond_vn);
            }
        }
        "cond".into()
    }

    fn line(&mut self, text: &str) {
        for _ in 0..self.indent {
            self.output.push_str("    ");
        }
        self.output.push_str(text);
        self.output.push('\n');
    }
}

impl Default for RustEmitter {
    fn default() -> Self {
        Self::new()
    }
}

struct RustFunctionSignature {
    return_type: Option<&'static str>,
    params: Vec<(String, String)>,
}

impl RustFunctionSignature {
    fn to_rust_declaration(&self, name: &str) -> String {
        let params_str = if self.params.is_empty() {
            String::new()
        } else {
            self.params
                .iter()
                .map(|(nm, ty)| format!("{}: {}", nm, ty))
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self.return_type {
            Some(rt) => format!("fn {}({}) -> {}", name, params_str, rt),
            None => format!("fn {}({})", name, params_str),
        }
    }
}

fn infer_signature(func: &SsaFunction) -> RustFunctionSignature {
    let has_return_value = func.ops.iter().any(|op| {
        if op.dead || op.opcode != OpCode::Return {
            return false;
        }
        if op.inputs.is_empty() {
            return false;
        }
        let ret_vn = &func.varnodes[op.inputs[0] as usize];
        ret_vn.data.space == SpaceId::REGISTER && ret_vn.data.offset == 0x00
    });

    let return_type = if has_return_value { Some("u64") } else { None };

    let param_regs: &[(u64, &str)] = &[
        (0x08, "param_1"), // RCX (Win) / RDI (SysV) - simplified
        (0x10, "param_2"), // RDX / RSI
        (0x80, "param_3"), // R8 / RDX
        (0x88, "param_4"), // R9 / RCX
    ];

    let mut params = Vec::new();
    for &(offset, name) in param_regs {
        let is_input = func.varnodes.iter().any(|vn| {
            vn.data.space == SpaceId::REGISTER
                && vn.data.offset == offset
                && vn.def_op.is_none()
                && !vn.uses.is_empty()
        });
        if is_input {
            params.push((name.to_string(), "u64".to_string()));
        }
    }

    RustFunctionSignature {
        return_type,
        params,
    }
}

fn varnode_name(vn: &crate::ssa::SsaVarnode) -> String {
    if vn.data.space == SpaceId::CONST {
        if vn.data.offset <= 9 {
            return format!("{}", vn.data.offset);
        }
        return format!("0x{:x}", vn.data.offset);
    }
    if vn.data.space == SpaceId::REGISTER {
        return reg_name(vn.data.offset, vn.data.size);
    }
    if vn.data.space == SpaceId::RAM {
        return format!("0x{:x}", vn.data.offset);
    }
    format!("tmp_{:x}", vn.data.offset)
}

fn reg_name(offset: u64, size: u32) -> String {
    match (offset, size) {
        (0x00, 8) => "rax".into(),
        (0x00, 4) => "eax".into(),
        (0x00, 2) => "ax".into(),
        (0x00, 1) => "al".into(),
        (0x08, 8) => "rcx".into(),
        (0x08, 4) => "ecx".into(),
        (0x10, 8) => "rdx".into(),
        (0x10, 4) => "edx".into(),
        (0x18, 8) => "rbx".into(),
        (0x18, 4) => "ebx".into(),
        (0x20, 8) => "rsp".into(),
        (0x20, 4) => "esp".into(),
        (0x28, 8) => "rbp".into(),
        (0x28, 4) => "ebp".into(),
        (0x30, 8) => "rsi".into(),
        (0x30, 4) => "esi".into(),
        (0x38, 8) => "rdi".into(),
        (0x38, 4) => "edi".into(),
        (0x80, 8) => "r8".into(),
        (0x88, 8) => "r9".into(),
        (0x90, 8) => "r10".into(),
        (0x98, 8) => "r11".into(),
        _ => format!("var_{:x}", offset),
    }
}

fn size_to_rust_type(size: u32) -> &'static str {
    match size {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        _ => "()",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use crate::ssa::SsaFunction;
    use crate::structure::structure_cfg;
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
    fn emit_simple_function() {
        let seq =
            |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![
            make_lifted(
                0x1000,
                vec![PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x1000),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[imm]),
                }],
            ),
            make_lifted(
                0x1001,
                vec![PcodeOp {
                    opcode: OpCode::Return,
                    seq: seq(0x1001),
                    output: None,
                    inputs: SmallVec::from_slice(&[reg_rax]),
                }],
            ),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("my_func".into(), 0x1000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let mut emitter = RustEmitter::new();
        let output = emitter.emit_function(&ssa, &structured);

        assert!(
            output.contains("fn my_func() -> u64"),
            "Expected Rust fn signature, got:\n{}",
            output
        );
        assert!(
            output.contains("rax = 0x2a;"),
            "Expected assignment, got:\n{}",
            output
        );
        assert!(
            output.contains("return rax;"),
            "Expected return statement, got:\n{}",
            output
        );
    }

    #[test]
    fn rust_types_are_correct() {
        assert_eq!(size_to_rust_type(1), "u8");
        assert_eq!(size_to_rust_type(2), "u16");
        assert_eq!(size_to_rust_type(4), "u32");
        assert_eq!(size_to_rust_type(8), "u64");
        assert_eq!(size_to_rust_type(16), "()");
    }

    #[test]
    fn rust_signature_no_params_no_return() {
        let sig = RustFunctionSignature {
            return_type: None,
            params: vec![],
        };
        assert_eq!(sig.to_rust_declaration("foo"), "fn foo()");
    }

    #[test]
    fn rust_signature_with_params_and_return() {
        let sig = RustFunctionSignature {
            return_type: Some("u64"),
            params: vec![
                ("param_1".into(), "u64".into()),
                ("param_2".into(), "u64".into()),
            ],
        };
        assert_eq!(
            sig.to_rust_declaration("bar"),
            "fn bar(param_1: u64, param_2: u64) -> u64"
        );
    }

    #[test]
    fn rust_var_declaration_format() {
        let seq =
            |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let reg_rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let imm = VarnodeData::new(SpaceId(0), 1, 8);

        let insns = vec![
            make_lifted(
                0x2000,
                vec![PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x2000),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[imm]),
                }],
            ),
            make_lifted(
                0x2001,
                vec![PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x2001),
                    output: Some(reg_rcx),
                    inputs: SmallVec::from_slice(&[imm]),
                }],
            ),
            make_lifted(
                0x2002,
                vec![PcodeOp {
                    opcode: OpCode::Return,
                    seq: seq(0x2002),
                    output: None,
                    inputs: SmallVec::from_slice(&[reg_rax]),
                }],
            ),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("decl_test".into(), 0x2000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let mut emitter = RustEmitter::new();
        let output = emitter.emit_function(&ssa, &structured);

        assert!(
            output.contains("let mut rax: u64;"),
            "Expected 'let mut rax: u64;', got:\n{}",
            output
        );
        assert!(
            output.contains("let mut rcx: u64;"),
            "Expected 'let mut rcx: u64;', got:\n{}",
            output
        );
        // Should NOT contain C-style declarations
        assert!(
            !output.contains("uint64_t"),
            "Should not contain C types, got:\n{}",
            output
        );
    }
}
