use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

/// Emit one indented line into the C emitter's output buffer.
///
/// Replaces the `linef!(self, "...", args)` pattern that paid
/// a heap allocation per line for the intermediate `String`. The
/// macro writes the indent prefix and the formatted body directly
/// into `self.output` via `write!`, then appends the newline, with
/// no temporary allocation. About a dozen call sites in this file
/// use it.
macro_rules! linef {
    ($self:expr, $($arg:tt)*) => {{
        for _ in 0..$self.indent {
            $self.output.push_str("    ");
        }
        write!($self.output, $($arg)*).unwrap();
        $self.output.push('\n');
    }};
}

use crate::ssa::SsaFunction;
use crate::structure::StructuredBlock;

/// Cached empty maps used as the default for `CEmitter::new()` and
/// for the symbol/string/stack inputs of `with_symbols`. Sharing the
/// same static `BTreeMap::new()` here means the no-symbol code path
/// pays zero allocation, vs. constructing a fresh empty BTreeMap on
/// every emitter (six per `decompile` call before round 7).
fn empty_u64_map() -> &'static BTreeMap<u64, String> {
    static M: OnceLock<BTreeMap<u64, String>> = OnceLock::new();
    M.get_or_init(BTreeMap::new)
}

pub struct CEmitter<'a> {
    indent: usize,
    output: String,
    symbol_names: &'a BTreeMap<u64, String>,
    string_literals: &'a BTreeMap<u64, String>,
    /// Per-instruction-address annotations (from the analyzer
    /// CommentManager). Surfaces them as inline `// …` lines in the
    /// decompiled output so the user sees `printf(format=…)` /
    /// `wrapper → foo` / `loop back-edge` right next to the
    /// statement they describe.
    annotations: Option<&'a BTreeMap<u64, Vec<String>>>,
    /// Per-call-site rendering: when set, the Call op at a given
    /// instruction address is emitted using the rendering string
    /// (a C-syntax `printf("hi", 42)` expression) instead of the
    /// untyped `<callee>@plt()` stub. Populated by
    /// `CallSiteAnnotator` once the iterative resolver has pinned
    /// arg values + a `SignatureDatabase` signature.
    call_renderings: Option<&'a BTreeMap<u64, String>>,
    /// Track which addresses we've already emitted annotations for,
    /// so multi-op instructions don't repeat the same comment.
    emitted: std::cell::RefCell<std::collections::BTreeSet<u64>>,
}

impl Default for CEmitter<'static> {
    fn default() -> Self {
        Self::new()
    }
}

impl CEmitter<'static> {
    pub fn new() -> Self {
        Self {
            indent: 0,
            output: String::new(),
            symbol_names: empty_u64_map(),
            string_literals: empty_u64_map(),
            annotations: None,
            call_renderings: None,
            emitted: std::cell::RefCell::new(std::collections::BTreeSet::new()),
        }
    }
}

impl<'a> CEmitter<'a> {
    /// Construct an emitter that borrows its lookup maps from the
    /// caller. Replaces the previous `with_symbols` /
    /// `set_string_literals` / `set_stack_vars` triple, each of which
    /// took an owned `BTreeMap` and forced a clone at the pipeline
    /// call site. Each `decompile` call used to clone the symbol /
    /// string maps once per emitter (four clones total for a C+Rust
    /// pair); the reference form pays zero clones.
    ///
    /// The previous `stack_var_names` field was wired through both
    /// emitters' constructors but never read by either, so it has
    /// been dropped here too; if a future change wants to surface
    /// stack-variable names, add the parameter and the read sites
    /// together so the data path is end-to-end honest.
    pub fn with_maps(
        symbol_names: &'a BTreeMap<u64, String>,
        string_literals: &'a BTreeMap<u64, String>,
    ) -> Self {
        Self {
            indent: 0,
            output: String::new(),
            symbol_names,
            string_literals,
            annotations: None,
            call_renderings: None,
            emitted: std::cell::RefCell::new(std::collections::BTreeSet::new()),
        }
    }

    /// Attach per-address annotations (typically from
    /// `program.comments`). Annotations are emitted as `// …` lines
    /// immediately before the first SsaOp that lifts an instruction
    /// at that address, deduped so multi-op instructions don't repeat.
    pub fn with_annotations(
        mut self,
        annotations: &'a BTreeMap<u64, Vec<String>>,
    ) -> Self {
        self.annotations = Some(annotations);
        self
    }

    /// Attach per-call-site C-syntax renderings (typically from
    /// `program.call_renderings`). When the Call op at an address
    /// in the map is emitted, the rendering string is used in
    /// place of the synthetic `<callee>@plt()` stub.
    pub fn with_call_renderings(
        mut self,
        renderings: &'a BTreeMap<u64, String>,
    ) -> Self {
        self.call_renderings = Some(renderings);
        self
    }

    pub fn emit_function(
        &mut self,
        func: &SsaFunction,
        structured: &StructuredBlock,
    ) -> String {
        self.output.clear();
        let sig = infer_signature(func);
        self.line(&sig.to_c_declaration(&func.name));
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
                    let type_name = size_to_type(vn.data.size);
                    let var_name = reg_name(vn.data.offset, vn.data.size);
                    linef!(self, "{} {};", type_name, var_name);
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
                linef!(self, "if ({}) {{", self.get_branch_condition(func, *condition_block));
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
                linef!(self, "if ({}) {{", self.get_branch_condition(func, *condition_block));
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
                linef!(self, "while ({}) {{", self.get_branch_condition(func, *condition_block)
                );
                self.indent += 1;
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::DoWhileLoop {
                body,
                condition_block,
            } => {
                self.line("do {");
                self.indent += 1;
                self.emit_block(func, body);
                self.emit_basic_block_no_branch(func, *condition_block);
                self.indent -= 1;
                linef!(self, "}} while ({});", self.get_branch_condition(func, *condition_block)
                );
            }
            StructuredBlock::ForLoop {
                init_block,
                condition_block,
                update_block,
                body,
            } => {
                self.emit_basic_block_no_branch(func, *init_block);
                linef!(self, "for (; {}; ) {{", self.get_branch_condition(func, *condition_block)
                );
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
                linef!(self, "if ({} && {}) {{", self.get_branch_condition(func, *left_block),
                    self.get_branch_condition(func, *right_block)
                );
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
                linef!(self, "if ({} || {}) {{", self.get_branch_condition(func, *left_block),
                    self.get_branch_condition(func, *right_block)
                );
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
                linef!(self, "switch ({}) {{", self.get_branch_condition(func, *condition_block)
                );
                self.indent += 1;
                for (val, body) in cases {
                    linef!(self, "case 0x{:x}:", val);
                    self.indent += 1;
                    self.emit_block(func, body);
                    self.line("break;");
                    self.indent -= 1;
                }
                if let Some(def) = default {
                    self.line("default:");
                    self.indent += 1;
                    self.emit_block(func, def);
                    self.line("break;");
                    self.indent -= 1;
                }
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Loop { header, body } => {
                self.line("while (true) {");
                self.indent += 1;
                self.emit_basic_block(func, *header);
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Goto(target) => {
                linef!(self, "goto label_{:x};", func.cfg.blocks[*target].start_addr);
            }
        }
    }

    fn emit_basic_block(&mut self, func: &SsaFunction, block_id: usize) {
        for op in &func.ops {
            if op.dead || op.block != block_id {
                continue;
            }
            self.emit_annotations_for(op.address);
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
            self.emit_annotations_for(op.address);
            if let Some(line) = self.emit_op(func, op) {
                self.line(&line);
            }
        }
    }

    /// Emit any analyzer-supplied annotations for `addr` as `// …`
    /// lines. Dedup so several ops lifted from the same instruction
    /// don't replay the same comment.
    fn emit_annotations_for(&mut self, addr: u64) {
        let Some(ann) = self.annotations else {
            return;
        };
        if self.emitted.borrow().contains(&addr) {
            return;
        }
        let Some(lines) = ann.get(&addr) else {
            self.emitted.borrow_mut().insert(addr);
            return;
        };
        for ln in lines {
            // Strip stray newlines so we don't break the
            // line-prefix indentation.
            let cleaned = ln.replace(['\n', '\r'], " ");
            linef!(self, "// {}", cleaned);
        }
        self.emitted.borrow_mut().insert(addr);
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
                Some(format!("{} = {} + {};", dst, a, b))
            }
            OpCode::IntSub => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} - {};", dst, a, b))
            }
            OpCode::IntMult => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} * {};", dst, a, b))
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
                Some(format!("{} = ~{};", dst, a))
            }
            OpCode::Int2Comp => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = -{};", dst, a))
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
                // Use a width-correct signed type, not bare `(int)` (which is
                // implementation-defined width and would silently truncate
                // 64-bit operands to 32 bits).
                let ty = size_to_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({}){} < ({}){};", dst, ty, a, ty, b))
            }
            OpCode::IntSLessEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let ty = size_to_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({}){} <= ({}){};", dst, ty, a, ty, b))
            }
            OpCode::IntLess => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} < {};", dst, a, b))
            }
            OpCode::IntLessEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} <= {};", dst, a, b))
            }
            OpCode::IntSRight => {
                // Signed shift requires casting the LHS to the size-matched
                // signed type so the compiler emits an arithmetic shift.
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let ty = size_to_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({}){} >> {};", dst, ty, a, b))
            }
            OpCode::IntDiv => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} / {};", dst, a, b))
            }
            OpCode::IntSDiv => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let ty = size_to_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({}){} / ({}){};", dst, ty, a, ty, b))
            }
            OpCode::IntRem => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} % {};", dst, a, b))
            }
            OpCode::IntSRem => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let ty = size_to_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({}){} % ({}){};", dst, ty, a, ty, b))
            }
            OpCode::FloatAdd => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} + {};", dst, a, b))
            }
            OpCode::FloatSub => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} - {};", dst, a, b))
            }
            OpCode::FloatMult => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} * {};", dst, a, b))
            }
            OpCode::FloatDiv => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} / {};", dst, a, b))
            }
            OpCode::FloatNeg => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = -{};", dst, a))
            }
            OpCode::FloatAbs => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = fabs({});", dst, a))
            }
            OpCode::FloatSqrt => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = sqrt({});", dst, a))
            }
            OpCode::FloatEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} == {};", dst, a, b))
            }
            OpCode::FloatNotEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} != {};", dst, a, b))
            }
            OpCode::FloatLess => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} < {};", dst, a, b))
            }
            OpCode::FloatLessEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} <= {};", dst, a, b))
            }
            OpCode::FloatInt2Float => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let out_size = op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                let ty = if out_size == 4 { "float" } else { "double" };
                Some(format!("{} = ({}){};", dst, ty, a))
            }
            OpCode::FloatFloat2Float => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let out_size = op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                let ty = if out_size == 4 { "float" } else { "double" };
                Some(format!("{} = ({}){};", dst, ty, a))
            }
            OpCode::FloatTrunc => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let out_size = op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                let ty = size_to_signed_type(out_size);
                Some(format!("{} = ({}){};", dst, ty, a))
            }
            OpCode::FloatFloor => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = floor({});", dst, a))
            }
            OpCode::FloatCeil => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = ceil({});", dst, a))
            }
            OpCode::FloatRound => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = round({});", dst, a))
            }
            OpCode::BoolAnd => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} && {};", dst, a, b))
            }
            OpCode::BoolOr => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} || {};", dst, a, b))
            }
            OpCode::BoolXor => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = !{} != !{};", dst, a, b))
            }
            OpCode::BoolNegate => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = !{};", dst, a))
            }
            OpCode::IntZExt => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                // Cast through the source's unsigned type so a non-MSB-set
                // value isn't accidentally sign-extended by C's promotion.
                let src_ty = size_to_type(func.varnodes[op.inputs[0] as usize].data.size);
                let dst_ty = size_to_type(func.varnodes[op.output.unwrap() as usize].data.size);
                Some(format!("{} = ({})({}){};", dst, dst_ty, src_ty, a))
            }
            OpCode::IntSExt => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let src_ty = size_to_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                let dst_ty = size_to_signed_type(func.varnodes[op.output.unwrap() as usize].data.size);
                Some(format!("{} = ({})({}){};", dst, dst_ty, src_ty, a))
            }
            OpCode::Load => {
                let dst = out_name?;
                let addr = self.input_expr(func, op, 1);
                let out_size = op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                Some(format!("{} = *({}*){};", dst, size_to_type(out_size), addr))
            }
            OpCode::Store => {
                let addr = self.input_expr(func, op, 1);
                let val = self.input_expr(func, op, 2);
                let size = if op.inputs.len() > 2 {
                    func.varnodes[op.inputs[2] as usize].data.size
                } else {
                    8
                };
                Some(format!("*({}*){} = {};", size_to_type(size), addr, val))
            }
            OpCode::Call => {
                // CallSiteAnnotator may have stashed a fully
                // resolved C-syntax rendering for this call site
                // (e.g. `printf("hello %d\n", 42)`). When present,
                // use it; otherwise fall back to the bare
                // `<callee>@plt()` stub from the symbol table.
                if let Some(renderings) = self.call_renderings
                    && let Some(rendering) = renderings.get(&op.address)
                {
                    return Some(format!("{};", rendering));
                }
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
            OpCode::CallOther => Some("__builtin_trap();".into()),
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


struct FunctionSignature {
    return_type: &'static str,
    params: Vec<(String, String)>,
}

impl FunctionSignature {
    fn to_c_declaration(&self, name: &str) -> String {
        if self.params.is_empty() {
            format!("{} {}(void)", self.return_type, name)
        } else {
            let params: Vec<String> = self
                .params
                .iter()
                .map(|(ty, nm)| format!("{} {}", ty, nm))
                .collect();
            format!("{} {}({})", self.return_type, name, params.join(", "))
        }
    }
}

fn infer_signature(func: &SsaFunction) -> FunctionSignature {
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

    let return_type = if has_return_value { "uint64_t" } else { "void" };

    let param_regs: &[(u64, &str)] = &[
        (0x08, "param_1"),  // RCX (Win) / RDI (SysV) - simplified
        (0x10, "param_2"),  // RDX / RSI
        (0x80, "param_3"),  // R8 / RDX
        (0x88, "param_4"),  // R9 / RCX
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
            params.push(("uint64_t".to_string(), name.to_string()));
        }
    }

    FunctionSignature {
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
        // XMM register file (base 0x1200, stride 0x10). Scalar sd/ss views
        // share the offset, so name by offset regardless of size.
        (off, _) if (0x1200..0x1300).contains(&off) && off % 0x10 == 0 => {
            format!("xmm{}", (off - 0x1200) / 0x10)
        }
        _ => format!("var_{:x}", offset),
    }
}

fn size_to_type(size: u32) -> &'static str {
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "void",
    }
}

fn size_to_signed_type(size: u32) -> &'static str {
    match size {
        1 => "int8_t",
        2 => "int16_t",
        4 => "int32_t",
        8 => "int64_t",
        _ => "int64_t",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use crate::ssa::SsaFunction;
    use crate::structure::structure_cfg;
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;
    use smallvec::SmallVec;

    fn make_lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction { address: addr, length: 1, mnemonic: "test".into(), ops }
    }

    #[test]
    fn emit_simple_function() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::Copy,
                seq: seq(0x1000),
                output: Some(reg_rax),
                inputs: SmallVec::from_slice(&[imm]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[reg_rax]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("my_func".into(), 0x1000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let mut emitter = CEmitter::new();
        let output = emitter.emit_function(&ssa, &structured);

        assert!(output.contains("my_func(void)"));
        assert!(output.contains("rax = 0x2a"));
        assert!(output.contains("return"));
    }

    #[test]
    fn emit_int_sless_uses_width_correct_signed_cast() {
        // For 4-byte operands the previous `(int)` cast had implementation-
        // defined width; for 8-byte operands it would silently truncate to
        // 32 bits and compare the wrong values. Verify the size-matched
        // signed type is used.
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg32 = VarnodeData::new(SpaceId(2), 0x00, 4);
        let reg64 = VarnodeData::new(SpaceId(2), 0x10, 8);
        let flag = VarnodeData::new(SpaceId(2), 0x20, 1);
        let zero4 = VarnodeData::new(SpaceId(0), 0, 4);
        let zero8 = VarnodeData::new(SpaceId(0), 0, 8);
        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntSLess,
                seq: seq(0x1000), output: Some(flag),
                inputs: SmallVec::from_slice(&[reg32, zero4]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::IntSLess,
                seq: seq(0x1001), output: Some(flag),
                inputs: SmallVec::from_slice(&[reg64, zero8]),
            }]),
            make_lifted(0x1002, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1002), output: None,
                inputs: SmallVec::from_slice(&[zero8]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("cmp".into(), 0x1000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let output = CEmitter::new().emit_function(&ssa, &structured);
        assert!(output.contains("(int32_t)"), "4-byte SLess must use int32_t cast:\n{}", output);
        assert!(output.contains("(int64_t)"), "8-byte SLess must use int64_t cast:\n{}", output);
        assert!(!output.contains("(int)"), "bare (int) cast leaks implementation-defined width:\n{}", output);
    }

    #[test]
    fn emit_int_sright_casts_to_signed_for_arithmetic_shift() {
        // Plain `a >> b` on an unsigned C type is a logical shift; the
        // previous fallback printed `op_name(...)` and lost the arithmetic
        // shift meaning. Verify the operand is cast to the size-matched
        // signed type so the C compiler emits an arithmetic shift.
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg32 = VarnodeData::new(SpaceId(2), 0x00, 4);
        let imm = VarnodeData::new(SpaceId(0), 3, 4);
        let zero8 = VarnodeData::new(SpaceId(0), 0, 8);
        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntSRight,
                seq: seq(0x1000), output: Some(reg32),
                inputs: SmallVec::from_slice(&[reg32, imm]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001), output: None,
                inputs: SmallVec::from_slice(&[zero8]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("asr".into(), 0x1000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let output = CEmitter::new().emit_function(&ssa, &structured);
        assert!(output.contains("(int32_t)") && output.contains(">> 3"),
            "ASR must cast LHS to int32_t and use >>:\n{}", output);
    }
}
