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
    /// Blocks some `goto` jumps to: each gets a `label_<addr>:` line where its code starts
    /// (otherwise the `goto` names a label that is never printed).
    goto_targets: std::collections::BTreeSet<usize>,
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
            goto_targets: std::collections::BTreeSet::new(),
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
            goto_targets: std::collections::BTreeSet::new(),
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
        self.goto_targets.clear();
        collect_goto_targets(structured, &mut self.goto_targets);
        let sig = infer_signature(func);
        self.line(&sig.to_c_declaration(&func.name));
        self.line("{");
        self.indent += 1;
        let params: std::collections::BTreeSet<&str> = sig.params.iter().map(|(_, n)| n.as_str()).collect();
        self.emit_var_declarations(func, &params);
        self.emit_block(func, structured);
        self.indent -= 1;
        self.line("}");
        self.output.clone()
    }

    fn emit_var_declarations(&mut self, func: &SsaFunction, params: &std::collections::BTreeSet<&str>) {
        let mut declared = std::collections::BTreeSet::new();
        for vn in &func.varnodes {
            // only registers the body assigns: a dead definition (most of a call's clobbers,
            // view syncs nobody reads) is not printed, so declaring it is noise
            if vn.data.space == SpaceId::REGISTER && vn.def_op.is_some_and(|d| !func.ops[d].dead) {
                let key = (vn.data.offset, vn.data.size);
                if declared.insert(key) {
                    let type_name = size_to_type(vn.data.size);
                    let var_name = reg_name(vn.data.offset, vn.data.size);
                    if !params.contains(var_name.as_str()) {
                        linef!(self, "{} {};", type_name, var_name);
                    }
                }
            }
        }
        if !declared.is_empty() {
            self.output.push('\n');
        }
    }

    fn emit_block(&mut self, func: &SsaFunction, block: &StructuredBlock) {
        if let Some(first) = leading_block(block) {
            // A label only at the node that starts with the block itself (a `Sequence` / `Goto`
            // has no leading block of its own); removing it prints each label once.
            if self.goto_targets.remove(&first) {
                let indent = self.indent;
                self.indent = indent.saturating_sub(1);
                linef!(self, "label_{:x}:", func.cfg.blocks[first].start_addr);
                self.indent = indent;
            }
        }
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
                negated,
            } => {
                self.emit_basic_block_no_branch(func, *condition_block);
                // an arm whose blocks print nothing (all their ops folded away) needs no `if`
                let then_text = self.render_nested(func, then_body);
                if !then_text.is_empty() {
                    linef!(self, "if ({}) {{", self.condition_text(func, *condition_block, *negated));
                    self.output.push_str(&then_text);
                    self.line("}");
                }
            }
            StructuredBlock::IfThenElse {
                condition_block,
                then_body,
                else_body,
            } => {
                self.emit_basic_block_no_branch(func, *condition_block);
                let then_text = self.render_nested(func, then_body);
                let else_text = self.render_nested(func, else_body);
                match (then_text.is_empty(), else_text.is_empty()) {
                    (true, true) => {}
                    (false, true) | (true, false) => {
                        let negated = then_text.is_empty();
                        linef!(self, "if ({}) {{", self.condition_text(func, *condition_block, negated));
                        self.output.push_str(if negated { &else_text } else { &then_text });
                        self.line("}");
                    }
                    (false, false) => {
                        linef!(self, "if ({}) {{", self.condition_text(func, *condition_block, false));
                        self.output.push_str(&then_text);
                        self.line("} else {");
                        self.output.push_str(&else_text);
                        self.line("}");
                    }
                }
            }
            StructuredBlock::WhileLoop {
                condition_block,
                body,
                negated,
            } => {
                // the header's statements run on every iteration: `while (c)` only when it
                // has none, else `while (true) { stmts; if (!c) break; … }`
                self.indent += 1;
                let mark = self.output.len();
                self.emit_basic_block_no_branch(func, *condition_block);
                let stmts = self.output.split_off(mark);
                self.indent -= 1;
                let code_free = stmts.lines().all(|l| l.trim_start().starts_with("//"));
                if code_free {
                    for l in stmts.lines() {
                        self.line(l.trim_start());
                    }
                    linef!(self, "while ({}) {{", self.condition_text(func, *condition_block, *negated));
                    self.indent += 1;
                } else {
                    self.line("while (true) {");
                    self.indent += 1;
                    self.output.push_str(&stmts);
                    linef!(self, "if ({}) break;", self.condition_text(func, *condition_block, !*negated));
                }
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::DoWhileLoop {
                body,
                condition_block,
                negated,
            } => {
                self.line("do {");
                self.indent += 1;
                self.emit_block(func, body);
                if self.goto_targets.remove(condition_block) {
                    let indent = self.indent;
                    self.indent = indent.saturating_sub(1);
                    linef!(self, "label_{:x}:", func.cfg.blocks[*condition_block].start_addr);
                    self.indent = indent;
                }
                self.emit_basic_block_no_branch(func, *condition_block);
                self.indent -= 1;
                linef!(self, "}} while ({});", self.condition_text(func, *condition_block, *negated));
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
            StructuredBlock::Loop { body, .. } => {
                // the body starts with the header's own code
                self.line("while (true) {");
                self.indent += 1;
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Goto(target) => {
                linef!(self, "goto label_{:x};", func.cfg.blocks[*target].start_addr);
            }
            StructuredBlock::Break => self.line("break;"),
            StructuredBlock::Continue => self.line("continue;"),
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
            // A phi joins versions of one register / slot, which the C output
            // names identically — nothing to print.
            OpCode::MultiEqual => None,
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
            OpCode::Piece if op.inputs.len() >= 2 => {
                // PIECE(hi, lo): concatenation, `lo` in the low bytes (the
                // lifter uses it to merge a scalar SSE result into the full
                // XMM register). Previously the opaque `PIECE(...)`.
                let dst = out_name?;
                let hi = self.input_expr(func, op, 0);
                let lo = self.input_expr(func, op, 1);
                let lo_sz = func.varnodes[op.inputs[1] as usize].data.size;
                Some(format!("{} = CONCAT({}, {}:{});", dst, hi, lo, lo_sz))
            }
            OpCode::Subpiece if op.inputs.len() >= 2 => {
                // SUBPIECE(a, k) = the low `out_size` bytes of `a >> 8k` — a
                // truncating cast (e.g. `ecx = (uint32_t)rcx` after a 64-bit
                // write). Previously printed as the opaque `SUBPIECE(...)`.
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let k = &func.varnodes[op.inputs[1] as usize].data;
                let dst_ty = size_to_type(func.varnodes[op.output.unwrap() as usize].data.size);
                if k.space == SpaceId::CONST && k.offset == 0 {
                    Some(format!("{} = ({}){};", dst, dst_ty, a))
                } else if k.space == SpaceId::CONST {
                    Some(format!("{} = ({})({} >> {});", dst, dst_ty, a, k.offset * 8))
                } else {
                    let kexpr = self.input_expr(func, op, 1);
                    Some(format!("{} = ({})({} >> ({} * 8));", dst, dst_ty, a, kexpr))
                }
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
                let assign = call_result(func, op)
                    .map(|v| format!("{} = ", varnode_name(&func.varnodes[v as usize])))
                    .unwrap_or_default();
                if let Some(renderings) = self.call_renderings
                    && let Some(rendering) = renderings.get(&op.address)
                {
                    return Some(format!("{assign}{};", rendering));
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
                let args: Vec<String> = (1..op.inputs.len()).map(|i| self.input_expr(func, op, i)).collect();
                Some(format!("{assign}{}({});", call_name, args.join(", ")))
            }
            OpCode::Indirect => {
                // a call's return register, or a caller-saved register it clobbers
                // (see `pipeline::apply_call_convention`)
                let dst = out_name?;
                let clobber = op.inputs.get(1).is_some_and(|&v| {
                    let d = &func.varnodes[v as usize].data;
                    d.space == reargo_core::address::SpaceId::CONST && d.offset == crate::pipeline::CLOBBER_MARK
                });
                if clobber {
                    Some(format!("{} = __clobbered;  // by {}", dst, self.input_expr(func, op, 0)))
                } else if is_merged_call_result(func, op) {
                    None // printed as `dst = call(…)`
                } else {
                    Some(format!("{} = __ret;  // of {}", dst, self.input_expr(func, op, 0)))
                }
            }
            OpCode::CallInd => {
                // Indirect / virtual call: render the resolved target (a
                // function pointer or `*(vtable+offset)` deref) so C++ virtual
                // dispatch is visible instead of `call 0x0`. When the target is
                // a `[obj_vtable + offset]` load, annotate the vtable index —
                // the single most useful hint for C++ virtual-method RE.
                let target = self.input_expr(func, op, 0);
                let ann = op
                    .inputs
                    .first()
                    .and_then(|&t| self.vcall_vtable_offset(func, t))
                    .map(|off| format!("  // vfn[{}] (vtable+0x{:x})", off / 8, off))
                    .unwrap_or_default();
                let args: Vec<String> = (1..op.inputs.len()).map(|i| self.input_expr(func, op, i)).collect();
                let assign = call_result(func, op)
                    .map(|v| format!("{} = ", varnode_name(&func.varnodes[v as usize])))
                    .unwrap_or_default();
                // WS79: an implementation of the slot, from the vtable of a class the function
                // is a method of
                let ann = match func.vcall_targets.get(&op.address) {
                    Some(t) => {
                        let name = self.symbol_names.get(t).cloned().unwrap_or_else(|| format!("0x{t:x}"));
                        if ann.is_empty() { format!("  // e.g. {name}") } else { format!("{ann} e.g. {name}") }
                    }
                    None => ann,
                };
                Some(format!("{assign}(*{})({});{}", target, args.join(", "), ann))
            }
            OpCode::Return => match return_value(func, op) {
                Some(i) => Some(format!("return {};", self.input_expr(func, op, i))),
                None => Some("return;".into()),
            },
            OpCode::Branch => None,
            OpCode::CBranch => None,
            OpCode::BranchInd => {
                // jump table / PLT stub / tail call through a function pointer
                let ann = op
                    .inputs
                    .first()
                    .and_then(|&t| self.vcall_vtable_offset(func, t))
                    .map(|off| format!("  // vfn[{}] (vtable+0x{:x})", off / 8, off))
                    .unwrap_or_else(|| "  // indirect jump".into());
                Some(format!("goto *{};{}", self.input_expr(func, op, 0), ann))
            }
            OpCode::CallOther => {
                // The lifter tags CallOther via its first const input: 3 = int3
                // (a real breakpoint/trap), 0x100+ = a named intrinsic (a known
                // op kept opaque but with intact dataflow, e.g. bsr/pmovmskb),
                // 0 = a not-yet-lifted instruction. Render each honestly rather
                // than as `__builtin_trap()` (which falsely implied a crash).
                let tag = op
                    .inputs
                    .first()
                    .and_then(|&inp| func.varnodes.get(inp as usize))
                    .filter(|v| v.data.space == SpaceId::CONST)
                    .map(|v| v.data.offset);
                if tag == Some(3) {
                    Some("__builtin_trap();".into())
                } else if let Some(name) = tag.and_then(reargo_core::pcode::intrinsic::name) {
                    // `out = name(operands…)` — the operands are inputs[1..].
                    let args: Vec<String> = (1..op.inputs.len())
                        .map(|i| self.input_expr(func, op, i))
                        .collect();
                    let call = format!("{}({})", name, args.join(", "));
                    match out_name {
                        Some(dst) => Some(format!("{} = {};", dst, call)),
                        None => Some(format!("{};", call)),
                    }
                } else {
                    Some("__unmodeled_insn();  // machine op not yet lifted (dataflow intact)".into())
                }
            }
            _ => {
                let dst = out_name.unwrap_or_else(|| "???".into());
                Some(format!("{} = {}(...);", dst, op.opcode.name()))
            }
        }
    }

    /// If `target` (a CALLIND callee) is a Load of `[base + const]` — the
    /// classic C++ virtual dispatch `*(this_vtable + vfn_offset)` — return the
    /// constant byte offset into the vtable. Traces two SSA defs: the Load,
    /// then the IntAdd that formed its address.
    fn vcall_vtable_offset(&self, func: &SsaFunction, target: crate::ssa::VarId) -> Option<u64> {
        let tvn = func.varnodes.get(target as usize)?;
        let load = func.ops.get(tvn.def_op?)?;
        if load.opcode != OpCode::Load || load.inputs.len() < 2 {
            return None;
        }
        let avn = func.varnodes.get(load.inputs[1] as usize)?;
        let add = func.ops.get(avn.def_op?)?;
        if add.opcode != OpCode::IntAdd {
            return None;
        }
        for &inp in add.inputs.iter() {
            if let Some(v) = func.varnodes.get(inp as usize)
                && v.data.space == SpaceId::CONST
            {
                let off = v.data.offset;
                // A real vtable slot offset is small and pointer-aligned;
                // anything else (e.g. `config_ptr + base`) is not a vfn index.
                if off > 0 && off < 0x4000 && off % 8 == 0 {
                    return Some(off);
                }
                return None;
            }
        }
        None
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

    /// The branch condition of `block_id`, inverted when `negated`.
    /// Print `body` one level deeper and hand the text back instead of keeping it.
    fn render_nested(&mut self, func: &SsaFunction, body: &StructuredBlock) -> String {
        let mark = self.output.len();
        self.indent += 1;
        self.emit_block(func, body);
        self.indent -= 1;
        self.output.split_off(mark)
    }

    fn condition_text(&self, func: &SsaFunction, block_id: usize, negated: bool) -> String {
        negate_condition(self.get_branch_condition(func, block_id), negated)
    }

    fn line(&mut self, text: &str) {
        for _ in 0..self.indent {
            self.output.push_str("    ");
        }
        self.output.push_str(text);
        self.output.push('\n');
    }
}


/// The register a call's result is used in, when exactly one of the return registers the
/// call defines (its non-clobber `INDIRECT`s, right after it) is still live (WS79): the
/// caller's use decides which register the callee returned in, and the call prints as
/// `xmm0 = f(…)` instead of `f(…); xmm0 = __ret;`.
pub(crate) fn call_result(func: &SsaFunction, call: &crate::ssa::SsaOp) -> Option<crate::ssa::VarId> {
    let live: Vec<crate::ssa::VarId> = func.ops[call.index + 1..]
        .iter()
        .take_while(|o| o.address == call.address && o.block == call.block)
        .filter(|o| o.opcode == OpCode::Indirect && !o.dead && !is_clobber(func, o))
        .filter_map(|o| o.output)
        .collect();
    match live.as_slice() {
        [v] => Some(*v),
        // both `rax` and `xmm0` look live: the one whose value is really read (not only the
        // upper lanes the lifter carries over when a later scalar write rebuilds the register)
        [_, _, ..] => {
            let real: Vec<_> = live.iter().copied().filter(|&v| really_used(func, v, 0)).collect();
            (real.len() == 1).then(|| real[0])
        }
        [] => None,
    }
}

/// Is the value of `v` read by something other than the lifter's register view syncs (a
/// `SUBPIECE` of its upper bytes, the high half of a `PIECE`)?
fn really_used(func: &SsaFunction, v: crate::ssa::VarId, depth: u32) -> bool {
    if depth > 4 {
        return true;
    }
    func.varnodes[v as usize].uses.iter().any(|&u| {
        let op = &func.ops[u];
        if op.dead {
            return false;
        }
        match op.opcode {
            OpCode::Subpiece => {
                let k = op.inputs.get(1).map(|&c| func.varnodes[c as usize].data);
                match k {
                    Some(k) if k.space == SpaceId::CONST && k.offset > 0 => false,
                    _ => op.output.is_some_and(|o| really_used(func, o, depth + 1)),
                }
            }
            OpCode::Piece => op.inputs.get(1) == Some(&v),
            _ => true,
        }
    })
}

fn is_clobber(func: &SsaFunction, op: &crate::ssa::SsaOp) -> bool {
    op.inputs.get(1).is_some_and(|&v| {
        let d = &func.varnodes[v as usize].data;
        d.space == SpaceId::CONST && d.offset == crate::pipeline::CLOBBER_MARK
    })
}

/// Is `op` (a call's return `INDIRECT`) printed as part of its call (`call_result`)?
pub(crate) fn is_merged_call_result(func: &SsaFunction, op: &crate::ssa::SsaOp) -> bool {
    let call = func.ops[..op.index]
        .iter()
        .rev()
        .take_while(|o| o.address == op.address && o.block == op.block)
        .find(|o| matches!(o.opcode, OpCode::Call | OpCode::CallInd) && !o.dead);
    call.is_some_and(|c| call_result(func, c) == op.output)
}

/// `cond` inverted when `negated`: `!x` for a plain name, `!(…)` otherwise.
pub(crate) fn negate_condition(cond: String, negated: bool) -> String {
    if !negated {
        cond
    } else if cond.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        format!("!{cond}")
    } else {
        format!("!({cond})")
    }
}

struct FunctionSignature {
    return_type: &'static str,
    params: Vec<(String, String)>,
}

/// Every block a `Goto` in the tree jumps to.
fn collect_goto_targets(block: &StructuredBlock, out: &mut std::collections::BTreeSet<usize>) {
    use StructuredBlock::*;
    match block {
        Goto(t) => {
            out.insert(*t);
        }
        Basic(_) | Break | Continue => {}
        Sequence(xs) => xs.iter().for_each(|b| collect_goto_targets(b, out)),
        IfThen { then_body, .. } => collect_goto_targets(then_body, out),
        IfThenElse { then_body, else_body, .. } => {
            collect_goto_targets(then_body, out);
            collect_goto_targets(else_body, out);
        }
        WhileLoop { body, .. }
        | DoWhileLoop { body, .. }
        | ForLoop { body, .. }
        | ShortCircuitAnd { body, .. }
        | ShortCircuitOr { body, .. }
        | Loop { body, .. } => collect_goto_targets(body, out),
        Switch { cases, default, .. } => {
            cases.iter().for_each(|(_, b)| collect_goto_targets(b, out));
            if let Some(d) = default {
                collect_goto_targets(d, out);
            }
        }
    }
}

/// The block whose code a structured node prints first, for nodes that print one themselves.
/// `None` for a `Sequence` (its first child carries the label) and a `Goto`.
fn leading_block(block: &StructuredBlock) -> Option<usize> {
    use StructuredBlock::*;
    match block {
        Basic(b) => Some(*b),
        IfThen { condition_block, .. }
        | IfThenElse { condition_block, .. }
        | WhileLoop { condition_block, .. }
        | Switch { condition_block, .. } => Some(*condition_block),
        ForLoop { init_block, .. } => Some(*init_block),
        ShortCircuitAnd { left_block, .. } | ShortCircuitOr { left_block, .. } => Some(*left_block),
        Loop { header, .. } => Some(*header),
        DoWhileLoop { body, .. } => leading_block(body),
        Sequence(_) | Goto(_) | Break | Continue => None,
    }
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

/// The value a `RETURN` hands back, if any (WS77). A lifted x86-64 `ret` is
/// `RETURN(target, rax)` (`pipeline::apply_call_convention` appends the return register):
/// the value is the second input, and it is no value when that register still holds what the
/// function was entered with (nothing on the path set it). A one-input `RETURN` counts as
/// returning its input only when that is `rax` itself (hand-built p-code in tests).
/// Returns the index of that input.
pub(crate) fn return_value(func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<usize> {
    let reg_set = |v: u32| {
        let vn = &func.varnodes[v as usize];
        !(vn.data.space == SpaceId::REGISTER && vn.def_op.is_none())
    };
    match op.inputs.as_slice() {
        [_, v, ..] => reg_set(*v).then_some(1),
        [v] => {
            let d = &func.varnodes[*v as usize].data;
            (d.space == SpaceId::REGISTER && d.offset == 0x00).then_some(0)
        }
        [] => None,
    }
}

fn infer_signature(func: &SsaFunction) -> FunctionSignature {
    let has_return_value = func.ops.iter().any(|op| {
        if op.dead || op.opcode != OpCode::Return {
            return false;
        }
        return_value(func, op).is_some()
    });

    let return_type = match (has_return_value, func.return_float) {
        (false, _) => "void",
        (true, Some(4)) => "float",
        (true, Some(_)) => "double",
        (true, None) => "uint64_t",
    };

    // WS78: the parameters the analysis of the function's entry found, named like the
    // registers the body reads (`rdi`, `xmm0`)
    if let Some(regs) = &func.signature_params {
        return FunctionSignature {
            return_type,
            params: regs
                .iter()
                .map(|r| (size_to_type(r.size).to_string(), reg_name(r.offset, r.size)))
                .collect(),
        };
    }

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
        // the 16/8-bit views of rcx..rdi (WS78): they used to fall through to `var_<off>`,
        // so `bp` and `bpl` both became `var_28` (two declarations of one name, and a name
        // that reads like a stack local)
        (0x08, 2) => "cx".into(),
        (0x08, 1) => "cl".into(),
        (0x10, 2) => "dx".into(),
        (0x10, 1) => "dl".into(),
        (0x18, 2) => "bx".into(),
        (0x18, 1) => "bl".into(),
        (0x20, 2) => "sp".into(),
        (0x20, 1) => "spl".into(),
        (0x28, 2) => "bp".into(),
        (0x28, 1) => "bpl".into(),
        (0x30, 2) => "si".into(),
        (0x30, 1) => "sil".into(),
        (0x38, 2) => "di".into(),
        (0x38, 1) => "dil".into(),
        // r8..r15 (offsets 0x80..0xB8): r12-r15 used to fall through to
        // `var_a0`..`var_b8`, indistinguishable from stack locals.
        (off, sz) if (0x80..0xC0).contains(&off) && off % 8 == 0 => {
            let n = 8 + (off - 0x80) / 8;
            match sz {
                8 => format!("r{}", n),
                4 => format!("r{}d", n),
                2 => format!("r{}w", n),
                1 => format!("r{}b", n),
                _ => format!("r{}_{}", n, sz),
            }
        }
        // XMM register file (base 0x1200, stride 0x10). Scalar sd/ss views
        // share the offset, so name by offset regardless of size.
        (off, sz) if (0x1200..0x1300).contains(&off) && off % 0x10 == 0 => {
            // Full register = `xmmN`; the scalar views get a suffix so a
            // view refresh reads `xmm0_d = (uint32_t)xmm0`, not `xmm0 = xmm0`.
            let n = (off - 0x1200) / 0x10;
            match sz {
                16 => format!("xmm{}", n),
                8 => format!("xmm{}_q", n),
                4 => format!("xmm{}_d", n),
                _ => format!("xmm{}_{}", n, sz),
            }
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
        // an XMM register / 128-bit memory access (it printed `void xmm0;`, `*(void*)p = ..`)
        16 => "uint128_t",
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
    fn emit_subpiece_as_truncating_cast() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let ecx = VarnodeData::new(SpaceId(2), 0x08, 4);
        let dx = VarnodeData::new(SpaceId(2), 0x10, 2);
        let k0 = VarnodeData::new(SpaceId(0), 0, 4);
        let k4 = VarnodeData::new(SpaceId(0), 4, 4);
        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::Subpiece,
                seq: seq(0x1000), output: Some(ecx),
                inputs: SmallVec::from_slice(&[rcx, k0]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Subpiece,
                seq: seq(0x1001), output: Some(dx),
                inputs: SmallVec::from_slice(&[rcx, k4]),
            }]),
            make_lifted(0x1002, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1002), output: None,
                inputs: SmallVec::from_slice(&[ecx, dx]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("sp".into(), 0x1000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let output = CEmitter::new().emit_function(&ssa, &structured);
        assert!(!output.contains("SUBPIECE("), "opaque fallback leaked:
{}", output);
        assert!(output.contains("(uint32_t)"), "low-dword cast:
{}", output);
        assert!(output.contains(">> 32"), "byte offset 4 = shift 32:
{}", output);
    }

    #[test]
    fn reg_names_cover_r8_r15_and_xmm_views() {
        assert_eq!(reg_name(0xA0, 8), "r12");
        assert_eq!(reg_name(0xB8, 8), "r15");
        assert_eq!(reg_name(0x80, 4), "r8d");
        assert_eq!(reg_name(0xB0, 1), "r14b");
        assert_eq!(reg_name(0x1200, 16), "xmm0");
        assert_eq!(reg_name(0x1210, 8), "xmm1_q");
        assert_eq!(reg_name(0x1220, 4), "xmm2_d");
        assert_eq!(reg_name(0x00, 8), "rax");
    }

    #[test]
    fn emit_piece_as_concat() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let x16 = VarnodeData::new(SpaceId(2), 0x1200, 16);
        let x4 = VarnodeData::new(SpaceId(2), 0x1200, 4);
        let hi = VarnodeData::new(SpaceId(3), 0x7f00, 8);
        let zero8 = VarnodeData::new(SpaceId(0), 0, 8);
        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::Piece,
                seq: seq(0x1000), output: Some(x16),
                inputs: SmallVec::from_slice(&[hi, x4]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001), output: None,
                inputs: SmallVec::from_slice(&[zero8, x16]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("pc".into(), 0x1000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let output = CEmitter::new().emit_function(&ssa, &structured);
        assert!(!output.contains("PIECE("), "opaque fallback leaked:
{}", output);
        assert!(output.contains("CONCAT("), "concat form:
{}", output);
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
