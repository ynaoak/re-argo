use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

/// Same `linef!` pattern as emit.rs -- write indent + formatted body
/// directly into `self.output`, skipping the intermediate `String`
/// allocation that `self.line(&format!(...))` paid per call.
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

fn empty_u64_map() -> &'static BTreeMap<u64, String> {
    static M: OnceLock<BTreeMap<u64, String>> = OnceLock::new();
    M.get_or_init(BTreeMap::new)
}

pub struct RustEmitter<'a> {
    indent: usize,
    output: String,
    symbol_names: &'a BTreeMap<u64, String>,
    string_literals: &'a BTreeMap<u64, String>,
    /// Per-instruction-address annotation map; mirrors the same
    /// surface CEmitter exposes so callers don't need to track
    /// emitter type to attach analyzer comments. See
    /// `CEmitter::with_annotations` for the contract.
    annotations: Option<&'a BTreeMap<u64, Vec<String>>>,
    /// Per-call-site C-syntax rendering map. Mirror of the C
    /// emitter's `call_renderings`; see `emit.rs` for the rationale.
    call_renderings: Option<&'a BTreeMap<u64, String>>,
    /// Conditions of the blocks the short-circuit merge collapsed (`a || b`), by block.
    conds: Option<&'a rustc_hash::FxHashMap<usize, crate::condition::Cond>>,
    /// Folds a test block's ops into its condition expression while a leaf is printed.
    inliner: crate::condition::Inliner,
    /// Epilogue ops not printed (`emit::epilogue_noise`).
    noise: rustc_hash::FxHashSet<usize>,
    /// Ops folded into their block's own branch condition (WS81): not statements.
    folded: rustc_hash::FxHashSet<usize>,
    /// Per-address emit-once dedup, so multi-op instructions don't
    /// replay the same comment.
    emitted: std::cell::RefCell<std::collections::BTreeSet<u64>>,
}

impl Default for RustEmitter<'static> {
    fn default() -> Self {
        Self::new()
    }
}

impl RustEmitter<'static> {
    pub fn new() -> Self {
        Self {
            indent: 0,
            output: String::new(),
            symbol_names: empty_u64_map(),
            string_literals: empty_u64_map(),
            annotations: None,
            call_renderings: None,
            conds: None,
            inliner: crate::condition::Inliner::default(),
            noise: rustc_hash::FxHashSet::default(),
            folded: rustc_hash::FxHashSet::default(),
            emitted: std::cell::RefCell::new(std::collections::BTreeSet::new()),
        }
    }
}

impl<'a> RustEmitter<'a> {
    /// Borrow form of the constructor -- see `CEmitter::with_maps`.
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
            conds: None,
            inliner: crate::condition::Inliner::default(),
            noise: rustc_hash::FxHashSet::default(),
            folded: rustc_hash::FxHashSet::default(),
            emitted: std::cell::RefCell::new(std::collections::BTreeSet::new()),
        }
    }

    /// Attach per-address annotations. Mirrors
    /// `CEmitter::with_annotations`.
    pub fn with_annotations(
        mut self,
        annotations: &'a BTreeMap<u64, Vec<String>>,
    ) -> Self {
        self.annotations = Some(annotations);
        self
    }

    /// Attach per-call-site C-syntax renderings. Mirror of
    /// `CEmitter::with_call_renderings`.
    pub fn with_call_renderings(
        mut self,
        renderings: &'a BTreeMap<u64, String>,
    ) -> Self {
        self.call_renderings = Some(renderings);
        self
    }

    /// Attach the merged short-circuit conditions (`condition::merge_short_circuits`).
    pub fn with_conditions(mut self, conds: &'a rustc_hash::FxHashMap<usize, crate::condition::Cond>) -> Self {
        self.conds = Some(conds);
        self
    }

    pub fn emit_function(
        &mut self,
        func: &SsaFunction,
        structured: &StructuredBlock,
    ) -> String {
        self.output.clear();
        self.noise = crate::emit::epilogue_noise(func);
        self.folded = (0..func.cfg.blocks.len())
            .filter_map(|b| self.own_condition(func, b))
            .flat_map(|(ops, _)| ops)
            .collect();
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
            if vn.data.space == SpaceId::REGISTER && vn.def_op.is_some_and(|d| !func.ops[d].dead && !self.folded.contains(&d)) {
                let key = (vn.data.offset, vn.data.size);
                if declared.insert(key) {
                    let type_name = size_to_rust_type(vn.data.size);
                    let var_name = reg_name(vn.data.offset, vn.data.size);
                    linef!(self, "let mut {}: {};", var_name, type_name);
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
                negated,
            } => {
                self.emit_basic_block_no_branch(func, *condition_block);
                // an arm whose blocks print nothing (all their ops folded away) needs no `if`
                let then_text = self.render_nested(func, then_body);
                if !then_text.is_empty() {
                    linef!(self, "if {} {{", self.condition_text(func, *condition_block, *negated));
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
                        linef!(self, "if {} {{", self.condition_text(func, *condition_block, negated));
                        self.output.push_str(if negated { &else_text } else { &then_text });
                        self.line("}");
                    }
                    (false, false) => {
                        linef!(self, "if {} {{", self.condition_text(func, *condition_block, false));
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
                // `while c` only when the header has no statements of its own (they run on
                // every iteration), else `loop { stmts; if !c { break; } … }`
                self.indent += 1;
                let mark = self.output.len();
                self.emit_basic_block_no_branch(func, *condition_block);
                let stmts = self.output.split_off(mark);
                self.indent -= 1;
                if stmts.lines().all(|l| l.trim_start().starts_with("//")) {
                    for l in stmts.lines() {
                        self.line(l.trim_start());
                    }
                    linef!(self, "while {} {{", self.condition_text(func, *condition_block, *negated));
                    self.indent += 1;
                } else {
                    self.line("loop {");
                    self.indent += 1;
                    self.output.push_str(&stmts);
                    linef!(self, "if {} {{ break; }}", self.condition_text(func, *condition_block, !*negated));
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
                // Rust has no do-while; emulate with loop + break
                self.line("loop {");
                self.indent += 1;
                self.emit_block(func, body);
                self.emit_basic_block_no_branch(func, *condition_block);
                linef!(self, "if {} {{ break; }}", self.condition_text(func, *condition_block, !*negated));
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
                linef!(self, "while {} {{", self.get_branch_condition(func, *condition_block)
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
                linef!(self, "if {} && {} {{", self.get_branch_condition(func, *left_block),
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
                linef!(self, "if {} || {} {{", self.get_branch_condition(func, *left_block),
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
                let index = func
                    .ops
                    .iter()
                    .rev()
                    .find(|op| op.block == *condition_block && !op.dead && op.opcode == OpCode::BranchInd)
                    .map_or_else(|| self.get_branch_condition(func, *condition_block), |op| self.input_expr(func, op, 0));
                linef!(self, "match {} {{", index);
                self.indent += 1;
                for (vals, body) in cases {
                    let pat: Vec<String> = vals.iter().map(|v| crate::emit::case_label(*v)).collect();
                    linef!(self, "{} => {{", pat.join(" | "));
                    self.indent += 1;
                    self.emit_block(func, body);
                    self.indent -= 1;
                    self.line("}");
                }
                match default {
                    Some(def) => {
                        self.line("_ => {");
                        self.indent += 1;
                        self.emit_block(func, def);
                        self.indent -= 1;
                        self.line("}");
                    }
                    None => self.line("_ => {}"),
                }
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Loop { body, .. } => {
                // the body starts with the header's own code
                self.line("loop {");
                self.indent += 1;
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Goto(target) => {
                // Rust does not have goto; emit as a comment-annotated break/continue placeholder
                linef!(self, "// goto label_{:x}; (unsupported in Rust)", func.cfg.blocks[*target].start_addr);
            }
            StructuredBlock::Handler { landing_pad, note, body } => {
                // reached only by unwinding (WS82)
                linef!(self, "// landing pad 0x{:x}: {}", func.cfg.blocks[*landing_pad].start_addr, note);
                self.line("{");
                self.indent += 1;
                self.emit_block(func, body);
                self.indent -= 1;
                self.line("}");
            }
            StructuredBlock::Break => self.line("break;"),
            StructuredBlock::Continue => self.line("continue;"),
        }
    }

    fn emit_basic_block(&mut self, func: &SsaFunction, block_id: usize) {
        for op in &func.ops {
            // (a folded op only feeds the branch, which prints nothing here)
            if op.dead || op.block != block_id || self.noise.contains(&op.index) || self.folded.contains(&op.index) {
                continue;
            }
            self.emit_annotations_for(op.address);
            if let Some(line) = self.emit_op(func, op) {
                self.line(&line);
            }
        }
    }

    /// Emit any analyzer-supplied annotations for `addr` as `// …`
    /// lines. Dedup against `self.emitted` so several ops lifted
    /// from one instruction don't replay the same comment.
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
            let cleaned = ln.replace(['\n', '\r'], " ");
            linef!(self, "// {}", cleaned);
        }
        self.emitted.borrow_mut().insert(addr);
    }

    fn emit_basic_block_no_branch(&mut self, func: &SsaFunction, block_id: usize) {
        for op in &func.ops {
            if op.dead || op.block != block_id || self.noise.contains(&op.index) || self.folded.contains(&op.index) {
                continue;
            }
            if matches!(op.opcode, OpCode::Branch | OpCode::CBranch) {
                continue;
            }
            // a recovered jump table's `jmp` is the `match` (WS83)
            if op.opcode == OpCode::BranchInd && func.cfg.switches.contains_key(&block_id) {
                continue;
            }
            self.emit_annotations_for(op.address);
            if let Some(line) = self.emit_op(func, op) {
                self.line(&line);
            }
        }
    }

    fn emit_op(&self, func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<String> {
        let out_name = op.output.map(|id| varnode_name(&func.varnodes[id as usize]));

        match op.opcode {
            // phi: same name on every incoming edge, nothing to print
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
                if op.inputs.len() == 2 && op.inputs[0] == op.inputs[1] {
                    // `test r, r`: `r & r` is `r`
                    return Some(format!("{} = {};", dst, a));
                }
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
                // Sign-extend at the source width before casting to i64: a
                // 32-bit value held in u64 as 0xFFFFFFFF must compare as -1,
                // not as +4294967295.
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let ty = size_to_rust_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({} as {} as i64) < ({} as {} as i64);", dst, a, ty, b, ty))
            }
            OpCode::IntSLessEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let ty = size_to_rust_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({} as {} as i64) <= ({} as {} as i64);", dst, a, ty, b, ty))
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
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let ty = size_to_rust_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = (({} as {}) >> {}) as u64;", dst, a, ty, b))
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
                let ty = size_to_rust_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = (({} as {}) / ({} as {})) as u64;", dst, a, ty, b, ty))
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
                let ty = size_to_rust_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = (({} as {}) % ({} as {})) as u64;", dst, a, ty, b, ty))
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
                Some(format!("{} = {}.abs();", dst, a))
            }
            OpCode::FloatSqrt => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {}.sqrt();", dst, a))
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
            OpCode::FloatInt2Float | OpCode::FloatFloat2Float => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let out_size = op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                let ty = if out_size == 4 { "f32" } else { "f64" };
                Some(format!("{} = {} as {};", dst, a, ty))
            }
            OpCode::FloatTrunc => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let out_size = op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                let ty = size_to_rust_signed_type(out_size);
                Some(format!("{} = {} as {};", dst, a, ty))
            }
            OpCode::FloatFloor => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {}.floor();", dst, a))
            }
            OpCode::FloatCeil => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {}.ceil();", dst, a))
            }
            OpCode::FloatRound => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {}.round();", dst, a))
            }
            OpCode::BoolAnd => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} != 0 && {} != 0;", dst, a, b))
            }
            OpCode::BoolOr => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = {} != 0 || {} != 0;", dst, a, b))
            }
            OpCode::BoolXor => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = ({} != 0) != ({} != 0);", dst, a, b))
            }
            OpCode::BoolNegate => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {} == 0;", dst, a))
            }
            // `cmovcc` (WS83, `select`)
            OpCode::Select if op.inputs.len() == 3 => {
                let dst = out_name?;
                let c = self.input_expr(func, op, 0);
                let a = self.input_expr(func, op, 1);
                let b = self.input_expr(func, op, 2);
                Some(format!("{} = if {} != 0 {{ {} }} else {{ {} }};", dst, c, a, b))
            }
            OpCode::IntZExt => {
                // Mask to the source width before widening so high bits of the
                // u64 storage cell don't leak through.
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let src_ty = size_to_rust_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({} as {}) as u64;", dst, a, src_ty))
            }
            OpCode::Piece if op.inputs.len() >= 2 => {
                // PIECE(hi, lo): concatenation with `lo` in the low bytes.
                let dst = out_name?;
                let hi = self.input_expr(func, op, 0);
                let lo = self.input_expr(func, op, 1);
                let lo_sz = func.varnodes[op.inputs[1] as usize].data.size;
                Some(format!("{} = concat({}, {} /* {} bytes */);", dst, hi, lo, lo_sz))
            }
            OpCode::Subpiece if op.inputs.len() >= 2 => {
                // Truncating extract: low `out_size` bytes of `a >> 8k`.
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let k = &func.varnodes[op.inputs[1] as usize].data;
                let out_ty = size_to_rust_type(func.varnodes[op.output.unwrap() as usize].data.size);
                if k.space == SpaceId::CONST {
                    let sh = k.offset * 8;
                    if sh == 0 {
                        Some(format!("{} = ({} as {}) as u64;", dst, a, out_ty))
                    } else {
                        Some(format!("{} = (({} >> {}) as {}) as u64;", dst, a, sh, out_ty))
                    }
                } else {
                    let kexpr = self.input_expr(func, op, 1);
                    Some(format!("{} = (({} >> ({} * 8)) as {}) as u64;", dst, a, kexpr, out_ty))
                }
            }
            OpCode::IntSExt => {
                // Sign-extend from the source width — not from i64 — so a
                // 1-byte 0xFF widens to -1, not +255.
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let src_ty = size_to_rust_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                Some(format!("{} = ({} as {} as i64) as u64;", dst, a, src_ty))
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
                // Same `program.call_renderings` short-circuit as
                // the C emitter — see emit.rs for the rationale.
                // We strip the `@plt` suffix the symbol table uses
                // since Rust identifiers can't contain `@`.
                let assign = crate::emit::call_result(func, op)
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
            OpCode::CallInd => {
                let target = self.input_expr(func, op, 0);
                let args: Vec<String> = (1..op.inputs.len()).map(|i| self.input_expr(func, op, i)).collect();
                let assign = crate::emit::call_result(func, op)
                    .map(|v| format!("{} = ", varnode_name(&func.varnodes[v as usize])))
                    .unwrap_or_default();
                Some(format!("{assign}(*{})({});", target, args.join(", ")))
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
                    Some(format!("{} = __clobbered; // by {}", dst, self.input_expr(func, op, 0)))
                } else if crate::emit::is_merged_call_result(func, op) {
                    None
                } else {
                    Some(format!("{} = __ret; // of {}", dst, self.input_expr(func, op, 0)))
                }
            }
            OpCode::Return => match crate::emit::return_value(func, op) {
                Some(i) => Some(format!("return {};", self.input_expr(func, op, i))),
                None => Some("return;".into()),
            },
            OpCode::Branch => None,
            OpCode::BranchInd => Some(format!("goto *{}; // indirect jump", self.input_expr(func, op, 0))),
            OpCode::CBranch => None,
            OpCode::CallOther => {
                // Tag in the first const input: 3 = int3 (real trap), 0x100+ =
                // named intrinsic (opaque-but-named with intact dataflow, e.g.
                // bsr/pmovmskb), 0 = not-yet-lifted instruction.
                let tag = op
                    .inputs
                    .first()
                    .and_then(|&inp| func.varnodes.get(inp as usize))
                    .filter(|v| v.data.space == SpaceId::CONST)
                    .map(|v| v.data.offset);
                if tag == Some(reargo_core::pcode::intrinsic::NORETURN) {
                    // the marker after a call that never returns (WS81)
                    None
                } else if tag == Some(3) {
                    Some("core::intrinsics::abort();".into())
                } else if let Some(name) = tag.and_then(reargo_core::pcode::intrinsic::name) {
                    let args: Vec<String> = (1..op.inputs.len())
                        .map(|i| self.input_expr(func, op, i))
                        .collect();
                    let call = format!("{}({})", name, args.join(", "));
                    match out_name {
                        Some(dst) => Some(format!("{} = {};", dst, call)),
                        None => Some(format!("{};", call)),
                    }
                } else {
                    Some("unmodeled_insn(); // machine op not yet lifted (dataflow intact)".into())
                }
            }
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
        if let Some(e) = self.inliner.get(func, op.inputs[idx]) {
            return e;
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

    /// Print `body` one level deeper and hand the text back instead of keeping it.
    fn render_nested(&mut self, func: &SsaFunction, body: &StructuredBlock) -> String {
        let mark = self.output.len();
        self.indent += 1;
        self.emit_block(func, body);
        self.indent -= 1;
        self.output.split_off(mark)
    }

    fn condition_text(&self, func: &SsaFunction, block_id: usize, negated: bool) -> String {
        if let Some(c) = self.conds.and_then(|m| m.get(&block_id)) {
            let mut leaf = |b: usize, neg: bool| {
                if b == block_id {
                    self.branch_folded(func, b).render(neg)
                } else {
                    self.inliner.fold(func, b, &|v| varnode_name(&func.varnodes[v as usize]), &|op| self.emit_op(func, op)).render(neg)
                }
            };
            return c.render(negated, &mut leaf);
        }
        self.branch_folded(func, block_id).render(negated)
    }

    /// The block's branch condition with the ops that only compute it folded in (WS81).
    fn own_condition(&self, func: &SsaFunction, block_id: usize) -> Option<(Vec<usize>, crate::condition::Folded)> {
        self.inliner.own_condition(func, block_id, &|v| varnode_name(&func.varnodes[v as usize]), &|op| self.emit_op(func, op))
    }

    fn branch_folded(&self, func: &SsaFunction, block_id: usize) -> crate::condition::Folded {
        self.own_condition(func, block_id)
            .map(|(_, f)| f)
            .unwrap_or_else(|| crate::condition::Folded::plain(self.get_branch_condition(func, block_id)))
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
        crate::emit::return_value(func, op).is_some()
    });

    let return_type = match (has_return_value, func.return_float) {
        (false, _) => None,
        (true, Some(4)) => Some("f32"),
        (true, Some(_)) => Some("f64"),
        (true, None) => Some("u64"),
    };

    // WS78: see `emit::infer_signature`
    if let Some(regs) = &func.signature_params {
        return RustFunctionSignature {
            return_type,
            params: regs
                .iter()
                .map(|r| (reg_name(r.offset, r.size), size_to_rust_type(r.size).to_string()))
                .collect(),
        };
    }

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
    if vn.data.space == SpaceId::UNIQUE && vn.data.offset >= crate::flags::SAVED_BASE {
        // a compared value kept before the compare's result overwrote it (WS82)
        return format!("old_{}", (vn.data.offset - crate::flags::SAVED_BASE) / 0x10 + 1);
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

fn size_to_rust_type(size: u32) -> &'static str {
    match size {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        16 => "u128",
        _ => "()",
    }
}

fn size_to_rust_signed_type(size: u32) -> &'static str {
    match size {
        1 => "i8",
        2 => "i16",
        4 => "i32",
        8 => "i64",
        _ => "i64",
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
        assert_eq!(size_to_rust_type(16), "u128");
        assert_eq!(size_to_rust_type(10), "()");
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

    #[test]
    fn emit_int_sext_sign_extends_from_source_width() {
        // Previously `IntSExt` rendered as `{} as i64 as u64`, which
        // sign-extends from i64 — the source's high bits in the u64 cell
        // already poisoned it. A 1-byte 0xFF should widen to -1, not 255.
        // Verify the source's signed type is in the cast chain.
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let byte_reg = VarnodeData::new(SpaceId(2), 0x00, 1);
        let wide_reg = VarnodeData::new(SpaceId(2), 0x08, 8);
        let zero = VarnodeData::new(SpaceId(0), 0, 8);
        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntSExt,
                seq: seq(0x1000), output: Some(wide_reg),
                inputs: SmallVec::from_slice(&[byte_reg]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001), output: None,
                inputs: SmallVec::from_slice(&[zero]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("sext".into(), 0x1000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let output = RustEmitter::new().emit_function(&ssa, &structured);
        assert!(output.contains("as i8"),
            "1-byte IntSExt must sign-extend via i8 (not bare i64):\n{}", output);
    }

    #[test]
    fn emit_int_sless_sign_extends_from_source_width() {
        // For 4-byte operands, `(a as i64) < (b as i64)` would treat a u32
        // 0xFFFFFFFF as +4294967295 instead of -1. The fix sign-extends at
        // the source width first.
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg32 = VarnodeData::new(SpaceId(2), 0x00, 4);
        let zero4 = VarnodeData::new(SpaceId(0), 0, 4);
        let flag = VarnodeData::new(SpaceId(2), 0x20, 1);
        let zero8 = VarnodeData::new(SpaceId(0), 0, 8);
        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntSLess,
                seq: seq(0x1000), output: Some(flag),
                inputs: SmallVec::from_slice(&[reg32, zero4]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001), output: None,
                inputs: SmallVec::from_slice(&[zero8]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let ssa = SsaFunction::from_cfg("sless".into(), 0x1000, cfg);
        let structured = structure_cfg(&ssa.cfg);
        let output = RustEmitter::new().emit_function(&ssa, &structured);
        assert!(output.contains("as i32 as i64"),
            "4-byte IntSLess must sign-extend via i32 before widening:\n{}", output);
    }
}
