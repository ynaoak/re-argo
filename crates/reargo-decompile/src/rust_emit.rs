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
    /// Temporaries printed inside their readers' expressions, as the C emitter does (WS87;
    /// `inline::candidates`): the defining op by value. Their definitions are in `folded`.
    inlined: std::cell::RefCell<rustc_hash::FxHashMap<crate::condition::ValueKey, usize>>,
    /// The condition of a select / `setcc` folded into it, by the op (WS88, as in C:
    /// `emit::select_conditions`).
    select_conds: rustc_hash::FxHashMap<usize, String>,
    /// The stack slots by name (WS88, `frame`, as in C).
    frame: crate::frame::Frame,
    /// Temporaries printed as the register they are copied to (WS88, as in C).
    coalesced: crate::emit::Coalesced,
    /// `lock cmpxchg` as one compare-and-swap, by its store (WS89, as in C)
    cas: rustc_hash::FxHashMap<usize, crate::cas::Cas>,
    /// the ops a compare-and-swap hides (its load is no reader that has to print)
    cas_hidden: rustc_hash::FxHashSet<usize>,
    /// `fxch` printed as one swap, at its last copy (WS90, `swap::find`), and the copies hidden.
    swaps: rustc_hash::FxHashMap<usize, (crate::ssa::VarId, crate::ssa::VarId)>,
    swap_hidden: rustc_hash::FxHashSet<usize>,
    /// Struct fields and virtual calls (WS91, as in C).
    structs: Option<&'a crate::structs::StructView>,
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
            inlined: Default::default(),
            select_conds: Default::default(),
            frame: Default::default(),
            coalesced: Default::default(),
            cas: Default::default(),
            cas_hidden: Default::default(),
            swaps: Default::default(),
            swap_hidden: Default::default(),
            structs: None,
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
            inlined: Default::default(),
            select_conds: Default::default(),
            frame: Default::default(),
            coalesced: Default::default(),
            cas: Default::default(),
            cas_hidden: Default::default(),
            swaps: Default::default(),
            swap_hidden: Default::default(),
            structs: None,
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

    /// Print struct fields and virtual calls from `view` (WS91, as in C).
    pub fn with_structs(mut self, view: &'a crate::structs::StructView) -> Self {
        self.structs = Some(view);
        self
    }

    /// Attach the merged short-circuit conditions (`condition::merge_short_circuits`).
    pub fn with_conditions(mut self, conds: &'a rustc_hash::FxHashMap<usize, crate::condition::Cond>) -> Self {
        self.conds = Some(conds);
        self
    }

    /// A virtual call printed as `(*obj).vfn_n(…)` (WS91), and the object's text.
    fn member_call_obj(&self, func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<(&crate::structs::VCall, String)> {
        let vc = self.structs?.member_call(func, op)?;
        let obj = self.input_expr(func, op, 1);
        crate::emit::is_identifier(&obj).then_some((vc, obj))
    }

    /// The place `(*base).field_k` of a struct field access (WS91, as `CEmitter::field_access`),
    /// with the field. The base is a variable or another field place.
    fn field_place(&self, func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<(String, crate::structs::Field)> {
        let sv = self.structs?;
        let a = sv.access.get(&op.index)?;
        let addr = *op.inputs.get(1)?;
        let base = match a.add {
            Some(d) => {
                if self.inlined.borrow().get(&crate::condition::value_key(func, addr)) != Some(&d) {
                    return None;
                }
                self.input_expr(func, &func.ops[d], a.base_input)
            }
            None => self.input_expr(func, op, 1),
        };
        // (a field loaded in place prints `unsafe { (*p).field_8 }`: its place is the base)
        let base = match base.strip_prefix("unsafe { ").and_then(|b| b.strip_suffix(" }")) {
            Some(inner) if inner.starts_with("(*") && !inner.contains(" as ") => inner.to_string(),
            _ if crate::emit::is_identifier(&base) => base,
            _ => return None,
        };
        let f = sv.defs[a.def].fields[a.field].clone();
        Some((format!("(*{base}).{}", f.name()), f))
    }

    pub fn emit_function(
        &mut self,
        func: &SsaFunction,
        structured: &StructuredBlock,
    ) -> String {
        self.output.clear();
        self.noise = crate::emit::epilogue_noise(func);
        // WS88: the stack slots by name; the stack pointer updates only they read go (as in C)
        self.frame = crate::frame::Frame::new(func, &|_| true);
        let frame_noise = self.frame.hidden(func, &self.noise);
        self.noise.extend(frame_noise);
        // WS89: `lock cmpxchg` as one statement at its store (as in C)
        let (cas, cas_hidden) = crate::cas::find(func, &self.noise);
        self.noise.extend(cas_hidden.iter().copied());
        self.cas = cas;
        self.cas_hidden = cas_hidden;
        // WS90: `fxch` as one swap
        let (swaps, swap_hidden) = crate::swap::find(func, &self.noise);
        self.noise.extend(swap_hidden.iter().copied());
        self.swaps = swaps;
        self.swap_hidden = swap_hidden;
        // WS87: first, as the conditions fold the expressions printed inline (as in C)
        let inlined = self.inline_temporaries(func);
        self.coalesced = crate::emit::Coalesced::new(func, &self.noise, &inlined);
        self.folded = (0..func.cfg.blocks.len())
            .filter_map(|b| self.own_condition(func, b))
            .flat_map(|(ops, _)| ops)
            .collect();
        // WS88: the conditions of selects and `setcc`s fold like branches (as in C)
        self.select_conds.clear();
        let (conds, hidden) = crate::emit::select_conditions(func, &self.inliner, &|op| self.emit_op(func, op));
        self.folded.extend(hidden);
        self.folded.extend(inlined);
        self.select_conds = conds;
        // WS91: a vtable pointer loaded only for `obj.vfn_n()` calls prints in them (as in C)
        if let Some(sv) = self.structs {
            let inl: rustc_hash::FxHashSet<usize> = self.inlined.borrow().values().copied().collect();
            let vptrs = sv.folded_vptr_loads(func, &|o| inl.contains(&o), &|c| self.member_call_obj(func, &func.ops[c]).is_some());
            self.folded.extend(vptrs);
        }
        let mut sig = infer_signature(func);
        // WS91: a parameter pointing to a struct is typed so
        if let Some(sv) = self.structs {
            for (name, ty) in sig.params.iter_mut() {
                if let Some(d) = sv.param_def(func, name, &|r| reg_name(r.offset, r.size)) {
                    *ty = format!("*mut {}", crate::structs::rust_ident(&sv.defs[d].name));
                }
            }
        }
        // the stack arguments (WS88) after the register parameters
        sig.params.extend(self.frame.slots().filter(|s| s.is_arg()).map(|s| (s.name(), s.rust_type())));
        self.line(&sig.to_rust_declaration(&func.name));
        self.line("{");
        self.indent += 1;
        self.emit_var_declarations(func);
        self.emit_block(func, structured);
        self.indent -= 1;
        self.line("}");
        if !self.cas.is_empty() {
            self.output = crate::cas::fold_into_conditions(&self.output, &|n| format!("let mut {n}: u8;"), crate::cas::RUST_FORMS);
        }
        self.output = crate::flags::renumber_named_flags(&self.output, func);
        self.output.clone()
    }

    fn emit_var_declarations(&mut self, func: &SsaFunction) {
        let mut declared = std::collections::BTreeSet::new();
        // WS91: a register that points to one struct wherever the body assigns it (as in C)
        let typed = match self.structs {
            Some(sv) => sv.register_defs(func, &|d| !func.ops[d].dead && !self.folded.contains(&d) && !self.noise.contains(&d)),
            None => Default::default(),
        };
        for vn in &func.varnodes {
            if vn.data.space == SpaceId::REGISTER
                && vn.def_op.is_some_and(|d| {
                    // (the flag and accumulator of a compare-and-swap print in its statement)
                    !func.ops[d].dead && !self.folded.contains(&d) && (!self.noise.contains(&d) || self.cas_hidden.contains(&d) || self.swap_hidden.contains(&d))
                })
            {
                let key = (vn.data.offset, vn.data.size);
                if declared.insert(key) {
                    let type_name = match (self.structs, typed.get(&vn.data.offset)) {
                        (Some(sv), Some(&d)) if vn.data.size == 8 => format!("*mut {}", crate::structs::rust_ident(&sv.defs[d].name)),
                        _ => size_to_rust_type(vn.data.size).to_string(),
                    };
                    let var_name = reg_name(vn.data.offset, vn.data.size);
                    linef!(self, "let mut {}: {};", var_name, type_name);
                }
            }
        }
        // the stack slots (WS88)
        let slots: Vec<crate::frame::Slot> = self.frame.slots().filter(|s| !s.is_arg()).copied().collect();
        for s in &slots {
            linef!(self, "let mut {}: {};", s.name(), s.rust_type());
        }
        if !declared.is_empty() || !slots.is_empty() {
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
        if self.coalesced.copies.contains(&op.index) {
            return None;
        }
        let out_name = self.coalesced.defs.get(&op.index).cloned().or_else(|| op.output.map(|id| varnode_name(&func.varnodes[id as usize])));

        match op.opcode {
            // phi: same name on every incoming edge, nothing to print
            OpCode::MultiEqual => None,
            OpCode::Copy if self.swaps.contains_key(&op.index) => {
                let (a, b) = self.swaps[&op.index];
                Some(format!("core::mem::swap(&mut {}, &mut {});", varnode_name(&func.varnodes[a as usize]), varnode_name(&func.varnodes[b as usize])))
            }
            // a stack address by its slot (WS88): `rdi = &raw mut local_48;`
            OpCode::Copy | OpCode::IntAdd | OpCode::IntSub
                if op.output.is_some_and(|o| {
                    let d = &func.varnodes[o as usize].data;
                    !(d.space == SpaceId::REGISTER && d.offset == 0x20)
                }) && op.output.and_then(|o| self.frame.address(func, o, true)).is_some() =>
            {
                Some(format!("{} = {};", out_name?, self.frame.address(func, op.output?, true)?))
            }
            OpCode::Copy => {
                let dst = out_name?;
                let src = self.input_expr(func, op, 0);
                Some(format!("{} = {};", dst, src))
            }
            OpCode::IntAdd => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                // `x + 0xfffffffffffffffa` is `x - 6` (WS88, as in C)
                if let Some(k) = op.inputs.get(1).and_then(|&v| crate::emit::negative_constant(&func.varnodes[v as usize].data)) {
                    return Some(format!("{} = {}.wrapping_sub({});", dst, a, crate::emit::small_hex(k)));
                }
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
            OpCode::FloatNan => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {}.is_nan();", dst, a))
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
                let ty = match out_size {
                    4 => "f32",
                    10 => "f80",
                    _ => "f64",
                };
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
                let zero = |i: usize| op.inputs.get(i).is_some_and(|&v| {
                    let d = &func.varnodes[v as usize].data;
                    d.space == SpaceId::CONST && d.offset == 0
                });
                match (zero(0), zero(1)) {
                    (false, true) => return Some(format!("{dst} = {a};")),
                    (true, false) => return Some(format!("{dst} = {b};")),
                    _ => {}
                }
                Some(format!("{} = ({} != 0) != ({} != 0);", dst, a, b))
            }
            OpCode::BoolNegate => {
                let dst = out_name?;
                // a `setcc` whose condition folded (WS88): the negation is the text
                if let Some(e) = self.select_conds.get(&op.index) {
                    return Some(format!("{dst} = ({}) as u8;", crate::emit::strip_outer_parens(e)));
                }
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = {} == 0;", dst, a))
            }
            // `cmovcc` (WS83, `select`); its folded condition (WS88) is a `bool` already
            OpCode::Select if op.inputs.len() == 3 => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 1);
                let b = self.input_expr(func, op, 2);
                if let Some(e) = self.select_conds.get(&op.index) {
                    return Some(format!("{} = if {} {{ {} }} else {{ {} }};", dst, crate::emit::strip_outer_parens(e), a, b));
                }
                let c = self.input_expr(func, op, 0);
                Some(format!("{} = if {} != 0 {{ {} }} else {{ {} }};", dst, c, a, b))
            }
            OpCode::IntZExt => {
                // Mask to the source width before widening so high bits of the
                // u64 storage cell don't leak through.
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let src_ty = size_to_rust_type(func.varnodes[op.inputs[0] as usize].data.size);
                // (to the destination's own width, WS90: `eax = (x as u8) as u32;`, not `as u64`)
                let dst_ty = size_to_rust_type(func.varnodes[op.output? as usize].data.size);
                Some(format!("{} = ({} as {}) as {};", dst, a, src_ty, dst_ty))
            }
            OpCode::Piece if op.inputs.len() >= 2 => {
                // PIECE(hi, lo): concatenation with `lo` in the low bytes.
                let dst = out_name?;
                // a write to a register's low view (WS88, as in C): `al = x` / `xmm0_d = x`
                match crate::emit::view_merge(func, op) {
                    Some(crate::emit::ViewMerge::Keep { view }) => {
                        let lo = self.input_expr(func, op, 1);
                        return (lo != view).then(|| format!("{view} = {lo};"));
                    }
                    Some(crate::emit::ViewMerge::Const(c)) => {
                        let lo = self.input_expr(func, op, 1);
                        let ty = size_to_rust_type(func.varnodes[op.output.unwrap() as usize].data.size);
                        let shifted = c << (8 * func.varnodes[op.inputs[1] as usize].data.size);
                        return Some(if c == 0 {
                            format!("{dst} = {lo} as {ty};")
                        } else {
                            format!("{dst} = 0x{shifted:x} | {lo} as {ty};")
                        });
                    }
                    None => {}
                }
                let hi = self.input_expr(func, op, 0);
                let lo = self.input_expr(func, op, 1);
                let lo_sz = func.varnodes[op.inputs[1] as usize].data.size;
                Some(format!("{} = concat({}, {} /* {} bytes */);", dst, hi, lo, lo_sz))
            }
            OpCode::Subpiece if op.inputs.len() >= 2 => {
                // Truncating extract: low `out_size` bytes of `a >> 8k`.
                let dst = out_name?;
                // the kept upper bytes of a view write, read only by the merge (WS88, as in C)
                if crate::emit::kept_upper_only(func, op) {
                    return None;
                }
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
                let out_size = func.varnodes[op.output.unwrap() as usize].data.size;
                // a stack slot by name (WS88)
                if let Some(slot) = op.inputs.get(1).and_then(|&a| self.frame.access(func, op.block, a, out_size, false, true)) {
                    return Some(match slot.starts_with('*') {
                        true => format!("{dst} = unsafe {{ {slot} }};"),
                        false => format!("{dst} = {};", crate::emit::strip_outer_parens(&slot)),
                    });
                }
                // a struct field (WS91): `unsafe { (*rdi).field_10 }`
                if let Some((place, f)) = self.field_place(func, op) {
                    return Some(if out_size == f.size {
                        format!("{dst} = unsafe {{ {place} }};")
                    } else if f.kind == crate::structs::FieldKind::Int {
                        format!("{dst} = unsafe {{ {place} }} as {};", size_to_rust_type(out_size))
                    } else {
                        format!("{dst} = unsafe {{ *(&raw const {place} as *const {}) }};", size_to_rust_type(out_size))
                    });
                }
                let addr = self.input_expr(func, op, 1);
                let ty = size_to_rust_type(out_size);
                Some(format!(
                    "{} = unsafe {{ *({} as *const {}) }};",
                    dst, addr, ty
                ))
            }
            OpCode::Store if self.cas.contains_key(&op.index) => {
                let c = &self.cas[&op.index];
                let ptr = match self.frame.access(func, op.block, c.addr, c.size, true, true) {
                    Some(slot) if !slot.starts_with('*') => format!("&raw mut {slot}"),
                    _ => format!("{} as *mut {}", self.input_expr(func, op, 1), size_to_rust_type(c.size)),
                };
                let sel = func.varnodes[op.inputs[2] as usize].def_op?;
                let expected = format!("mut {}", varnode_name(&func.varnodes[c.expected as usize]));
                let call = crate::cas::call_text(&ptr, &expected, &self.input_expr(func, &func.ops[sel], 1));
                Some(match c.flag {
                    Some(f) if c.branch => format!("{} = {call};{}", varnode_name(&func.varnodes[f as usize]), crate::cas::FOLDABLE),
                    Some(f) => format!("{} = {call};", varnode_name(&func.varnodes[f as usize])),
                    None => format!("{call};"),
                })
            }
            OpCode::Store => {
                let val = self.input_expr(func, op, 2);
                let size = if op.inputs.len() > 2 {
                    func.varnodes[op.inputs[2] as usize].data.size
                } else {
                    8
                };
                if let Some(slot) = op.inputs.get(1).and_then(|&a| self.frame.access(func, op.block, a, size, true, true)) {
                    return Some(match slot.starts_with('*') {
                        true => format!("unsafe {{ {slot} = {val}; }}"),
                        false => format!("{slot} = {val};"),
                    });
                }
                if let Some((place, f)) = self.field_place(func, op) {
                    return Some(if size == f.size {
                        format!("unsafe {{ {place} = {val}; }}")
                    } else {
                        format!("unsafe {{ *(&raw mut {place} as *mut {}) = {val}; }}", size_to_rust_type(size))
                    });
                }
                let addr = self.input_expr(func, op, 1);
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
                // WS91: `unsafe { (*rdi).vfn_6(rsi) }`, as in C
                if let Some(sv) = self.structs
                    && let Some((vc, obj)) = self.member_call_obj(func, op)
                {
                    let n = vc.slot / 8;
                    let ann = match (vc.target, func.vcall_targets.get(&op.address)) {
                        (Some(t), _) => format!(" // vfn[{n}] (vtable+0x{:x}) = {}", vc.slot, crate::structs::method_name(self.symbol_names, sv.defs[vc.def].class.as_deref(), t)),
                        (None, Some(t)) => format!(" // vfn[{n}] (vtable+0x{:x}) e.g. {}", vc.slot, self.symbol_names.get(t).cloned().unwrap_or_else(|| format!("0x{t:x}"))),
                        (None, None) => format!(" // vfn[{n}] (vtable+0x{:x})", vc.slot),
                    };
                    return Some(format!("{assign}unsafe {{ (*{obj}).vfn_{n}({}) }};{ann}", args[1..].join(", ")));
                }
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
            // the carry / overflow flags of an add or a subtraction, with their operands (WS90)
            OpCode::IntCarry | OpCode::IntSCarry | OpCode::IntSBorrow if op.inputs.len() == 2 => {
                let dst = out_name?;
                let size = func.varnodes[op.inputs[0] as usize].data.size;
                let (ty, method) = match op.opcode {
                    OpCode::IntCarry => (size_to_rust_type(size), "overflowing_add"),
                    OpCode::IntSCarry => (size_to_rust_signed_type(size), "overflowing_add"),
                    _ => (size_to_rust_signed_type(size), "overflowing_sub"),
                };
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                Some(format!("{} = ({} as {}).{}({} as {}).1;", dst, a, ty, method, b, ty))
            }
            _ => {
                let dst = out_name.unwrap_or_else(|| "???".into());
                Some(format!("{} = {}(...);", dst, op.opcode.name()))
            }
        }
    }

    /// Fill `inlined` (see [`crate::inline`]); returns the definitions not to print.
    fn inline_temporaries(&self, func: &SsaFunction) -> Vec<usize> {
        self.inlined.borrow_mut().clear();
        let prints = |u: usize| self.cas_hidden.contains(&u) || (!self.noise.contains(&u) && self.emit_op(func, &func.ops[u]).is_some());
        let prints_operands = |u: usize| {
            let op = &func.ops[u];
            op.opcode == OpCode::CallInd || !self.call_renderings.is_some_and(|r| r.contains_key(&op.address))
        };
        let mut hidden = Vec::new();
        for (d, readers) in crate::inline::candidates(func, &|d| self.noise.contains(&d), &prints_operands) {
            let v = func.ops[d].output.expect("candidate has an output");
            if !readers.iter().all(|&u| prints(u)) {
                continue;
            }
            let Some(text) = self.inline_text(func, d) else { continue };
            if text.len() > crate::emit::MAX_INLINE_LEN || text.contains("//") {
                continue;
            }
            self.inlined.borrow_mut().insert(crate::condition::value_key(func, v), d);
            hidden.push(d);
        }
        hidden
    }

    /// The right-hand side of inlined op `d` as it prints now.
    fn inline_text(&self, func: &SsaFunction, d: usize) -> Option<String> {
        let op = &func.ops[d];
        let line = self.emit_op(func, op)?;
        let prefix = format!("{} = ", varnode_name(&func.varnodes[op.output? as usize]));
        line.strip_prefix(&prefix).and_then(|r| r.strip_suffix(';')).map(str::to_string)
    }

    fn input_expr(&self, func: &SsaFunction, op: &crate::ssa::SsaOp, idx: usize) -> String {
        if idx >= op.inputs.len() {
            return "???".into();
        }
        // a `setcc`'s folded condition (WS88), a whole right-hand side: a `bool` as the byte
        if ((idx == 0 && op.opcode == OpCode::Copy) || (idx == 2 && op.opcode == OpCode::Store))
            && let Some(e) = self.select_conds.get(&op.index)
        {
            return format!("({}) as u8", crate::emit::strip_outer_parens(e));
        }
        if let Some(r) = self.coalesced.values.get(&crate::condition::value_key(func, op.inputs[idx])) {
            return r.clone();
        }
        let inlined = self.inlined.borrow().get(&crate::condition::value_key(func, op.inputs[idx])).copied();
        if let Some(rhs) = inlined.and_then(|d| self.inline_text(func, d)) {
            // a whole right-hand side or an argument needs no parentheses; a method call or an
            // `unsafe { … }` block is one operand already
            let whole = (op.opcode == OpCode::Store && idx == 2)
                || op.opcode == OpCode::Copy
                || (matches!(op.opcode, OpCode::Call | OpCode::CallOther | OpCode::CallInd) && idx > 0);
            let block = rhs.starts_with("unsafe {") && rhs.ends_with('}') && !rhs[1..rhs.len() - 1].contains('}');
            return if whole || block || method_call(&rhs) || crate::condition::is_atomic(&rhs) { rhs } else { format!("({rhs})") };
        }
        if let Some(e) = self.inliner.get(func, op.inputs[idx]) {
            return e;
        }
        let vn = &func.varnodes[op.inputs[idx] as usize];
        // a constant a float op reads is the bits of a float (WS88, as in C): `0.0f32`
        if vn.data.space == SpaceId::CONST
            && crate::emit::is_float_op(op.opcode)
            && let Some(f) = crate::emit::float_literal(vn.data.offset, vn.data.size)
        {
            return match f.strip_suffix('f') {
                Some(t) => format!("{t}f32"),
                None => f,
            };
        }
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
        _ if crate::emit::returns_long_double(func) => Some("f80"),
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
        // a flag value named by what it computes (WS90, `flags::name_flag_webs`)
        (off, 1) if off >= crate::flags::NAMED_FLAG_BASE && crate::flags::named_flag(off).is_some() => crate::flags::named_flag(off).unwrap_or_default(),
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
        // WS89: see `emit::reg_name`
        (off, 10) if (0x1100..0x1180).contains(&off) && off % 0x10 == 0 => format!("st{}", (off - 0x1100) / 0x10),
        (0x10a0, 2) => "fpucw".into(),
        (off, 1) if (0x10a8..0x10ac).contains(&off) => format!("fpu_c{}", off - 0x10a8),
        _ => format!("var_{:x}", offset),
    }
}

/// `x.wrapping_add(y)`: a method call on a name, one operand (WS87).
fn method_call(s: &str) -> bool {
    let Some(open) = s.find('(') else { return false };
    let head = &s[..open];
    if !head.contains('.') || !head.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') || !s.ends_with(')') {
        return false;
    }
    // the parenthesis after the method closes at the end
    let mut depth = 0i32;
    for (i, c) in s.char_indices().skip(open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i == s.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}

pub(crate) fn size_to_rust_type(size: u32) -> &'static str {
    match size {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        16 => "u128",
        // the x87's 80-bit float (no Rust type: `f80` names it, WS89)
        10 => "f80",
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
        assert_eq!(size_to_rust_type(10), "f80");
        assert_eq!(size_to_rust_type(12), "()");
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
