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
    /// Conditions of the blocks the short-circuit merge collapsed (`a || b`), by block.
    conds: Option<&'a rustc_hash::FxHashMap<usize, crate::condition::Cond>>,
    /// Folds a test block's ops into its condition expression while a leaf is printed.
    inliner: crate::condition::Inliner,
    /// Track which addresses we've already emitted annotations for,
    /// so multi-op instructions don't repeat the same comment.
    emitted: std::cell::RefCell<std::collections::BTreeSet<u64>>,
    /// Blocks some `goto` jumps to: each gets a `label_<addr>:` line where its code starts
    /// (otherwise the `goto` names a label that is never printed).
    goto_targets: std::collections::BTreeSet<usize>,
    /// Epilogue ops not printed (`epilogue_noise`).
    noise: rustc_hash::FxHashSet<usize>,
    /// Ops folded into their block's own branch condition (WS81): not statements.
    folded: rustc_hash::FxHashSet<usize>,
    /// The condition of a select (`cmovcc`) folded into it (WS83): the comparison's text, by
    /// the value it computes. Its op is in `folded`.
    /// a select's folded condition, by the select op (WS84: by op, not by value — two selects
    /// on one flag can see its operands in different states)
    select_conds: rustc_hash::FxHashMap<usize, String>,
    /// Temporaries printed inside their readers' expressions (WS86, `inline::candidates`): the
    /// defining op by value, rendered where it is read (so a condition folding the values it
    /// reads folds them there too). Their definitions are in `folded`.
    inlined: std::cell::RefCell<rustc_hash::FxHashMap<crate::condition::ValueKey, usize>>,
    /// The stack slots by name (WS87, `frame`).
    frame: crate::frame::Frame,
    /// A temporary printed as the register it is copied to (WS88, `inline::coalesced`).
    coalesced: Coalesced,
    /// `lock cmpxchg` printed as one compare-and-swap, by its store (WS89, `cas::find`).
    cas: rustc_hash::FxHashMap<usize, crate::cas::Cas>,
    /// the ops a compare-and-swap hides (its load is no reader that has to print)
    cas_hidden: rustc_hash::FxHashSet<usize>,
    /// `fxch` printed as one swap, at its last copy (WS90, `swap::find`), and the copies hidden.
    swaps: rustc_hash::FxHashMap<usize, (crate::ssa::VarId, crate::ssa::VarId)>,
    swap_hidden: rustc_hash::FxHashSet<usize>,
    /// Struct fields and virtual calls (WS91, `structs`); `None`: every access prints raw.
    structs: Option<&'a crate::structs::StructView>,
}

/// Temporaries printed as the register they are copied to (WS88, `inline::coalesced`): the
/// definition by op, the value by key, and the copies printing nothing.
#[derive(Default)]
pub(crate) struct Coalesced {
    pub defs: rustc_hash::FxHashMap<usize, String>,
    pub values: rustc_hash::FxHashMap<crate::condition::ValueKey, String>,
    pub copies: rustc_hash::FxHashSet<usize>,
}

impl Coalesced {
    /// Fill from `inline::coalesced` (definitions in `inlined` print inside their readers).
    pub(crate) fn new(func: &SsaFunction, noise: &rustc_hash::FxHashSet<usize>, inlined: &[usize]) -> Self {
        let inl: rustc_hash::FxHashSet<usize> = inlined.iter().copied().collect();
        let mut c = Coalesced::default();
        for (d, copy) in crate::inline::coalesced(func, &|d| noise.contains(&d), &|d| inl.contains(&d)) {
            let reg = varnode_name(&func.varnodes[func.ops[copy].output.expect("a copy") as usize]);
            let v = func.ops[d].output.expect("a definition");
            c.values.insert(crate::condition::value_key(func, v), reg.clone());
            c.defs.insert(d, reg);
            c.copies.insert(copy);
        }
        c
    }
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
            conds: None,
            inliner: crate::condition::Inliner::default(),
            select_conds: Default::default(),
            inlined: Default::default(),
            emitted: std::cell::RefCell::new(std::collections::BTreeSet::new()),
            goto_targets: std::collections::BTreeSet::new(),
            noise: rustc_hash::FxHashSet::default(),
            folded: rustc_hash::FxHashSet::default(),
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
            conds: None,
            inliner: crate::condition::Inliner::default(),
            select_conds: Default::default(),
            inlined: Default::default(),
            emitted: std::cell::RefCell::new(std::collections::BTreeSet::new()),
            goto_targets: std::collections::BTreeSet::new(),
            noise: rustc_hash::FxHashSet::default(),
            folded: rustc_hash::FxHashSet::default(),
            frame: Default::default(),
            coalesced: Default::default(),
            cas: Default::default(),
            cas_hidden: Default::default(),
            swaps: Default::default(),
            swap_hidden: Default::default(),
            structs: None,
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

    /// Print struct fields and virtual calls from `view` (WS91).
    pub fn with_structs(mut self, view: &'a crate::structs::StructView) -> Self {
        self.structs = Some(view);
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
        self.goto_targets.clear();
        collect_goto_targets(structured, &mut self.goto_targets);
        self.noise = epilogue_noise(func);
        // WS87: the stack slots by name; the stack pointer updates only they read go
        self.frame = crate::frame::Frame::new(func, &|_| true);
        let frame_noise = self.frame.hidden(func, &self.noise);
        self.noise.extend(frame_noise);
        // WS89: `lock cmpxchg` as one statement at its store
        let (cas, cas_hidden) = crate::cas::find(func, &self.noise);
        self.noise.extend(cas_hidden.iter().copied());
        self.cas = cas;
        self.cas_hidden = cas_hidden;
        // WS90: `fxch` as one swap
        let (swaps, swap_hidden) = crate::swap::find(func, &self.noise);
        self.noise.extend(swap_hidden.iter().copied());
        self.swaps = swaps;
        self.swap_hidden = swap_hidden;
        // WS86: first, as the conditions and selects fold the expressions printed inline
        let inlined = self.inline_temporaries(func);
        // WS88: a temporary copied to a register and read again by stores prints as that register
        self.coalesced = Coalesced::new(func, &self.noise, &inlined);
        self.folded = (0..func.cfg.blocks.len())
            .filter_map(|b| self.own_condition(func, b))
            .flat_map(|(ops, _)| ops)
            .collect();
        self.select_conds.clear();
        let (conds, hidden) = select_conditions(func, &self.inliner, &|op| self.emit_op(func, op));
        self.folded.extend(hidden);
        self.folded.extend(inlined);
        self.select_conds = conds;
        // WS91: a vtable pointer loaded only for `obj->vfn_n()` calls prints in them
        if let Some(sv) = self.structs {
            let inl: rustc_hash::FxHashSet<usize> = self.inlined.borrow().values().copied().collect();
            let vptrs = sv.folded_vptr_loads(func, &|o| inl.contains(&o), &|c| self.member_call(func, &func.ops[c]).is_some());
            self.folded.extend(vptrs);
        }
        let mut sig = infer_signature(func);
        // WS91: a parameter pointing to a struct is typed so
        if let Some(sv) = self.structs {
            for (ty, name) in sig.params.iter_mut() {
                if let Some(d) = sv.param_def(func, name, &|r| reg_name(r.offset, r.size)) {
                    *ty = format!("struct {}*", sv.defs[d].name);
                }
            }
        }
        // the stack arguments (WS88) after the register parameters
        sig.params.extend(self.frame.slots().filter(|s| s.is_arg()).map(|s| match s.c_declaration().rsplit_once(' ') {
            Some((ty, name)) => (ty.to_string(), name.to_string()),
            None => (String::new(), s.c_declaration()),
        }));
        self.line(&sig.to_c_declaration(&func.name));
        self.line("{");
        self.indent += 1;
        let params: std::collections::BTreeSet<&str> = sig.params.iter().map(|(_, n)| n.as_str()).collect();
        self.emit_var_declarations(func, &params);
        self.emit_block(func, structured);
        self.indent -= 1;
        self.line("}");
        // WS89: a compare-and-swap's flag read only by the next condition goes into it
        if !self.cas.is_empty() {
            self.output = crate::cas::fold_into_conditions(
                &self.output,
                &|n| if n.starts_with("var_") { format!("uint8_t {n};") } else { format!("bool {n};") },
                crate::cas::C_FORMS,
            );
        }
        self.output = crate::flags::renumber_named_flags(&self.output, func);
        self.output.clone()
    }

    fn emit_var_declarations(&mut self, func: &SsaFunction, params: &std::collections::BTreeSet<&str>) {
        let mut declared = std::collections::BTreeSet::new();
        // WS91: a register that points to one struct wherever the body assigns it is typed so
        let typed = match self.structs {
            Some(sv) => sv.register_defs(func, &|d| !func.ops[d].dead && !self.folded.contains(&d) && !self.noise.contains(&d)),
            None => Default::default(),
        };
        for vn in &func.varnodes {
            // only registers the body assigns: a dead definition (most of a call's clobbers,
            // view syncs nobody reads) is not printed, so declaring it is noise
            if vn.data.space == SpaceId::REGISTER
                && vn.def_op.is_some_and(|d| {
                    // (the flag and accumulator of a compare-and-swap print in its statement)
                    !func.ops[d].dead && !self.folded.contains(&d) && (!self.noise.contains(&d) || self.cas_hidden.contains(&d) || self.swap_hidden.contains(&d))
                })
            {
                let key = (vn.data.offset, vn.data.size);
                if declared.insert(key) {
                    let type_name = match (self.structs, typed.get(&vn.data.offset)) {
                        (Some(sv), Some(&d)) if vn.data.size == 8 => format!("struct {}*", sv.defs[d].name),
                        _ if crate::flags::named_flag(vn.data.offset).is_some() => "bool".to_string(),
                        _ => size_to_type(vn.data.size).to_string(),
                    };
                    let var_name = reg_name(vn.data.offset, vn.data.size);
                    if !params.contains(var_name.as_str()) {
                        linef!(self, "{} {};", type_name, var_name);
                    }
                }
            }
        }
        // the stack slots (WS87)
        let slots: Vec<crate::frame::Slot> = self.frame.slots().filter(|s| !s.is_arg()).copied().collect();
        for s in &slots {
            linef!(self, "{};", s.c_declaration());
        }
        if !declared.is_empty() || !slots.is_empty() {
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
                linef!(self, "switch ({}) {{", self.switch_index(func, *condition_block));
                let arms = cases.iter().map(|(v, b)| (Some(v), b)).chain(default.iter().map(|d| (None, &**d)));
                for (values, body) in arms {
                    match values {
                        Some(vs) => {
                            for v in vs {
                                linef!(self, "case {}:", case_label(*v));
                            }
                        }
                        None => self.line("default:"),
                    }
                    self.indent += 1;
                    let mark = self.output.len();
                    self.emit_block(func, body);
                    // no `break` after a body that leaves on its own
                    let last = self.output[mark..].lines().map(str::trim).rfind(|l| !l.is_empty() && !l.starts_with("//")).unwrap_or("");
                    let ends = last.starts_with("return") || last.starts_with("goto ") || last == "continue;" || last == "break;";
                    if !ends {
                        self.line("break;");
                    }
                    self.indent -= 1;
                }
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
            StructuredBlock::Handler { landing_pad, note, body } => {
                // reached only by unwinding (WS82)
                linef!(self, "/* landing pad 0x{:x}: {} */", func.cfg.blocks[*landing_pad].start_addr, note);
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

    fn emit_basic_block_no_branch(&mut self, func: &SsaFunction, block_id: usize) {
        for op in &func.ops {
            if op.dead || op.block != block_id || self.noise.contains(&op.index) || self.folded.contains(&op.index) {
                continue;
            }
            if matches!(op.opcode, OpCode::Branch | OpCode::CBranch) {
                continue;
            }
            // a recovered jump table's `jmp` is the `switch` (WS83)
            if op.opcode == OpCode::BranchInd && func.cfg.switches.contains_key(&block_id) {
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
        if self.coalesced.copies.contains(&op.index) {
            return None;
        }
        let out_name = self.coalesced.defs.get(&op.index).cloned().or_else(|| op.output.map(|id| varnode_name(&func.varnodes[id as usize])));

        match op.opcode {
            // A phi joins versions of one register / slot, which the C output
            // names identically — nothing to print.
            OpCode::MultiEqual => None,
            OpCode::Copy if self.swaps.contains_key(&op.index) => {
                let (a, b) = self.swaps[&op.index];
                Some(format!("swap({}, {});", varnode_name(&func.varnodes[a as usize]), varnode_name(&func.varnodes[b as usize])))
            }
            // a stack address by its slot (WS87): `rdi = &local_48;`
            OpCode::Copy | OpCode::IntAdd | OpCode::IntSub
                if op.output.is_some_and(|o| {
                    let d = &func.varnodes[o as usize].data;
                    !(d.space == SpaceId::REGISTER && d.offset == 0x20)
                }) && op.output.and_then(|o| self.frame.address(func, o, false)).is_some() =>
            {
                Some(format!("{} = {};", out_name?, self.frame.address(func, op.output?, false)?))
            }
            OpCode::Copy => {
                let dst = out_name?;
                // the copy of a jump table's index the `switch` prints by its register (WS84)
                if is_switch_index_copy(func, op) {
                    return None;
                }
                // a field's address copied to a register (WS91): `rdi = &rbx->field_98;`
                if func.varnodes[op.output? as usize].data.space == SpaceId::REGISTER
                    && let Some(d) = self.inlined.borrow().get(&crate::condition::value_key(func, op.inputs[0])).copied()
                    && let Some(sv) = self.structs
                    && let Some((bi, f)) = sv.field_address(func, &func.ops[d])
                {
                    let base = self.input_expr(func, &func.ops[d], bi);
                    if is_identifier(&base) {
                        return Some(format!("{dst} = &{base}->{};", f.name()));
                    }
                }
                let src = self.input_expr(func, op, 0);
                Some(format!("{} = {};", dst, src))
            }
            // the address of a struct field (WS91): `rdi = &rbx->field_98;`
            OpCode::IntAdd if self.field_address(func, op).is_some() => {
                Some(format!("{} = {};", out_name?, self.field_address(func, op)?))
            }
            OpCode::IntAdd => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                // `x + 0xfffffffffffffffa` is `x - 6` (WS83)
                if let Some(k) = op.inputs.get(1).and_then(|&v| negative_constant(&func.varnodes[v as usize].data)) {
                    return Some(format!("{} = {} - {};", dst, a, small_hex(k)));
                }
                let b = self.input_expr(func, op, 1);
                // WS90: `0xffffffffffffffff + x` (`adc rdx, -1` after a `cmp`) is `x - 1` (at 32 / 64
                // bits, where unsigned arithmetic wraps and nothing is promoted)
                if let Some(k) = self.wide_negative(func, op, 0)
                    && func.varnodes[op.inputs[1] as usize].data.space != SpaceId::CONST
                {
                    return Some(format!("{} = {} - {};", dst, b, small_hex(k)));
                }
                Some(format!("{} = {} + {};", dst, a, b))
            }
            OpCode::IntSub => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let c = |i: usize| func.varnodes[op.inputs[i] as usize].data;
                // WS90: `x - 0` (`sbb al, 0`) is `x`, `0 - x` (`sbb eax, eax` after it is folded) `-x`,
                // and `x - 0xffffffffffffffff` (`sbb rdx, -1`) `x + 1` at 32 / 64 bits
                if c(1).space == SpaceId::CONST && c(1).offset == 0 {
                    return Some(format!("{} = {};", dst, a));
                }
                if c(0).space == SpaceId::CONST && c(0).offset == 0 && c(1).space != SpaceId::CONST {
                    return Some(format!("{} = -{};", dst, if crate::condition::is_atomic(&b) || is_deref(&b) { b } else { format!("({b})") }));
                }
                if let Some(k) = self.wide_negative(func, op, 1) {
                    return Some(format!("{} = {} + {};", dst, a, small_hex(k)));
                }
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
                let w = func.varnodes[op.inputs[0] as usize].data.size;
                Some(format!("{} = {} < {};", dst, signed_operand(ty, w, &a), signed_operand(ty, w, &b)))
            }
            OpCode::IntSLessEqual => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let b = self.input_expr(func, op, 1);
                let ty = size_to_signed_type(func.varnodes[op.inputs[0] as usize].data.size);
                let w = func.varnodes[op.inputs[0] as usize].data.size;
                Some(format!("{} = {} <= {};", dst, signed_operand(ty, w, &a), signed_operand(ty, w, &b)))
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
            OpCode::FloatNan => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = isnan({});", dst, a))
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
                let ty = float_type(out_size);
                Some(format!("{} = ({}){};", dst, ty, a))
            }
            OpCode::FloatFloat2Float => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let out_size = op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                let ty = float_type(out_size);
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
                // WS90: `x != false` is `x` (`SF != OF` after a `test`, which clears OF)
                let zero = |i: usize| op.inputs.get(i).is_some_and(|&v| {
                    let d = &func.varnodes[v as usize].data;
                    d.space == SpaceId::CONST && d.offset == 0
                });
                match (zero(0), zero(1)) {
                    (false, true) => return Some(format!("{dst} = {};", strip_outer_parens(&a))),
                    (true, false) => return Some(format!("{dst} = {};", strip_outer_parens(&b))),
                    _ => {}
                }
                Some(format!("{} = !{} != !{};", dst, a, b))
            }
            OpCode::BoolNegate => {
                let dst = out_name?;
                // a `setcc` whose condition folded (WS87): the negation is the text
                if let Some(e) = self.select_conds.get(&op.index) {
                    return Some(format!("{dst} = {};", strip_outer_parens(e)));
                }
                let a = self.input_expr(func, op, 0);
                Some(format!("{} = !{};", dst, a))
            }
            // `popcnt` / `lzcnt` (WS84)
            OpCode::PopCount | OpCode::LzCount if !op.inputs.is_empty() => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                let f = if op.opcode == OpCode::PopCount { "popcount" } else { "lzcount" };
                Some(format!("{dst} = {f}({a});"))
            }
            // `cmovcc` (WS83, `select`)
            OpCode::Select if op.inputs.len() == 3 => {
                let dst = out_name?;
                let c = self.input_expr(func, op, 0);
                // a constant arm of an XMM select (`maxss`, WS84) is a float: `0.0f`, not `0`
                let out = func.varnodes[op.output.unwrap() as usize].data;
                let arm = |i: usize| {
                    let v = func.varnodes[op.inputs[i] as usize].data;
                    let xmm = out.space == SpaceId::REGISTER && (0x1200..0x1300).contains(&out.offset);
                    match (xmm && v.space == SpaceId::CONST).then(|| float_literal(v.offset, out.size)).flatten() {
                        Some(f) => f,
                        None => self.input_expr(func, op, i),
                    }
                };
                let (a, b) = (arm(1), arm(2));
                Some(format!("{} = {} ? {} : {};", dst, c, a, b))
            }
            OpCode::IntZExt => {
                let dst = out_name?;
                let a = self.input_expr(func, op, 0);
                // Cast through the source's unsigned type so a non-MSB-set
                // value isn't accidentally sign-extended by C's promotion.
                let src = func.varnodes[op.inputs[0] as usize].data.size;
                let src_ty = size_to_type(src);
                let dst_ty = size_to_type(func.varnodes[op.output.unwrap() as usize].data.size);
                // WS90: not when the operand already has that type (`(uint64_t)(uint32_t)eax` is
                // `(uint64_t)eax`, `(uint32_t)(uint8_t)*(uint8_t*)p` is `(uint32_t)*(uint8_t*)p`)
                // a comparison's value is 0 or 1: `(uint64_t)(rdi < 0x1f5)`
                let boolean = func.varnodes[op.inputs[0] as usize].def_op.is_some_and(|d| {
                    matches!(
                        func.ops[d].opcode,
                        OpCode::IntEqual | OpCode::IntNotEqual | OpCode::IntLess | OpCode::IntSLess | OpCode::IntLessEqual | OpCode::IntSLessEqual
                    )
                });
                if boolean && crate::condition::is_atomic(&a) {
                    return Some(format!("{} = ({}){};", dst, dst_ty, a));
                }
                let a = match self.c_int_type(func, op.inputs[0], &a) {
                    Some((w, false)) if w == src => return Some(format!("{} = ({}){};", dst, dst_ty, drop_widening_casts(&a))),
                    _ => a,
                };
                Some(format!("{} = ({})({}){};", dst, dst_ty, src_ty, a))
            }
            OpCode::Piece if op.inputs.len() >= 2 => {
                // PIECE(hi, lo): concatenation, `lo` in the low bytes (the
                // lifter uses it to merge a scalar SSE result into the full
                // XMM register). Previously the opaque `PIECE(...)`.
                let dst = out_name?;
                // a write to a register's low view (WS84): `al = x` / `xmm0_d = x`
                match view_merge(func, op) {
                    Some(ViewMerge::Keep { view }) => {
                        let lo = self.input_expr(func, op, 1);
                        return (lo != view).then(|| format!("{view} = {lo};"));
                    }
                    Some(ViewMerge::Const(c)) => {
                        let lo = self.input_expr(func, op, 1);
                        let ty = size_to_type(func.varnodes[op.output.unwrap() as usize].data.size);
                        let shifted = c << (8 * func.varnodes[op.inputs[1] as usize].data.size);
                        return Some(if c == 0 {
                            format!("{dst} = ({ty}){lo};")
                        } else {
                            format!("{dst} = 0x{shifted:x} | ({ty}){lo};")
                        });
                    }
                    None => {}
                }
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
                // the kept upper bytes of a view write, read only by the merge (WS84)
                if kept_upper_only(func, op) {
                    return None;
                }
                let a = self.input_expr(func, op, 0);
                let k = &func.varnodes[op.inputs[1] as usize].data;
                let dst_size = func.varnodes[op.output.unwrap() as usize].data.size;
                let dst_ty = size_to_type(dst_size);
                if k.space == SpaceId::CONST && k.offset == 0 {
                    // WS90: the low bytes of a zero extension are what it extended:
                    // `(uint8_t)((uint32_t)*(uint8_t*)p)` is `*(uint8_t*)p`
                    if let Some((w, false, y)) = int_cast(strip_outer_parens(&a))
                        && w >= dst_size
                        && let Some((k, false)) = text_int_type(y)
                        && k <= dst_size
                    {
                        return Some(if k == dst_size { format!("{dst} = {y};") } else { format!("{dst} = ({dst_ty}){y};") });
                    }
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
                let src = func.varnodes[op.inputs[0] as usize].data.size;
                let src_ty = size_to_signed_type(src);
                let dst_ty = size_to_signed_type(func.varnodes[op.output.unwrap() as usize].data.size);
                // WS90: not when the operand is already that signed type
                if self.c_int_type(func, op.inputs[0], &a) == Some((src, true)) {
                    return Some(format!("{} = ({}){};", dst, dst_ty, a));
                }
                Some(format!("{} = ({})({}){};", dst, dst_ty, src_ty, a))
            }
            OpCode::Load => {
                let dst = out_name?;
                let out_size = op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(8);
                // a stack slot by name (WS87)
                if let Some(slot) = op.inputs.get(1).and_then(|&a| self.frame.access(func, op.block, a, out_size, false, false)) {
                    return Some(format!("{dst} = {slot};"));
                }
                // a struct field (WS91)
                if let Some(f) = self.field_access(func, op, false) {
                    return Some(format!("{dst} = {f};"));
                }
                let addr = self.input_expr(func, op, 1);
                Some(format!("{} = *({}*){};", dst, size_to_type(out_size), addr))
            }
            OpCode::Store if self.cas.contains_key(&op.index) => {
                let c = &self.cas[&op.index];
                let ptr = match self.frame.access(func, op.block, c.addr, c.size, true, false) {
                    Some(slot) if !slot.starts_with('*') => format!("&{slot}"),
                    _ => format!("({}*){}", size_to_type(c.size), self.input_expr(func, op, 1)),
                };
                let sel = func.varnodes[op.inputs[2] as usize].def_op?;
                let call = crate::cas::call_text(&ptr, &varnode_name(&func.varnodes[c.expected as usize]), &self.input_expr(func, &func.ops[sel], 1));
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
                if let Some(slot) = op.inputs.get(1).and_then(|&a| self.frame.access(func, op.block, a, size, true, false)) {
                    return Some(format!("{slot} = {val};"));
                }
                if let Some(f) = self.field_access(func, op, true) {
                    // (a constructor's vtable store names the class)
                    let class = self.structs.and_then(|sv| {
                        let a = sv.access.get(&op.index)?;
                        let d = &sv.defs[a.def];
                        let k = func.varnodes[*op.inputs.get(2)? as usize].data;
                        (d.fields[a.field].kind == crate::structs::FieldKind::VPtr && k.space == SpaceId::CONST && d.vtable == Some(k.offset)).then(|| d.class.clone())?
                    });
                    return Some(match class {
                        Some(c) => format!("{f} = {val};  // vtable of {c}"),
                        None => format!("{f} = {val};"),
                    });
                }
                let addr = self.input_expr(func, op, 1);
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
                // WS91: `obj->vfn_6(…)`, the slot's function named when the object's class is known
                if let Some((obj, n, resolved)) = self.member_call(func, op) {
                    let ann = match (resolved, func.vcall_targets.get(&op.address)) {
                        (Some(m), _) => format!("  // vfn[{n}] (vtable+0x{:x}) = {m}", n * 8),
                        // (an implementation from a vtable of `this`'s classes, WS79)
                        (None, Some(t)) => {
                            let name = self.symbol_names.get(t).cloned().unwrap_or_else(|| format!("0x{t:x}"));
                            format!("  // vfn[{n}] (vtable+0x{:x}) e.g. {name}", n * 8)
                        }
                        (None, None) => format!("  // vfn[{n}] (vtable+0x{:x})", n * 8),
                    };
                    return Some(format!("{assign}{obj}->vfn_{n}({});{ann}", args[1..].join(", ")));
                }
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
                if tag == Some(reargo_core::pcode::intrinsic::NORETURN) {
                    // the marker after a call that never returns (WS81)
                    None
                } else if tag == Some(3) {
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
            // the carry / overflow flags of an add or a subtraction, with their operands (WS90; they
            // printed `INT_SBORROW(...)`): GCC's overflow builtins, exact for any operand values
            OpCode::IntCarry | OpCode::IntSCarry | OpCode::IntSBorrow if op.inputs.len() == 2 => {
                let dst = out_name?;
                let size = func.varnodes[op.inputs[0] as usize].data.size;
                let (ty, builtin) = match op.opcode {
                    OpCode::IntCarry => (size_to_type(size), "__builtin_add_overflow_p"),
                    OpCode::IntSCarry => (size_to_signed_type(size), "__builtin_add_overflow_p"),
                    _ => (size_to_signed_type(size), "__builtin_sub_overflow_p"),
                };
                let unsigned = op.opcode == OpCode::IntCarry;
                // (an unsigned operand that is a plain variable already has the type; anything
                // else, and every signed operand, is cast to the operation's width)
                let arg = |i: usize| {
                    let e = self.input_expr(func, op, i);
                    if unsigned && is_identifier(&e) { e } else { format!("({}){}", ty, if crate::condition::is_atomic(&e) { e } else { format!("({e})") }) }
                };
                Some(format!("{} = {}({}, {}, ({})0);", dst, builtin, arg(0), arg(1), ty))
            }
            _ => {
                let dst = out_name.unwrap_or_else(|| "???".into());
                Some(format!("{} = {}(...);", dst, op.opcode.name()))
            }
        }
    }

    /// A load / store of a struct field as `base->field_k` (WS91), when its address prints in
    /// place: the address is the base itself, or `base + k` inlined into this access. A narrower
    /// access at the field's start goes through the field: `(uint32_t)p->field_8` (an integer
    /// field read), `*(uint32_t*)&p->field_8` (written, or a float / pointer field).
    fn field_access(&self, func: &SsaFunction, op: &crate::ssa::SsaOp, store: bool) -> Option<String> {
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
        if !(is_identifier(&base) || crate::condition::is_member(&base)) {
            return None;
        }
        let f = &sv.defs[a.def].fields[a.field];
        let m = format!("{base}->{}", f.name());
        Some(if a.size == f.size {
            m
        } else if store || f.kind != crate::structs::FieldKind::Int {
            format!("*({}*)&{m}", size_to_type(a.size))
        } else {
            format!("({}){m}", size_to_type(a.size))
        })
    }

    /// `&base->field_k` for a register set to a struct pointer plus a field's offset (WS91).
    fn field_address(&self, func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<String> {
        // (a register's own statement; a temporary inlined into an access stays `base + k`)
        if !(op.output.is_some_and(|o| func.varnodes[o as usize].data.space == SpaceId::REGISTER) || self.coalesced.defs.contains_key(&op.index)) {
            return None;
        }
        let (bi, f) = self.structs?.field_address(func, op)?;
        let base = self.input_expr(func, op, bi);
        is_identifier(&base).then(|| format!("&{base}->{}", f.name()))
    }

    /// A virtual call printed as `obj->vfn_n(…)` (WS91): the object's text, the slot number and
    /// the slot's function when the object's class is known.
    fn member_call(&self, func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<(String, u64, Option<String>)> {
        let sv = self.structs?;
        let vc = sv.member_call(func, op)?;
        let obj = self.input_expr(func, op, 1);
        if !(is_identifier(&obj) || crate::condition::is_member(&obj)) {
            return None;
        }
        let def = &sv.defs[vc.def];
        let resolved = vc.target.map(|t| crate::structs::method_name(self.symbol_names, def.class.as_deref(), t));
        Some((obj, vc.slot / 8, resolved))
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

    /// Fill `inlined` (see [`crate::inline`]); returns the definitions not to print.
    fn inline_temporaries(&self, func: &SsaFunction) -> Vec<usize> {
        self.inlined.borrow_mut().clear();
        let prints = |u: usize| self.cas_hidden.contains(&u) || (!self.noise.contains(&u) && self.emit_op(func, &func.ops[u]).is_some());
        let mut hidden = Vec::new();
        // (a call printed from a rendering of its site does not print its operands)
        let prints_operands = |u: usize| {
            let op = &func.ops[u];
            op.opcode == OpCode::CallInd || !self.call_renderings.is_some_and(|r| r.contains_key(&op.address))
        };
        for (d, readers) in crate::inline::candidates(func, &|d| self.noise.contains(&d), &prints_operands) {
            let op = &func.ops[d];
            let v = op.output.expect("candidate has an output");
            if !readers.iter().all(|&u| prints(u)) {
                continue;
            }
            let Some(text) = self.inline_text(func, d) else { continue };
            if text.len() > MAX_INLINE_LEN || text.contains("//") {
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
        // a `setcc`'s folded condition (WS87), a whole right-hand side
        if ((idx == 0 && op.opcode == OpCode::Copy) || (idx == 2 && op.opcode == OpCode::Store))
            && let Some(e) = self.select_conds.get(&op.index)
        {
            return strip_outer_parens(e).to_string();
        }
        if let Some(r) = self.coalesced.values.get(&crate::condition::value_key(func, op.inputs[idx])) {
            return r.clone();
        }
        let inlined = self.inlined.borrow().get(&crate::condition::value_key(func, op.inputs[idx])).copied();
        if let Some(rhs) = inlined.and_then(|d| self.inline_text(func, d)) {
            // a whole right-hand side needs no parentheses
            // (an argument of a call or intrinsic is separated by commas: WS87)
            let whole = (op.opcode == OpCode::Store && idx == 2)
                || op.opcode == OpCode::Copy
                || (matches!(op.opcode, OpCode::Call | OpCode::CallOther) && idx > 0)
                || (op.opcode == OpCode::CallInd && idx > 0);
            // (a cast of a struct field, `(uint16_t)p->field_8`, is unary like a dereference: WS91)
            let unary_field = int_cast(&rhs).is_some_and(|(_, _, x)| crate::condition::is_member(x));
            return if whole || crate::condition::is_atomic(&rhs) || is_deref(&rhs) || unary_field { rhs } else { format!("({rhs})") };
        }
        if let Some(e) = self.inliner.get(func, op.inputs[idx]) {
            return e;
        }
        if idx == 0
            && op.opcode == OpCode::Select
            && let Some(e) = self.select_conds.get(&op.index)
        {
            return if crate::condition::is_atomic(e) { e.clone() } else { format!("({e})") };
        }
        let vn = &func.varnodes[op.inputs[idx] as usize];
        // a constant a float op reads is the bits of a float (WS83: constants now reach their
        // readers, `xmm3_d = 0; x <= xmm3_d` -> `x <= 0.0f`)
        if vn.data.space == SpaceId::CONST
            && is_float_op(op.opcode)
            && let Some(f) = float_literal(vn.data.offset, vn.data.size)
        {
            return f;
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

    /// `k` when input `i` of `op` is the constant `-k` of a 32- or 64-bit operation (WS90).
    fn wide_negative(&self, func: &SsaFunction, op: &crate::ssa::SsaOp, i: usize) -> Option<u64> {
        let d = func.varnodes[*op.inputs.get(i)? as usize].data;
        (d.size >= 4).then(|| negative_constant(&d)).flatten()
    }

    /// The C integer type of `text` (the printed operand `v`) when it is certain (WS90): `(width
    /// in bytes, signed)` of a cast covering the whole text (`(uint8_t)x`), a dereference
    /// (`*(uint16_t*)p`), or a register printed by its own name (declared by its size, unsigned;
    /// a named flag is a `bool`, 0 or 1).
    fn c_int_type(&self, func: &SsaFunction, v: crate::ssa::VarId, text: &str) -> Option<(u32, bool)> {
        if let Some((w, signed, _)) = int_cast(text) {
            return Some((w, signed));
        }
        if let Some(rest) = text.strip_prefix("*(")
            && is_deref(text)
        {
            return int_type_name(rest.split_once("*)")?.0);
        }
        // a struct field read whole (WS91): an integer field has its declared type
        if let Some(sv) = self.structs
            && crate::condition::is_member(text)
            && let Some(a) = func.varnodes[v as usize].def_op.and_then(|d| sv.access.get(&d))
        {
            let f = &sv.defs[a.def].fields[a.field];
            return (a.size == f.size && f.kind == crate::structs::FieldKind::Int && matches!(f.size, 1 | 2 | 4 | 8)).then_some((f.size, false));
        }
        let vn = &func.varnodes[v as usize];
        (vn.data.space == SpaceId::REGISTER && is_identifier(text) && text == varnode_name(vn) && matches!(vn.data.size, 1 | 2 | 4 | 8))
            .then_some((vn.data.size, false))
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

    /// The value a jump table's `switch` tests: what its `BRANCHIND` reads (WS83), or the
    /// register the index was copied from when that still holds it (WS84).
    fn switch_index(&self, func: &SsaFunction, block_id: usize) -> String {
        let Some(op) = func.ops.iter().rev().find(|op| op.block == block_id && !op.dead && op.opcode == OpCode::BranchInd) else {
            return "cond".into();
        };
        match switch_index_source(func, op) {
            Some(src) => varnode_name(&func.varnodes[src as usize]),
            None => self.input_expr(func, op, 0),
        }
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

    fn line(&mut self, text: &str) {
        for _ in 0..self.indent {
            self.output.push_str("    ");
        }
        self.output.push_str(text);
        self.output.push('\n');
    }
}


/// The register a jump table's index was copied from at the dispatch window's start
/// (`switch::INDEX_TMP`), when no live op between the copy and the `BRANCHIND` writes it — the
/// window's table computation is dead once the dispatch reads the copy (WS84).
fn switch_index_source(func: &SsaFunction, br: &crate::ssa::SsaOp) -> Option<crate::ssa::VarId> {
    let v = *br.inputs.first()?;
    let d = func.varnodes[v as usize].data;
    if d.space != SpaceId::UNIQUE || d.offset != crate::switch::INDEX_TMP {
        return None;
    }
    let c = func.varnodes[v as usize].def_op?;
    let copy = &func.ops[c];
    if copy.dead || copy.opcode != OpCode::Copy || c >= br.index {
        return None;
    }
    let src = *copy.inputs.first()?;
    let sd = func.varnodes[src as usize].data;
    let overwritten = func.ops[c + 1..br.index].iter().any(|o| {
        !o.dead
            && o.output.is_some_and(|w| {
                let w = func.varnodes[w as usize].data;
                w.space == sd.space && w.offset < sd.offset + sd.size as u64 && sd.offset < w.offset + w.size as u64
            })
    });
    (!overwritten).then_some(src)
}

/// Is `op` the index copy [`switch_index_source`] prints through?
fn is_switch_index_copy(func: &SsaFunction, op: &crate::ssa::SsaOp) -> bool {
    let Some(v) = op.output else { return false };
    let d = func.varnodes[v as usize].data;
    if d.space != SpaceId::UNIQUE || d.offset != crate::switch::INDEX_TMP {
        return false;
    }
    let readers: Vec<&crate::ssa::SsaOp> =
        func.varnodes[v as usize].uses.iter().map(|&u| &func.ops[u]).filter(|o| !o.dead && o.inputs.contains(&v)).collect();
    !readers.is_empty()
        && readers.iter().all(|r| r.opcode == OpCode::BranchInd && r.inputs.first() == Some(&v) && switch_index_source(func, r).is_some())
}

/// How a `PIECE` that rebuilds a register after a write to its low view prints (WS84).
pub(crate) enum ViewMerge {
    /// `R = PIECE(SUBPIECE(R, n), lo)`: the upper bytes are kept, it is the write `view = lo`
    Keep { view: String },
    /// `R = PIECE(c, lo)` with the upper bytes a known constant
    Const(u64),
}

/// The lifter rebuilds a register after a write to its low byte / word (`mov al, 1` ->
/// `rax = PIECE(SUBPIECE(rax, 1), al)`) and an XMM register after a scalar write. Printed as
/// is that was `tmp_7e00 = (void)(rax >> 8); rax = CONCAT(tmp_7e00, al:1);`; it is the write of
/// the view, which the register names already alias.
pub(crate) fn view_merge(func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<ViewMerge> {
    let out = func.varnodes[op.output? as usize].data;
    let (hi, lo) = (*op.inputs.first()?, *op.inputs.get(1)?);
    let (hi_d, lo_d) = (func.varnodes[hi as usize].data, func.varnodes[lo as usize].data);
    if out.space != SpaceId::REGISTER || lo_d.size >= out.size {
        return None;
    }
    if hi_d.space == SpaceId::CONST {
        return Some(ViewMerge::Const(hi_d.offset));
    }
    if !is_kept_upper(func, hi, out, lo_d.size) {
        return None;
    }
    Some(ViewMerge::Keep { view: reg_name(out.offset, lo_d.size) })
}

/// Is `hi` the upper bytes of the register `out` itself, `SUBPIECE(out, n)`?
fn is_kept_upper(func: &SsaFunction, hi: crate::ssa::VarId, out: reargo_core::pcode::VarnodeData, n: u32) -> bool {
    let Some(d) = func.varnodes[hi as usize].def_op else { return false };
    let sub = &func.ops[d];
    if sub.dead || sub.opcode != OpCode::Subpiece || sub.inputs.len() != 2 {
        return false;
    }
    let (x, k) = (func.varnodes[sub.inputs[0] as usize].data, func.varnodes[sub.inputs[1] as usize].data);
    x.space == SpaceId::REGISTER && x.offset == out.offset && x.size == out.size && k.space == SpaceId::CONST && k.offset == u64::from(n)
}

/// Is `op` (a SUBPIECE) the kept upper bytes of view writes only, so it needs no statement?
pub(crate) fn kept_upper_only(func: &SsaFunction, op: &crate::ssa::SsaOp) -> bool {
    let Some(v) = op.output else { return false };
    let readers: Vec<&crate::ssa::SsaOp> = func.varnodes[v as usize]
        .uses
        .iter()
        .map(|&u| &func.ops[u])
        .filter(|o| !o.dead && o.inputs.contains(&v))
        .collect();
    !readers.is_empty()
        && readers.iter().all(|r| {
            r.opcode == OpCode::Piece && r.inputs.first() == Some(&v) && matches!(view_merge(func, r), Some(ViewMerge::Keep { .. }))
        })
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

/// `cond` inverted when `negated`: `!x` for a plain name, `x` for `!x`, `a != b` for
/// `a == b` (and back), `!(…)` otherwise.
pub(crate) fn negate_condition(cond: String, negated: bool) -> String {
    if !negated {
        return cond;
    }
    if cond.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return format!("!{cond}");
    }
    if let Some(rest) = cond.strip_prefix('!')
        && crate::condition::is_atomic(rest)
    {
        return strip_outer_parens(rest).to_string();
    }
    if let Some(flipped) = flip_equality(&cond) {
        return flipped;
    }
    format!("!({cond})")
}

/// `(x)` -> `x` when the parentheses enclose the whole expression.
pub(crate) fn strip_outer_parens(s: &str) -> &str {
    if s.starts_with('(') && crate::condition::is_atomic(s) { &s[1..s.len() - 1] } else { s }
}

/// `a == b` -> `a != b` (and back) when that comparison is the only operator at the top level
/// (outside parentheses) that binds looser than arithmetic.
fn flip_equality(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut found: Option<(usize, &str)> = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ if depth == 0 => {
                for op in [" == ", " != ", " && ", " || ", " < ", " <= ", " > ", " >= ", " ? ", " & ", " | ", " ^ "] {
                    if s[i..].starts_with(op) {
                        if found.is_some() || !matches!(op, " == " | " != ") {
                            return None;
                        }
                        found = Some((i, op));
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    let (at, op) = found?;
    let flipped = if op == " == " { " != " } else { " == " };
    Some(format!("{}{}{}", &s[..at], flipped, &s[at + op.len()..]))
}

/// The opposite of an integer comparison printed as `a OP b` (WS81): `<` <-> `>=`, `<=` <-> `>`,
/// `==` <-> `!=`, when that comparison is the only operator at the top level (outside
/// parentheses) that binds looser than arithmetic. Only for integers (`!(a < b)` is not
/// `a >= b` for a NaN).
pub(crate) fn flip_comparison(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut found: Option<(usize, &str)> = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ if depth == 0 => {
                for op in [" == ", " != ", " <= ", " >= ", " < ", " > ", " && ", " || ", " ? ", " & ", " | ", " ^ "] {
                    if s[i..].starts_with(op) {
                        if found.is_some() || matches!(op, " && " | " || " | " ? " | " & " | " | " | " ^ ") {
                            return None;
                        }
                        found = Some((i, op));
                        i += op.len() - 1;
                        break;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    let (at, op) = found?;
    let flipped = match op {
        " == " => " != ",
        " != " => " == ",
        " < " => " >= ",
        " >= " => " < ",
        " <= " => " > ",
        _ => " <= ",
    };
    Some(format!("{}{}{}", &s[..at], flipped, &s[at + op.len()..]))
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
        | Loop { body, .. }
        | Handler { body, .. } => collect_goto_targets(body, out),
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
        Sequence(_) | Goto(_) | Break | Continue | Handler { .. } => None,
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
/// The ops of the function's epilogues that print only frame bookkeeping (WS80): in the run
/// of [`crate::cfg::is_epilogue_insn`] instructions that ends a return block, a write of the
/// stack pointer, the load of the return address the `ret` jumps to, and anything read only by
/// such ops. A `pop` whose value is returned (`pop rax` before `ret`) is kept.
pub(crate) fn epilogue_noise(func: &SsaFunction) -> rustc_hash::FxHashSet<usize> {
    let mut noise = rustc_hash::FxHashSet::default();
    let mut addrs = rustc_hash::FxHashSet::default();
    for b in &func.cfg.blocks {
        if b.is_return() {
            for (k, insn) in b.instructions.iter().rev().enumerate() {
                // (a tail call's `jmp` ends the block: the frame restore is before it)
                if k == 0 && insn.mnemonic.trim_start().starts_with("jmp") {
                    continue;
                }
                if !crate::cfg::is_epilogue_insn(&insn.mnemonic) {
                    break;
                }
                addrs.insert(insn.address);
            }
        }
    }
    if addrs.is_empty() {
        return noise;
    }
    // backwards, so an op's readers are classified before it
    for op in func.ops.iter().rev() {
        if op.dead || op.opcode == OpCode::Return || !addrs.contains(&op.address) {
            continue;
        }
        let Some(out) = op.output else { continue };
        let vn = &func.varnodes[out as usize];
        let is_sp = vn.data.space == SpaceId::REGISTER && matches!(varnode_name(vn).as_str(), "rsp" | "esp");
        let only_noise = vn.uses.iter().all(|&u| {
            let r = &func.ops[u];
            r.dead
                || noise.contains(&u)
                || (r.opcode == OpCode::Return && r.inputs.first() == Some(&out) && return_value(func, r) != Some(0))
        });
        if is_sp || only_noise {
            noise.insert(op.index);
        }
    }
    noise
}

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

/// A function that returns the top of the x87 stack (WS89: its `ret`s have an 80-bit value).
pub(crate) fn returns_long_double(func: &SsaFunction) -> bool {
    func.ops.iter().any(|op| {
        !op.dead
            && op.opcode == OpCode::Return
            && return_value(func, op).is_some_and(|i| func.varnodes[op.inputs[i] as usize].data.size == 10)
    })
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
        _ if returns_long_double(func) => "long double",
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
        (0x01, 1) => "ah".into(),
        (0x09, 1) => "ch".into(),
        (0x11, 1) => "dh".into(),
        (0x19, 1) => "bh".into(),
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
        // WS89: the x87 stack slots, named from the bottom of the stack (`st0` = the first value
        // pushed; see `reargo_lift::x86::x87`), the control word and the condition codes
        (off, 10) if (0x1100..0x1180).contains(&off) && off % 0x10 == 0 => format!("st{}", (off - 0x1100) / 0x10),
        (0x10a0, 2) => "fpucw".into(),
        (off, 1) if (0x10a8..0x10ac).contains(&off) => format!("fpu_c{}", off - 0x10a8),
        _ => format!("var_{:x}", offset),
    }
}

/// `(width in bytes, signed)` of a C integer type name (`uint32_t`, `int8_t`).
fn int_type_name(t: &str) -> Option<(u32, bool)> {
    let (signed, bits) = match t.strip_prefix('u') {
        Some(r) => (false, r.strip_prefix("int")?.strip_suffix("_t")?),
        None => (true, t.strip_prefix("int")?.strip_suffix("_t")?),
    };
    match bits {
        "8" => Some((1, signed)),
        "16" => Some((2, signed)),
        "32" => Some((4, signed)),
        "64" => Some((8, signed)),
        _ => None,
    }
}

/// `(T)rest` where the cast to the integer type `T` covers the whole text (WS90): its width,
/// signedness and operand. `rest` is one operand — a name, a parenthesised whole, a call, a
/// dereference or another such cast — so `(uint8_t)x + 1` is no cast of the whole.
pub(crate) fn int_cast(s: &str) -> Option<(u32, bool, &str)> {
    let rest = s.strip_prefix('(')?;
    let (ty, operand) = rest.split_once(')')?;
    let (w, signed) = int_type_name(ty)?;
    let unary = crate::condition::is_atomic(operand) || is_deref(operand) || int_cast(operand).is_some();
    (!operand.is_empty() && unary).then_some((w, signed, operand))
}

/// The integer type of a cast covering the whole text or a dereference (`*(uint8_t*)p`):
/// `(width, signed)` (WS90).
fn text_int_type(s: &str) -> Option<(u32, bool)> {
    int_cast(s).map(|(k, signed, _)| (k, signed)).or_else(|| s.strip_prefix("*(").filter(|_| is_deref(s)).and_then(|r| int_type_name(r.split_once("*)")?.0)))
}

/// `(intW_t)text` for a signed comparison's operand (WS90), without a cast of the same width
/// under it: `(int32_t)((uint32_t)*(uint64_t*)(rsp + 0x18))` is `(int32_t)*(uint64_t*)(rsp + 0x18)`
/// — both keep the value modulo 2^W read as two's complement (C's conversion to a signed type
/// out of its range is implementation-defined; GCC and Clang define it so).
fn signed_operand(ty: &str, w: u32, text: &str) -> String {
    // a constant the signed type holds as it is needs no cast (`(int64_t)rdi < 0`)
    let value = text.strip_prefix("0x").map_or_else(|| text.parse::<u64>().ok(), |h| u64::from_str_radix(h, 16).ok());
    if value.is_some_and(|v| (1..=8).contains(&w) && v < 1u64 << (8 * w - 1)) {
        return text.to_string();
    }
    match int_cast(strip_outer_parens(text)) {
        Some((cw, _, y)) if cw == w => format!("({ty}){y}"),
        _ => format!("({ty}){text}"),
    }
}

/// `(uintA_t)(uintB_t)…x` with the casts made minimal (WS90): an unsigned cast whose operand
/// is an unsigned cast to a type no wider is the identity on its value, so it goes —
/// `(uint32_t)(uint8_t)x` stays, `(uint32_t)(uint32_t)x` and `(uint32_t)(uint16_t)(uint8_t)x`
/// lose the outer / middle cast. Only the outermost cast is kept when everything below it is
/// such a widening; nothing else is rewritten.
pub(crate) fn drop_widening_casts(s: &str) -> String {
    let Some((w, false, operand)) = int_cast(s) else { return s.to_string() };
    let inner = drop_widening_casts(operand);
    match text_int_type(&inner) {
        // (uintW)(uintK)y with K <= W: the outer cast changes nothing
        Some((k, false)) if k <= w => inner,
        _ => format!("({}){}", size_to_type(w), inner),
    }
}

/// A plain variable name (`eax`, `tmp_510`, `local_30`), not a constant or an expression.
pub(crate) fn is_identifier(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The C type of a float of `size` bytes (`long double` = the x87's 80 bits, WS89).
pub(crate) fn float_type(size: u32) -> &'static str {
    match size {
        4 => "float",
        10 => "long double",
        _ => "double",
    }
}

pub(crate) fn size_to_type(size: u32) -> &'static str {
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        // an XMM register / 128-bit memory access (it printed `void xmm0;`, `*(void*)p = ..`)
        16 => "uint128_t",
        // only an x87 value is 10 bytes (WS89)
        10 => "long double",
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

/// Add to `chain` the ops defining `v` that fold into a condition read at op `s`: temporaries
/// and flags of the block (not loads or calls, which stay named), each kept only when what it
/// reads keeps its value up to `s`. False when `v` itself does not fold (it is then printed by
/// name, which the caller checks is still valid). The values the folded text names are added
/// to `leaves` (their definitions must stay printed).
#[allow(clippy::too_many_arguments)]
fn fold_chain(
    func: &SsaFunction,
    v: crate::ssa::VarId,
    s: usize,
    block: usize,
    temp: &dyn Fn(crate::ssa::VarId) -> bool,
    unchanged: &dyn Fn(crate::ssa::VarId, usize, usize) -> bool,
    chain: &mut Vec<usize>,
    leaves: &mut Vec<crate::ssa::VarId>,
    depth: u32,
) -> bool {
    let Some(d) = func.varnodes[v as usize].def_op else { return false };
    if chain.contains(&d) {
        return true;
    }
    let dop = &func.ops[d];
    if depth > 6
        || dop.dead
        || dop.block != block
        || d >= s
        || !temp(v)
        || matches!(dop.opcode, OpCode::Load | OpCode::Call | OpCode::CallInd | OpCode::CallOther | OpCode::MultiEqual | OpCode::Indirect)
    {
        return false;
    }
    let mark = chain.len();
    chain.push(d);
    for &x in &dop.inputs {
        if func.varnodes[x as usize].data.space == SpaceId::CONST {
            continue;
        }
        let folds = temp(x) && fold_chain(func, x, s, block, temp, unchanged, chain, leaves, depth + 1);
        // a value printed by name must still hold it at the select
        if !folds && !unchanged(x, d, s) {
            chain.truncate(mark);
            return false;
        }
        if !folds {
            leaves.push(x);
        }
    }
    true
}

/// The conditions of `cmov` selects (WS83, generalised in WS84): the select's condition with
/// its definition chain in the block folded in, as a branch condition is — `(a == b) ? x : y`
/// instead of `var_206 ? x : y`, `(tmp_100 == 0) ? …`. The chain is the temporaries and flags
/// defining the condition (not loads, calls or other registers), and folds only when none of
/// the registers it reads is written between its op and the select. Returns each select's text
/// and the ops no longer printed: those every live reader of which folds them.
///
/// WS87: a `setcc` folds its condition the same way — a byte register or a byte stored taking
/// a flag / temporary (`sil = !tmp_49a;` after `ucomiss; seta sil` -> `sil = tmp_700 <
/// xmm1_d;`): the text of a `!` site is its negation, the whole right-hand side.
pub(crate) fn select_conditions(
    func: &SsaFunction,
    inliner: &crate::condition::Inliner,
    emit: &dyn Fn(&crate::ssa::SsaOp) -> Option<String>,
) -> (rustc_hash::FxHashMap<usize, String>, Vec<usize>) {
    let mut texts = rustc_hash::FxHashMap::default();
    let temp = |v: crate::ssa::VarId| {
        let d = &func.varnodes[v as usize].data;
        d.space == SpaceId::UNIQUE || (crate::flags::is_flag_storage(d) && d.size == 1)
    };
    // the value a site folds (its input), and whether its text is the negation
    let site = |op: &crate::ssa::SsaOp| -> Option<(crate::ssa::VarId, bool)> {
        if op.dead {
            return None;
        }
        let byte_reg = op.output.is_some_and(|w| {
            let d = &func.varnodes[w as usize].data;
            d.space == SpaceId::REGISTER && d.size == 1 && !crate::flags::is_flag_storage(d)
        });
        let c = match op.opcode {
            OpCode::Select if op.inputs.len() == 3 => return Some((op.inputs[0], false)),
            OpCode::Copy | OpCode::BoolNegate if byte_reg => op.inputs[0],
            OpCode::Store if op.inputs.len() == 3 && func.varnodes[op.inputs[2] as usize].data.size == 1 => op.inputs[2],
            _ => return None,
        };
        // (a flag / temporary computed by a comparison or a boolean op, through copies)
        let mut v = c;
        while let Some(d) = func.varnodes[v as usize].def_op.filter(|&d| func.ops[d].opcode == OpCode::Copy && temp(func.ops[d].inputs[0])) {
            v = func.ops[d].inputs[0];
        }
        let def = func.varnodes[v as usize].def_op.map(|d| func.ops[d].opcode);
        let boolean = def.is_some_and(|o| {
            matches!(
                o,
                OpCode::BoolNegate
                    | OpCode::BoolOr
                    | OpCode::BoolAnd
                    | OpCode::BoolXor
                    | OpCode::IntEqual
                    | OpCode::IntNotEqual
                    | OpCode::IntLess
                    | OpCode::IntSLess
                    | OpCode::IntLessEqual
                    | OpCode::IntSLessEqual
                    | OpCode::FloatEqual
                    | OpCode::FloatNotEqual
                    | OpCode::FloatLess
                    | OpCode::FloatLessEqual
                    | OpCode::FloatNan
            )
        });
        (temp(c) && boolean).then_some((c, op.opcode == OpCode::BoolNegate))
    };
    if !func.ops.iter().any(|o| site(o).is_some()) {
        return (texts, Vec::new());
    }
    let overlaps = |x: &reargo_core::pcode::VarnodeData, w: &reargo_core::pcode::VarnodeData| {
        x.space != SpaceId::CONST && x.space == w.space && x.offset < w.offset + w.size as u64 && w.offset < x.offset + x.size as u64
    };
    // `x` keeps its value from op `from` up to op `to`
    let unchanged = |x: crate::ssa::VarId, from: usize, to: usize| {
        let xd = &func.varnodes[x as usize].data;
        !func.ops[from + 1..to].iter().any(|o| !o.dead && o.output.is_some_and(|w| overlaps(xd, &func.varnodes[w as usize].data)))
    };
    let mut folded_by: rustc_hash::FxHashMap<usize, Vec<usize>> = rustc_hash::FxHashMap::default();
    let mut named: Vec<crate::ssa::VarId> = Vec::new();
    for (s, op) in func.ops.iter().enumerate() {
        let Some((c, negated)) = site(op) else { continue };
        let mut chain: Vec<usize> = Vec::new();
        let mut leaves = Vec::new();
        if !fold_chain(func, c, s, op.block, &temp, &unchanged, &mut chain, &mut leaves, 0) {
            continue;
        }
        chain.sort_unstable();
        let name = |v: crate::ssa::VarId| varnode_name(&func.varnodes[v as usize]);
        if let Some(f) = inliner.fold_value(func, &chain, c, &name, emit)
            && f.text != name(c)
        {
            texts.insert(s, f.render(negated));
            folded_by.insert(s, chain);
            named.extend(leaves);
        }
    }
    // an op is not printed when every live reader of it folds it (and no folded text names
    // its value)
    let mut hidden: rustc_hash::FxHashSet<usize> = folded_by.values().flatten().copied().collect();
    for v in named {
        if let Some(d) = func.varnodes[v as usize].def_op {
            hidden.remove(&d);
        }
    }
    // (WS90: every reader of the value — common subexpression elimination leaves readers of
    // one value under several varnodes, each with its own `uses`: a branch reading the flag a
    // select folded through another name printed `if (var_206)` with no assignment)
    let readers = crate::condition::Readers::new(func);
    loop {
        let keep: Vec<usize> = hidden
            .iter()
            .copied()
            .filter(|&d| {
                let Some(v) = func.ops[d].output else { return true };
                readers.of(func, v).iter().any(|&u| {
                    let r = &func.ops[u];
                    !r.dead && !hidden.contains(&u) && !folded_by.get(&u).is_some_and(|ch| ch.contains(&d))
                })
            })
            .collect();
        if keep.is_empty() {
            break;
        }
        for d in keep {
            hidden.remove(&d);
        }
    }
    (texts, hidden.into_iter().collect())
}

/// Longest expression printed inside its reader (WS86).
pub(crate) const MAX_INLINE_LEN: usize = 100;

/// A dereference or an integer cast covering the whole text: a unary expression, no
/// parentheses needed around it as an operand (WS90).
pub(crate) fn is_unary(s: &str) -> bool {
    is_deref(s) || int_cast(s).is_some()
}

/// `*(T*)x` with `x` atomic: a unary expression, no parentheses needed around it.
fn is_deref(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("*(") else { return false };
    let Some(close) = rest.find(")") else { return false };
    let ty = &rest[..close];
    ty.ends_with('*') && ty[..ty.len() - 1].chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && crate::condition::is_atomic(&rest[close + 1..])
}

/// A `case` value: decimal, hex from 0x100 on.
pub(crate) fn case_label(v: u64) -> String {
    if v < 0x100 { v.to_string() } else { format!("0x{v:x}") }
}

/// An op whose operands are floats (arithmetic and comparisons, not conversions from an
/// integer).
pub(crate) fn is_float_op(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::FloatEqual
            | OpCode::FloatNotEqual
            | OpCode::FloatLess
            | OpCode::FloatLessEqual
            | OpCode::FloatAdd
            | OpCode::FloatSub
            | OpCode::FloatMult
            | OpCode::FloatDiv
            | OpCode::FloatNeg
            | OpCode::FloatAbs
            | OpCode::FloatSqrt
            | OpCode::FloatNan
            | OpCode::FloatFloat2Float
            | OpCode::FloatTrunc
            | OpCode::FloatCeil
            | OpCode::FloatFloor
            | OpCode::FloatRound
    )
}

/// The C literal of the float whose bits are `bits` (`size` 4 = `float`, 8 = `double`).
pub(crate) fn float_literal(bits: u64, size: u32) -> Option<String> {
    let (mut t, suffix) = match size {
        4 => {
            let v = f32::from_bits(bits as u32);
            (v.is_finite().then(|| format!("{v:?}"))?, "f")
        }
        8 => {
            let v = f64::from_bits(bits);
            (v.is_finite().then(|| format!("{v:?}"))?, "")
        }
        _ => return None,
    };
    if !t.contains(['.', 'e']) {
        t.push_str(".0");
    }
    Some(format!("{t}{suffix}"))
}

/// `k` when `v` is the constant `-k` of its width, `k` small (below 2^31): an addition of it
/// reads as a subtraction.
pub(crate) fn negative_constant(v: &reargo_core::pcode::VarnodeData) -> Option<u64> {
    if v.space != SpaceId::CONST || v.size == 0 || v.size > 8 {
        return None;
    }
    let bits = v.size * 8;
    let x = if bits == 64 { v.offset } else { v.offset & ((1u64 << bits) - 1) };
    if x >> (bits - 1) & 1 == 0 {
        return None;
    }
    let k = if bits == 64 { x.wrapping_neg() } else { (1u64 << bits) - x };
    (k != 0 && k < 1 << 31 && bits > 8).then_some(k)
}

/// A constant as the C output prints it: decimal below 10, else hex.
pub(crate) fn small_hex(k: u64) -> String {
    if k < 10 { k.to_string() } else { format!("0x{k:x}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WS90: an integer cast covering the whole text, and the widening casts below an unsigned
    /// one dropped (each dropped cast is the identity on the value it gets).
    #[test]
    fn integer_cast_chains() {
        assert_eq!(int_cast("(uint8_t)x"), Some((1, false, "x")));
        assert_eq!(int_cast("(int32_t)*(uint32_t*)(rbx + 4)"), Some((4, true, "*(uint32_t*)(rbx + 4)")));
        assert_eq!(int_cast("(uint32_t)(uint8_t)(al >> 1)"), Some((4, false, "(uint8_t)(al >> 1)")));
        assert_eq!(int_cast("(uint8_t)x + 1"), None);
        assert_eq!(int_cast("(uint8_t)x)(y"), None);
        assert_eq!(int_cast("(float)x"), None);
        assert_eq!(drop_widening_casts("(uint32_t)(uint8_t)x"), "(uint8_t)x");
        assert_eq!(drop_widening_casts("(uint32_t)(uint32_t)x"), "(uint32_t)x");
        assert_eq!(drop_widening_casts("(uint32_t)(uint16_t)(uint8_t)x"), "(uint8_t)x");
        // a narrowing cast in between, or a signed one, changes the value: kept
        assert_eq!(drop_widening_casts("(uint32_t)(uint8_t)(uint16_t)x"), "(uint8_t)(uint16_t)x");
        assert_eq!(drop_widening_casts("(uint16_t)(uint32_t)x"), "(uint16_t)(uint32_t)x");
        assert_eq!(drop_widening_casts("(uint32_t)(int8_t)x"), "(uint32_t)(int8_t)x");
        assert_eq!(drop_widening_casts("(uint32_t)x + 1"), "(uint32_t)x + 1");
        assert_eq!(drop_widening_casts("(uint32_t)*(uint8_t*)(rbx + 1)"), "*(uint8_t*)(rbx + 1)");
        assert_eq!(signed_operand("int32_t", 4, "((uint32_t)(*(uint64_t*)(rsp + 0x18)))"), "(int32_t)(*(uint64_t*)(rsp + 0x18))");
        assert_eq!(signed_operand("int32_t", 4, "((uint32_t)rax)"), "(int32_t)rax");
        assert_eq!(signed_operand("int32_t", 4, "((uint16_t)rax)"), "(int32_t)((uint16_t)rax)");
        assert_eq!(signed_operand("int32_t", 4, "ebp"), "(int32_t)ebp");
        assert_eq!(signed_operand("int32_t", 4, "0"), "0");
        assert_eq!(signed_operand("int32_t", 4, "0x7fffffff"), "0x7fffffff");
        assert_eq!(signed_operand("int32_t", 4, "0xffffffff"), "(int32_t)0xffffffff");
        assert_eq!(signed_operand("int8_t", 1, "0x80"), "(int8_t)0x80");
        assert_eq!(drop_widening_casts("(uint8_t)*(uint32_t*)rbx"), "(uint8_t)*(uint32_t*)rbx");
    }
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
        assert_eq!(reg_name(0x1100, 10), "st0");
        assert_eq!(reg_name(0x1170, 10), "st7");
        assert_eq!(reg_name(0x10a0, 2), "fpucw");
        assert_eq!(reg_name(0x10ab, 1), "fpu_c3");
        assert_eq!(size_to_type(10), "long double");
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
