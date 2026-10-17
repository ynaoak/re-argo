//! Struct fields and virtual calls (WS91): `*(uint32_t*)(rdx + 0x10)` -> `rdx->field_10`,
//! `(**(uint64_t*)(rax + 0x30))(rdi)` -> `rdi->vfn_6()`.
//!
//! The pointers of a function are typed by unification (Steensgaard): the SSA values that hold
//! the same pointer — a copy, the versions a phi joins, the pointers loaded from (or stored to)
//! one field of one struct — share a type. A memory access `*(T*)(base + k)` whose base is such
//! a pointer (a register or a pointer loaded from memory; not a stack address, which `frame`
//! names, nor a constant) is an access of the field at offset `k` of the base's type. Each type
//! with an access past offset 0 (or a vtable pointer) is a struct; its fields are the access
//! starts, the widest access at each start, kept greedily — the most accessed first — when they
//! do not overlap a field already kept. An access that is no field start (inside a wider field,
//! a 16-byte copy over several fields, an indexed element) prints as before.
//!
//! The view changes no statement: an access prints as a field only where its address prints
//! in place (`base + k` inlined into the access, or the base itself for offset 0), so the base
//! named is the value at the access. A narrower access at a field start prints through the
//! field (`(uint32_t)p->field_8`, `*(uint32_t*)&p->field_8 = v`).
//!
//! A field's type is a hint: `struct X*` when the values loaded from / stored to it are
//! pointers of type X, `float` / `double` when every access reads or writes a float, `void**
//! _vptr` for the vtable pointer at offset 0 (loaded to reach a virtual call's slot, or a
//! vtable stored by a constructor), else an unsigned integer of its size.
//!
//! A virtual call `(*(*obj + 8·n))(obj, …)` prints as `obj->vfn_n(…)` when the slot is read
//! through the vtable pointer loaded from `obj` in the same block with nothing written to
//! memory in between and the first argument is `obj` (else as before). When the object's class
//! is known — the function's `this` in a method listed in a class's primary vtable (the class
//! from its RTTI), or a vtable stored into the object — the slot's function is named in the
//! comment (`= BiomeSource3d::method_at_43fadc0`, or its symbol).

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_loader::Memory;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::condition::{value_key, ValueKey};
use crate::ssa::{OpIdx, SsaFunction, VarId};

/// Field offsets past this are no struct fields (an address computed some other way).
const MAX_FIELD: u64 = 0x10_0000;
/// Passes of the field-type unification (each may join types and expose new pairs).
const MAX_PASSES: usize = 16;
const RSP: u64 = 0x20;

/// Union-find over value nodes.
#[derive(Default)]
struct Uf {
    parent: Vec<u32>,
}

impl Uf {
    fn add(&mut self) -> u32 {
        self.parent.push(self.parent.len() as u32);
        self.parent.len() as u32 - 1
    }
    fn find(&mut self, mut x: u32) -> u32 {
        while self.parent[x as usize] != x {
            let p = self.parent[self.parent[x as usize] as usize];
            self.parent[x as usize] = p;
            x = p;
        }
        x
    }
    /// `find` without path compression.
    fn find_const(&self, mut x: u32) -> u32 {
        while self.parent[x as usize] != x {
            x = self.parent[x as usize];
        }
        x
    }
    fn union(&mut self, a: u32, b: u32) -> bool {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return false;
        }
        // (the smaller node stays the root: deterministic)
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        self.parent[hi as usize] = lo;
        true
    }
}

/// What a field holds (a hint printed in the struct's definition).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Int,
    Float,
    /// A pointer to the struct with this index (`None`: dereferenced, but no struct).
    Ptr(Option<usize>),
    /// The vtable pointer at offset 0.
    VPtr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub off: u64,
    pub size: u32,
    pub kind: FieldKind,
    /// Only a callee accesses it (through the pointer passed to it): that callee.
    pub from: Option<u64>,
    /// (WS96) A pointer of a vector of pointers to objects of a class (the `this` index's
    /// element classes): `std::vector<T*>`'s begin, end or capacity pointer.
    pub vector: Option<VectorField>,
}

/// (WS96) A field that is one of the three pointers of a vector (`{begin, end, capacity}`) whose
/// elements are pointers to objects of the class `elem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorField {
    pub elem: String,
    /// 0: begin, 1: end, 2: capacity
    pub role: u8,
    /// the begin pointer's offset
    pub begin: u64,
}

impl Field {
    pub fn name(&self) -> String {
        if self.kind == FieldKind::VPtr { "_vptr".into() } else { format!("field_{:x}", self.off) }
    }
}

/// A recovered struct.
#[derive(Debug, Clone)]
pub struct StructDef {
    /// `struct_0`, or the C++ class name when known.
    pub name: String,
    /// The C++ class (from RTTI), when known.
    pub class: Option<String>,
    /// The class's vtable (its address point), when known.
    pub vtable: Option<u64>,
    /// Fields by offset, not overlapping.
    pub fields: Vec<Field>,
    /// The step of a pointer to it walking an array (an element is no longer).
    pub stride: Option<u64>,
    /// `class` comes from the function's symbol (a mangled method name), not from RTTI.
    pub class_from_symbol: bool,
}

impl StructDef {
    fn field_type(&self, f: &Field, defs: &[StructDef]) -> String {
        if let Some(v) = &f.vector {
            return format!("struct {}**", v.elem);
        }
        match f.kind {
            FieldKind::VPtr => "void**".into(),
            FieldKind::Ptr(Some(i)) => format!("struct {}*", defs[i].name),
            FieldKind::Ptr(None) => "void*".into(),
            FieldKind::Float => crate::emit::float_type(f.size).into(),
            FieldKind::Int => crate::emit::size_to_type(f.size).into(),
        }
    }

    /// The C definition, with the gaps between fields as byte arrays (so the offsets hold).
    pub fn c_definition(&self, defs: &[StructDef]) -> String {
        let mut out = format!("struct {} {{", self.name);
        match (&self.class, self.vtable) {
            (Some(_), Some(v)) if !self.class_from_symbol => out.push_str(&format!("  // class from RTTI, vtable 0x{v:x}")),
            (Some(_), Some(v)) => out.push_str(&format!("  // class from the symbol, vtable 0x{v:x}")),
            (Some(_), None) if !self.class_from_symbol => out.push_str("  // class from RTTI"),
            (Some(_), None) => out.push_str("  // class from the symbol"),
            (None, Some(v)) => out.push_str(&format!("  // vtable 0x{v:x}")),
            (None, None) => {}
        }
        if let Some(st) = self.stride {
            out.push_str(&format!("  // array element: a pointer to it steps by 0x{st:x}"));
        }
        out.push('\n');
        let mut at = 0u64;
        for f in &self.fields {
            if f.off > at {
                out.push_str(&format!("    uint8_t _gap_{at:x}[0x{:x}];\n", f.off - at));
            }
            let vector = f.vector.as_ref().map(vector_note).unwrap_or_default();
            match f.from {
                Some(c) => out.push_str(&format!("    {} {}; // +0x{:x}{vector} (used by 0x{c:x})\n", self.field_type(f, defs), f.name(), f.off)),
                None => out.push_str(&format!("    {} {}; // +0x{:x}{vector}\n", self.field_type(f, defs), f.name(), f.off)),
            }
            at = f.off + u64::from(f.size);
        }
        out.push_str("};");
        out
    }

    /// The Rust definition (`#[repr(C)]`, gaps as byte arrays).
    pub fn rust_definition(&self, defs: &[StructDef]) -> String {
        let mut out = "#[repr(C)]\n".to_string();
        out.push_str(&format!("struct {} {{", rust_ident(&self.name)));
        if let Some(v) = self.vtable {
            out.push_str(&format!("  // vtable 0x{v:x}"));
        }
        out.push('\n');
        let mut at = 0u64;
        for f in &self.fields {
            if f.off > at {
                out.push_str(&format!("    _gap_{at:x}: [u8; 0x{:x}],\n", f.off - at));
            }
            let ty = match f.kind {
                _ if f.vector.is_some() => format!("*mut *mut {}", rust_ident(&f.vector.as_ref().expect("vector").elem)),
                FieldKind::VPtr => "*const *const u8".to_string(),
                FieldKind::Ptr(Some(i)) => format!("*mut {}", rust_ident(&defs[i].name)),
                FieldKind::Ptr(None) => "*mut u8".into(),
                FieldKind::Float if f.size == 4 => "f32".into(),
                FieldKind::Float if f.size == 8 => "f64".into(),
                _ => crate::rust_emit::size_to_rust_type(f.size).into(),
            };
            out.push_str(&format!("    {}: {ty}, // +0x{:x}{}\n", f.name(), f.off, f.vector.as_ref().map(vector_note).unwrap_or_default()));
            at = f.off + u64::from(f.size);
        }
        out.push('}');
        out
    }
}

/// The comment of a vector's field (WS96): ` std::vector<T*> begin (end +0x28, capacity +0x30)`,
/// ` end of the std::vector<T*> at +0x20`.
fn vector_note(v: &VectorField) -> String {
    match v.role {
        0 => format!(" std::vector<{}*> begin (end +0x{:x}, capacity +0x{:x})", v.elem, v.begin + 8, v.begin + 16),
        1 => format!(" end of the std::vector<{}*> at +0x{:x}", v.elem, v.begin),
        _ => format!(" capacity of the std::vector<{}*> at +0x{:x}", v.elem, v.begin),
    }
}

/// The structs of C++ classes merged over several functions (WS91: `decompile-all` prints a
/// class's struct once): per class, the fields of every function's struct of it, kept when they
/// do not overlap one kept before (the struct seen first wins). Pointer fields name their target
/// struct; one that is a function's anonymous struct becomes `void*`. `(C, Rust)` definitions.
pub fn merge_class_structs<'d>(per_function: impl Iterator<Item = &'d [StructDef]>) -> (Vec<String>, Vec<String>) {
    let mut merged: Vec<StructDef> = Vec::new();
    let mut by_name: FxHashMap<String, usize> = FxHashMap::default();
    let mut targets: FxHashMap<(usize, u64), String> = FxHashMap::default();
    for defs in per_function {
        for d in defs.iter().filter(|d| d.class.is_some()) {
            let i = *by_name.entry(d.name.clone()).or_insert_with(|| {
                merged.push(StructDef { name: d.name.clone(), class: d.class.clone(), vtable: d.vtable, fields: Vec::new(), stride: None, class_from_symbol: d.class_from_symbol });
                merged.len() - 1
            });
            if merged[i].vtable.is_none() {
                merged[i].vtable = d.vtable;
            }
            for f in &d.fields {
                let end = f.off + u64::from(f.size);
                if merged[i].fields.iter().any(|g| !(end <= g.off || g.off + u64::from(g.size) <= f.off)) {
                    continue;
                }
                let mut f = f.clone();
                if let FieldKind::Ptr(Some(t)) = f.kind {
                    f.kind = FieldKind::Ptr(None);
                    if defs[t].class.is_some() {
                        targets.insert((i, f.off), defs[t].name.clone());
                    }
                }
                merged[i].fields.push(f);
            }
            merged[i].fields.sort_by_key(|f| f.off);
        }
    }
    // pointer fields to classes: by name now
    let index: FxHashMap<String, usize> = merged.iter().enumerate().map(|(i, d)| (d.name.clone(), i)).collect();
    for ((i, off), name) in targets {
        if let Some(f) = merged[i].fields.iter_mut().find(|f| f.off == off) {
            f.kind = FieldKind::Ptr(index.get(&name).copied());
        }
    }
    (merged.iter().map(|d| d.c_definition(&merged)).collect(), merged.iter().map(|d| d.rust_definition(&merged)).collect())
}

/// A Rust identifier for a C++ class name (`CachedBiomeSource<Pos2d>` -> `CachedBiomeSource_Pos2d_`).
pub fn rust_ident(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

/// An access of a field: the struct, the field and where its base prints.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Access {
    pub def: usize,
    pub field: usize,
    /// the access's own width
    pub size: u32,
    /// the `base + k` op computing the address (`None`: the address is the base itself)
    pub add: Option<OpIdx>,
    /// the base's input index in `add` (or in the access op when `add` is `None`)
    pub base_input: usize,
}

/// A virtual call through the vtable pointer of a struct.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VCall {
    pub def: usize,
    /// the vtable byte offset of the slot
    pub slot: u64,
    /// the load of the vtable pointer from the object
    pub vptr_load: OpIdx,
    /// the object (copies looked through)
    pub object: ValueKey,
    /// the slot's function in the vtable of the object's class, when known
    pub target: Option<u64>,
}

/// The struct view of one function (see the module documentation).
#[derive(Default)]
pub struct StructView {
    pub defs: Vec<StructDef>,
    /// value -> struct
    pub(crate) value_def: FxHashMap<ValueKey, usize>,
    /// load / store op -> the field it accesses
    pub(crate) access: FxHashMap<OpIdx, Access>,
    /// `CALLIND` op -> the virtual call
    pub(crate) vcalls: FxHashMap<OpIdx, VCall>,
    /// `INT_ADD`s stepping a register in place (`add r9, 0x18`): no field addresses
    pub(crate) steps: FxHashSet<OpIdx>,
    /// stores to the function's own stack slots (they change no object's vtable pointer)
    pub(crate) local_stores: FxHashSet<OpIdx>,
}

/// What `StructView::new` knows about the program around the function.
#[derive(Default)]
pub struct Context<'a> {
    pub memory: Option<&'a Memory>,
    /// The function's entry (its class is that of the vtables listing it).
    pub entry: u64,
    /// The registers of the first two arguments: `this` is the first, or the second when the
    /// first is the address of a struct the function returns in memory.
    pub arg_regs: [Option<VarnodeData>; 2],
    /// The class of `this` from the function's (mangled) name.
    pub name_class: Option<String>,
    /// The callees' parameters: the fields a callee accesses through a pointer passed to it.
    pub oracle: Option<&'a crate::callee_params::CalleeParams<'a>>,
    /// The function's own (mangled) name: its parameter types (WS92).
    pub name: Option<&'a str>,
    /// Names by address: the parameter types of the callees with a mangled name (WS92).
    pub symbols: Option<&'a std::collections::BTreeMap<u64, String>>,
    /// The classes the callers pass (WS93): of the parameters, the callees' results, the fields.
    pub this_index: Option<&'a crate::thisclass::ThisIndex>,
}

/// A raw access before the layout: op, base node, offset, width, value node (a pointer loaded
/// or stored), float, address op, base input.
struct Raw {
    op: OpIdx,
    base: u32,
    off: u64,
    size: u32,
    value: Option<u32>,
    float: bool,
    add: Option<OpIdx>,
    base_input: usize,
    vptr: bool,
    vtable_store: Option<u64>,
    /// not a field access after all (a vtable slot, an element past an array stride)
    skip: bool,
    /// an access a callee makes through the pointer passed to it (no op of this function)
    callee: Option<u64>,
}

fn is_xmm(d: &VarnodeData) -> bool {
    d.space == SpaceId::REGISTER && (0x1200..0x1300).contains(&d.offset)
}

/// `v` with copies looked through.
pub(crate) fn strip_copies(func: &SsaFunction, mut v: VarId) -> VarId {
    for _ in 0..16 {
        match func.varnodes[v as usize].def_op.map(|d| &func.ops[d]) {
            Some(op) if op.opcode == OpCode::Copy && op.inputs.len() == 1 && func.varnodes[op.inputs[0] as usize].data.space != SpaceId::CONST => {
                v = op.inputs[0]
            }
            _ => break,
        }
    }
    v
}

impl StructView {
    pub fn new(func: &SsaFunction, ctx: &Context<'_>) -> Self {
        Self::with_frame(func, ctx, &crate::frame::Frame::new(func, &|_| true))
    }

    /// [`Self::new`] with the function's stack frame (`Frame::new(func, &|_| true)`) computed
    /// by the caller.
    pub(crate) fn with_frame(func: &SsaFunction, ctx: &Context<'_>, frame: &crate::frame::Frame) -> Self {
        let readers = crate::condition::Readers::new(func);
        let mut uf = Uf::default();
        let mut nodes: FxHashMap<ValueKey, u32> = FxHashMap::default();
        fn node(uf: &mut Uf, nodes: &mut FxHashMap<ValueKey, u32>, k: ValueKey) -> u32 {
            *nodes.entry(k).or_insert_with(|| uf.add())
        }

        let konst = |v: VarId| func.varnodes[v as usize].data.space == SpaceId::CONST;
        let def_of = |v: VarId| func.varnodes[v as usize].def_op.map(|d| &func.ops[d]);
        // the base of an address: a register (not the stack pointer) or a value loaded / copied
        let base_ok = |v: VarId| {
            let d = &func.varnodes[v as usize].data;
            if d.size != 8 || d.space == SpaceId::CONST || (d.space == SpaceId::REGISTER && d.offset == RSP) {
                return false;
            }
            d.space == SpaceId::REGISTER || def_of(v).is_some_and(|o| matches!(o.opcode, OpCode::Load | OpCode::Copy | OpCode::MultiEqual))
        };
        let float_value = |v: VarId, is_load: bool| {
            let d = func.varnodes[v as usize].data;
            if is_xmm(&d) {
                return true;
            }
            if is_load {
                readers.of(func, v).iter().any(|&u| {
                    let r = &func.ops[u];
                    crate::emit::is_float_op(r.opcode) || (r.opcode == OpCode::Copy && r.output.is_some_and(|o| is_xmm(&func.varnodes[o as usize].data)))
                })
            } else {
                def_of(v).is_some_and(|o| crate::emit::is_float_op(o.opcode))
            }
        };

        // the accesses
        let mut raws: Vec<Raw> = Vec::new();
        for op in func.ops.iter().filter(|o| !o.dead && matches!(o.opcode, OpCode::Load | OpCode::Store)) {
            let Some(size) = crate::frame::access_size(func, op) else { continue };
            let Some(&addr) = op.inputs.get(1) else { continue };
            if size == 0 || konst(addr) || frame.is_stack(func, addr, op.block) {
                continue;
            }
            let (base, off, add, base_input) = match def_of(addr) {
                Some(d) if d.opcode == OpCode::IntAdd && d.inputs.len() == 2 && (konst(d.inputs[0]) != konst(d.inputs[1])) => {
                    let (bi, ki) = if konst(d.inputs[1]) { (0, 1) } else { (1, 0) };
                    let k = func.varnodes[d.inputs[ki] as usize].data.offset;
                    (d.inputs[bi], k, Some(d.index), bi)
                }
                _ => (addr, 0, None, 1),
            };
            if off >= MAX_FIELD || !base_ok(base) || frame.is_stack(func, base, op.block) {
                continue;
            }
            let value = match op.opcode {
                OpCode::Load => op.output.filter(|_| size == 8),
                _ => op.inputs.get(2).copied().filter(|&v| size == 8 && !konst(v)),
            };
            let float = match op.opcode {
                OpCode::Load => op.output.is_some_and(|o| float_value(o, true)),
                _ => op.inputs.get(2).is_some_and(|&v| float_value(v, false)),
            };
            // a constructor's vtable store
            let vtable_store = match (op.opcode, off, size, ctx.memory) {
                (OpCode::Store, 0, 8, Some(mem)) => op.inputs.get(2).filter(|&&v| konst(v)).map(|&v| func.varnodes[v as usize].data.offset).filter(|&p| crate::vcall::is_vtable_point(mem, p)),
                _ => None,
            };
            let b = node(&mut uf, &mut nodes, value_key(func, base));
            let value = value.map(|v| node(&mut uf, &mut nodes, value_key(func, v)));
            raws.push(Raw { op: op.index, base: b, off, size, value, float, add, base_input, vptr: vtable_store.is_some(), vtable_store, skip: false, callee: None });
        }
        let local = raws.len();

        // across calls: what a callee accesses through a pointer passed to it, and the classes
        // whose methods take it as `this`
        let mut this_calls: Vec<(u32, u64)> = Vec::new();
        // (WS92) pointers a callee stores a vtable into: a constructor's / destructor's object
        let mut constructed: Vec<(u32, u64)> = Vec::new();
        // (WS92) pointers whose class a mangled signature names: a parameter, or a pointer passed
        // to a callee with such a name
        let mut declared: Vec<(u32, String)> = Vec::new();
        if let Some(oracle) = ctx.oracle {
            for op in func.ops.iter().filter(|o| !o.dead && o.opcode == OpCode::Call) {
                let Some(t) = op.inputs.first().map(|&t| func.varnodes[t as usize].data).filter(|t| t.space == SpaceId::RAM).map(|t| t.offset) else { continue };
                for &v in op.inputs.iter().skip(1) {
                    let d = func.varnodes[v as usize].data;
                    if d.space != SpaceId::REGISTER || d.size != 8 || d.offset == RSP || frame.is_stack(func, v, op.block) {
                        continue;
                    }
                    let Some(ai) = oracle.args().iter().position(|a| a.space == d.space && a.offset == d.offset && a.size == d.size) else { continue };
                    let pu = oracle.param_use(t);
                    let used: Vec<_> = pu.iter().flat_map(|p| p.fields.iter()).filter(|f| f.arg == ai && f.size <= 16).copied().collect();
                    // (`this` is the second argument of a method returning a struct in memory)
                    let this_arg = usize::from(pu.as_ref().is_some_and(|p| p.returns_first));
                    let vtables: Vec<u64> = match ctx.memory {
                        Some(mem) => pu.iter().flat_map(|p| p.vtable_stores.iter()).filter(|&&(a, k)| a == ai && crate::vcall::is_vtable_point(mem, k)).map(|&(_, k)| k).collect(),
                        None => Vec::new(),
                    };
                    // the callee's mangled signature: the class its parameter points to
                    let int_index = oracle.args()[..ai].iter().filter(|a| a.size == d.size).count();
                    let named = ctx
                        .symbols
                        .and_then(|s| s.get(&t))
                        .and_then(|n| signature_classes(n))
                        .and_then(|cs| int_index.checked_sub(this_arg).and_then(|i| cs.get(i).cloned()))
                        .flatten();
                    if used.is_empty() && vtables.is_empty() && named.is_none() && !(ai == this_arg && nodes.contains_key(&value_key(func, v))) {
                        continue;
                    }
                    if let Some(c) = named {
                        let n = node(&mut uf, &mut nodes, value_key(func, v));
                        declared.push((n, c));
                    }
                    let n = node(&mut uf, &mut nodes, value_key(func, v));
                    if ai == this_arg {
                        this_calls.push((n, t));
                    }
                    constructed.extend(vtables.into_iter().map(|k| (n, k)));
                    for f in used {
                        raws.push(Raw { op: usize::MAX, base: n, off: f.off, size: f.size, value: None, float: false, add: None, base_input: 0, vptr: false, vtable_store: None, skip: false, callee: Some(t) });
                    }
                }
            }
        }
        if raws.is_empty() {
            return StructView::default();
        }

        let mut targets: Vec<u64> = vec![ctx.entry];
        targets.extend(this_calls.iter().map(|&(_, t)| t));
        let listing = match (ctx.memory, ctx.oracle) {
            (Some(m), Some(o)) if std::ptr::eq(m, o.memory) => o.vtables_listing(&targets),
            (Some(m), _) => crate::vcall::vtables_listing(m, &targets),
            (None, _) => FxHashMap::default(),
        };
        let class_of = |f: u64| ctx.memory.zip(listing.get(&f)).and_then(|(m, vts)| crate::vcall::method_class(m, vts));
        let sret = ctx.oracle.and_then(|o| o.param_use(ctx.entry)).is_some_and(|p| p.returns_first);
        // WS93: the classes the callers pass (the whole-binary index): `this` when neither the
        // name nor a vtable says it, the other parameters, the callees' results
        let indexed = |f: u64, i: Option<usize>| -> Option<(String, u64)> {
            let (ix, mem) = (ctx.this_index?, ctx.memory?);
            let vt = match i {
                Some(i) => ix.param_class(f, i)?,
                None => ix.ret_class(f)?,
            };
            Some((crate::vcall::vtable_class(mem, vt)?, vt))
        };
        let this_class: Option<(String, Option<u64>)> = ctx
            .name_class
            .clone()
            .map(|c| (c, None))
            .or_else(|| class_of(ctx.entry).map(|(c, v)| (c, Some(v))))
            .or_else(|| indexed(ctx.entry, Some(usize::from(sret))).map(|(c, v)| (c, Some(v))));
        let mut index_classes: Vec<(u32, (String, u64))> = Vec::new();
        if let (Some(_), Some(oracle)) = (ctx.this_index, ctx.oracle) {
            let ints: Vec<VarnodeData> = oracle.args().iter().filter(|a| a.size == 8).copied().collect();
            for (i, reg) in ints.iter().enumerate().take(6) {
                if i == usize::from(sret) {
                    continue;
                }
                if let Some(c) = indexed(ctx.entry, Some(i))
                    && let Some(v) = func.varnodes.iter().find(|v| v.def_op.is_none() && v.data == *reg)
                {
                    index_classes.push((node(&mut uf, &mut nodes, value_key(func, v.id)), c));
                }
            }
            for op in func.ops.iter().filter(|o| !o.dead && o.opcode == OpCode::Call) {
                let Some(t) = op.inputs.first().map(|&t| func.varnodes[t as usize].data).filter(|t| t.space == SpaceId::RAM).map(|t| t.offset) else { continue };
                if let Some(c) = indexed(t, None)
                    && let Some(o) = crate::emit::call_result(func, op).filter(|&o| func.varnodes[o as usize].data.size == 8 && !is_xmm(&func.varnodes[o as usize].data))
                {
                    index_classes.push((node(&mut uf, &mut nodes, value_key(func, o)), c));
                }
            }
        }
        // WS92: the parameters a mangled name types (`Scene::add(Circle*, Shape const&)`: `rsi`
        // is a `Circle*`, `rdx` a `Shape*`; `this` is `name_class`)
        if let (Some(classes), Some(oracle)) = (ctx.name.and_then(signature_classes), ctx.oracle) {
            let sret = usize::from(oracle.param_use(ctx.entry).is_some_and(|p| p.returns_first));
            let ints: Vec<VarnodeData> = oracle.args().iter().filter(|a| a.size == 8).copied().collect();
            for (i, c) in classes.iter().enumerate().skip(usize::from(ctx.name_class.is_some())) {
                let (Some(c), Some(reg)) = (c, ints.get(i + sret)) else { continue };
                if let Some(v) = func.varnodes.iter().find(|v| v.def_op.is_none() && v.data == *reg)
                    && let Some(&n) = nodes.get(&value_key(func, v.id))
                {
                    declared.push((n, c.clone()));
                }
            }
        }

        // WS92: what says a value is of a class, before the values are joined: `this`, a pointer
        // passed as `this` to a method listed in vtables, a vtable stored into an object here or
        // by a callee (a constructor called on it)
        let mut evidence: Vec<(u32, (String, u64))> = Vec::new();
        if let Some(mem) = ctx.memory {
            for &(n, t) in &this_calls {
                if let Some(c) = class_of(t) {
                    evidence.push((n, c));
                }
            }
            let stored = raws[..local].iter().filter_map(|r| Some((r.base, r.vtable_store?)));
            for (n, vt) in stored.chain(constructed.iter().copied()) {
                if let Some(c) = crate::vcall::vtable_class(mem, vt) {
                    evidence.push((n, (c, vt)));
                }
            }
            evidence.extend(index_classes.iter().cloned());
            if let (Some(reg), Some((c, Some(vt)))) = (ctx.arg_regs[usize::from(sret)], &this_class)
                && let Some(v) = func.varnodes.iter().find(|v| v.def_op.is_none() && v.data == reg)
                && let Some(&n) = nodes.get(&value_key(func, v.id))
            {
                evidence.push((n, (c.clone(), *vt)));
            }
        }
        // joining these types would mix two classes neither of which derives from the other
        let conflict = |uf: &Uf, roots: &[u32]| {
            let Some(mem) = ctx.memory else { return false };
            let mut classes: Vec<(String, u64)> = Vec::new();
            for (n, c) in &evidence {
                if roots.contains(&uf.find_const(*n)) && !classes.contains(c) {
                    classes.push(c.clone());
                }
            }
            classes.len() > 1 && crate::vcall::most_derived(mem, &classes).is_none()
        };

        // copies hold the same pointer; so do the versions a phi joins, unless they are objects
        // of unrelated classes (a register reused for two objects)
        // (the nodes first, in the order of the ops: the numbering decides the roots)
        for op in func.ops.iter().filter(|o| !o.dead && matches!(o.opcode, OpCode::Copy | OpCode::MultiEqual)) {
            let Some(out) = op.output.filter(|&o| func.varnodes[o as usize].data.size == 8) else { continue };
            node(&mut uf, &mut nodes, value_key(func, out));
            for &i in &op.inputs {
                let d = &func.varnodes[i as usize].data;
                if d.size == 8 && d.space != SpaceId::CONST {
                    node(&mut uf, &mut nodes, value_key(func, i));
                }
            }
        }
        for phis in [false, true] {
            let opcode = if phis { OpCode::MultiEqual } else { OpCode::Copy };
            for op in func.ops.iter().filter(|o| !o.dead && o.opcode == opcode) {
                let Some(out) = op.output else { continue };
                if func.varnodes[out as usize].data.size != 8 {
                    continue;
                }
                let o = node(&mut uf, &mut nodes, value_key(func, out));
                let ins: Vec<u32> = op
                    .inputs
                    .iter()
                    .filter(|&&i| {
                        let d = &func.varnodes[i as usize].data;
                        d.size == 8 && d.space != SpaceId::CONST
                    })
                    .map(|&i| node(&mut uf, &mut nodes, value_key(func, i)))
                    .collect();
                if phis && !evidence.is_empty() {
                    let roots: Vec<u32> = ins.iter().chain([&o]).map(|&n| uf.find(n)).collect();
                    if conflict(&uf, &roots) {
                        continue;
                    }
                }
                for n in ins {
                    uf.union(o, n);
                }
            }
        }

        // virtual calls: the slot is read through a vtable pointer loaded from the object
        let raw_at: FxHashMap<OpIdx, usize> = raws[..local].iter().enumerate().map(|(i, r)| (r.op, i)).collect();
        let mut vcall_raw: Vec<(OpIdx, usize, u64)> = Vec::new();
        let mut vtable_keys: Vec<ValueKey> = Vec::new();
        for op in func.ops.iter().filter(|o| !o.dead && o.opcode == OpCode::CallInd) {
            let Some(&t) = op.inputs.first() else { continue };
            let Some(slot_load) = def_of(strip_copies(func, t)).filter(|o| o.opcode == OpCode::Load && o.inputs.len() == 2) else { continue };
            let a = strip_copies(func, slot_load.inputs[1]);
            let (vt, slot) = match def_of(a) {
                Some(d) if d.opcode == OpCode::IntAdd && d.inputs.len() == 2 && konst(d.inputs[1]) && !konst(d.inputs[0]) => {
                    (strip_copies(func, d.inputs[0]), func.varnodes[d.inputs[1] as usize].data.offset)
                }
                _ => (a, 0),
            };
            if slot % 8 != 0 || slot >= 0x8000 {
                continue;
            }
            vtable_keys.push(value_key(func, vt));
            let Some(vload) = def_of(vt).filter(|o| o.opcode == OpCode::Load) else { continue };
            let Some(&ri) = raw_at.get(&vload.index) else { continue };
            if raws[ri].off != 0 || raws[ri].size != 8 {
                continue;
            }
            raws[ri].vptr = true;
            vcall_raw.push((op.index, ri, slot));
        }
        // a vtable is no struct: the reads through a vtable pointer (the slots) print as before
        let vtable_nodes: FxHashSet<u32> = vtable_keys
            .iter()
            .filter_map(|k| nodes.get(k).copied())
            .chain(raws[..local].iter().filter(|r| r.vptr).filter_map(|r| func.ops[r.op].output.and_then(|o| nodes.get(&value_key(func, o)).copied())))
            .collect::<Vec<u32>>()
            .into_iter()
            .map(|n| uf.find(n))
            .collect();
        for r in raws.iter_mut() {
            r.skip = vtable_nodes.contains(&uf.find(r.base));
        }
        vcall_raw.retain(|&(_, ri, _)| !raws[ri].skip);

        // the pointers loaded from / stored to one field of one type are of one type
        for _ in 0..MAX_PASSES {
            let mut seen: FxHashMap<(u32, u64), u32> = FxHashMap::default();
            let mut changed = false;
            for r in raws.iter().filter(|r| !r.vptr && !r.skip) {
                let Some(v) = r.value else { continue };
                let key = (uf.find(r.base), r.off);
                match seen.get(&key) {
                    Some(&w) if evidence.is_empty() || !conflict(&uf, &[uf.find_const(v), uf.find_const(w)]) => changed |= uf.union(v, w),
                    Some(_) => {}
                    None => {
                        seen.insert(key, v);
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // a pointer stepping through an array (`p = p + 4` of its own type): the element is at
        // most the step long, an access past it is another element's (it prints as before)
        let mut stride: FxHashMap<u32, u64> = FxHashMap::default();
        for op in func.ops.iter().filter(|o| !o.dead && matches!(o.opcode, OpCode::IntAdd | OpCode::IntSub) && o.inputs.len() == 2) {
            let Some(out) = op.output else { continue };
            let (b, k) = (op.inputs[0], op.inputs[1]);
            if !konst(k) || konst(b) {
                continue;
            }
            let k = (func.varnodes[k as usize].data.offset as i64).unsigned_abs();
            let (Some(&o), Some(&n)) = (nodes.get(&value_key(func, out)), nodes.get(&value_key(func, b))) else { continue };
            let root = uf.find(n);
            if k > 0 && k < MAX_FIELD && uf.find(o) == root {
                let e = stride.entry(root).or_insert(k);
                *e = (*e).min(k);
            }
        }
        for r in raws.iter_mut() {
            if stride.get(&uf.find(r.base)).is_some_and(|&st| r.off + u64::from(r.size) > st) {
                r.skip = true;
            }
        }
        vcall_raw.retain(|&(_, ri, _)| !raws[ri].skip);

        // classes: of `this` (its name, or the vtables listing the function), and of a pointer
        // passed as `this` to a method listed in vtables (the most derived of those classes)
        let mut root_classes: FxHashMap<u32, Vec<(String, u64)>> = FxHashMap::default();
        let mut add_class = |root: u32, c: (String, u64)| {
            let e = root_classes.entry(root).or_default();
            if !e.contains(&c) {
                e.push(c);
            }
        };
        for &(n, t) in &this_calls {
            if let Some(c) = class_of(t) {
                add_class(uf.find(n), c);
            }
        }
        for (n, c) in &index_classes {
            add_class(uf.find(*n), c.clone());
        }
        // WS92: the vtables stored into an object, here or by a callee (a constructor called on
        // it): of the class it is (with a base class's constructor or an inlined one, the most
        // derived of them)
        if let Some(mem) = ctx.memory {
            let stored = raws[..local].iter().filter(|r| !r.skip).filter_map(|r| Some((r.base, r.vtable_store?)));
            for (n, vt) in stored.chain(constructed.iter().copied()) {
                if let Some(c) = crate::vcall::vtable_class(mem, vt) {
                    add_class(uf.find(n), (c, vt));
                }
            }
        }
        let this_root = ctx.arg_regs[usize::from(sret)].and_then(|reg| {
            let v = func.varnodes.iter().find(|v| v.def_op.is_none() && v.data == reg)?;
            nodes.get(&value_key(func, v.id)).copied().map(|n| uf.find(n))
        });
        // WS92: the object a virtual call is made on, loaded from a field of an object of a known
        // class: of the class the constructors of that class store there (`classfields`)
        if let (Some(oracle), Some(mem)) = (ctx.oracle, ctx.memory)
            && !vcall_raw.is_empty()
        {
            // the parameters' nodes: `(node, integer parameter)`
            let param_roots: Vec<(u32, usize)> = oracle
                .args()
                .iter()
                .filter(|a| a.size == 8)
                .take(6)
                .enumerate()
                .filter_map(|(i, reg)| {
                    let v = func.varnodes.iter().find(|v| v.def_op.is_none() && v.data == *reg)?;
                    Some((*nodes.get(&value_key(func, v.id))?, i))
                })
                .collect();
            let objects: FxHashSet<u32> = vcall_raw.iter().map(|&(_, ri, _)| uf.find(raws[ri].base)).collect();
            // WS95: a pointer loaded from a field: `pointer root -> (container root, field offset)`,
            // so a vcall object loaded through an element pointer (`container->begin[i]`) can be
            // typed by the container's element class
            let mut loaded_from: FxHashMap<u32, (u32, u64)> = FxHashMap::default();
            for r in raws[..local].iter().filter(|r| !r.skip && !r.vptr && r.size == 8 && func.ops[r.op].opcode == OpCode::Load) {
                if let Some(v) = r.value {
                    loaded_from.entry(uf.find(v)).or_insert((uf.find(r.base), r.off));
                }
            }
            for _ in 0..2 {
                let mut added = false;
                for r in raws[..local].iter().filter(|r| !r.skip && !r.vptr && r.size == 8 && func.ops[r.op].opcode == OpCode::Load) {
                    let Some(v) = r.value else { continue };
                    let obj = uf.find(v);
                    if !objects.contains(&obj) || root_classes.contains_key(&obj) || Some(obj) == this_root {
                        continue;
                    }
                    let base = uf.find(r.base);
                    let vt = match (Some(base) == this_root, &this_class) {
                        (true, Some((_, Some(vt)))) => Some(*vt),
                        _ => root_classes.get(&base).and_then(|cs| crate::vcall::most_derived(mem, cs)).map(|c| c.1),
                    };
                    // (WS93: else the class the index joins over every store into that field)
                    let ovt = vt.and_then(|vt| oracle.class_fields(vt).iter().find(|f| f.0 == r.off).map(|f| f.1).or_else(|| ctx.this_index?.field_class(vt, r.off as i64)));
                    // (WS94: a field of a parameter: the class every caller put there)
                    let ovt = ovt.or_else(|| {
                        let i = param_roots.iter().find(|p| uf.find_const(p.0) == base)?.1;
                        ctx.this_index?.param_field_class(ctx.entry, i, r.off as i64)
                    });
                    // (WS95: an element of a buffer: `obj = container->begin[i]`, the base being
                    // the begin pointer loaded from the container's `begin` field; only at offset
                    // 0, an element dereferenced at its start)
                    let ovt = ovt.or_else(|| {
                        if r.off != 0 {
                            return None;
                        }
                        let &(cbase, boff) = loaded_from.get(&base)?;
                        let cvt = match (Some(cbase) == this_root, &this_class) {
                            (true, Some((_, Some(vt)))) => Some(*vt),
                            _ => root_classes.get(&cbase).and_then(|cs| crate::vcall::most_derived(mem, cs)).map(|c| c.1),
                        }?;
                        ctx.this_index?.element_class(cvt, boff as i64)
                    });
                    if let Some(ovt) = ovt
                        && let Some(c) = crate::vcall::vtable_class(mem, ovt)
                    {
                        root_classes.entry(obj).or_default().push((c, ovt));
                        added = true;
                    }
                }
                if !added {
                    break;
                }
            }
            // WS96: an object loaded from an element at an address computed from a container's
            // begin / end pointer — indexed (`begin[i]`, `*(begin + (i << 3))`) or before it
            // (`end[-1]`) —, a virtual call made on it: the container's element class
            if let Some(ix) = ctx.this_index {
                for &(_, ri, _) in &vcall_raw {
                    let obj = uf.find(raws[ri].base);
                    if root_classes.contains_key(&obj) || Some(obj) == this_root {
                        continue;
                    }
                    let Some(&ovar) = func.ops[raws[ri].op].inputs.get(1) else { continue };
                    let Some(load) = def_of(strip_copies(func, ovar)).filter(|o| o.opcode == OpCode::Load && o.inputs.len() == 2) else { continue };
                    let Some(add) = def_of(strip_copies(func, load.inputs[1])).filter(|o| o.opcode == OpCode::IntAdd && o.inputs.len() == 2) else { continue };
                    let found = add.inputs.iter().filter(|&&b| !konst(b)).find_map(|&b| {
                        let n = *nodes.get(&value_key(func, strip_copies(func, b)))?;
                        let &(cbase, boff) = loaded_from.get(&uf.find_const(n))?;
                        let cvt = match (Some(cbase) == this_root, &this_class) {
                            (true, Some((_, Some(vt)))) => Some(*vt),
                            _ => root_classes.get(&cbase).and_then(|cs| crate::vcall::most_derived(mem, cs)).map(|c| c.1),
                        }?;
                        let evt = ix.element_class(cvt, boff as i64)?;
                        Some((crate::vcall::vtable_class(mem, evt)?, evt))
                    });
                    if let Some(c) = found {
                        root_classes.entry(obj).or_default().push(c);
                    }
                }
            }
        }

        // the types that are structs: an access past offset 0, or a vtable pointer
        let mut is_base: FxHashSet<u32> = FxHashSet::default();
        let mut struct_roots: Vec<u32> = Vec::new();
        for r in raws.iter().filter(|r| !r.skip) {
            let root = uf.find(r.base);
            is_base.insert(root);
            if (r.off > 0 || r.vptr) && !struct_roots.contains(&root) {
                struct_roots.push(root);
            }
        }
        // `this` of a known class is a struct too
        if let (Some(r), Some(_)) = (this_root, &this_class)
            && is_base.contains(&r)
            && !struct_roots.contains(&r)
        {
            struct_roots.push(r);
        }
        // and a pointer a signature names the class of, when it is dereferenced
        let declared_roots: Vec<(u32, String)> = declared.iter().map(|(n, c)| (uf.find(*n), c.clone())).collect();
        for (r, _) in &declared_roots {
            if is_base.contains(r) && !struct_roots.contains(r) {
                struct_roots.push(*r);
            }
        }
        // and a pointer a method of a known class takes as `this`
        for &r in root_classes.keys() {
            if !struct_roots.contains(&r) {
                struct_roots.push(r);
            }
        }
        struct_roots.sort_by_key(|&r| first_use(&raws, &uf, r));
        let def_of_root: FxHashMap<u32, usize> = struct_roots.iter().enumerate().map(|(i, &r)| (r, i)).collect();

        // the layout of each struct
        let mut defs: Vec<StructDef> = (0..struct_roots.len())
            .map(|i| StructDef { name: format!("struct_{i}"), class: None, vtable: None, fields: Vec::new(), stride: stride.get(&struct_roots[i]).copied(), class_from_symbol: false })
            .collect();
        let mut by_def: Vec<Vec<usize>> = vec![Vec::new(); defs.len()];
        for (i, r) in raws.iter().enumerate().filter(|(_, r)| !r.skip) {
            if let Some(&d) = def_of_root.get(&uf.find(r.base)) {
                by_def[d].push(i);
            }
        }
        let mut access: FxHashMap<OpIdx, Access> = FxHashMap::default();
        for (d, list) in by_def.iter().enumerate() {
            // candidates: the widest access (at most 16 bytes) at each start, and how often
            // (the function's own accesses first, then those only a callee makes)
            let mut starts: std::collections::BTreeMap<u64, (u32, usize, bool)> = std::collections::BTreeMap::new();
            for &i in list {
                let r = &raws[i];
                if r.size > 16 {
                    continue;
                }
                let e = starts.entry(r.off).or_insert((0, 0, true));
                e.0 = e.0.max(r.size);
                e.1 += 1;
                e.2 &= r.callee.is_some();
            }
            let mut order: Vec<(u64, u32, usize, bool)> = starts.iter().map(|(&o, &(s, n, c))| (o, s, n, c)).collect();
            // (a 16-byte access is a copy of several fields more often than one: last)
            order.sort_by_key(|&(o, s, n, c)| (c, s > 10, std::cmp::Reverse(n), o));
            let mut kept: Vec<(u64, u32)> = Vec::new();
            for (o, s, _, _) in order {
                let end = o + u64::from(s);
                if kept.iter().all(|&(ko, ks)| end <= ko || ko + u64::from(ks) <= o) {
                    kept.push((o, s));
                }
            }
            kept.sort();
            let mut fields = Vec::new();
            for (o, s) in kept {
                let all: Vec<&Raw> = list.iter().map(|&i| &raws[i]).filter(|r| r.off == o).collect();
                let from = all.iter().all(|r| r.callee.is_some()).then(|| all.iter().find_map(|r| r.callee)).flatten();
                let at: Vec<&Raw> = all.iter().copied().filter(|r| r.callee.is_none()).collect();
                let kind = if o == 0 && s == 8 && at.iter().any(|r| r.vptr) {
                    FieldKind::VPtr
                } else if s == 8 && !at.is_empty() && at.iter().all(|r| r.size == 8 && r.value.is_some_and(|v| is_base.contains(&uf.find(v)))) {
                    FieldKind::Ptr(at.iter().find_map(|r| r.value.and_then(|v| def_of_root.get(&uf.find(v)).copied())))
                } else if matches!(s, 4 | 8) && !at.is_empty() && at.iter().all(|r| r.size == s && r.float) {
                    FieldKind::Float
                } else {
                    FieldKind::Int
                };
                fields.push(Field { off: o, size: s, kind, from, vector: None });
            }
            for &i in list.iter().filter(|&&i| raws[i].callee.is_none()) {
                let r = &raws[i];
                if let Some(fi) = fields.iter().position(|f| f.off == r.off && r.size <= f.size) {
                    access.insert(r.op, Access { def: d, field: fi, size: r.size, add: r.add, base_input: r.base_input });
                }
                if let Some(v) = r.vtable_store {
                    defs[d].vtable = Some(v);
                }
            }
            defs[d].fields = fields;
        }

        // classes: `this`, and the vtables stored into objects
        if let (Some(r), Some((name, vt))) = (this_root, &this_class)
            && let Some(&d) = def_of_root.get(&r)
        {
            defs[d].class = Some(name.clone());
            defs[d].class_from_symbol = ctx.name_class.is_some();
            if defs[d].vtable.is_none() {
                defs[d].vtable = *vt;
            }
        }
        for (r, classes) in &root_classes {
            if let (Some(&d), Some(mem)) = (def_of_root.get(r), ctx.memory)
                && defs[d].class.is_none()
                && let Some((name, vt)) = crate::vcall::most_derived(mem, classes)
            {
                defs[d].class = Some(name);
                defs[d].vtable = Some(vt);
            }
        }
        if let Some(mem) = ctx.memory {
            for d in defs.iter_mut().filter(|d| d.class.is_none()) {
                if let Some(v) = d.vtable {
                    d.class = crate::vcall::vtable_class(mem, v);
                }
            }
        }
        for (r, c) in &declared_roots {
            if let Some(&d) = def_of_root.get(r)
                && defs[d].class.is_none()
            {
                defs[d].class = Some(c.clone());
                defs[d].class_from_symbol = true;
            }
        }
        // WS96: the fields of a class that are a vector's pointers (the index's element classes)
        if let (Some(ix), Some(mem)) = (ctx.this_index, ctx.memory) {
            for d in defs.iter_mut() {
                let Some(vt) = d.vtable else { continue };
                let roles: Vec<(u64, VectorField)> = d
                    .fields
                    .iter()
                    .filter(|f| f.size == 8 && f.kind != FieldKind::VPtr)
                    .flat_map(|f| (0..3u8).map(move |role| (f.off, role)))
                    .filter_map(|(off, role)| {
                        let begin = off.checked_sub(8 * u64::from(role))?;
                        let evt = ix.vector_element(vt, begin as i64)?;
                        Some((off, VectorField { elem: crate::vcall::vtable_class(mem, evt)?, role, begin }))
                    })
                    .collect();
                for (off, v) in roles {
                    if let Some(f) = d.fields.iter_mut().find(|f| f.off == off && f.vector.is_none()) {
                        f.vector = Some(v);
                    }
                }
            }
        }
        // names: the class, else `struct_N` by first access; one struct per class name
        let mut taken: FxHashMap<String, usize> = FxHashMap::default();
        let mut anon = 0;
        for d in defs.iter_mut() {
            d.name = match &d.class {
                Some(c) => {
                    let n = taken.entry(c.clone()).or_insert(0);
                    *n += 1;
                    if *n == 1 { c.clone() } else { format!("{c}_{}", *n - 1) }
                }
                None => {
                    anon += 1;
                    format!("struct_{}", anon - 1)
                }
            };
        }

        let value_def: FxHashMap<ValueKey, usize> = nodes
            .iter()
            .filter_map(|(&k, &n)| def_of_root.get(&uf.find(n)).map(|&d| (k, d)))
            .collect();
        let mut vcalls = FxHashMap::default();
        for (call, ri, slot) in vcall_raw {
            let r = &raws[ri];
            let Some(&d) = def_of_root.get(&uf.find(r.base)) else { continue };
            let obj = strip_copies(func, func.ops[r.op].inputs[1]);
            let target = defs[d].vtable.zip(ctx.memory).and_then(|(vt, mem)| crate::vcall::slot_target(mem, vt, slot));
            vcalls.insert(call, VCall { def: d, slot, vptr_load: r.op, object: value_key(func, obj), target });
        }
        // a register stepped in place (`add r9, 0x18`, `lea r9, [r9+0x18]`) — unless the new value
        // is passed to a call (`lea rdi, [rdi+0x10]; call f`: a member's address)
        let same_register = |a: VarId, b: VarId| {
            let (x, y) = (func.varnodes[a as usize].data, func.varnodes[b as usize].data);
            x.space == SpaceId::REGISTER && y.space == SpaceId::REGISTER && x.offset == y.offset
        };
        let passed = |v: VarId| {
            readers.of(func, v).iter().any(|&u| {
                let c = &func.ops[u];
                matches!(c.opcode, OpCode::Call | OpCode::CallInd) && c.inputs.iter().skip(1).any(|&i| value_key(func, i) == value_key(func, v))
            })
        };
        let steps = func
            .ops
            .iter()
            .filter(|o| !o.dead && o.opcode == OpCode::IntAdd && o.inputs.len() == 2)
            .filter(|o| {
                let Some(out) = o.output else { return false };
                o.inputs.iter().any(|&b| {
                    (same_register(out, b) && !passed(out))
                        || readers.of(func, out).iter().any(|&u| {
                            func.ops[u].opcode == OpCode::Copy && func.ops[u].output.is_some_and(|w| same_register(w, b) && !passed(w))
                        })
                })
            })
            .map(|o| o.index)
            .collect();
        let local_stores = func
            .ops
            .iter()
            .filter(|o| !o.dead && o.opcode == OpCode::Store)
            .filter(|o| o.inputs.get(1).and_then(|&a| frame.offset_at(func, a, o.block)).is_some_and(|k| k < 0))
            .map(|o| o.index)
            .collect();
        StructView { defs, value_def, access, vcalls, steps, local_stores }
    }

    /// The struct of value `v`, if it is a pointer to one.
    pub(crate) fn def_of_value(&self, func: &SsaFunction, v: VarId) -> Option<usize> {
        self.value_def.get(&value_key(func, v)).copied()
    }

    /// The struct a parameter register named `name` points to on entry.
    pub(crate) fn param_def(&self, func: &SsaFunction, name: &str, reg_name: &dyn Fn(&VarnodeData) -> String) -> Option<usize> {
        let v = func.varnodes.iter().find(|v| v.def_op.is_none() && v.data.space == SpaceId::REGISTER && v.data.size == 8 && reg_name(&v.data) == name)?;
        self.def_of_value(func, v.id)
    }

    /// The registers (by offset, 8 bytes) that point to one struct in every value the body
    /// assigns them (`printed`: the defining op prints).
    pub(crate) fn register_defs(&self, func: &SsaFunction, printed: &dyn Fn(OpIdx) -> bool) -> FxHashMap<u64, usize> {
        let mut seen: FxHashMap<u64, Option<usize>> = FxHashMap::default();
        for v in func.varnodes.iter().filter(|v| v.data.space == SpaceId::REGISTER && v.data.size == 8) {
            let Some(d) = v.def_op.filter(|&d| printed(d)) else { continue };
            let _ = d;
            let def = self.def_of_value(func, v.id);
            let e = seen.entry(v.data.offset).or_insert(def);
            if *e != def {
                *e = None;
            }
        }
        seen.into_iter().filter_map(|(k, d)| Some((k, d?))).collect()
    }

    /// `base + k` as the address of a field (WS91, `&base->field_k`): the base's input index and
    /// the field, when `op` adds a constant to a pointer to a struct with a field starting there.
    pub(crate) fn field_address(&self, func: &SsaFunction, op: &crate::ssa::SsaOp) -> Option<(usize, &Field)> {
        if op.opcode != OpCode::IntAdd || op.inputs.len() != 2 {
            return None;
        }
        let konst = |i: usize| func.varnodes[op.inputs[i] as usize].data.space == SpaceId::CONST;
        let (bi, ki) = match (konst(0), konst(1)) {
            (false, true) => (0, 1),
            (true, false) => (1, 0),
            _ => return None,
        };
        let k = func.varnodes[op.inputs[ki] as usize].data.offset;
        let d = self.def_of_value(func, op.inputs[bi])?;
        // (a pointer of the type stepping on, `p = p + 4`, is no field's address; nor is a
        // register stepped in place, `add r9, 0x18`)
        if op.output.is_some_and(|o| self.def_of_value(func, o) == Some(d)) {
            return None;
        }
        if self.steps.contains(&op.index) {
            return None;
        }
        let f = self.defs[d].fields.iter().find(|f| f.off == k && k > 0)?;
        Some((bi, f))
    }

    /// The statements that only load a vtable pointer for virtual calls printed as `obj->vfn_n()`
    /// (WS91): the vptr's load (or the copy it is inlined into) when every reader of the value
    /// is the slot load of such a call, inlined into it (`inlined`), and the call prints as a
    /// member call (`member`). Folded into the calls, they print nothing.
    pub(crate) fn folded_vptr_loads(
        &self,
        func: &SsaFunction,
        inlined: &dyn Fn(OpIdx) -> bool,
        member: &dyn Fn(OpIdx) -> bool,
    ) -> Vec<OpIdx> {
        let readers = crate::condition::Readers::new(func);
        let mut out = Vec::new();
        let loads: FxHashSet<OpIdx> = self.vcalls.values().map(|v| v.vptr_load).collect();
        for &l in &loads {
            let Some(v) = func.ops[l].output else { continue };
            // the statement printing the vptr: the load, or the copy of the inlined load
            let (stmt, w) = if inlined(l) {
                match readers.of(func, v) {
                    [c] if func.ops[*c].opcode == OpCode::Copy && func.ops[*c].output.is_some() => (*c, func.ops[*c].output.expect("checked")),
                    _ => continue,
                }
            } else {
                (l, v)
            };
            // a slot load inlined into member calls only (a call's INDIRECT annotations name it too)
            let slot_load = |u: OpIdx| {
                let r = &func.ops[u];
                r.opcode == OpCode::Load && inlined(u) && r.output.is_some_and(|o| {
                    let rs = readers.of(func, o);
                    rs.iter().any(|&c| func.ops[c].opcode == OpCode::CallInd)
                        && rs.iter().all(|&c| {
                            let call = &func.ops[c];
                            call.opcode == OpCode::Indirect
                                || (call.opcode == OpCode::CallInd && call.inputs.first().is_some_and(|&t| value_key(func, t) == value_key(func, o)) && member(c))
                        })
                })
            };
            // ... read directly or through `vptr + 8·n` inlined into it
            let ok = readers.of(func, w).iter().all(|&u| {
                let r = &func.ops[u];
                match r.opcode {
                    OpCode::Load => slot_load(u),
                    OpCode::IntAdd => inlined(u) && r.output.is_some_and(|o| {
                        let rs = readers.of(func, o);
                        !rs.is_empty() && rs.iter().all(|&l| slot_load(l))
                    }),
                    _ => false,
                }
            });
            if ok && !readers.of(func, w).is_empty() {
                out.push(stmt);
            }
        }
        out
    }

    /// The C definitions, in order.
    pub fn c_definitions(&self) -> Vec<String> {
        self.defs.iter().map(|d| d.c_definition(&self.defs)).collect()
    }

    pub fn rust_definitions(&self) -> Vec<String> {
        self.defs.iter().map(|d| d.rust_definition(&self.defs)).collect()
    }

    /// Whether virtual call `call` prints as `obj->vfn_n(…)`: the vtable pointer is loaded in
    /// the call's block with no store or call between, and the first argument is the object.
    pub(crate) fn member_call(&self, func: &SsaFunction, call: &crate::ssa::SsaOp) -> Option<&VCall> {
        let vc = self.vcalls.get(&call.index)?;
        let arg = *call.inputs.get(1)?;
        if value_key(func, strip_copies(func, arg)) != vc.object {
            return None;
        }
        let load = &func.ops[vc.vptr_load];
        if load.block != call.block || load.index > call.index {
            return None;
        }
        // (a store to the function's own stack slot is fine: a spill)
        let between = func.ops[load.index + 1..call.index].iter().any(|o| {
            !o.dead
                && o.block == call.block
                && matches!(o.opcode, OpCode::Store | OpCode::Call | OpCode::CallInd | OpCode::CallOther)
                && !self.local_stores.contains(&o.index)
        });
        (!between).then_some(vc)
    }
}

/// The first op (index) of a local access through a pointer of type `root` (callee accesses
/// last): the structs are numbered in the order the body first uses them.
fn first_use(raws: &[Raw], uf: &Uf, root: u32) -> usize {
    raws.iter().filter(|r| uf.find_const(r.base) == root).map(|r| if r.callee.is_some() { usize::MAX } else { r.op }).min().unwrap_or(usize::MAX)
}

/// The name of the slot function `target` of a virtual call on an object of class `class`:
/// its symbol (demangled), else `Class::method_at_<addr>`.
pub(crate) fn method_name(symbols: &std::collections::BTreeMap<u64, String>, class: Option<&str>, target: u64) -> String {
    if let Some(s) = symbols.get(&target) {
        return demangle_symbol(s).unwrap_or_else(|| s.clone());
    }
    match class {
        Some(c) => format!("{c}::method_at_{target:x}"),
        None => format!("0x{target:x}"),
    }
}

/// An Itanium-mangled function name as C++ (`_ZN5Class6methodEv` -> `Class::method()`).
pub fn demangle_symbol(s: &str) -> Option<String> {
    if !s.starts_with("_Z") {
        return None;
    }
    cpp_demangle::Symbol::new(s.as_bytes()).ok()?.demangle(&cpp_demangle::DemangleOptions::default()).ok()
}

/// The classes the integer / pointer parameters of a function point to, from its mangled name
/// (WS92), in register order — `this` first for a method (taken to be no static member),
/// `None` for one that is no class pointer or reference (an `int`, a `char*`, a pointer to a
/// pointer). `_ZN5Scene3addEP6CircleRK5Shape` (`Scene::add(Circle*, Shape const&)`) ->
/// `[Scene, Circle, Shape]`. A float parameter takes no integer register; the list ends before
/// a parameter passed by value that is no scalar (a class or an enum: where it goes is not
/// known) or `...`. `None` when the name does not demangle.
pub fn signature_classes(name: &str) -> Option<Vec<Option<String>>> {
    let demangled = demangle_symbol(name)?;
    let s = demangled.as_str();
    // the top-level parameter list
    let mut depth = 0i32;
    let mut open = None;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            '(' if depth == 0 && !s[i..].starts_with("(anonymous namespace)") => {
                open = Some(i);
                break;
            }
            _ => {}
        }
    }
    let open = open?;
    let mut params: Vec<&str> = Vec::new();
    let (mut depth, mut start, mut close) = (0i32, open + 1, None);
    for (i, c) in s[open + 1..].char_indices().map(|(i, c)| (i + open + 1, c)) {
        match c {
            '<' | '(' | '[' => depth += 1,
            ')' if depth == 0 => {
                close = Some(i);
                break;
            }
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                params.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let close = close?;
    let last = s[start..close].trim();
    if !last.is_empty() {
        params.push(last);
    }
    let mut out: Vec<Option<String>> = Vec::new();
    if let Some(c) = method_class(name) {
        out.push(Some(c));
    }
    const INTS: &[&str] = &[
        "bool", "char", "signed char", "unsigned char", "short", "unsigned short", "int", "unsigned int", "long", "unsigned long", "long long",
        "unsigned long long", "wchar_t", "char8_t", "char16_t", "char32_t", "__int128", "unsigned __int128", "std::nullptr_t", "decltype(nullptr)",
    ];
    const FLOATS: &[&str] = &["float", "double"];
    for p in params {
        let p = p.strip_suffix(" const").unwrap_or(p);
        if p == "void" || p.is_empty() {
            continue;
        }
        if p == "..." || p == "long double" {
            break;
        }
        if p.contains('(') {
            out.push(None); // a pointer to a function
            continue;
        }
        let pointee = p.strip_suffix("&&").or_else(|| p.strip_suffix('&')).or_else(|| p.strip_suffix('*'));
        match pointee {
            Some(t) => {
                let t = t.trim_end();
                let t = t.strip_suffix(" const").unwrap_or(t).trim();
                let t = t.strip_prefix("const ").unwrap_or(t);
                let class = !(t.ends_with('*') || t.ends_with('&') || t == "void" || INTS.contains(&t) || FLOATS.contains(&t) || t == "long double");
                out.push(class.then(|| t.to_string()));
            }
            None if INTS.contains(&p) => out.push(None),
            None if FLOATS.contains(&p) => {}
            None => break,
        }
    }
    Some(out)
}

/// The class of a method from its (mangled or demangled) name: `_ZN5Class6methodEv` /
/// `Class::method()` -> `Class`, `_ZNK2ns5Class3getEv` -> `ns::Class`. `None` for a free
/// function, a name without a scope, or a function-local entity.
pub fn method_class(name: &str) -> Option<String> {
    let demangled = demangle_symbol(name);
    let s = demangled.as_deref().unwrap_or(name);
    // the qualified name ends at the top-level `(` of the parameter list
    let mut depth = 0i32;
    let mut end = s.len();
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            '(' if depth == 0 && !s[i..].starts_with("(anonymous namespace)") => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    if end == s.len() && demangled.is_none() {
        // not a demangled signature (a plain symbol like `FUN_401000`)
        return None;
    }
    let q = &s[..end];
    // split at the last top-level `::`
    let mut depth = 0i32;
    let mut cut = None;
    let b = q.as_bytes();
    for i in 0..b.len() {
        match b[i] {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b':' if depth == 0 && b.get(i + 1) == Some(&b':') => cut = Some(i),
            _ => {}
        }
    }
    let class = &q[..cut?];
    let plain = class.replace("(anonymous namespace)", "");
    (!class.is_empty() && !plain.contains('(') && !plain.ends_with(')')).then(|| class.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pipeline::{decompile, decompile_with_options, DecompileOptions};
    use reargo_core::address::Endian;
    use reargo_lift::x86::X86Lifter;
    use reargo_loader::memory::{MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    fn block(name: &str, start: u64, data: Vec<u8>, flags: MemoryFlags) -> MemoryBlock {
        MemoryBlock { name: name.into(), start, size: data.len() as u64, flags, data: Some(Arc::from(data.as_slice())) }
    }

    fn text(code: &[u8]) -> Memory {
        let mut mem = Memory::new(reargo_core::address::SpaceId(1), Endian::Little);
        mem.add_block(block(".text", 0x1000, code.to_vec(), MemoryFlags::READ | MemoryFlags::EXECUTE));
        mem
    }

    fn c_of(code: &[u8]) -> crate::pipeline::DecompileResult {
        decompile(&X86Lifter::new_64(), &text(code), 0x1000, "f", 100).unwrap()
    }

    fn raw_of(code: &[u8]) -> crate::pipeline::DecompileResult {
        let opts = DecompileOptions { structs: false, ..Default::default() };
        decompile_with_options(&X86Lifter::new_64(), &text(code), 0x1000, "f", 100, &Default::default(), &opts).unwrap()
    }

    #[test]
    fn accesses_through_one_pointer_are_fields_of_one_struct() {
        // mov [rdi+0x10], esi ; mov eax, [rdi+0x14] ; ret
        let code = [0x89, 0x77, 0x10, 0x8b, 0x47, 0x14, 0xc3];
        let r = c_of(&code);
        assert!(r.c_code.contains("rdi->field_10 = esi;"), "{}", r.c_code);
        assert!(r.c_code.contains("rdi->field_14"), "{}", r.c_code);
        assert!(r.c_code.contains("(struct struct_0* rdi, uint64_t rsi)"), "{}", r.c_code);
        assert_eq!(r.recovered_structs.len(), 1);
        assert!(r.recovered_structs[0].contains("uint32_t field_10; // +0x10\n    uint32_t field_14; // +0x14"), "{}", r.recovered_structs[0]);
        // the flag turns it off
        let raw = raw_of(&code);
        assert!(raw.c_code.contains("*(uint32_t*)(rdi + 0x10) = esi;"), "{}", raw.c_code);
        assert!(!raw.c_code.contains("->") && raw.recovered_structs.is_empty(), "{}", raw.c_code);
    }

    #[test]
    fn a_copied_pointer_has_the_same_struct() {
        // mov rbx, rdi ; mov [rbx+8], esi ; mov eax, [rdi+0xc] ; ret
        let r = c_of(&[0x48, 0x89, 0xfb, 0x89, 0x73, 0x08, 0x8b, 0x47, 0x0c, 0xc3]);
        assert!(r.c_code.contains("rbx->field_8 = esi;"), "{}", r.c_code);
        assert!(r.c_code.contains("rdi->field_c"), "{}", r.c_code);
        assert_eq!(r.recovered_structs.len(), 1, "{:?}", r.recovered_structs);
        assert!(r.c_code.contains("struct struct_0* rbx;"), "{}", r.c_code);
    }

    #[test]
    fn an_access_inside_a_wider_field_stays_raw() {
        // mov [rdi+8], rax ; mov ecx, [rdi+0xc] ; mov [rdi+0x18], ecx ; ret
        let r = c_of(&[0x48, 0x89, 0x47, 0x08, 0x8b, 0x4f, 0x0c, 0x89, 0x4f, 0x18, 0xc3]);
        assert!(r.c_code.contains("rdi->field_8 = rax;"), "{}", r.c_code);
        assert!(r.c_code.contains("*(uint32_t*)(rdi + 0xc)"), "{}", r.c_code);
        assert!(r.c_code.contains("rdi->field_18 = "), "{}", r.c_code);
        assert!(!r.recovered_structs[0].contains("field_c;"), "{}", r.recovered_structs[0]);
    }

    #[test]
    fn a_narrower_read_goes_through_the_field() {
        // mov rax, [rdi+8] ; mov ecx, [rdi+8] ; mov [rsi], ecx ; ret
        let r = c_of(&[0x48, 0x8b, 0x47, 0x08, 0x8b, 0x4f, 0x08, 0x89, 0x0e, 0xc3]);
        assert!(r.c_code.contains("rax = rdi->field_8;"), "{}", r.c_code);
        assert!(r.c_code.contains("(uint32_t)rdi->field_8"), "{}", r.c_code);
    }

    #[test]
    fn a_loaded_pointer_is_a_typed_field() {
        // mov rax, [rdi+8] ; mov ecx, [rax+0x10] ; mov eax, [rax+0x14] ; add eax, ecx ; ret
        let r = c_of(&[0x48, 0x8b, 0x47, 0x08, 0x8b, 0x48, 0x10, 0x8b, 0x40, 0x14, 0x01, 0xc8, 0xc3]);
        assert!(r.c_code.contains("rax = rdi->field_8;"), "{}", r.c_code);
        assert!(r.c_code.contains("rax->field_10"), "{}", r.c_code);
        assert!(r.recovered_structs[0].contains("struct struct_1* field_8;"), "{:?}", r.recovered_structs);
    }

    #[test]
    fn a_pointer_stepping_through_an_array_has_no_fields_past_the_step() {
        // xor ecx, ecx ; L: mov eax, [rdi+4] ; add eax, [rdi+0xc] ; mov [rdi], eax ; add rdi, 8 ; cmp rdi, rsi ; jne L ; ret
        let code = [0x31, 0xc9, 0x8b, 0x47, 0x04, 0x03, 0x47, 0x0c, 0x89, 0x07, 0x48, 0x83, 0xc7, 0x08, 0x48, 0x39, 0xf7, 0x75, 0xef, 0xc3];
        let r = c_of(&code);
        assert!(r.c_code.contains("*(uint32_t*)(rdi + 0xc)"), "{}", r.c_code);
        assert!(r.c_code.contains("rdi->field_4"), "{}", r.c_code);
        assert!(r.c_code.contains("rdi = rdi + 8;"), "{}", r.c_code);
        assert!(r.recovered_structs[0].contains("array element: a pointer to it steps by 0x8"), "{:?}", r.recovered_structs);
    }

    #[test]
    fn a_members_address_passed_to_a_call() {
        // mov rsi, [rdi+0x10] ; lea rdi, [rdi+0x10] ; call 0x2000 ; ret
        let mut code = vec![0x48, 0x8b, 0x77, 0x10, 0x48, 0x8d, 0x7f, 0x10, 0xe8, 0xf3, 0x0f, 0x00, 0x00, 0xc3];
        code.resize(0x1100, 0xcc);
        // 0x2000: mov rax, [rsi] ; add rax, [rdi] ; ret
        code[0x1000..0x1007].copy_from_slice(&[0x48, 0x8b, 0x06, 0x48, 0x03, 0x07, 0xc3]);
        let r = c_of(&code);
        assert!(r.c_code.contains("rdi = &rdi->field_10;"), "{}", r.c_code);
        // WS92: the Rust output too
        assert!(r.rust_code.contains("rdi = unsafe { &raw mut (*rdi).field_10 };"), "{}", r.rust_code);
    }

    /// WS92: a field's address copied from another register prints as one in Rust too.
    #[test]
    fn a_members_address_in_another_register_in_rust() {
        // mov rbx, rdi ; mov dword [rbx+0x98], 0 ; lea rdi, [rbx+0x98] ; call 0x2000 ; ret
        let mut code = vec![0x48, 0x89, 0xfb, 0xc7, 0x83, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0xbb, 0x98, 0x00, 0x00, 0x00, 0xe8, 0xe7, 0x0f, 0x00, 0x00, 0xc3];
        code.resize(0x1100, 0xcc);
        // 0x2000: mov eax, [rdi] ; ret
        code[0x1000..0x1003].copy_from_slice(&[0x8b, 0x07, 0xc3]);
        let r = c_of(&code);
        assert!(r.c_code.contains("rdi = &rbx->field_98;"), "{}", r.c_code);
        assert!(r.rust_code.contains("rdi = unsafe { &raw mut (*rbx).field_98 };"), "{}", r.rust_code);
    }

    #[test]
    fn a_virtual_call_on_an_object_is_a_member_call() {
        // mov rax, [rdi] ; call [rax+0x18] ; ret
        let code = [0x48, 0x8b, 0x07, 0xff, 0x50, 0x18, 0xc3];
        let r = c_of(&code);
        assert!(r.c_code.contains("rdi->vfn_3();  // vfn[3] (vtable+0x18)"), "{}", r.c_code);
        assert!(!r.c_code.contains("_vptr;"), "the vtable pointer load prints in the call: {}", r.c_code);
        assert!(r.recovered_structs[0].contains("void** _vptr; // +0x0"), "{:?}", r.recovered_structs);
        assert!(raw_of(&code).c_code.contains("(**(uint64_t*)(rax + 0x18))(rdi);"));
        // Rust too
        assert!(r.rust_code.contains("unsafe { (*rdi).vfn_3() };"), "{}", r.rust_code);
    }

    #[test]
    fn a_virtual_call_is_raw_when_memory_changes_after_the_vtable_load() {
        // mov rax, [rdi] ; mov dword [rdi+8], 0 ; call [rax+0x18] ; ret
        let r = c_of(&[0x48, 0x8b, 0x07, 0xc7, 0x47, 0x08, 0x00, 0x00, 0x00, 0x00, 0xff, 0x50, 0x18, 0xc3]);
        assert!(r.c_code.contains("rax = rdi->_vptr;"), "{}", r.c_code);
        assert!(r.c_code.contains("(**(uint64_t*)(rax + 0x18))(rdi);"), "{}", r.c_code);
    }

    #[test]
    fn a_spill_between_the_vtable_load_and_the_call_keeps_the_member_call() {
        // sub rsp, 0x18 ; mov rax, [rdi] ; mov [rsp+8], rsi ; call [rax+0x18] ; add rsp, 0x18 ; ret
        let code = [0x48, 0x83, 0xec, 0x18, 0x48, 0x8b, 0x07, 0x48, 0x89, 0x74, 0x24, 0x08, 0xff, 0x50, 0x18, 0x48, 0x83, 0xc4, 0x18, 0xc3];
        let r = c_of(&code);
        assert!(r.c_code.contains("rdi->vfn_3("), "{}", r.c_code);
    }

    #[test]
    fn a_virtual_call_is_raw_when_this_is_another_object() {
        // mov rax, [rdi] ; mov rdi, rsi ; call [rax+0x18] ; ret
        let r = c_of(&[0x48, 0x8b, 0x07, 0x48, 0x89, 0xf7, 0xff, 0x50, 0x18, 0xc3]);
        assert!(!r.c_code.contains("->vfn_"), "{}", r.c_code);
    }

    /// A PIE with a class `Shape`: vtable at 0x2010 (slot 0 = 0x1100, slot 1 = 0x1200), its
    /// type_info at 0x2030 naming `5Shape` (at 0x3000); `ctor` at 0x1000, `method` at 0x1100.
    fn shape(ctor: &[u8], method: &[u8]) -> Memory {
        let mut t = vec![0xccu8; 0x300];
        t[..ctor.len()].copy_from_slice(ctor);
        t[0x100..0x100 + method.len()].copy_from_slice(method);
        // 0x1200: mov eax, [rdi+4] ; ret (it reads `this`)
        t[0x200..0x204].copy_from_slice(&[0x8b, 0x47, 0x04, 0xc3]);
        let mut mem = Memory::new(reargo_core::address::SpaceId(1), Endian::Little);
        mem.add_block(block(".text", 0x1000, t, MemoryFlags::READ | MemoryFlags::EXECUTE));
        mem.add_block(block(".data.rel.ro", 0x2000, vec![0; 0x40], MemoryFlags::READ | MemoryFlags::WRITE));
        mem.add_block(block(".rodata", 0x3000, b"5Shape\0".to_vec(), MemoryFlags::READ));
        let rela: Vec<u8> = [(0x2008u64, 8u64, 0x2030u64), (0x2010, 8, 0x1100), (0x2018, 8, 0x1200), (0x2038, 8, 0x3000)]
            .iter()
            .flat_map(|&(o, i, a)| [o.to_le_bytes(), i.to_le_bytes(), a.to_le_bytes()].concat())
            .collect();
        mem.set_dynamic_relocations(Arc::from(rela));
        mem
    }

    #[test]
    fn a_constructor_names_the_class_of_its_vtable() {
        // lea rax, [0x2010] ; mov [rdi], rax ; mov rax, [rdi] ; call [rax+8] ; ret
        let ctor = [0x48, 0x8d, 0x05, 0x09, 0x10, 0x00, 0x00, 0x48, 0x89, 0x07, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x08, 0xc3];
        let r = decompile(&X86Lifter::new_64(), &shape(&ctor, &[0xc3]), 0x1000, "f", 100).unwrap();
        assert!(r.c_code.contains("rdi->_vptr = 0x2010;  // vtable of Shape"), "{}", r.c_code);
        assert!(r.c_code.contains("rdi->vfn_1();  // vfn[1] (vtable+0x8) = Shape::method_at_1200"), "{}", r.c_code);
        assert!(r.recovered_structs[0].starts_with("struct Shape {  // class from RTTI, vtable 0x2010"), "{:?}", r.recovered_structs);
        assert!(r.c_code.contains("(struct Shape* rdi)"), "{}", r.c_code);
    }

    #[test]
    fn a_method_in_a_vtable_types_this_as_its_class() {
        // 0x1100: mov eax, [rdi+8] ; mov rax, [rdi] ; call [rax+8] ; ret
        let m = [0x8b, 0x47, 0x08, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x08, 0xc3];
        let r = decompile(&X86Lifter::new_64(), &shape(&[0xc3], &m), 0x1100, "m", 100).unwrap();
        assert!(r.c_code.contains("(struct Shape* rdi)"), "{}", r.c_code);
        assert!(r.c_code.contains("= Shape::method_at_1200"), "{}", r.c_code);
    }

    #[test]
    fn a_method_returning_a_struct_in_memory_has_this_in_the_second_argument() {
        // 0x1100 (listed in Shape's vtable): mov eax, [rsi+8] ; mov [rdi], eax ; mov [rdi+4], eax ; mov rax, rdi ; ret
        let m = [0x8b, 0x46, 0x08, 0x89, 0x07, 0x89, 0x47, 0x04, 0x48, 0x89, 0xf8, 0xc3];
        let r = decompile(&X86Lifter::new_64(), &shape(&[0xc3], &m), 0x1100, "m", 100).unwrap();
        assert!(r.c_code.contains("struct Shape* rsi"), "{}", r.c_code);
        assert!(!r.c_code.contains("struct Shape* rdi"), "{}", r.c_code);
    }

    #[test]
    fn a_mangled_method_name_types_this() {
        // mov eax, [rdi+8] ; ret
        let r = decompile(&X86Lifter::new_64(), &text(&[0x8b, 0x47, 0x08, 0xc3]), 0x1000, "_ZNK5Shape4areaEv", 100).unwrap();
        assert!(r.c_code.contains("(struct Shape* rdi)"), "{}", r.c_code);
        assert!(r.recovered_structs[0].starts_with("struct Shape {  // class from the symbol"), "{:?}", r.recovered_structs);
    }

    #[test]
    fn a_callees_accesses_through_a_passed_pointer_are_fields() {
        // mov eax, [rdi+8] ; mov [rdi+0xc], eax ; call 0x2000 ; ret
        // 0x2000: mov rax, [rdi+0x20] ; add eax, [rdi+0x28] ; ret
        let mut code = vec![0x8b, 0x47, 0x08, 0x89, 0x47, 0x0c, 0xe8, 0xf5, 0x0f, 0x00, 0x00, 0xc3];
        code.resize(0x1100, 0xcc);
        code[0x1000..0x1008].copy_from_slice(&[0x48, 0x8b, 0x47, 0x20, 0x03, 0x47, 0x28, 0xc3]);
        let r = c_of(&code);
        let d = &r.recovered_structs[0];
        assert!(d.contains("uint32_t field_8; // +0x8\n"), "{d}");
        assert!(d.contains("uint64_t field_20; // +0x20 (used by 0x2000)"), "{d}");
        assert!(d.contains("uint32_t field_28; // +0x28 (used by 0x2000)"), "{d}");
        assert!(r.c_code.contains("rdi->field_8"), "{}", r.c_code);
    }

    #[test]
    fn a_pointer_passed_to_a_method_has_the_methods_class() {
        // push rbx ; mov rbx, rdi ; call 0x1100 (Shape's method) ; mov rax, [rbx] ; mov rdi, rbx ;
        // call [rax+8] ; pop rbx ; ret
        let f = [0x53, 0x48, 0x89, 0xfb, 0xe8, 0xf7, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x03, 0x48, 0x89, 0xdf, 0xff, 0x50, 0x08, 0x5b, 0xc3];
        let r = decompile(&X86Lifter::new_64(), &shape(&f, &[0x8b, 0x47, 0x08, 0xc3]), 0x1000, "f", 100).unwrap();
        assert!(r.recovered_structs[0].starts_with("struct Shape {"), "{:?}", r.recovered_structs);
        assert!(r.recovered_structs[0].contains("field_8; // +0x8 (used by 0x1100)"), "{:?}", r.recovered_structs);
        assert!(r.c_code.contains("rdi->vfn_1();  // vfn[1] (vtable+0x8) = Shape::method_at_1200"), "{}", r.c_code);
    }

    /// WS92: an object a callee stores a vtable into (its constructor) is of that class, so a
    /// virtual call on it names the slot's function.
    #[test]
    fn an_object_a_constructor_was_called_on_has_its_class() {
        // push rbx ; mov rbx, rdi ; mov rdi, rbx ; call 0x1080 (the constructor) ; mov rax, [rbx] ;
        // mov rdi, rbx ; call [rax+8] ; pop rbx ; ret
        let mut f = vec![0x53, 0x48, 0x89, 0xfb, 0x48, 0x89, 0xdf, 0xe8, 0x74, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x03, 0x48, 0x89, 0xdf, 0xff, 0x50, 0x08, 0x5b, 0xc3];
        f.resize(0x80, 0xcc);
        // 0x1080: lea rax, [0x2010] ; mov [rdi], rax ; ret
        f.extend_from_slice(&[0x48, 0x8d, 0x05, 0x89, 0x0f, 0x00, 0x00, 0x48, 0x89, 0x07, 0xc3]);
        let r = decompile(&X86Lifter::new_64(), &shape(&f, &[0xc3]), 0x1000, "f", 100).unwrap();
        assert!(r.c_code.contains("rdi->vfn_1();  // vfn[1] (vtable+0x8) = Shape::method_at_1200"), "{}", r.c_code);
        assert!(r.recovered_structs.iter().any(|d| d.starts_with("struct Shape {  // class from RTTI, vtable 0x2010")), "{:?}", r.recovered_structs);
    }

    /// Two classes: `Shape` (vtable 0x2010: 0x1100, 0x1200; type_info 0x2030 -> `5Shape`) and
    /// `Holder` (vtable 0x2050: 0x1300, 0x1310; type_info 0x2070 -> `6Holder`). `Holder`'s
    /// constructor at 0x1000 stores a new object at `this + 8` and calls `Shape`'s constructor
    /// (0x1080) on it; `Holder::m` (0x1300) makes a virtual call on `this->field_8`.
    fn holder() -> Memory {
        holder_with(&[])
    }

    /// [`holder`] with more code (`(offset in .text, bytes)`; .text is 0x1000..0x1600).
    fn holder_with(extra: &[(usize, &[u8])]) -> Memory {
        let mut t = vec![0xccu8; 0x600];
        let mut put = |at: usize, b: &[u8]| t[at..at + b.len()].copy_from_slice(b);
        put(0x000, &[
            0x53, 0x48, 0x89, 0xfb, // push rbx ; mov rbx, rdi
            0x48, 0x8d, 0x05, 0x45, 0x10, 0x00, 0x00, // lea rax, [0x2050]
            0x48, 0x89, 0x03, // mov [rbx], rax
            0xbf, 0x10, 0x00, 0x00, 0x00, // mov edi, 0x10
            0xe8, 0xe8, 0x03, 0x00, 0x00, // call 0x1400 (operator new)
            0x48, 0x89, 0x43, 0x08, // mov [rbx+8], rax
            0x48, 0x89, 0xc7, // mov rdi, rax
            0xe8, 0x5c, 0x00, 0x00, 0x00, // call 0x1080 (Shape's constructor)
            0x5b, 0xc3, // pop rbx ; ret
        ]);
        put(0x080, &[0x48, 0x8d, 0x05, 0x89, 0x0f, 0x00, 0x00, 0x48, 0x89, 0x07, 0xc3]);
        put(0x100, &[0xc3]);
        put(0x200, &[0x8b, 0x47, 0x04, 0xc3]);
        // 0x1300: mov rdi, [rdi+8] ; mov rax, [rdi] ; call [rax+8] ; ret
        put(0x300, &[0x48, 0x8b, 0x7f, 0x08, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x08, 0xc3]);
        put(0x310, &[0xc3]);
        put(0x400, &[0x31, 0xc0, 0xc3]);
        for (at, b) in extra {
            put(*at, b);
        }
        let mut mem = Memory::new(reargo_core::address::SpaceId(1), Endian::Little);
        mem.add_block(block(".text", 0x1000, t, MemoryFlags::READ | MemoryFlags::EXECUTE));
        mem.add_block(block(".data.rel.ro", 0x2000, vec![0; 0x80], MemoryFlags::READ | MemoryFlags::WRITE));
        mem.add_block(block(".rodata", 0x3000, [&b"5Shape"[..], &[0; 10], b"6Holder\0"].concat(), MemoryFlags::READ));
        let rela: Vec<u8> = [
            (0x2008u64, 8u64, 0x2030u64),
            (0x2010, 8, 0x1100),
            (0x2018, 8, 0x1200),
            (0x2038, 8, 0x3000),
            (0x2048, 8, 0x2070),
            (0x2050, 8, 0x1300),
            (0x2058, 8, 0x1310),
            (0x2078, 8, 0x3010),
        ]
        .iter()
        .flat_map(|&(o, i, a)| [o.to_le_bytes(), i.to_le_bytes(), a.to_le_bytes()].concat())
        .collect();
        mem.set_dynamic_relocations(Arc::from(rela));
        mem
    }

    /// WS92: an object loaded from a field of an object of a known class is of the class that
    /// class's constructor stores there, so a virtual call on it names the slot's function.
    #[test]
    fn a_field_object_has_the_class_its_owners_constructor_stores() {
        let r = decompile(&X86Lifter::new_64(), &holder(), 0x1300, "m", 100).unwrap();
        assert!(r.c_code.contains("(struct Holder* rdi)"), "{}", r.c_code);
        assert!(r.c_code.contains("vfn_1();  // vfn[1] (vtable+0x8) = Shape::method_at_1200"), "{}", r.c_code);
        assert!(r.recovered_structs.iter().any(|d| d.contains("struct Shape* field_8; // +0x8")), "{:?}", r.recovered_structs);
    }

    /// [`holder`] plus a non-virtual helper `0x1500` (`mov rdi, [rdi+8]; mov rax, [rdi];
    /// call [rax+8]; ret`) that `Holder`'s virtual method `0x1310` calls on `this`; with
    /// `stray`, `0x1520` (no caller: anything may call it) calls the helper too.
    fn holder_helper(stray: bool) -> (Memory, Vec<(u64, u64)>) {
        let helper = [0x48, 0x8b, 0x7f, 0x08, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x08, 0xc3];
        // 0x1310: call 0x1500 ; ret        0x1520: call 0x1500 ; ret
        let m = [0xe8, 0xeb, 0x01, 0x00, 0x00, 0xc3];
        let other = [0xe8, 0xdb, 0xff, 0xff, 0xff, 0xc3];
        let mut extra: Vec<(usize, &[u8])> = vec![(0x310, &m), (0x500, &helper)];
        let mut fs = vec![(0x1000, 0x26), (0x1080, 0xb), (0x1100, 1), (0x1200, 4), (0x1300, 0xb), (0x1310, 6), (0x1400, 3), (0x1500, 0xb)];
        if stray {
            extra.push((0x520, &other));
            fs.push((0x1520, 6));
        }
        (holder_with(&extra), fs)
    }

    fn with_index(mem: &Memory, fs: &[(u64, u64)], entry: u64) -> crate::pipeline::DecompileResult {
        let idx = crate::thisclass::build(mem, fs, &[]);
        let opts = DecompileOptions { structs: true, this_index: Some(Arc::new(idx)), ..Default::default() };
        decompile_with_options(&X86Lifter::new_64(), mem, entry, "f", 100, &Default::default(), &opts).unwrap()
    }

    /// WS96: `Holder` has a vector of `Shape*` at +0x20 (the index's element class): a virtual
    /// call on `this->field_20[i]` or on `this->field_28[-1]` (the end pointer) names the slot,
    /// and the struct prints the three pointers as the vector's.
    #[test]
    fn a_virtual_call_on_a_vector_element_has_the_element_class() {
        let m = [
            0x53, // push rbx
            0x48, 0x89, 0xfb, // mov rbx, rdi
            0x48, 0x8b, 0x47, 0x20, // mov rax, [rdi+0x20]
            0x48, 0x8b, 0x3c, 0xc8, // mov rdi, [rax+rcx*8]
            0x48, 0x8b, 0x07, // mov rax, [rdi]
            0xff, 0x50, 0x08, // call [rax+8]
            0x48, 0x8b, 0x43, 0x28, // mov rax, [rbx+0x28]
            0x48, 0x8b, 0x78, 0xf8, // mov rdi, [rax-8]
            0x48, 0x8b, 0x07, // mov rax, [rdi]
            0xff, 0x50, 0x08, // call [rax+8]
            0x48, 0x8b, 0x43, 0x30, // mov rax, [rbx+0x30]
            0x5b, 0xc3, // pop rbx ; ret
        ];
        let mem = holder_with(&[(0x310, &m)]);
        let fs = [(0x1000, 0x26), (0x1080, 0xb), (0x1100, 1), (0x1200, 4), (0x1300, 0xb), (0x1310, m.len() as u64), (0x1400, 3)];
        let mut idx = crate::thisclass::build(&mem, &fs, &[]);
        let class = |vt: u64| idx.hierarchy.vtables.iter().position(|&v| v == vt).expect("class") as u32;
        let (holder, shape) = (class(0x2050), class(0x2010));
        let opts = |idx: crate::thisclass::ThisIndex| DecompileOptions { structs: true, this_index: Some(Arc::new(idx)), ..Default::default() };
        let r = decompile_with_options(&X86Lifter::new_64(), &mem, 0x1310, "f", 100, &Default::default(), &opts(idx.clone())).unwrap();
        assert!(!r.c_code.contains("= Shape::"), "no element class yet: {}", r.c_code);
        for off in [0x20, 0x28, 0x30] {
            idx.elements.insert((holder, off), shape + 2);
        }
        idx.vectors = vec![(holder, 0x20)];
        let r = decompile_with_options(&X86Lifter::new_64(), &mem, 0x1310, "f", 100, &Default::default(), &opts(idx)).unwrap();
        assert_eq!(r.c_code.matches("// vfn[1] (vtable+0x8) = Shape::method_at_1200").count(), 2, "{}", r.c_code);
        let d = r.recovered_structs.iter().find(|d| d.starts_with("struct Holder {")).expect("Holder");
        assert!(d.contains("struct Shape** field_20; // +0x20 std::vector<Shape*> begin (end +0x28, capacity +0x30)"), "{d}");
        assert!(d.contains("struct Shape** field_28; // +0x28 end of the std::vector<Shape*> at +0x20"), "{d}");
        assert!(d.contains("struct Shape** field_30; // +0x30 capacity of the std::vector<Shape*> at +0x20"), "{d}");
    }

    /// WS93: `this` of a non-virtual method has the class its callers pass (here `Holder`'s
    /// virtual method passes its own `this`), so a virtual call on a field of it names the slot.
    #[test]
    fn this_of_a_non_virtual_method_has_its_callers_class() {
        let (mem, fs) = holder_helper(false);
        let idx = crate::thisclass::build(&mem, &fs, &[]);
        assert_eq!(idx.param_class(0x1500, 0), Some(0x2050), "{idx:?}");
        assert_eq!(idx.field_class(0x2050, 8), Some(0x2010), "{idx:?}");
        let r = with_index(&mem, &fs, 0x1500);
        assert!(r.c_code.contains("(struct Holder* rdi)"), "{}", r.c_code);
        assert!(r.c_code.contains("vfn_1();  // vfn[1] (vtable+0x8) = Shape::method_at_1200"), "{}", r.c_code);
        // without the index nothing is known
        let r = decompile(&X86Lifter::new_64(), &mem, 0x1500, "f", 100).unwrap();
        assert!(!r.c_code.contains("Holder") && !r.c_code.contains("= Shape::"), "{}", r.c_code);
    }

    /// WS93: one caller that may pass anything (a function nobody calls directly) leaves the
    /// class unknown.
    #[test]
    fn one_unknown_caller_leaves_this_without_class() {
        let (mem, fs) = holder_helper(true);
        let idx = crate::thisclass::build(&mem, &fs, &[]);
        assert_eq!(idx.param_class(0x1500, 0), None, "{idx:?}");
        let r = with_index(&mem, &fs, 0x1500);
        assert!(!r.c_code.contains("Holder") && !r.c_code.contains("= Shape::"), "{}", r.c_code);
    }

    /// [`holder`] plus the helper `0x1500` (`this->field_8->vfn_1()`) called by `0x1540` on a
    /// stack object whose `+8` holds a new `Shape` (built by its constructor); with `holder`,
    /// `0x1580` calls it too on a stack object whose `+8` holds a new `Holder`.
    fn stack_object_helper(holder: bool) -> (Memory, Vec<(u64, u64)>) {
        let helper = [0x48, 0x8b, 0x7f, 0x08, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x08, 0xc3];
        // push rbx ; sub rsp, 0x20 ; mov edi, 0x10 ; call 0x1400 (new) ; mov rbx, rax ;
        // mov rdi, rax ; call <constructor> ; mov [rsp+8], rbx ; mov rdi, rsp ; call 0x1500 ;
        // add rsp, 0x20 ; pop rbx ; ret
        let caller = |new: [u8; 4], ctor: [u8; 4], helper: [u8; 4]| -> Vec<u8> {
            [
                &[0x53, 0x48, 0x83, 0xec, 0x20, 0xbf, 0x10, 0x00, 0x00, 0x00, 0xe8][..],
                &new,
                &[0x48, 0x89, 0xc3, 0x48, 0x89, 0xc7, 0xe8],
                &ctor,
                &[0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0xe7, 0xe8],
                &helper,
                &[0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3],
            ]
            .concat()
        };
        let shape = caller([0xb1, 0xfe, 0xff, 0xff], [0x26, 0xfb, 0xff, 0xff], [0x99, 0xff, 0xff, 0xff]);
        let other = caller([0x71, 0xfe, 0xff, 0xff], [0x66, 0xfa, 0xff, 0xff], [0x59, 0xff, 0xff, 0xff]);
        let mut extra: Vec<(usize, &[u8])> = vec![(0x500, &helper), (0x540, &shape)];
        let mut fs = vec![(0x1000, 0x26), (0x1080, 0xb), (0x1100, 1), (0x1200, 4), (0x1300, 0xb), (0x1310, 1), (0x1400, 3), (0x1500, 0xb), (0x1540, 0x2d)];
        if holder {
            extra.push((0x580, &other));
            fs.push((0x1580, 0x2d));
        }
        (holder_with(&extra), fs)
    }

    /// WS94: a field of an object the callers pass has the class every caller put there (here a
    /// stack object whose `+8` holds a `Shape`), so a virtual call on `rdi->field_8` names the
    /// slot even though `rdi` has no class.
    #[test]
    fn a_field_of_an_object_the_callers_pass_has_their_class() {
        let (mem, fs) = stack_object_helper(false);
        let idx = crate::thisclass::build(&mem, &fs, &[]);
        assert_eq!(idx.param_class(0x1500, 0), None, "{idx:?}");
        assert_eq!(idx.param_field_class(0x1500, 0, 8), Some(0x2010), "{idx:?}");
        let r = with_index(&mem, &fs, 0x1500);
        assert!(r.c_code.contains("vfn_1();  // vfn[1] (vtable+0x8) = Shape::method_at_1200"), "{}", r.c_code);
        assert!(r.recovered_structs.iter().any(|d| d.contains("struct Shape* field_8; // +0x8")), "{:?}", r.recovered_structs);
        // without the index nothing is known
        let r = decompile(&X86Lifter::new_64(), &mem, 0x1500, "f", 100).unwrap();
        assert!(!r.c_code.contains("= Shape::"), "{}", r.c_code);
    }

    /// WS95: [`holder`] plus `Holder`'s method `0x1310` passing `this` to a helper that writes a
    /// field of it, which `0x1520` (no caller: anything) calls too — `setter`: `0x1580` stores
    /// its second argument (`this->field_8`, a `Shape`) at `+0x10`; else `0x15a0` writes a
    /// number at `+8`.
    fn callee_writes(setter: bool) -> (Memory, Vec<(u64, u64)>) {
        let (m, other): ([u8; 9], [u8; 5]) = if setter {
            // mov rsi, [rdi+8] ; jmp 0x1580        jmp 0x1580
            ([0x48, 0x8b, 0x77, 0x08, 0xe9, 0x67, 0x02, 0x00, 0x00], [0xe9, 0x5b, 0x00, 0x00, 0x00])
        } else {
            // jmp 0x15a0 (+ padding)                jmp 0x15a0
            ([0xe9, 0x8b, 0x02, 0x00, 0x00, 0xcc, 0xcc, 0xcc, 0xcc], [0xe9, 0x7b, 0x00, 0x00, 0x00])
        };
        // 0x1580: mov [rdi+0x10], rsi ; ret      0x15a0: mov dword [rdi+8], 1 ; ret
        let set = [0x48, 0x89, 0x77, 0x10, 0xc3];
        let clobber = [0xc7, 0x47, 0x08, 0x01, 0x00, 0x00, 0x00, 0xc3];
        let extra: Vec<(usize, &[u8])> = vec![(0x310, &m), (0x520, &other), (0x580, &set), (0x5a0, &clobber)];
        let fs = vec![(0x1000, 0x26), (0x1080, 0xb), (0x1100, 1), (0x1200, 4), (0x1300, 0xb), (0x1310, 9), (0x1400, 3), (0x1520, 5), (0x1580, 5), (0x15a0, 8)];
        (holder_with(&extra), fs)
    }

    /// WS95: a field a callee stores into the object a method passes it has the class of what
    /// that call stores (the callee's own parameter has no class: another caller passes anything).
    #[test]
    fn a_field_stored_by_a_callee_has_the_class_of_what_the_call_stores() {
        let (mem, fs) = callee_writes(true);
        let idx = crate::thisclass::build(&mem, &fs, &[]);
        assert_eq!(idx.param_class(0x1580, 0), None, "{idx:?}");
        assert_eq!(idx.field_class(0x2050, 0x10), Some(0x2010), "{idx:?}");
    }

    /// WS95: a callee writing a number into a field of the object passed: the field has no
    /// class any more.
    #[test]
    fn a_field_a_callee_writes_a_number_into_has_no_class() {
        let (mem, fs) = callee_writes(false);
        let idx = crate::thisclass::build(&mem, &fs, &[]);
        assert_eq!(idx.field_class(0x2050, 8), None, "{idx:?}");
        // (without that write it is the constructor's Shape)
        let (mem, fs) = callee_writes(true);
        assert_eq!(crate::thisclass::build(&mem, &fs, &[]).field_class(0x2050, 8), Some(0x2010));
    }

    /// WS94: two callers putting objects of unrelated classes there: no class.
    #[test]
    fn callers_putting_unrelated_classes_in_a_field_leave_it_without_class() {
        let (mem, fs) = stack_object_helper(true);
        let idx = crate::thisclass::build(&mem, &fs, &[]);
        assert_eq!(idx.param_field_class(0x1500, 0, 8), None, "{idx:?}");
        let r = with_index(&mem, &fs, 0x1500);
        assert!(!r.c_code.contains("= Shape::") && !r.c_code.contains("= Holder::"), "{}", r.c_code);
    }

    /// WS92: a phi joining objects of two unrelated classes does not merge their types: the
    /// virtual calls on each before the join keep their class (the one on the joined value is
    /// unresolved).
    #[test]
    fn a_phi_of_two_classes_keeps_each_class_before_the_join() {
        // 0x1500: push rbx ; test esi, esi ; je L1 ; rbx = new ; Shape::Shape(rbx) ; rbx->vfn_1() ;
        // jmp L2 ; L1: rbx = new ; Holder::Holder(rbx) ; rbx->vfn_1() ; L2: rbx->vfn_0() ; pop rbx ; ret
        let f = [
            0x53, 0x85, 0xf6, 0x74, 0x1b, 0xe8, 0xf6, 0xfe, 0xff, 0xff, 0x48, 0x89, 0xc3, 0x48, 0x89, 0xc7, 0xe8, 0x6b, 0xfb, 0xff, 0xff, 0x48, 0x8b, 0x03,
            0x48, 0x89, 0xdf, 0xff, 0x50, 0x08, 0xeb, 0x19, 0xe8, 0xdb, 0xfe, 0xff, 0xff, 0x48, 0x89, 0xc3, 0x48, 0x89, 0xc7, 0xe8, 0xd0, 0xfa, 0xff, 0xff,
            0x48, 0x8b, 0x03, 0x48, 0x89, 0xdf, 0xff, 0x50, 0x08, 0x48, 0x8b, 0x03, 0x48, 0x89, 0xdf, 0xff, 0x10, 0x5b, 0xc3,
        ];
        let r = decompile(&X86Lifter::new_64(), &holder_with(&[(0x500, &f)]), 0x1500, "f", 100).unwrap();
        assert!(r.c_code.contains("= Shape::method_at_1200"), "{}", r.c_code);
        assert!(r.c_code.contains("= Holder::method_at_1310"), "{}", r.c_code);
    }

    /// WS92: the parameter types of a mangled name.
    #[test]
    fn signature_classes_from_mangled_names() {
        let c = |n: &str| signature_classes(n).unwrap().into_iter().map(|c| c.unwrap_or_default()).collect::<Vec<_>>();
        assert_eq!(c("_ZN5Scene3addEP6CircleRK5Shape"), ["Scene", "Circle", "Shape"]);
        // `this`, a `std::vector<int> const&`, a `char**` (no class), a `double` (no integer
        // register), a `Baz*`
        assert_eq!(c("_ZNK3Foo3barERKSt6vectorIiSaIiEEPPcdP3Baz"), ["Foo", "std::vector<int, std::allocator<int> >", "", "Baz"]);
        assert_eq!(c("_Z4drawP6Circle"), ["Circle"]);
        // a class by value: where it goes is not known, the list ends
        assert_eq!(c("_Z4fill5ShapeP6Circle"), Vec::<String>::new());
        assert_eq!(c("_Z1fiP6Circle"), ["", "Circle"]);
        assert!(signature_classes("FUN_401000").is_none());
    }

    /// WS92: a mangled function name types its parameters; a pointer passed to a callee with a
    /// mangled name gets the class of that parameter.
    #[test]
    fn mangled_signatures_type_parameters_and_arguments() {
        // _ZN5Scene3addEP6CircleRK5Shape: mov eax, [rsi+8] ; add eax, [rdx+0x10] ; mov [rdi+4], eax ; ret
        let code = [0x8b, 0x46, 0x08, 0x03, 0x42, 0x10, 0x89, 0x47, 0x04, 0xc3];
        let r = crate::pipeline::decompile_with_symbols(&X86Lifter::new_64(), &text(&code), 0x1000, "_ZN5Scene3addEP6CircleRK5Shape", 100, &Default::default()).unwrap();
        assert!(r.c_code.contains("(struct Scene* rdi, struct Circle* rsi, struct Shape* rdx)"), "{}", r.c_code);
        assert!(r.recovered_structs.iter().any(|d| d.starts_with("struct Circle {  // class from the symbol")), "{:?}", r.recovered_structs);
        // f: push rbx ; mov rbx, rsi ; mov eax, [rsi+8] ; mov [rdi+4], eax ; mov rdi, rbx ;
        // call 0x1100 (_Z4drawP6Circle) ; mov eax, [rbx+0xc] ; pop rbx ; ret
        let mut f = vec![0x53, 0x48, 0x89, 0xf3, 0x8b, 0x46, 0x08, 0x89, 0x47, 0x04, 0x48, 0x89, 0xdf, 0xe8, 0xee, 0x00, 0x00, 0x00, 0x8b, 0x43, 0x0c, 0x5b, 0xc3];
        f.resize(0x100, 0xcc);
        f.extend_from_slice(&[0x8b, 0x47, 0x08, 0xc3]);
        let symbols = std::collections::BTreeMap::from([(0x1100u64, "_Z4drawP6Circle".to_string())]);
        let r = crate::pipeline::decompile_with_symbols(&X86Lifter::new_64(), &text(&f), 0x1000, "f", 100, &symbols).unwrap();
        assert!(r.c_code.contains("struct Circle* rsi"), "{}", r.c_code);
        assert!(r.c_code.contains("rbx->field_c"), "{}", r.c_code);
    }

    #[test]
    fn rust_output_names_the_same_fields() {
        // mov [rdi+0x10], esi ; mov eax, [rdi+0x14] ; ret
        let r = c_of(&[0x89, 0x77, 0x10, 0x8b, 0x47, 0x14, 0xc3]);
        assert!(r.rust_code.contains("unsafe { (*rdi).field_10 = esi; }"), "{}", r.rust_code);
        assert!(r.rust_code.contains("rdi: *mut struct_0"), "{}", r.rust_code);
        assert!(r.rust_structs[0].contains("field_10: u32, // +0x10"), "{:?}", r.rust_structs);
    }

    #[test]
    fn class_structs_merge_over_functions() {
        let a = vec![StructDef { name: "Shape".into(), class: Some("Shape".into()), vtable: Some(0x2010), stride: None, class_from_symbol: false, fields: vec![Field { off: 8, size: 4, kind: FieldKind::Int, from: None, vector: None }] }];
        let b = vec![
            StructDef {
                name: "Shape".into(),
                class: Some("Shape".into()),
                vtable: None,
                stride: None,
                class_from_symbol: false,
                fields: vec![Field { off: 8, size: 8, kind: FieldKind::Int, from: None, vector: None }, Field { off: 0x10, size: 8, kind: FieldKind::Ptr(Some(1)), from: None, vector: None }],
            },
            StructDef { name: "struct_1".into(), class: None, vtable: None, stride: None, class_from_symbol: false, fields: vec![] },
        ];
        let (c, _) = merge_class_structs([a.as_slice(), b.as_slice()].into_iter());
        assert_eq!(c.len(), 1);
        // field_8 of the first wins over the overlapping 8-byte one; a pointer to an anonymous struct is void*
        assert!(c[0].contains("uint32_t field_8;") && c[0].contains("void* field_10;"), "{}", c[0]);
    }

    #[test]
    fn method_class_from_mangled_and_demangled_names() {
        assert_eq!(method_class("_ZN5Class6methodEv").as_deref(), Some("Class"));
        assert_eq!(method_class("_ZNK2ns5Class3getEi").as_deref(), Some("ns::Class"));
        assert_eq!(method_class("_ZN17CachedBiomeSourceI13BiomeSource3dE3getEv").as_deref(), Some("CachedBiomeSource<BiomeSource3d>"));
        assert_eq!(method_class("Foo::bar(int)").as_deref(), Some("Foo"));
        assert_eq!(method_class("_ZN12_GLOBAL__N_15Local3getEv").as_deref(), Some("(anonymous namespace)::Local"));
        assert_eq!(method_class("_Z4freev"), None);
        assert_eq!(method_class("FUN_401000"), None);
        assert_eq!(method_class("main"), None);
    }

    #[test]
    fn struct_definition_has_gaps_and_types() {
        let defs = vec![
            StructDef {
                name: "Node".into(),
                class: None,
                vtable: None,
                stride: None,
                class_from_symbol: false,
                fields: vec![
                    Field { off: 0, size: 8, kind: FieldKind::VPtr, from: None, vector: None },
                    Field { off: 0x10, size: 4, kind: FieldKind::Float, from: None, vector: None },
                    Field { off: 0x18, size: 8, kind: FieldKind::Ptr(Some(0)), from: None, vector: None },
                ],
            },
        ];
        let c = defs[0].c_definition(&defs);
        assert_eq!(
            c,
            "struct Node {\n    void** _vptr; // +0x0\n    uint8_t _gap_8[0x8];\n    float field_10; // +0x10\n    uint8_t _gap_14[0x4];\n    struct Node* field_18; // +0x18\n};"
        );
    }
}
