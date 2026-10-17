//! Function effect summaries (WS95): what a function does to the memory its parameters reach,
//! composed bottom-up into its callers' summaries (`thisclass`).
//!
//! The [`Summary`] of a function records the pointers it stores into fields, the other bytes it
//! writes, the vtables it stores, the elements it stores into buffers and what its calls do to
//! buffers — in terms of its own values (`Src`). Its **effects** are those of them whose
//! destination is reached from a parameter (`Arg(i)`, the pointer at `[Arg(i) + k]`, two
//! levels) or is the object it returns, written as such paths. At each direct call they are
//! **instantiated** in the caller's terms — a parameter is the argument passed, `[arg + k]` a
//! load the caller's summary gains (for a stack object passed: its slot at the call), the
//! returned object the call's result — and become the caller's own facts, so its callers get
//! them too. The functions are visited callees first (the strongly connected components of the
//! direct call graph, a component repeated until its effects stop changing, at most
//! [`MAX_SCC_ROUNDS`] times).
//!
//! Soundness: a value the caller cannot name (an object the callee made, a pointer it loaded
//! from its own stack) is stored as unknown — a clobber —, never dropped; a function with more
//! than [`MAX_EFFECTS`] effects gives none, and each pointer argument of a call to it escapes
//! (`buf_escapes`). The effects of a parameter whose class a vtable or a constructor gives are
//! not exported: the function's own facts are already keyed by that class.

use crate::thisclass::{FieldVal, ImportKind, Src, StackEv, Summary, ELEM};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;

/// Most effects exported per function.
pub const MAX_EFFECTS: usize = 256;
/// Most rounds over a strongly connected component of the call graph.
pub const MAX_SCC_ROUNDS: usize = 4;
/// Most loads on a parameter path.
const MAX_DEPTH: usize = 2;

/// Where a path starts: a parameter, or the object the function returns.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Root {
    Arg(u8),
    Ret,
}

/// A pointer reached from a parameter: the root, then the pointer loaded from `+k[0]`, from
/// `+k[1]` of that (the first `n`); `k = ELEM`: an element of the buffer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Path {
    pub root: Root,
    pub n: u8,
    pub k: [i32; MAX_DEPTH],
}

impl Path {
    fn root(root: Root) -> Path {
        Path { root, n: 0, k: [0; MAX_DEPTH] }
    }

    fn then(self, k: i32) -> Option<Path> {
        let n = self.n as usize;
        (n < MAX_DEPTH).then(|| {
            let mut p = self;
            p.k[n] = k;
            p.n += 1;
            p
        })
    }
}

/// An object a callee's effect names that the caller has no value for (WS95).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ObjRef {
    /// an object whose vtable pointer is this vtable (its class)
    Vtable(u64),
    /// an object the function returns (of its return class)
    RetOf(u64),
    /// (WS96) fresh memory a callee allocated (`n`: which of its buffers; a pointer anywhere into
    /// it): no class, and its elements are those the callee's effects store into the buffers it
    /// installed it in
    Fresh(u32),
}

/// A value an effect stores.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum EVal {
    Ptr(Path, i32),
    /// a pointer into the buffer the path points into
    Elem(Path),
    Obj(ObjRef),
    Unk,
}

/// What a function does to memory its parameters reach (offset `ELEM`: an element of the
/// buffer the path points into).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Effect {
    Store(Path, i32, EVal),
    /// bytes written with something not followed (`number`: no pointer at all)
    Clobber(Path, i32, i32, bool),
    Vtable(Path, i32, u64),
    /// the elements of the buffer the second path points into are copied into the first's
    Copy(Path, Path),
    /// data written into the buffer the path points into
    Write(Path),
    /// the pointer `path + k` given to unknown code
    Escape(Path, i32),
    /// (WS96) pointers into one buffer stored at `+k`, `+k + 8`, `+k + 16` of the path's object
    Triple(Path, i32),
}

/// The effects of one function: `None` when there are too many.
pub type Effects = Option<Vec<Effect>>;

/// The value of `src` of `s` as a path (`ret`: the source it returns).
fn path_of(s: &Summary, src: Src, export: u8, ret: Option<Src>, depth: usize) -> Option<Path> {
    if Some(src) == ret {
        return Some(Path::root(Root::Ret));
    }
    match src {
        Src::Arg(i) if export & (1 << i) != 0 => Some(Path::root(Root::Arg(i))),
        Src::Ld(l) if depth < MAX_DEPTH => {
            let (b, k) = *s.loads.get(l as usize)?;
            if k < 0 && k != ELEM {
                return None;
            }
            path_of(s, b, export, ret, depth + 1)?.then(k)
        }
        _ => None,
    }
}

/// The value `(src, off)` of `s` as an effect's value.
fn value_of(s: &Summary, src: Src, off: i32, export: u8, ret: Option<Src>) -> EVal {
    if let Some(p) = path_of(s, src, export, ret, 0) {
        return if off == ELEM { EVal::Elem(p) } else { EVal::Ptr(p, off) };
    }
    // (WS96: a pointer into fresh memory, at any offset; an object constructed in it has the
    // class of its vtable, below)
    match src {
        Src::Ret(_) if off == 0 && s.vt_stores.iter().any(|v| v.0 == src && v.1 == 0) => {}
        Src::Ret(c) if s.fresh.binary_search(&c).is_ok() => return EVal::Obj(ObjRef::Fresh(c)),
        Src::Obj(i) if matches!(s.objs.get(i as usize), Some(ObjRef::Fresh(_))) => return EVal::Obj(ObjRef::Fresh(FRESH_OBJ | i)),
        _ => {}
    }
    if off != 0 {
        return EVal::Unk;
    }
    match src {
        Src::Ret(c) => {
            if let Some(&(_, _, vt)) = s.vt_stores.iter().find(|v| v.0 == src && v.1 == 0) {
                return EVal::Obj(ObjRef::Vtable(vt));
            }
            match s.call_targets.get(c as usize) {
                Some(&t) if t != 0 => EVal::Obj(ObjRef::RetOf(t)),
                _ => EVal::Unk,
            }
        }
        Src::Obj(i) => s.objs.get(i as usize).map_or(EVal::Unk, |&o| EVal::Obj(o)),
        _ => EVal::Unk,
    }
}

/// `ObjRef::Fresh(FRESH_OBJ | i)`: the callee's own `Src::Obj(i)` (not one of its calls).
const FRESH_OBJ: u32 = 0x8000_0000;

/// The source every `ret` of `s` returns, when it is one (at offset 0).
pub fn returned(s: &Summary) -> Option<Src> {
    let first = *s.rets.first()?;
    (!s.ret_unknown && first.1 == 0 && first.0 != Src::Stack && s.rets.iter().all(|&r| r == first)).then_some(first.0)
}

/// The effects of `s` (its own facts and those its calls brought in) on the memory reached
/// from the parameters `export` (a mask) and from the object it returns.
pub fn effects_of(s: &Summary, export: u8) -> Effects {
    let ret = returned(s);
    let path = |src: Src| path_of(s, src, export, ret, 0);
    let mut out: Vec<Effect> = Vec::new();
    let mut add = |e: Effect| {
        if !out.contains(&e) {
            out.push(e);
        }
    };
    for &(d, off, vs, vo) in &s.field_stores {
        if let Some(p) = path(d) {
            add(Effect::Store(p, off, value_of(s, vs, vo, export, ret)));
        }
    }
    for &(d, off, n) in &s.field_clobbers {
        if let Some(p) = path(d) {
            add(Effect::Clobber(p, off, n, s.field_numbers.contains(&(d, off, n))));
        }
    }
    for &(d, off, vt) in &s.vt_stores {
        if let Some(p) = path(d) {
            add(Effect::Vtable(p, off, vt));
        }
    }
    for &(d, from) in &s.buf_copies {
        match (path(d), path(from)) {
            (Some(a), Some(b)) => add(Effect::Copy(a, b)),
            (Some(a), None) => add(Effect::Write(a)),
            _ => {}
        }
    }
    for &d in &s.buf_writes {
        if let Some(p) = path(d) {
            add(Effect::Write(p));
        }
    }
    for &(d, k) in &s.buf_escapes {
        if let Some(p) = path(d) {
            add(Effect::Escape(p, k));
        }
    }
    for &(d, k) in &s.triples {
        if let Some(p) = path(d) {
            add(Effect::Triple(p, k));
        }
    }
    (out.len() <= MAX_EFFECTS).then_some(out)
}

/// A value in the caller: a pointer `source + offset`, a pointer into the buffer `source` points
/// into, or none it can name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CVal {
    Ptr(Src, i32),
    Elem(Src),
    Unk,
}

/// The instantiation of a callee's effects in one caller.
struct Caller<'a> {
    s: &'a mut Summary,
    loads: FxHashMap<(Src, i32), u32>,
    /// `(call, object)`: the call only for a fresh object (one per call site)
    objs: FxHashMap<(u32, ObjRef), u32>,
}

impl Caller<'_> {
    fn load(&mut self, src: Src, k: i32) -> CVal {
        if let Some(&l) = self.loads.get(&(src, k)) {
            return CVal::Ptr(Src::Ld(l), 0);
        }
        let l = self.s.loads.len() as u32;
        self.s.loads.push((src, k));
        self.loads.insert((src, k), l);
        CVal::Ptr(Src::Ld(l), 0)
    }

    fn obj(&mut self, c: u32, o: ObjRef) -> Src {
        let key = (if matches!(o, ObjRef::Fresh(_)) { c } else { u32::MAX }, o);
        if let Some(&i) = self.objs.get(&key) {
            return Src::Obj(i);
        }
        let i = self.s.objs.len() as u32;
        self.s.objs.push(o);
        self.objs.insert(key, i);
        Src::Obj(i)
    }

    /// The pointer `p` of the callee at call `c` (`args`: the caller's argument values).
    fn path(&mut self, c: u32, args: &[CVal; 6], p: Path) -> CVal {
        let mut v = match p.root {
            Root::Arg(j) => args[j as usize],
            Root::Ret => CVal::Ptr(Src::Ret(c), 0),
        };
        for d in 0..p.n as usize {
            let k = p.k[d];
            v = match v {
                // (a stack object passed: its slot at the call)
                CVal::Ptr(Src::Stack, _) => match p.root {
                    Root::Arg(j) if d == 0 && k != ELEM => match self.s.stack_fields.iter().find(|f| f.0 == c && f.1 == j && f.2 == k).map(|f| f.3) {
                        Some(FieldVal::Ptr(s, o)) => CVal::Ptr(s, o),
                        Some(FieldVal::Elem(s)) => CVal::Elem(s),
                        _ => CVal::Unk,
                    },
                    _ => CVal::Unk,
                },
                CVal::Ptr(s, _) if k == ELEM => self.load(s, ELEM),
                CVal::Ptr(s, o) => match o.checked_add(k) {
                    Some(at) => self.load(s, at),
                    None => CVal::Unk,
                },
                CVal::Elem(s) => self.load(s, ELEM),
                CVal::Unk => CVal::Unk,
            };
        }
        v
    }

    /// The address `p + off` in the caller: `(source, offset)` (offset `ELEM`: an element).
    fn at(&mut self, c: u32, args: &[CVal; 6], p: Path, off: i32) -> Option<(Src, i32)> {
        match self.path(c, args, p) {
            CVal::Ptr(Src::Stack, _) | CVal::Unk => None,
            CVal::Ptr(s, _) if off == ELEM => Some((s, ELEM)),
            CVal::Ptr(s, o) => Some((s, o.checked_add(off)?)),
            CVal::Elem(s) => Some((s, ELEM)),
        }
    }

    fn value(&mut self, c: u32, args: &[CVal; 6], v: EVal) -> Option<(Src, i32)> {
        match v {
            EVal::Ptr(p, k) => match self.path(c, args, p) {
                CVal::Ptr(Src::Stack, _) | CVal::Unk => None,
                CVal::Ptr(s, o) => Some((s, o.checked_add(k)?)),
                CVal::Elem(s) => Some((s, ELEM)),
            },
            EVal::Elem(p) => match self.path(c, args, p) {
                CVal::Ptr(Src::Stack, _) | CVal::Unk => None,
                CVal::Ptr(s, _) | CVal::Elem(s) => Some((s, ELEM)),
            },
            EVal::Obj(o) => Some((self.obj(c, o), 0)),
            EVal::Unk => None,
        }
    }

    /// The buffer pointer `p` points into, in the caller.
    fn buffer(&mut self, c: u32, args: &[CVal; 6], p: Path) -> Option<Src> {
        match self.path(c, args, p) {
            CVal::Ptr(Src::Stack, _) | CVal::Unk => None,
            CVal::Ptr(s, _) | CVal::Elem(s) => Some(s),
        }
    }

    /// The effects `fx` of the callee of call `c`, in the caller's terms.
    fn apply(&mut self, c: u32, fx: &Effects) {
        let mut args = [CVal::Unk; 6];
        for &(cc, j, s, k) in &self.s.args {
            if cc == c && (j as usize) < 6 {
                args[j as usize] = CVal::Ptr(s, k);
            }
        }
        for &(cc, j, s) in &self.s.elem_args {
            if cc == c && (j as usize) < 6 {
                args[j as usize] = CVal::Elem(s);
            }
        }
        let Some(fx) = fx else {
            // (too many effects: the pointers passed may get anything)
            for a in args {
                match a {
                    CVal::Ptr(s, k) if s != Src::Stack => self.s.buf_escapes.push((s, k)),
                    CVal::Elem(s) => self.s.buf_escapes.push((s, ELEM)),
                    _ => {}
                }
            }
            return;
        };
        for &e in fx {
            match e {
                Effect::Store(p, off, v) => {
                    let Some((d, o)) = self.at(c, &args, p, off) else { continue };
                    match self.value(c, &args, v) {
                        Some((vs, vo)) => self.s.field_stores.push((d, o, vs, vo)),
                        None => self.s.field_clobbers.push((d, o, 8)),
                    }
                }
                Effect::Clobber(p, off, n, number) => {
                    if let Some((d, o)) = self.at(c, &args, p, off) {
                        self.s.field_clobbers.push((d, o, n));
                        if number {
                            self.s.field_numbers.push((d, o, n));
                        }
                    }
                }
                Effect::Vtable(p, off, vt) => {
                    if let (Root::Arg(j), 0, 0) = (p.root, p.n, off)
                        && matches!(args[j as usize], CVal::Ptr(Src::Stack, _))
                    {
                        // (a stack object: the one first given to a call)
                        let inst = match self.s.stack_ev.iter().find(|e| e.0 == c && e.1 == j).map(|e| e.2) {
                            Some(StackEv::Made(c0, j0)) => Some((c0, j0)),
                            Some(StackEv::Vtable(_)) => None,
                            None => Some((c, j)),
                        };
                        if let Some((c0, j0)) = inst {
                            self.s.made_vt.push((c0, j0, vt));
                        }
                        continue;
                    }
                    if let Some((d, o)) = self.at(c, &args, p, off) {
                        self.s.vt_stores.push((d, o, vt));
                    }
                }
                Effect::Copy(a, b) => match (self.buffer(c, &args, a), self.buffer(c, &args, b)) {
                    (Some(x), Some(y)) => self.s.buf_copies.push((x, y)),
                    (Some(x), None) => self.s.buf_writes.push(x),
                    _ => {}
                },
                Effect::Write(p) => {
                    if let Some(x) = self.buffer(c, &args, p) {
                        self.s.buf_writes.push(x);
                    }
                }
                Effect::Escape(p, k) => {
                    if let Some((d, o)) = self.at(c, &args, p, k) {
                        self.s.buf_escapes.push((d, o));
                    }
                }
                Effect::Triple(p, k) => {
                    if let Some((d, o)) = self.at(c, &args, p, k)
                        && o != ELEM
                    {
                        self.s.triples.push((d, o));
                    }
                }
            }
        }
    }
}

/// The strongly connected components of the direct call graph, callees first.
fn sccs(succ: &[Vec<u32>]) -> Vec<Vec<u32>> {
    let n = succ.len();
    let mut index = vec![u32::MAX; n];
    let mut low = vec![0u32; n];
    let mut on = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut out: Vec<Vec<u32>> = Vec::new();
    let mut next = 0u32;
    for root in 0..n {
        if index[root] != u32::MAX {
            continue;
        }
        let mut work: Vec<(u32, usize)> = vec![(root as u32, 0)];
        index[root] = next;
        low[root] = next;
        next += 1;
        stack.push(root as u32);
        on[root] = true;
        while let Some(&mut (v, ref mut i)) = work.last_mut() {
            let vs = &succ[v as usize];
            if *i < vs.len() {
                let w = vs[*i] as usize;
                *i += 1;
                if index[w] == u32::MAX {
                    index[w] = next;
                    low[w] = next;
                    next += 1;
                    stack.push(w as u32);
                    on[w] = true;
                    work.push((w as u32, 0));
                } else if on[w] {
                    low[v as usize] = low[v as usize].min(index[w]);
                }
                continue;
            }
            work.pop();
            if let Some(&(u, _)) = work.last() {
                low[u as usize] = low[u as usize].min(low[v as usize]);
            }
            if low[v as usize] == index[v as usize] {
                let mut comp = Vec::new();
                while let Some(w) = stack.pop() {
                    on[w as usize] = false;
                    comp.push(w);
                    if w == v {
                        break;
                    }
                }
                out.push(comp);
            }
        }
    }
    out
}

/// The functions that allocate and free memory (WS96): a call to an allocator returns fresh
/// memory (no element in it yet), a deallocator has no effect (the memory it is given is dead).
#[derive(Default, Debug, Clone)]
pub struct MemFns {
    /// allocators: import stubs (`malloc`, `operator new`) and functions of the binary
    pub alloc: FxHashSet<u64>,
    /// deallocators (functions of the binary; an import's kind says it for imports)
    pub dealloc: FxHashSet<u64>,
    /// `(global, slot)`: the virtual methods of global allocator objects the allocators /
    /// deallocators call (`[g]->vfn(size)`: one inlined elsewhere is the same)
    pub alloc_slots: FxHashSet<(u64, i32)>,
    pub dealloc_slots: FxHashSet<(u64, i32)>,
}

/// Most callers needed to take a function for an allocator / deallocator by its use.
pub const MIN_MEM_USES: usize = 8;

/// The allocators and deallocators of the binary (WS96): the import stubs named so, and the
/// functions of the binary found by their shape and their use (a stripped binary's `operator
/// new` / `operator delete`, which may call a global allocator object's virtual methods):
///
/// * an **allocator** returns the result of one call, which it neither stores nor passes on,
///   and at least [`MIN_MEM_USES`] functions construct an object in its result (a vtable stored
///   at its `+0`, or the result given as `this` to a function storing a vtable there); or it so
///   returns an allocator's result (a wrapper);
/// * a **deallocator** neither reads nor writes through its first argument and only gives it to
///   unknown code, an import or another deallocator, and at least [`MIN_MEM_USES`] methods listed
///   in vtables give it `this` (deleting destructors); and the deallocators it calls.
pub fn memory_functions(starts: &[u64], sums: &[Summary], listed: &(dyn Fn(u64) -> bool + Sync), imports: &FxHashMap<u64, ImportKind>) -> MemFns {
    let n = starts.len();
    let fidx = |a: u64| starts.binary_search(&a).ok();
    let mut alloc: FxHashSet<u64> = imports.iter().filter(|(_, k)| matches!(k, ImportKind::Alloc | ImportKind::Realloc)).map(|(&a, _)| a).collect();
    // (a constructor: stores a vtable at +0 of its first argument)
    let ctor: Vec<bool> = sums.par_iter().map(|s| s.vt_stores.iter().any(|v| v.0 == Src::Arg(0) && v.1 == 0)).collect();
    let pairs: Vec<(u32, u32)> = sums
        .par_iter()
        .enumerate()
        .flat_map_iter(|(k, s)| {
            let made = |c: u32| {
                let r = Src::Ret(c);
                s.vt_stores.iter().any(|v| v.0 == r && v.1 == 0) || s.args.iter().any(|a| a.1 == 0 && a.2 == r && a.3 == 0 && fidx(s.call_targets[a.0 as usize]).is_some_and(|t| ctor[t]))
            };
            let mut ts: Vec<(u32, u32)> = (0..s.call_targets.len() as u32).filter(|&c| made(c)).filter_map(|c| fidx(s.call_targets[c as usize]).map(|t| (t as u32, k as u32))).collect();
            ts.sort_unstable();
            ts.dedup();
            ts
        })
        .collect();
    let mut made_in = vec![0usize; n];
    for (t, _) in pairs {
        made_in[t as usize] += 1;
    }
    // (returns the result of call `c`, used nowhere else)
    let returns_call = |s: &Summary| -> Option<u32> {
        let Some(Src::Ret(c)) = returned(s) else { return None };
        let r = Src::Ret(c);
        let used = s.field_stores.iter().any(|f| f.0 == r || f.2 == r)
            || s.field_clobbers.iter().any(|f| f.0 == r)
            || s.vt_stores.iter().any(|v| v.0 == r)
            || s.args.iter().any(|a| a.2 == r)
            || s.buf_copies.iter().any(|b| b.0 == r || b.1 == r)
            || s.buf_writes.contains(&r)
            || s.buf_escapes.iter().any(|e| e.0 == r)
            || s.loads.iter().any(|l| l.0 == r);
        (!used).then_some(c)
    };
    let shape: Vec<Option<u32>> = sums.par_iter().map(returns_call).collect();
    for _ in 0..6 {
        let mut changed = false;
        for k in 0..n {
            let Some(c) = shape[k] else { continue };
            if !alloc.contains(&starts[k]) && (made_in[k] >= MIN_MEM_USES || alloc.contains(&sums[k].call_targets[c as usize])) {
                alloc.insert(starts[k]);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // deallocators: the shape (a greatest fixpoint over the calls given the pointer), then the use
    let a0 = Src::Arg(0);
    let local: Vec<bool> = sums
        .par_iter()
        .map(|s| {
            let touched = s.loads.iter().any(|l| l.0 == a0)
                || s.field_stores.iter().any(|f| f.0 == a0 || f.2 == a0)
                || s.field_clobbers.iter().any(|f| f.0 == a0)
                || s.vt_stores.iter().any(|v| v.0 == a0)
                || s.rets.iter().any(|r| r.0 == a0)
                || s.buf_writes.contains(&a0)
                || s.buf_copies.iter().any(|b| b.0 == a0 || b.1 == a0)
                || s.stack_fields.iter().any(|f| matches!(f.3, FieldVal::Ptr(x, _) | FieldVal::Elem(x) if x == a0));
            let bad_import = s.args.iter().filter(|a| a.2 == a0).any(|a| matches!(imports.get(&s.call_targets[a.0 as usize]), Some(ImportKind::Copy | ImportKind::Memset | ImportKind::WritesArgs | ImportKind::Realloc)));
            !touched && !bad_import && s.args.iter().any(|a| a.2 == a0)
        })
        .collect();
    let mut cand = local;
    loop {
        let next: Vec<bool> = (0..n)
            .into_par_iter()
            .map(|k| cand[k] && sums[k].args.iter().filter(|a| a.2 == a0).all(|a| fidx(sums[k].call_targets[a.0 as usize]).is_none_or(|t| cand[t])))
            .collect();
        if next == cand {
            break;
        }
        cand = next;
    }
    let mut freed_by = vec![0usize; n];
    let mut fp: Vec<(u32, u32)> = sums
        .par_iter()
        .enumerate()
        .filter(|(k, _)| listed(starts[*k]))
        .flat_map_iter(|(k, s)| s.args.iter().filter(|a| a.1 == 0 && a.2 == a0 && a.3 == 0).filter_map(move |a| fidx(s.call_targets[a.0 as usize]).map(|t| (t as u32, k as u32))))
        .collect();
    fp.sort_unstable();
    fp.dedup();
    for (t, _) in fp {
        freed_by[t as usize] += 1;
    }
    let mut dealloc: FxHashSet<u64> = FxHashSet::default();
    let mut work: Vec<usize> = (0..n).filter(|&k| cand[k] && freed_by[k] >= MIN_MEM_USES).collect();
    while let Some(k) = work.pop() {
        if !dealloc.insert(starts[k]) {
            continue;
        }
        work.extend(sums[k].args.iter().filter(|a| a.2 == a0).filter_map(|a| fidx(sums[k].call_targets[a.0 as usize])).filter(|&t| cand[t]));
    }
    let mut alloc_slots: FxHashSet<(u64, i32)> = FxHashSet::default();
    for k in 0..n {
        if let Some(c) = shape[k]
            && alloc.contains(&starts[k])
            && let Some(g) = sums[k].global_calls.iter().find(|g| g.0 == c)
        {
            alloc_slots.insert((g.1, g.2));
        }
    }
    let mut dealloc_slots: FxHashSet<(u64, i32)> = FxHashSet::default();
    for &f in &dealloc {
        let s = &sums[fidx(f).expect("a function")];
        for g in &s.global_calls {
            if s.buf_escapes[g.3 as usize..g.4 as usize].contains(&(a0, 0)) {
                dealloc_slots.insert((g.1, g.2));
            }
        }
    }
    MemFns { alloc, dealloc, alloc_slots, dealloc_slots }
}

/// (WS96) The fresh-memory facts of `s` moved to where the memory went, and its triples: a fresh
/// buffer `B` (the result of a call to an allocator) whose pointer is stored into fields of an
/// object (the lowest offset per object: the begin pointer) or that is copied into another
/// buffer has its facts — what is stored, clobbered, written, copied or escapes through it, the
/// elements loaded from it — duplicated onto the buffer of that field (`(Ld([D + o]), ELEM)`) or
/// that buffer: the elements the container gets. Pointers into one buffer stored at `+o`,
/// `+o + 8`, `+o + 16` of one object (one of them past the buffer's start) are a
/// `{begin, end, capacity}` triple.
pub fn install(s: &mut Summary) {
    // the triples
    // (value source, object) -> the offsets it is stored at (and whether past the buffer's start)
    type Stored = FxHashMap<(Src, Src), SmallVec<[(i32, bool); 4]>>;
    let mut by: Stored = FxHashMap::default();
    for &(d, o, vs, vo) in &s.field_stores {
        if d != Src::Stack && vs != Src::Stack && o != ELEM && o >= 0 {
            by.entry((vs, d)).or_default().push((o, vo != 0));
        }
    }
    for ((_, d), offs) in by {
        let at = |x: i32| offs.iter().filter(|e| e.0 == x).map(|e| e.1).reduce(|a, b| a | b);
        for &(o, _) in &offs {
            if let (Some(a), Some(b), Some(c)) = (at(o), at(o + 8), at(o + 16))
                && (a | b | c)
            {
                s.triples.push((d, o));
            }
        }
    }
    let fresh = |x: Src| matches!(x, Src::Ret(c) if s.fresh.binary_search(&c).is_ok());
    let mut sources: Vec<Src> = s.field_stores.iter().map(|f| f.2).chain(s.buf_copies.iter().map(|b| b.1)).filter(|&x| fresh(x)).collect();
    sources.sort_unstable();
    sources.dedup();
    if sources.is_empty() {
        normalize(s);
        return;
    }
    let mut loads: FxHashMap<(Src, i32), u32> = s.loads.iter().enumerate().map(|(l, &k)| (k, l as u32)).collect();
    for b in sources {
        let mut low: FxHashMap<Src, i32> = FxHashMap::default();
        for &(d, o, vs, _) in &s.field_stores {
            if vs == b && d != Src::Stack && d != b && o != ELEM && o >= 0 {
                let e = low.entry(d).or_insert(o);
                *e = (*e).min(o);
            }
        }
        let mut low: Vec<(Src, i32)> = low.into_iter().collect();
        low.sort_unstable();
        let mut targets: Vec<Src> = Vec::new();
        for (d, o) in low {
            let l = *loads.entry((d, o)).or_insert_with(|| {
                s.loads.push((d, o));
                s.loads.len() as u32 - 1
            });
            targets.push(Src::Ld(l));
        }
        targets.extend(s.buf_copies.iter().filter(|c| c.1 == b && c.0 != b && c.0 != Src::Stack).map(|c| c.0));
        targets.sort_unstable();
        targets.dedup();
        if targets.is_empty() {
            continue;
        }
        let stores: Vec<(Src, i32)> = s.field_stores.iter().filter(|f| f.0 == b).map(|f| (f.2, f.3)).collect();
        let clobbers: Vec<(i32, bool)> = s.field_clobbers.iter().filter(|f| f.0 == b).map(|f| (f.2, s.field_numbers.contains(f))).collect();
        let constructed = s.vt_stores.iter().any(|v| v.0 == b);
        let copies: Vec<Src> = s.buf_copies.iter().filter(|c| c.0 == b && c.1 != b).map(|c| c.1).collect();
        let written = s.buf_writes.contains(&b);
        let escapes = s.buf_escapes.iter().any(|e| e.0 == b);
        for &t in &targets {
            s.field_stores.extend(stores.iter().map(|&(vs, vo)| (t, ELEM, vs, vo)));
            for &(n, number) in &clobbers {
                s.field_clobbers.push((t, ELEM, n));
                if number {
                    s.field_numbers.push((t, ELEM, n));
                }
            }
            if constructed {
                s.field_clobbers.push((t, ELEM, 8));
            }
            s.buf_copies.extend(copies.iter().map(|&y| (t, y)));
            if written {
                s.buf_writes.push(t);
            }
            if escapes {
                s.buf_escapes.push((t, ELEM));
            }
        }
        // (an element loaded from it is one of the container's, when it went to one)
        if let [t] = targets[..] {
            for l in s.loads.iter_mut() {
                if l.0 == b {
                    *l = (t, ELEM);
                }
            }
        }
    }
    normalize(s);
}

/// The summaries `sums` of the functions `starts` (address order) with the effects of their
/// direct callees composed in; `export[k]`: the parameters of function `k` whose effects its
/// callers get (a mask); `mem`: the allocators and deallocators (WS96: an allocator's result is
/// fresh memory, see [`install`]; a deallocator has no effects).
pub fn compose(starts: &[u64], mut sums: Vec<Summary>, export: &[u8], mem: &MemFns) -> Vec<Summary> {
    let n = starts.len();
    sums.par_iter_mut().for_each(|s| {
        s.fresh = (0..s.call_targets.len() as u32).filter(|&c| mem.alloc.contains(&s.call_targets[c as usize])).collect();
        // (a global allocator's methods called inline: what `operator new` / `delete` call)
        let mut drop: Vec<(u32, u32)> = Vec::new();
        for &(c, g, slot, from, to) in &s.global_calls {
            if mem.alloc_slots.contains(&(g, slot)) {
                s.fresh.push(c);
                drop.push((from, to));
            } else if mem.dealloc_slots.contains(&(g, slot)) {
                drop.push((from, to));
            }
        }
        if !drop.is_empty() {
            let mut k = 0u32;
            s.buf_escapes.retain(|_| {
                let keep = !drop.iter().any(|&(a, b)| (a..b).contains(&k));
                k += 1;
                keep
            });
            s.fresh.sort_unstable();
            s.fresh.dedup();
        }
    });
    let fidx = |a: u64| starts.binary_search(&a).ok();
    let succ: Vec<Vec<u32>> = sums
        .par_iter()
        .map(|s| {
            let mut v: Vec<u32> = s.call_targets.iter().filter_map(|&t| fidx(t).map(|x| x as u32)).collect();
            v.sort_unstable();
            v.dedup();
            v
        })
        .collect();
    let comps = sccs(&succ);
    // (levels: a component after every component it calls)
    let mut comp_of = vec![0u32; n];
    for (ci, c) in comps.iter().enumerate() {
        for &v in c {
            comp_of[v as usize] = ci as u32;
        }
    }
    let mut level = vec![0u32; comps.len()];
    for (ci, c) in comps.iter().enumerate() {
        let mut l = 0;
        for &v in c {
            for &w in &succ[v as usize] {
                let cw = comp_of[w as usize] as usize;
                if cw != ci {
                    l = l.max(level[cw] + 1);
                }
            }
        }
        level[ci] = l;
    }
    let mut by_level: Vec<Vec<u32>> = vec![Vec::new(); level.iter().max().map_or(0, |&m| m as usize + 1)];
    for (ci, &l) in level.iter().enumerate() {
        by_level[l as usize].push(ci as u32);
    }
    let mut fx: Vec<Effects> = vec![Some(Vec::new()); n];
    let mut out: Vec<Option<Summary>> = (0..n).map(|_| None).collect();
    for comps_at in by_level {
        let done: Vec<Vec<(u32, Summary, Effects)>> = comps_at
            .par_iter()
            .map(|&ci| {
                let comp = &comps[ci as usize];
                let recursive = comp.len() > 1 || succ[comp[0] as usize].contains(&comp[0]);
                let mut local: FxHashMap<u32, Effects> = FxHashMap::default();
                let mut res: Vec<(u32, Summary, Effects)> = Vec::new();
                for _ in 0..if recursive { MAX_SCC_ROUNDS } else { 1 } {
                    res.clear();
                    let view = |t: usize| -> &Effects { local.get(&(t as u32)).unwrap_or(&fx[t]) };
                    for &v in comp {
                        let mut s = compose_with(&sums[v as usize], &view, &fidx);
                        install(&mut s);
                        // (the memory functions: none — what an allocator is given is its size)
                        let e = if mem.dealloc.contains(&starts[v as usize]) || mem.alloc.contains(&starts[v as usize]) { Some(Vec::new()) } else { effects_of(&s, export[v as usize]) };
                        res.push((v, s, e));
                    }
                    let mut changed = false;
                    for (v, _, e) in &res {
                        if local.get(v) != Some(e) {
                            changed = true;
                            local.insert(*v, e.clone());
                        }
                    }
                    if !changed {
                        break;
                    }
                }
                res
            })
            .collect();
        for (v, s, e) in done.into_iter().flatten() {
            fx[v as usize] = e;
            out[v as usize] = Some(s);
        }
    }
    out.into_iter().map(|s| s.unwrap_or_default()).collect()
}

/// `orig` with the effects of its direct callees (`view`: by function index; `fidx` maps an
/// address to one).
fn compose_with<'v>(orig: &Summary, view: &dyn Fn(usize) -> &'v Effects, fidx: &dyn Fn(u64) -> Option<usize>) -> Summary {
    let mut s = orig.clone();
    let calls: SmallVec<[(u32, usize); 16]> = orig.call_targets.iter().enumerate().filter_map(|(c, &t)| Some((c as u32, fidx(t)?))).filter(|&(_, t)| view(t).as_ref().is_none_or(|v| !v.is_empty())).collect();
    if calls.is_empty() {
        return s;
    }
    let loads = s.loads.iter().enumerate().map(|(l, &k)| (k, l as u32)).collect();
    let objs = s.objs.iter().enumerate().filter(|(_, o)| !matches!(o, ObjRef::Fresh(_))).map(|(i, &o)| ((u32::MAX, o), i as u32)).collect();
    let mut cx = Caller { s: &mut s, loads, objs };
    for (c, t) in calls {
        cx.apply(c, view(t));
    }
    normalize(&mut s);
    s
}

fn normalize(s: &mut Summary) {
    s.field_stores.sort_unstable();
    s.field_stores.dedup();
    s.field_clobbers.sort_unstable();
    s.field_clobbers.dedup();
    s.field_numbers.sort_unstable();
    s.field_numbers.dedup();
    s.vt_stores.sort_unstable();
    s.vt_stores.dedup();
    s.buf_copies.sort_unstable();
    s.buf_copies.dedup();
    s.buf_writes.sort_unstable();
    s.buf_writes.dedup();
    s.buf_escapes.sort_unstable();
    s.buf_escapes.dedup();
    s.made_vt.sort_unstable();
    s.made_vt.dedup();
    s.triples.sort_unstable();
    s.triples.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sum(targets: &[u64]) -> Summary {
        Summary { call_targets: targets.to_vec(), ..Default::default() }
    }

    /// WS96: an allocator by its use (callers construct objects in its result) and a wrapper
    /// returning its result; a deallocator by its shape (it only hands its argument to unknown
    /// code) and its use (deleting destructors give it `this`).
    #[test]
    fn allocators_and_deallocators_are_found_by_their_shape_and_use() {
        // 0x100: operator new (returns an indirect call's result); 0x200: a wrapper of it;
        // 0x300: operator delete (gives its argument to unknown code); 0x400: a getter (returns
        // a loaded pointer, never constructed in); 0x1000..: the users
        let mut starts = vec![0x100, 0x200, 0x300, 0x400];
        let mut new = sum(&[0]);
        new.rets = vec![(Src::Ret(0), 0)];
        let mut wrap = sum(&[0x100]);
        wrap.rets = vec![(Src::Ret(0), 0)];
        let mut del = sum(&[0]);
        del.args = vec![(0, 1, Src::Arg(0), 0)];
        del.buf_escapes = vec![(Src::Arg(0), 0)];
        let mut get = sum(&[]);
        get.loads = vec![(Src::Arg(0), 8)];
        get.rets = vec![(Src::Ld(0), 0)];
        let mut sums = vec![new, wrap, del, get];
        let mut listed = Vec::new();
        for i in 0..MIN_MEM_USES as u64 {
            // a user: `p = new(…); p->_vptr = vt; delete(this)` (a listed deleting destructor)
            starts.push(0x1000 + i * 0x10);
            let mut u = sum(&[0x100, 0x300, 0x400]);
            u.vt_stores = vec![(Src::Ret(0), 0, 0x9000)];
            u.args = vec![(1, 0, Src::Arg(0), 0)];
            sums.push(u);
            listed.push(0x1000 + i * 0x10);
        }
        let is_listed = |f: u64| listed.contains(&f);
        let m = memory_functions(&starts, &sums, &is_listed, &FxHashMap::default());
        let mut a: Vec<u64> = m.alloc.iter().copied().collect();
        a.sort_unstable();
        assert_eq!(a, [0x100, 0x200]);
        assert_eq!(m.dealloc.iter().copied().collect::<Vec<_>>(), [0x300]);
    }

    /// WS96: fresh memory installed into a container's fields (an inlined `push_back` slow
    /// path): what is stored into it, copied into it, are the facts of the buffer of the field
    /// it went to (the lowest offset: the begin pointer); three pointers into it at `+o`, `+o+8`,
    /// `+o+16` are a triple; exported to the callers in their terms.
    #[test]
    fn fresh_memory_installed_into_fields_gives_its_elements_to_their_buffer() {
        // `new = operator new(n); new[i] = *x; memcpy(new, this->begin, …); this->begin = new;
        // this->end = new + …; this->cap = new + n`
        let mut s = sum(&[0x100, 0x200]);
        s.fresh = vec![0];
        s.loads = vec![(Src::Arg(1), 0), (Src::Arg(0), 0)];
        s.field_stores = vec![
            (Src::Ret(0), ELEM, Src::Ld(0), 0),
            (Src::Arg(0), 0, Src::Ret(0), 0),
            (Src::Arg(0), 8, Src::Ret(0), ELEM),
            (Src::Arg(0), 16, Src::Ret(0), ELEM),
        ];
        s.buf_copies = vec![(Src::Ret(0), Src::Ld(1))];
        install(&mut s);
        assert_eq!(s.triples, [(Src::Arg(0), 0)]);
        assert!(s.field_stores.contains(&(Src::Ld(1), ELEM, Src::Ld(0), 0)), "{:?}", s.field_stores);
        assert!(s.buf_copies.contains(&(Src::Ld(1), Src::Ld(1))), "{:?}", s.buf_copies);
        let fx = effects_of(&s, 0x3f).expect("effects");
        let begin = Path { root: Root::Arg(0), n: 1, k: [0, 0] };
        let x = Path { root: Root::Arg(1), n: 1, k: [0, 0] };
        assert!(fx.contains(&Effect::Store(begin, ELEM, EVal::Ptr(x, 0))), "{fx:?}");
        assert!(fx.contains(&Effect::Triple(Path::root(Root::Arg(0)), 0)), "{fx:?}");
        // the begin pointer is fresh memory to the callers, at any offset (no clobber)
        assert!(fx.contains(&Effect::Store(Path::root(Root::Arg(0)), 8, EVal::Obj(ObjRef::Fresh(0)))), "{fx:?}");
        // a caller pushing its own argument into its member vector (`this + 0x20`)
        let mut c = sum(&[0x1000]);
        c.args = vec![(0, 0, Src::Arg(0), 0x20), (0, 1, Src::Arg(1), 0)];
        let mut cx = Caller { loads: FxHashMap::default(), objs: FxHashMap::default(), s: &mut c };
        cx.apply(0, &Some(fx));
        assert_eq!(c.loads, [(Src::Arg(0), 0x20), (Src::Arg(1), 0)]);
        assert!(c.field_stores.contains(&(Src::Ld(0), ELEM, Src::Ld(1), 0)), "{:?}", c.field_stores);
        assert_eq!(c.triples, [(Src::Arg(0), 0x20)]);
        assert!(c.field_clobbers.is_empty(), "{:?}", c.field_clobbers);
    }

    /// WS96: memory not fresh (a function's result that is no allocator's) is not moved: its
    /// earlier elements are not known.
    #[test]
    fn memory_not_fresh_is_not_moved() {
        let mut s = sum(&[0x100]);
        s.field_stores = vec![(Src::Ret(0), ELEM, Src::Arg(1), 0), (Src::Arg(0), 8, Src::Ret(0), 0)];
        install(&mut s);
        assert!(!s.field_stores.iter().any(|f| f.1 == ELEM && f.0 != Src::Ret(0)), "{:?}", s.field_stores);
        assert!(s.triples.is_empty());
    }
}
