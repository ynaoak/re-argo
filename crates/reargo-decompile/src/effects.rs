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

use crate::thisclass::{FieldVal, Src, StackEv, Summary, ELEM};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
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

/// The source every `ret` of `s` returns, when it is one (at offset 0).
fn returned(s: &Summary) -> Option<Src> {
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
    objs: FxHashMap<ObjRef, u32>,
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

    fn obj(&mut self, o: ObjRef) -> Src {
        if let Some(&i) = self.objs.get(&o) {
            return Src::Obj(i);
        }
        let i = self.s.objs.len() as u32;
        self.s.objs.push(o);
        self.objs.insert(o, i);
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
            EVal::Obj(o) => Some((self.obj(o), 0)),
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

/// The summaries `sums` of the functions `starts` (address order) with the effects of their
/// direct callees composed in; `export[k]`: the parameters of function `k` whose effects its
/// callers get (a mask).
pub fn compose(starts: &[u64], sums: Vec<Summary>, export: &[u8]) -> Vec<Summary> {
    let n = starts.len();
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
                        let s = compose_with(&sums[v as usize], &view, &fidx);
                        let e = effects_of(&s, export[v as usize]);
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
    let objs = s.objs.iter().enumerate().map(|(i, &o)| (o, i as u32)).collect();
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
}
