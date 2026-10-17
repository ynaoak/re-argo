//! The classes of the objects a function is given (WS93): `this` of a non-virtual method in a
//! stripped binary, from what its callers pass.
//!
//! A whole-binary index, built once per binary (and cached, see [`load_or_build`]):
//!
//! * **Summaries.** Each function (an `.eh_frame` FDE range) is decoded linearly (x86-64) and
//!   followed with a forward data flow over its basic blocks: the 16 general registers, the
//!   stack pointer as an offset from its value on entry, and the 8-byte stack slots (spills).
//!   A value is unknown, a constant, or a pointer `source + k`, the source being an argument
//!   register on entry (`Arg(i)`), the result of a call (`Ret(c)`), a value loaded from a
//!   field of a pointer (`Ld(l)`: `[source + k]`) or the stack (an address in the frame). A
//!   block no jump reaches (a jump table's case, a landing pad) starts from the meet of the
//!   states after the calls and at the indirect jumps. A stack object is followed through the
//!   flow, as a slot may be reused for another object: it is the one the first call it is given
//!   to made (its constructor, when that callee is one; or the vtable an inlined constructor
//!   stored) until the slot is written again, and the objects a slot holds on two joined paths
//!   are one. The facts kept: the direct calls and
//!   tail jumps with the pointers passed in `rdi rsi rdx rcx r8 r9` (an argument that is no
//!   pointer — unknown, a constant other than 0 — makes the callee's parameter unknown), the
//!   vtables stored at `[p + 0]` (a constructor or destructor; a primary vtable at `[p + k]`:
//!   an embedded member object), the pointers stored into fields, the pointer left in `rax`
//!   at each `ret`, and the functions whose address is taken (`lea r, [rip + f]`).
//! * **Classes.** The polymorphic classes come from the RTTI: a vtable's address point is
//!   a run of code pointers behind a `type_info` pointer and an offset-to-top; the class's
//!   primary vtable has offset-to-top 0, its bases come from the `type_info`.
//! * **Seeds.** A method listed in primary vtables has the class all of them derive from as
//!   `this` (the second argument for a method returning a struct in memory); a function
//!   storing a vtable into its argument `i` (a constructor / destructor) has that class there
//!   (the most derived of several). The other parameters of a function listed in a vtable, and
//!   every parameter of a function whose address is taken or with no direct caller, are
//!   unknown (it can be called from anywhere).
//! * **Propagation.** The class of parameter `j` of `f` is the join of what every direct call
//!   of `f` passes there: the caller's own parameter's class, a local object's class (from the
//!   vtables stored into it and the seeds of the calls made on it — its constructor, destructor,
//!   virtual methods called directly; or the callee's return class for a call result), the
//!   class of a field of an object of a known class (the join of
//!   the objects stored there by any function of that class or its bases), an embedded member's
//!   class. The join of two classes is their nearest common base (unknown when there is none);
//!   one unknown caller makes the parameter unknown. The return class of a function is the
//!   join of what it returns. Rounds are repeated (from "nothing known") until nothing changes
//!   or the budget runs out.
//!
//! The index records, per function, the class (primary vtable) of each parameter known, the
//! return class, and the field / member classes by container class.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use rayon::prelude::*;
use reargo_loader::{Memory, MemoryFlags};
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;

/// Integer argument registers (System V): rdi rsi rdx rcx r8 r9 (iced GPR numbers).
const ARG_REGS: [usize; 6] = [7, 6, 2, 1, 8, 9];
/// Registers a call clobbers (rax is the result).
const CALLER_SAVED: [usize; 9] = [0, 1, 2, 6, 7, 8, 9, 10, 11];
const RAX: usize = 0;
const RSP: usize = 4;
const RBP: usize = 5;
/// Most instructions decoded per function.
const MAX_INSNS: usize = 200_000;
/// Most stack slots tracked per state.
const MAX_SLOTS: usize = 48;
/// Most loaded values named per function.
const MAX_LOADS: usize = 4096;
/// Rounds of the propagation.
pub const MAX_ROUNDS: usize = 40;

/// Where a pointer comes from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Src {
    /// argument register `i` on entry
    Arg(u8),
    /// the result of call `c` (an index into [`Summary::call_targets`])
    Ret(u32),
    /// the value loaded from `loads[l]`
    Ld(u32),
    /// the stack (the offset is from the stack pointer on entry)
    Stack,
    /// (WS95) an object a callee's effects name (`Summary::objs[i]`: of a vtable's class, or of
    /// a function's return class)
    Obj(u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Val {
    Unk,
    Const(u64),
    Ptr(Src, i32),
    /// (a stack slot only) the object here was first given to call `c` as argument `j` since
    /// the slot was last written: its constructor, when that callee is one
    Made(u32, u8),
    /// (WS95) a pointer into the buffer `source` points into, at an offset not known (an
    /// indexed address, a pointer plus a register, or stepped through it in a loop): an element
    /// of an array / a vector
    Elem(Src),
}

/// The offset of an element of a buffer (WS95; see `Val::Elem`) in the loads, field stores,
/// vtable stores and clobbers of a summary: `(src, ELEM)` is an element of the buffer `src`
/// points into; a stored value `(src, ELEM)` is a pointer into it.
pub const ELEM: i32 = i32::MIN;

/// What a call to an import does with the memory its pointer arguments reach (WS95).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImportKind {
    /// nothing a pointer's class depends on (`free`, `strlen`, `pthread_mutex_lock`, …)
    Pure,
    /// copies the elements of the buffer its second argument points into into the buffer its
    /// first argument points into (`memcpy`, `memmove`)
    Copy,
    /// its result is a buffer holding the elements of the buffer its first argument points into
    Realloc,
    /// fills the buffer its first argument points into (nothing when it fills with 0)
    Memset,
    /// writes data (no pointers of a class) into the buffers its pointer arguments point into
    /// (`read`, `snprintf`, `strcpy`, …)
    WritesArgs,
    /// anything (another module's function, a callback): the memory its pointer arguments
    /// reach may get anything
    Escape,
}

/// The kind of an import, by its name (WS95): `Escape` when not known.
pub fn import_kind(name: &str) -> ImportKind {
    let name = name.trim_end_matches("@plt");
    let name = name.split('@').next().unwrap_or(name);
    match name {
        "memcpy" | "memmove" | "__memcpy_chk" | "__memmove_chk" | "mempcpy" | "wmemcpy" | "wmemmove" => ImportKind::Copy,
        "realloc" | "reallocarray" => ImportKind::Realloc,
        "memset" | "__memset_chk" | "wmemset" | "bzero" | "explicit_bzero" => ImportKind::Memset,
        // (they call back user code with a user pointer, or do anything)
        "pthread_once" | "pthread_create" | "__cxa_atexit" | "__cxa_thread_atexit_impl" | "atexit" | "qsort" | "bsearch" | "syscall" | "dl_iterate_phdr" => ImportKind::Escape,
        _ if PURE_IMPORTS.contains(&name) || name.starts_with("_Unwind_") || name.starts_with("pthread_") || name.starts_with("__cxa_") || name.starts_with("sched_") => ImportKind::Pure,
        _ if WRITING_IMPORTS.contains(&name) || is_math(name) => ImportKind::WritesArgs,
        _ => ImportKind::Escape,
    }
}

/// libm-style names (`sqrtf`, `ldexpl`, …) and the compiler's arithmetic helpers: no pointers,
/// or an out-parameter of numbers.
fn is_math(name: &str) -> bool {
    const MATH: &[&str] = &[
        "sqrt", "cbrt", "pow", "exp", "exp2", "expm1", "log", "log2", "log10", "log1p", "sin", "cos", "tan", "asin", "acos", "atan", "atan2", "sinh", "cosh",
        "tanh", "fmod", "modf", "frexp", "ldexp", "floor", "ceil", "round", "trunc", "lround", "llround", "lrint", "llrint", "rint", "nearbyint", "hypot",
        "nextafter", "nan", "fabs", "fmin", "fmax", "remainder", "copysign", "sincos",
    ];
    let base = name.strip_suffix('f').or_else(|| name.strip_suffix('l')).filter(|b| MATH.contains(b)).unwrap_or(name);
    MATH.contains(&base) || ["__float", "__fix", "__udiv", "__div", "__umod", "__mod"].iter().any(|p| name.starts_with(p))
}

/// Imports that write nothing a pointer's class depends on into user memory.
const PURE_IMPORTS: &[&str] = &[
    "free", "malloc", "calloc", "aligned_alloc", "posix_memalign", "malloc_usable_size", "strlen", "strnlen", "wcslen", "strcmp", "strncmp", "strcasecmp",
    "strncasecmp", "memcmp", "bcmp", "wmemcmp", "memchr", "memrchr", "wmemchr", "strchr", "strrchr", "strstr", "strspn", "strcspn", "strpbrk", "strcoll_l",
    "wcscoll_l", "strdup", "abort", "exit", "_exit", "_Exit", "__assert_fail", "__stack_chk_fail", "__errno_location", "fwrite", "fputs", "fputc", "fputwc",
    "fprintf", "printf", "vfprintf", "fflush", "fflush_unlocked", "fclose", "fseek", "fseeko", "fseeko64", "ftell", "ftello", "setbuf", "setvbuf", "ferror",
    "feof", "clearerr", "fileno", "flockfile", "funlockfile", "__overflow", "close", "write", "send", "sendto", "sendmsg", "socket", "setsockopt", "bind",
    "listen", "connect", "shutdown", "epoll_ctl", "epoll_create", "epoll_create1", "timerfd_create", "timerfd_settime", "eventfd", "getenv", "secure_getenv",
    "sysconf", "getpagesize", "getpid", "geteuid", "time", "clock", "rand", "srand", "nanosleep", "usleep", "sleep", "pause", "mmap", "munmap", "dlopen",
    "dlerror", "dlclose", "dlsym", "access", "rename", "remove", "unlink", "mkdir", "rmdir", "chmod", "fchmod", "utime", "opendir", "closedir", "readdir",
    "readdir64", "lseek", "lseek64", "fopen", "fopen64", "fdopen", "getc", "ungetc", "getwc", "ungetwc", "freeaddrinfo", "gai_strerror", "gethostbyname",
    "if_nametoindex", "freeifaddrs", "fnmatch", "localeconv", "newlocale", "uselocale", "freelocale", "setlocale", "catopen", "catgets", "catclose", "btowc",
    "wctob", "__ctype_get_mb_cur_max", "__ctype_b_loc", "__ctype_toupper_loc", "__ctype_tolower_loc", "toupper_l", "tolower_l", "towupper_l", "towlower_l",
    "iswspace_l", "iswprint_l", "iswblank_l", "iswcntrl_l", "iswupper_l", "iswlower_l", "iswalpha_l", "iswdigit_l", "iswpunct_l", "iswxdigit_l", "isspace",
    "tolower", "toupper", "atoi", "atol", "strerror", "inet_ntoa", "backtrace_symbols", "shmget", "shmat", "shmdt", "setrlimit", "fcntl", "fcntl64", "ftruncate",
    "ioctl", "__register_atfork", "__xpg_basename", "signal", "open", "open64", "kill", "raise", "getentropy",
];

/// Imports that write data (no pointers of a class) into the buffers their arguments point into.
const WRITING_IMPORTS: &[&str] = &[
    "read", "recv", "recvfrom", "recvmsg", "fread", "fgets", "snprintf", "sprintf", "vsnprintf", "vsprintf", "swprintf", "vasprintf", "asprintf", "strcpy",
    "strncpy", "strcat", "strncat", "stpcpy", "strerror_r", "__xpg_strerror_r", "strftime", "strftime_l", "strxfrm_l", "wcsxfrm_l", "mbsrtowcs", "mbsnrtowcs",
    "wcsnrtombs", "wcrtomb", "mbrtowc", "mbtowc", "__isoc99_sscanf", "__isoc99_vsscanf", "sscanf", "strtol", "strtoul", "strtoll", "strtoull", "strtof",
    "strtod", "strtold", "wcstol", "wcstoul", "wcstoll", "wcstoull", "wcstof", "wcstod", "wcstold", "strtoll_l", "strtoull_l", "strtof_l", "strtod_l",
    "strtold_l", "clock_gettime", "gettimeofday", "localtime_r", "gmtime_r", "mktime", "uname", "sysinfo", "statvfs", "stat", "stat64", "fstat", "fstat64",
    "lstat", "realpath", "readlink", "getaddrinfo", "getnameinfo", "gethostname", "getsockname", "getpeername", "getsockopt", "getifaddrs", "if_indextoname",
    "inet_pton", "inet_ntop", "accept", "accept4", "select", "poll", "epoll_wait", "pipe", "socketpair", "backtrace", "sigaction", "sigemptyset", "sigaddset",
    "sigfillset", "sigprocmask", "getpwuid_r", "ldiv", "div", "getrandom",
];

// A stack object, by the call it was first given to and the argument: `(call, argument)`.
pub type Instance = (u32, u8);

/// What says the class of a stack object passed to a call, at that call (WS93): the vtable
/// pointer it holds (an inlined constructor stored it), or the call it was first given to
/// (`(call, argument)`: its constructor, when that callee stores a vtable into it). A stack slot
/// is reused for several objects, so this is followed through the function's flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StackEv {
    Vtable(u64),
    Made(u32, u8),
}

/// What a field of a stack object passed to a call holds at that call (WS94): a pointer
/// `source + offset`, or the address of another stack object (its evidence).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FieldVal {
    Ptr(Src, i32),
    Obj(StackEv),
    /// (WS95) a pointer into the buffer `source` points into
    Elem(Src),
}

/// Most bytes past a stack object's address whose slots are recorded as its fields at a call.
const MAX_STACK_FIELD: i32 = 0x400;

/// What one function does with pointers (see the module documentation).
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Summary {
    /// by call id: the direct target, 0 for an indirect call
    pub call_targets: Vec<u64>,
    /// `(call, argument, source, offset)`: a pointer passed to a call
    pub args: Vec<(u32, u8, Src, i32)>,
    /// `(target, mask)`: the arguments a direct call passes that are no pointer
    pub top_args: Vec<(u64, u8)>,
    /// `(call, argument, evidence)`: the class evidence of a stack object passed to a call
    pub stack_ev: Vec<(u32, u8, StackEv)>,
    /// `(call, argument, vtable)`: a vtable stored into the stack object first given to that
    /// call (an inlined destructor or constructor of it)
    pub made_vt: Vec<(u32, u8, u64)>,
    /// two stack objects (by the call first given each) that are one after a join
    pub made_alias: Vec<(Instance, Instance)>,
    /// `(source, offset, vtable)`: a vtable stored at `source + offset`
    pub vt_stores: Vec<(Src, i32, u64)>,
    /// `(source, offset, value source, value offset)`: a pointer stored into a field
    pub field_stores: Vec<(Src, i32, Src, i32)>,
    /// `(source, offset, size)`: bytes written with something else than a pointer
    /// `field_stores` names (a stack address, a value not followed, a constant other than 0
    /// and a vtable, a narrower or wider store)
    pub field_clobbers: Vec<(Src, i32, i32)>,
    /// `(source, offset, size)`: the clobbers that write no pointer at all (WS95: a store
    /// narrower than 8 bytes, a number, arithmetic on memory) — they make a field's class unknown
    pub field_numbers: Vec<(Src, i32, i32)>,
    /// `(call, argument, k, value)`: the 8 bytes at `+k` of a stack object passed to a call,
    /// at that call (WS94: the fields of the objects callers pass)
    pub stack_fields: Vec<(u32, u8, i32, FieldVal)>,
    /// `(call, argument, source)`: a pointer into the buffer `source` points into passed to a
    /// call (WS95; it is also in `top_args`: no pointer of a class)
    pub elem_args: Vec<(u32, u8, Src)>,
    /// `(destination, source)`: the elements of the buffer `source` points into are copied into
    /// the buffer `destination` points into (`memcpy`, `realloc`; WS95)
    pub buf_copies: Vec<(Src, Src)>,
    /// the buffers an import writes data into (`read(fd, p, n)`: the one `p` points into; WS95)
    pub buf_writes: Vec<Src>,
    /// `(source, offset)`: a pointer `source + offset` given to unknown code (an import not known,
    /// an indirect call — not the object of a virtual call; WS95): the buffer it points into
    /// and the buffer the pointer at `source + offset` points into may get anything
    pub buf_escapes: Vec<(Src, i32)>,
    /// the pointers returned in `rax`
    pub rets: Vec<(Src, i32)>,
    /// a `ret` returns something else
    pub ret_unknown: bool,
    /// `loads[l] = (source, offset)`: `Ld(l)` is the value at `source + offset`
    pub loads: Vec<(Src, i32)>,
    /// addresses taken in code (`lea r, [rip + x]`, `mov r, imm`)
    pub refs: Vec<u64>,
    /// the objects `Src::Obj(i)` names (WS95: brought in by the callees' effects)
    pub objs: Vec<crate::effects::ObjRef>,
}

impl Summary {
    /// Every `ret` returns the first argument: a struct returned in memory (`this` is next).
    pub fn returns_first(&self) -> bool {
        !self.ret_unknown && !self.rets.is_empty() && self.rets.iter().all(|&r| r == (Src::Arg(0), 0))
    }
}

#[derive(Clone, PartialEq, Debug)]
struct St {
    r: [Val; 16],
    slots: SmallVec<[(i32, Val); 8]>,
}

impl St {
    fn entry() -> St {
        let mut r = [Val::Unk; 16];
        for (i, &a) in ARG_REGS.iter().enumerate() {
            r[a] = Val::Ptr(Src::Arg(i as u8), 0);
        }
        r[RSP] = Val::Ptr(Src::Stack, 0);
        St { r, slots: SmallVec::new() }
    }

    fn unknown() -> St {
        St { r: [Val::Unk; 16], slots: SmallVec::new() }
    }

    /// `self ∧= o`; whether `self` changed.
    fn meet(&mut self, o: &St) -> bool {
        self.meet_objects(o, &mut Vec::new())
    }

    /// [`St::meet`]; two objects a slot holds on two paths (two markers) are one object after
    /// the join: the slot keeps the first marker and `aliases` gets the pair.
    fn meet_objects(&mut self, o: &St, aliases: &mut Vec<(Instance, Instance)>) -> bool {
        let mut changed = false;
        for (a, b) in self.r.iter_mut().zip(o.r.iter()) {
            if *a != *b && *a != Val::Unk {
                // (two pointers into one buffer: an element of it)
                let m = match (*a, *b) {
                    (Val::Ptr(x, _) | Val::Elem(x), Val::Ptr(y, _) | Val::Elem(y)) if x == y && x != Src::Stack => Val::Elem(x),
                    _ => Val::Unk,
                };
                if *a != m {
                    *a = m;
                    changed = true;
                }
            }
        }
        let before = self.slots.clone();
        self.slots.retain(|s| match (s.1, o.slot_raw(s.0)) {
            (Val::Made(a, i), Val::Made(b, j)) if (a, i) != (b, j) => {
                let pair = ((a, i).min((b, j)), (a, i).max((b, j)));
                if !aliases.contains(&pair) {
                    aliases.push(pair);
                }
                s.1 = Val::Made(pair.0 .0, pair.0 .1);
                true
            }
            (x, y) => {
                if !o.slots.iter().any(|t| t.0 == s.0) {
                    return false;
                }
                match (x, y) {
                    _ if x == y => true,
                    (Val::Ptr(a, _) | Val::Elem(a), Val::Ptr(b, _) | Val::Elem(b)) if a == b && a != Src::Stack => {
                        s.1 = Val::Elem(a);
                        true
                    }
                    _ => false,
                }
            }
        });
        changed | (self.slots != before)
    }

    /// The value in the stack slot at `off` (a marker is no value).
    fn slot(&self, off: i32) -> Val {
        match self.slot_raw(off) {
            Val::Made(..) => Val::Unk,
            v => v,
        }
    }

    fn slot_raw(&self, off: i32) -> Val {
        self.slots.iter().find(|s| s.0 == off).map_or(Val::Unk, |s| s.1)
    }

    /// A store of `size` bytes at stack offset `off`.
    fn store_slot(&mut self, off: i32, size: u32, v: Val) {
        let end = i64::from(off) + i64::from(size.max(1));
        self.slots.retain(|s| i64::from(s.0) + 8 <= i64::from(off) || i64::from(s.0) >= end);
        if size == 8 && v != Val::Unk {
            if self.slots.len() >= MAX_SLOTS {
                self.slots.remove(0);
            }
            self.slots.push((off, v));
        }
    }
}

fn gpr(r: Register) -> Option<usize> {
    let f = r.full_register();
    f.is_gpr64().then(|| f as usize - Register::RAX as usize)
}

fn add(v: Val, k: i64) -> Val {
    match v {
        Val::Ptr(s, o) => i32::try_from(i64::from(o) + k).map_or(Val::Unk, |o| Val::Ptr(s, o)),
        Val::Const(c) => Val::Const(c.wrapping_add(k as u64)),
        Val::Elem(s) => Val::Elem(s),
        Val::Unk | Val::Made(..) => Val::Unk,
    }
}

/// The interpretation of one function's instructions (see [`summarize`]).
struct Interp<'a> {
    vt_points: &'a FxHashSet<u64>,
    env: &'a Env<'a>,
    loads: FxHashMap<(Src, i32), u32>,
    out: Summary,
    info: InstructionInfoFactory,
    /// states after calls and at indirect jumps (the entry of the blocks no jump reaches)
    fallback: Option<St>,
}

impl Interp<'_> {
    fn addr(&self, st: &St, i: &Instruction) -> Val {
        if matches!(i.segment_prefix(), Register::FS | Register::GS) {
            return Val::Unk;
        }
        let base = i.memory_base();
        if i.memory_index() != Register::None {
            // (WS95: an indexed address into a buffer is an element of it; the pointer may be the
            // index register, scaled by 1)
            let reg = |r: Register| gpr(r).filter(|_| r.is_gpr64()).map(|g| st.r[g]);
            let index = (i.memory_index_scale() == 1).then(|| reg(i.memory_index())).flatten();
            return match (reg(base), index) {
                (Some(Val::Ptr(s, _) | Val::Elem(s)), _) | (_, Some(Val::Ptr(s, _) | Val::Elem(s))) if s != Src::Stack => Val::Elem(s),
                _ => Val::Unk,
            };
        }
        if base == Register::RIP {
            return Val::Const(i.ip_rel_memory_address());
        }
        let disp = i.memory_displacement64() as i64;
        match base {
            Register::None => Val::Const(disp as u64),
            b => match gpr(b) {
                Some(g) if b.is_gpr64() => add(st.r[g], disp),
                _ => Val::Unk,
            },
        }
    }

    fn load(&mut self, st: &St, a: Val) -> Val {
        let a = match a {
            Val::Elem(src) => Val::Ptr(src, ELEM),
            a => a,
        };
        match a {
            Val::Ptr(Src::Stack, s) => st.slot(s),
            Val::Ptr(src, k) => {
                let n = self.loads.len() as u32;
                if let Some(&l) = self.loads.get(&(src, k)) {
                    return Val::Ptr(Src::Ld(l), 0);
                }
                if self.loads.len() >= MAX_LOADS {
                    return Val::Unk;
                }
                self.loads.insert((src, k), n);
                self.out.loads.push((src, k));
                Val::Ptr(Src::Ld(n), 0)
            }
            _ => Val::Unk,
        }
    }

    fn store(&mut self, st: &mut St, a: Val, size: u32, v: Val, emit: bool) {
        let a = match a {
            Val::Elem(src) => Val::Ptr(src, ELEM),
            a => a,
        };
        match a {
            Val::Ptr(Src::Stack, s) => {
                if emit
                    && size == 8
                    && let (Val::Made(c, j), Val::Const(vt)) = (st.slot_raw(s), v)
                    && self.vt_points.contains(&vt)
                {
                    self.out.made_vt.push((c, j, vt));
                }
                st.store_slot(s, size, v);
                if emit && size == 8
                    && let Val::Const(c) = v
                    && self.vt_points.contains(&c)
                {
                    self.out.vt_stores.push((Src::Stack, s, c));
                }
            }
            Val::Ptr(src, k) if emit => match v {
                Val::Const(c) if size == 8 && self.vt_points.contains(&c) => self.out.vt_stores.push((src, k, c)),
                Val::Ptr(vs, vo) if size == 8 && vs != Src::Stack => self.out.field_stores.push((src, k, vs, vo)),
                // (WS95: a pointer into a buffer)
                Val::Elem(vs) if size == 8 => self.out.field_stores.push((src, k, vs, ELEM)),
                Val::Const(0) if size == 8 => {}
                _ => {
                    self.out.field_clobbers.push((src, k, size.max(1) as i32));
                    // (WS95: no pointer at all: a narrower store, a number)
                    if size < 8 || matches!(v, Val::Const(_)) {
                        self.out.field_numbers.push((src, k, size.max(1) as i32));
                    }
                }
            },
            _ => {}
        }
    }

    fn fallback_with(&mut self, st: &St) {
        match &mut self.fallback {
            Some(f) => {
                f.meet(st);
            }
            None => self.fallback = Some(st.clone()),
        }
    }

    /// What the stack slot at `s` says of the object there (see [`StackEv`]).
    fn stack_ev(&self, st: &St, s: i32) -> Option<StackEv> {
        match st.slot_raw(s) {
            Val::Const(c) if self.vt_points.contains(&c) => Some(StackEv::Vtable(c)),
            Val::Made(c, j) => Some(StackEv::Made(c, j)),
            _ => None,
        }
    }

    /// The arguments of call `id` to `target` (0: indirect).
    fn call_args(&mut self, st: &St, id: u32, target: u64) {
        let mut mask = 0u8;
        for (j, &a) in ARG_REGS.iter().enumerate() {
            match st.r[a] {
                Val::Ptr(s, k) => {
                    self.out.args.push((id, j as u8, s, k));
                    if s == Src::Stack {
                        if let Some(e) = self.stack_ev(st, k) {
                            self.out.stack_ev.push((id, j as u8, e));
                        }
                        for &(off, v) in &st.slots {
                            let f = off.wrapping_sub(k);
                            if !(0..MAX_STACK_FIELD).contains(&f) {
                                continue;
                            }
                            let fv = match v {
                                Val::Ptr(Src::Stack, s2) => self.stack_ev(st, s2).map(FieldVal::Obj),
                                Val::Ptr(src, o) => Some(FieldVal::Ptr(src, o)),
                                Val::Elem(src) => Some(FieldVal::Elem(src)),
                                _ => None,
                            };
                            if let Some(fv) = fv {
                                self.out.stack_fields.push((id, j as u8, f, fv));
                            }
                        }
                    }
                }
                Val::Const(0) => {}
                v => {
                    mask |= 1 << j;
                    if let Val::Elem(s) = v {
                        self.out.elem_args.push((id, j as u8, s));
                    }
                }
            }
        }
        if target != 0 && mask != 0 {
            self.out.top_args.push((target, mask));
        }
    }

    /// What call `id` to `target` (0: indirect, through `i`) does to the buffers its pointer
    /// arguments reach (WS95): a function of the binary's says it in its own summary (composed
    /// later); an import by its kind; unknown code may write anything there.
    fn call_effects(&mut self, st: &St, id: u32, target: u64, i: &Instruction) {
        let kind = if target != 0 {
            match self.env.imports.get(&target) {
                Some(&k) => k,
                None if self.env.functions.is_none_or(|f| f.binary_search(&target).is_ok()) => return,
                None => ImportKind::Escape,
            }
        } else {
            ImportKind::Escape
        };
        let ptr = |j: usize| match st.r[ARG_REGS[j]] {
            Val::Ptr(s, k) if s != Src::Stack => Some((s, k)),
            Val::Elem(s) => Some((s, ELEM)),
            _ => None,
        };
        match kind {
            ImportKind::Pure => {}
            ImportKind::Copy => match (ptr(0), ptr(1)) {
                (Some(d), Some(s)) => self.out.buf_copies.push((d.0, s.0)),
                (Some(d), None) => self.out.buf_writes.push(d.0),
                _ => {}
            },
            ImportKind::Realloc => {
                if let Some(s) = ptr(0) {
                    self.out.buf_copies.push((Src::Ret(id), s.0));
                }
            }
            ImportKind::Memset => {
                if st.r[ARG_REGS[1]] != Val::Const(0)
                    && let Some(d) = ptr(0)
                {
                    self.out.buf_writes.push(d.0);
                }
            }
            ImportKind::WritesArgs => {
                for j in 0..6 {
                    if let Some(p) = ptr(j) {
                        self.out.buf_writes.push(p.0);
                    }
                }
            }
            ImportKind::Escape => {
                // (the object of a virtual call: its class's methods say what they do to it)
                let receiver = target == 0 && self.virtual_receiver(st, i);
                for j in usize::from(receiver)..6 {
                    if let Some(p) = ptr(j) {
                        self.out.buf_escapes.push(p);
                    }
                }
            }
        }
    }

    /// Whether the indirect call `i` calls a slot of the vtable of the object in `rdi`
    /// (`call [vt + k]` / `call r` with `r = [vt + k]`, `vt = [rdi]`).
    fn virtual_receiver(&self, st: &St, i: &Instruction) -> bool {
        let slot = match i.op0_kind() {
            OpKind::Memory => match self.addr(st, i) {
                Val::Ptr(Src::Ld(vt), _) => Some(vt),
                _ => None,
            },
            OpKind::Register => match gpr(i.op0_register()).map(|g| st.r[g]) {
                Some(Val::Ptr(Src::Ld(f), 0)) => match self.out.loads.get(f as usize) {
                    Some(&(Src::Ld(vt), _)) => Some(vt),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        };
        let Some(vt) = slot else { return false };
        matches!(self.out.loads.get(vt as usize), Some(&(obj, 0)) if st.r[ARG_REGS[0]] == Val::Ptr(obj, 0))
    }

    /// One instruction; `call_id` names a call / tail jump, `outside` says a branch leaves
    /// the function.
    fn step(&mut self, st: &mut St, i: &Instruction, call_id: Option<u32>, emit: bool, inside: &dyn Fn(u64) -> bool) {
        let op0 = || (i.op_count() > 0).then(|| i.op0_kind());
        let reg64 = |r: Register| r.is_gpr64();
        match i.mnemonic() {
            Mnemonic::Mov if i.op_count() == 2 => {
                match (i.op0_kind(), i.op1_kind()) {
                    (OpKind::Register, OpKind::Register) => {
                        let (d, s) = (i.op0_register(), i.op1_register());
                        if let Some(g) = gpr(d) {
                            st.r[g] = if reg64(d) && reg64(s) { gpr(s).map_or(Val::Unk, |x| st.r[x]) } else { Val::Unk };
                        }
                    }
                    (OpKind::Register, OpKind::Memory) => {
                        let d = i.op0_register();
                        if let Some(g) = gpr(d) {
                            st.r[g] = if reg64(d) {
                                let a = self.addr(st, i);
                                self.load(st, a)
                            } else {
                                Val::Unk
                            };
                        }
                    }
                    (OpKind::Register, _) => {
                        let d = i.op0_register();
                        if let Some(g) = gpr(d) {
                            st.r[g] = match d.size() {
                                8 => Val::Const(i.immediate(1)),
                                4 => Val::Const(i.immediate(1) & 0xffff_ffff),
                                _ => Val::Unk,
                            };
                            if emit && let Val::Const(c) = st.r[g] {
                                self.out.refs.push(c);
                            }
                        }
                    }
                    (OpKind::Memory, OpKind::Register) => {
                        let s = i.op1_register();
                        let a = self.addr(st, i);
                        let v = if reg64(s) { gpr(s).map_or(Val::Unk, |x| st.r[x]) } else { Val::Unk };
                        self.store(st, a, s.size() as u32, v, emit);
                    }
                    (OpKind::Memory, _) => {
                        let a = self.addr(st, i);
                        let size = i.memory_size().size() as u32;
                        let v = if size == 8 { Val::Const(i.immediate(1)) } else { Val::Unk };
                        self.store(st, a, size, v, emit);
                    }
                    _ => self.generic(st, i, emit),
                }
            }
            Mnemonic::Lea => {
                let d = i.op0_register();
                if let Some(g) = gpr(d) {
                    st.r[g] = if reg64(d) { self.addr(st, i) } else { Val::Unk };
                    if emit && i.memory_base() == Register::RIP {
                        self.out.refs.push(i.ip_rel_memory_address());
                    }
                }
            }
            Mnemonic::Add | Mnemonic::Sub if op0() == Some(OpKind::Register) && reg64(i.op0_register()) && matches!(i.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate8 | OpKind::Immediate32) => {
                let g = gpr(i.op0_register()).expect("gpr64");
                let k = i.immediate(1) as i64;
                st.r[g] = add(st.r[g], if i.mnemonic() == Mnemonic::Sub { k.wrapping_neg() } else { k });
            }
            Mnemonic::Xor | Mnemonic::Sub if i.op_count() == 2 && i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register && i.op0_register() == i.op1_register() => {
                if let Some(g) = gpr(i.op0_register()) {
                    st.r[g] = if i.op0_register().size() >= 4 { Val::Const(0) } else { Val::Unk };
                }
            }
            // (WS95) a pointer plus / minus a number in a register: a pointer into its buffer
            Mnemonic::Add | Mnemonic::Sub if i.op_count() == 2 && i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register && reg64(i.op0_register()) && reg64(i.op1_register()) => {
                let (d, s) = (gpr(i.op0_register()).expect("gpr64"), gpr(i.op1_register()).expect("gpr64"));
                let into = |v: Val| match v {
                    Val::Ptr(x, _) | Val::Elem(x) if x != Src::Stack => Some(x),
                    _ => None,
                };
                let number = |v: Val| matches!(v, Val::Unk | Val::Const(_));
                st.r[d] = match (st.r[d], st.r[s]) {
                    (a, b) if number(b) && into(a).is_some() => Val::Elem(into(a).expect("pointer")),
                    (a, b) if i.mnemonic() == Mnemonic::Add && number(a) && into(b).is_some() => Val::Elem(into(b).expect("pointer")),
                    _ => Val::Unk,
                };
            }
            Mnemonic::Push if i.op_count() == 1 => {
                let v = match i.op0_kind() {
                    OpKind::Register if reg64(i.op0_register()) => gpr(i.op0_register()).map_or(Val::Unk, |g| st.r[g]),
                    OpKind::Immediate8to64 | OpKind::Immediate32to64 => Val::Const(i.immediate(0)),
                    _ => Val::Unk,
                };
                st.r[RSP] = add(st.r[RSP], -8);
                if let Val::Ptr(Src::Stack, s) = st.r[RSP] {
                    st.store_slot(s, 8, v);
                }
            }
            Mnemonic::Pop if i.op_count() == 1 && i.op0_kind() == OpKind::Register && reg64(i.op0_register()) && i.op0_register() != Register::RSP => {
                let v = match st.r[RSP] {
                    Val::Ptr(Src::Stack, s) => st.slot(s),
                    _ => Val::Unk,
                };
                st.r[RSP] = add(st.r[RSP], 8);
                st.r[gpr(i.op0_register()).expect("gpr64")] = v;
            }
            Mnemonic::Leave => {
                st.r[RSP] = st.r[RBP];
                st.r[RBP] = match st.r[RSP] {
                    Val::Ptr(Src::Stack, s) => st.slot(s),
                    _ => Val::Unk,
                };
                st.r[RSP] = add(st.r[RSP], 8);
            }
            Mnemonic::Call => {
                let id = call_id.unwrap_or(u32::MAX);
                let target = if i.op0_kind() == OpKind::NearBranch64 { i.near_branch64() } else { 0 };
                if emit && id != u32::MAX {
                    self.call_args(st, id, target);
                    self.call_effects(st, id, target, i);
                }
                // a stack object passed to the call may be written by it; it stays the object it
                // was (its vtable pointer, the call it was first given to), else this call made it
                let objects: SmallVec<[(i32, Val); 2]> = ARG_REGS
                    .iter()
                    .enumerate()
                    .filter_map(|(j, &a)| match st.r[a] {
                        Val::Ptr(Src::Stack, s) => Some((
                            s,
                            match self.stack_ev(st, s) {
                                Some(StackEv::Vtable(c)) => Val::Const(c),
                                Some(StackEv::Made(c, k)) => Val::Made(c, k),
                                None if id != u32::MAX => Val::Made(id, j as u8),
                                None => Val::Unk,
                            },
                        )),
                        _ => None,
                    })
                    .collect();
                // (what other objects in the frame are — a marker, a vtable pointer — stays)
                if let Some(low) = objects.iter().map(|o| o.0).min() {
                    let vt_points = self.vt_points;
                    st.slots.retain(|s| {
                        s.0 + 8 <= low
                            || (!objects.iter().any(|o| o.0 == s.0) && (matches!(s.1, Val::Made(..)) || matches!(s.1, Val::Const(c) if vt_points.contains(&c))))
                    });
                }
                for &(s, v) in objects.iter().rev() {
                    st.store_slot(s, 8, v);
                }
                for &c in &CALLER_SAVED {
                    st.r[c] = Val::Unk;
                }
                st.r[RAX] = if id != u32::MAX { Val::Ptr(Src::Ret(id), 0) } else { Val::Unk };
                let mut after = st.clone();
                after.r[RAX] = Val::Unk;
                after.r[2] = Val::Unk;
                self.fallback_with(&after);
            }
            Mnemonic::Ret => {
                if emit {
                    match st.r[RAX] {
                        Val::Ptr(s, k) if s != Src::Stack => self.out.rets.push((s, k)),
                        Val::Const(0) => {}
                        _ => self.out.ret_unknown = true,
                    }
                }
            }
            _ => match i.flow_control() {
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                    if i.op0_kind() == OpKind::NearBranch64 && !inside(i.near_branch64()) && emit {
                        // a tail call
                        if let Some(id) = call_id {
                            self.call_args(st, id, i.near_branch64());
                            self.call_effects(st, id, i.near_branch64(), i);
                        }
                    }
                }
                FlowControl::IndirectBranch => {
                    let s = st.clone();
                    self.fallback_with(&s);
                }
                _ => self.generic(st, i, emit),
            },
        }
    }

    /// Any other instruction: the registers it writes are unknown, the stack slots it writes
    /// are forgotten.
    fn generic(&mut self, st: &mut St, i: &Instruction, emit: bool) {
        let has_mem = (0..i.op_count()).any(|k| i.op_kind(k) == OpKind::Memory);
        let addr = if has_mem { self.addr(st, i) } else { Val::Unk };
        let info = self.info.info(i);
        for u in info.used_registers() {
            if matches!(u.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
                && let Some(g) = gpr(u.register())
            {
                st.r[g] = Val::Unk;
            }
        }
        let writes_memory = info
            .used_memory()
            .iter()
            .any(|m| matches!(m.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite) && m.base() != Register::RSP);
        if writes_memory {
            match addr {
                Val::Ptr(Src::Stack, s) => st.store_slot(s, i.memory_size().size().max(8) as u32, Val::Unk),
                Val::Ptr(_, _) | Val::Elem(_) if emit => {
                    let (src, k) = match addr {
                        Val::Ptr(src, k) => (src, k),
                        Val::Elem(src) => (src, ELEM),
                        _ => unreachable!(),
                    };
                    let n = i.memory_size().size().max(1);
                    self.out.field_clobbers.push((src, k, n as i32));
                    // (WS95: arithmetic on memory, a narrower write: no pointer; a wide copy,
                    // `cmpxchg`, `movq` may be pointers)
                    let arith = matches!(
                        i.mnemonic(),
                        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Inc | Mnemonic::Dec | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor | Mnemonic::Not | Mnemonic::Neg | Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar | Mnemonic::Adc | Mnemonic::Sbb | Mnemonic::Xadd | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc | Mnemonic::Rol | Mnemonic::Ror
                    );
                    if n < 8 || (n == 8 && arith) {
                        self.out.field_numbers.push((src, k, n as i32));
                    }
                }
                // a string store through `rdi` into the frame (`rep stosq`): the slots are not known
                _ if !has_mem && matches!(st.r[7], Val::Ptr(Src::Stack, _)) => st.slots.clear(),
                _ => {}
            }
        }
    }
}

/// The summary of the function at `[start, start + len)` (x86-64); `vt_points` are the vtable
/// address points of the binary.
pub fn summarize(mem: &Memory, start: u64, len: u64, vt_points: &FxHashSet<u64>) -> Summary {
    summarize_in(mem, start, len, &Env { vt_points, imports: &FxHashMap::default(), functions: None })
}

/// What a summary knows of the binary around the function (WS95).
pub struct Env<'a> {
    /// the vtable address points of the binary
    pub vt_points: &'a FxHashSet<u64>,
    /// the PLT stubs of the imports, by what they do
    pub imports: &'a FxHashMap<u64, ImportKind>,
    /// the functions of the binary (sorted); a direct call elsewhere is unknown code (`None`:
    /// every direct call is to a function of the binary)
    pub functions: Option<&'a [u64]>,
}

/// [`summarize`] in `env`.
pub fn summarize_in(mem: &Memory, start: u64, len: u64, env: &Env) -> Summary {
    let vt_points = env.vt_points;
    let Some(block) = mem.find_block(start) else { return Summary::default() };
    let Some(data) = block.data.as_ref() else { return Summary::default() };
    let from = (start - block.start) as usize;
    let to = (from as u64 + len).min(data.len() as u64) as usize;
    if from >= to {
        return Summary::default();
    }
    let end = start + (to - from) as u64;
    let mut dec = Decoder::with_ip(64, &data[from..to], start, DecoderOptions::NONE);
    let mut insns: Vec<Instruction> = Vec::new();
    while dec.can_decode() && insns.len() < MAX_INSNS {
        let i = dec.decode();
        if i.is_invalid() {
            break;
        }
        insns.push(i);
    }
    if insns.is_empty() {
        return Summary::default();
    }
    let inside = |a: u64| a >= start && a < end;
    let index_of = |a: u64| insns.binary_search_by_key(&a, |i| i.ip()).ok();

    // call ids: every call, then every branch out of the function (a tail call)
    let mut call_id: Vec<Option<u32>> = vec![None; insns.len()];
    let mut n = 0u32;
    for (k, i) in insns.iter().enumerate() {
        if matches!(i.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            call_id[k] = Some(n);
            n += 1;
        }
    }
    let mut targets: Vec<u64> = insns
        .iter()
        .zip(&call_id)
        .filter(|(_, c)| c.is_some())
        .map(|(i, _)| if i.op0_kind() == OpKind::NearBranch64 { i.near_branch64() } else { 0 })
        .collect();
    for (k, i) in insns.iter().enumerate() {
        if matches!(i.flow_control(), FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch)
            && i.op0_kind() == OpKind::NearBranch64
            && !inside(i.near_branch64())
        {
            call_id[k] = Some(n);
            targets.push(i.near_branch64());
            n += 1;
        }
    }

    // basic blocks
    let mut leader = vec![false; insns.len()];
    leader[0] = true;
    for (k, i) in insns.iter().enumerate() {
        match i.flow_control() {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                if i.op0_kind() == OpKind::NearBranch64
                    && let Some(t) = index_of(i.near_branch64())
                {
                    leader[t] = true;
                }
                if k + 1 < insns.len() {
                    leader[k + 1] = true;
                }
            }
            FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception
                if k + 1 < insns.len() =>
            {
                leader[k + 1] = true;
            }
            _ => {}
        }
    }
    let starts: Vec<usize> = (0..insns.len()).filter(|&k| leader[k]).collect();
    let block_of = |k: usize| starts.partition_point(|&s| s <= k) - 1;
    let nb = starts.len();
    let block_end = |b: usize| if b + 1 < nb { starts[b + 1] } else { insns.len() };
    let succs = |b: usize| -> SmallVec<[usize; 2]> {
        let last = &insns[block_end(b) - 1];
        let mut s = SmallVec::new();
        let next = (block_end(b) < insns.len()).then(|| b + 1);
        match last.flow_control() {
            FlowControl::UnconditionalBranch => {
                if last.op0_kind() == OpKind::NearBranch64
                    && let Some(t) = index_of(last.near_branch64())
                {
                    s.push(block_of(t));
                }
            }
            FlowControl::ConditionalBranch => {
                if last.op0_kind() == OpKind::NearBranch64
                    && let Some(t) = index_of(last.near_branch64())
                {
                    s.push(block_of(t));
                }
                s.extend(next);
            }
            FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => {}
            _ => s.extend(next),
        }
        s
    };

    let mut it = Interp { vt_points, env, loads: FxHashMap::default(), out: Summary::default(), info: InstructionInfoFactory::new(), fallback: None };
    let mut states: Vec<Option<St>> = vec![None; nb];
    states[0] = Some(St::entry());
    let mut work: Vec<usize> = vec![0];
    let mut queued = vec![false; nb];
    queued[0] = true;
    for _round in 0..8 {
        let mut steps = 0usize;
        while let Some(b) = work.pop() {
            queued[b] = false;
            steps += 1;
            if steps > nb * 24 + 64 {
                break;
            }
            let Some(mut st) = states[b].clone() else { continue };
            for k in starts[b]..block_end(b) {
                it.step(&mut st, &insns[k], call_id[k], false, &inside);
            }
            for s in succs(b) {
                let changed = match &mut states[s] {
                    Some(old) => old.meet_objects(&st, &mut it.out.made_alias),
                    None => {
                        states[s] = Some(st.clone());
                        true
                    }
                };
                if changed && !queued[s] {
                    queued[s] = true;
                    work.push(s);
                }
            }
        }
        // blocks no jump reaches: from the states after calls / at indirect jumps
        let unreached: Vec<usize> = (0..nb).filter(|&b| states[b].is_none()).collect();
        if unreached.is_empty() {
            break;
        }
        let fb = it.fallback.clone().unwrap_or_else(St::unknown);
        for b in unreached {
            states[b] = Some(fb.clone());
            queued[b] = true;
            work.push(b);
        }
    }
    // the facts, from the states found
    it.out.call_targets = targets;
    for b in 0..nb {
        let mut st = states[b].clone().unwrap_or_else(St::unknown);
        for k in starts[b]..block_end(b) {
            it.step(&mut st, &insns[k], call_id[k], true, &inside);
        }
    }
    let mut out = it.out;
    out.refs.retain(|&r| r != 0);
    out.refs.sort_unstable();
    out.refs.dedup();
    out
}

/// The polymorphic classes of a binary, from its RTTI.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Hierarchy {
    /// class -> its primary vtable (address point)
    pub vtables: Vec<u64>,
    /// class -> its bases at offset 0 (transitively; not itself): a pointer to an object is a
    /// pointer to each of them
    pub bases: Vec<Vec<u32>>,
}

impl Hierarchy {
    fn derives(&self, a: u32, b: u32) -> bool {
        a == b || self.bases[a as usize].contains(&b)
    }

    /// The nearest common base of two classes (one of them when it is a base of the other).
    pub fn join(&self, a: u32, b: u32) -> Option<u32> {
        if self.derives(a, b) {
            return Some(b);
        }
        if self.derives(b, a) {
            return Some(a);
        }
        let common: Vec<u32> = self.bases[a as usize].iter().copied().filter(|c| self.bases[b as usize].contains(c)).collect();
        common.iter().copied().find(|&c| common.iter().all(|&o| self.derives(c, o)))
    }

    /// The class deriving from all of `cs` (`None` when no one does).
    pub fn most_derived(&self, cs: &[u32]) -> Option<u32> {
        cs.iter().copied().find(|&c| cs.iter().all(|&o| self.derives(c, o)))
    }
}

/// The lattice of the propagation: nothing known yet, unknown (any class), or a class.
const BOT: u32 = 0;
const TOP: u32 = 1;
fn cls(c: u32) -> u32 {
    c + 2
}

/// The index of one binary (see the module documentation).
#[derive(Default, Debug, Clone, PartialEq)]
pub struct ThisIndex {
    pub hierarchy: Hierarchy,
    /// function -> the class of each integer parameter its callers give it (`u32::MAX`: not
    /// known) — not the classes a vtable listing the function or a vtable it stores into its
    /// argument gives (the decompiler finds those itself)
    pub params: FxHashMap<u64, [u32; 6]>,
    /// function -> the class of the pointer it returns
    pub rets: FxHashMap<u64, u32>,
    /// `(container class, offset)` -> the class of the pointer stored there (lattice value:
    /// class + 2)
    pub fields: FxHashMap<(u32, i32), u32>,
    /// `(container class, offset)` -> the class of the member object embedded there (class + 2)
    pub members: FxHashMap<(u32, i32), u32>,
    /// `(function, parameter, k)` -> the class of the pointer at `+k` of the object every caller
    /// passes as that parameter (WS94)
    pub param_fields: FxHashMap<(u64, u8, i32), u32>,
    /// `(container class, begin offset)` -> the class of the pointers in the buffer (an array /
    /// a vector) whose begin pointer is at that offset of the class (class + 2; WS95)
    pub elements: FxHashMap<(u32, i32), u32>,
    pub stats: IndexStats,
}

/// How the index was built.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct IndexStats {
    pub functions: u64,
    pub classes: u64,
    pub rounds: u64,
    pub converged: bool,
    /// functions whose `this` class a vtable gives (listing it, or stored into `this`)
    pub seeded_this: u64,
    pub summarize_ms: u64,
    pub solve_ms: u64,
    /// WS95: composing the effect summaries
    pub compose_ms: u64,
}

impl ThisIndex {
    fn vt(&self, c: u32) -> Option<u64> {
        (c != u32::MAX).then(|| self.hierarchy.vtables.get(c as usize).copied()).flatten()
    }

    /// The class (primary vtable) of integer parameter `i` of `f`.
    pub fn param_class(&self, f: u64, i: usize) -> Option<u64> {
        self.params.get(&f).and_then(|p| self.vt(*p.get(i)?))
    }

    /// The class (primary vtable) of the pointer at `+k` of the object the callers of `f` pass
    /// as integer parameter `i` (WS94: what every caller put there).
    pub fn param_field_class(&self, f: u64, i: usize, k: i64) -> Option<u64> {
        let key = (f, u8::try_from(i).ok()?, i32::try_from(k).ok()?);
        self.param_fields.get(&key).and_then(|&c| self.vt(c))
    }

    /// The class (primary vtable) of the pointer `f` returns.
    pub fn ret_class(&self, f: u64) -> Option<u64> {
        self.rets.get(&f).and_then(|&c| self.vt(c))
    }

    fn class_of_vtable(&self, vt: u64) -> Option<u32> {
        self.hierarchy.vtables.iter().position(|&v| v == vt).map(|c| c as u32)
    }

    /// The class (primary vtable) of the pointer stored at offset `off` of objects of the class
    /// whose primary vtable is `vt`: the join of what the functions of that class and of its
    /// bases store there.
    pub fn field_class(&self, vt: u64, off: i64) -> Option<u64> {
        let c = self.class_of_vtable(vt)?;
        let off = i32::try_from(off).ok()?;
        let l = lookup(&self.hierarchy, &self.fields, c, off);
        (l >= 2).then(|| self.vt(l - 2)).flatten()
    }

    /// The class (primary vtable) of the pointers in the buffer whose begin pointer is at offset
    /// `off` of objects of the class whose primary vtable is `vt` (WS95): the join of what the
    /// functions of that class and of its bases store into it.
    pub fn element_class(&self, vt: u64, off: i64) -> Option<u64> {
        let c = self.class_of_vtable(vt)?;
        let off = i32::try_from(off).ok()?;
        let l = lookup(&self.hierarchy, &self.elements, c, off);
        (l >= 2).then(|| self.vt(l - 2)).flatten()
    }

    /// The fields and member objects of known class of the class whose primary vtable is `vt`
    /// (its own and its bases'): `(offset, class vtable, member)` by offset.
    pub fn class_fields(&self, vt: u64) -> Vec<(i32, u64, bool)> {
        let Some(c) = self.class_of_vtable(vt) else { return Vec::new() };
        let mut offs: Vec<(i32, bool)> = Vec::new();
        for k in std::iter::once(c).chain(self.hierarchy.bases[c as usize].iter().copied()) {
            offs.extend(self.fields.keys().filter(|f| f.0 == k).map(|f| (f.1, false)));
            offs.extend(self.members.keys().filter(|f| f.0 == k).map(|f| (f.1, true)));
        }
        offs.sort_unstable();
        offs.dedup();
        offs.into_iter()
            .filter_map(|(off, m)| {
                let l = lookup(&self.hierarchy, if m { &self.members } else { &self.fields }, c, off);
                Some((off, self.vt((l >= 2).then(|| l - 2)?)?, m))
            })
            .collect()
    }

    /// The element classes of the class whose primary vtable is `vt` (its own and its bases'):
    /// `(begin offset, element class vtable)` by offset (WS95).
    pub fn class_elements(&self, vt: u64) -> Vec<(i32, u64)> {
        let Some(c) = self.class_of_vtable(vt) else { return Vec::new() };
        let mut offs: Vec<i32> = std::iter::once(c)
            .chain(self.hierarchy.bases[c as usize].iter().copied())
            .flat_map(|k| self.elements.keys().filter(move |f| f.0 == k).map(|f| f.1))
            .collect();
        offs.sort_unstable();
        offs.dedup();
        offs.into_iter()
            .filter_map(|off| {
                let l = lookup(&self.hierarchy, &self.elements, c, off);
                Some((off, self.vt((l >= 2).then(|| l - 2)?)?))
            })
            .collect()
    }

    /// The number of functions whose parameter `i` has a class from the callers.
    pub fn count_known(&self, i: usize) -> usize {
        self.params.values().filter(|p| p[i] != u32::MAX).count()
    }
}

/// The class at `(c, off)` in `map`, joined over `c` and its bases.
fn lookup(h: &Hierarchy, map: &FxHashMap<(u32, i32), u32>, c: u32, off: i32) -> u32 {
    let mut out = BOT;
    for k in std::iter::once(c).chain(h.bases[c as usize].iter().copied()) {
        if let Some(&v) = map.get(&(k, off)) {
            out = join(h, out, v);
        }
    }
    out
}

fn join(h: &Hierarchy, a: u32, b: u32) -> u32 {
    match (a, b) {
        (BOT, x) | (x, BOT) => x,
        (TOP, _) | (_, TOP) => TOP,
        (x, y) if x == y => x,
        (x, y) => h.join(x - 2, y - 2).map_or(TOP, cls),
    }
}

/// Pointer words of the data: `(address, value)` in address order — the relative relocations
/// of a PIE, else the aligned words of the non-executable blocks that point into code.
fn pointer_words(mem: &Memory) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    if let Some(t) = mem.dynamic_relocations() {
        // (not the GOT: a slot bound to a function is no reference to it in data)
        let got: Vec<(u64, u64)> = mem.blocks().filter(|b| b.name.starts_with(".got")).map(|b| (b.start, b.start + b.size)).collect();
        for e in t.chunks_exact(24) {
            let w = |k: usize| u64::from_le_bytes(e[k * 8..k * 8 + 8].try_into().expect("8 bytes"));
            let ty = w(1) & 0xffff_ffff;
            if (ty == 8 || ty == 1027) && !got.iter().any(|&(s, e)| (s..e).contains(&w(0))) {
                out.push((w(0), w(2)));
            }
        }
    } else {
        for b in mem.blocks().filter(|b| !b.flags.contains(MemoryFlags::EXECUTE)) {
            let Some(data) = &b.data else { continue };
            let skip = ((8 - b.start % 8) % 8) as usize;
            for (k, w) in data.get(skip..).unwrap_or(&[]).chunks_exact(8).enumerate() {
                let v = u64::from_le_bytes(w.try_into().expect("8 bytes"));
                if v != 0 && crate::vcall::is_code(mem, v) {
                    out.push((b.start + skip as u64 + k as u64 * 8, v));
                }
            }
        }
    }
    out.sort_unstable();
    out
}

/// The vtables of the binary: `(address point, offset-to-top, type_info, slots)`.
fn vtables(mem: &Memory, words: &[(u64, u64)]) -> Vec<(u64, i64, u64, Vec<u64>)> {
    let exec: Vec<(u64, u64)> = mem.blocks().filter(|b| b.flags.contains(MemoryFlags::EXECUTE)).map(|b| (b.start, b.start + b.size)).collect();
    let is_code = |a: u64| exec.iter().any(|&(s, e)| a >= s && a < e);
    let mut ti_ok: FxHashMap<u64, bool> = FxHashMap::default();
    let mut out = Vec::new();
    let mut k = 1;
    while k < words.len() {
        let (p, f) = words[k];
        let (q, ti) = words[k - 1];
        if q + 8 != p || !is_code(f) || is_code(ti) {
            k += 1;
            continue;
        }
        let ok = *ti_ok.entry(ti).or_insert_with(|| crate::vcall::type_info_name(mem, ti).is_some());
        let ott = mem.read_u64(p - 16).ok().map(|v| v as i64).filter(|o| (-0x10_0000..=0).contains(o));
        let (true, Some(ott)) = (ok, ott) else {
            k += 1;
            continue;
        };
        let mut slots = Vec::new();
        let mut j = k;
        while j < words.len() && words[j].0 == p + 8 * (j - k) as u64 && is_code(words[j].1) {
            slots.push(words[j].1);
            j += 1;
        }
        out.push((p, ott, ti, slots));
        k = j.max(k + 1);
    }
    out
}

/// What [`solve`] needs to know about the binary.
pub struct Universe {
    pub hierarchy: Hierarchy,
    /// every vtable address point (primary or not)
    pub vt_points: FxHashSet<u64>,
    /// a vtable address point -> its class, when it is a primary vtable
    pub primary: FxHashMap<u64, u32>,
    /// a function -> the primary vtables listing it (classes)
    pub listing: FxHashMap<u64, Vec<u32>>,
    /// functions whose address is in data (not a vtable slot) or in a non-primary vtable only
    pub taken: FxHashSet<u64>,
}

/// The classes, vtables and data references of a binary.
pub fn universe(mem: &Memory) -> Universe {
    let words = pointer_words(mem);
    let vts = vtables(mem, &words);
    let mut by_ti: FxHashMap<u64, u32> = FxHashMap::default();
    let mut hier = Hierarchy::default();
    let mut tis: Vec<u64> = Vec::new();
    for (p, ott, ti, _) in &vts {
        if *ott == 0 && !by_ti.contains_key(ti) {
            by_ti.insert(*ti, hier.vtables.len() as u32);
            hier.vtables.push(*p);
            tis.push(*ti);
        }
    }
    let direct: Vec<Vec<u64>> = tis.par_iter().map(|&ti| crate::vcall::type_info_bases(mem, ti)).collect();
    let direct_of: FxHashMap<u64, &Vec<u64>> = tis.iter().copied().zip(direct.iter()).collect();
    for &ti in &tis {
        let mut seen: Vec<u64> = Vec::new();
        let mut work: Vec<u64> = direct_of.get(&ti).map(|v| v.to_vec()).unwrap_or_else(|| crate::vcall::type_info_bases(mem, ti));
        while let Some(t) = work.pop() {
            if seen.contains(&t) || seen.len() > 64 {
                continue;
            }
            seen.push(t);
            match direct_of.get(&t) {
                Some(v) => work.extend(v.iter().copied()),
                None => work.extend(crate::vcall::type_info_bases(mem, t)),
            }
        }
        hier.bases.push(seen.iter().filter_map(|t| by_ti.get(t).copied()).collect());
    }
    let mut listing: FxHashMap<u64, Vec<u32>> = FxHashMap::default();
    let mut in_vtables: FxHashSet<u64> = FxHashSet::default();
    let mut slot_words: FxHashSet<u64> = FxHashSet::default();
    let mut primary: FxHashMap<u64, u32> = FxHashMap::default();
    for (p, ott, ti, slots) in &vts {
        for (s, &f) in slots.iter().enumerate() {
            slot_words.insert(p + 8 * s as u64);
            in_vtables.insert(f);
        }
        if *ott == 0
            && let Some(&c) = by_ti.get(ti)
        {
            primary.insert(*p, c);
            for &f in slots {
                let e = listing.entry(f).or_default();
                if !e.contains(&c) {
                    e.push(c);
                }
            }
        }
    }
    let mut taken: FxHashSet<u64> = words.iter().filter(|w| !slot_words.contains(&w.0)).map(|w| w.1).collect();
    taken.extend(in_vtables.into_iter().filter(|f| !listing.contains_key(f)));
    Universe { hierarchy: hier, vt_points: vts.iter().map(|v| v.0).collect(), primary, listing, taken }
}

/// The classes known in a round, to evaluate the values of one function.
struct Ctx<'a> {
    h: &'a Hierarchy,
    /// primary vtable -> class
    primary: &'a FxHashMap<u64, u32>,
    starts: &'a [u64],
    sums: &'a [Summary],
    evidence: &'a [FxHashMap<(Src, i32), u32>],
    stack: &'a [FxHashMap<(u32, u8), u32>],
    p: &'a [[u32; 6]],
    r: &'a [u32],
    fields: &'a FxHashMap<(u32, i32), u32>,
    members: &'a FxHashMap<(u32, i32), u32>,
    /// WS95: `(container class, begin offset)` -> the element class
    elements: &'a FxHashMap<(u32, i32), u32>,
    /// WS94: the parameters whose callers are not all known
    fixed: &'a [[bool; 6]],
    /// WS94: `(function, parameter, k)` -> the class of the pointer at `+k` of what the callers
    /// pass (the offsets demanded only)
    pf: &'a [u32],
    /// WS94: `(function, parameter, k)` -> its index in `pf`
    pf_at: &'a FxHashMap<FieldKey, u32>,
    /// WS94: per function, the pointers it stores into fields: `(source, offset)` -> values
    stores: &'a [StoresAt],
    /// WS94: per function, the class of the stack objects whose address a field of a stack
    /// object passed to a call holds: `(call, argument, k)`
    stack_objs: &'a [FxHashMap<FieldKey, u32>],
    /// WS94: per function, the pointers in the fields of the stack objects passed to calls
    stack_ptrs: &'a [StackPtrs],
}

impl Ctx<'_> {
    fn fidx(&self, a: u64) -> Option<usize> {
        self.starts.binary_search(&a).ok()
    }

    /// The class of the object `src` points to in function `k` (`ld`: of its loaded values).
    fn base(&self, k: usize, src: Src, ld: &[u32]) -> u32 {
        let ev = &self.evidence[k];
        match src {
            Src::Arg(i) => self.p[k][i as usize],
            Src::Stack => TOP,
            Src::Ret(c) => ev.get(&(src, 0)).copied().unwrap_or_else(|| match self.fidx(self.sums[k].call_targets[c as usize]) {
                Some(t) => self.r[t],
                None => TOP,
            }),
            Src::Ld(l) => ev.get(&(src, 0)).copied().unwrap_or(ld[l as usize]),
            Src::Obj(i) => match self.sums[k].objs[i as usize] {
                crate::effects::ObjRef::Vtable(vt) => self.primary.get(&vt).map_or(TOP, |&c| cls(c)),
                crate::effects::ObjRef::RetOf(f) => self.fidx(f).map_or(TOP, |t| self.r[t]),
            },
        }
    }

    /// The class of argument `j` of call `c` of function `k`, the object at `src + off`.
    fn arg_value(&self, k: usize, c: u32, j: u8, src: Src, off: i32, ld: &[u32]) -> u32 {
        match src {
            Src::Stack => self.stack[k].get(&(c, j)).copied().unwrap_or(TOP),
            _ => self.value(k, src, off, ld),
        }
    }

    /// The class of the object at `src + off` (a member object when `off` is not 0).
    fn value(&self, k: usize, src: Src, off: i32, ld: &[u32]) -> u32 {
        // (a pointer into a buffer, WS95: no object of a class)
        if src == Src::Stack || off == ELEM {
            return TOP;
        }
        let b = self.base(k, src, ld);
        if off == 0 || b < 2 {
            return b;
        }
        match lookup(self.h, self.members, b - 2, off) {
            BOT => TOP,
            m => m,
        }
    }

    /// The container class and begin offset of the buffer the pointer loaded by `loads[b]` of
    /// `k` points into (WS95): `loads[b] = (bs, bf)`, the begin pointer at `bf` (>= 0) of the
    /// object `bs` points to; or a vector's end pointer (`*end = x; end += 8`: begin 8 before).
    fn buffer(&self, k: usize, b: u32, ld: &[u32]) -> Option<(u32, i32)> {
        let s = &self.sums[k];
        let &(bs, bf) = s.loads.get(b as usize)?;
        if bf == ELEM {
            return None;
        }
        let begin = if bf >= 0 {
            bf
        } else {
            return None;
        };
        // (a vector's end pointer stored back one element on: the begin pointer is 8 before)
        let off = if begin >= 8 && s.field_stores.contains(&(bs, begin, Src::Ld(b), 8)) { begin - 8 } else { begin };
        let c = self.base(k, bs, ld);
        (c >= 2).then_some((c - 2, off))
    }

    /// The classes of the values function `k` loads (a field's class by its container's).
    fn loads(&self, k: usize) -> Vec<u32> {
        let s = &self.sums[k];
        let mut ld = vec![BOT; s.loads.len()];
        for l in 0..s.loads.len() {
            let (src, off) = s.loads[l];
            if off == ELEM {
                // WS95: an element of the buffer whose begin pointer is `src` (`Ld(b)`, the
                // pointer at `bs + bf` of a container of a known class)
                ld[l] = match src {
                    Src::Ld(b) => match self.buffer(k, b, &ld) {
                        Some((c, bf)) => match lookup(self.h, self.elements, c, bf) {
                            BOT => TOP,
                            v => v,
                        },
                        None => TOP,
                    },
                    _ => TOP,
                };
                continue;
            }
            let c = self.base(k, src, &ld);
            ld[l] = if c >= 2 {
                match lookup(self.h, self.fields, c - 2, off) {
                    BOT => TOP,
                    v => v,
                }
            } else if let Src::Arg(j) = src
                && !self.fixed[k][j as usize]
                && self.pf_at.contains_key(&(k as u32, j, off))
            {
                // WS94: a field of an object the callers pass, of the class they all put there
                self.field_at(k, src, off, &ld[..l])
            } else {
                c
            };
        }
        ld
    }
}

impl Ctx<'_> {
    /// The class of the value at `src + off` (`ld`: the classes of the loaded values known so
    /// far; a later one counts as unknown).
    fn value_known(&self, k: usize, src: Src, off: i32, ld: &[u32]) -> u32 {
        match src {
            Src::Ld(l) if l as usize >= ld.len() => TOP,
            _ => self.value(k, src, off, ld),
        }
    }

    /// What function `k` itself stores at `src + off` (WS94): the join of the pointers it
    /// stores there, unknown when it writes anything else there; nothing when it does not
    /// write it.
    fn own_stores(&self, k: usize, src: Src, off: i32, ld: &[u32]) -> u32 {
        let s = &self.sums[k];
        if s.field_clobbers.iter().any(|&(a, o, n)| a == src && (o == ELEM || (o < off.saturating_add(8) && o.saturating_add(n) > off))) {
            return TOP;
        }
        // (a pointer stored at an offset not known may be stored there)
        if self.stores[k].contains_key(&(src, ELEM)) {
            return TOP;
        }
        let mut v = BOT;
        for &(vs, vo) in self.stores[k].get(&(src, off)).map(|x| x.as_slice()).unwrap_or(&[]) {
            v = join(self.h, v, self.value_known(k, vs, vo, ld));
        }
        v
    }

    /// The class of the pointer at `src + off` in function `k` (WS94): what `k` stores there,
    /// joined with what is there on entry (a parameter's field: what the callers pass; a field
    /// of an object of a known class: what that class's functions store there).
    fn field_at(&self, k: usize, src: Src, off: i32, ld: &[u32]) -> u32 {
        let own = self.own_stores(k, src, off, ld);
        let before = match src {
            Src::Stack => TOP,
            Src::Arg(i) if !self.fixed[k][i as usize] => self.pf_at.get(&(k as u32, i, off)).map_or(TOP, |&x| self.pf[x as usize]),
            _ => {
                let b = match src {
                    Src::Ld(l) if l as usize >= ld.len() => TOP,
                    _ => self.base(k, src, ld),
                };
                if b >= 2 {
                    match lookup(self.h, self.fields, b - 2, off) {
                        BOT => TOP,
                        v => v,
                    }
                } else if own != BOT && !matches!(src, Src::Arg(_)) {
                    // (an object made here, a call's result: what this function puts there)
                    BOT
                } else {
                    b
                }
            }
        };
        join(self.h, own, before)
    }

    /// The class of the pointer at `+kk` of argument `j` of call `c` of function `k`, the
    /// object at `src + off` (WS94).
    fn arg_field(&self, k: usize, (c, j): (u32, u8), (src, off): (Src, i32), kk: i32, ld: &[u32]) -> u32 {
        if src != Src::Stack {
            return match off.checked_add(kk) {
                Some(o) => self.field_at(k, src, o, ld),
                None => TOP,
            };
        }
        if let Some(&v) = self.stack_objs[k].get(&(c, j, kk)) {
            return v;
        }
        match self.stack_ptrs[k].get(&(c, j, kk)) {
            Some(&(vs, vo)) => self.value(k, vs, vo, ld),
            None => TOP,
        }
    }
}

/// A parameter: `(function index, integer parameter)`.
type Param = (u32, u8);
/// A field of a parameter (`(function index, parameter, offset)`), or of an argument of a call
/// (`(call, argument, offset)`).
type FieldKey = (u32, u8, i32);
/// The pointers a function stores into fields: `(source, offset)` -> values.
type StoresAt = FxHashMap<(Src, i32), SmallVec<[(Src, i32); 1]>>;
/// Per function: `(call, argument, offset)` -> the pointer in that field of a stack object.
type StackPtrs = FxHashMap<FieldKey, (Src, i32)>;
/// Per function: the class of each stack object passed (`(call, argument)`), and of the stack
/// objects whose address a field of one holds (`(call, argument, offset)`).
type StackClasses = (FxHashMap<(u32, u8), u32>, FxHashMap<FieldKey, u32>);

/// Most offsets per parameter whose class from the callers is followed (WS94).
const MAX_DEMAND: usize = 64;

/// What one function contributes in a round: `(callee, parameter, class)`, its return class,
/// field classes and member classes by `(container class, offset)`.
type Contributions = (Vec<(u32, u8, u32)>, u32, Vec<((u32, i32), u32)>, Vec<((u32, i32), u32)>, Vec<(u32, u32)>, Vec<(u32, i32, i32)>, Vec<((u32, i32), u32)>);

/// The propagation over the summaries of the functions `starts` (address order); `external`
/// functions (exported) may be called with anything.
pub fn solve(u: &Universe, starts: &[u64], sums: &[Summary], external: &FxHashSet<u64>, max_rounds: usize) -> ThisIndex {
    let h = &u.hierarchy;
    let n = starts.len();
    let fidx = |a: u64| starts.binary_search(&a).ok();
    let class_of_vt = |vt: u64| u.primary.get(&vt).copied();

    // seeds: a vtable listing the function, a vtable stored into an argument
    let mut fixed = vec![[false; 6]; n];
    let mut seed = vec![[BOT; 6]; n];
    let mut has_callers = vec![false; n];
    let mut taken = vec![false; n];
    for s in sums {
        for &t in &s.call_targets {
            if let Some(k) = fidx(t) {
                has_callers[k] = true;
            }
        }
        for &r in &s.refs {
            if let Some(k) = fidx(r) {
                taken[k] = true;
            }
        }
    }
    for (k, &f) in starts.iter().enumerate() {
        let s = &sums[k];
        for i in 0..6u8 {
            let cs: Vec<u32> = s.vt_stores.iter().filter(|v| v.0 == Src::Arg(i) && v.1 == 0).filter_map(|v| class_of_vt(v.2)).collect();
            if !cs.is_empty() {
                fixed[k][i as usize] = true;
                seed[k][i as usize] = h.most_derived(&cs).map_or(TOP, cls);
            }
        }
        let listed = u.listing.contains_key(&f);
        if let Some(cs) = u.listing.get(&f) {
            let this = usize::from(s.returns_first());
            let common = cs.iter().copied().find(|&c| cs.iter().all(|&o| h.derives(o, c)));
            if !fixed[k][this] {
                fixed[k][this] = true;
                seed[k][this] = common.map_or(TOP, cls);
            }
        }
        if listed || u.taken.contains(&f) || taken[k] || !has_callers[k] || external.contains(&f) {
            for i in 0..6 {
                if !fixed[k][i] {
                    fixed[k][i] = true;
                    seed[k][i] = TOP;
                }
            }
        }
    }
    // the arguments that are no pointer
    let mut static_top = vec![0u8; n];
    for s in sums {
        for &(t, m) in &s.top_args {
            if let Some(k) = fidx(t) {
                static_top[k] |= m;
            }
        }
    }
    let init: Vec<[u32; 6]> = (0..n)
        .map(|k| {
            let mut p = seed[k];
            for i in 0..6 {
                if !fixed[k][i] && static_top[k] & (1 << i) != 0 {
                    p[i] = TOP;
                }
            }
            p
        })
        .collect();

    // the objects whose class the seeds say (vtables stored into them, constructors called on
    // them), per function: (source, offset) -> class
    let evidence: Vec<FxHashMap<(Src, i32), u32>> = sums
        .par_iter()
        .map(|s| {
            let mut ev: FxHashMap<(Src, i32), Vec<u32>> = FxHashMap::default();
            for &(src, k, vt) in &s.vt_stores {
                let key = match src {
                    Src::Stack | Src::Arg(_) => continue,
                    _ if k == 0 => (src, 0),
                    _ => continue,
                };
                if let Some(c) = class_of_vt(vt) {
                    ev.entry(key).or_default().push(c);
                }
            }
            for &(c, j, src, k) in &s.args {
                let Some(t) = fidx(s.call_targets[c as usize]) else { continue };
                if !fixed[t][j as usize] || seed[t][j as usize] < 2 || matches!(src, Src::Arg(_) | Src::Stack) {
                    continue;
                }
                let key = match src {
                    _ if k == 0 => (src, 0),
                    _ => continue,
                };
                ev.entry(key).or_default().push(seed[t][j as usize] - 2);
            }
            ev.into_iter().map(|(key, cs)| (key, h.most_derived(&cs).map_or(TOP, cls))).collect()
        })
        .collect();
    // the stack objects passed to calls: the vtable they hold there, else the most derived of
    // the seeds of the calls made on that object — the one first given to call `c` as argument
    // `j` (its constructor, the destructor, the virtual methods called directly) — and of the
    // vtables stored into it (an inlined destructor)
    let (stack, stack_objs): (Vec<_>, Vec<_>) = sums
        .par_iter()
        .map(|s| {
            let seed_of = |c: u32, j: u8| match fidx(s.call_targets[c as usize]) {
                Some(t) if fixed[t][j as usize] && seed[t][j as usize] >= 2 => Some(seed[t][j as usize] - 2),
                _ => None,
            };
            // (objects joined at a merge of paths are one)
            let mut parent: FxHashMap<(u32, u8), (u32, u8)> = FxHashMap::default();
            fn root(parent: &FxHashMap<(u32, u8), (u32, u8)>, mut x: (u32, u8)) -> (u32, u8) {
                while let Some(&p) = parent.get(&x) {
                    if p == x {
                        break;
                    }
                    x = p;
                }
                x
            }
            for &(a, b) in &s.made_alias {
                let (ra, rb) = (root(&parent, a), root(&parent, b));
                if ra != rb {
                    parent.insert(ra.max(rb), ra.min(rb));
                }
            }
            let mut objects: FxHashMap<(u32, u8), Vec<u32>> = FxHashMap::default();
            for &(c, j, vt) in &s.made_vt {
                objects.entry(root(&parent, (c, j))).or_default().extend(class_of_vt(vt));
            }
            for &(c, j, e) in &s.stack_ev {
                if let StackEv::Made(c2, j2) = e {
                    let o = objects.entry(root(&parent, (c2, j2))).or_default();
                    o.extend(seed_of(c2, j2));
                    o.extend(seed_of(c, j));
                }
            }
            for &(a, b) in &s.made_alias {
                for x in [a, b] {
                    objects.entry(root(&parent, x)).or_default().extend(seed_of(x.0, x.1));
                }
            }
            // (a call given an object with no evidence yet made it: the object is that instance)
            let ev: FxHashMap<(u32, u8), StackEv> = s.stack_ev.iter().map(|&(c, j, e)| ((c, j), e)).collect();
            let class_of_ev = |e: StackEv| match e {
                StackEv::Vtable(vt) => class_of_vt(vt).map_or(TOP, cls),
                StackEv::Made(c2, j2) => {
                    let mut cs = objects.get(&root(&parent, (c2, j2))).cloned().unwrap_or_default();
                    cs.extend(seed_of(c2, j2));
                    if cs.is_empty() { TOP } else { h.most_derived(&cs).map_or(TOP, cls) }
                }
            };
            let passed = s
                .args
                .iter()
                .filter(|a| a.2 == Src::Stack)
                .map(|&(c, j, _, _)| ((c, j), class_of_ev(ev.get(&(c, j)).copied().unwrap_or(StackEv::Made(c, j)))))
                .collect();
            // (WS94: the stack objects whose address a field of a stack object passed holds)
            let pointed = s
                .stack_fields
                .iter()
                .filter_map(|&(c, j, k, v)| match v {
                    FieldVal::Obj(e) => Some(((c, j, k), class_of_ev(e))),
                    FieldVal::Ptr(..) | FieldVal::Elem(_) => None,
                })
                .collect();
            let out: StackClasses = (passed, pointed);
            out
        })
        .unzip();
    // WS94: the fields of its parameters a function loads, or a callee it passes them to
    // (transitively): the offsets whose class from the callers is followed
    let mut demand: FxHashMap<Param, SmallVec<[i32; 4]>> = FxHashMap::default();
    let want = |d: &mut FxHashMap<Param, SmallVec<[i32; 4]>>, key: Param, off: i32| {
        let e = d.entry(key).or_default();
        if e.len() < MAX_DEMAND && !e.contains(&off) {
            e.push(off);
            return true;
        }
        false
    };
    for (k, s) in sums.iter().enumerate() {
        // (a loaded value used as a pointer: passed, returned, stored, dereferenced)
        let mut used: FxHashSet<u32> = FxHashSet::default();
        let srcs = s.args.iter().map(|a| a.2).chain(s.loads.iter().map(|l| l.0)).chain(s.rets.iter().map(|r| r.0));
        for src in srcs.chain(s.field_stores.iter().flat_map(|f| [f.0, f.2])) {
            if let Src::Ld(l) = src {
                used.insert(l);
            }
        }
        for (l, &(src, off)) in s.loads.iter().enumerate() {
            if let Src::Arg(j) = src
                && off >= 0
                && !fixed[k][j as usize]
                && used.contains(&(l as u32))
            {
                want(&mut demand, (k as u32, j), off);
            }
        }
    }
    // (a caller passing its own parameter `i` + `o` as `j` of `t` demands `t`'s offsets + `o`)
    let fixed_ref = &fixed;
    let edges: Vec<(Param, FieldKey)> = sums
        .par_iter()
        .enumerate()
        .flat_map_iter(|(k, s)| {
            s.args.iter().filter_map(move |&(c, j, src, o)| {
                let Src::Arg(i) = src else { return None };
                let t = fidx(s.call_targets[c as usize])?;
                (!fixed_ref[k][i as usize] && !fixed_ref[t][j as usize]).then_some(((t as u32, j), (k as u32, i, o)))
            })
        })
        .collect();
    let mut callers_of: FxHashMap<Param, SmallVec<[FieldKey; 2]>> = FxHashMap::default();
    for (callee, caller) in edges {
        callers_of.entry(callee).or_default().push(caller);
    }
    let mut work: Vec<(u32, u8)> = demand.keys().copied().collect();
    while let Some(key) = work.pop() {
        let Some(cs) = callers_of.get(&key) else { continue };
        let ks = demand[&key].clone();
        for &(k, i, o) in cs {
            let mut grew = false;
            for &kk in &ks {
                if let Some(f) = o.checked_add(kk).filter(|f| (0..0x10000).contains(f)) {
                    grew |= want(&mut demand, (k, i), f);
                }
            }
            if grew {
                work.push((k, i));
            }
        }
    }
    // (dense: `pf_at` numbers the offsets, `pf_of` lists them by parameter)
    let mut pf_init: Vec<u32> = Vec::new();
    let mut pf_at: FxHashMap<FieldKey, u32> = FxHashMap::default();
    let mut pf_keys: Vec<FieldKey> = Vec::new();
    let mut pf_of: FxHashMap<Param, SmallVec<[(i32, u32); 4]>> = FxHashMap::default();
    let mut dkeys: Vec<_> = demand.keys().copied().collect();
    dkeys.sort_unstable();
    for (f, j) in dkeys {
        // (a caller passing something that is no pointer: nothing is known of its fields)
        let v = if static_top[f as usize] & (1 << j) != 0 { TOP } else { BOT };
        for &k in &demand[&(f, j)] {
            let x = pf_init.len() as u32;
            pf_init.push(v);
            pf_at.insert((f, j, k), x);
            pf_keys.push((f, j, k));
            pf_of.entry((f, j)).or_default().push((k, x));
        }
    }
    drop(demand);
    let (stores, stack_ptrs): (Vec<StoresAt>, Vec<StackPtrs>) = sums
        .par_iter()
        .map(|s| {
            let mut st: StoresAt = FxHashMap::default();
            for &(a, o, vs, vo) in &s.field_stores {
                st.entry((a, o)).or_default().push((vs, vo));
            }
            let sp = s
                .stack_fields
                .iter()
                .filter_map(|&(c, j, k, v)| match v {
                    FieldVal::Ptr(vs, vo) => Some(((c, j, k), (vs, vo))),
                    FieldVal::Obj(_) | FieldVal::Elem(_) => None,
                })
                .collect();
            (st, sp)
        })
        .unzip();
    let mut pf = pf_init.clone();
    let mut p = init.clone();
    let mut r = vec![BOT; n];
    let mut fields: FxHashMap<(u32, i32), u32> = FxHashMap::default();
    let mut members: FxHashMap<(u32, i32), u32> = FxHashMap::default();
    let mut elements: FxHashMap<(u32, i32), u32> = FxHashMap::default();
    let mut rounds = 0;
    let mut converged = false;
    while rounds < max_rounds {
        rounds += 1;
        // per function: the class of each loaded value, then the contributions
        let per: Vec<Contributions> = (0..n)
            .into_par_iter()
            .map(|k| {
                let s = &sums[k];
                let cx = Ctx { h, primary: &u.primary, starts, sums, evidence: &evidence, stack: &stack, p: &p, r: &r, fields: &fields, members: &members, elements: &elements, fixed: &fixed, pf: &pf, pf_at: &pf_at, stores: &stores, stack_objs: &stack_objs, stack_ptrs: &stack_ptrs };
                let ld = cx.loads(k);
                let value = |src: Src, off: i32, ld: &[u32]| cx.value(k, src, off, ld);
                let base = |src: Src, ld: &[u32]| cx.base(k, src, ld);
                let mut contrib = Vec::new();
                let mut pfs = Vec::new();
                for &(c, j, src, off) in &s.args {
                    let Some(t) = fidx(s.call_targets[c as usize]) else { continue };
                    if fixed[t][j as usize] {
                        continue;
                    }
                    contrib.push((t as u32, j, cx.arg_value(k, c, j, src, off, &ld)));
                    for &(kk, x) in pf_of.get(&(t as u32, j)).map(|d| d.as_slice()).unwrap_or(&[]) {
                        pfs.push((x, cx.arg_field(k, (c, j), (src, off), kk, &ld)));
                    }
                }
                let mut ret = BOT;
                if s.ret_unknown {
                    ret = TOP;
                } else {
                    for &(src, off) in &s.rets {
                        ret = join(h, ret, value(src, off, &ld));
                    }
                }
                let mut fs = Vec::new();
                // (a field is past the vtable pointer; a negative offset is no field of this
                // class: `this` of a base class's method reaching the derived object around it)
                for &(src, off, vs, vo) in s.field_stores.iter().filter(|f| f.1 > 0) {
                    let b = base(src, &ld);
                    if b >= 2 {
                        fs.push(((b - 2, off), value(vs, vo, &ld)));
                    }
                }
                // (WS95: bytes written with something else — here or by a callee — make the
                // fields they overlap unknown)
                let mut cl = Vec::new();
                for &(src, off, n) in s.field_numbers.iter().filter(|f| f.1 > 0) {
                    let b = base(src, &ld);
                    if b >= 2 {
                        cl.push((b - 2, off, n));
                    }
                }
                // WS95: the elements of the buffers of containers of a known class
                let mut es = Vec::new();
                for &(src, _, vs, vo) in s.field_stores.iter().filter(|f| f.1 == ELEM) {
                    if let Src::Ld(b) = src
                        && let Some(key) = cx.buffer(k, b, &ld)
                    {
                        es.push((key, value(vs, vo, &ld)));
                    }
                }
                let clobbers = s.field_numbers.iter().map(|f| (f.0, f.1)).chain(s.buf_writes.iter().map(|&w| (w, ELEM))).chain(s.buf_escapes.iter().copied());
                for (src, _off) in clobbers.filter(|f| f.1 == ELEM) {
                    if let Src::Ld(b) = src
                        && let Some(key) = cx.buffer(k, b, &ld)
                    {
                        es.push((key, TOP));
                    }
                }
                let mut ms = Vec::new();
                for &(src, off, vt) in &s.vt_stores {
                    if off <= 0 || src == Src::Stack {
                        continue;
                    }
                    let b = base(src, &ld);
                    if b >= 2
                        && let Some(c) = class_of_vt(vt)
                    {
                        ms.push(((b - 2, off), cls(c)));
                    }
                }
                (contrib, ret, fs, ms, pfs, cl, es)
            })
            .collect();
        let mut np = init.clone();
        let mut nr = vec![BOT; n];
        let mut nf: FxHashMap<(u32, i32), u32> = FxHashMap::default();
        let mut nm: FxHashMap<(u32, i32), u32> = FxHashMap::default();
        let mut npf = pf_init.clone();
        let mut clobbered: FxHashMap<u32, Vec<(i32, i32)>> = FxHashMap::default();
        let mut ne: FxHashMap<(u32, i32), u32> = FxHashMap::default();
        for (k, (contrib, ret, fs, ms, pfs, cl, es)) in per.into_iter().enumerate() {
            for (key, v) in es {
                let e = ne.entry(key).or_insert(BOT);
                *e = join(h, *e, v);
            }
            for (c, off, n) in cl {
                clobbered.entry(c).or_default().push((off, n));
            }
            for (x, v) in pfs {
                let e = &mut npf[x as usize];
                *e = join(h, *e, v);
            }
            for (t, j, v) in contrib {
                let e = &mut np[t as usize][j as usize];
                *e = join(h, *e, v);
            }
            nr[k] = ret;
            for (key, v) in fs {
                let e = nf.entry(key).or_insert(BOT);
                *e = join(h, *e, v);
            }
            for (key, v) in ms {
                let e = nm.entry(key).or_insert(BOT);
                *e = join(h, *e, v);
            }
        }
        // (also where the class itself stores nothing: a derived class's field of a base)
        for (&c, rs) in &clobbered {
            for &(o, n) in rs {
                let mut a = o & !7;
                while a < o.saturating_add(n) && a - (o & !7) < 0x80 {
                    nf.insert((c, a), TOP);
                    a += 8;
                }
            }
        }
        for ((c, off), v) in nf.iter_mut() {
            if let Some(rs) = clobbered.get(c)
                && rs.iter().any(|&(o, n)| o < off.saturating_add(8) && o.saturating_add(n) > *off)
            {
                *v = TOP;
            }
        }
        let same = np == p && nr == r && nf == fields && nm == members && npf == pf && ne == elements;
        elements = ne;
        pf = npf;
        p = np;
        r = nr;
        fields = nf;
        members = nm;
        if same {
            converged = true;
            break;
        }
    }

    // (development: `REARGO_THIS_EXPLAIN=0x…,0x…` prints why `this` of those functions is what it is)
    if let Some(list) = std::env::var_os("REARGO_THIS_EXPLAIN") {
        let cx = Ctx { h, primary: &u.primary, starts, sums, evidence: &evidence, stack: &stack, p: &p, r: &r, fields: &fields, members: &members, elements: &elements, fixed: &fixed, pf: &pf, pf_at: &pf_at, stores: &stores, stack_objs: &stack_objs, stack_ptrs: &stack_ptrs };
        let show = |v: u32| match v {
            BOT => "nothing".to_string(),
            TOP => "unknown".to_string(),
            c => format!("class vtable 0x{:x}", h.vtables[(c - 2) as usize]),
        };
        for t in list.to_string_lossy().split(',').filter_map(|a| u64::from_str_radix(a.trim().trim_start_matches("0x"), 16).ok()) {
            let Some(ti) = fidx(t) else {
                eprintln!("[explain] 0x{t:x}: no function");
                continue;
            };
            eprintln!(
                "[explain] 0x{t:x}: this = {} (fixed {}, listed {}, taken {}, callers {}, a caller passes no pointer {})",
                show(p[ti][0]),
                fixed[ti][0],
                u.listing.contains_key(&t),
                u.taken.contains(&t) || taken[ti] || external.contains(&t),
                has_callers[ti],
                static_top[ti] & 1 != 0
            );
            for (k, s) in sums.iter().enumerate() {
                if s.top_args.iter().any(|&(x, m)| x == t && m & 1 != 0) {
                    eprintln!("[explain]   0x{:x} passes no pointer", starts[k]);
                }
                let ld = cx.loads(k);
                for &(c, j, src, off) in &s.args {
                    if j == 0 && s.call_targets[c as usize] == t {
                        let detail = match src {
                            Src::Ld(l) => format!("{:?}", s.loads[l as usize]),
                            Src::Stack => {
                                let ev: Vec<_> = s.stack_ev.iter().filter(|e| e.0 == c && e.1 == j).collect();
                                let made: Vec<_> = s.made_vt.iter().collect();
                                let on: Vec<_> = s.stack_ev.iter().filter(|e| ev.iter().any(|x| x.2 == e.2)).map(|e| (format!("{:#x}", s.call_targets[e.0 as usize]), e.1)).collect();
                                format!("call {c} ev {ev:?} vtables {made:?} calls on it {on:?}")
                            }
                            _ => String::new(),
                        };
                        eprintln!("[explain]   0x{:x} passes {src:?}+{off:#x} {detail}: {}", starts[k], show(cx.arg_value(k, c, j, src, off, &ld)));
                    }
                }
            }
        }
    }
    let mut idx = ThisIndex { hierarchy: h.clone(), ..Default::default() };
    for k in 0..n {
        let mut q = [u32::MAX; 6];
        for i in 0..6 {
            if !fixed[k][i] && p[k][i] >= 2 {
                q[i] = p[k][i] - 2;
            }
        }
        if q.iter().any(|&v| v != u32::MAX) {
            idx.params.insert(starts[k], q);
        }
        if r[k] >= 2 {
            idx.rets.insert(starts[k], r[k] - 2);
        }
    }
    idx.fields = fields.into_iter().filter(|e| e.1 >= 2).collect();
    idx.members = members.into_iter().filter(|e| e.1 >= 2).collect();
    idx.elements = elements.into_iter().filter(|e| e.1 >= 2).collect();
    idx.param_fields = pf_keys.iter().zip(&pf).filter(|e| *e.1 >= 2).map(|(&(f, j, k), &v)| ((starts[f as usize], j, k), v - 2)).collect();
    let seeded_this = (0..n).filter(|&k| seed[k][usize::from(sums[k].returns_first())] >= 2).count() as u64;
    idx.stats = IndexStats { functions: n as u64, classes: h.vtables.len() as u64, rounds: rounds as u64, converged, seeded_this, ..Default::default() };
    idx
}

/// The functions of the image the PLT stubs jump to (WS94): a shared library calls its own
/// exported functions through its PLT (`jmp [rip + slot]`, the GOT slot bound to the
/// function); stub address -> function.
pub fn plt_targets(mem: &Memory) -> FxHashMap<u64, u64> {
    let mut out = FxHashMap::default();
    for b in mem.blocks().filter(|b| b.name.starts_with(".plt") && b.flags.contains(MemoryFlags::EXECUTE)) {
        let Some(data) = &b.data else { continue };
        let mut dec = Decoder::with_ip(64, data, b.start, DecoderOptions::NONE);
        while dec.can_decode() {
            let i = dec.decode();
            if i.mnemonic() != Mnemonic::Jmp || i.op_count() != 1 || i.op0_kind() != OpKind::Memory || i.memory_base() != Register::RIP {
                continue;
            }
            let Some(f) = crate::vcall::pointer_at(mem, i.ip_rel_memory_address()) else { continue };
            if crate::vcall::is_code(mem, f) && mem.find_block(f).is_some_and(|t| !t.name.starts_with(".plt")) {
                out.insert(b.start + (i.ip() - b.start) / 16 * 16, f);
            }
        }
    }
    out
}

/// The index of the functions `[start, start + len)` of `mem`; `external` are the functions
/// another module may call (exported).
pub fn build(mem: &Memory, functions: &[(u64, u64)], external: &[u64]) -> ThisIndex {
    build_with(mem, functions, external, &[])
}

/// [`build`], `imports` naming the PLT stubs of the imports (`(stub, symbol)`, WS95: what a call
/// to one does to the memory its arguments reach; a direct call to an address that is neither a
/// function nor a stub named there is unknown code).
pub fn build_with(mem: &Memory, functions: &[(u64, u64)], external: &[u64], imports: &[(u64, String)]) -> ThisIndex {
    let t0 = std::time::Instant::now();
    let u = universe(mem);
    let mut fs: Vec<(u64, u64)> = functions.to_vec();
    fs.sort_unstable();
    fs.dedup_by_key(|f| f.0);
    // (a call through the image's own PLT is a call to the function)
    let plt = plt_targets(mem);
    let mut known: Vec<u64> = fs.iter().map(|f| f.0).chain(plt.keys().copied()).collect();
    known.sort_unstable();
    let kinds: FxHashMap<u64, ImportKind> = imports.iter().filter(|i| !plt.contains_key(&i.0)).map(|(a, n)| (*a, import_kind(n))).collect();
    let env = Env { vt_points: &u.vt_points, imports: &kinds, functions: (!imports.is_empty()).then_some(known.as_slice()) };
    let mut sums: Vec<Summary> = fs.par_iter().map(|&(s, l)| summarize_in(mem, s, l, &env)).collect();
    if !plt.is_empty() {
        let through = |a: &mut u64| {
            if let Some(&f) = plt.get(a) {
                *a = f;
            }
        };
        for s in &mut sums {
            s.call_targets.iter_mut().for_each(through);
            s.refs.iter_mut().for_each(through);
            s.top_args.iter_mut().for_each(|t| through(&mut t.0));
        }
    }
    let starts: Vec<u64> = fs.iter().map(|f| f.0).collect();
    // WS95: the callees' effects, composed bottom-up (not those on a parameter whose class a
    // vtable listing the function or a vtable it stores there gives)
    let export: Vec<u8> = starts
        .par_iter()
        .zip(&sums)
        .map(|(f, s)| {
            let mut m = 0x3fu8;
            if u.listing.contains_key(f) {
                m &= !(1 << u8::from(s.returns_first()));
            }
            for &(d, off, vt) in &s.vt_stores {
                if let (Src::Arg(i), 0) = (d, off)
                    && u.primary.contains_key(&vt)
                {
                    m &= !(1 << i);
                }
            }
            m
        })
        .collect();
    let t_sum = std::time::Instant::now();
    // (development: `REARGO_NO_EFFECTS=1` leaves them out, to compare)
    let sums = if std::env::var_os("REARGO_NO_EFFECTS").is_some() { sums } else { crate::effects::compose(&starts, sums, &export) };
    let compose_ms = t_sum.elapsed().as_millis() as u64;
    let t1 = std::time::Instant::now();
    let mut idx = solve(&u, &starts, &sums, &external.iter().copied().collect(), MAX_ROUNDS);
    idx.stats.summarize_ms = (t1 - t0).as_millis() as u64 - compose_ms;
    idx.stats.compose_ms = compose_ms;
    idx.stats.solve_ms = t1.elapsed().as_millis() as u64;
    idx
}

/// The version of the index format and of the analysis behind it (a cached index of another
/// version is rebuilt).
const INDEX_VERSION: u8 = 11;
const MAGIC: &[u8; 7] = b"RATHIS\0";

impl ThisIndex {
    /// The index as bytes (little-endian; see [`ThisIndex::from_bytes`]).
    pub fn to_bytes(&self, key: u64) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        let u32_ = |b: &mut Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());
        let u64_ = |b: &mut Vec<u8>, v: u64| b.extend_from_slice(&v.to_le_bytes());
        b.extend_from_slice(MAGIC);
        b.push(INDEX_VERSION);
        u64_(&mut b, key);
        let s = &self.stats;
        for v in [s.functions, s.classes, s.rounds, u64::from(s.converged), s.summarize_ms, s.solve_ms, s.seeded_this, s.compose_ms] {
            u64_(&mut b, v);
        }
        u32_(&mut b, self.hierarchy.vtables.len() as u32);
        for (vt, bases) in self.hierarchy.vtables.iter().zip(&self.hierarchy.bases) {
            u64_(&mut b, *vt);
            u32_(&mut b, bases.len() as u32);
            for &c in bases {
                u32_(&mut b, c);
            }
        }
        let mut params: Vec<_> = self.params.iter().collect();
        params.sort_unstable_by_key(|p| p.0);
        u32_(&mut b, params.len() as u32);
        for (f, p) in params {
            u64_(&mut b, *f);
            for &c in p {
                u32_(&mut b, c);
            }
        }
        let mut rets: Vec<_> = self.rets.iter().collect();
        rets.sort_unstable();
        u32_(&mut b, rets.len() as u32);
        for (f, c) in rets {
            u64_(&mut b, *f);
            u32_(&mut b, *c);
        }
        for map in [&self.fields, &self.members, &self.elements] {
            let mut m: Vec<_> = map.iter().collect();
            m.sort_unstable();
            u32_(&mut b, m.len() as u32);
            for ((c, off), v) in m {
                u32_(&mut b, *c);
                u32_(&mut b, *off as u32);
                u32_(&mut b, *v);
            }
        }
        let mut pf: Vec<_> = self.param_fields.iter().collect();
        pf.sort_unstable();
        u32_(&mut b, pf.len() as u32);
        for ((f, j, k), v) in pf {
            u64_(&mut b, *f);
            b.push(*j);
            u32_(&mut b, *k as u32);
            u32_(&mut b, *v);
        }
        b
    }

    /// The index [`ThisIndex::to_bytes`] wrote, when its key is `key`.
    pub fn from_bytes(b: &[u8], key: u64) -> Option<ThisIndex> {
        struct R<'a>(&'a [u8], usize);
        impl R<'_> {
            fn take(&mut self, n: usize) -> Option<&[u8]> {
                let s = self.0.get(self.1..self.1 + n)?;
                self.1 += n;
                Some(s)
            }
            fn u32(&mut self) -> Option<u32> {
                Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
            }
            fn u64(&mut self) -> Option<u64> {
                Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
            }
        }
        let mut r = R(b, 0);
        if r.take(7)? != MAGIC || r.take(1)?[0] != INDEX_VERSION || r.u64()? != key {
            return None;
        }
        let mut idx = ThisIndex::default();
        let mut st = [0u64; 8];
        for v in st.iter_mut() {
            *v = r.u64()?;
        }
        idx.stats = IndexStats { functions: st[0], classes: st[1], rounds: st[2], converged: st[3] != 0, summarize_ms: st[4], solve_ms: st[5], seeded_this: st[6], compose_ms: st[7] };
        let n = r.u32()? as usize;
        for _ in 0..n {
            idx.hierarchy.vtables.push(r.u64()?);
            let k = r.u32()? as usize;
            let mut bases = Vec::with_capacity(k.min(64));
            for _ in 0..k {
                bases.push(r.u32()?);
            }
            idx.hierarchy.bases.push(bases);
        }
        for _ in 0..r.u32()? {
            let f = r.u64()?;
            let mut p = [0u32; 6];
            for c in p.iter_mut() {
                *c = r.u32()?;
            }
            idx.params.insert(f, p);
        }
        for _ in 0..r.u32()? {
            let f = r.u64()?;
            idx.rets.insert(f, r.u32()?);
        }
        for m in 0..3 {
            for _ in 0..r.u32()? {
                let (c, off, v) = (r.u32()?, r.u32()? as i32, r.u32()?);
                match m {
                    0 => idx.fields.insert((c, off), v),
                    1 => idx.members.insert((c, off), v),
                    _ => idx.elements.insert((c, off), v),
                };
            }
        }
        for _ in 0..r.u32()? {
            let (f, j) = (r.u64()?, r.take(1)?[0]);
            let (k, v) = (r.u32()? as i32, r.u32()?);
            idx.param_fields.insert((f, j, k), v);
        }
        (r.1 == b.len()).then_some(idx)
    }
}

/// A fingerprint of the file at `path`: its size and 64 samples of 4 KiB spread over it.
pub fn file_key(path: &std::path::Path) -> std::io::Result<u64> {
    use std::hash::Hasher;
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut h = rustc_hash::FxHasher::default();
    h.write_u64(len);
    let mut buf = vec![0u8; 4096];
    for k in 0..64u64 {
        let at = if len > 4096 { (len - 4096) / 63 * k } else { 0 };
        f.seek(SeekFrom::Start(at))?;
        let n = f.read(&mut buf)?;
        h.write(&buf[..n]);
    }
    Ok(h.finish())
}

/// Where the index of `binary` is cached: `$REARGO_CACHE_DIR`, else the user's cache directory
/// (`%LOCALAPPDATA%\re-argo`, `$XDG_CACHE_HOME/re-argo`, `~/.cache/re-argo`), else the temp
/// directory; named after the binary and its fingerprint.
pub fn cache_path(binary: &std::path::Path, key: u64) -> std::path::PathBuf {
    let dir = std::env::var_os("REARGO_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(|d| std::path::Path::new(&d).join("re-argo")))
        .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(|d| std::path::Path::new(&d).join("re-argo")))
        .or_else(|| std::env::var_os("HOME").map(|d| std::path::Path::new(&d).join(".cache").join("re-argo")))
        .unwrap_or_else(std::env::temp_dir);
    let name = binary.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "binary".into());
    dir.join(format!("{name}-{key:016x}.this"))
}

/// The index of `binary` (loaded into `mem`, `.eh_frame_hdr` at `hdr`): read from the cache,
/// else built from the functions of the `.eh_frame_hdr` table and saved there (best effort).
/// `rebuild` ignores the cache. `None` when the binary has no such table.
pub fn load_or_build(binary: &std::path::Path, mem: &Memory, hdr: Option<u64>, rebuild: bool) -> Option<ThisIndex> {
    let key = file_key(binary).ok()?;
    let path = cache_path(binary, key);
    if !rebuild
        && let Ok(b) = std::fs::read(&path)
        && let Some(idx) = ThisIndex::from_bytes(&b, key)
    {
        return Some(idx);
    }
    let functions = reargo_loader::fde_functions(mem, hdr?);
    if functions.is_empty() {
        return None;
    }
    let data = std::fs::read(binary).unwrap_or_default();
    let external = reargo_loader::elf_exported_functions(&data);
    let imports = reargo_loader::elf_import_stubs(&data);
    drop(data);
    let idx = build_with(mem, &functions, &external, &imports);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        if std::fs::write(&tmp, idx.to_bytes(key)).is_ok() && std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    Some(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Endian;
    use reargo_loader::memory::MemoryBlock;
    use std::sync::Arc;

    fn text(code: &[u8]) -> Memory {
        let mut mem = Memory::new(reargo_core::address::SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock { name: ".text".into(), start: 0x1000, size: code.len() as u64, flags: MemoryFlags::READ | MemoryFlags::EXECUTE, data: Some(Arc::from(code)) });
        mem
    }

    fn this_args(s: &Summary) -> Vec<(u64, Src, i32)> {
        s.args.iter().filter(|a| a.1 == 0).map(|a| (s.call_targets[a.0 as usize], a.2, a.3)).collect()
    }

    /// The pointers passed as the first argument: `this`, a member's address, a loaded field
    /// (also in a tail call), through a callee-saved register.
    #[test]
    fn a_summary_follows_this_through_registers_and_fields() {
        // push rbx ; mov rbx, rdi ; lea rdi, [rbx+0x10] ; call 0x1100 ; mov rdi, rbx ;
        // call 0x1100 ; mov rax, [rbx+8] ; mov rdi, rax ; pop rbx ; jmp 0x1200
        let code = [
            0x53, 0x48, 0x89, 0xfb, 0x48, 0x8d, 0x7b, 0x10, 0xe8, 0xf3, 0x00, 0x00, 0x00, 0x48, 0x89, 0xdf, 0xe8, 0xeb, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x43, 0x08,
            0x48, 0x89, 0xc7, 0x5b, 0xe9, 0xde, 0x01, 0x00, 0x00,
        ];
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &FxHashSet::default());
        assert_eq!(this_args(&s), [(0x1100, Src::Arg(0), 0x10), (0x1100, Src::Arg(0), 0), (0x1200, Src::Ld(0), 0)]);
        assert_eq!(s.loads, [(Src::Arg(0), 8)]);
        // after the first call `rsi` … `r9` are no pointers
        assert!(s.top_args.contains(&(0x1100, 0b11_1110)), "{:?}", s.top_args);
    }

    /// WS94: the pointers in the fields of a stack object passed to a call are recorded at
    /// that call; a field written with something else than a pointer is a clobber.
    #[test]
    fn a_summary_records_the_fields_of_the_stack_objects_passed() {
        let code = [
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
            0x48, 0x89, 0x74, 0x24, 0x10, // mov [rsp+0x10], rsi (the object at rsp+8: +8)
            0xc7, 0x44, 0x24, 0x18, 0x01, 0x00, 0x00, 0x00, // mov dword [rsp+0x18], 1 (+0x10: no pointer)
            0x48, 0x89, 0x77, 0x10, // mov [rdi+0x10], rsi
            0x89, 0x47, 0x18, // mov [rdi+0x18], eax
            0x48, 0x8d, 0x7c, 0x24, 0x08, // lea rdi, [rsp+8]
            0xe8, 0xde, 0x00, 0x00, 0x00, // call 0x1100 (next 0x1022)
            0x48, 0x83, 0xc4, 0x28, // add rsp, 0x28
            0xc3,
        ];
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &FxHashSet::default());
        assert_eq!(s.stack_fields, [(0, 0, 8, FieldVal::Ptr(Src::Arg(1), 0))]);
        assert_eq!(s.field_stores, [(Src::Arg(0), 0x10, Src::Arg(1), 0)]);
        assert_eq!(s.field_clobbers, [(Src::Arg(0), 0x18, 4)]);
    }

    /// WS95: a pointer stepped through a buffer in a loop, or indexed, points to its elements:
    /// what is loaded / stored through it is keyed `(buffer pointer, ELEM)`.
    #[test]
    fn a_summary_keys_the_elements_of_a_buffer() {
        let code = [
            0x48, 0x8b, 0x47, 0x08, // mov rax, [rdi+8] (the begin pointer)
            0x48, 0x8b, 0x57, 0x10, // mov rdx, [rdi+0x10]
            0x48, 0x8b, 0x08, // L: mov rcx, [rax]
            0x48, 0x89, 0x4e, 0x08, // mov [rsi+8], rcx
            0x48, 0x83, 0xc0, 0x08, // add rax, 8
            0x48, 0x39, 0xd0, // cmp rax, rdx
            0x75, 0xf0, // jne L
            0x4c, 0x8b, 0x47, 0x08, // mov r8, [rdi+8]
            0x49, 0x89, 0x34, 0xc8, // mov [r8+rcx*8], rsi
            0xc3,
        ];
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &FxHashSet::default());
        let begin = s.loads.iter().position(|&l| l == (Src::Arg(0), 8)).expect("begin load") as u32;
        let elem = s.loads.iter().position(|&l| l == (Src::Ld(begin), ELEM));
        assert!(elem.is_some(), "{:?}", s.loads);
        assert!(s.field_stores.contains(&(Src::Ld(begin), ELEM, Src::Arg(1), 0)), "{:?}", s.field_stores);
        assert!(s.field_stores.contains(&(Src::Arg(1), 8, Src::Ld(elem.expect("elem") as u32), 0)), "{:?}", s.field_stores);
    }

    /// WS95: an import copying memory copies the elements of one buffer into another; unknown
    /// code given a pointer may write anything where it reaches (the object of a virtual call
    /// excepted: its class's methods say what they do).
    #[test]
    fn a_summary_records_what_calls_may_do_to_buffers() {
        let code = [
            0x53, // push rbx
            0x48, 0x89, 0xfb, // mov rbx, rdi
            0x48, 0x8b, 0x7f, 0x08, // mov rdi, [rdi+8]
            0x48, 0x8b, 0x76, 0x10, // mov rsi, [rsi+0x10]
            0xe8, 0xef, 0x00, 0x00, 0x00, // call 0x1100 (memcpy)
            0x48, 0x8d, 0x7b, 0x20, // lea rdi, [rbx+0x20]
            0xe8, 0xe6, 0x01, 0x00, 0x00, // call 0x1200 (an import not known)
            0x48, 0x89, 0xdf, // mov rdi, rbx
            0x48, 0x8b, 0x03, // mov rax, [rbx]
            0xff, 0x50, 0x10, // call [rax+0x10] (virtual: on this)
            0x48, 0x89, 0xdf, // mov rdi, rbx
            0x48, 0x8d, 0x73, 0x30, // lea rsi, [rbx+0x30]
            0x48, 0x8b, 0x03, // mov rax, [rbx]
            0xff, 0x50, 0x18, // call [rax+0x18] (rsi given to it)
            0x5b, 0xc3, // pop rbx ; ret
        ];
        let imports: FxHashMap<u64, ImportKind> = [(0x1100, import_kind("memcpy@plt")), (0x1200, import_kind("frobnicate"))].into_iter().collect();
        let vts = FxHashSet::default();
        let s = summarize_in(&text(&code), 0x1000, code.len() as u64, &Env { vt_points: &vts, imports: &imports, functions: Some(&[0x1000]) });
        assert_eq!(s.loads[..2], [(Src::Arg(0), 8), (Src::Arg(1), 0x10)]);
        assert_eq!(s.buf_copies, [(Src::Ld(0), Src::Ld(1))]);
        assert_eq!(s.buf_escapes, [(Src::Arg(0), 0x20), (Src::Arg(0), 0x30)]);
        assert!(s.buf_writes.is_empty());
        assert_eq!(import_kind("strlen"), ImportKind::Pure);
        assert_eq!(import_kind("snprintf"), ImportKind::WritesArgs);
        assert_eq!(import_kind("sqrtf"), ImportKind::WritesArgs);
        assert_eq!(import_kind("pthread_once"), ImportKind::Escape);
    }

    /// A spilled `this` comes back from its stack slot; two values joined at a branch are no
    /// one pointer; a vtable stored into `this` is a constructor's.
    #[test]
    fn a_summary_follows_spills_and_joins() {
        // sub rsp, 0x18 ; mov [rsp+8], rdi ; call 0x1100 ; mov rdi, [rsp+8] ; call 0x1100 ;
        // test eax, eax ; je L ; mov rdi, rsi ; L: call 0x1100 ; lea rax, [rip+0x2000] ;
        // mov rcx, [rsp+8] ; mov [rcx], rax ; add rsp, 0x18 ; ret
        let code = [
            0x48, 0x83, 0xec, 0x18, // sub rsp, 0x18
            0x48, 0x89, 0x7c, 0x24, 0x08, // mov [rsp+8], rdi
            0xe8, 0xf2, 0x00, 0x00, 0x00, // call 0x1100 (next 0x100e)
            0x48, 0x8b, 0x7c, 0x24, 0x08, // mov rdi, [rsp+8]
            0xe8, 0xe8, 0x00, 0x00, 0x00, // call 0x1100 (next 0x1018)
            0x85, 0xc0, // test eax, eax
            0x74, 0x03, // je +3
            0x48, 0x89, 0xf7, // mov rdi, rsi
            0xe8, 0xdc, 0x00, 0x00, 0x00, // call 0x1100 (next 0x1024)
            0x48, 0x8d, 0x05, 0xd5, 0x0f, 0x00, 0x00, // lea rax, [0x2000] (next 0x102b)
            0x48, 0x8b, 0x4c, 0x24, 0x08, // mov rcx, [rsp+8]
            0x48, 0x89, 0x01, // mov [rcx], rax
            0x48, 0x83, 0xc4, 0x18, // add rsp, 0x18
            0xc3,
        ];
        let vts: FxHashSet<u64> = [0x2000].into_iter().collect();
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &vts);
        // the first two calls get `this`, the third one an unknown value (`this` or `rsi`)
        assert_eq!(this_args(&s), [(0x1100, Src::Arg(0), 0), (0x1100, Src::Arg(0), 0)]);
        assert!(s.top_args.iter().any(|&(t, m)| t == 0x1100 && m & 1 != 0), "{:?}", s.top_args);
        assert_eq!(s.vt_stores, [(Src::Arg(0), 0, 0x2000)]);
        assert!(s.refs.contains(&0x2000));
    }

    /// A stack object is the one its first call made (its constructor, when that callee is
    /// one) until the slot is written again: a reused slot holds another object.
    #[test]
    fn a_stack_object_is_followed_through_the_reuse_of_its_slot() {
        // sub rsp, 0x28 ; mov rdi, rsp ; call 0x1100 ; mov rdi, rsp ; call 0x1200 ;
        // mov qword [rsp], 5 ; mov rdi, rsp ; call 0x1300 ; add rsp, 0x28 ; ret
        let code = [
            0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0xe7, 0xe8, 0xf4, 0x00, 0x00, 0x00, 0x48, 0x89, 0xe7, 0xe8, 0xec, 0x01, 0x00, 0x00, 0x48, 0xc7, 0x04, 0x24,
            0x05, 0x00, 0x00, 0x00, 0x48, 0x89, 0xe7, 0xe8, 0xdc, 0x02, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &FxHashSet::default());
        assert_eq!(this_args(&s), [(0x1100, Src::Stack, -0x28), (0x1200, Src::Stack, -0x28), (0x1300, Src::Stack, -0x28)]);
        // the second call gets the object the first one made; the third one another object
        assert_eq!(s.stack_ev, [(1, 0, StackEv::Made(0, 0))]);
    }

    /// Two objects a slot holds on two paths are one after the join: a vtable stored there
    /// afterwards (an inlined destructor) is the class of both.
    #[test]
    fn stack_objects_joined_at_a_merge_are_one() {
        // sub rsp, 0x28 ; test esi, esi ; je L ; mov rdi, rsp ; call 0x1100 ; jmp M ;
        // L: mov rdi, rsp ; call 0x1200 ; M: lea rax, [0x2000] ; mov [rsp], rax ; add rsp, 0x28 ; ret
        let code = [
            0x48, 0x83, 0xec, 0x28, 0x85, 0xf6, 0x74, 0x0a, 0x48, 0x89, 0xe7, 0xe8, 0xf0, 0x00, 0x00, 0x00, 0xeb, 0x08, 0x48, 0x89, 0xe7, 0xe8, 0xe6, 0x01,
            0x00, 0x00, 0x48, 0x8d, 0x05, 0xdf, 0x0f, 0x00, 0x00, 0x48, 0x89, 0x04, 0x24, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        let vts: FxHashSet<u64> = [0x2000].into_iter().collect();
        let s = summarize(&text(&code), 0x1000, code.len() as u64, &vts);
        assert_eq!(s.made_alias, [((0, 0), (1, 0))]);
        assert_eq!(s.made_vt, [(0, 0, 0x2000)]);
    }

    /// The bases of a class with several (`__vmi_class_type_info`): only those at offset 0.
    #[test]
    fn only_bases_at_offset_zero_count() {
        let mut d = vec![0u8; 0x400];
        let mut w = |at: usize, v: u64| d[at..at + 8].copy_from_slice(&v.to_le_bytes());
        // 0x2000: D (vmi) — name 0x2300, flags 0 / 2 bases: 0x2100 at 0 (public), 0x2200 at +0x10
        w(0x08, 0x2300);
        w(0x10, 2 << 32);
        w(0x18, 0x2100);
        w(0x20, 2);
        w(0x28, 0x2200);
        w(0x30, (0x10 << 8) | 2);
        // 0x2100: B1, 0x2200: B2 (no bases)
        w(0x108, 0x2310);
        w(0x208, 0x2320);
        d[0x300..0x302].copy_from_slice(b"1D");
        d[0x310..0x313].copy_from_slice(b"2B1");
        d[0x320..0x323].copy_from_slice(b"2B2");
        let mut mem = Memory::new(reargo_core::address::SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock { name: ".data.rel.ro".into(), start: 0x2000, size: d.len() as u64, flags: MemoryFlags::READ, data: Some(Arc::from(d.as_slice())) });
        assert_eq!(crate::vcall::type_info_bases(&mem, 0x2000), [0x2100]);
        assert_eq!(crate::vcall::type_info_bases(&mem, 0x2100), Vec::<u64>::new());
    }

    /// WS94: a shared library calls its own exported functions through its PLT: the stub's GOT
    /// slot is bound to the function, so the stub stands for it; the slot is no reference to
    /// the function in data (its address is not taken).
    #[test]
    fn a_plt_stub_bound_to_a_function_of_the_image_stands_for_it() {
        let mut mem = Memory::new(reargo_core::address::SpaceId(1), Endian::Little);
        let block = |name: &str, start: u64, data: Vec<u8>, flags: MemoryFlags| MemoryBlock { name: name.into(), start, size: data.len() as u64, flags, data: Some(Arc::from(data.as_slice())) };
        mem.add_block(block(".text", 0x1000, vec![0xc3; 0x200], MemoryFlags::READ | MemoryFlags::EXECUTE));
        // 0x1500: endbr64 ; bnd jmp [rip + 0x1af5] (0x3000) ; nop    0x1510: the same to 0x3008
        let mut plt = vec![0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0xf5, 0x1a, 0x00, 0x00, 0x0f, 0x1f, 0x44, 0x00, 0x00];
        plt.extend([0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0xed, 0x1a, 0x00, 0x00, 0x0f, 0x1f, 0x44, 0x00, 0x00]);
        mem.add_block(block(".plt.sec", 0x1500, plt, MemoryFlags::READ | MemoryFlags::EXECUTE));
        mem.add_block(block(".got", 0x3000, vec![0; 0x10], MemoryFlags::READ | MemoryFlags::WRITE));
        // the slot 0x3000 is bound to 0x1100 (the image's own function); 0x3008 to an import
        mem.set_dynamic_relocations(Arc::from([0x3000u64.to_le_bytes(), 8u64.to_le_bytes(), 0x1100u64.to_le_bytes()].concat().as_slice()));
        let m = plt_targets(&mem);
        assert_eq!(m.into_iter().collect::<Vec<_>>(), [(0x1500, 0x1100)]);
        assert!(!universe(&mem).taken.contains(&0x1100));
    }

    /// The join of two classes is their nearest common base.
    #[test]
    fn classes_join_at_their_nearest_common_base() {
        // 0 Shape ; 1 Circle : Shape ; 2 Square : Shape ; 3 Holder ; 4 Disc : Circle
        let h = Hierarchy { vtables: vec![0x10, 0x20, 0x30, 0x40, 0x50], bases: vec![vec![], vec![0], vec![0], vec![], vec![1, 0]] };
        assert_eq!(h.join(1, 2), Some(0));
        assert_eq!(h.join(4, 2), Some(0));
        assert_eq!(h.join(4, 1), Some(1));
        assert_eq!(h.join(1, 3), None);
        assert_eq!(h.most_derived(&[0, 1, 4]), Some(4));
        assert_eq!(h.most_derived(&[1, 2]), None);
        assert_eq!(join(&h, BOT, cls(1)), cls(1));
        assert_eq!(join(&h, cls(1), cls(2)), cls(0));
        assert_eq!(join(&h, cls(1), cls(3)), TOP);
        assert_eq!(join(&h, cls(1), TOP), TOP);
    }

    #[test]
    fn an_index_reads_back_what_it_wrote() {
        let mut idx = ThisIndex { hierarchy: Hierarchy { vtables: vec![0x10, 0x20], bases: vec![vec![], vec![0]] }, ..Default::default() };
        idx.params.insert(0x1000, [1, u32::MAX, 0, u32::MAX, u32::MAX, u32::MAX]);
        idx.rets.insert(0x1100, 0);
        idx.fields.insert((0, 8), cls(1));
        idx.members.insert((1, 0x10), cls(0));
        idx.param_fields.insert((0x1000, 1, 0x18), 1);
        idx.elements.insert((0, 0x20), cls(0));
        idx.stats.rounds = 3;
        let b = idx.to_bytes(42);
        assert_eq!(ThisIndex::from_bytes(&b, 42), Some(idx.clone()));
        assert_eq!(ThisIndex::from_bytes(&b, 43), None, "another binary");
        assert_eq!(ThisIndex::from_bytes(&b[..b.len() - 1], 42), None, "truncated");
        assert_eq!(idx.param_class(0x1000, 0), Some(0x20));
        assert_eq!(idx.param_class(0x1000, 1), None);
        assert_eq!(idx.ret_class(0x1100), Some(0x10));
        assert_eq!(idx.param_field_class(0x1000, 1, 0x18), Some(0x20));
        assert_eq!(idx.param_field_class(0x1000, 0, 0x18), None);
        assert_eq!(idx.element_class(0x10, 0x20), Some(0x10));
        assert_eq!(idx.element_class(0x20, 0x20), Some(0x10), "an element buffer of a base class");
        // a field of a base class is a field of the derived class
        assert_eq!(idx.field_class(0x20, 8), Some(0x20));
        assert_eq!(idx.field_class(0x10, 0x10), None);
    }
}
