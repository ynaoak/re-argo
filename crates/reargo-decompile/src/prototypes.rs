//! Prototypes of common C library imports (WS82).
//!
//! An import's code is not in the binary (its PLT stub jumps through the GOT), so its
//! parameters cannot be read from its body and the System V prefix rule guesses them from
//! what the caller left in the argument registers — `pthread_mutex_unlock(0xde10c20, rsi, rdx,
//! rcx, xmm0)` after a `setne sil`. For the libc / libm / pthread functions below the
//! parameter counts and the return register are known.

use reargo_core::pcode::VarnodeData;

use crate::callee_params::{ParamInfo, ReturnKind};

/// Where a prototype's return value goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ret {
    Int,
    Float,
    Void,
}

/// Integer and vector-register parameter counts and the return register of an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proto {
    pub ints: u8,
    pub floats: u8,
    pub ret: Ret,
    /// `...`: more arguments may follow the fixed ones.
    pub variadic: bool,
}

const fn p(ints: u8, floats: u8, ret: Ret) -> Proto {
    Proto { ints, floats, ret, variadic: false }
}

const fn va(ints: u8) -> Proto {
    Proto { ints, floats: 0, ret: Ret::Int, variadic: true }
}

use Ret::{Float as F, Int as I, Void as V};

/// `(name, prototype)`, sorted by name. The `long double` functions (`ldexpl`, WS89) return on
/// the x87 stack (`Void` here: neither `rax` nor `xmm0`; the lifter finds the value the caller
/// pops) and take their `long double` arguments in memory.
static PROTOTYPES: &[(&str, Proto)] = &[
    ("_Exit", p(1, 0, V)),
    ("_Unwind_Resume", p(1, 0, V)),
    ("__assert_fail", p(4, 0, V)),
    ("__cxa_atexit", p(3, 0, I)),
    ("__cxa_finalize", p(1, 0, V)),
    ("__cxa_thread_atexit_impl", p(3, 0, I)),
    ("__errno_location", p(0, 0, I)),
    ("__isoc99_sscanf", va(2)),
    ("__stack_chk_fail", p(0, 0, V)),
    ("_exit", p(1, 0, V)),
    ("abort", p(0, 0, V)),
    ("accept", p(3, 0, I)),
    ("accept4", p(4, 0, I)),
    ("access", p(2, 0, I)),
    ("acosf", p(0, 1, F)),
    ("acosl", p(0, 0, V)),
    ("aligned_alloc", p(2, 0, I)),
    ("asinf", p(0, 1, F)),
    ("asinl", p(0, 0, V)),
    ("atan2f", p(0, 2, F)),
    ("atan2l", p(0, 0, V)),
    ("atanf", p(0, 1, F)),
    ("atanl", p(0, 0, V)),
    ("atoi", p(1, 0, I)),
    ("bcmp", p(3, 0, I)),
    ("bind", p(3, 0, I)),
    ("calloc", p(2, 0, I)),
    ("cbrtf", p(0, 1, F)),
    ("ceil", p(0, 1, F)),
    ("ceilf", p(0, 1, F)),
    ("ceill", p(0, 0, V)),
    ("chmod", p(2, 0, I)),
    ("clearerr", p(1, 0, V)),
    ("clock", p(0, 0, I)),
    ("clock_gettime", p(2, 0, I)),
    ("close", p(1, 0, I)),
    ("closedir", p(1, 0, I)),
    ("connect", p(3, 0, I)),
    ("cos", p(0, 1, F)),
    ("cosf", p(0, 1, F)),
    ("cosl", p(0, 0, V)),
    ("dlclose", p(1, 0, I)),
    ("dlerror", p(0, 0, I)),
    ("dlopen", p(2, 0, I)),
    ("dlsym", p(2, 0, I)),
    ("epoll_create", p(1, 0, I)),
    ("epoll_create1", p(1, 0, I)),
    ("epoll_ctl", p(4, 0, I)),
    ("epoll_wait", p(4, 0, I)),
    ("exit", p(1, 0, V)),
    ("exp", p(0, 1, F)),
    ("exp2", p(0, 1, F)),
    ("exp2f", p(0, 1, F)),
    ("exp2l", p(0, 0, V)),
    ("expf", p(0, 1, F)),
    ("expl", p(0, 0, V)),
    ("fabsl", p(0, 0, V)),
    ("fclose", p(1, 0, I)),
    ("fcntl", va(2)),
    ("fcntl64", va(2)),
    ("fdopen", p(2, 0, I)),
    ("feof", p(1, 0, I)),
    ("ferror", p(1, 0, I)),
    ("fflush", p(1, 0, I)),
    ("fgets", p(3, 0, I)),
    ("fileno", p(1, 0, I)),
    ("floor", p(0, 1, F)),
    ("floorf", p(0, 1, F)),
    ("floorl", p(0, 0, V)),
    ("fmod", p(0, 2, F)),
    ("fmodf", p(0, 2, F)),
    ("fmodl", p(0, 0, V)),
    ("fopen", p(2, 0, I)),
    ("fopen64", p(2, 0, I)),
    ("fprintf", va(2)),
    ("fputc", p(2, 0, I)),
    ("fputs", p(2, 0, I)),
    ("fread", p(4, 0, I)),
    ("free", p(1, 0, V)),
    ("freeaddrinfo", p(1, 0, V)),
    ("freelocale", p(1, 0, V)),
    ("frexp", p(1, 1, F)),
    ("frexpl", p(1, 0, V)),
    ("fseek", p(3, 0, I)),
    ("fseeko", p(3, 0, I)),
    ("fseeko64", p(3, 0, I)),
    ("fstat", p(2, 0, I)),
    ("fstat64", p(2, 0, I)),
    ("ftell", p(1, 0, I)),
    ("ftello", p(1, 0, I)),
    ("ftruncate", p(2, 0, I)),
    ("fwrite", p(4, 0, I)),
    ("gai_strerror", p(1, 0, I)),
    ("getaddrinfo", p(4, 0, I)),
    ("getc", p(1, 0, I)),
    ("getentropy", p(2, 0, I)),
    ("getenv", p(1, 0, I)),
    ("gethostname", p(2, 0, I)),
    ("getpagesize", p(0, 0, I)),
    ("getpeername", p(3, 0, I)),
    ("getpid", p(0, 0, I)),
    ("getsockname", p(3, 0, I)),
    ("getsockopt", p(5, 0, I)),
    ("gettimeofday", p(2, 0, I)),
    ("gmtime_r", p(2, 0, I)),
    ("hypot", p(0, 2, F)),
    ("hypotl", p(0, 0, V)),
    ("inet_ntop", p(4, 0, I)),
    ("inet_pton", p(3, 0, I)),
    ("ioctl", va(2)),
    ("isspace", p(1, 0, I)),
    ("ldexp", p(1, 1, F)),
    ("ldexpf", p(1, 1, F)),
    ("ldexpl", p(1, 0, V)),
    ("listen", p(2, 0, I)),
    ("llrintl", p(0, 0, I)),
    ("llround", p(0, 1, I)),
    ("llroundl", p(0, 0, I)),
    ("localtime_r", p(2, 0, I)),
    ("log", p(0, 1, F)),
    ("log10l", p(0, 0, V)),
    ("log2l", p(0, 0, V)),
    ("logf", p(0, 1, F)),
    ("logl", p(0, 0, V)),
    ("lrint", p(0, 1, I)),
    ("lrintl", p(0, 0, I)),
    ("lroundl", p(0, 0, I)),
    ("lseek64", p(3, 0, I)),
    ("malloc", p(1, 0, I)),
    ("malloc_usable_size", p(1, 0, I)),
    ("memchr", p(3, 0, I)),
    ("memcmp", p(3, 0, I)),
    ("memcpy", p(3, 0, I)),
    ("memmove", p(3, 0, I)),
    ("memrchr", p(3, 0, I)),
    ("memset", p(3, 0, I)),
    ("mkdir", p(2, 0, I)),
    ("mktime", p(1, 0, I)),
    ("mmap", p(6, 0, I)),
    ("modf", p(1, 1, F)),
    ("modff", p(1, 1, F)),
    ("modfl", p(1, 0, V)),
    ("munmap", p(2, 0, I)),
    ("nan", p(1, 0, F)),
    ("nanf", p(1, 0, F)),
    ("nanosleep", p(2, 0, I)),
    ("nearbyintf", p(0, 1, F)),
    ("newlocale", p(3, 0, I)),
    ("nextafter", p(0, 2, F)),
    ("nextafterf", p(0, 2, F)),
    ("open", va(2)),
    ("open64", va(2)),
    ("opendir", p(1, 0, I)),
    ("pipe", p(1, 0, I)),
    ("poll", p(3, 0, I)),
    ("posix_memalign", p(3, 0, I)),
    ("pow", p(0, 2, F)),
    ("powf", p(0, 2, F)),
    ("powl", p(0, 0, V)),
    ("printf", va(1)),
    ("pthread_attr_destroy", p(1, 0, I)),
    ("pthread_attr_init", p(1, 0, I)),
    ("pthread_attr_setdetachstate", p(2, 0, I)),
    ("pthread_attr_setschedparam", p(2, 0, I)),
    ("pthread_attr_setstacksize", p(2, 0, I)),
    ("pthread_cond_broadcast", p(1, 0, I)),
    ("pthread_cond_clockwait", p(4, 0, I)),
    ("pthread_cond_destroy", p(1, 0, I)),
    ("pthread_cond_init", p(2, 0, I)),
    ("pthread_cond_signal", p(1, 0, I)),
    ("pthread_cond_timedwait", p(3, 0, I)),
    ("pthread_cond_wait", p(2, 0, I)),
    ("pthread_condattr_destroy", p(1, 0, I)),
    ("pthread_condattr_init", p(1, 0, I)),
    ("pthread_condattr_setclock", p(2, 0, I)),
    ("pthread_create", p(4, 0, I)),
    ("pthread_detach", p(1, 0, I)),
    ("pthread_getschedparam", p(3, 0, I)),
    ("pthread_getspecific", p(1, 0, I)),
    ("pthread_join", p(2, 0, I)),
    ("pthread_key_create", p(2, 0, I)),
    ("pthread_key_delete", p(1, 0, I)),
    ("pthread_kill", p(2, 0, I)),
    ("pthread_mutex_destroy", p(1, 0, I)),
    ("pthread_mutex_init", p(2, 0, I)),
    ("pthread_mutex_lock", p(1, 0, I)),
    ("pthread_mutex_trylock", p(1, 0, I)),
    ("pthread_mutex_unlock", p(1, 0, I)),
    ("pthread_mutexattr_destroy", p(1, 0, I)),
    ("pthread_mutexattr_init", p(1, 0, I)),
    ("pthread_mutexattr_settype", p(2, 0, I)),
    ("pthread_once", p(2, 0, I)),
    ("pthread_rwlock_destroy", p(1, 0, I)),
    ("pthread_rwlock_init", p(2, 0, I)),
    ("pthread_rwlock_rdlock", p(1, 0, I)),
    ("pthread_rwlock_unlock", p(1, 0, I)),
    ("pthread_rwlock_wrlock", p(1, 0, I)),
    ("pthread_self", p(0, 0, I)),
    ("pthread_setname_np", p(2, 0, I)),
    ("pthread_setschedparam", p(3, 0, I)),
    ("pthread_setspecific", p(2, 0, I)),
    ("pthread_sigmask", p(3, 0, I)),
    ("qsort", p(4, 0, V)),
    ("rand", p(0, 0, I)),
    ("read", p(3, 0, I)),
    ("readdir", p(1, 0, I)),
    ("readdir64", p(1, 0, I)),
    ("readlink", p(3, 0, I)),
    ("realloc", p(2, 0, I)),
    ("reallocarray", p(3, 0, I)),
    ("realpath", p(2, 0, I)),
    ("recv", p(4, 0, I)),
    ("recvfrom", p(6, 0, I)),
    ("remove", p(1, 0, I)),
    ("rename", p(2, 0, I)),
    ("rmdir", p(1, 0, I)),
    ("round", p(0, 1, F)),
    ("roundf", p(0, 1, F)),
    ("roundl", p(0, 0, V)),
    ("scalbnl", p(1, 0, V)),
    ("sched_yield", p(0, 0, I)),
    ("secure_getenv", p(1, 0, I)),
    ("select", p(5, 0, I)),
    ("send", p(4, 0, I)),
    ("sendto", p(6, 0, I)),
    ("setbuf", p(2, 0, V)),
    ("setlocale", p(2, 0, I)),
    ("setsockopt", p(5, 0, I)),
    ("setvbuf", p(4, 0, I)),
    ("shutdown", p(2, 0, I)),
    ("sigaction", p(3, 0, I)),
    ("sigaddset", p(2, 0, I)),
    ("sigemptyset", p(1, 0, I)),
    ("sigfillset", p(1, 0, I)),
    ("signal", p(2, 0, I)),
    ("sin", p(0, 1, F)),
    ("sinf", p(0, 1, F)),
    ("sinl", p(0, 0, V)),
    ("snprintf", va(3)),
    ("socket", p(3, 0, I)),
    ("sprintf", va(2)),
    ("sqrt", p(0, 1, F)),
    ("sqrtf", p(0, 1, F)),
    ("sqrtl", p(0, 0, V)),
    ("srand", p(1, 0, V)),
    ("stat", p(2, 0, I)),
    ("stat64", p(2, 0, I)),
    ("statvfs", p(2, 0, I)),
    ("strcasecmp", p(2, 0, I)),
    ("strcat", p(2, 0, I)),
    ("strchr", p(2, 0, I)),
    ("strcmp", p(2, 0, I)),
    ("strcpy", p(2, 0, I)),
    ("strcspn", p(2, 0, I)),
    ("strdup", p(1, 0, I)),
    ("strerror", p(1, 0, I)),
    ("strerror_r", p(3, 0, I)),
    ("strlen", p(1, 0, I)),
    ("strncasecmp", p(3, 0, I)),
    ("strncat", p(3, 0, I)),
    ("strncmp", p(3, 0, I)),
    ("strncpy", p(3, 0, I)),
    ("strnlen", p(2, 0, I)),
    ("strpbrk", p(2, 0, I)),
    ("strrchr", p(2, 0, I)),
    ("strspn", p(2, 0, I)),
    ("strstr", p(2, 0, I)),
    ("strtod", p(2, 0, F)),
    ("strtof", p(2, 0, F)),
    ("strtol", p(3, 0, I)),
    ("strtold", p(2, 0, V)),
    ("strtoll", p(3, 0, I)),
    ("strtoul", p(3, 0, I)),
    ("strtoull", p(3, 0, I)),
    ("swprintf", va(3)),
    ("syscall", va(1)),
    ("sysconf", p(1, 0, I)),
    ("sysinfo", p(1, 0, I)),
    ("tanl", p(0, 0, V)),
    ("time", p(1, 0, I)),
    ("tolower", p(1, 0, I)),
    ("trunc", p(0, 1, F)),
    ("truncf", p(0, 1, F)),
    ("truncl", p(0, 0, V)),
    ("uname", p(1, 0, I)),
    ("ungetc", p(2, 0, I)),
    ("unlink", p(1, 0, I)),
    ("uselocale", p(1, 0, I)),
    ("vasprintf", p(3, 0, I)),
    ("vfprintf", p(3, 0, I)),
    ("vsnprintf", p(4, 0, I)),
    ("wcslen", p(1, 0, I)),
    ("wcstod", p(2, 0, F)),
    ("wcstof", p(2, 0, F)),
    ("wcstol", p(3, 0, I)),
    ("wcstold", p(2, 0, V)),
    ("wcstoll", p(3, 0, I)),
    ("wcstoul", p(3, 0, I)),
    ("wcstoull", p(3, 0, I)),
    ("wmemchr", p(3, 0, I)),
    ("wmemcmp", p(3, 0, I)),
    ("write", p(3, 0, I)),
];

/// The prototype of the import named `name` (`memset@plt`, `pthread_mutex_lock@GLIBC_2.2.5`
/// and `memset` all name `memset`).
pub fn import_prototype(name: &str) -> Option<Proto> {
    let base = name.split('@').next().unwrap_or(name);
    PROTOTYPES.binary_search_by(|(n, _)| (*n).cmp(base)).ok().map(|i| PROTOTYPES[i].1)
}

impl Proto {
    /// The parameter mask over the convention's argument registers `args` (8-byte registers
    /// take the integer parameters in order, wider ones the vector parameters).
    pub fn params(&self, args: &[VarnodeData]) -> ParamInfo {
        let (mut ints, mut floats, mut mask) = (0u8, 0u8, 0u32);
        for (i, a) in args.iter().enumerate().take(32) {
            let take = if a.size <= 8 {
                ints += 1;
                ints <= self.ints
            } else {
                floats += 1;
                floats <= self.floats
            };
            if take {
                mask |= 1 << i;
            }
        }
        ParamInfo { mask, complete: !self.variadic }
    }

    pub fn return_kind(&self) -> Option<ReturnKind> {
        match self.ret {
            Ret::Int => Some(ReturnKind::Int),
            Ret::Float => Some(ReturnKind::Float),
            Ret::Void => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::SpaceId;

    #[test]
    fn table_is_sorted_for_binary_search() {
        for w in PROTOTYPES.windows(2) {
            assert!(w[0].0 < w[1].0, "{} !< {}", w[0].0, w[1].0);
        }
    }

    #[test]
    fn plt_and_versioned_names_resolve() {
        assert_eq!(import_prototype("pthread_mutex_unlock@plt").map(|p| p.ints), Some(1));
        assert_eq!(import_prototype("memset@GLIBC_2.2.5").map(|p| p.ints), Some(3));
        assert_eq!(import_prototype("sqrtf").map(|p| (p.floats, p.ret)), Some((1, Ret::Float)));
        assert!(import_prototype("FUN_1234").is_none());
    }

    #[test]
    fn mask_counts_each_register_class() {
        let reg = |off, size| VarnodeData::new(SpaceId::REGISTER, off, size);
        let args = [reg(0x38, 8), reg(0x30, 8), reg(0x10, 8), reg(0x1200, 16), reg(0x1210, 16)];
        assert_eq!(import_prototype("ldexpf").unwrap().params(&args).mask, 0b01001);
        let memcpy = import_prototype("memcpy").unwrap().params(&args);
        assert_eq!((memcpy.mask, memcpy.complete), (0b00111, true));
        assert!(!import_prototype("printf").unwrap().params(&args).complete);
    }
}
