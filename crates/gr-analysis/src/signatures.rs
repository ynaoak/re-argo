use std::collections::BTreeMap;

use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<(String, String)>,
    pub calling_convention: Option<String>,
    pub library: String,
    pub no_return: bool,
}

#[derive(Debug, Default)]
pub struct SignatureDatabase {
    by_pattern: BTreeMap<Vec<u8>, FunctionSignature>,
    by_name: BTreeMap<String, FunctionSignature>,
}

macro_rules! sig {
    ($name:expr, $ret:expr, [$($pname:expr => $ptype:expr),*], $lib:expr) => {
        ($name, $ret, &[$(($pname, $ptype)),*][..], $lib, false)
    };
    ($name:expr, $ret:expr, [$($pname:expr => $ptype:expr),*], $lib:expr, noreturn) => {
        ($name, $ret, &[$(($pname, $ptype)),*][..], $lib, true)
    };
}

impl SignatureDatabase {
    pub fn new() -> Self {
        let mut db = Self::default();
        db.load_builtins();
        db
    }

    fn load_builtins(&mut self) {
        // Each entry: (name, return_type, params, library, no_return)
        // Sources: IDA TIL (libc.til, mssdk.til), Binary Ninja type libraries,
        //          glibc headers, POSIX.1-2017, Win32 SDK
        let sigs: &[(&str, &str, &[(&str, &str)], &str, bool)] = &[
            // ── stdio.h ────────────────────────────────────────────────────────────
            sig!("printf",    "int",    ["format" => "const char*"],                                     "libc"),
            sig!("fprintf",   "int",    ["stream" => "FILE*", "format" => "const char*"],                "libc"),
            sig!("sprintf",   "int",    ["buf" => "char*", "format" => "const char*"],                   "libc"),
            sig!("snprintf",  "int",    ["buf" => "char*", "size" => "size_t", "format" => "const char*"], "libc"),
            sig!("vprintf",   "int",    ["format" => "const char*", "ap" => "va_list"],                  "libc"),
            sig!("vfprintf",  "int",    ["stream" => "FILE*", "format" => "const char*", "ap" => "va_list"], "libc"),
            sig!("vsprintf",  "int",    ["buf" => "char*", "format" => "const char*", "ap" => "va_list"], "libc"),
            sig!("vsnprintf", "int",    ["buf" => "char*", "size" => "size_t", "format" => "const char*", "ap" => "va_list"], "libc"),
            sig!("puts",      "int",    ["s" => "const char*"],                                          "libc"),
            sig!("fputs",     "int",    ["s" => "const char*", "stream" => "FILE*"],                     "libc"),
            sig!("putchar",   "int",    ["c" => "int"],                                                  "libc"),
            sig!("fputc",     "int",    ["c" => "int", "stream" => "FILE*"],                             "libc"),
            sig!("getchar",   "int",    [],                                                               "libc"),
            sig!("fgetc",     "int",    ["stream" => "FILE*"],                                           "libc"),
            sig!("fgets",     "char*",  ["buf" => "char*", "n" => "int", "stream" => "FILE*"],           "libc"),
            sig!("gets",      "char*",  ["buf" => "char*"],                                              "libc"),
            sig!("scanf",     "int",    ["format" => "const char*"],                                     "libc"),
            sig!("fscanf",    "int",    ["stream" => "FILE*", "format" => "const char*"],                "libc"),
            sig!("sscanf",    "int",    ["buf" => "const char*", "format" => "const char*"],             "libc"),
            sig!("fopen",     "FILE*",  ["path" => "const char*", "mode" => "const char*"],              "libc"),
            sig!("fclose",    "int",    ["fp" => "FILE*"],                                               "libc"),
            sig!("fread",     "size_t", ["buf" => "void*", "size" => "size_t", "count" => "size_t", "fp" => "FILE*"], "libc"),
            sig!("fwrite",    "size_t", ["buf" => "const void*", "size" => "size_t", "count" => "size_t", "fp" => "FILE*"], "libc"),
            sig!("fseek",     "int",    ["fp" => "FILE*", "offset" => "long", "whence" => "int"],        "libc"),
            sig!("ftell",     "long",   ["fp" => "FILE*"],                                               "libc"),
            sig!("rewind",    "void",   ["fp" => "FILE*"],                                               "libc"),
            sig!("fflush",    "int",    ["fp" => "FILE*"],                                               "libc"),
            sig!("feof",      "int",    ["fp" => "FILE*"],                                               "libc"),
            sig!("ferror",    "int",    ["fp" => "FILE*"],                                               "libc"),
            sig!("clearerr",  "void",   ["fp" => "FILE*"],                                               "libc"),
            sig!("ftruncate", "int",    ["fd" => "int", "length" => "off_t"],                            "libc"),
            sig!("fileno",    "int",    ["fp" => "FILE*"],                                               "libc"),
            sig!("tmpfile",   "FILE*",  [],                                                               "libc"),
            sig!("perror",    "void",   ["s" => "const char*"],                                          "libc"),
            sig!("remove",    "int",    ["path" => "const char*"],                                       "libc"),
            sig!("rename",    "int",    ["oldpath" => "const char*", "newpath" => "const char*"],        "libc"),

            // ── stdlib.h ───────────────────────────────────────────────────────────
            sig!("malloc",    "void*",  ["size" => "size_t"],                                            "libc"),
            sig!("calloc",    "void*",  ["nmemb" => "size_t", "size" => "size_t"],                      "libc"),
            sig!("realloc",   "void*",  ["ptr" => "void*", "size" => "size_t"],                         "libc"),
            sig!("free",      "void",   ["ptr" => "void*"],                                              "libc"),
            sig!("exit",      "void",   ["status" => "int"],                                             "libc", noreturn),
            sig!("_exit",     "void",   ["status" => "int"],                                             "libc", noreturn),
            sig!("_Exit",     "void",   ["status" => "int"],                                             "libc", noreturn),
            sig!("quick_exit","void",   ["status" => "int"],                                             "libc", noreturn),
            sig!("abort",     "void",   [],                                                               "libc", noreturn),
            sig!("atexit",    "int",    ["func" => "void(*)(void)"],                                     "libc"),
            sig!("at_quick_exit","int", ["func" => "void(*)(void)"],                                     "libc"),
            sig!("atoi",      "int",    ["s" => "const char*"],                                          "libc"),
            sig!("atol",      "long",   ["s" => "const char*"],                                          "libc"),
            sig!("atoll",     "long long", ["s" => "const char*"],                                       "libc"),
            sig!("atof",      "double", ["s" => "const char*"],                                          "libc"),
            sig!("strtol",    "long",   ["s" => "const char*", "endptr" => "char**", "base" => "int"],  "libc"),
            sig!("strtoul",   "unsigned long", ["s" => "const char*", "endptr" => "char**", "base" => "int"], "libc"),
            sig!("strtoll",   "long long", ["s" => "const char*", "endptr" => "char**", "base" => "int"], "libc"),
            sig!("strtoull",  "unsigned long long", ["s" => "const char*", "endptr" => "char**", "base" => "int"], "libc"),
            sig!("strtod",    "double", ["s" => "const char*", "endptr" => "char**"],                   "libc"),
            sig!("strtof",    "float",  ["s" => "const char*", "endptr" => "char**"],                   "libc"),
            sig!("getenv",    "char*",  ["name" => "const char*"],                                       "libc"),
            sig!("putenv",    "int",    ["string" => "char*"],                                           "libc"),
            sig!("setenv",    "int",    ["name" => "const char*", "value" => "const char*", "overwrite" => "int"], "libc"),
            sig!("unsetenv",  "int",    ["name" => "const char*"],                                       "libc"),
            sig!("system",    "int",    ["command" => "const char*"],                                    "libc"),
            sig!("rand",      "int",    [],                                                               "libc"),
            sig!("srand",     "void",   ["seed" => "unsigned int"],                                      "libc"),
            sig!("abs",       "int",    ["x" => "int"],                                                  "libc"),
            sig!("labs",      "long",   ["x" => "long"],                                                 "libc"),
            sig!("llabs",     "long long", ["x" => "long long"],                                         "libc"),
            sig!("qsort",     "void",   ["base" => "void*", "nmemb" => "size_t", "size" => "size_t", "compar" => "int(*)(const void*,const void*)"], "libc"),
            sig!("bsearch",   "void*",  ["key" => "const void*", "base" => "const void*", "nmemb" => "size_t", "size" => "size_t", "compar" => "int(*)(const void*,const void*)"], "libc"),

            // ── string.h ───────────────────────────────────────────────────────────
            sig!("memcpy",    "void*",  ["dst" => "void*", "src" => "const void*", "n" => "size_t"],    "libc"),
            sig!("memmove",   "void*",  ["dst" => "void*", "src" => "const void*", "n" => "size_t"],    "libc"),
            sig!("memset",    "void*",  ["s" => "void*", "c" => "int", "n" => "size_t"],                "libc"),
            sig!("memcmp",    "int",    ["s1" => "const void*", "s2" => "const void*", "n" => "size_t"], "libc"),
            sig!("memchr",    "void*",  ["s" => "const void*", "c" => "int", "n" => "size_t"],          "libc"),
            sig!("strlen",    "size_t", ["s" => "const char*"],                                          "libc"),
            sig!("strnlen",   "size_t", ["s" => "const char*", "maxlen" => "size_t"],                   "libc"),
            sig!("strcmp",    "int",    ["s1" => "const char*", "s2" => "const char*"],                  "libc"),
            sig!("strncmp",   "int",    ["s1" => "const char*", "s2" => "const char*", "n" => "size_t"], "libc"),
            sig!("strcasecmp","int",    ["s1" => "const char*", "s2" => "const char*"],                  "libc"),
            sig!("strncasecmp","int",   ["s1" => "const char*", "s2" => "const char*", "n" => "size_t"], "libc"),
            sig!("strcpy",    "char*",  ["dst" => "char*", "src" => "const char*"],                      "libc"),
            sig!("strncpy",   "char*",  ["dst" => "char*", "src" => "const char*", "n" => "size_t"],    "libc"),
            sig!("strcat",    "char*",  ["dst" => "char*", "src" => "const char*"],                      "libc"),
            sig!("strncat",   "char*",  ["dst" => "char*", "src" => "const char*", "n" => "size_t"],    "libc"),
            sig!("strchr",    "char*",  ["s" => "const char*", "c" => "int"],                            "libc"),
            sig!("strrchr",   "char*",  ["s" => "const char*", "c" => "int"],                            "libc"),
            sig!("strstr",    "char*",  ["haystack" => "const char*", "needle" => "const char*"],        "libc"),
            sig!("strtok",    "char*",  ["s" => "char*", "delim" => "const char*"],                      "libc"),
            sig!("strtok_r",  "char*",  ["s" => "char*", "delim" => "const char*", "saveptr" => "char**"], "libc"),
            sig!("strdup",    "char*",  ["s" => "const char*"],                                          "libc"),
            sig!("strndup",   "char*",  ["s" => "const char*", "n" => "size_t"],                        "libc"),
            sig!("strerror",  "char*",  ["errnum" => "int"],                                             "libc"),
            sig!("strerror_r","int",    ["errnum" => "int", "buf" => "char*", "buflen" => "size_t"],     "libc"),
            sig!("strspn",    "size_t", ["s" => "const char*", "accept" => "const char*"],               "libc"),
            sig!("strcspn",   "size_t", ["s" => "const char*", "reject" => "const char*"],               "libc"),
            sig!("strpbrk",   "char*",  ["s" => "const char*", "accept" => "const char*"],               "libc"),

            // ── unistd.h / POSIX I/O ──────────────────────────────────────────────
            sig!("open",      "int",    ["path" => "const char*", "flags" => "int"],                     "libc"),
            sig!("close",     "int",    ["fd" => "int"],                                                 "libc"),
            sig!("read",      "ssize_t", ["fd" => "int", "buf" => "void*", "count" => "size_t"],         "libc"),
            sig!("write",     "ssize_t", ["fd" => "int", "buf" => "const void*", "count" => "size_t"],   "libc"),
            sig!("lseek",     "off_t",  ["fd" => "int", "offset" => "off_t", "whence" => "int"],         "libc"),
            sig!("dup",       "int",    ["fd" => "int"],                                                 "libc"),
            sig!("dup2",      "int",    ["oldfd" => "int", "newfd" => "int"],                            "libc"),
            sig!("pipe",      "int",    ["pipefd" => "int[2]"],                                          "libc"),
            sig!("access",    "int",    ["path" => "const char*", "mode" => "int"],                      "libc"),
            sig!("unlink",    "int",    ["path" => "const char*"],                                       "libc"),
            sig!("rmdir",     "int",    ["path" => "const char*"],                                       "libc"),
            sig!("mkdir",     "int",    ["path" => "const char*", "mode" => "mode_t"],                   "libc"),
            sig!("chdir",     "int",    ["path" => "const char*"],                                       "libc"),
            sig!("getcwd",    "char*",  ["buf" => "char*", "size" => "size_t"],                          "libc"),
            sig!("getpid",    "pid_t",  [],                                                               "libc"),
            sig!("getppid",   "pid_t",  [],                                                               "libc"),
            sig!("getuid",    "uid_t",  [],                                                               "libc"),
            sig!("geteuid",   "uid_t",  [],                                                               "libc"),
            sig!("getgid",    "gid_t",  [],                                                               "libc"),
            sig!("fork",      "pid_t",  [],                                                               "libc"),
            sig!("execve",    "int",    ["path" => "const char*", "argv" => "char* const[]", "envp" => "char* const[]"], "libc"),
            sig!("execvp",    "int",    ["file" => "const char*", "argv" => "char* const[]"],            "libc"),
            sig!("waitpid",   "pid_t",  ["pid" => "pid_t", "status" => "int*", "options" => "int"],      "libc"),
            sig!("kill",      "int",    ["pid" => "pid_t", "sig" => "int"],                               "libc"),
            sig!("signal",    "void(*)(int)", ["signum" => "int", "handler" => "void(*)(int)"],           "libc"),
            sig!("raise",     "int",    ["sig" => "int"],                                                 "libc"),
            sig!("sleep",     "unsigned int", ["seconds" => "unsigned int"],                              "libc"),
            sig!("usleep",    "int",    ["usec" => "useconds_t"],                                        "libc"),
            sig!("nanosleep", "int",    ["req" => "const struct timespec*", "rem" => "struct timespec*"], "libc"),

            // ── socket / network ──────────────────────────────────────────────────
            sig!("socket",    "int",    ["domain" => "int", "type" => "int", "protocol" => "int"],       "libc"),
            sig!("bind",      "int",    ["sockfd" => "int", "addr" => "const struct sockaddr*", "addrlen" => "socklen_t"], "libc"),
            sig!("listen",    "int",    ["sockfd" => "int", "backlog" => "int"],                          "libc"),
            sig!("accept",    "int",    ["sockfd" => "int", "addr" => "struct sockaddr*", "addrlen" => "socklen_t*"], "libc"),
            sig!("connect",   "int",    ["sockfd" => "int", "addr" => "const struct sockaddr*", "addrlen" => "socklen_t"], "libc"),
            sig!("send",      "ssize_t", ["sockfd" => "int", "buf" => "const void*", "len" => "size_t", "flags" => "int"], "libc"),
            sig!("recv",      "ssize_t", ["sockfd" => "int", "buf" => "void*", "len" => "size_t", "flags" => "int"], "libc"),
            sig!("sendto",    "ssize_t", ["sockfd" => "int", "buf" => "const void*", "len" => "size_t", "flags" => "int", "dest" => "const struct sockaddr*", "addrlen" => "socklen_t"], "libc"),
            sig!("recvfrom",  "ssize_t", ["sockfd" => "int", "buf" => "void*", "len" => "size_t", "flags" => "int", "src" => "struct sockaddr*", "addrlen" => "socklen_t*"], "libc"),
            sig!("setsockopt","int",    ["sockfd" => "int", "level" => "int", "optname" => "int", "optval" => "const void*", "optlen" => "socklen_t"], "libc"),
            sig!("getsockopt","int",    ["sockfd" => "int", "level" => "int", "optname" => "int", "optval" => "void*", "optlen" => "socklen_t*"], "libc"),
            sig!("shutdown",  "int",    ["sockfd" => "int", "how" => "int"],                              "libc"),
            sig!("getaddrinfo","int",   ["node" => "const char*", "service" => "const char*", "hints" => "const struct addrinfo*", "res" => "struct addrinfo**"], "libc"),
            sig!("freeaddrinfo","void", ["res" => "struct addrinfo*"],                                    "libc"),
            sig!("getnameinfo","int",   ["addr" => "const struct sockaddr*", "addrlen" => "socklen_t", "host" => "char*", "hostlen" => "socklen_t", "serv" => "char*", "servlen" => "socklen_t", "flags" => "int"], "libc"),

            // ── pthread ───────────────────────────────────────────────────────────
            sig!("pthread_create",   "int",  ["thread" => "pthread_t*", "attr" => "const pthread_attr_t*", "start" => "void*(*)(void*)", "arg" => "void*"], "libc"),
            sig!("pthread_join",     "int",  ["thread" => "pthread_t", "retval" => "void**"],             "libc"),
            sig!("pthread_detach",   "int",  ["thread" => "pthread_t"],                                   "libc"),
            sig!("pthread_exit",     "void", ["retval" => "void*"],                                       "libc", noreturn),
            sig!("pthread_cancel",   "int",  ["thread" => "pthread_t"],                                   "libc"),
            sig!("pthread_self",     "pthread_t", [],                                                     "libc"),
            sig!("pthread_mutex_init","int", ["mutex" => "pthread_mutex_t*", "attr" => "const pthread_mutexattr_t*"], "libc"),
            sig!("pthread_mutex_lock","int", ["mutex" => "pthread_mutex_t*"],                             "libc"),
            sig!("pthread_mutex_trylock","int", ["mutex" => "pthread_mutex_t*"],                          "libc"),
            sig!("pthread_mutex_unlock","int", ["mutex" => "pthread_mutex_t*"],                           "libc"),
            sig!("pthread_mutex_destroy","int", ["mutex" => "pthread_mutex_t*"],                          "libc"),
            sig!("pthread_cond_init","int",  ["cond" => "pthread_cond_t*", "attr" => "const pthread_condattr_t*"], "libc"),
            sig!("pthread_cond_wait","int",  ["cond" => "pthread_cond_t*", "mutex" => "pthread_mutex_t*"], "libc"),
            sig!("pthread_cond_signal","int",["cond" => "pthread_cond_t*"],                               "libc"),
            sig!("pthread_cond_broadcast","int",["cond" => "pthread_cond_t*"],                            "libc"),
            sig!("pthread_cond_destroy","int",["cond" => "pthread_cond_t*"],                              "libc"),
            sig!("pthread_rwlock_init","int",["rwlock" => "pthread_rwlock_t*", "attr" => "const pthread_rwlockattr_t*"], "libc"),
            sig!("pthread_rwlock_rdlock","int",["rwlock" => "pthread_rwlock_t*"],                         "libc"),
            sig!("pthread_rwlock_wrlock","int",["rwlock" => "pthread_rwlock_t*"],                         "libc"),
            sig!("pthread_rwlock_unlock","int",["rwlock" => "pthread_rwlock_t*"],                         "libc"),
            sig!("pthread_rwlock_destroy","int",["rwlock" => "pthread_rwlock_t*"],                        "libc"),

            // ── math.h ────────────────────────────────────────────────────────────
            sig!("sin",   "double", ["x" => "double"], "libm"),
            sig!("cos",   "double", ["x" => "double"], "libm"),
            sig!("tan",   "double", ["x" => "double"], "libm"),
            sig!("asin",  "double", ["x" => "double"], "libm"),
            sig!("acos",  "double", ["x" => "double"], "libm"),
            sig!("atan",  "double", ["x" => "double"], "libm"),
            sig!("atan2", "double", ["y" => "double", "x" => "double"], "libm"),
            sig!("sinh",  "double", ["x" => "double"], "libm"),
            sig!("cosh",  "double", ["x" => "double"], "libm"),
            sig!("tanh",  "double", ["x" => "double"], "libm"),
            sig!("exp",   "double", ["x" => "double"], "libm"),
            sig!("log",   "double", ["x" => "double"], "libm"),
            sig!("log2",  "double", ["x" => "double"], "libm"),
            sig!("log10", "double", ["x" => "double"], "libm"),
            sig!("pow",   "double", ["x" => "double", "y" => "double"], "libm"),
            sig!("sqrt",  "double", ["x" => "double"], "libm"),
            sig!("cbrt",  "double", ["x" => "double"], "libm"),
            sig!("ceil",  "double", ["x" => "double"], "libm"),
            sig!("floor", "double", ["x" => "double"], "libm"),
            sig!("round", "double", ["x" => "double"], "libm"),
            sig!("fabs",  "double", ["x" => "double"], "libm"),
            sig!("fmod",  "double", ["x" => "double", "y" => "double"], "libm"),
            sig!("frexp", "double", ["x" => "double", "exp" => "int*"], "libm"),
            sig!("ldexp", "double", ["x" => "double", "exp" => "int"], "libm"),
            sig!("modf",  "double", ["x" => "double", "iptr" => "double*"], "libm"),
            sig!("hypot", "double", ["x" => "double", "y" => "double"], "libm"),

            // ── time.h ────────────────────────────────────────────────────────────
            sig!("time",      "time_t",  ["t" => "time_t*"],                                              "libc"),
            sig!("clock",     "clock_t", [],                                                              "libc"),
            sig!("difftime",  "double",  ["time1" => "time_t", "time0" => "time_t"],                     "libc"),
            sig!("mktime",    "time_t",  ["tm" => "struct tm*"],                                          "libc"),
            sig!("gmtime",    "struct tm*", ["t" => "const time_t*"],                                     "libc"),
            sig!("localtime", "struct tm*", ["t" => "const time_t*"],                                     "libc"),
            sig!("strftime",  "size_t",  ["s" => "char*", "max" => "size_t", "format" => "const char*", "tm" => "const struct tm*"], "libc"),
            sig!("gettimeofday","int",   ["tv" => "struct timeval*", "tz" => "struct timezone*"],         "libc"),
            sig!("clock_gettime","int",  ["clk_id" => "clockid_t", "tp" => "struct timespec*"],          "libc"),

            // ── memory management (non-libc but common) ───────────────────────────
            sig!("mmap",   "void*",  ["addr" => "void*", "length" => "size_t", "prot" => "int", "flags" => "int", "fd" => "int", "offset" => "off_t"], "libc"),
            sig!("munmap", "int",    ["addr" => "void*", "length" => "size_t"],                           "libc"),
            sig!("mprotect","int",   ["addr" => "void*", "len" => "size_t", "prot" => "int"],             "libc"),
            sig!("brk",    "int",    ["addr" => "void*"],                                                  "libc"),
            sig!("sbrk",   "void*",  ["increment" => "intptr_t"],                                         "libc"),
            sig!("posix_memalign","int", ["memptr" => "void**", "alignment" => "size_t", "size" => "size_t"], "libc"),
            sig!("aligned_alloc","void*", ["alignment" => "size_t", "size" => "size_t"],                  "libc"),

            // ── C++ runtime (libstdc++ / libc++) ──────────────────────────────────
            sig!("__cxa_allocate_exception", "void*",  ["thrown_size" => "size_t"],                       "libstdcxx"),
            sig!("__cxa_free_exception",     "void",   ["thrown_exception" => "void*"],                   "libstdcxx"),
            sig!("__cxa_throw",              "void",   ["thrown_exception" => "void*", "tinfo" => "std::type_info*", "dest" => "void(*)(void*)"], "libstdcxx", noreturn),
            sig!("__cxa_rethrow",            "void",   [],                                                 "libstdcxx", noreturn),
            sig!("__cxa_begin_catch",        "void*",  ["exc_obj" => "void*"],                            "libstdcxx"),
            sig!("__cxa_end_catch",          "void",   [],                                                 "libstdcxx"),
            sig!("__cxa_get_exception_ptr",  "void*",  ["exc_obj" => "void*"],                            "libstdcxx"),
            sig!("__cxa_call_unexpected",    "void",   ["exc" => "void*"],                                 "libstdcxx", noreturn),
            sig!("__cxa_bad_cast",           "void",   [],                                                 "libstdcxx", noreturn),
            sig!("__cxa_bad_typeid",         "void",   [],                                                 "libstdcxx", noreturn),
            sig!("__cxa_pure_virtual",       "void",   [],                                                 "libstdcxx", noreturn),
            sig!("__cxa_deleted_virtual",    "void",   [],                                                 "libstdcxx", noreturn),
            sig!("__cxa_demangle",           "char*",  ["mangled" => "const char*", "buf" => "char*", "n" => "size_t*", "status" => "int*"], "libstdcxx"),
            sig!("__cxa_finalize",           "void",   ["d" => "void*"],                                   "libstdcxx"),
            sig!("__cxa_atexit",             "int",    ["func" => "void(*)(void*)", "arg" => "void*", "d" => "void*"], "libstdcxx"),
            sig!("__gxx_personality_v0",     "uintptr_t", [],                                              "libstdcxx"),
            sig!("_Unwind_Resume",           "void",   ["exception" => "struct _Unwind_Exception*"],       "libstdcxx", noreturn),
            sig!("_Unwind_RaiseException",   "int",    ["exception" => "struct _Unwind_Exception*"],       "libstdcxx"),

            // ── security / canary ─────────────────────────────────────────────────
            sig!("__stack_chk_fail",   "void", [],                                                         "libc", noreturn),
            sig!("__stack_chk_guard",  "void", [],                                                         "libc"),
            sig!("__fortify_fail",     "void", ["msg" => "const char*"],                                   "libc", noreturn),
            sig!("__chk_fail",         "void", [],                                                         "libc", noreturn),

            // ── assert / diagnostic ───────────────────────────────────────────────
            sig!("__assert_fail",     "void", ["assertion" => "const char*", "file" => "const char*", "line" => "unsigned int", "function" => "const char*"], "libc", noreturn),
            sig!("__assert_perror_fail","void",["errnum" => "int", "file" => "const char*", "line" => "unsigned int", "function" => "const char*"], "libc", noreturn),
            sig!("err",   "void", ["eval" => "int", "fmt" => "const char*"],                               "libc", noreturn),
            sig!("errx",  "void", ["eval" => "int", "fmt" => "const char*"],                               "libc", noreturn),
            sig!("warn",  "void", ["fmt" => "const char*"],                                                 "libc"),
            sig!("warnx", "void", ["fmt" => "const char*"],                                                 "libc"),

            // ── longjmp (BN-tagged no-return on the throw side) ───────────────────
            sig!("longjmp",    "void", ["env" => "jmp_buf", "val" => "int"],                               "libc", noreturn),
            sig!("siglongjmp", "void", ["env" => "sigjmp_buf", "val" => "int"],                            "libc", noreturn),
            sig!("_longjmp",   "void", ["env" => "jmp_buf", "val" => "int"],                               "libc", noreturn),
            sig!("setjmp",     "int",  ["env" => "jmp_buf"],                                               "libc"),
            sig!("sigsetjmp",  "int",  ["env" => "sigjmp_buf", "savesigs" => "int"],                       "libc"),

            // ── C11 threads ───────────────────────────────────────────────────────
            sig!("thrd_exit",   "void", ["res" => "int"],                                                  "libc", noreturn),
            sig!("thrd_create", "int",  ["thr" => "thrd_t*", "func" => "thrd_start_t", "arg" => "void*"], "libc"),
            sig!("thrd_join",   "int",  ["thr" => "thrd_t", "res" => "int*"],                             "libc"),

            // ── dynamic linking ───────────────────────────────────────────────────
            sig!("dlopen",  "void*",  ["path" => "const char*", "mode" => "int"],                          "libdl"),
            sig!("dlclose", "int",    ["handle" => "void*"],                                               "libdl"),
            sig!("dlsym",   "void*",  ["handle" => "void*", "symbol" => "const char*"],                    "libdl"),
            sig!("dlerror", "char*",  [],                                                                    "libdl"),
            sig!("dladdr",  "int",    ["addr" => "const void*", "info" => "Dl_info*"],                     "libdl"),

            // ── GLib (very common in Linux binaries) ──────────────────────────────
            sig!("g_malloc",        "gpointer", ["n_bytes" => "gsize"],                                    "glib"),
            sig!("g_malloc0",       "gpointer", ["n_bytes" => "gsize"],                                    "glib"),
            sig!("g_realloc",       "gpointer", ["mem" => "gpointer", "n_bytes" => "gsize"],               "glib"),
            sig!("g_free",          "void",     ["mem" => "gpointer"],                                     "glib"),
            sig!("g_strdup",        "gchar*",   ["str" => "const gchar*"],                                  "glib"),
            sig!("g_strndup",       "gchar*",   ["str" => "const gchar*", "n" => "gsize"],                 "glib"),
            sig!("g_strdup_printf", "gchar*",   ["format" => "const gchar*"],                              "glib"),
            sig!("g_error",         "void",     ["domain" => "GQuark", "code" => "gint", "format" => "const gchar*"], "glib", noreturn),
            sig!("g_critical",      "void",     ["format" => "const gchar*"],                              "glib"),
            sig!("g_warning",       "void",     ["format" => "const gchar*"],                              "glib"),
            sig!("g_message",       "void",     ["format" => "const gchar*"],                              "glib"),
            sig!("g_print",         "void",     ["format" => "const gchar*"],                              "glib"),
            sig!("g_printerr",      "void",     ["format" => "const gchar*"],                              "glib"),
            sig!("g_assert_warning","void",     ["log_domain" => "const char*", "file" => "const char*", "line" => "int", "pretty_function" => "const char*", "expression" => "const char*"], "glib", noreturn),

            // ── Win32 kernel32.dll ────────────────────────────────────────────────
            sig!("ExitProcess",         "void",   ["uExitCode" => "UINT"],                                                 "kernel32", noreturn),
            sig!("TerminateProcess",    "BOOL",   ["hProcess" => "HANDLE", "uExitCode" => "UINT"],                         "kernel32", noreturn),
            sig!("RaiseException",      "void",   ["dwExceptionCode" => "DWORD", "dwExceptionFlags" => "DWORD", "nNumberOfArguments" => "DWORD", "lpArguments" => "const ULONG_PTR*"], "kernel32", noreturn),
            sig!("FatalAppExitA",       "void",   ["uAction" => "UINT", "lpMessageText" => "LPCSTR"],                      "kernel32", noreturn),
            sig!("FatalAppExitW",       "void",   ["uAction" => "UINT", "lpMessageText" => "LPCWSTR"],                     "kernel32", noreturn),
            sig!("CreateFileA",         "HANDLE", ["lpFileName" => "LPCSTR", "dwDesiredAccess" => "DWORD", "dwShareMode" => "DWORD", "lpSecurityAttributes" => "LPSECURITY_ATTRIBUTES", "dwCreationDisposition" => "DWORD", "dwFlagsAndAttributes" => "DWORD", "hTemplateFile" => "HANDLE"], "kernel32"),
            sig!("CreateFileW",         "HANDLE", ["lpFileName" => "LPCWSTR", "dwDesiredAccess" => "DWORD", "dwShareMode" => "DWORD", "lpSecurityAttributes" => "LPSECURITY_ATTRIBUTES", "dwCreationDisposition" => "DWORD", "dwFlagsAndAttributes" => "DWORD", "hTemplateFile" => "HANDLE"], "kernel32"),
            sig!("ReadFile",            "BOOL",   ["hFile" => "HANDLE", "lpBuffer" => "LPVOID", "nNumberOfBytesToRead" => "DWORD", "lpNumberOfBytesRead" => "LPDWORD", "lpOverlapped" => "LPOVERLAPPED"], "kernel32"),
            sig!("WriteFile",           "BOOL",   ["hFile" => "HANDLE", "lpBuffer" => "LPCVOID", "nNumberOfBytesToWrite" => "DWORD", "lpNumberOfBytesWritten" => "LPDWORD", "lpOverlapped" => "LPOVERLAPPED"], "kernel32"),
            sig!("CloseHandle",         "BOOL",   ["hObject" => "HANDLE"],                                                 "kernel32"),
            sig!("VirtualAlloc",        "LPVOID", ["lpAddress" => "LPVOID", "dwSize" => "SIZE_T", "flAllocationType" => "DWORD", "flProtect" => "DWORD"], "kernel32"),
            sig!("VirtualFree",         "BOOL",   ["lpAddress" => "LPVOID", "dwSize" => "SIZE_T", "dwFreeType" => "DWORD"], "kernel32"),
            sig!("VirtualProtect",      "BOOL",   ["lpAddress" => "LPVOID", "dwSize" => "SIZE_T", "flNewProtect" => "DWORD", "lpflOldProtect" => "PDWORD"], "kernel32"),
            sig!("HeapAlloc",           "LPVOID", ["hHeap" => "HANDLE", "dwFlags" => "DWORD", "dwBytes" => "SIZE_T"],      "kernel32"),
            sig!("HeapFree",            "BOOL",   ["hHeap" => "HANDLE", "dwFlags" => "DWORD", "lpMem" => "LPVOID"],        "kernel32"),
            sig!("GetProcessHeap",      "HANDLE", [],                                                                       "kernel32"),
            sig!("GetLastError",        "DWORD",  [],                                                                       "kernel32"),
            sig!("SetLastError",        "void",   ["dwErrCode" => "DWORD"],                                                 "kernel32"),
            sig!("LoadLibraryA",        "HMODULE",["lpLibFileName" => "LPCSTR"],                                            "kernel32"),
            sig!("LoadLibraryW",        "HMODULE",["lpLibFileName" => "LPCWSTR"],                                           "kernel32"),
            sig!("GetProcAddress",      "FARPROC",["hModule" => "HMODULE", "lpProcName" => "LPCSTR"],                       "kernel32"),
            sig!("FreeLibrary",         "BOOL",   ["hLibModule" => "HMODULE"],                                              "kernel32"),
            sig!("CreateThread",        "HANDLE", ["lpThreadAttributes" => "LPSECURITY_ATTRIBUTES", "dwStackSize" => "SIZE_T", "lpStartAddress" => "LPTHREAD_START_ROUTINE", "lpParameter" => "LPVOID", "dwCreationFlags" => "DWORD", "lpThreadId" => "LPDWORD"], "kernel32"),
            sig!("ExitThread",          "void",   ["dwExitCode" => "DWORD"],                                                "kernel32", noreturn),
            sig!("GetCurrentThread",    "HANDLE", [],                                                                       "kernel32"),
            sig!("GetCurrentThreadId",  "DWORD",  [],                                                                       "kernel32"),
            sig!("WaitForSingleObject", "DWORD",  ["hHandle" => "HANDLE", "dwMilliseconds" => "DWORD"],                    "kernel32"),
            sig!("WaitForMultipleObjects","DWORD", ["nCount" => "DWORD", "lpHandles" => "const HANDLE*", "bWaitAll" => "BOOL", "dwMilliseconds" => "DWORD"], "kernel32"),
            sig!("GetModuleHandleA",    "HMODULE",["lpModuleName" => "LPCSTR"],                                             "kernel32"),
            sig!("GetModuleHandleW",    "HMODULE",["lpModuleName" => "LPCWSTR"],                                            "kernel32"),
            sig!("MultiByteToWideChar", "int",    ["CodePage" => "UINT", "dwFlags" => "DWORD", "lpMultiByteStr" => "LPCCH", "cbMultiByte" => "int", "lpWideCharStr" => "LPWSTR", "cchWideChar" => "int"], "kernel32"),
            sig!("WideCharToMultiByte", "int",    ["CodePage" => "UINT", "dwFlags" => "DWORD", "lpWideCharStr" => "LPCWCH", "cchWideChar" => "int", "lpMultiByteStr" => "LPSTR", "cbMultiByte" => "int", "lpDefaultChar" => "LPCCH", "lpUsedDefaultChar" => "LPBOOL"], "kernel32"),
            sig!("GetSystemInfo",       "void",   ["lpSystemInfo" => "LPSYSTEM_INFO"],                                      "kernel32"),
            sig!("GetTickCount",        "DWORD",  [],                                                                        "kernel32"),
            sig!("GetTickCount64",      "ULONGLONG", [],                                                                     "kernel32"),
            sig!("Sleep",               "void",   ["dwMilliseconds" => "DWORD"],                                             "kernel32"),
            sig!("CreateEventA",        "HANDLE", ["lpEventAttributes" => "LPSECURITY_ATTRIBUTES", "bManualReset" => "BOOL", "bInitialState" => "BOOL", "lpName" => "LPCSTR"], "kernel32"),
            sig!("SetEvent",            "BOOL",   ["hEvent" => "HANDLE"],                                                   "kernel32"),
            sig!("ResetEvent",          "BOOL",   ["hEvent" => "HANDLE"],                                                   "kernel32"),
            sig!("InitializeCriticalSection","void",["lpCriticalSection" => "LPCRITICAL_SECTION"],                          "kernel32"),
            sig!("EnterCriticalSection","void",   ["lpCriticalSection" => "LPCRITICAL_SECTION"],                            "kernel32"),
            sig!("LeaveCriticalSection","void",   ["lpCriticalSection" => "LPCRITICAL_SECTION"],                            "kernel32"),
            sig!("DeleteCriticalSection","void",  ["lpCriticalSection" => "LPCRITICAL_SECTION"],                            "kernel32"),
            sig!("OutputDebugStringA",  "void",   ["lpOutputString" => "LPCSTR"],                                           "kernel32"),
            sig!("OutputDebugStringW",  "void",   ["lpOutputString" => "LPCWSTR"],                                          "kernel32"),
            sig!("IsDebuggerPresent",   "BOOL",   [],                                                                        "kernel32"),

            // ── ntdll.dll ─────────────────────────────────────────────────────────
            sig!("RtlRaiseException",   "void",   ["ExceptionRecord" => "PEXCEPTION_RECORD"],                               "ntdll", noreturn),
            sig!("NtTerminateProcess",  "NTSTATUS",["ProcessHandle" => "HANDLE", "ExitStatus" => "NTSTATUS"],               "ntdll"),
            sig!("RtlAllocateHeap",     "PVOID",  ["HeapHandle" => "PVOID", "Flags" => "ULONG", "Size" => "SIZE_T"],        "ntdll"),
            sig!("RtlFreeHeap",         "BOOLEAN",["HeapHandle" => "PVOID", "Flags" => "ULONG", "BaseAddress" => "PVOID"],  "ntdll"),
            sig!("RtlMoveMemory",       "void",   ["Destination" => "PVOID", "Source" => "const VOID*", "Length" => "SIZE_T"], "ntdll"),
            sig!("RtlZeroMemory",       "void",   ["Destination" => "PVOID", "Length" => "SIZE_T"],                         "ntdll"),
            sig!("RtlCopyMemory",       "void",   ["Destination" => "PVOID", "Source" => "const VOID*", "Length" => "SIZE_T"], "ntdll"),
            sig!("DbgBreakPoint",       "void",   [],                                                                        "ntdll"),
        ];

        for (name, ret, params, lib, no_return) in sigs {
            let sig = FunctionSignature {
                name: name.to_string(),
                return_type: ret.to_string(),
                parameters: params.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect(),
                calling_convention: None,
                library: lib.to_string(),
                no_return: *no_return,
            };
            self.by_name.insert(name.to_string(), sig);
        }
    }

    pub fn lookup_by_name(&self, name: &str) -> Option<&FunctionSignature> {
        let clean = name
            .strip_suffix("@plt")
            .or_else(|| name.strip_suffix("@got.plt"))
            .or_else(|| name.strip_suffix("@got"))
            .unwrap_or(name);
        self.by_name.get(clean)
    }

    pub fn add_pattern(&mut self, pattern: Vec<u8>, sig: FunctionSignature) {
        self.by_pattern.insert(pattern, sig);
    }

    pub fn signature_count(&self) -> usize {
        self.by_name.len() + self.by_pattern.len()
    }

    pub fn no_return_names(&self) -> impl Iterator<Item = &str> {
        self.by_name.values().filter(|s| s.no_return).map(|s| s.name.as_str())
    }
}

pub struct SignatureApplierAnalyzer;

impl Analyzer for SignatureApplierAnalyzer {
    fn name(&self) -> &str {
        "Signature Applier"
    }
    fn description(&self) -> &str {
        "Applies known function signatures (types, parameters, no-return) from the signature database"
    }
    fn priority(&self) -> u32 {
        700
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        use std::sync::OnceLock;
        static DB: OnceLock<SignatureDatabase> = OnceLock::new();
        let db = DB.get_or_init(SignatureDatabase::new);
        let mut applied = 0;

        // Collect (addr, name) snapshot to avoid borrow conflicts
        let symbol_names: Vec<(u64, String)> = program
            .symbol_table
            .iter()
            .map(|s| (s.address, s.name.clone()))
            .collect();

        for (addr, name) in &symbol_names {
            let Some(sig) = db.lookup_by_name(name) else { continue };

            // Ensure a Function-typed symbol exists
            if program.symbol_table.get_at(*addr).iter().all(|s| s.symbol_type != SymbolType::Function) {
                program.symbol_table.add(Symbol::new(
                    name.clone(),
                    *addr,
                    SymbolType::Function,
                    SourceType::Analysis,
                ));
            }

            // Annotate the Function object if one is registered
            if let Some(func) = program.listing.get_function_mut(*addr) {
                if func.return_type.is_none() {
                    func.return_type = Some(sig.return_type.clone());
                }
                if func.parameters.is_empty() && !sig.parameters.is_empty() {
                    func.parameters = sig.parameters.clone();
                }
                if sig.no_return {
                    func.no_return = true;
                }
                if func.library.is_none() {
                    func.library = Some(sig.library.clone());
                }
                if func.calling_convention.is_none() {
                    func.calling_convention = sig.calling_convention.clone();
                }
            }

            applied += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: applied,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_signatures() {
        let db = SignatureDatabase::new();
        let printf = db.lookup_by_name("printf").unwrap();
        assert_eq!(printf.return_type, "int");
        assert_eq!(printf.parameters.len(), 1);
        assert_eq!(printf.parameters[0].1, "const char*");
    }

    #[test]
    fn plt_suffix_strip() {
        let db = SignatureDatabase::new();
        assert!(db.lookup_by_name("printf@plt").is_some());
        assert!(db.lookup_by_name("printf@got.plt").is_some());
        assert!(db.lookup_by_name("unknown_func").is_none());
    }

    #[test]
    fn no_return_flags() {
        let db = SignatureDatabase::new();
        // Core no-return set
        for name in &["exit", "_exit", "abort", "__cxa_throw", "ExitProcess",
                      "longjmp", "siglongjmp", "pthread_exit", "thrd_exit",
                      "__stack_chk_fail", "__assert_fail", "err", "errx"] {
            let sig = db.lookup_by_name(name)
                .unwrap_or_else(|| panic!("{name} not found in DB"));
            assert!(sig.no_return, "{name} should be no_return");
        }
        // Returning functions must NOT be flagged
        for name in &["malloc", "printf", "strlen", "open", "pthread_create"] {
            let sig = db.lookup_by_name(name)
                .unwrap_or_else(|| panic!("{name} not found in DB"));
            assert!(!sig.no_return, "{name} must NOT be no_return");
        }
    }

    #[test]
    fn win32_present() {
        let db = SignatureDatabase::new();
        assert!(db.lookup_by_name("CreateFileA").is_some());
        assert!(db.lookup_by_name("VirtualAlloc").is_some());
        assert!(db.lookup_by_name("ExitProcess").unwrap().no_return);
    }

    #[test]
    fn posix_present() {
        let db = SignatureDatabase::new();
        assert!(db.lookup_by_name("pthread_mutex_lock").is_some());
        assert!(db.lookup_by_name("mmap").is_some());
        assert!(db.lookup_by_name("socket").is_some());
    }

    #[test]
    fn signature_count() {
        let db = SignatureDatabase::new();
        assert!(db.signature_count() >= 200, "expected ≥200 signatures, got {}", db.signature_count());
    }

    #[test]
    fn no_return_iterator() {
        let db = SignatureDatabase::new();
        let nr: Vec<&str> = db.no_return_names().collect();
        assert!(nr.contains(&"exit"));
        assert!(nr.contains(&"pthread_exit"));
        assert!(nr.contains(&"__cxa_throw"));
        assert!(!nr.contains(&"malloc"));
    }
}
