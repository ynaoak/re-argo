pub mod analyzer;
#[cfg(test)]
mod testutil;
pub mod addrtable;
pub mod anti_debug;
pub mod arity;
pub mod authenticode;
pub mod boundary;
pub mod callingconv;
pub mod canary;
pub mod callgraph;
pub mod blockflow;
pub mod byteconst;
pub mod callsite;
pub mod callsite_annotate;
pub mod capa;
pub mod cfg_const;
pub mod complexity;
pub mod coverage;
pub mod crt;
pub mod crt_patterns;
pub mod crypto;
pub mod dataref;
pub mod deadcode;
pub mod float_const;
pub mod funcstart;
pub mod magic_div;
pub mod members;
pub mod xref_scan;
pub mod dwarf_enrich;
pub mod demangle;
pub mod discovery;
pub mod ehframe;
pub mod embedded;
pub mod entropy;
pub mod exception;
pub mod filler;
pub mod fingerprint;
pub mod floss_lite;
pub mod format_varargs;
pub mod func_lift;
pub mod got_annotate;
pub mod hot;
pub mod immstr;
pub mod imphash;
pub mod indirect;
pub mod indirect_resolve;
pub mod inline_mem;
pub mod ioc;
pub mod iterate;
pub mod loops;
pub mod macho_objc;
pub mod macho_strings;
pub mod manager;
pub mod propagation;
pub mod references;
pub mod rich_header;
pub mod rop;
pub mod stack;
pub mod linear_sweep;
pub mod vsa;
pub mod vuln;
pub mod stackstr;
pub mod tagger;
pub mod string_rename;
pub mod string_xref;
pub mod strings;
pub mod switches;
pub mod switches_v2;
pub mod noreturn_prop;
pub mod packer;
pub mod panic_like;
pub mod patterns;
pub mod pcoderef;
pub mod range_lift;
pub mod pe_enrich;
pub mod pe_seh;
pub mod rtti;
pub mod runtime_fp;
pub mod scc;
pub mod section_anomaly;
pub mod shared_lift;
pub mod signatures;
pub mod thunk;
pub mod tls;
pub mod tlsh;
pub mod typerecovery;
pub mod utils;
pub mod vtable;
pub mod wrapper;
pub mod xref_report;
pub mod yara_lite;

pub use analyzer::Analyzer;
pub use callgraph::CallGraph;
pub use manager::AnalysisManager;

/// What gives the memory the allocator holds free back to the operating
/// system, on the calling thread ([`set_release_free_memory`]).
static RELEASE_FREE_MEMORY: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Set the function that gives the memory the program's allocator holds
/// free back to the operating system, on the calling thread (with
/// mimalloc: `mi_collect(true)`). The analysis calls it on every thread
/// after a parallel phase whose threads freed much of what they had
/// allocated: an allocator that keeps freed memory for a while (to hand
/// it out again cheaply) would otherwise keep it all through the run, on
/// threads that may not allocate the same again. Unset, nothing is done.
pub fn set_release_free_memory(release: fn()) {
    let _ = RELEASE_FREE_MEMORY.set(release);
}

/// Call the function [`set_release_free_memory`] set on every thread of
/// the pool and on this one.
pub(crate) fn release_free_memory() {
    if let Some(&release) = RELEASE_FREE_MEMORY.get() {
        rayon::broadcast(|_| release());
        release();
    }
}
