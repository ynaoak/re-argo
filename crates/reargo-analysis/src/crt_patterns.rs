//! FLIRT-lite pattern recognition for compiler-generated CRT helpers.
//!
//! GCC, clang, and the linker drop a fixed set of helper functions
//! into every ELF executable:
//!
//! ```text
//!   _init
//!   _fini
//!   register_tm_clones
//!   deregister_tm_clones
//!   __do_global_dtors_aux
//!   frame_dummy
//!   __libc_csu_init        (pre-glibc-2.34)
//!   __libc_csu_fini        (pre-glibc-2.34)
//! ```
//!
//! When the binary is stripped these show up as `FUN_XXXX` and
//! anyone reading the disassembly has to recognise the prologue
//! pattern by eye. We do that automatically:
//!
//! * Iterate over functions that still have a generic `FUN_*` name.
//! * Read up to 24 bytes from the entry.
//! * Match against a small dictionary of canonical prologues.
//! * On hit, rename the function (Symbol + Listing) and add a
//!   plate comment naming the role.
//!
//! Each pattern includes its full canonical prologue (≥ 12 bytes of
//! literal-or-mask) so collisions with user code are effectively
//! impossible. This is the same flavour of recognition Hex-Rays
//! FLIRT signatures do, just without the .pat / .sig file format
//! overhead — we encode the patterns directly in Rust.

use rayon::prelude::*;
use reargo_program::comments::CommentType;
use reargo_program::function::Function;
use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Prepared, State};

pub struct CrtPatternAnalyzer;

impl Analyzer for CrtPatternAnalyzer {
    fn name(&self) -> &str {
        "CRT Pattern"
    }
    fn description(&self) -> &str {
        "Renames unidentified CRT helpers (frame_dummy, register_tm_clones, …) by prologue match"
    }
    fn priority(&self) -> u32 {
        // After Discovery (100) + ThunkDetector (450). Before
        // CallSiteAnnotator (750) so renames cascade through
        // annotation output.
        470
    }
    fn prepare_reads(&self) -> Option<State> {
        // (only the bytes: the functions are looked at in `apply`)
        Some(State::NONE)
    }
    fn writes(&self) -> State {
        // (and the results computed ahead for the functions it adds,
        // left in the analysis cache)
        State::SYMBOLS.union(State::COMMENTS).union(State::FUNCTIONS).union(State::CACHE)
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let prepared = self.prepare(program);
        self.apply(program, prepared)
    }
    /// The CRT helpers found at the 16-byte steps of the executable
    /// sections, by address, from the bytes alone (what a pattern
    /// matches at an address depends on nothing else); the functions
    /// still `FUN_*` and the ones already named are looked at in
    /// `apply`, at this analyzer's place.
    fn prepare(&self, program: &Program) -> Prepared {
        if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
            return Box::new(Found::default());
        }
        let tt = std::time::Instant::now();
        let matcher = Matcher::new();
        // Walk in 16-byte steps. The linker aligns every CRT helper to
        // 16 bytes, so a candidate that isn't on a 16-byte boundary
        // can't be one of these.
        let mut steps: Vec<u64> = Vec::new();
        for sec in &program.info.sections {
            if !sec.flags.contains(reargo_loader::SectionFlags::EXECUTE) {
                continue;
            }
            let base = sec.address;
            let end = sec.address + sec.size;
            let first = (base + 15) & !15;
            if first + 24 <= end {
                steps.extend((first..=end - 24).step_by(16));
            }
        }
        // (a few ascending runs: the stable sort merges them)
        steps.sort();
        steps.dedup();
        let found: Vec<(u64, &'static str)> = steps
            .par_iter()
            .with_min_len(4096)
            .filter_map(|&entry| matcher.at(program, entry).map(|name| (entry, name)))
            .collect();
        // The functions `apply` adds at them have no body (P-code
        // Reference and the Indirect Call Resolver lift them later, with
        // their budgets' floors): their results computed here, from the
        // bytes, with the others'.
        let entries: Vec<u64> = found.iter().map(|&(entry, _)| entry).collect();
        crate::tr!(tt, "crt steps {} found {}", steps.len(), entries.len());
        let ahead = (!entries.is_empty() && std::env::var_os("REARGO_X_NOAHEAD").is_none()).then(|| crate::stack::ahead_for_new(program, &entries));
        crate::tr!(tt, "crt ahead");
        Box::new(Found { at_steps: found, ahead })
    }
    fn apply(&self, program: &mut Program, prepared: Prepared) -> Result<AnalysisResult, AnalysisError> {
        let Found { at_steps, ahead } = crate::analyzer::prepared(prepared);
        if let Some((pcode, indirect)) = ahead {
            // (with the ones the Stack Frame analyzer computed: one of the
            // same key is the same result)
            let mut held = program.analysis_cache.take::<crate::pcoderef::Ahead>().map_or_else(Default::default, |a| a.0);
            for (k, v) in pcode {
                held.entry(k).or_insert(v);
            }
            program.analysis_cache.insert(crate::pcoderef::Ahead(held));
            if let Some(indirect) = indirect {
                let mut held =
                    program.analysis_cache.take::<crate::indirect_resolve::Ahead>().map_or_else(Default::default, |a| a.0);
                for (k, v) in indirect {
                    held.entry(k).or_insert(v);
                }
                program.analysis_cache.insert(crate::indirect_resolve::Ahead(held));
            }
        }
        if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }
        // Two scan sources, deduped:
        // (a) every existing FUN_* function — covers the common case
        //     where Discovery found the function but couldn't name it.
        // (b) 16-byte-aligned candidate offsets inside every
        //     executable section (matched in `prepare`) — covers
        //     stripped binaries where Discovery never reaches the CRT
        //     helper at all (e.g., `.init_array` is unmapped in our
        //     memory model so `frame_dummy` is never queued).
        // (both in address order, merged, each address once: its
        // pattern is the same from either)
        let matcher = Matcher::new();
        let at_functions: Vec<(u64, &'static str)> = program
            .listing
            .functions()
            .filter(|f| f.name.starts_with("FUN_"))
            .filter_map(|f| matcher.at(program, f.entry_point).map(|name| (f.entry_point, name)))
            .collect();
        let mut found: Vec<(u64, &'static str)> = Vec::with_capacity(at_steps.len() + at_functions.len());
        let (mut a, mut b) = (at_functions.into_iter().peekable(), at_steps.into_iter().peekable());
        loop {
            let next = match (a.peek(), b.peek()) {
                (Some(x), Some(y)) if x.0 == y.0 => {
                    b.next();
                    a.next()
                }
                (Some(x), Some(y)) if x.0 < y.0 => a.next(),
                (Some(_), None) => a.next(),
                _ => b.next(),
            };
            match next {
                Some(hit) => found.push(hit),
                None => break,
            }
        }
        // Skip candidates that already host a function with a
        // non-generic name (user / DWARF / earlier analyzer wins).
        found.retain(|&(entry, _)| !program.listing.get_function(entry).is_some_and(|f| !f.name.starts_with("FUN_")));
        let recovered = found.len();
        for (entry, name) in found {
            apply_rename(program, entry, name);
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: recovered,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// What [`CrtPatternAnalyzer`]'s `prepare` finds: the helpers at the
/// 16-byte steps, by address, and the results computed ahead for
/// functions there ([`crate::stack::ahead_for_new`]).
#[derive(Default)]
struct Found {
    at_steps: Vec<(u64, &'static str)>,
    ahead: Option<crate::stack::NewAhead>,
}

/// The patterns, and the first bytes one can start with.
struct Matcher {
    patterns: Vec<Pattern>,
    /// (every byte for a pattern whose first byte is masked out)
    first_byte: [bool; 256],
}

impl Matcher {
    fn new() -> Self {
        let patterns = patterns();
        let mut first_byte = [false; 256];
        for pattern in &patterns {
            match (pattern.prefix.first(), pattern.mask.first()) {
                (Some(&p), Some(&m)) if m != 0 => first_byte[p as usize] = true,
                _ => first_byte = [true; 256],
            }
        }
        Self { patterns, first_byte }
    }

    /// The name of the first pattern the bytes at `entry` match (24 read,
    /// else 16, 12 or 8).
    fn at(&self, program: &Program, entry: u64) -> Option<&'static str> {
        let mut buf = [0u8; 24];
        let n = [24, 16, 12, 8].iter().copied().find(|&n| program.info.memory.read_bytes(entry, &mut buf[..n]).is_ok())?;
        let bytes = &buf[..n];
        if !self.first_byte[bytes[0] as usize] {
            return None;
        }
        self.patterns.iter().find(|pattern| matches_pattern(bytes, pattern.prefix, pattern.mask)).map(|p| p.name)
    }
}

/// Mask-matching: `prefix[i]` must equal `bytes[i]` everywhere
/// `mask[i] == 1`. A zero in `mask` is a "don't care" position used
/// for fields that the linker fills in at link time (rip-relative
/// displacements, immediate offsets to .data, …).
fn matches_pattern(bytes: &[u8], prefix: &[u8], mask: &[u8]) -> bool {
    if bytes.len() < prefix.len() {
        return false;
    }
    debug_assert_eq!(prefix.len(), mask.len());
    prefix
        .iter()
        .zip(mask.iter())
        .enumerate()
        .all(|(i, (p, m))| *m == 0 || bytes[i] == *p)
}

fn apply_rename(program: &mut Program, addr: u64, name: &str) {
    program.symbol_table.add(Symbol::new(
        name.to_string(),
        addr,
        SymbolType::Function,
        SourceType::Analysis,
    ));
    if program.comments.get(addr, CommentType::Plate).is_none() {
        program.comments.set(
            addr,
            CommentType::Plate,
            format!("CRT helper: {}", name),
        );
    }
    if let Some(f) = program.listing.get_function_mut(addr) {
        if f.name.starts_with("FUN_") {
            f.name = name.to_string();
        }
    } else {
        program
            .listing
            .add_function(Function::new(addr, name.to_string()));
    }
}

struct Pattern {
    name: &'static str,
    prefix: &'static [u8],
    mask: &'static [u8],
}

/// Hand-curated CRT prologue signatures. Each `prefix` includes the
/// distinctive opening of the function; `mask` zeroes-out positions
/// that vary by load address (rip-relative disp32, immediates).
fn patterns() -> Vec<Pattern> {
    vec![
        // deregister_tm_clones (gcc, glibc):
        //   48 8d 3d <disp32>         lea rdi, [rip+_TMC_END_]
        //   48 8d 35 <disp32>         lea rsi, [rip+...]
        //   48 39 fe                  cmp rsi, rdi
        //   74 15                     je <ret>
        //   48 8b 05 <disp32>         mov rax, [rip+_ITM_deregisterTMCloneTable]
        Pattern {
            name: "deregister_tm_clones",
            prefix: &[
                0x48, 0x8d, 0x3d, 0, 0, 0, 0,
                0x48, 0x8d, 0x35, 0, 0, 0, 0,
                0x48, 0x39, 0xfe,
            ],
            mask: &[
                1, 1, 1, 0, 0, 0, 0,
                1, 1, 1, 0, 0, 0, 0,
                1, 1, 1,
            ],
        },
        // register_tm_clones (gcc, glibc):
        //   48 8d 3d <disp32>         lea rdi, [rip+_TMC_LIST_]
        //   48 8d 35 <disp32>         lea rsi, [rip+...]
        //   48 29 fe                  sub rsi, rdi
        //   48 89 f0                  mov rax, rsi
        //   48 c1 ee 3f               shr rsi, 63
        Pattern {
            name: "register_tm_clones",
            prefix: &[
                0x48, 0x8d, 0x3d, 0, 0, 0, 0,
                0x48, 0x8d, 0x35, 0, 0, 0, 0,
                0x48, 0x29, 0xfe, 0x48, 0x89, 0xf0,
            ],
            mask: &[
                1, 1, 1, 0, 0, 0, 0,
                1, 1, 1, 0, 0, 0, 0,
                1, 1, 1, 1, 1, 1,
            ],
        },
        // __do_global_dtors_aux (gcc/glibc):
        //   endbr64 (f3 0f 1e fa) is optional on CET binaries; both
        //   variants observed.
        //   80 3d <disp32> 00         cmp byte ptr [rip+__bss_start], 0
        //   75 ??                     jne <ret>
        //   55                        push rbp
        Pattern {
            name: "__do_global_dtors_aux",
            prefix: &[
                0xf3, 0x0f, 0x1e, 0xfa,
                0x80, 0x3d, 0, 0, 0, 0, 0x00,
            ],
            mask: &[
                1, 1, 1, 1,
                1, 1, 0, 0, 0, 0, 1,
            ],
        },
        // __do_global_dtors_aux (no CET / no endbr64 variant):
        Pattern {
            name: "__do_global_dtors_aux",
            prefix: &[0x80, 0x3d, 0, 0, 0, 0, 0x00, 0x75],
            mask: &[1, 1, 0, 0, 0, 0, 1, 1],
        },
        // frame_dummy: usually a single jmp to register_tm_clones.
        //   endbr64 (optional)
        //   e9 <disp32>               jmp register_tm_clones  (PIE / rip-rel)
        Pattern {
            name: "frame_dummy",
            prefix: &[0xf3, 0x0f, 0x1e, 0xfa, 0xe9],
            mask: &[1, 1, 1, 1, 1],
        },
        // frame_dummy (no-pie short-jump variant):
        //   f3 0f 1e fa eb <disp8>    endbr64; jmp register_tm_clones
        Pattern {
            name: "frame_dummy",
            prefix: &[0xf3, 0x0f, 0x1e, 0xfa, 0xeb],
            mask: &[1, 1, 1, 1, 1],
        },
        // deregister_tm_clones (no-pie absolute-address variant):
        //   b8 <imm32>                mov eax, imm32       (addr of __TMC_END__)
        //   48 3d <imm32>             cmp rax, imm32       (matching addr)
        //   74 ??                     je <skip>
        // The two immediates at the same VA-sized constant are
        // diagnostic (it's a self-compare against __TMC_END__);
        // post-`je` the body varies across toolchains so we leave
        // it unmasked.
        Pattern {
            name: "deregister_tm_clones",
            prefix: &[
                0xb8, 0, 0, 0, 0,
                0x48, 0x3d, 0, 0, 0, 0,
                0x74,
            ],
            mask: &[
                1, 0, 0, 0, 0,
                1, 1, 0, 0, 0, 0,
                1,
            ],
        },
        // register_tm_clones (no-pie absolute-address variant):
        //   be <imm32>                mov esi, imm32       (addr of __TMC_END__)
        //   48 81 ee <imm32>          sub rsi, imm32       (addr of __TMC_LIST__)
        //   48 89 f0                  mov rax, rsi
        //   48 c1 ee 3f               shr rsi, 63
        Pattern {
            name: "register_tm_clones",
            prefix: &[
                0xbe, 0, 0, 0, 0,
                0x48, 0x81, 0xee, 0, 0, 0, 0,
                0x48, 0x89, 0xf0,
                0x48, 0xc1, 0xee, 0x3f,
            ],
            mask: &[
                1, 0, 0, 0, 0,
                1, 1, 1, 0, 0, 0, 0,
                1, 1, 1,
                1, 1, 1, 1,
            ],
        },
        // __libc_csu_init (pre-glibc-2.34):
        //   41 57                     push r15
        //   49 89 ff                  mov r15, rdi
        //   41 56                     push r14
        //   49 89 f6                  mov r14, rsi
        //   41 55                     push r13
        //   41 89 d5                  mov r13d, edx
        Pattern {
            name: "__libc_csu_init",
            prefix: &[
                0x41, 0x57, 0x49, 0x89, 0xff,
                0x41, 0x56, 0x49, 0x89, 0xf6,
                0x41, 0x55, 0x41, 0x89, 0xd5,
            ],
            mask: &[1; 15],
        },
        // __libc_csu_fini (pre-glibc-2.34):
        //   f3 c3                     rep ret  (some toolchains)
        //   OR
        //   c3                        ret      (some toolchains)
        // No distinctive prologue — match the canonical empty body
        // when preceded by __libc_csu_init only at link time, which
        // we can't see here. Skip.

        // _dl_relocate_static_pie (glibc dynamic-linker stub
        // emitted by every PIE executable):
        //   f3 0f 1e fa               endbr64
        //   c3                        ret
        // Trivial body — just an endbr64 + ret. Emit on length-5
        // exactly so a more interesting function happening to
        // start with endbr64+ret doesn't false-positive.
        Pattern {
            name: "_dl_relocate_static_pie",
            prefix: &[0xf3, 0x0f, 0x1e, 0xfa, 0xc3],
            mask: &[1, 1, 1, 1, 1],
        },

        // glibc's `__do_global_ctors_aux` (legacy: pre-glibc-2.34,
        // still emitted by some sysv toolchains targeting ELF):
        //   55                        push rbp
        //   48 89 e5                  mov rbp, rsp
        //   53                        push rbx
        //   48 83 ec 08               sub rsp, 8
        //   48 8d 1d <disp32>         lea rbx, [rip+__CTOR_END__]
        Pattern {
            name: "__do_global_ctors_aux",
            prefix: &[
                0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec, 0x08,
                0x48, 0x8d, 0x1d, 0, 0, 0, 0,
            ],
            mask: &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        },

        // gcc's `call_weak_fn` (libgcc / crt helper):
        //   48 8b 05 <disp32>         mov rax, [rip+_Jv_RegisterClasses]
        //   48 85 c0                  test rax, rax
        //   74 02                     je <skip>
        //   ff e0                     jmp rax
        Pattern {
            name: "call_weak_fn",
            prefix: &[
                0x48, 0x8b, 0x05, 0, 0, 0, 0,
                0x48, 0x85, 0xc0,
                0x74, 0x02,
                0xff, 0xe0,
            ],
            mask: &[
                1, 1, 1, 0, 0, 0, 0,
                1, 1, 1,
                1, 1,
                1, 1,
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_with_dontcares() {
        let bytes = [0x48, 0x8D, 0x3D, 0xAB, 0xCD, 0xEF, 0x12, 0x48];
        let prefix = [0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x48];
        let mask = [1, 1, 1, 0, 0, 0, 0, 1];
        assert!(matches_pattern(&bytes, &prefix, &mask));
    }

    #[test]
    fn rejects_too_short() {
        assert!(!matches_pattern(&[0x48], &[0x48, 0x8D], &[1, 1]));
    }

    #[test]
    fn rejects_diff_outside_mask() {
        let bytes = [0x90, 0x8D, 0x3D];
        let prefix = [0x48, 0x8D, 0x3D];
        let mask = [1, 1, 1];
        assert!(!matches_pattern(&bytes, &prefix, &mask));
    }

    #[test]
    fn pattern_table_well_formed() {
        for p in patterns() {
            assert_eq!(p.prefix.len(), p.mask.len(), "pattern {}", p.name);
            assert!(p.prefix.len() >= 5, "pattern {} too short", p.name);
            assert!(!p.name.is_empty());
        }
    }

    #[test]
    fn register_tm_clones_prologue_recovers() {
        let bytes = [
            0x48, 0x8D, 0x3D, 0xDE, 0xAD, 0xBE, 0xEF,
            0x48, 0x8D, 0x35, 0xCA, 0xFE, 0xBA, 0xBE,
            0x48, 0x29, 0xFE, 0x48, 0x89, 0xF0,
        ];
        let pats = patterns();
        let m = pats
            .iter()
            .find(|p| p.name == "register_tm_clones")
            .unwrap();
        assert!(matches_pattern(&bytes, m.prefix, m.mask));
    }
}
