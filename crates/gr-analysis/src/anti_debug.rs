//! Detect common anti-debug / anti-analysis patterns.
//!
//! Mirrors Binary Ninja's "Suspicious Behaviour" tag and the IDA
//! BlackBerry/Hex-Rays "anti-reversing" community plugin. Each
//! pattern produces a plate or pre comment so a security reviewer
//! can spot the technique without disassembly.
//!
//! Patterns covered:
//!
//! 1. `int3` (`0xCC`) standalone as a function's only instruction
//!    or as the first instruction past a normal prologue — classic
//!    debugger trap / breakpoint test.
//! 2. `rdtsc` (`0F 31`) — used for timing-based debugger detection
//!    (run code A, run code B between two `rdtsc`, compare deltas).
//! 3. `cpuid` (`0F A2`) issued with EAX=1 right before a `bt` against
//!    bit 31 (hypervisor flag) — VM detection.
//! 4. Calls to known runtime APIs that exist for debug detection:
//!    `ptrace`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
//!    `NtQueryInformationProcess`, `OutputDebugStringA`,
//!    `GetTickCount`.
//!
//! Patterns 1-3 are bytewise; pattern 4 is a symbol-table lookup
//! that piggybacks on the signature DB.

use std::collections::BTreeSet;

use gr_program::comments::CommentType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct AntiDebugAnalyzer;

impl Analyzer for AntiDebugAnalyzer {
    fn name(&self) -> &str {
        "Anti-Debug"
    }
    fn description(&self) -> &str {
        "Flags timing / debugger-detection / VM-detection / int3-trap patterns"
    }
    fn priority(&self) -> u32 {
        // After CallSiteAnnotator (750), in the same band as
        // ExceptionFlow (790). Both write Post / Plate slots.
        795
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, gr_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        // (1)+(2)+(3) — bytewise scan of every decoded instruction.
        let mut bytewise: Vec<(u64, &'static str)> = Vec::new();
        for insn in program.listing.instructions() {
            if let Some(note) = bytewise_pattern(&insn.bytes) {
                bytewise.push((insn.address, note));
            }
        }

        // (4) — symbol-table lookup of known debugger-API names,
        // then walk *call* references to them. A `lea` / `mov` of
        // the address is just plumbing (PLT stubs do this routinely);
        // only a transfer of control counts as actually "using" the
        // API.
        let api_addrs = collect_anti_debug_api_addrs(program);
        let api_edges: Vec<(u64, &'static str)> = program
            .references
            .all_refs()
            // Direct call only — `is_call()` also covers
            // `IndirectCall`, but the IndirectCallAnalyzer resolves
            // those with a coarse "first import within 1 MiB"
            // heuristic and is too noisy to feed downstream
            // anti-debug flagging.
            .filter(|r| {
                matches!(
                    r.ref_type,
                    gr_program::reference::RefType::UnconditionalCall
                        | gr_program::reference::RefType::ConditionalCall
                )
            })
            .filter_map(|r| api_addrs.get(&r.to).map(|note| (r.from, *note)))
            .collect();

        // Emit.
        let mut emitted = 0usize;
        for (addr, note) in &bytewise {
            if program.comments.get(*addr, CommentType::Pre).is_some() {
                continue;
            }
            program.comments.set(*addr, CommentType::Pre, *note);
            emitted += 1;
        }
        for (addr, note) in &api_edges {
            if program
                .listing
                .instructions_in_range(*addr, *addr + 1)
                .next()
                .is_none()
            {
                continue;
            }
            if program.comments.get(*addr, CommentType::Post).is_some() {
                continue;
            }
            program.comments.set(*addr, CommentType::Post, *note);
            emitted += 1;
        }

        // Plate on each function that hosts ≥ 1 finding — helpful
        // overview.
        // PLT stubs reference the GOT slot of the API they thunk to,
        // which would otherwise cause every PLT entry pointing at
        // `ptrace` to inherit the plate annotation. Filter them — a
        // function that's marked thunk *or* whose name carries the
        // @plt suffix is not "using" the API in the analysis sense.
        let func_ranges: Vec<(u64, Vec<(u64, u64)>)> = program
            .listing
            .functions()
            .filter(|f| !f.is_thunk && !f.name.contains("@plt"))
            .map(|f| {
                (
                    f.entry_point,
                    f.body
                        .ranges()
                        .map(|r| (r.start.offset, r.start.offset + r.size))
                        .collect(),
                )
            })
            .collect();
        let finding_addrs: BTreeSet<u64> = bytewise
            .iter()
            .map(|(a, _)| *a)
            .chain(api_edges.iter().map(|(a, _)| *a))
            .collect();
        let mut flagged_funcs = 0usize;
        for (entry, ranges) in &func_ranges {
            let touched = ranges.iter().any(|(s, e)| {
                finding_addrs
                    .range(*s..*e)
                    .next()
                    .is_some()
            });
            if !touched {
                continue;
            }
            if program.comments.get(*entry, CommentType::Plate).is_some() {
                continue;
            }
            program
                .comments
                .set(*entry, CommentType::Plate, "anti-debug / anti-analysis indicators");
            flagged_funcs += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: flagged_funcs,
            references_found: 0,
            instructions_decoded: emitted,
        })
    }
}

fn bytewise_pattern(bytes: &[u8]) -> Option<&'static str> {
    if bytes.is_empty() {
        return None;
    }
    match bytes {
        [0xCC] => Some("int3 — debugger trap / breakpoint test"),
        [0x0F, 0x31] => Some("rdtsc — timing read (possible anti-debug)"),
        [0x0F, 0x01, 0xF9] => Some("rdtscp — timing read with serialization"),
        [0x0F, 0xA2] => Some("cpuid — feature probe (possible VM-detect)"),
        // ud2 — explicit undefined-instruction trap (used in some
        // packers as anti-disassembly).
        [0x0F, 0x0B] => Some("ud2 — explicit invalid-op trap"),
        _ => None,
    }
}

fn collect_anti_debug_api_addrs(program: &Program) -> std::collections::BTreeMap<u64, &'static str> {
    let mut m = std::collections::BTreeMap::new();
    for s in program.symbol_table.iter() {
        let n = s.name.strip_suffix("@plt").unwrap_or(&s.name);
        let n = n.split('@').next().unwrap_or(n);
        let note: Option<&'static str> = match n {
            "ptrace" => Some("ptrace — PTRACE_TRACEME / debugger detection"),
            "IsDebuggerPresent" => Some("IsDebuggerPresent — Win32 debugger probe"),
            "CheckRemoteDebuggerPresent" => Some("CheckRemoteDebuggerPresent — Win32 debugger probe"),
            "NtQueryInformationProcess" => Some("NtQueryInformationProcess — Win32 debugger / handle probe"),
            "OutputDebugStringA" | "OutputDebugStringW" => Some("OutputDebugString — Win32 debug-side-channel"),
            "GetTickCount" | "GetTickCount64" => Some("GetTickCount — Win32 timing probe"),
            "QueryPerformanceCounter" => Some("QueryPerformanceCounter — Win32 timing probe"),
            _ => None,
        };
        if let Some(note) = note {
            m.insert(s.address, note);
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_int3_standalone() {
        assert!(bytewise_pattern(&[0xCC]).unwrap().contains("int3"));
    }

    #[test]
    fn detects_rdtsc_pair() {
        assert!(bytewise_pattern(&[0x0F, 0x31]).unwrap().contains("rdtsc"));
        assert!(bytewise_pattern(&[0x0F, 0x01, 0xF9])
            .unwrap()
            .contains("rdtscp"));
    }

    #[test]
    fn detects_cpuid() {
        assert!(bytewise_pattern(&[0x0F, 0xA2]).unwrap().contains("cpuid"));
    }

    #[test]
    fn detects_ud2() {
        assert!(bytewise_pattern(&[0x0F, 0x0B]).unwrap().contains("ud2"));
    }

    #[test]
    fn normal_mov_ignored() {
        // 48 89 e5 — mov rbp, rsp — must not match
        assert!(bytewise_pattern(&[0x48, 0x89, 0xE5]).is_none());
    }

    #[test]
    fn empty_ignored() {
        assert!(bytewise_pattern(&[]).is_none());
    }
}
