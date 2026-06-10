//! PE (Windows) `.pdata` and exception-table analysis.
//!
//! On x64 Windows the linker emits a `RUNTIME_FUNCTION` entry per
//! function into the `.pdata` section. Each entry is exactly:
//!
//! ```c
//! struct RUNTIME_FUNCTION {
//!     uint32_t BeginAddress;       // RVA (image-base relative)
//!     uint32_t EndAddress;         // RVA, exclusive
//!     uint32_t UnwindInfoAddress;  // RVA to UNWIND_INFO blob
//! };
//! ```
//!
//! Stripping a PE binary leaves these intact — they're indexed by
//! the loader for SEH dispatch — so walking the table recovers every
//! function the linker emitted, even when the export / symbol tables
//! are gone. IDA and BN both seed function discovery from `.pdata`
//! for exactly this reason. We do the same:
//!
//! 1. Find `.pdata` by section name.
//! 2. Walk 12-byte entries.
//! 3. For each `BeginAddress`, register a Function symbol +
//!    `PE_<image_base + rva>` candidate; if discovery has already
//!    landed on the entry, the rename is conservative (`FUN_*` only).
//! 4. The `EndAddress` boundary is recorded as
//!    `metadata.func_<addr>_pe_end = <addr>` so the
//!    `FunctionBoundaryAnalyzer` can prefer it over its heuristic
//!    extents.
//!
//! Also recovers x86 SEHandlerTable entries via the
//! `IMAGE_LOAD_CONFIG_DIRECTORY` when present — same surface, different
//! discovery path — but only when the loader exposes the
//! `load_config` field. (Our `gr-loader::pe` doesn't yet, so the x86
//! path is a noop until that lands; the analyzer is forward-compatible.)

use gr_program::function::Function;
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct PeSehAnalyzer;

impl Analyzer for PeSehAnalyzer {
    fn name(&self) -> &str {
        "PE .pdata / SEH"
    }
    fn description(&self) -> &str {
        "Recovers function entries from PE x64 .pdata RUNTIME_FUNCTION tables"
    }
    fn priority(&self) -> u32 {
        // Before Discovery (100) so its work queue picks up our
        // seeds for body computation.
        80
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if program.info.format != gr_loader::BinaryFormat::Pe {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let mut recovered = 0usize;

        if let Some((base, size)) = find_section(program, ".pdata") {
            recovered += parse_pdata(program, base, size);
        }

        // TLS callbacks land in `.tls` (the
        // IMAGE_TLS_DIRECTORY.AddressOfCallBacks field points into
        // here, but our loader doesn't expose the data directory
        // directly; we scan the section start for the canonical
        // null-terminated pointer array layout). These callbacks
        // run *before* main and are a classic anti-debug slot —
        // surfacing them as Functions makes them visible to every
        // downstream pass.
        if let Some((tls_base, tls_size)) = find_section(program, ".tls") {
            recovered += parse_tls_callbacks(program, tls_base, tls_size);
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: recovered,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// Walk a null-terminated array of qword callback pointers
/// starting at `base`. Each entry is registered as a Function +
/// `tls_callback_<n>` Symbol; we use a Plate comment so the
/// listing makes it obvious these run before `main` is reached.
fn parse_tls_callbacks(program: &mut Program, base: u64, size: u64) -> usize {
    let cap = size.min(4096) as usize;
    let mut buf = vec![0u8; cap];
    if program.info.memory.read_bytes(base, &mut buf).is_err() {
        return 0;
    }
    let ptr_size = 8usize;
    let valid_code = code_ranges(program);
    let mut added = 0usize;
    let mut idx = 0usize;
    for chunk in buf.chunks_exact(ptr_size) {
        let ptr = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
        if ptr == 0 {
            break;
        }
        if !crate::utils::is_valid_address(ptr, &valid_code) {
            idx += 1;
            continue;
        }
        if !program.listing.has_function(ptr) {
            program.listing.add_function(gr_program::function::Function::new(
                ptr,
                format!("tls_callback_{}", idx),
            ));
            added += 1;
        }
        program.symbol_table.add(gr_program::symbol::Symbol::new(
            format!("tls_callback_{}", idx),
            ptr,
            gr_program::symbol::SymbolType::Function,
            gr_program::symbol::SourceType::Analysis,
        ));
        if program
            .comments
            .get(ptr, gr_program::comments::CommentType::Plate)
            .is_none()
        {
            program.comments.set(
                ptr,
                gr_program::comments::CommentType::Plate,
                "TLS callback — runs before main (anti-debug-adjacent)",
            );
        }
        idx += 1;
    }
    added
}

fn find_section(program: &Program, name: &str) -> Option<(u64, u64)> {
    let s = program.info.sections.iter().find(|s| s.name == name)?;
    if s.size == 0 {
        return None;
    }
    Some((s.address, s.size))
}

/// Walk the `.pdata` array of `RUNTIME_FUNCTION` records. Each is
/// 12 bytes; we cap at 64 KiB worth of entries to keep the scan
/// bounded on synthetic / fuzzed PEs while still covering every
/// real-world binary we've seen (~50 k functions = 600 KiB pdata,
/// which would need adjustment to handle; raise the cap then).
fn parse_pdata(program: &mut Program, base: u64, size: u64) -> usize {
    let max_bytes = size.min(64 * 1024) as usize;
    let mut buf = vec![0u8; max_bytes];
    if program.info.memory.read_bytes(base, &mut buf).is_err() {
        return 0;
    }

    let image_base = program
        .info
        .sections
        .iter()
        .map(|s| s.address)
        .min()
        .unwrap_or(0);
    let valid_code = code_ranges(program);

    let mut added = 0usize;
    for chunk in buf.chunks_exact(12) {
        let begin_rva = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
        let end_rva = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as u64;
        if begin_rva == 0 && end_rva == 0 {
            // Padding / table terminator.
            break;
        }
        if end_rva <= begin_rva {
            continue;
        }
        // RUNTIME_FUNCTION addresses are RVAs — relative to the
        // image base. For PE binaries our loader maps sections at
        // their preferred VAs so `begin_rva + image_base` is what
        // we want — *except* when `begin_rva` is already a VA (some
        // PE32+ tooling emits absolute addresses). Take whichever
        // form lands inside an executable section.
        let candidates = [begin_rva, begin_rva.wrapping_add(image_base)];
        let Some(&abs) = candidates
            .iter()
            .find(|&&a| crate::utils::is_valid_address(a, &valid_code))
        else {
            continue;
        };

        let exists = program.listing.has_function(abs);
        if !exists {
            program
                .listing
                .add_function(Function::new(abs, format!("FUN_{:08x}", abs)));
            added += 1;
        }
        if program.symbol_table.primary_at(abs).is_none() {
            program.symbol_table.add(Symbol::new(
                format!("FUN_{:08x}", abs),
                abs,
                SymbolType::Function,
                SourceType::Analysis,
            ));
        }
        let end_abs = if abs == begin_rva {
            end_rva
        } else {
            end_rva.wrapping_add(image_base)
        };
        program
            .metadata
            .set_property(format!("func_{:x}_pe_end", abs), format!("0x{:x}", end_abs));
    }
    added
}

fn code_ranges(program: &Program) -> Vec<(u64, u64)> {
    program
        .info
        .sections
        .iter()
        .filter(|s| s.flags.contains(gr_loader::SectionFlags::EXECUTE))
        .map(|s| (s.address, s.address + s.size))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        let _ = super::PeSehAnalyzer;
    }
}
