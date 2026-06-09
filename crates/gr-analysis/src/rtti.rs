//! Itanium C++ ABI RTTI recovery.
//!
//! Why this matters: stripped C++ binaries lose `.symtab` and DWARF
//! but the Itanium ABI requires the compiler to keep `type_info`
//! structures in `.rodata` for every polymorphic class so
//! `dynamic_cast` and exception unwinding still work. Those
//! structures embed the mangled class name as a plain
//! null-terminated string. That makes class identity *recoverable
//! from the bytes alone* with no external symbol DB -- the
//! complement to PR #26's bulk-import path (which depends on a
//! community DB existing). With both, an analyst walking a Bedrock
//! / Skia / V8 build sees readable class names where there were
//! only `vtable_<hex>` placeholders.
//!
//! ## Layout we exploit (Itanium ABI §2.9 / §2.7)
//!
//! ```text
//!   type_info (at address T):
//!     T+ 0  ptr to type_info-kind vtable (libstdc++ -- any loaded ptr)
//!     T+ 8  ptr to length-prefixed mangled class name in .rodata
//!     T+16  (__si_class_type_info only) ptr to parent type_info
//!
//!   vtable for class C (linker symbol points at "linker base" below):
//!     vt- 16  offset_to_top (ptrdiff_t, 0 for primary base)
//!     vt-  8  ptr to type_info T
//!     vt+  0  virtual function 0       ← "vtable for C" points here
//!     vt+  8  virtual function 1
//!     ...
//! ```
//!
//! The name field at `T+8` holds the bare length-prefixed mangled
//! form (`5myCls`, `N3foo3barE`, ...). Prepend `_ZTS` and the
//! standard C++ demangler turns it into a readable class name --
//! this is how `__cxxabiv1::__class_type_info::name()` works at
//! runtime and how every reverse-engineering tool (Ghidra/IDA/BN)
//! recovers class identity from stripped binaries.
//!
//! ## What we emit
//!
//! For each recovered type_info at address T:
//!
//! * Symbol at T -- `typeinfo for ClassName` (Data kind; the name
//!   carries the kind so xref consumers stay self-describing).
//! * For each vtable slot pointing at T -- vtable symbol at
//!   `slot + ptr_size` renamed `vtable for ClassName`, on top of
//!   `VTableAnalyzer`'s generic `vtable_<hex>` placeholder
//!   (primary-lookup order picks the more-recent symbol).
//!
//! Vtable function-slot naming (`ClassName::vfunc_<N>`) is left to
//! a follow-up so this PR doesn't fight `--import` names already
//! in the override sidecar.

use cpp_demangle::{DemangleOptions, Symbol as CppSymbol};
use gr_loader::SectionFlags;
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;
use rustc_hash::FxHashMap;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

/// Cap on how many bytes we'll walk looking for a class-name's
/// null terminator. Real Itanium-mangled class names from
/// Mojang-scale C++ go ~150 chars; 512 is generous and bounds
/// junk-pointer scans cheaply.
const MAX_NAME_LEN: usize = 512;

pub struct RttiAnalyzer;

impl Analyzer for RttiAnalyzer {
    fn name(&self) -> &str {
        "RTTI Recovery"
    }

    fn description(&self) -> &str {
        "Recovers C++ class names + vtable identities from Itanium ABI type_info structures (works on stripped binaries)"
    }

    fn priority(&self) -> u32 {
        // After VTableAnalyzer (600) so we can overwrite its
        // generic `vtable_<hex>` placeholders with `vtable for
        // ClassName` when we identify the class.
        610
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let ptr_size = (program.info.bits / 8) as u64;
        if ptr_size != 8 {
            // Itanium ABI on 32-bit follows the same shape but
            // 32-bit C++ binaries are rare in modern RE targets;
            // gate on 64-bit until we have a binary to validate
            // against and keep this PR focused.
            return Ok(self.empty_result());
        }

        // (start, end, exec) ranges for "is this a sensible
        // pointer?" checks. Includes everything loaded so a
        // type_info-vtable pointer landing in libstdc++ (static
        // link) or anywhere else doesn't trip us up -- we only
        // care that it's *in the image*.
        let all_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.address != 0 && s.size > 0)
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Executable ranges, for distinguishing a real vtable
        // (next slot is a function pointer) from
        // `__si_class_type_info`'s parent-typeinfo field (next
        // slot is the next type_info's vptr -- not code).
        let code_ranges: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.flags.contains(SectionFlags::EXECUTE))
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Data sections to scan for type_info / vtable headers.
        // `.rodata` / `.data.rel.ro` are the canonical homes;
        // `.data` too, conservatively, for static vtables that
        // ended up writable.
        let data_sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| !s.flags.contains(SectionFlags::EXECUTE))
            .filter(|s| s.address != 0 && s.size > 0)
            .map(|s| (s.address, s.address + s.size))
            .collect();

        // Phase 1: enumerate type_info structures.
        // Iterate every pointer-aligned slot S in every data
        // section; if `*S` points at a string that the C++
        // demangler can read as a typeinfo name string (`_ZTS<s>`),
        // the type_info structure starts at `S - ptr_size`.
        let mut typeinfos: FxHashMap<u64, String> = FxHashMap::default();
        for &(start, end) in &data_sections {
            let mut addr = (start + ptr_size - 1) & !(ptr_size - 1);
            while addr + ptr_size <= end {
                let Ok(name_ptr) = program.info.memory.read_u64(addr) else {
                    addr += ptr_size;
                    continue;
                };
                if !in_any_range(name_ptr, &all_ranges) {
                    addr += ptr_size;
                    continue;
                }
                if let Some(mangled) = read_cstring(program, name_ptr, MAX_NAME_LEN)
                    && let Some(demangled) = demangle_typeinfo_name(&mangled)
                {
                    // The type_info structure starts one slot
                    // before this -- the `name` field is the
                    // second member after the vtable_ptr.
                    if addr >= start + ptr_size {
                        let ti_addr = addr - ptr_size;
                        typeinfos.entry(ti_addr).or_insert(demangled);
                    }
                }
                addr += ptr_size;
            }
        }

        // Phase 2: link vtables to recovered type_infos.
        // For each pointer-aligned slot S whose value is a
        // recovered type_info address, the slot is *either*:
        //   (a) the `type_info` field of a vtable header -- the
        //       slot one ahead (S + ptr_size) is the first
        //       virtual function pointer, i.e. code, and S
        //       + ptr_size is the address the linker calls
        //       "vtable for ClassName".
        //   (b) `__si_class_type_info`'s parent-typeinfo field
        //       -- the slot one ahead is the next type_info's
        //       vptr, not a code pointer.
        // Gate on "next slot is a code pointer" to keep only
        // (a). Without this, the smoke ELF (Animal/Dog/Cat
        // chain) emits two extra "vtable for Animal"s pointing
        // at Dog's and Animal's own typeinfo structures.
        let mut vtables: Vec<(u64, String)> = Vec::new();
        for &(start, end) in &data_sections {
            let mut addr = (start + ptr_size - 1) & !(ptr_size - 1);
            while addr + ptr_size * 2 <= end {
                let Ok(val) = program.info.memory.read_u64(addr) else {
                    addr += ptr_size;
                    continue;
                };
                if let Some(class_name) = typeinfos.get(&val) {
                    let vt_addr = addr + ptr_size;
                    if let Ok(first_vfunc) = program.info.memory.read_u64(vt_addr)
                        && in_any_range(first_vfunc, &code_ranges)
                    {
                        vtables.push((vt_addr, class_name.clone()));
                    }
                }
                addr += ptr_size;
            }
        }

        // Phase 3: apply symbols.
        let mut classes_found = 0usize;
        for (ti_addr, class_name) in &typeinfos {
            let sym_name = format!("typeinfo for {}", class_name);
            // Always add -- the symbol table dedupes by (addr,
            // name) so a re-run is a no-op, and Analysis-sourced
            // symbols are subordinate to user-import overrides.
            program.symbol_table.add(Symbol::new(
                sym_name,
                *ti_addr,
                SymbolType::Data,
                SourceType::Analysis,
            ));
            classes_found += 1;
        }

        for (vt_addr, class_name) in &vtables {
            let sym_name = format!("vtable for {}", class_name);
            // `set_primary` front-inserts so this class-aware name
            // wins over VTableAnalyzer's earlier `vtable_<hex>`
            // placeholder under `primary_at` lookup. (User
            // `--import` renames still win at the override-apply
            // step, which runs after every analyzer.)
            program
                .symbol_table
                .set_primary(*vt_addr, sym_name, SymbolType::Data);
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: classes_found,
            references_found: vtables.len(),
            instructions_decoded: 0,
        })
    }
}

impl RttiAnalyzer {
    fn empty_result(&self) -> AnalysisResult {
        AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: 0,
        }
    }
}

fn in_any_range(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges.iter().any(|&(s, e)| addr >= s && addr < e)
}

/// Read a NULL-terminated ASCII string, capped at `max_len`. We
/// require ASCII / non-control because non-ASCII at this position
/// is almost certainly a junk pointer, and tightening the gate
/// keeps the demangle hot loop off random garbage.
fn read_cstring(program: &Program, addr: u64, max_len: usize) -> Option<String> {
    let mut bytes = Vec::with_capacity(64);
    for i in 0..max_len {
        let b = program.info.memory.read_byte(addr + i as u64)?;
        if b == 0 {
            if bytes.is_empty() {
                return None;
            }
            return String::from_utf8(bytes).ok();
        }
        if !(0x20..=0x7e).contains(&b) {
            return None;
        }
        bytes.push(b);
    }
    None
}

/// Try to demangle the bare typeinfo-name string (`5myCls`,
/// `N3foo3barE`, ...) by re-applying the `_ZTS` prefix that
/// strips off at storage time. Returns the class name only
/// (e.g. `myCls`, `foo::bar`), stripping the `typeinfo name for `
/// prefix the demangler emits.
///
/// Mandatory length-prefix check: a real Itanium typeinfo name
/// always starts with a digit (length of next component) or `N`
/// (nested-name introducer) -- gating on that up front filters
/// out ~all random rodata strings before the demangle call.
fn demangle_typeinfo_name(s: &str) -> Option<String> {
    let first = s.bytes().next()?;
    if !first.is_ascii_digit() && first != b'N' {
        return None;
    }
    let candidate = format!("_ZTS{}", s);
    let sym = CppSymbol::new(candidate.as_bytes()).ok()?;
    let opts = DemangleOptions::new();
    let full = sym.demangle(&opts).ok()?;
    Some(
        full.strip_prefix("typeinfo name for ")
            .unwrap_or(&full)
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::helpers::make_x86_64_program_with_data;

    #[test]
    fn demangle_simple_class_name() {
        assert_eq!(
            demangle_typeinfo_name("5myCls").as_deref(),
            Some("myCls")
        );
    }

    #[test]
    fn demangle_nested_class_name() {
        // N3foo3barE = foo::bar
        let got = demangle_typeinfo_name("N3foo3barE").unwrap();
        assert!(got.contains("foo"));
        assert!(got.contains("bar"));
    }

    #[test]
    fn demangle_rejects_non_typeinfo_string() {
        assert!(demangle_typeinfo_name("hello world").is_none());
        assert!(demangle_typeinfo_name("0xdeadbeef").is_none());
        // Starts with digit but the rest isn't a valid component
        // -- demangler should refuse, not accept it as length-5
        // garbage.
        assert!(demangle_typeinfo_name("5!!!!!").is_none());
    }

    #[test]
    fn read_cstring_stops_at_null() {
        let data = b"abc\0xyz";
        let prog = make_x86_64_program_with_data(&[], data, 0x1000, 0x2000);
        assert_eq!(read_cstring(&prog, 0x2000, 32).as_deref(), Some("abc"));
        // Reading at 'b' returns "bc".
        assert_eq!(read_cstring(&prog, 0x2001, 32).as_deref(), Some("bc"));
    }

    #[test]
    fn read_cstring_rejects_non_ascii() {
        let data = b"ab\xffcd\0";
        let prog = make_x86_64_program_with_data(&[], data, 0x1000, 0x2000);
        assert!(read_cstring(&prog, 0x2000, 32).is_none());
    }

    #[test]
    fn recover_typeinfo_and_vtable_end_to_end() {
        // .rodata layout (everything in one section so the
        // testutil helper is enough):
        //
        //   data_addr + 0x000  type_info structure:
        //                        [0] = 0x0000000000002100  (vptr -- any in-image ptr)
        //                        [8] = 0x0000000000002080  (name_ptr)
        //   data_addr + 0x010  ... padding ...
        //   data_addr + 0x040  vtable region:
        //                        [0] = 0                    (offset_to_top)
        //                        [8] = 0x0000000000002000   (type_info addr)
        //                        [16] = 0x0000000000001000  (vfunc 0)
        //                        [24] = 0x0000000000001008  (vfunc 1)
        //   data_addr + 0x080  "5myCls\0"
        //   data_addr + 0x100  arbitrary -- target of vptr
        //
        // type_info at 0x2000; vtable for myCls at 0x2050.

        let code_addr = 0x1000u64;
        let data_addr = 0x2000u64;
        let mut data = vec![0u8; 0x200];

        // type_info @ 0x2000:
        data[0x00..0x08].copy_from_slice(&0x0000_0000_0000_2100u64.to_le_bytes());
        data[0x08..0x10].copy_from_slice(&0x0000_0000_0000_2080u64.to_le_bytes());
        // vtable header @ 0x2040 / linker base @ 0x2050:
        data[0x40..0x48].copy_from_slice(&0u64.to_le_bytes()); // offset_to_top
        data[0x48..0x50].copy_from_slice(&0x0000_0000_0000_2000u64.to_le_bytes()); // ptr to type_info
        data[0x50..0x58].copy_from_slice(&0x0000_0000_0000_1000u64.to_le_bytes()); // vfunc 0
        data[0x58..0x60].copy_from_slice(&0x0000_0000_0000_1008u64.to_le_bytes()); // vfunc 1
        // "5myCls\0" @ 0x2080:
        data[0x80..0x87].copy_from_slice(b"5myCls\0");

        let code = vec![0xc3u8; 0x10]; // ret ret ret ...
        let mut prog = make_x86_64_program_with_data(&code, &data, code_addr, data_addr);

        let res = RttiAnalyzer.analyze(&mut prog).unwrap();
        assert_eq!(res.functions_found, 1, "expected 1 class");
        assert_eq!(res.references_found, 1, "expected 1 vtable");

        let ti_sym = prog
            .symbol_table
            .primary_at(0x2000)
            .expect("typeinfo symbol present");
        assert_eq!(ti_sym.name, "typeinfo for myCls");
        let vt_sym = prog
            .symbol_table
            .primary_at(0x2050)
            .expect("vtable symbol present");
        assert_eq!(vt_sym.name, "vtable for myCls");
    }

    #[test]
    fn parent_typeinfo_pointer_doesnt_emit_extra_vtable() {
        // Repro for the smoke-binary bug: with single-inheritance
        // (`Dog : Animal`), libstdc++ uses __si_class_type_info,
        // which holds a parent-typeinfo pointer in the slot
        // immediately after the name field. A naive Phase-2 scan
        // sees that pointer too and emits a phantom
        // "vtable for Animal" pointing at Dog's own type_info.
        //
        // Layout:
        //   0x2000  Animal type_info (vptr, name_ptr→0x2080)
        //   0x2020  Dog    type_info (vptr, name_ptr→0x2088,
        //                             parent_ptr→0x2000)
        //   0x2040  Dog vtable header: [0, ti_ptr=0x2020] then vf at 0x2050.
        //           Linker "vtable for Dog" points at 0x2050.
        //   0x2080  "6Animal\0"
        //   0x2088  "3Dog\0"
        //
        // Expected: ONE vtable (Dog), even though Phase 2 sees
        // Dog::__si.parent_ptr = 0x2000 (Animal ti) as well.
        let code_addr = 0x1000u64;
        let data_addr = 0x2000u64;
        let mut data = vec![0u8; 0x100];

        // Animal type_info @ 0x2000:
        data[0x00..0x08].copy_from_slice(&0x0000_0000_0000_2100u64.to_le_bytes());
        data[0x08..0x10].copy_from_slice(&0x0000_0000_0000_2080u64.to_le_bytes());
        // Dog type_info @ 0x2020 (__si_class_type_info):
        data[0x20..0x28].copy_from_slice(&0x0000_0000_0000_2100u64.to_le_bytes());
        data[0x28..0x30].copy_from_slice(&0x0000_0000_0000_2088u64.to_le_bytes());
        data[0x30..0x38].copy_from_slice(&0x0000_0000_0000_2000u64.to_le_bytes()); // parent ptr
        // Dog vtable header @ 0x2040:
        data[0x40..0x48].copy_from_slice(&0u64.to_le_bytes());
        data[0x48..0x50].copy_from_slice(&0x0000_0000_0000_2020u64.to_le_bytes());
        data[0x50..0x58].copy_from_slice(&0x0000_0000_0000_1000u64.to_le_bytes()); // vfunc 0
        // Names:
        data[0x80..0x88].copy_from_slice(b"6Animal\0");
        data[0x88..0x8d].copy_from_slice(b"3Dog\0");

        let code = vec![0xc3u8; 0x10];
        let mut prog = make_x86_64_program_with_data(&code, &data, code_addr, data_addr);

        let res = RttiAnalyzer.analyze(&mut prog).unwrap();
        assert_eq!(res.functions_found, 2, "Animal + Dog typeinfos");
        // ONE real vtable (Dog), not two. The parent_ptr slot in
        // Dog's __si_class_type_info points at Animal's ti but
        // the slot after it isn't a code pointer, so the gate
        // suppresses the phantom emit.
        assert_eq!(res.references_found, 1, "exactly one real vtable");
        assert_eq!(
            prog.symbol_table.primary_at(0x2000).unwrap().name,
            "typeinfo for Animal"
        );
        assert_eq!(
            prog.symbol_table.primary_at(0x2020).unwrap().name,
            "typeinfo for Dog"
        );
        assert_eq!(
            prog.symbol_table.primary_at(0x2050).unwrap().name,
            "vtable for Dog"
        );
    }
}
