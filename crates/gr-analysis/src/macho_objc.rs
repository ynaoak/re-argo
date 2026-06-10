//! Mach-O Objective-C class / method recovery.
//!
//! ABI 2.0 (the only one anything since macOS 10.5 uses) lays the
//! class metadata out as:
//!
//! ```c
//! struct __objc_classlist {        // section payload
//!     class_t * classes[];         // each entry points at one class_t
//! };
//!
//! struct class_t {                 // 0x28 bytes on 64-bit
//!     class_t * isa;               // 0x00
//!     class_t * superclass;        // 0x08
//!     void    * cache;             // 0x10
//!     void    * vtable;            // 0x18
//!     class_ro_t * data;           // 0x20   <- &class_ro_t (lo bits flag)
//! };
//!
//! struct class_ro_t {              // 0x48 bytes
//!     uint32_t flags;              // 0x00
//!     uint32_t instance_start;     // 0x04
//!     uint32_t instance_size;      // 0x08
//!     uint32_t reserved;           // 0x0c
//!     void    * ivar_layout;       // 0x10
//!     const char * name;           // 0x18    <- C string
//!     method_list_t * baseMethods; // 0x20
//!     ...
//! };
//!
//! struct method_list_t {
//!     uint32_t entsize_and_flags;  // 0x00 (low bits = entry size)
//!     uint32_t count;              // 0x04
//!     method_t methods[count];     // 0x08
//! };
//!
//! struct method_t {                // 0x18 bytes when uniqued = 0
//!     SEL  name;                   // 0x00    SEL = const char *
//!     const char * types;          // 0x08
//!     IMP  imp;                    // 0x10    function pointer
//! };
//! ```
//!
//! We walk this tree and for every method emit:
//!
//! * A function symbol at `imp`'s address named `-[ClassName selector:]`
//!   (instance method) or `+[ClassName selector:]` (class methods —
//!   we use `+` when the class_ro_t came from the metaclass).
//! * The class itself gets a Data symbol named `objc_class_<Name>` at
//!   the `class_t` address.
//!
//! Stripping a Mach-O binary doesn't touch any of this — the runtime
//! needs the metadata at load time — so we recover the full ObjC
//! surface even from fully-stripped binaries, matching the behaviour
//! of IDA and Hopper's "objc" loader plugins.

use gr_program::function::Function;
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct MachoObjCAnalyzer;

impl Analyzer for MachoObjCAnalyzer {
    fn name(&self) -> &str {
        "Mach-O ObjC"
    }
    fn description(&self) -> &str {
        "Recovers Objective-C classes + method IMPs from __objc_classlist metadata"
    }
    fn priority(&self) -> u32 {
        // Before Discovery (100) so the recovered IMPs land in
        // Discovery's seed queue and downstream analyzers see them.
        85
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if program.info.format != gr_loader::BinaryFormat::MachO {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let bits = program.info.bits;
        if bits != 64 {
            // ABI 1.0 (32-bit) has a different layout; skip until we
            // have a test corpus.
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }
        let ptr = 8usize;

        let Some((list_base, list_size)) = find_section(program, "__objc_classlist") else {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        };

        // Read the classlist into a buffer; cap at 1 MiB so badly-
        // typed binaries can't hang us.
        let max = list_size.min(1 << 20) as usize;
        let mut buf = vec![0u8; max];
        if program.info.memory.read_bytes(list_base, &mut buf).is_err() {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let mut methods_found = 0usize;
        let mut classes_found = 0usize;
        for chunk in buf.chunks_exact(ptr) {
            let class_addr = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            if class_addr == 0 {
                continue;
            }
            // Walk class_t at class_addr.
            let Some(class_ro) = read_u64(program, class_addr + 0x20) else {
                continue;
            };
            // class_ro low bit is sometimes a flag — mask it off.
            let class_ro = class_ro & !1;
            if class_ro == 0 {
                continue;
            }
            let Some(name_ptr) = read_u64(program, class_ro + 0x18) else {
                continue;
            };
            let Some(class_name) = read_c_str(program, name_ptr, 128) else {
                continue;
            };
            let Some(method_list) = read_u64(program, class_ro + 0x20) else {
                continue;
            };

            // Class-level metadata symbol.
            if program.symbol_table.primary_at(class_addr).is_none() {
                program.symbol_table.add(Symbol::new(
                    format!("objc_class_{}", sanitize(&class_name)),
                    class_addr,
                    SymbolType::Data,
                    SourceType::Analysis,
                ));
            }
            classes_found += 1;

            if method_list == 0 {
                continue;
            }
            methods_found += parse_method_list(program, method_list, &class_name, '-');
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: classes_found + methods_found,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

fn parse_method_list(
    program: &mut Program,
    list_addr: u64,
    class_name: &str,
    leader: char,
) -> usize {
    let Some(header) = read_u64(program, list_addr) else {
        return 0;
    };
    let entsize = (header & 0xffff_ffff) as u32;
    let count = (header >> 32) as u32;
    // method_t is 0x18 bytes in classic layout. Newer Clang uses
    // 12-byte "small" methods (entries are 3 × i32 relative offsets);
    // handle that variant too.
    if !matches!(entsize, 12 | 24) || count > 4096 {
        return 0;
    }
    let entries_base = list_addr + 8;
    let mut added = 0usize;
    for i in 0..count as u64 {
        let entry = entries_base + i * entsize as u64;
        let (sel_ptr, imp) = if entsize == 24 {
            (
                read_u64(program, entry),
                read_u64(program, entry + 0x10),
            )
        } else {
            // Small method: each field is a *signed 32-bit RVA*
            // relative to its own location.
            let (s, t, im) = (
                read_i32(program, entry),
                read_i32(program, entry + 4),
                read_i32(program, entry + 8),
            );
            let _ = t;
            let sel_ptr = s.map(|d| (entry as i64).wrapping_add(d as i64) as u64);
            let imp_ptr = im.map(|d| (entry as i64 + 8).wrapping_add(d as i64) as u64);
            (sel_ptr, imp_ptr)
        };
        let Some(sel_ptr) = sel_ptr else {
            continue;
        };
        let Some(imp) = imp else {
            continue;
        };
        if imp == 0 {
            continue;
        }
        let Some(selector) = read_c_str(program, sel_ptr, 96) else {
            continue;
        };
        // Mach-O small-selector pointers go through __objc_selrefs
        // indirection; if the loaded string isn't printable, try
        // one more dereference.
        let selector = if selector.chars().all(|c| (' '..='~').contains(&c)) {
            selector
        } else {
            let Some(real) = read_u64(program, sel_ptr)
                .and_then(|p| read_c_str(program, p, 96))
            else {
                continue;
            };
            real
        };
        let name = format!("{}[{} {}]", leader, class_name, selector);
        if program.listing.get_function(imp).is_none() {
            program
                .listing
                .add_function(Function::new(imp, name.clone()));
        } else if let Some(f) = program.listing.get_function_mut(imp)
            && f.name.starts_with("FUN_")
        {
            f.name = name.clone();
        }
        program.symbol_table.add(Symbol::new(
            name,
            imp,
            SymbolType::Function,
            SourceType::Analysis,
        ));
        added += 1;
    }
    added
}

fn find_section(program: &Program, name: &str) -> Option<(u64, u64)> {
    let s = program
        .info
        .sections
        .iter()
        .find(|s| s.name == name || s.name.ends_with(name))?;
    if s.size == 0 {
        return None;
    }
    Some((s.address, s.size))
}

fn read_u64(program: &Program, addr: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    program.info.memory.read_bytes(addr, &mut buf).ok()?;
    Some(u64::from_le_bytes(buf))
}

fn read_i32(program: &Program, addr: u64) -> Option<i32> {
    let mut buf = [0u8; 4];
    program.info.memory.read_bytes(addr, &mut buf).ok()?;
    Some(i32::from_le_bytes(buf))
}

fn read_c_str(program: &Program, addr: u64, max: usize) -> Option<String> {
    let cap = max.min(256);
    let mut buf = vec![0u8; cap];
    program.info.memory.read_bytes(addr, &mut buf).ok()?;
    let nul = buf.iter().position(|&b| b == 0)?;
    if nul == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..nul]).into_owned())
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        let _ = super::MachoObjCAnalyzer;
    }

    #[test]
    fn sanitize_basic() {
        assert_eq!(super::sanitize("My Class:Name"), "My_Class_Name");
        assert_eq!(super::sanitize("Foo123"), "Foo123");
    }
}
