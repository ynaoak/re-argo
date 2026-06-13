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
//!     uint32_t reserved;           // 0x0c (64-bit only)
//!     uint8_t       * ivar_layout; // 0x10
//!     const char    * name;        // 0x18    <- C string
//!     method_list_t * baseMethods; // 0x20
//!     protocol_list_t * baseProtocols; // 0x28
//!     ivar_list_t   * ivars;       // 0x30
//!     uint8_t       * weak_ivar_layout; // 0x38
//!     property_list_t * baseProperties; // 0x40
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

use reargo_program::function::Function;
use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;

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
        if program.info.format != reargo_loader::BinaryFormat::MachO {
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
            // `chunks_exact(8)` guarantees an 8-byte slice, so the
            // try_into can't fail. The previous `unwrap_or([0; 8])`
            // pessimistically masked any conversion failure into a
            // null pointer that then got skipped, which was harmless
            // but obscured intent.
            let class_addr = u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8)"));
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
            if !looks_like_identifier(&class_name) {
                continue;
            }
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

            if method_list != 0 {
                methods_found += parse_method_list(program, method_list, &class_name, '-');
            }

            // class_ro_t at 0x30 holds the ivar list; we recover
            // the instance variables as Data symbols on the class
            // metadata's offset table. Class methods (the meta-
            // class IMPs) live behind the `isa` chain — read the
            // meta-class via class_addr's `isa` field at 0x00 and
            // walk its method list as `+[ClassName ...]`.
            if let Some(ivar_list) = read_u64(program, class_ro + 0x30)
                && ivar_list != 0
            {
                methods_found += parse_ivar_list(program, ivar_list, &class_name);
            }
            if let Some(meta_class) = read_u64(program, class_addr)
                && meta_class != 0
                && meta_class != class_addr
                && let Some(meta_ro) = read_u64(program, meta_class + 0x20)
            {
                let meta_ro = meta_ro & !1;
                if let Some(meta_methods) = read_u64(program, meta_ro + 0x20)
                    && meta_methods != 0
                {
                    methods_found += parse_method_list(program, meta_methods, &class_name, '+');
                }
            }
        }

        // (2) Protocols — `__objc_protolist` is a parallel
        // pointer list. Each entry is a `protocol_t*`. Layout
        // mirrors class_ro_t roughly: name pointer at +0x08,
        // instance method list at +0x18.
        let mut protocols_found = 0usize;
        if let Some((proto_base, proto_size)) = find_section(program, "__objc_protolist") {
            protocols_found = parse_protocol_list(program, proto_base, proto_size);
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: classes_found + methods_found + protocols_found,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// Walk a Mach-O `ivar_list_t`. Layout:
/// ```c
/// struct ivar_list_t {
///     uint32_t entsize_and_flags;  // 0x00
///     uint32_t count;              // 0x04
///     ivar_t   ivars[count];       // 0x08
/// };
/// struct ivar_t {                  // 0x20 bytes
///     uint64_t * offset;           // 0x00 -> *int32
///     const char * name;           // 0x08
///     const char * type;           // 0x10
///     uint32_t alignment;          // 0x18
///     uint32_t size;               // 0x1c
/// };
/// ```
fn parse_ivar_list(program: &mut Program, list_addr: u64, class_name: &str) -> usize {
    let Some(header) = read_u64(program, list_addr) else {
        return 0;
    };
    let entsize = (header & 0xffff_ffff) as u32;
    let count = (header >> 32) as u32;
    if entsize != 0x20 || count > 4096 {
        return 0;
    }
    let mut added = 0usize;
    for i in 0..count as u64 {
        let entry = list_addr + 8 + i * entsize as u64;
        let Some(name_ptr) = read_u64(program, entry + 0x08) else {
            continue;
        };
        let Some(ivar_name) = read_c_str(program, name_ptr, 96) else {
            continue;
        };
        if !looks_like_identifier(&ivar_name) {
            continue;
        }
        let Some(offset_ptr) = read_u64(program, entry) else {
            continue;
        };
        if offset_ptr == 0 {
            continue;
        }
        let sym_name = format!("objc_ivar_{}_{}", sanitize(class_name), sanitize(&ivar_name));
        if program.symbol_table.primary_at(offset_ptr).is_none() {
            program.symbol_table.add(Symbol::new(
                sym_name,
                offset_ptr,
                SymbolType::Data,
                SourceType::Analysis,
            ));
            added += 1;
        }
    }
    added
}

/// Walk `__objc_protolist`. Each pointer goes to a `protocol_t`:
/// ```c
/// struct protocol_t {
///     void       * isa;              // 0x00
///     const char * name;             // 0x08
///     protocol_list_t * protocols;   // 0x10
///     method_list_t * instance;      // 0x18
///     method_list_t * class;         // 0x20
///     method_list_t * opt_instance;  // 0x28
///     method_list_t * opt_class;     // 0x30
///     ...
/// };
/// ```
fn parse_protocol_list(program: &mut Program, list_base: u64, list_size: u64) -> usize {
    let cap = list_size.min(1 << 16) as usize;
    let mut buf = vec![0u8; cap];
    if program.info.memory.read_bytes(list_base, &mut buf).is_err() {
        return 0;
    }
    let mut added = 0usize;
    for chunk in buf.chunks_exact(8) {
        let proto_addr = u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8)"));
        if proto_addr == 0 {
            continue;
        }
        let Some(name_ptr) = read_u64(program, proto_addr + 0x08) else {
            continue;
        };
        let Some(name) = read_c_str(program, name_ptr, 128) else {
            continue;
        };
        if !looks_like_identifier(&name) {
            continue;
        }
        if program.symbol_table.primary_at(proto_addr).is_none() {
            program.symbol_table.add(Symbol::new(
                format!("objc_proto_{}", sanitize(&name)),
                proto_addr,
                SymbolType::Data,
                SourceType::Analysis,
            ));
        }
        // Required instance + class methods get protocol-qualified
        // function symbols so the listing names the contract.
        for (slot, leader, kind) in [(0x18u64, '-', "req"), (0x20, '+', "req"), (0x28, '-', "opt"), (0x30, '+', "opt")] {
            let Some(ml) = read_u64(program, proto_addr + slot) else {
                continue;
            };
            if ml != 0 {
                let label = format!("{}<{}>", name, kind);
                added += parse_method_list(program, ml, &label, leader);
            }
        }
        added += 1;
    }
    added
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
            // relative to its own location. Layout:
            //   +0  i32: SEL ref     → entry + s  → &SEL → C-string
            //   +4  i32: types ref   → entry + 4 + t → @ encoded types
            //   +8  i32: IMP ref     → entry + 8 + im → function
            // We currently don't use the types string but read + discard
            // it; surfacing it as an EOL comment or per-method tag is
            // a follow-up improvement.
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

/// Validate a candidate class / protocol / ivar name: must be at least
/// 2 characters, must contain at least one ASCII alphabetic, and must
/// not contain any control characters. Rejects null / partially-read
/// strings + accidentally-parsed binary blobs that would otherwise
/// produce noise-y symbols.
fn looks_like_identifier(s: &str) -> bool {
    if s.len() < 2 {
        return false;
    }
    let mut has_alpha = false;
    for c in s.chars() {
        if c.is_control() {
            return false;
        }
        if c.is_ascii_alphabetic() {
            has_alpha = true;
        }
    }
    has_alpha
}

#[cfg(test)]
mod tests {
    use super::{looks_like_identifier, sanitize};

    #[test]
    fn module_compiles() {
        let _ = super::MachoObjCAnalyzer;
    }

    #[test]
    fn sanitize_basic() {
        assert_eq!(sanitize("My Class:Name"), "My_Class_Name");
        assert_eq!(sanitize("Foo123"), "Foo123");
    }

    #[test]
    fn identifier_accepts_normal_names() {
        assert!(looks_like_identifier("NSString"));
        assert!(looks_like_identifier("MyView_v2"));
        assert!(looks_like_identifier("__internal"));
    }

    #[test]
    fn identifier_rejects_too_short() {
        // Mach-O class names are always ≥ 2 characters (`__` etc.);
        // single-char hits are almost certainly garbage from a stray
        // pointer.
        assert!(!looks_like_identifier(""));
        assert!(!looks_like_identifier("A"));
    }

    #[test]
    fn identifier_rejects_control_chars() {
        // Random bytes 0x01..0x1f would otherwise sneak through and
        // produce noise symbols.
        assert!(!looks_like_identifier("Hello\x01World"));
        assert!(!looks_like_identifier("\x7f"));
    }

    #[test]
    fn identifier_rejects_all_digits_or_punctuation() {
        // No alphabetic anywhere — almost certainly a bad pointer
        // landed on a length-prefixed binary blob.
        assert!(!looks_like_identifier("12345"));
        assert!(!looks_like_identifier(":::"));
    }
}
