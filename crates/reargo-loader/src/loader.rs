use std::path::Path;
use std::sync::Arc;

use goblin::Object;
use reargo_core::address::Endian;

use crate::dwarf::{self, DwarfInfo};
use crate::error::LoaderError;
use crate::memory::{Memory, MemoryBlock, MemoryFlags};
use reargo_core::address::SpaceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
    Riscv32,
    Riscv64,
    PowerPc,
    PowerPc64,
    Sparc,
    Unknown,
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm => write!(f, "ARM"),
            Self::Arm64 => write!(f, "AArch64"),
            Self::Mips => write!(f, "MIPS"),
            Self::Mips64 => write!(f, "MIPS64"),
            Self::Riscv32 => write!(f, "RISC-V 32"),
            Self::Riscv64 => write!(f, "RISC-V 64"),
            Self::PowerPc => write!(f, "PowerPC"),
            Self::PowerPc64 => write!(f, "PowerPC64"),
            Self::Sparc => write!(f, "SPARC"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    Export,
    Section,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct LoadSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SectionFlags: u32 {
        const READ    = 0x4;
        const WRITE   = 0x2;
        const EXECUTE = 0x1;
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub flags: SectionFlags,
}

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub name: String,
    pub plt_address: u64,
    pub got_address: u64,
}

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct DynamicInfo {
    pub needed_libs: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    /// Entries of the functions the ELF image defines in `.dynsym`
    /// (callable from other images), sorted.
    pub exported_functions: Vec<u64>,
    /// GOT slots the dynamic loader fills with the address of a named
    /// symbol: `(slot address, symbol name)` for every `GLOB_DAT` /
    /// `JUMP_SLOT` / absolute-address relocation against a named dynamic
    /// symbol. Version suffixes are not part of the name. Sorted by slot.
    pub got_slots: Vec<(u64, String)>,
}


#[derive(Debug)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub arch: Architecture,
    pub endian: Endian,
    pub bits: u32,
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<LoadSymbol>,
    pub imports: Vec<ImportEntry>,
    pub memory: Memory,
    pub dwarf: DwarfInfo,
    pub dynamic: DynamicInfo,
    pub address_map: reargo_core::address::AddressMap,
}

pub struct BinaryLoader;

/// Parse an ELF image and return `(slot_offset, target_address)` for every
/// RELATIVE relocation (`R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE`). In a PIE
/// binary these are the absolute pointers the dynamic loader writes at load
/// time — vtable slots, function-pointer / jump tables, RTTI — whose target
/// does **not** appear in the on-disk bytes (the slot reads as zero; the
/// value lives in the relocation addend). This lets tools find indirect /
/// vtable references that a raw byte search or code-operand scan cannot see.
/// An absolute relocation against a symbol the image defines itself
/// (`R_X86_64_64` / `R_AARCH64_ABS64`) is such a pointer too (WS94): a shared
/// library refers to its exported vtables, `type_info`s and functions that way.
/// Sorted by slot.
pub fn elf_pointer_relocations(data: &[u8]) -> Vec<(u64, u64)> {
    let Ok(elf) = goblin::elf::Elf::parse(data) else {
        return Vec::new();
    };
    local_pointer_relocations(&elf, false)
}

/// [`elf_pointer_relocations`] of a parsed image; with `got`, also the GOT slots bound to a
/// symbol the image defines (`GLOB_DAT` / `JUMP_SLOT`: a shared library calling its own
/// exported function through its PLT).
fn local_pointer_relocations(elf: &goblin::elf::Elf, got: bool) -> Vec<(u64, u64)> {
    let relocs = elf.dynrelas.iter().chain(elf.pltrelocs.iter()).map(|r| {
        let sym = elf.dynsyms.get(r.r_sym).map(|s| (s.st_value, s.st_shndx, goblin::elf::sym::st_type(s.st_info)));
        (r.r_type, r.r_offset, r.r_addend, sym)
    });
    resolve_pointer_relocations(elf.header.e_machine, got, relocs)
}

/// The pointers relocations write (see [`local_pointer_relocations`]): `(type, slot, addend,
/// symbol (value, section index, type))` -> `(slot, target)` sorted by slot.
fn resolve_pointer_relocations(machine: u16, got: bool, relocs: impl Iterator<Item = (u32, u64, Option<i64>, Option<(u64, usize, u8)>)>) -> Vec<(u64, u64)> {
    const R_X86_64_RELATIVE: u32 = 8;
    const R_AARCH64_RELATIVE: u32 = 1027;
    // absolute, then GLOB_DAT, JUMP_SLOT
    let absolute: &[u32] = match (machine, got) {
        (goblin::elf::header::EM_X86_64, false) => &[1],
        (goblin::elf::header::EM_X86_64, true) => &[1, 6, 7],
        (goblin::elf::header::EM_AARCH64, false) => &[257],
        (goblin::elf::header::EM_AARCH64, true) => &[257, 1025, 1026],
        _ => &[],
    };
    let mut out = Vec::new();
    for (ty, slot, addend, sym) in relocs {
        if ty == R_X86_64_RELATIVE || ty == R_AARCH64_RELATIVE {
            if let Some(a) = addend {
                out.push((slot, a as u64));
            }
        } else if absolute.contains(&ty)
            && let Some((value, shndx, st_type)) = sym
            && shndx != 0
            && value != 0
            && st_type != goblin::elf::sym::STT_TLS
        {
            out.push((slot, value.wrapping_add(addend.unwrap_or(0) as u64)));
        }
    }
    out.sort_unstable();
    out.dedup_by_key(|r| r.0);
    out
}

/// [`local_pointer_relocations`] (with the GOT slots) as the RELA table
/// `Memory::dynamic_relocations` reads (sorted by slot; `pointer_at` searches it): every entry
/// relative (`R_X86_64_RELATIVE`, or `R_AARCH64_RELATIVE` for an AArch64 image). Read from the
/// section's bytes (`raw`) directly: a program has hundreds of thousands of them.
fn relative_rela_table(elf: &goblin::elf::Elf, raw: &[u8]) -> Arc<[u8]> {
    let aarch64 = elf.header.e_machine == goblin::elf::header::EM_AARCH64;
    let relative: u32 = if aarch64 { 1027 } else { 8 };
    let absolute: &[u32] = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => &[1, 6, 7],
        goblin::elf::header::EM_AARCH64 => &[257, 1025, 1026],
        _ => &[],
    };
    // a symbol the image defines (not thread-local): its value
    let own = |sym: usize| {
        elf.dynsyms
            .get(sym)
            .filter(|s| s.st_shndx != 0 && s.st_value != 0 && goblin::elf::sym::st_type(s.st_info) != goblin::elf::sym::STT_TLS)
            .map(|s| s.st_value)
    };
    let plt = elf.pltrelocs.iter().filter(|r| absolute.contains(&r.r_type)).filter_map(|r| Some((r.r_offset, own(r.r_sym)?.wrapping_add(r.r_addend.unwrap_or(0) as u64))));
    Arc::from(relative_table(raw, relative, absolute, own, plt))
}

/// [`relative_rela_table`] of the RELA entries `raw`: `own` gives the value of a symbol the
/// image defines, `plt` the GOT slots of `.rela.plt` bound to one.
fn relative_table(raw: &[u8], relative: u32, absolute: &[u32], own: impl Fn(usize) -> Option<u64>, plt: impl Iterator<Item = (u64, u64)>) -> Vec<u8> {
    // the relative entries as they are (in a program, all of them but a few imports, sorted)
    let word = |e: &[u8], k: usize| u64::from_le_bytes(e[k * 8..k * 8 + 8].try_into().expect("8 bytes"));
    let mut table: Vec<u8> = Vec::with_capacity(raw.len());
    let mut extra: Vec<(u64, u64)> = Vec::new();
    let mut prev = 0u64;
    let mut sorted = true;
    for e in raw.chunks_exact(24) {
        let (slot, info, addend) = (word(e, 0), word(e, 1), word(e, 2));
        let ty = info as u32;
        if ty == relative {
            sorted &= slot > prev || table.is_empty();
            prev = slot;
            table.extend_from_slice(e);
        } else if absolute.contains(&ty)
            && let Some(v) = own((info >> 32) as usize)
        {
            extra.push((slot, v.wrapping_add(addend)));
        }
    }
    extra.extend(plt);
    if extra.is_empty() && sorted {
        return table;
    }
    let mut all: Vec<(u64, u64)> = table.chunks_exact(24).map(|e| (word(e, 0), word(e, 2))).chain(extra).collect();
    all.sort_unstable();
    all.dedup_by_key(|r| r.0);
    let ty = u64::from(relative).to_le_bytes();
    table.clear();
    for (slot, target) in all {
        table.extend_from_slice(&slot.to_le_bytes());
        table.extend_from_slice(&ty);
        table.extend_from_slice(&target.to_le_bytes());
    }
    table
}

/// The functions an ELF exports (WS93): defined `STT_FUNC` / `STT_GNU_IFUNC` dynamic symbols
/// with global or weak binding and default or protected visibility — another module may call
/// them with anything.
pub fn elf_exported_functions(data: &[u8]) -> Vec<u64> {
    use goblin::elf::sym;
    let Ok(elf) = goblin::elf::Elf::parse(data) else {
        return Vec::new();
    };
    let mut out: Vec<u64> = elf
        .dynsyms
        .iter()
        .filter(|s| {
            s.st_value != 0
                && s.st_shndx != 0
                && matches!(sym::st_type(s.st_info), sym::STT_FUNC | sym::STT_GNU_IFUNC)
                && matches!(sym::st_bind(s.st_info), sym::STB_GLOBAL | sym::STB_WEAK)
                && matches!(sym::st_visibility(s.st_other), sym::STV_DEFAULT | sym::STV_PROTECTED)
        })
        .map(|s| s.st_value)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The PLT stubs of an ELF's imports (WS95): `(stub address, symbol name)` for each `.rela.plt`
/// entry, at its `.plt` (after the resolver header), `.plt.sec` and `.plt.got` slots.
pub fn elf_import_stubs(data: &[u8]) -> Vec<(u64, String)> {
    let Ok(elf) = goblin::elf::Elf::parse(data) else {
        return Vec::new();
    };
    // (WS96) each stub's `jmp [rip + slot]` names its GOT slot, the slot's relocation the
    // symbol: right for `.plt`, `.plt.sec` (IBT) and `.plt.got` alike (the stubs are not in
    // relocation order in the last two)
    let mut by_slot: std::collections::HashMap<u64, &str> = std::collections::HashMap::new();
    for reloc in elf.pltrelocs.iter().chain(elf.dynrelas.iter()) {
        if let Some(name) = elf.dynsyms.get(reloc.r_sym).and_then(|s| elf.dynstrtab.get_at(s.st_name)).filter(|n| !n.is_empty()) {
            by_slot.entry(reloc.r_offset).or_insert(name);
        }
    }
    let mut out = Vec::new();
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if !matches!(name, ".plt" | ".plt.sec" | ".plt.got") || sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
            continue;
        }
        let Some(bytes) = data.get(sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize) else { continue };
        for (stub, slot) in plt_stub_slots(sh.sh_addr, bytes) {
            if let Some(n) = by_slot.get(&slot) {
                out.push((stub, n.to_string()));
            }
        }
    }
    out
}

/// The stubs of a PLT section at `addr` and the GOT slot each jumps through: `(stub, slot)` for
/// every entry (16 bytes, or 8 for an 8-byte `.plt.got`) holding `jmp [rip + d]` at its start,
/// after `endbr64` and / or a `bnd` prefix.
fn plt_stub_slots(addr: u64, bytes: &[u8]) -> Vec<(u64, u64)> {
    let entry = if bytes.len().is_multiple_of(16) { 16 } else { 8 };
    let mut out = Vec::new();
    for (k, e) in bytes.chunks(entry).enumerate() {
        let start = addr + (k * entry) as u64;
        for at in [0usize, 1, 4, 5] {
            if e.get(at..at + 2) == Some(&[0xff, 0x25]) && (at == 0 || e[..at] == [0xf2] || e[..4] == [0xf3, 0x0f, 0x1e, 0xfa]) {
                let Some(d) = e.get(at + 2..at + 6) else { break };
                let d = i32::from_le_bytes(d.try_into().expect("4 bytes"));
                out.push((start, (start + at as u64 + 6).wrapping_add(d as i64 as u64)));
                break;
            }
        }
    }
    out
}

impl BinaryLoader {
    pub fn load(path: &Path) -> Result<BinaryInfo, LoaderError> {
        let data = std::fs::read(path)?;
        Self::load_bytes(&data)
    }

    pub fn load_bytes(data: &[u8]) -> Result<BinaryInfo, LoaderError> {
        let dwarf_info = dwarf::parse_dwarf(data).unwrap_or_default();
        let mut info = match Object::parse(data).map_err(|e| LoaderError::Parse(e.to_string()))? {
            Object::Elf(elf) => Self::load_elf(&elf, data),
            Object::PE(pe) => Self::load_pe(&pe, data),
            Object::Mach(mach) => Self::load_mach(&mach, data),
            _ => Err(LoaderError::UnsupportedFormat),
        }?;
        info.dwarf = dwarf_info;
        Ok(info)
    }

    pub fn load_raw(data: &[u8], base_address: u64, arch: Architecture, endian: Endian) -> BinaryInfo {
        let ram_space = SpaceId::RAM;
        let mut memory = Memory::new(ram_space, endian);
        memory.add_block(MemoryBlock {
            name: ".raw".into(),
            start: base_address,
            size: data.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::WRITE | MemoryFlags::EXECUTE,
            data: Some(Arc::from(data)),
        });

        let bits = match arch {
            Architecture::X86 | Architecture::Arm | Architecture::Mips
            | Architecture::PowerPc | Architecture::Riscv32 => 32,
            _ => 64,
        };

        let mut address_map = reargo_core::address::AddressMap::new();
        address_map.add_mapping(0, base_address, data.len() as u64);

        BinaryInfo {
            format: BinaryFormat::Unknown,
            arch,
            endian,
            bits,
            entry_point: base_address,
            sections: vec![Section {
                name: ".raw".into(),
                address: base_address,
                size: data.len() as u64,
                flags: SectionFlags::READ | SectionFlags::WRITE | SectionFlags::EXECUTE,
            }],
            symbols: Vec::new(),
            imports: Vec::new(),
            memory,
            dwarf: DwarfInfo::default(),
            dynamic: DynamicInfo::default(),
            address_map,
        }
    }

    fn load_elf(elf: &goblin::elf::Elf, data: &[u8]) -> Result<BinaryInfo, LoaderError> {
        let endian = if elf.little_endian {
            Endian::Little
        } else {
            Endian::Big
        };
        let bits = if elf.is_64 { 64 } else { 32 };
        let arch = Self::elf_arch(elf);

        let ram_space = SpaceId::RAM;
        let mut memory = Memory::new(ram_space, endian);

        let mut sections = Vec::new();
        for sh in &elf.section_headers {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("")
                .to_string();
            if sh.sh_type == goblin::elf::section_header::SHT_NULL {
                continue;
            }

            let mut flags = SectionFlags::empty();
            if sh.sh_flags as u32 & goblin::elf::section_header::SHF_WRITE != 0 {
                flags |= SectionFlags::WRITE;
            }
            if sh.sh_flags as u32 & goblin::elf::section_header::SHF_EXECINSTR != 0 {
                flags |= SectionFlags::EXECUTE;
            }
            if sh.sh_flags as u32 & goblin::elf::section_header::SHF_ALLOC != 0 {
                flags |= SectionFlags::READ;
            }

            sections.push(Section {
                name: name.clone(),
                address: sh.sh_addr,
                size: sh.sh_size,
                flags,
            });

            // the dynamic relocations of a 64-bit image, for reading the pointers a PIE's
            // loader writes (`Memory::dynamic_relocations`)
            // (WS94: relative, and absolute against a symbol the image defines, sorted)
            if sh.sh_type == goblin::elf::section_header::SHT_RELA
                && name == ".rela.dyn"
                && elf.is_64
                && let Some(table) = data.get(sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize)
            {
                memory.set_dynamic_relocations(relative_rela_table(elf, table));
            }

            if sh.sh_type == goblin::elf::section_header::SHT_PROGBITS
                && sh.sh_addr != 0
                && sh.sh_size > 0
            {
                let file_offset = sh.sh_offset as usize;
                let file_end = file_offset + sh.sh_size as usize;
                let block_data = if file_end <= data.len() {
                    Some(Arc::from(&data[file_offset..file_end]))
                } else {
                    None
                };

                let mut mem_flags = MemoryFlags::empty();
                if flags.contains(SectionFlags::READ) {
                    mem_flags |= MemoryFlags::READ;
                }
                if flags.contains(SectionFlags::WRITE) {
                    mem_flags |= MemoryFlags::WRITE;
                }
                if flags.contains(SectionFlags::EXECUTE) {
                    mem_flags |= MemoryFlags::EXECUTE;
                }

                memory.add_block(MemoryBlock {
                    name,
                    start: sh.sh_addr,
                    size: sh.sh_size,
                    flags: mem_flags,
                    data: block_data,
                });
            }
        }

        let mut symbols = Vec::new();
        for sym in elf.syms.iter() {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let kind = match goblin::elf::sym::st_type(sym.st_info) {
                goblin::elf::sym::STT_FUNC => SymbolKind::Function,
                goblin::elf::sym::STT_OBJECT => SymbolKind::Data,
                goblin::elf::sym::STT_SECTION => SymbolKind::Section,
                _ => SymbolKind::Unknown,
            };
            symbols.push(LoadSymbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                kind,
            });
        }

        for sym in elf.dynsyms.iter() {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let kind = if sym.is_import() {
                SymbolKind::Import
            } else {
                match goblin::elf::sym::st_type(sym.st_info) {
                    goblin::elf::sym::STT_FUNC => SymbolKind::Function,
                    goblin::elf::sym::STT_OBJECT => SymbolKind::Data,
                    _ => SymbolKind::Unknown,
                }
            };
            symbols.push(LoadSymbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                kind,
            });
        }

        // Modern glibc + linkers split the PLT in two when CET / IBT is
        // enabled:
        //   `.plt`     — legacy stubs, kept for fallback; index 0 is the
        //                resolver header, so import i lives at +`(i+1)*16`.
        //   `.plt.sec` — IBT-aware entries called directly by compiler
        //                output; no header, so import i lives at +`i*16`.
        //   `.plt.got` — bind-now variant used when the linker can resolve
        //                lazily-bound stubs at load time; same shape as
        //                `.plt.sec` but indexed independently.
        //
        // The relocation order in `.rela.plt` is the canonical mapping
        // both sections obey, so we can emit `name@plt` symbols at every
        // matching base. Without this, callers that target `.plt.sec`
        // (CET binaries → essentially everything on modern distros) see
        // no symbol at the call target and downstream signature- /
        // call-site analyzers all silently miss.
        let mut imports = Vec::new();
        let section_addr = |want: &str| -> Option<u64> {
            elf.section_headers
                .iter()
                .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == want)
                .map(|sh| sh.sh_addr)
        };
        let plt_base = section_addr(".plt").unwrap_or(0);
        let plt_sec_base = section_addr(".plt.sec");
        let plt_got_base = section_addr(".plt.got");
        let plt_entry_size: u64 = 16;

        for (i, reloc) in elf.pltrelocs.iter().enumerate() {
            let sym_idx = reloc.r_sym;
            if let Some(sym) = elf.dynsyms.get(sym_idx) {
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
                if !name.is_empty() {
                    let plt_addr = plt_base + (i as u64 + 1) * plt_entry_size;
                    let got_addr = reloc.r_offset;
                    imports.push(ImportEntry {
                        name: name.clone(),
                        plt_address: plt_addr,
                        got_address: got_addr,
                    });
                    symbols.push(LoadSymbol {
                        name: format!("{}@plt", name),
                        address: plt_addr,
                        size: plt_entry_size,
                        kind: SymbolKind::Function,
                    });
                    if let Some(base) = plt_sec_base {
                        symbols.push(LoadSymbol {
                            name: format!("{}@plt", name),
                            address: base + i as u64 * plt_entry_size,
                            size: plt_entry_size,
                            kind: SymbolKind::Function,
                        });
                    }
                    if let Some(base) = plt_got_base {
                        symbols.push(LoadSymbol {
                            name: format!("{}@plt", name),
                            address: base + i as u64 * plt_entry_size,
                            size: plt_entry_size,
                            kind: SymbolKind::Function,
                        });
                    }
                    symbols.push(LoadSymbol {
                        name: format!("{}@GOT", name),
                        address: got_addr,
                        size: if bits == 64 { 8 } else { 4 },
                        kind: SymbolKind::Data,
                    });
                }
            }
        }

        let mut exported_functions: Vec<u64> = elf
            .dynsyms
            .iter()
            .filter(|sym| {
                !sym.is_import()
                    && sym.st_value != 0
                    && matches!(
                        goblin::elf::sym::st_type(sym.st_info),
                        goblin::elf::sym::STT_FUNC | goblin::elf::sym::STT_GNU_IFUNC
                    )
            })
            .map(|sym| sym.st_value)
            .collect();
        exported_functions.sort_unstable();
        exported_functions.dedup();
        let mut got_slots: Vec<(u64, String)> = Vec::new();
        for reloc in elf.dynrelas.iter().chain(elf.pltrelocs.iter()) {
            if !Self::is_symbol_binding_reloc(elf.header.e_machine, reloc.r_type) || reloc.r_sym == 0 {
                continue;
            }
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym)
                && let Some(name) = elf.dynstrtab.get_at(sym.st_name)
                && !name.is_empty()
            {
                got_slots.push((reloc.r_offset, name.to_string()));
            }
        }
        got_slots.sort_unstable();
        got_slots.dedup();
        let mut dynamic = DynamicInfo { exported_functions, got_slots, ..DynamicInfo::default() };
        if let Some(ref dyns) = elf.dynamic {
            for d in &dyns.dyns {
                if d.d_tag == goblin::elf::dynamic::DT_NEEDED
                    && let Some(name) = elf.dynstrtab.get_at(d.d_val as usize) {
                        dynamic.needed_libs.push(name.to_string());
                    }
                if d.d_tag == goblin::elf::dynamic::DT_SONAME
                    && let Some(name) = elf.dynstrtab.get_at(d.d_val as usize) {
                        dynamic.soname = Some(name.to_string());
                    }
            }
        }

        let mut address_map = reargo_core::address::AddressMap::new();
        for ph in &elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD && ph.p_filesz > 0 {
                address_map.add_mapping(ph.p_offset, ph.p_vaddr, ph.p_filesz);
            }
        }

        Ok(BinaryInfo {
            format: BinaryFormat::Elf,
            arch,
            endian,
            bits,
            entry_point: elf.entry,
            sections,
            symbols,
            imports,
            memory,
            dwarf: DwarfInfo::default(),
            dynamic,
            address_map,
        })
    }

    /// Relocation types that store a symbol's address in a slot
    /// (`GLOB_DAT`, `JUMP_SLOT`, absolute) for the machines we resolve
    /// GOT slots on.
    fn is_symbol_binding_reloc(machine: u16, r_type: u32) -> bool {
        use goblin::elf::header::{EM_386, EM_AARCH64, EM_X86_64};
        match machine {
            // R_X86_64_64, GLOB_DAT, JUMP_SLOT
            EM_X86_64 => matches!(r_type, 1 | 6 | 7),
            // R_386_32, GLOB_DAT, JMP_SLOT
            EM_386 => matches!(r_type, 1 | 6 | 7),
            // R_AARCH64_ABS64, GLOB_DAT, JUMP_SLOT
            EM_AARCH64 => matches!(r_type, 257 | 1025 | 1026),
            _ => false,
        }
    }

    fn elf_arch(elf: &goblin::elf::Elf) -> Architecture {
        match elf.header.e_machine {
            goblin::elf::header::EM_386 => Architecture::X86,
            goblin::elf::header::EM_X86_64 => Architecture::X86_64,
            goblin::elf::header::EM_ARM => Architecture::Arm,
            goblin::elf::header::EM_AARCH64 => Architecture::Arm64,
            goblin::elf::header::EM_MIPS => {
                if elf.is_64 {
                    Architecture::Mips64
                } else {
                    Architecture::Mips
                }
            }
            goblin::elf::header::EM_PPC => Architecture::PowerPc,
            goblin::elf::header::EM_PPC64 => Architecture::PowerPc64,
            goblin::elf::header::EM_SPARC | goblin::elf::header::EM_SPARCV9 => Architecture::Sparc,
            goblin::elf::header::EM_RISCV => {
                if elf.is_64 {
                    Architecture::Riscv64
                } else {
                    Architecture::Riscv32
                }
            }
            _ => Architecture::Unknown,
        }
    }

    fn load_pe(pe: &goblin::pe::PE, data: &[u8]) -> Result<BinaryInfo, LoaderError> {
        let bits = if pe.is_64 { 64 } else { 32 };
        let arch = if pe.is_64 {
            Architecture::X86_64
        } else {
            Architecture::X86
        };

        let image_base = pe.image_base as u64;
        let ram_space = SpaceId::RAM;
        let mut memory = Memory::new(ram_space, Endian::Little);

        let mut sections = Vec::new();
        for section in &pe.sections {
            let name = String::from_utf8_lossy(
                &section.name[..section.name.iter().position(|&b| b == 0).unwrap_or(section.name.len())],
            )
            .to_string();

            let chars = section.characteristics;
            let mut flags = SectionFlags::empty();
            if chars & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0 {
                flags |= SectionFlags::READ;
            }
            if chars & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0 {
                flags |= SectionFlags::WRITE;
            }
            if chars & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
                flags |= SectionFlags::EXECUTE;
            }

            let vaddr = image_base + section.virtual_address as u64;
            let vsize = section.virtual_size as u64;
            sections.push(Section {
                name: name.clone(),
                address: vaddr,
                size: vsize,
                flags,
            });

            let raw_offset = section.pointer_to_raw_data as usize;
            let raw_size = section.size_of_raw_data as usize;
            let block_data = if raw_size > 0 && raw_offset + raw_size <= data.len() {
                Some(Arc::from(&data[raw_offset..raw_offset + raw_size]))
            } else {
                None
            };

            let mut mem_flags = MemoryFlags::empty();
            if flags.contains(SectionFlags::READ) {
                mem_flags |= MemoryFlags::READ;
            }
            if flags.contains(SectionFlags::WRITE) {
                mem_flags |= MemoryFlags::WRITE;
            }
            if flags.contains(SectionFlags::EXECUTE) {
                mem_flags |= MemoryFlags::EXECUTE;
            }

            memory.add_block(MemoryBlock {
                name,
                start: vaddr,
                size: vsize,
                flags: mem_flags,
                data: block_data,
            });
        }

        let mut symbols = Vec::new();
        for export in &pe.exports {
            if let Some(ref name) = export.name {
                symbols.push(LoadSymbol {
                    name: name.to_string(),
                    address: export.rva as u64 + image_base,
                    size: 0,
                    kind: SymbolKind::Export,
                });
            }
        }
        let mut imports = Vec::new();
        for import in &pe.imports {
            let addr = import.rva as u64 + image_base;
            symbols.push(LoadSymbol {
                name: import.name.to_string(),
                address: addr,
                size: 0,
                kind: SymbolKind::Import,
            });
            imports.push(ImportEntry {
                name: import.name.to_string(),
                plt_address: addr,
                got_address: import.rva as u64 + image_base,
            });
        }

        let entry = pe
            .header
            .optional_header
            .map(|oh| oh.standard_fields.address_of_entry_point + image_base)
            .unwrap_or(0);

        Ok(BinaryInfo {
            format: BinaryFormat::Pe,
            arch,
            endian: Endian::Little,
            bits,
            entry_point: entry,
            sections,
            symbols,
            imports,
            memory,
            dwarf: DwarfInfo::default(),
            dynamic: DynamicInfo::default(),
            address_map: reargo_core::address::AddressMap::new(),
        })
    }

    fn load_mach(mach: &goblin::mach::Mach, data: &[u8]) -> Result<BinaryInfo, LoaderError> {
        match mach {
            goblin::mach::Mach::Binary(macho) => Self::load_macho_single(macho, data),
            goblin::mach::Mach::Fat(fat) => {
                match fat.get(0).map_err(|e| LoaderError::Parse(e.to_string()))? {
                    goblin::mach::SingleArch::MachO(macho) => {
                        Self::load_macho_single(&macho, data)
                    }
                    _ => Err(LoaderError::UnsupportedFormat),
                }
            }
        }
    }

    fn load_macho_single(
        macho: &goblin::mach::MachO,
        data: &[u8],
    ) -> Result<BinaryInfo, LoaderError> {
        let endian = if macho.little_endian {
            Endian::Little
        } else {
            Endian::Big
        };
        let bits = if macho.is_64 { 64 } else { 32 };
        let arch = Self::mach_arch(macho);

        let ram_space = SpaceId::RAM;
        let mut memory = Memory::new(ram_space, endian);

        let mut sections = Vec::new();
        for segment in macho.segments.iter() {
            for (sec, _) in segment.sections().unwrap_or_default() {
                let sect_name = String::from_utf8_lossy(&sec.sectname)
                    .trim_end_matches('\0')
                    .to_string();
                let seg_name = String::from_utf8_lossy(&sec.segname)
                    .trim_end_matches('\0')
                    .to_string();
                let full_name = format!("{}.{}", seg_name, sect_name);

                let mut flags = SectionFlags::READ;
                if seg_name == "__DATA" || seg_name == "__DATA_CONST" {
                    flags |= SectionFlags::WRITE;
                }
                if seg_name == "__TEXT" {
                    flags |= SectionFlags::EXECUTE;
                }

                sections.push(Section {
                    name: full_name.clone(),
                    address: sec.addr,
                    size: sec.size,
                    flags,
                });

                let offset = sec.offset as usize;
                let sz = sec.size as usize;
                let block_data = if sz > 0 && offset + sz <= data.len() {
                    Some(Arc::from(&data[offset..offset + sz]))
                } else {
                    None
                };

                let mut mem_flags = MemoryFlags::READ;
                if flags.contains(SectionFlags::WRITE) {
                    mem_flags |= MemoryFlags::WRITE;
                }
                if flags.contains(SectionFlags::EXECUTE) {
                    mem_flags |= MemoryFlags::EXECUTE;
                }

                memory.add_block(MemoryBlock {
                    name: full_name,
                    start: sec.addr,
                    size: sec.size,
                    flags: mem_flags,
                    data: block_data,
                });
            }
        }

        let mut symbols = Vec::new();
        if let Some(ref syms) = macho.symbols {
            for (name, nlist) in syms.iter().flatten() {
                if name.is_empty() {
                    continue;
                }
                let clean_name = name.strip_prefix('_').unwrap_or(name).to_string();
                let kind = if nlist.is_undefined() {
                    SymbolKind::Import
                } else if nlist.n_type & 0x0e == 0x0e {
                    SymbolKind::Function
                } else {
                    SymbolKind::Unknown
                };
                symbols.push(LoadSymbol {
                    name: clean_name,
                    address: nlist.n_value,
                    size: 0,
                    kind,
                });
            }
        }

        Ok(BinaryInfo {
            format: BinaryFormat::MachO,
            arch,
            endian,
            bits,
            entry_point: macho.entry,
            sections,
            symbols,
            imports: Vec::new(),
            memory,
            dwarf: DwarfInfo::default(),
            dynamic: DynamicInfo::default(),
            address_map: reargo_core::address::AddressMap::new(),
        })
    }

    fn mach_arch(macho: &goblin::mach::MachO) -> Architecture {
        use goblin::mach::cputype::*;
        match macho.header.cputype() {
            CPU_TYPE_X86 => Architecture::X86,
            CPU_TYPE_X86_64 => Architecture::X86_64,
            CPU_TYPE_ARM => Architecture::Arm,
            CPU_TYPE_ARM64 => Architecture::Arm64,
            CPU_TYPE_POWERPC => Architecture::PowerPc,
            CPU_TYPE_POWERPC64 => Architecture::PowerPc64,
            _ => Architecture::Unknown,
        }
    }
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf => write!(f, "ELF"),
            Self::Pe => write!(f, "PE"),
            Self::MachO => write!(f, "Mach-O"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Function => write!(f, "FUNC"),
            Self::Data => write!(f, "DATA"),
            Self::Import => write!(f, "IMPORT"),
            Self::Export => write!(f, "EXPORT"),
            Self::Section => write!(f, "SECTION"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[cfg(test)]
mod reloc_tests {
    use super::{elf_exported_functions, elf_pointer_relocations, plt_stub_slots, relative_table, resolve_pointer_relocations};

    /// WS96: a PLT stub's GOT slot comes from its own `jmp [rip + d]` — a lazy `.plt` entry, an
    /// IBT `.plt.sec` one (`endbr64; bnd jmp`), an 8-byte `.plt.got` one; the `.plt` header (no
    /// such jump at its start) is none.
    #[test]
    fn plt_stubs_name_their_got_slots() {
        // .plt at 0x1000: header (push [rip]; jmp [rip]); entry 1: jmp [rip + 0x2000]; push 0; jmp .plt
        let mut plt = vec![0xff, 0x35, 0, 0, 0, 0, 0xf2, 0xff, 0x25, 0, 0, 0, 0, 0x0f, 0x1f, 0x00];
        plt.extend([0xff, 0x25, 0x00, 0x20, 0x00, 0x00, 0x68, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0]);
        assert_eq!(plt_stub_slots(0x1000, &plt), [(0x1010, 0x1016 + 0x2000)]);
        // .plt.sec at 0x2000: endbr64 ; bnd jmp [rip + 0x100] ; nop
        let sec = [0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0x00, 0x01, 0x00, 0x00, 0x0f, 0x1f, 0x44, 0x00, 0x00];
        assert_eq!(plt_stub_slots(0x2000, &sec), [(0x2000, 0x200b + 0x100)]);
        // .plt.got (8-byte entries): jmp [rip + 0x10] ; xchg ax, ax
        let got = [0xff, 0x25, 0x10, 0x00, 0x00, 0x00, 0x66, 0x90, 0xff, 0x25, 0x20, 0x00, 0x00, 0x00, 0x66, 0x90, 0xff, 0x25, 0x30, 0x00, 0x00, 0x00, 0x66, 0x90];
        assert_eq!(plt_stub_slots(0x3000, &got), [(0x3000, 0x3016), (0x3008, 0x302e), (0x3010, 0x3046)]);
    }

    /// WS93: no exports in what is no ELF; a BDS-internal function (`REARGO_TEST_BDS`) is none.
    #[test]
    fn exported_functions() {
        assert!(elf_exported_functions(b"not an elf").is_empty());
        let Ok(path) = std::env::var("REARGO_TEST_BDS") else { return };
        let ex = elf_exported_functions(&std::fs::read(path).unwrap());
        assert!(!ex.contains(&0x4bd0820), "{} exports", ex.len());
    }

    /// WS94: relative relocations, and absolute (and GOT, when asked) ones against a symbol the
    /// image defines (not an undefined one, not a thread-local one), sorted by slot.
    #[test]
    fn pointer_relocations_resolve_the_symbols_the_image_defines() {
        use goblin::elf::{header::EM_X86_64, sym::{STT_FUNC, STT_OBJECT, STT_TLS}};
        let relocs = vec![
            (8u32, 0x3010u64, Some(0x1100i64), None),
            (1, 0x3000, Some(0x10), Some((0x2000u64, 12usize, STT_OBJECT))), // a vtable + 0x10
            (1, 0x3008, Some(0), Some((0, 0, STT_FUNC))),                     // an import
            (7, 0x4000, Some(0), Some((0x1200, 11, STT_FUNC))),               // its own function's GOT slot
            (6, 0x4008, Some(0), Some((0x80, 13, STT_TLS))),                  // thread-local
            (5, 0x4010, Some(0), Some((0x1300, 11, STT_FUNC))),               // a copy relocation
        ];
        assert_eq!(resolve_pointer_relocations(EM_X86_64, true, relocs.clone().into_iter()), [(0x3000, 0x2010), (0x3010, 0x1100), (0x4000, 0x1200)]);
        assert_eq!(resolve_pointer_relocations(EM_X86_64, false, relocs.into_iter()), [(0x3000, 0x2010), (0x3010, 0x1100)], "no GOT slots");
        let relative_only = vec![(8u32, 0x3010u64, Some(0x1100i64), None), (1, 0x3000, Some(0x10), Some((0x2000u64, 12usize, STT_OBJECT)))];
        assert_eq!(resolve_pointer_relocations(0, true, relative_only.into_iter()), [(0x3010, 0x1100)], "another machine");
    }

    /// WS94: the table `Memory` reads: relative entries kept as they are when sorted and nothing
    /// is added; else absolute / GOT entries against the image's own symbols added as relative
    /// ones, imports dropped, sorted by slot.
    #[test]
    fn the_memory_table_is_relative_and_sorted() {
        let e = |slot: u64, info: u64, addend: u64| [slot.to_le_bytes(), info.to_le_bytes(), addend.to_le_bytes()].concat();
        let own = |sym: usize| (sym == 3).then_some(0x2000u64);
        // sorted relative entries and an import: the relative ones as they are
        let raw = [e(0x3000, 8, 0x1100), e(0x3008, 8, 0x1200), e(0x3010, (2 << 32) | 1, 0)].concat();
        assert_eq!(relative_table(&raw, 8, &[1, 6, 7], own, std::iter::empty()), [e(0x3000, 8, 0x1100), e(0x3008, 8, 0x1200)].concat());
        // an absolute entry against the image's own symbol 3 (+0x10), a bound GOT slot, out of order
        let raw = [e(0x3008, 8, 0x1200), e(0x3000, (3 << 32) | 1, 0x10), e(0x2ff8, 8, 0x1100)].concat();
        let t = relative_table(&raw, 8, &[1, 6, 7], own, [(0x4000, 0x1300)].into_iter());
        assert_eq!(t, [e(0x2ff8, 8, 0x1100), e(0x3000, 8, 0x2010), e(0x3008, 8, 0x1200), e(0x4000, 8, 0x1300)].concat());
    }

    #[test]
    fn non_elf_returns_empty_without_panicking() {
        assert!(elf_pointer_relocations(b"not an elf").is_empty());
        assert!(elf_pointer_relocations(&[]).is_empty());
        // A valid ELF magic but truncated body must also not panic.
        assert!(elf_pointer_relocations(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).is_empty());
    }
}
