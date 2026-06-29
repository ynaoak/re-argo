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
pub fn elf_pointer_relocations(data: &[u8]) -> Vec<(u64, u64)> {
    const R_X86_64_RELATIVE: u32 = 8;
    const R_AARCH64_RELATIVE: u32 = 1027;
    let Ok(elf) = goblin::elf::Elf::parse(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for reloc in elf.dynrelas.iter().chain(elf.pltrelocs.iter()) {
        if (reloc.r_type == R_X86_64_RELATIVE || reloc.r_type == R_AARCH64_RELATIVE)
            && let Some(addend) = reloc.r_addend
        {
            out.push((reloc.r_offset, addend as u64));
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

        let mut dynamic = DynamicInfo::default();
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
    use super::elf_pointer_relocations;

    #[test]
    fn non_elf_returns_empty_without_panicking() {
        assert!(elf_pointer_relocations(b"not an elf").is_empty());
        assert!(elf_pointer_relocations(&[]).is_empty());
        // A valid ELF magic but truncated body must also not panic.
        assert!(elf_pointer_relocations(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).is_empty());
    }
}
