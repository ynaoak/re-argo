//! Function "carving": extract a single function (or an arbitrary VA range)
//! from a large binary into a small standalone file so size-limited tools can
//! analyse it. GUI Ghidra's importer truncates / chokes on very large images
//! (e.g. the ~222 MB Minecraft Bedrock server); carving the one function of
//! interest sidesteps the limit while keeping the original virtual address so
//! RIP-relative operands and call targets still resolve to the right addresses.
//!
//! Two container formats:
//!   * `raw` — the bytes verbatim; the caller is told the SLEIGH language id
//!     and base address to type into Ghidra's "Raw Binary" import dialog.
//!   * `elf` — a minimal single-section ELF placed at the original virtual
//!     address. Ghidra (and RE-Argo itself) auto-detect arch + base, so the
//!     carved function round-trips with zero manual setup.

use reargo_core::address::Endian;
use reargo_loader::Architecture;

/// Best-effort Ghidra SLEIGH language id for the source architecture. Used in
/// the `raw` output to tell the user what to pick in the import dialog.
pub fn ghidra_language_id(arch: Architecture, endian: Endian, thumb: bool) -> &'static str {
    use Architecture::*;
    let le = matches!(endian, Endian::Little);
    match arch {
        X86 => "x86:LE:32:default",
        X86_64 => "x86:LE:64:default",
        Arm if thumb && le => "ARM:LE:32:v8", // set TMode=1 in the Ghidra context
        Arm if thumb => "ARM:BE:32:v8",
        Arm if le => "ARM:LE:32:v8",
        Arm => "ARM:BE:32:v8",
        Arm64 if le => "AARCH64:LE:64:v8A",
        Arm64 => "AARCH64:BE:64:v8A",
        Mips if le => "MIPS:LE:32:default",
        Mips => "MIPS:BE:32:default",
        Mips64 if le => "MIPS:LE:64:default",
        Mips64 => "MIPS:BE:64:default",
        Riscv32 => "RISCV:LE:32:RV32GC",
        Riscv64 => "RISCV:LE:64:RV64GC",
        PowerPc if le => "PowerPC:LE:32:default",
        PowerPc => "PowerPC:BE:32:default",
        PowerPc64 if le => "PowerPC:LE:64:default",
        PowerPc64 => "PowerPC:BE:64:default",
        Sparc => "sparc:BE:32:default",
        Unknown => "unknown",
    }
}

/// ELF `e_machine` value for the source architecture.
fn elf_machine(arch: Architecture) -> u16 {
    use Architecture::*;
    match arch {
        X86 => 3,        // EM_386
        X86_64 => 62,    // EM_X86_64
        Arm => 40,       // EM_ARM
        Arm64 => 183,    // EM_AARCH64
        Mips | Mips64 => 8, // EM_MIPS
        Riscv32 | Riscv64 => 243, // EM_RISCV
        PowerPc => 20,   // EM_PPC
        PowerPc64 => 21, // EM_PPC64
        Sparc => 2,      // EM_SPARC
        Unknown => 0,    // EM_NONE
    }
}

/// Little helper that appends fixed-width integers in a chosen endianness.
struct Writer {
    buf: Vec<u8>,
    le: bool,
}

impl Writer {
    fn new(le: bool) -> Self {
        Self { buf: Vec::new(), le }
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&if self.le { v.to_le_bytes() } else { v.to_be_bytes() });
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&if self.le { v.to_le_bytes() } else { v.to_be_bytes() });
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&if self.le { v.to_le_bytes() } else { v.to_be_bytes() });
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
}

/// Build a minimal standalone ELF holding `data` at virtual address `base`.
///
/// Layout: `ehdr | phdr[1] | <data> | .shstrtab | shdr[3]`. The single `.text`
/// section is `SHT_PROGBITS` at `sh_addr = base` (so analysers that build memory
/// from PROGBITS sections map it) and a `PT_LOAD` segment covers the same bytes
/// (so loaders that build their address map from program headers map it too).
pub fn build_min_elf(
    arch: Architecture,
    bits: u32,
    endian: Endian,
    base: u64,
    entry: u64,
    data: &[u8],
) -> Vec<u8> {
    let le = matches!(endian, Endian::Little);
    let is64 = bits == 64;
    let machine = elf_machine(arch);

    // Section-name string table: "\0.text\0.shstrtab\0".
    let shstrtab: &[u8] = b"\0.text\0.shstrtab\0";
    let name_text: u32 = 1; // offset of ".text"
    let name_shstr: u32 = 7; // offset of ".shstrtab"

    let (ehsize, phentsize, shentsize) = if is64 { (64u64, 56u64, 64u64) } else { (52u64, 32u64, 40u64) };
    let phoff = ehsize;
    let phnum = 1u64;
    let data_off = phoff + phentsize * phnum;
    let shstr_off = data_off + data.len() as u64;
    // Align the section-header table to 8 bytes for tidiness.
    let shoff = (shstr_off + shstrtab.len() as u64 + 7) & !7;
    let shnum = 3u64; // NULL, .text, .shstrtab
    let shstrndx = 2u16;

    let mut w = Writer::new(le);

    // --- ELF header ---
    w.bytes(&[0x7f, b'E', b'L', b'F']);
    w.bytes(&[if is64 { 2 } else { 1 }]); // EI_CLASS
    w.bytes(&[if le { 1 } else { 2 }]); // EI_DATA
    w.bytes(&[1]); // EI_VERSION
    w.bytes(&[0; 9]); // EI_OSABI + pad to 16
    w.u16(2); // e_type = ET_EXEC
    w.u16(machine); // e_machine
    w.u32(1); // e_version
    if is64 {
        w.u64(entry);
        w.u64(phoff);
        w.u64(shoff);
    } else {
        w.u32(entry as u32);
        w.u32(phoff as u32);
        w.u32(shoff as u32);
    }
    w.u32(0); // e_flags
    w.u16(ehsize as u16);
    w.u16(phentsize as u16);
    w.u16(phnum as u16);
    w.u16(shentsize as u16);
    w.u16(shnum as u16);
    w.u16(shstrndx);

    // --- Program header: one PT_LOAD, R+X ---
    let filesz = data.len() as u64;
    if is64 {
        w.u32(1); // p_type = PT_LOAD
        w.u32(5); // p_flags = PF_R | PF_X
        w.u64(data_off); // p_offset
        w.u64(base); // p_vaddr
        w.u64(base); // p_paddr
        w.u64(filesz); // p_filesz
        w.u64(filesz); // p_memsz
        w.u64(0x1000); // p_align
    } else {
        w.u32(1); // p_type
        w.u32(data_off as u32); // p_offset
        w.u32(base as u32); // p_vaddr
        w.u32(base as u32); // p_paddr
        w.u32(filesz as u32); // p_filesz
        w.u32(filesz as u32); // p_memsz
        w.u32(5); // p_flags
        w.u32(0x1000); // p_align
    }

    debug_assert_eq!(w.buf.len() as u64, data_off);
    // --- carved bytes ---
    w.bytes(data);
    // --- .shstrtab ---
    w.bytes(shstrtab);
    // pad to shoff
    while (w.buf.len() as u64) < shoff {
        w.buf.push(0);
    }

    // --- Section headers ---
    // [0] NULL
    let null_shdr = if is64 { 64 } else { 40 };
    w.bytes(&vec![0u8; null_shdr]);
    // [1] .text (PROGBITS, ALLOC|EXECINSTR)
    write_shdr(&mut w, is64, name_text, 1, 0x6, base, data_off, filesz, 16, 0);
    // [2] .shstrtab (STRTAB)
    write_shdr(&mut w, is64, name_shstr, 3, 0, 0, shstr_off, shstrtab.len() as u64, 1, 0);

    w.buf
}

#[allow(clippy::too_many_arguments)]
fn write_shdr(
    w: &mut Writer,
    is64: bool,
    name: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    addralign: u64,
    entsize: u64,
) {
    w.u32(name);
    w.u32(sh_type);
    if is64 {
        w.u64(flags);
        w.u64(addr);
        w.u64(offset);
        w.u64(size);
        w.u32(0); // sh_link
        w.u32(0); // sh_info
        w.u64(addralign);
        w.u64(entsize);
    } else {
        w.u32(flags as u32);
        w.u32(addr as u32);
        w.u32(offset as u32);
        w.u32(size as u32);
        w.u32(0); // sh_link
        w.u32(0); // sh_info
        w.u32(addralign as u32);
        w.u32(entsize as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf64_roundtrips_through_loader() {
        // A tiny x86_64 stub placed at a non-trivial base.
        let base = 0x140001000u64;
        let code = vec![0x55, 0x48, 0x89, 0xe5, 0x90, 0x5d, 0xc3]; // push rbp; mov rbp,rsp; nop; pop rbp; ret
        let elf = build_min_elf(Architecture::X86_64, 64, Endian::Little, base, base, &code);

        let info = reargo_loader::BinaryLoader::load_bytes(&elf).expect("carved ELF must load");
        assert_eq!(info.arch, Architecture::X86_64);
        assert_eq!(info.entry_point, base);

        let mut buf = vec![0u8; code.len()];
        info.memory.read_bytes(base, &mut buf).expect("text must be mapped at base");
        assert_eq!(buf, code);
    }

    #[test]
    fn elf32_be_header_is_wellformed() {
        let base = 0x10000u64;
        let code = vec![0u8; 8];
        let elf = build_min_elf(Architecture::PowerPc, 32, Endian::Big, base, base, &code);
        assert_eq!(&elf[0..4], &[0x7f, b'E', b'L', b'F']);
        assert_eq!(elf[4], 1); // ELFCLASS32
        assert_eq!(elf[5], 2); // ELFDATA2MSB
        let info = reargo_loader::BinaryLoader::load_bytes(&elf).expect("carved ELF32 must load");
        assert_eq!(info.arch, Architecture::PowerPc);
    }
}
