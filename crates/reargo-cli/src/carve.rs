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
/// One loadable region of a carved file.
pub struct CarveSegment {
    /// Virtual address the bytes load at (their original VA).
    pub vaddr: u64,
    /// Executable (`.text`, R+X) vs read-only data (`.rodata`, R).
    pub exec: bool,
    pub data: Vec<u8>,
}

/// Build a minimal ELF with one PT_LOAD per segment, each placed at its
/// original VA. The first segment is `.text` (or named by its exec flag);
/// the rest become `.rodataN`. This lets a carve carry the function's
/// constant pool / jump tables so rodata-dependent decompilation (e.g.
/// float-constant resolution) works on the carved file.
pub fn build_min_elf_segments(
    arch: Architecture,
    bits: u32,
    endian: Endian,
    entry: u64,
    segments: &[CarveSegment],
) -> Vec<u8> {
    assert!(!segments.is_empty(), "at least one segment required");
    let le = matches!(endian, Endian::Little);
    let is64 = bits == 64;
    let machine = elf_machine(arch);

    // Build the section-name string table and per-section name offsets.
    // Layout: "\0" + each section name + "\0" + ".shstrtab\0".
    let mut shstrtab: Vec<u8> = vec![0];
    let mut name_offs: Vec<u32> = Vec::with_capacity(segments.len());
    for (i, seg) in segments.iter().enumerate() {
        name_offs.push(shstrtab.len() as u32);
        let nm = if i == 0 {
            if seg.exec { ".text".to_string() } else { ".rodata".to_string() }
        } else {
            format!(".rodata{}", i)
        };
        shstrtab.extend_from_slice(nm.as_bytes());
        shstrtab.push(0);
    }
    let name_shstr = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let (ehsize, phentsize, shentsize) = if is64 { (64u64, 56u64, 64u64) } else { (52u64, 32u64, 40u64) };
    let phoff = ehsize;
    let phnum = segments.len() as u64;

    // Assign 8-byte-aligned file offsets to each segment's data.
    let mut seg_off: Vec<u64> = Vec::with_capacity(segments.len());
    let mut cursor = phoff + phentsize * phnum;
    for seg in segments {
        cursor = (cursor + 7) & !7;
        seg_off.push(cursor);
        cursor += seg.data.len() as u64;
    }
    let shstr_off = cursor;
    let shoff = (shstr_off + shstrtab.len() as u64 + 7) & !7;
    let shnum = segments.len() as u64 + 2; // NULL + per-segment + .shstrtab
    let shstrndx = (segments.len() + 1) as u16;

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

    // --- Program headers: one PT_LOAD per segment ---
    for (i, seg) in segments.iter().enumerate() {
        let filesz = seg.data.len() as u64;
        let flags = if seg.exec { 5u32 } else { 4u32 }; // R+X or R
        if is64 {
            w.u32(1); // PT_LOAD
            w.u32(flags);
            w.u64(seg_off[i]);
            w.u64(seg.vaddr);
            w.u64(seg.vaddr);
            w.u64(filesz);
            w.u64(filesz);
            w.u64(0x1000);
        } else {
            w.u32(1);
            w.u32(seg_off[i] as u32);
            w.u32(seg.vaddr as u32);
            w.u32(seg.vaddr as u32);
            w.u32(filesz as u32);
            w.u32(filesz as u32);
            w.u32(flags);
            w.u32(0x1000);
        }
    }

    // --- Segment data blocks (8-byte aligned) ---
    for (i, seg) in segments.iter().enumerate() {
        while (w.buf.len() as u64) < seg_off[i] {
            w.buf.push(0);
        }
        w.bytes(&seg.data);
    }
    // --- .shstrtab ---
    debug_assert_eq!(w.buf.len() as u64, shstr_off);
    w.bytes(&shstrtab);
    // pad to shoff
    while (w.buf.len() as u64) < shoff {
        w.buf.push(0);
    }

    // --- Section headers ---
    // [0] NULL
    let null_shdr = if is64 { 64 } else { 40 };
    w.bytes(&vec![0u8; null_shdr]);
    // [1..] per-segment PROGBITS
    for (i, seg) in segments.iter().enumerate() {
        // .text = ALLOC|EXECINSTR (0x6); .rodata = ALLOC (0x2)
        let flags = if seg.exec { 0x6u64 } else { 0x2u64 };
        write_shdr(
            &mut w,
            is64,
            name_offs[i],
            1,
            flags,
            seg.vaddr,
            seg_off[i],
            seg.data.len() as u64,
            16,
            0,
        );
    }
    // [last] .shstrtab (STRTAB)
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

    fn one_text(base: u64, data: &[u8]) -> Vec<CarveSegment> {
        vec![CarveSegment { vaddr: base, exec: true, data: data.to_vec() }]
    }

    #[test]
    fn elf64_roundtrips_through_loader() {
        // A tiny x86_64 stub placed at a non-trivial base.
        let base = 0x140001000u64;
        let code = vec![0x55, 0x48, 0x89, 0xe5, 0x90, 0x5d, 0xc3]; // push rbp; mov rbp,rsp; nop; pop rbp; ret
        let elf = build_min_elf_segments(Architecture::X86_64, 64, Endian::Little, base, &one_text(base, &code));

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
        let elf = build_min_elf_segments(Architecture::PowerPc, 32, Endian::Big, base, &one_text(base, &code));
        assert_eq!(&elf[0..4], &[0x7f, b'E', b'L', b'F']);
        assert_eq!(elf[4], 1); // ELFCLASS32
        assert_eq!(elf[5], 2); // ELFDATA2MSB
        let info = reargo_loader::BinaryLoader::load_bytes(&elf).expect("carved ELF32 must load");
        assert_eq!(info.arch, Architecture::PowerPc);
    }

    #[test]
    fn multi_segment_maps_code_and_rodata() {
        // .text at a high base, plus a disjoint .rodata constant pool.
        let code_base = 0x491ba30u64;
        let data_base = 0xee4730u64;
        let code = vec![0x90, 0x90, 0xc3]; // nop; nop; ret
        let rodata = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        let segs = vec![
            CarveSegment { vaddr: code_base, exec: true, data: code.clone() },
            CarveSegment { vaddr: data_base, exec: false, data: rodata.clone() },
        ];
        let elf = build_min_elf_segments(Architecture::X86_64, 64, Endian::Little, code_base, &segs);

        let info = reargo_loader::BinaryLoader::load_bytes(&elf).expect("multi-seg ELF must load");
        assert_eq!(info.entry_point, code_base);
        let mut cbuf = vec![0u8; code.len()];
        info.memory.read_bytes(code_base, &mut cbuf).expect("code mapped");
        assert_eq!(cbuf, code);
        let mut dbuf = vec![0u8; rodata.len()];
        info.memory.read_bytes(data_base, &mut dbuf).expect("rodata mapped at its VA");
        assert_eq!(dbuf, rodata);
    }
}
