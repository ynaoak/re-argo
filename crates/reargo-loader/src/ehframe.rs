//! Function bounds from an ELF's `.eh_frame_hdr` binary-search table.
//!
//! Stripped C++ binaries (e.g. the 230 MB Bedrock server) keep complete unwind
//! info, so the FDE covering an address gives that function's exact
//! `[start, start + len)` without running any analysis. This is what lets
//! `decompile --fast` work on a binary whose full analysis takes tens of minutes.

/// `DW_EH_PE_*` pointer-encoding helpers.
const DW_EH_PE_OMIT: u8 = 0xff;

struct Image<'a> {
    data: &'a [u8],
    /// `(vaddr, file offset, size)` of every section with file contents.
    sections: Vec<(u64, u64, u64)>,
}

impl Image<'_> {
    fn offset_of(&self, va: u64) -> Option<usize> {
        self.sections
            .iter()
            .find(|&&(a, _, s)| va >= a && va < a + s)
            .map(|&(a, o, _)| (va - a + o) as usize)
    }
    fn bytes(&self, va: u64, n: usize) -> Option<&[u8]> {
        let o = self.offset_of(va)?;
        self.data.get(o..o + n)
    }
    fn u8(&self, va: u64) -> Option<u8> {
        self.bytes(va, 1).map(|b| b[0])
    }
    fn u32(&self, va: u64) -> Option<u32> {
        self.bytes(va, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn u64(&self, va: u64) -> Option<u64> {
        self.bytes(va, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
    fn uleb(&self, va: &mut u64) -> Option<u64> {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let b = self.u8(*va)?;
            *va += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
    }
    fn sleb(&self, va: &mut u64) -> Option<i64> {
        let (mut v, mut shift) = (0i64, 0);
        loop {
            let b = self.u8(*va)?;
            *va += 1;
            v |= i64::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1 << shift;
                }
                return Some(v);
            }
            if shift >= 64 {
                return None;
            }
        }
    }
    /// Read a pointer with encoding `enc` at `*va`. `datarel` is the base for
    /// `DW_EH_PE_datarel` (the `.eh_frame_hdr` start).
    fn encoded(&self, va: &mut u64, enc: u8, datarel: u64) -> Option<u64> {
        let at = *va;
        let raw: u64 = match enc & 0x0f {
            0x00 => {
                *va += 8;
                self.u64(at)?
            }
            0x01 => self.uleb(va)?,
            0x02 => {
                *va += 2;
                u64::from(u16::from_le_bytes(self.bytes(at, 2)?.try_into().ok()?))
            }
            0x03 => {
                *va += 4;
                u64::from(self.u32(at)?)
            }
            0x04 => {
                *va += 8;
                self.u64(at)?
            }
            0x09 => self.sleb(va)? as u64,
            0x0a => {
                *va += 2;
                i16::from_le_bytes(self.bytes(at, 2)?.try_into().ok()?) as i64 as u64
            }
            0x0b => {
                *va += 4;
                self.u32(at)? as i32 as i64 as u64
            }
            0x0c => {
                *va += 8;
                self.u64(at)?
            }
            _ => return None,
        };
        let base = match enc & 0x70 {
            0x00 => 0,
            0x10 => at,
            0x30 => datarel,
            _ => return None,
        };
        Some(base.wrapping_add(raw))
    }
}

/// `[start, start + len)` of the function whose FDE covers `addr`, from the
/// ELF's `.eh_frame_hdr` table. `None` when the binary has no such table, the
/// encodings are unsupported, or no FDE covers `addr`.
pub fn elf_eh_frame_function(data: &[u8], addr: u64) -> Option<(u64, u64)> {
    let elf = goblin::elf::Elf::parse(data).ok()?;
    let mut hdr = None;
    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        if sh.sh_type == goblin::elf::section_header::SHT_NOBITS || sh.sh_addr == 0 {
            continue;
        }
        sections.push((sh.sh_addr, sh.sh_offset, sh.sh_size));
        if elf.shdr_strtab.get_at(sh.sh_name) == Some(".eh_frame_hdr") {
            hdr = Some(sh.sh_addr);
        }
    }
    let img = Image { data, sections };
    let hdr = hdr?;
    if img.u8(hdr)? != 1 {
        return None;
    }
    let (ptr_enc, cnt_enc, tab_enc) = (img.u8(hdr + 1)?, img.u8(hdr + 2)?, img.u8(hdr + 3)?);
    if cnt_enc == DW_EH_PE_OMIT || tab_enc != 0x3b {
        return None; // only the datarel|sdata4 sorted table every toolchain emits
    }
    let mut p = hdr + 4;
    img.encoded(&mut p, ptr_enc, hdr)?;
    let count = img.encoded(&mut p, cnt_enc, hdr)?;
    let table = p;
    let entry = |i: u64| -> Option<(u64, u64)> {
        let loc = hdr.wrapping_add(img.u32(table + 8 * i)? as i32 as i64 as u64);
        let fde = hdr.wrapping_add(img.u32(table + 8 * i + 4)? as i32 as i64 as u64);
        Some((loc, fde))
    };
    // last entry with initial location <= addr
    let (mut lo, mut hi) = (0u64, count);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if entry(mid)?.0 <= addr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    let (_, fde) = entry(lo - 1)?;
    let (start, len) = fde_range(&img, fde)?;
    (addr >= start && addr < start + len).then_some((start, len))
}

/// Parse one FDE: its CIE's `R` augmentation gives the pointer encoding.
fn fde_range(img: &Image, fde: u64) -> Option<(u64, u64)> {
    let len = img.u32(fde)?;
    if len == 0 || len == 0xffff_ffff {
        return None;
    }
    let cie_ptr = img.u32(fde + 4)?;
    let cie = (fde + 4).wrapping_sub(u64::from(cie_ptr));
    let enc = cie_fde_encoding(img, cie)?;
    let mut p = fde + 8;
    let start = img.encoded(&mut p, enc, 0)?;
    let range = img.encoded(&mut p, enc & 0x0f, 0)?;
    Some((start, range))
}

fn cie_fde_encoding(img: &Image, cie: u64) -> Option<u8> {
    if img.u32(cie)? == 0xffff_ffff || img.u32(cie + 4)? != 0 {
        return None;
    }
    let version = img.u8(cie + 8)?;
    let mut p = cie + 9;
    let mut aug = Vec::new();
    loop {
        let c = img.u8(p)?;
        p += 1;
        if c == 0 {
            break;
        }
        aug.push(c);
    }
    img.uleb(&mut p)?; // code alignment
    img.sleb(&mut p)?; // data alignment
    if version == 1 {
        p += 1;
    } else {
        img.uleb(&mut p)?;
    }
    if aug.first() != Some(&b'z') {
        return Some(0x00); // absptr
    }
    img.uleb(&mut p)?; // augmentation data length
    for &c in &aug[1..] {
        match c {
            b'R' => return img.u8(p),
            b'L' => p += 1,
            b'P' => {
                let penc = img.u8(p)?;
                p += 1;
                img.encoded(&mut p, penc, 0)?;
            }
            b'S' | b'B' | b'G' => {}
            _ => return None,
        }
    }
    Some(0x00)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test binary itself has unwind info: the FDE of this very test function covers its
    /// own address, starts at or before it, and is a plausible size.
    #[test]
    fn finds_the_fde_of_a_function_in_the_running_binary() {
        let exe = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe).unwrap();
        if goblin::elf::Elf::parse(&data).is_err() {
            return; // not an ELF host (Windows / macOS CI): nothing to check
        }
        // a link-time address: symbol table lookup of this module's helper
        let elf = goblin::elf::Elf::parse(&data).unwrap();
        let sym = elf
            .syms
            .iter()
            .find(|s| s.st_size > 0 && elf.strtab.get_at(s.st_name).is_some_and(|n| n.contains("cie_fde_encoding")));
        let Some(sym) = sym else { return };
        let mid = sym.st_value + sym.st_size / 2;
        let (start, len) = elf_eh_frame_function(&data, mid).expect("an FDE covers the helper");
        assert!(start <= mid && mid < start + len);
        assert_eq!(start, sym.st_value);
    }

    /// A large stripped binary named by `REARGO_TEST_BDS` (Bedrock server 1.26.33.2 linux):
    /// known FDEs read off its `.eh_frame_hdr` by hand. Skipped when unset.
    #[test]
    fn finds_known_fdes_in_bds() {
        let Ok(path) = std::env::var("REARGO_TEST_BDS") else { return };
        let data = std::fs::read(path).unwrap();
        // CanyonFeature's carve-ellipsoid (vtable slot 0) and the aquifer's computeFluid
        assert_eq!(elf_eh_frame_function(&data, 0x49efc50), Some((0x49ef770, 2172)));
        assert_eq!(elf_eh_frame_function(&data, 0x49ef770), Some((0x49ef770, 2172)));
        assert_eq!(elf_eh_frame_function(&data, 0x4bd0820), Some((0x4bd0820, 1376)));
    }

    /// A hand-built ELF64 with one CIE (`zR`, pcrel|sdata4) and two FDEs (0x1000+0x40,
    /// 0x1040+0x20) behind a sorted `.eh_frame_hdr` table.
    fn synthetic_elf() -> Vec<u8> {
        let mut b = vec![0u8; 0x500];
        let w16 = |b: &mut Vec<u8>, o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let w32 = |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let w64 = |b: &mut Vec<u8>, o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        // ELF header
        b[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        w16(&mut b, 16, 3); // ET_DYN
        w16(&mut b, 18, 0x3e); // x86-64
        w32(&mut b, 20, 1);
        w64(&mut b, 40, 0x400); // e_shoff
        w16(&mut b, 52, 64); // e_ehsize
        w16(&mut b, 54, 56); // e_phentsize
        w16(&mut b, 58, 64); // e_shentsize
        w16(&mut b, 60, 4); // e_shnum
        w16(&mut b, 62, 3); // e_shstrndx
        // .eh_frame @0x100: CIE (len 16)
        w32(&mut b, 0x100, 16);
        b[0x108..0x111].copy_from_slice(&[1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]);
        // FDE 1 @0x114 (len 16): CIE pointer, pc_begin (pcrel), pc_range, aug len 0
        let fde = |b: &mut Vec<u8>, at: u32, start: u32, len: u32| {
            w32(b, at as usize, 16);
            w32(b, at as usize + 4, at + 4 - 0x100);
            w32(b, at as usize + 8, start.wrapping_sub(at + 8));
            w32(b, at as usize + 12, len);
        };
        fde(&mut b, 0x114, 0x1000, 0x40);
        fde(&mut b, 0x128, 0x1040, 0x20);
        // .eh_frame_hdr @0x200
        b[0x200..0x204].copy_from_slice(&[1, 0x1b, 0x03, 0x3b]);
        w32(&mut b, 0x204, 0x100u32.wrapping_sub(0x204));
        w32(&mut b, 0x208, 2);
        for (i, (loc, f)) in [(0x1000u32, 0x114u32), (0x1040, 0x128)].into_iter().enumerate() {
            w32(&mut b, 0x20c + 8 * i, loc - 0x200);
            w32(&mut b, 0x210 + 8 * i, f - 0x200);
        }
        // .shstrtab @0x300
        let names = b"\0.eh_frame\0.eh_frame_hdr\0.shstrtab\0";
        b[0x300..0x300 + names.len()].copy_from_slice(names);
        // section headers @0x400: null, .eh_frame, .eh_frame_hdr, .shstrtab
        let sh = |b: &mut Vec<u8>, i: usize, name: u32, ty: u32, addr: u64, size: u64| {
            let o = 0x400 + 64 * i;
            if o + 64 > b.len() {
                b.resize(o + 64, 0);
            }
            w32(b, o, name);
            w32(b, o + 4, ty);
            w64(b, o + 16, addr);
            w64(b, o + 24, if ty == 3 { 0x300 } else { addr });
            w64(b, o + 32, size);
        };
        sh(&mut b, 1, 1, 1, 0x100, 0x3c);
        sh(&mut b, 2, 11, 1, 0x200, 0x1c);
        sh(&mut b, 3, 25, 3, 0, names.len() as u64);
        b
    }

    #[test]
    fn finds_fdes_in_a_synthetic_elf() {
        let elf = synthetic_elf();
        assert_eq!(elf_eh_frame_function(&elf, 0x1000), Some((0x1000, 0x40)));
        assert_eq!(elf_eh_frame_function(&elf, 0x103f), Some((0x1000, 0x40)));
        assert_eq!(elf_eh_frame_function(&elf, 0x1040), Some((0x1040, 0x20)));
        assert_eq!(elf_eh_frame_function(&elf, 0x105f), Some((0x1040, 0x20)));
        assert_eq!(elf_eh_frame_function(&elf, 0x1060), None, "past the last FDE");
        assert_eq!(elf_eh_frame_function(&elf, 0xfff), None, "before the first FDE");
    }

    #[test]
    fn non_elf_input_is_none() {
        assert_eq!(elf_eh_frame_function(b"MZ not an elf", 0x1000), None);
    }
}
