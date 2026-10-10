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
}

impl Reader for Image<'_> {
    fn read_into(&self, va: u64, buf: &mut [u8]) -> Option<()> {
        let o = self.offset_of(va)?;
        buf.copy_from_slice(self.data.get(o..o + buf.len())?);
        Some(())
    }
}

impl Reader for crate::memory::Memory {
    fn read_into(&self, va: u64, buf: &mut [u8]) -> Option<()> {
        self.read_bytes(va, buf).ok()
    }
}

/// Byte access by virtual address: the file's sections ([`Image`]) or a loaded [`Memory`].
trait Reader {
    fn read_into(&self, va: u64, buf: &mut [u8]) -> Option<()>;

    fn u8(&self, va: u64) -> Option<u8> {
        let mut b = [0u8; 1];
        self.read_into(va, &mut b)?;
        Some(b[0])
    }
    fn u16(&self, va: u64) -> Option<u16> {
        let mut b = [0u8; 2];
        self.read_into(va, &mut b)?;
        Some(u16::from_le_bytes(b))
    }
    fn u32(&self, va: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        self.read_into(va, &mut b)?;
        Some(u32::from_le_bytes(b))
    }
    fn u64(&self, va: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        self.read_into(va, &mut b)?;
        Some(u64::from_le_bytes(b))
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
    /// `DW_EH_PE_datarel` (the `.eh_frame_hdr` start). `DW_EH_PE_indirect` is not followed
    /// (the caller does: in a PIE the slot is a relocation).
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
                u64::from(self.u16(at)?)
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
                self.u16(at)? as i16 as i64 as u64
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
    let fde = find_fde(&img, hdr?, addr)?;
    let (start, len) = fde_range(&img, fde)?;
    (addr >= start && addr < start + len).then_some((start, len))
}

/// The FDE whose initial location is the last one at or before `addr`, from the sorted
/// table of the `.eh_frame_hdr` at `hdr`.
fn find_fde(img: &impl Reader, hdr: u64, addr: u64) -> Option<u64> {
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
    Some(entry(lo - 1)?.1)
}

/// Parse one FDE: its CIE's `R` augmentation gives the pointer encoding.
fn fde_range(img: &impl Reader, fde: u64) -> Option<(u64, u64)> {
    let len = img.u32(fde)?;
    if len == 0 || len == 0xffff_ffff {
        return None;
    }
    let cie_ptr = img.u32(fde + 4)?;
    let cie = (fde + 4).wrapping_sub(u64::from(cie_ptr));
    let enc = cie_info(img, cie)?.fde_enc;
    let mut p = fde + 8;
    let start = img.encoded(&mut p, enc, 0)?;
    let range = img.encoded(&mut p, enc & 0x0f, 0)?;
    Some((start, range))
}

/// What an FDE needs from its CIE.
struct CieInfo {
    /// `R`: the encoding of the FDE's address range
    fde_enc: u8,
    /// `L`: the encoding of the FDE's LSDA pointer
    lsda_enc: Option<u8>,
    /// `z`: the FDE has augmentation data (its length first)
    has_aug_data: bool,
}

fn cie_info(img: &impl Reader, cie: u64) -> Option<CieInfo> {
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
    let mut info = CieInfo { fde_enc: 0x00, lsda_enc: None, has_aug_data: false };
    if aug.first() != Some(&b'z') {
        return Some(info); // absptr
    }
    info.has_aug_data = true;
    img.uleb(&mut p)?; // augmentation data length
    for &c in &aug[1..] {
        match c {
            b'R' => {
                info.fde_enc = img.u8(p)?;
                p += 1;
            }
            b'L' => {
                info.lsda_enc = Some(img.u8(p)?);
                p += 1;
            }
            b'P' => {
                let penc = img.u8(p)?;
                p += 1;
                img.encoded(&mut p, penc & 0x7f, 0)?;
            }
            b'S' | b'B' | b'G' => {}
            _ => return None,
        }
    }
    Some(info)
}

/// What a call site's landing pad does with an exception (an LSDA action record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhAction {
    /// runs destructors and resumes unwinding
    Cleanup,
    /// `catch (T)`: the typeinfo of `T` (0: `catch (...)`); when `indirect`, `typeinfo` is
    /// the address of a pointer to it (a relocation in a PIE)
    Catch { typeinfo: u64, indirect: bool },
    /// an exception specification (`noexcept` / `throw(...)`)
    Filter,
}

/// A call-site record of a function's LSDA: the calls in `[start, start + len)` unwind to
/// `landing_pad` (0: none, the exception propagates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    pub start: u64,
    pub len: u64,
    pub landing_pad: u64,
    pub actions: Vec<EhAction>,
}

/// The call-site table of the LSDA (`.gcc_except_table`) of the function whose FDE covers
/// `addr`, read from loaded memory; `hdr` is the address of `.eh_frame_hdr`. `None` when
/// the function has no LSDA or its encodings are unsupported.
pub fn landing_pads(mem: &crate::memory::Memory, hdr: u64, addr: u64) -> Option<Vec<CallSite>> {
    let img = mem;
    let fde = find_fde(img, hdr, addr)?;
    let (start, len) = fde_range(img, fde)?;
    if addr < start || addr >= start + len {
        return None;
    }
    let cie = (fde + 4).wrapping_sub(u64::from(img.u32(fde + 4)?));
    let info = cie_info(img, cie)?;
    let lsda_enc = info.lsda_enc.filter(|&e| e != DW_EH_PE_OMIT)?;
    if !info.has_aug_data {
        return None;
    }
    let mut p = fde + 8;
    img.encoded(&mut p, info.fde_enc, 0)?;
    img.encoded(&mut p, info.fde_enc & 0x0f, 0)?;
    img.uleb(&mut p)?; // augmentation data length
    let lsda = img.encoded(&mut p, lsda_enc & 0x7f, 0)?;
    if lsda == 0 {
        return None;
    }
    parse_lsda(img, lsda, start)
}

/// The call-site table of the LSDA at `lsda` (GCC / LLVM `.gcc_except_table` format).
fn parse_lsda(img: &impl Reader, lsda: u64, func_start: u64) -> Option<Vec<CallSite>> {
    let mut p = lsda;
    let lp_enc = img.u8(p)?;
    p += 1;
    let lp_start = if lp_enc == DW_EH_PE_OMIT { func_start } else { img.encoded(&mut p, lp_enc, 0)? };
    let tt_enc = img.u8(p)?;
    p += 1;
    let tt_base = if tt_enc == DW_EH_PE_OMIT {
        None
    } else {
        let off = img.uleb(&mut p)?;
        Some(p + off)
    };
    let cs_enc = img.u8(p)?;
    p += 1;
    let cs_len = img.uleb(&mut p)?;
    let cs_end = p + cs_len;
    let action_table = cs_end;
    let tt_size = match tt_enc & 0x0f {
        0x02 | 0x0a => 2,
        0x03 | 0x0b => 4,
        _ => 8,
    };
    let mut out = Vec::new();
    while p < cs_end && out.len() < 100_000 {
        // offsets from the landing-pad base: the encoding's size, no base applied
        let start = img.encoded(&mut p, cs_enc & 0x0f, 0)?;
        let len = img.encoded(&mut p, cs_enc & 0x0f, 0)?;
        let lp = img.encoded(&mut p, cs_enc & 0x0f, 0)?;
        let action = img.uleb(&mut p)?;
        let mut actions = Vec::new();
        if action != 0 {
            let mut a = action_table + action - 1;
            for _ in 0..32 {
                let filter = img.sleb(&mut a)?;
                let here = a;
                let next = img.sleb(&mut a)?;
                actions.push(match filter {
                    0 => EhAction::Cleanup,
                    f if f > 0 => {
                        let mut slot = tt_base?.wrapping_sub(f as u64 * tt_size);
                        let typeinfo = img.encoded(&mut slot, tt_enc & 0x7f, 0)?;
                        EhAction::Catch { typeinfo, indirect: tt_enc & 0x80 != 0 }
                    }
                    _ => EhAction::Filter,
                });
                if next == 0 {
                    break;
                }
                a = here.wrapping_add(next as u64);
            }
        } else if lp != 0 {
            actions.push(EhAction::Cleanup);
        }
        out.push(CallSite {
            start: lp_start + start,
            len,
            landing_pad: if lp == 0 { 0 } else { lp_start + lp },
            actions,
        });
    }
    Some(out)
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
            w32(&mut b, 0x20c + 8 * i, loc.wrapping_sub(0x200));
            w32(&mut b, 0x210 + 8 * i, f.wrapping_sub(0x200));
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

    /// Bytes at a base address, for parsing hand-built tables.
    struct At(u64, Vec<u8>);

    impl Reader for At {
        fn read_into(&self, va: u64, buf: &mut [u8]) -> Option<()> {
            let o = va.checked_sub(self.0)? as usize;
            buf.copy_from_slice(self.1.get(o..o + buf.len())?);
            Some(())
        }
    }

    /// An LSDA with a cleanup, a `catch` (indirect pcrel typeinfo) and a call site with no
    /// landing pad.
    #[test]
    fn parses_an_lsda_call_site_table() {
        let mut b = vec![0xff, 0x9b, 20, 0x01, 12];
        b.extend([0x10, 0x08, 0x40, 0x00, 0x20, 0x05, 0x50, 0x01, 0x30, 0x05, 0x00, 0x00]);
        b.extend([0x01, 0x00]); // action 1: catch type filter 1, no next
        b.extend((0x6000u32.wrapping_sub(0x5000 + 19)).to_le_bytes()); // ttype[1]
        let sites = parse_lsda(&At(0x5000, b), 0x5000, 0x1000).unwrap();
        assert_eq!(sites.len(), 3);
        assert_eq!((sites[0].start, sites[0].len, sites[0].landing_pad), (0x1010, 8, 0x1040));
        assert_eq!(sites[0].actions, vec![EhAction::Cleanup]);
        assert_eq!(sites[1].landing_pad, 0x1050);
        assert_eq!(sites[1].actions, vec![EhAction::Catch { typeinfo: 0x6000, indirect: true }]);
        assert_eq!((sites[2].landing_pad, sites[2].actions.len()), (0, 0));
    }

    /// A known LSDA of the binary named by `REARGO_TEST_BDS`. Skipped when unset.
    #[test]
    fn reads_landing_pads_in_bds() {
        let Ok(path) = std::env::var("REARGO_TEST_BDS") else { return };
        let info = crate::BinaryLoader::load(std::path::Path::new(&path)).unwrap();
        let hdr = info.sections.iter().find(|s| s.name == ".eh_frame_hdr").unwrap().address;
        // a function whose calls unwind to cleanups (its CIE is `zPLR`)
        let sites = landing_pads(&info.memory, hdr, 0x41cc080).unwrap();
        assert!(sites.iter().any(|s| s.landing_pad != 0 && s.actions == [EhAction::Cleanup]), "{sites:?}");
        for s in &sites {
            assert!(s.start >= 0x41cc080 && s.start + s.len <= 0x41cc080 + 0x17e, "{s:?}");
            assert!(s.landing_pad == 0 || (s.landing_pad > 0x41cc080 && s.landing_pad < 0x41cc080 + 0x17e), "{s:?}");
        }
        // a CIE without `L`: no LSDA
        assert_eq!(landing_pads(&info.memory, hdr, 0x4bd0820), None);
    }
}
