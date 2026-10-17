//! Minimal ZIP reader for JAR archives: central directory (with ZIP64),
//! stored and deflated entries. Encrypted entries are not supported.

use std::io::Read;
use std::path::Path;

use crate::{JvmError, Reader, Result};

const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    local_header_offset: u64,
}

impl ZipEntry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

pub struct Jar {
    data: Vec<u8>,
    entries: Vec<ZipEntry>,
}

/// ZIP stores integers little-endian; the shared `Reader` is big-endian.
fn le16(b: &[u8], at: usize) -> Result<u16> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(JvmError::Truncated(at))
}

fn le32(b: &[u8], at: usize) -> Result<u32> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(JvmError::Truncated(at))
}

fn le64(b: &[u8], at: usize) -> Result<u64> {
    Ok(le32(b, at)? as u64 | (le32(b, at + 4)? as u64) << 32)
}

impl Jar {
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_bytes(std::fs::read(path)?)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let entries = read_central_directory(&data)?;
        Ok(Self { data, entries })
    }

    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Decompressed contents of `entry`.
    pub fn read(&self, entry: &ZipEntry) -> Result<Vec<u8>> {
        if entry.flags & 1 != 0 {
            return Err(JvmError::Zip(format!("{}: encrypted entries are not supported", entry.name)));
        }
        let at = usize::try_from(entry.local_header_offset).map_err(|_| JvmError::Zip("offset overflow".into()))?;
        if le32(&self.data, at)? != LOCAL_SIG {
            return Err(JvmError::Zip(format!("{}: bad local header", entry.name)));
        }
        let start = at + 30 + le16(&self.data, at + 26)? as usize + le16(&self.data, at + 28)? as usize;
        let len = usize::try_from(entry.compressed_size).map_err(|_| JvmError::Zip("size overflow".into()))?;
        let raw = self.data.get(start..start.saturating_add(len)).ok_or(JvmError::Truncated(start))?;
        match entry.method {
            0 => Ok(raw.to_vec()),
            8 => {
                let mut out = Vec::with_capacity(entry.uncompressed_size.min(1 << 28) as usize);
                flate2::read::DeflateDecoder::new(raw).read_to_end(&mut out)?;
                Ok(out)
            }
            m => Err(JvmError::Zip(format!("{}: unsupported compression method {m}", entry.name))),
        }
    }
}

fn read_central_directory(data: &[u8]) -> Result<Vec<ZipEntry>> {
    // EOCD is 22 bytes plus a comment of up to 65535 bytes.
    let min = data.len().saturating_sub(22 + 0xFFFF);
    let eocd = (min..=data.len().saturating_sub(22))
        .rev()
        .find(|&i| le32(data, i).ok() == Some(EOCD_SIG))
        .ok_or_else(|| JvmError::Zip("end of central directory not found".into()))?;
    let mut total = le16(data, eocd + 10)? as u64;
    let mut cd_offset = le32(data, eocd + 16)? as u64;
    if (total == 0xFFFF || cd_offset == 0xFFFF_FFFF) && eocd >= 20 && le32(data, eocd - 20)? == ZIP64_LOCATOR_SIG {
        let z64 = le64(data, eocd - 20 + 8)? as usize;
        if le32(data, z64)? != ZIP64_EOCD_SIG {
            return Err(JvmError::Zip("bad ZIP64 end of central directory".into()));
        }
        total = le64(data, z64 + 32)?;
        cd_offset = le64(data, z64 + 48)?;
    }
    let mut entries = Vec::with_capacity(total.min(1 << 20) as usize);
    let mut at = cd_offset as usize;
    for _ in 0..total {
        if le32(data, at)? != CENTRAL_SIG {
            return Err(JvmError::Zip(format!("bad central directory entry at offset {at}")));
        }
        let flags = le16(data, at + 8)?;
        let method = le16(data, at + 10)?;
        let mut compressed_size = le32(data, at + 20)? as u64;
        let mut uncompressed_size = le32(data, at + 24)? as u64;
        let name_len = le16(data, at + 28)? as usize;
        let extra_len = le16(data, at + 30)? as usize;
        let comment_len = le16(data, at + 32)? as usize;
        let mut local_header_offset = le32(data, at + 42)? as u64;
        let name_bytes = data.get(at + 46..at + 46 + name_len).ok_or(JvmError::Truncated(at + 46))?;
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let extra = data.get(at + 46 + name_len..at + 46 + name_len + extra_len).ok_or(JvmError::Truncated(at))?;
        apply_zip64_extra(extra, &mut uncompressed_size, &mut compressed_size, &mut local_header_offset)?;
        entries.push(ZipEntry { name, method, flags, compressed_size, uncompressed_size, local_header_offset });
        at += 46 + name_len + extra_len + comment_len;
    }
    Ok(entries)
}

/// ZIP64 extended-information extra field (id 0x0001): 64-bit values
/// replace the 32-bit fields that are saturated, in this order.
fn apply_zip64_extra(extra: &[u8], usize_: &mut u64, csize: &mut u64, offset: &mut u64) -> Result<()> {
    let mut r = Reader::new(extra);
    while r.pos() + 4 <= extra.len() {
        let hdr = r.bytes(4)?;
        let id = u16::from_le_bytes([hdr[0], hdr[1]]);
        let len = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
        let body = r.bytes(len)?;
        if id != 1 {
            continue;
        }
        let mut k = 0;
        for field in [usize_, csize, offset] {
            if *field == 0xFFFF_FFFF {
                *field = le64(body, k)?;
                k += 8;
            }
        }
        break;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::io::Write;

    /// Build an in-memory ZIP with the given `(name, data, deflate)` entries.
    pub fn build_zip(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, deflate) in files {
            let payload = if *deflate {
                let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(data).unwrap();
                enc.finish().unwrap()
            } else {
                data.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 8]); // time, date, crc (unchecked)
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&payload);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 8]);
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]); // extra, comment, disk, int attr, ext attr
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stored_and_deflated_entries() {
        let big = b"hello hello hello hello hello hello".repeat(10);
        let zip = testutil::build_zip(&[("META-INF/", b"", false), ("a.txt", b"plain", false), ("b/c.bin", &big, true)]);
        let jar = Jar::from_bytes(zip).unwrap();
        assert_eq!(jar.entries().len(), 3);
        assert!(jar.entries()[0].is_dir());
        assert_eq!(jar.read(jar.find("a.txt").unwrap()).unwrap(), b"plain");
        assert_eq!(jar.read(jar.find("b/c.bin").unwrap()).unwrap(), big);
    }

    #[test]
    fn rejects_non_zip() {
        assert!(matches!(Jar::from_bytes(vec![0; 100]), Err(JvmError::Zip(_))));
    }
}
