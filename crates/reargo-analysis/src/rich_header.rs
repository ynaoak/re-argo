//! PE Rich Header parser.
//!
//! The "Rich Header" is an undocumented Microsoft linker artefact
//! embedded between the DOS stub and the PE header in nearly every
//! Microsoft-toolchain-compiled binary. It records the `@comp.id`
//! values of every compiler / linker / assembler invocation that
//! contributed to the binary, along with their use counts.
//!
//! For malware analysis, the Rich Header is gold:
//!
//! * **Toolchain fingerprint** — exact Visual Studio version + build
//!   tools (`VS2019 16.x`, MASM `14.28.29910`, etc.) that the author
//!   used. Often distinguishes legit code from copy-pasted compiled
//!   modules.
//! * **RichHash / RichPV** — MD5 of the un-XOR'd Rich Header data
//!   used by VirusTotal and Hybrid Analysis to cluster samples that
//!   share a build environment, surviving recompilation that
//!   changes everything else.
//! * **Anomalies** — Rich Header tampering (mismatched checksum,
//!   unusual @comp.id values, missing for an MSVC binary) is itself
//!   a strong malware signal.
//!
//! ## Format
//!
//! The Rich Header sits at file offsets `[start..end]` where
//! * `end` is the offset of the literal `"Rich"` ASCII signature,
//!   followed by a 4-byte XOR key.
//! * `start` is the offset of the literal `"DanS"` ASCII signature
//!   *XOR'd against the key*. Walk backwards from "Rich" through
//!   the file looking for `DanS ^ key`.
//!
//! The body between `start + 16` and `end` is a sequence of 8-byte
//! records, each `(comp_id, count)`, all XOR'd against the key.
//!
//! ## Implementation
//!
//! We re-read the original file bytes (the loader doesn't surface
//! pre-PE header content). Walk the DOS stub backwards from the
//! `e_lfanew` pointer's resolved PE start, find the `Rich` marker,
//! recover the XOR key, walk back to `DanS`, then decode each
//! 8-byte record. The MD5 of the un-XOR'd body (excluding the `Rich`
//! marker and key) is the canonical RichHash, written to
//! `metadata.richhash`.

use reargo_loader::BinaryFormat;
use reargo_program::Program;
use md5::{Digest, Md5};

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct RichHeaderAnalyzer;

impl Analyzer for RichHeaderAnalyzer {
    fn name(&self) -> &str {
        "Rich Header"
    }
    fn description(&self) -> &str {
        "Parse the PE Rich Header (MSVC toolchain fingerprint + RichHash clustering)"
    }
    fn priority(&self) -> u32 {
        // Cheap header scan. Same neighbourhood as imphash (290).
        288
    }
    fn provides(&self) -> &'static [&'static str] {
        &["richhash"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if program.info.format != BinaryFormat::Pe {
            return Ok(default_result(self.name()));
        }
        let path = std::path::Path::new(&program.name);
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(default_result(self.name()));
        };
        let Some(rh) = parse_rich_header(&bytes) else {
            return Ok(default_result(self.name()));
        };

        program
            .metadata
            .set_property("richhash", rh.richhash.clone());
        program
            .metadata
            .set_property("rich_records", rh.records.len().to_string());

        // Per-record summary as `\n`-joined `comp_id:count` for the
        // `info` / `triage` reports to render.
        let summary: Vec<String> = rh
            .records
            .iter()
            .map(|r| format!("0x{:08x}:{}", r.comp_id, r.count))
            .collect();
        if !summary.is_empty() {
            program
                .metadata
                .set_property("rich_summary", summary.join("\n"));
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: rh.records.len(),
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

fn default_result(name: &str) -> AnalysisResult {
    AnalysisResult {
        analyzer_name: name.into(),
        functions_found: 0,
        references_found: 0,
        instructions_decoded: 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichHeader {
    pub xor_key: u32,
    pub records: Vec<RichRecord>,
    /// MD5 of the un-XOR'd body (between `DanS` and `Rich`,
    /// excluding the markers and the trailing key).
    pub richhash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RichRecord {
    pub comp_id: u32,
    pub count: u32,
}

/// Parse the Rich Header from raw PE file bytes. Returns `None` for
/// non-PE inputs or PE files without a Rich Header (most non-MSVC
/// binaries lack it).
pub fn parse_rich_header(data: &[u8]) -> Option<RichHeader> {
    // Locate `e_lfanew` at file offset 0x3C → PE header offset.
    if data.len() < 0x40 {
        return None;
    }
    let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if pe_off > data.len() || pe_off < 0x80 {
        return None;
    }
    // Scan the DOS stub region [0x80..pe_off] for the literal
    // "Rich" marker.
    let needle = b"Rich";
    let mut rich_off: Option<usize> = None;
    let mut i = 0x80;
    while i + 8 <= pe_off {
        if &data[i..i + 4] == needle {
            rich_off = Some(i);
            break;
        }
        i += 1;
    }
    let rich_off = rich_off?;
    if rich_off + 8 > data.len() {
        return None;
    }
    let xor_key = u32::from_le_bytes(data[rich_off + 4..rich_off + 8].try_into().ok()?);

    // Walk back from rich_off looking for `DanS ^ xor_key`. The
    // `DanS` marker is the start of the un-XOR'd header.
    let dans = u32::from_le_bytes(*b"DanS") ^ xor_key;
    let dans_bytes = dans.to_le_bytes();
    let mut dans_off: Option<usize> = None;
    let mut j = rich_off;
    while j >= 4 {
        j -= 4;
        if data[j..j + 4] == dans_bytes {
            dans_off = Some(j);
            break;
        }
    }
    let dans_off = dans_off?;

    // Body is between dans_off+16 (skip DanS + 3 padding dwords)
    // and rich_off. Each record is 8 bytes: (comp_id, count) both
    // XOR'd against xor_key.
    let body_start = dans_off + 16;
    if body_start >= rich_off {
        return None;
    }
    let body = &data[body_start..rich_off];
    let mut records = Vec::with_capacity(body.len() / 8);
    let mut k = 0;
    while k + 8 <= body.len() {
        let comp_id = u32::from_le_bytes(body[k..k + 4].try_into().ok()?) ^ xor_key;
        let count = u32::from_le_bytes(body[k + 4..k + 8].try_into().ok()?) ^ xor_key;
        records.push(RichRecord { comp_id, count });
        k += 8;
    }

    // RichHash: MD5 of the un-XOR'd body bytes (canonical format
    // used by VirusTotal / RichPV).
    let mut decoded = Vec::with_capacity(body.len());
    for chunk in body.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let v = u32::from_le_bytes(chunk.try_into().ok()?) ^ xor_key;
        decoded.extend_from_slice(&v.to_le_bytes());
    }
    let digest = Md5::digest(&decoded);
    let richhash = hex_string(&digest);

    Some(RichHeader {
        xor_key,
        records,
        richhash,
    })
}

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0xF));
    }
    s
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE-shaped buffer with a synthetic Rich Header
    /// for round-tripping our parser. The DOS header section is
    /// faked just enough for the parser's `e_lfanew` walk to land
    /// at the correct offset.
    fn build_minimal_pe_with_rich(records: &[(u32, u32)], xor_key: u32) -> Vec<u8> {
        // Plan:
        //   [0..0x3C] DOS header (MZ + padding)
        //   [0x3C..0x40] e_lfanew = 0x200
        //   [0x40..0x80] DOS stub padding
        //   [0x80..0x90] DanS + 3 padding dwords (all XOR'd with key)
        //   [0x90..0x90 + records.len()*8] records
        //   [end..end+8] "Rich" + key
        //   [..0x200] padding
        //   [0x200..0x204] "PE\0\0"
        let mut data = vec![0u8; 0x300];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x200u32.to_le_bytes());
        // DanS section
        let dans = u32::from_le_bytes(*b"DanS") ^ xor_key;
        data[0x80..0x84].copy_from_slice(&dans.to_le_bytes());
        // Three padding dwords (XOR'd zero = key).
        data[0x84..0x88].copy_from_slice(&xor_key.to_le_bytes());
        data[0x88..0x8C].copy_from_slice(&xor_key.to_le_bytes());
        data[0x8C..0x90].copy_from_slice(&xor_key.to_le_bytes());
        let mut off = 0x90;
        for (comp_id, count) in records {
            let cid = comp_id ^ xor_key;
            let cnt = count ^ xor_key;
            data[off..off + 4].copy_from_slice(&cid.to_le_bytes());
            data[off + 4..off + 8].copy_from_slice(&cnt.to_le_bytes());
            off += 8;
        }
        // Rich marker + key
        data[off..off + 4].copy_from_slice(b"Rich");
        data[off + 4..off + 8].copy_from_slice(&xor_key.to_le_bytes());
        // PE marker at e_lfanew
        data[0x200..0x204].copy_from_slice(b"PE\x00\x00");
        data
    }

    #[test]
    fn parse_two_records() {
        let key = 0xDEADBEEFu32;
        let recs = [(0x010C7809u32, 5u32), (0x00FF1234u32, 3u32)];
        let data = build_minimal_pe_with_rich(&recs, key);
        let parsed = parse_rich_header(&data).expect("parsable");
        assert_eq!(parsed.xor_key, key);
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].comp_id, recs[0].0);
        assert_eq!(parsed.records[0].count, recs[0].1);
        assert_eq!(parsed.records[1].comp_id, recs[1].0);
        assert_eq!(parsed.records[1].count, recs[1].1);
        assert_eq!(parsed.richhash.len(), 32);
    }

    #[test]
    fn parse_no_rich_returns_none() {
        let mut data = vec![0u8; 0x300];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x200u32.to_le_bytes());
        data[0x200..0x204].copy_from_slice(b"PE\x00\x00");
        assert!(parse_rich_header(&data).is_none());
    }

    #[test]
    fn rich_hash_deterministic() {
        let key = 0x12345678u32;
        let recs = [(0x010C7809u32, 5u32), (0x00FF1234u32, 3u32)];
        let a = parse_rich_header(&build_minimal_pe_with_rich(&recs, key)).unwrap();
        let b = parse_rich_header(&build_minimal_pe_with_rich(&recs, key)).unwrap();
        assert_eq!(a.richhash, b.richhash);
    }

    #[test]
    fn rich_hash_changes_with_records() {
        let key = 0x12345678u32;
        let a = parse_rich_header(&build_minimal_pe_with_rich(
            &[(0x010C7809u32, 5u32)],
            key,
        ))
        .unwrap();
        let b = parse_rich_header(&build_minimal_pe_with_rich(
            &[(0x010C7809u32, 6u32)],
            key,
        ))
        .unwrap();
        // Different count → different hash.
        assert_ne!(a.richhash, b.richhash);
    }

    #[test]
    fn rich_hash_independent_of_xor_key() {
        // The whole point of the RichHash is that it's independent
        // of the XOR key — two binaries with the same records
        // should hash identically.
        let recs = [(0x010C7809u32, 5u32)];
        let a = parse_rich_header(&build_minimal_pe_with_rich(&recs, 0xDEADBEEF)).unwrap();
        let b = parse_rich_header(&build_minimal_pe_with_rich(&recs, 0xCAFEBABE)).unwrap();
        assert_eq!(a.richhash, b.richhash);
    }
}
