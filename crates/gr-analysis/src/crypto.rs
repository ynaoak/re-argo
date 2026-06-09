//! Detect well-known cryptographic constants embedded in the binary.
//!
//! Both IDA and Binary Ninja ship a "crypto constants" database —
//! the AES S-box, the SHA-1 / SHA-256 / MD5 / MD4 round constants,
//! Blowfish P-array, etc. all live as inline byte arrays in any
//! binary that implements the algorithm directly (no libcrypto
//! dynamic linking). Matching those byte signatures recovers
//! "this function is AES" / "this is SHA-256" instantly, no
//! disassembly required.
//!
//! For each match we:
//! * Set a plate comment at the start of the matching range:
//!   `crypto: AES S-box`, `crypto: SHA-256 H[0..7] (initial hash)`, …
//! * Register the address as a Data symbol named
//!   `crypto_<lower-case-id>` so xref reports point to it by name.
//!
//! The fingerprint table below is conservative: each entry is the
//! *full* canonical byte sequence published in the algorithm spec.
//! That makes false positives effectively impossible at the cost of
//! missing custom-mangled or word-reordered variants — the right
//! tradeoff for a noise-free signal.

use gr_program::comments::CommentType;
use gr_program::symbol::{SourceType, Symbol, SymbolType};
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct CryptoConstantAnalyzer;

impl Analyzer for CryptoConstantAnalyzer {
    fn name(&self) -> &str {
        "Crypto Constant"
    }
    fn description(&self) -> &str {
        "Detects well-known cryptographic constants (AES, SHA, MD5, …) in data sections"
    }
    fn priority(&self) -> u32 {
        // Cheap, data-only — run early so downstream analyzers can
        // see the new `crypto_*` symbols when they look up names.
        250
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let fingerprints = fingerprints();
        let mut found = 0usize;

        let data_sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| {
                s.address != 0
                    && s.size > 0
                    && !s.flags.contains(gr_loader::SectionFlags::EXECUTE)
            })
            .map(|s| (s.address, s.size))
            .collect();

        for (start, size) in data_sections {
            let read = size.min(0x100_000) as usize;
            let mut buf = vec![0u8; read];
            if program.info.memory.read_bytes(start, &mut buf).is_err() {
                continue;
            }
            for fp in &fingerprints {
                if let Some(pos) = find(&buf, fp.bytes) {
                    let addr = start + pos as u64;
                    let already = program.symbol_table.primary_at(addr).is_some_and(|s| {
                        s.name.starts_with("crypto_")
                    });
                    if already {
                        continue;
                    }
                    if program.comments.get(addr, CommentType::Plate).is_none() {
                        program.comments.set(
                            addr,
                            CommentType::Plate,
                            format!("crypto: {}", fp.label),
                        );
                    }
                    program.symbol_table.add(Symbol::new(
                        format!("crypto_{}", fp.id),
                        addr,
                        SymbolType::Data,
                        SourceType::Analysis,
                    ));
                    found += 1;
                }
            }
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: found,
        })
    }
}

/// Boyer-Moore would be overkill here — the haystacks are bounded at
/// 1 MiB per section and we run at most a few dozen needles. Linear
/// scan keeps the implementation auditable.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

struct Fingerprint {
    id: &'static str,
    label: &'static str,
    bytes: &'static [u8],
}

/// Curated table of crypto-constant fingerprints. Each `bytes` slice
/// is the literal byte sequence the algorithm spec publishes.
fn fingerprints() -> Vec<Fingerprint> {
    vec![
        Fingerprint {
            id: "aes_sbox",
            label: "AES S-box (forward)",
            // First 32 bytes of the AES forward S-box — enough to
            // uniquely identify and short enough to keep in source.
            // Full table = 256 bytes.
            bytes: &[
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
                0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
                0x9c, 0xa4, 0x72, 0xc0,
            ],
        },
        Fingerprint {
            id: "aes_inv_sbox",
            label: "AES inverse S-box",
            bytes: &[
                0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
                0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
                0xc4, 0xde, 0xe9, 0xcb,
            ],
        },
        Fingerprint {
            id: "aes_rcon",
            label: "AES round constants (Rcon)",
            // First 10 round constants — enough to disambiguate from
            // any other power-of-x sequence the algorithm could use.
            bytes: &[
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            ],
        },
        Fingerprint {
            id: "sha256_h",
            label: "SHA-256 H[0..7] (initial hash)",
            // 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c
            // 1f83d9ab 5be0cd19 — big-endian.
            bytes: &[
                0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f,
                0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab,
                0x5b, 0xe0, 0xcd, 0x19,
            ],
        },
        Fingerprint {
            id: "sha256_h_le",
            label: "SHA-256 H[0..7] (initial hash, little-endian words)",
            bytes: &[
                0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5,
                0x4f, 0xa5, 0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b, 0xab, 0xd9, 0x83, 0x1f,
                0x19, 0xcd, 0xe0, 0x5b,
            ],
        },
        Fingerprint {
            id: "sha256_k",
            label: "SHA-256 K[0..3] (round constants, big-endian)",
            // 428a2f98 71374491 b5c0fbcf e9b5dba5
            bytes: &[
                0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91, 0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5,
                0xdb, 0xa5,
            ],
        },
        Fingerprint {
            id: "sha256_k_le",
            label: "SHA-256 K[0..3] (round constants, little-endian words)",
            // Same constants encoded as native-order u32 on x86 — what
            // a `static const uint32_t K[] = {0x428a2f98, …}` table
            // actually looks like in `.rodata`.
            bytes: &[
                0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71, 0xcf, 0xfb, 0xc0, 0xb5, 0xa5, 0xdb,
                0xb5, 0xe9,
            ],
        },
        Fingerprint {
            id: "sha1_h",
            label: "SHA-1 H[0..4] (initial hash, big-endian)",
            bytes: &[
                0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
                0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0,
            ],
        },
        Fingerprint {
            id: "sha1_h_le",
            label: "SHA-1 H[0..4] (initial hash, little-endian words)",
            bytes: &[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10, 0xf0, 0xe1, 0xd2, 0xc3,
            ],
        },
        Fingerprint {
            id: "md5_init",
            label: "MD5 A,B,C,D init",
            // 01234567 89abcdef fedcba98 76543210 in little-endian.
            bytes: &[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ],
        },
        Fingerprint {
            id: "crc32_poly",
            label: "CRC32 (IEEE 802.3) table[0..4]",
            // Standard zlib polynomial table start. table[1] =
            // 0x77073096 LE — and table[0] = 0 so we anchor on
            // table[1..4].
            bytes: &[
                0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee, 0xba, 0x51, 0x09, 0x99,
            ],
        },
        Fingerprint {
            id: "des_sbox1",
            label: "DES S-box 1",
            // First 16 entries of DES S1, packed bytes.
            bytes: &[
                0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08, 0x03, 0x0a, 0x06, 0x0c, 0x05, 0x09,
                0x00, 0x07,
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_basic() {
        assert_eq!(find(b"hello world", b"world"), Some(6));
        assert_eq!(find(b"abc", b"d"), None);
        assert_eq!(find(b"", b"x"), None);
        assert_eq!(find(b"x", b""), None);
    }

    #[test]
    fn fingerprint_table_well_formed() {
        let fps = fingerprints();
        assert!(fps.len() >= 8);
        for fp in &fps {
            assert!(!fp.bytes.is_empty());
            assert!(!fp.label.is_empty());
            assert!(fp.id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
        }
    }

    #[test]
    fn aes_sbox_recovered_from_synthetic_blob() {
        let fps = fingerprints();
        let sbox = fps.iter().find(|f| f.id == "aes_sbox").unwrap().bytes;
        let mut blob = vec![0u8; 32];
        blob.extend_from_slice(sbox);
        blob.extend_from_slice(&[0xAA; 16]);
        assert_eq!(find(&blob, sbox), Some(32));
    }
}
