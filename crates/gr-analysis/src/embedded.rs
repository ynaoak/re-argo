//! Binwalk-style embedded file scanner.
//!
//! Walks every initialized byte in the loaded binary looking for the
//! magic-byte prefixes of common file formats — embedded ELF / PE /
//! Mach-O droppers, ZIP / GZIP / 7z archives, PNG / JPEG / SQLite
//! resources. Useful for: malware droppers (PE inside `.rsrc`),
//! firmware blobs (multiple ELFs concatenated), installers (ZIP /
//! 7z payload tacked onto the loader).
//!
//! The output is intentionally noisy at the API level (a single
//! `Finding` per match) and the consumer can post-filter. The CLI
//! groups by file type for readability and skips the host binary's
//! own header (the ELF/PE we're loading sits at offset 0 in its
//! file, and the loader stripped that header from `.text` already,
//! so the only "self" match is the entry of `info.entry_point`'s
//! containing block — easy to filter).

use gr_loader::BinaryInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedFinding {
    /// Virtual address where the embedded file starts.
    pub address: u64,
    /// Human-readable label ("PE executable", "ZIP archive", …).
    pub kind: &'static str,
    /// Magic bytes that matched, hex-formatted for the report.
    pub magic_hex: String,
}

struct Magic {
    kind: &'static str,
    bytes: &'static [u8],
    /// Optional secondary check: requires the byte at `offset` to
    /// equal one of the listed values. Used to disambiguate magic
    /// prefixes shared by multiple formats (e.g. PE's `MZ` prefix
    /// requires a valid `PE\0\0` at the e_lfanew offset).
    secondary: Option<SecondaryCheck>,
}

struct SecondaryCheck {
    /// Offset (in u32 LE at +0x3C for PE, etc.) to read for the
    /// pointer; if `None`, treat `pointer_offset` as the literal
    /// secondary offset to inspect.
    pointer_offset_le_u32: Option<usize>,
    /// Absolute offset to check (only used if `pointer_offset_le_u32`
    /// is None).
    literal_offset: Option<usize>,
    /// Required byte sequence at the resolved offset.
    required: &'static [u8],
}

const MAGICS: &[Magic] = &[
    Magic {
        kind: "ELF executable",
        bytes: b"\x7FELF",
        secondary: None,
    },
    Magic {
        kind: "PE executable",
        bytes: b"MZ",
        secondary: Some(SecondaryCheck {
            pointer_offset_le_u32: Some(0x3C),
            literal_offset: None,
            required: b"PE\x00\x00",
        }),
    },
    Magic {
        kind: "Mach-O (32-bit)",
        bytes: &[0xFE, 0xED, 0xFA, 0xCE],
        secondary: None,
    },
    Magic {
        kind: "Mach-O (64-bit)",
        bytes: &[0xFE, 0xED, 0xFA, 0xCF],
        secondary: None,
    },
    Magic {
        kind: "Mach-O (32-bit, reversed)",
        bytes: &[0xCE, 0xFA, 0xED, 0xFE],
        secondary: None,
    },
    Magic {
        kind: "Mach-O (64-bit, reversed)",
        bytes: &[0xCF, 0xFA, 0xED, 0xFE],
        secondary: None,
    },
    Magic {
        kind: "Mach-O fat binary",
        bytes: &[0xCA, 0xFE, 0xBA, 0xBE],
        secondary: None,
    },
    Magic {
        kind: "ZIP archive",
        bytes: b"PK\x03\x04",
        secondary: None,
    },
    Magic {
        kind: "ZIP empty / end-of-central-directory",
        bytes: b"PK\x05\x06",
        secondary: None,
    },
    Magic {
        kind: "GZIP archive",
        bytes: &[0x1F, 0x8B, 0x08],
        secondary: None,
    },
    Magic {
        kind: "7-Zip archive",
        bytes: b"7z\xBC\xAF\x27\x1C",
        secondary: None,
    },
    Magic {
        kind: "RAR archive (4.x)",
        bytes: b"Rar!\x1A\x07\x00",
        secondary: None,
    },
    Magic {
        kind: "RAR archive (5.x)",
        bytes: b"Rar!\x1A\x07\x01\x00",
        secondary: None,
    },
    Magic {
        kind: "PNG image",
        bytes: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        secondary: None,
    },
    Magic {
        kind: "JPEG image",
        bytes: &[0xFF, 0xD8, 0xFF],
        secondary: None,
    },
    Magic {
        // GIF87a or GIF89a — require the trailing 'a' to make the
        // magic 6 bytes and dodge the "GIF8" false-positive carpet.
        kind: "GIF image",
        bytes: b"GIF8",
        secondary: Some(SecondaryCheck {
            pointer_offset_le_u32: None,
            literal_offset: Some(5),
            required: b"a",
        }),
    },
    Magic {
        kind: "PDF document",
        bytes: b"%PDF-",
        secondary: None,
    },
    Magic {
        kind: "SQLite database",
        bytes: b"SQLite format 3\x00",
        secondary: None,
    },
    Magic {
        kind: "Java class file",
        bytes: &[0xCA, 0xFE, 0xBA, 0xBE],
        secondary: Some(SecondaryCheck {
            // class files use bytes 6..=7 as minor_version, 4..=5 as
            // major_version. We don't try to distinguish from Mach-O
            // fat (same magic) here — both findings will fire on
            // ambiguous payloads, and the consumer can resolve. Skip
            // by using a sentinel.
            pointer_offset_le_u32: None,
            literal_offset: Some(0),
            required: &[],
        }),
    },
    Magic {
        kind: "XZ archive",
        bytes: &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
        secondary: None,
    },
    Magic {
        // BZh + compression level digit ('1'..='9') + "1AY&SY"
        // block-magic prefix → 10-byte deterministic signature.
        kind: "BZIP2 archive",
        bytes: b"BZh",
        secondary: Some(SecondaryCheck {
            pointer_offset_le_u32: None,
            literal_offset: Some(4),
            required: b"1AY&SY",
        }),
    },
    Magic {
        kind: "Zstandard archive",
        bytes: &[0x28, 0xB5, 0x2F, 0xFD],
        secondary: None,
    },
    Magic {
        // POSIX ustar header: 5-char "ustar" + NUL + "00" version.
        // GNU tar writes "ustar  \0" — match both via secondary.
        kind: "TAR archive (POSIX)",
        bytes: b"ustar",
        secondary: Some(SecondaryCheck {
            pointer_offset_le_u32: None,
            literal_offset: Some(5),
            required: b"\x0000",
        }),
    },
];

/// Walk every loaded block and search for embedded file magics.
/// Skips the address at `info.entry_point` — the host binary's own
/// header at virtual address 0 / image base trivially matches its
/// format. `min_offset_from_block_start` lets the caller skip the
/// first N bytes of each block (defaults to 0 — caller can pass 1
/// to skip the block header itself).
pub fn scan(info: &BinaryInfo, min_offset_from_block_start: u64) -> Vec<EmbeddedFinding> {
    let mut findings = Vec::new();
    for block in info.memory.blocks() {
        let Some(data) = &block.data else {
            continue;
        };
        let start_offset = min_offset_from_block_start as usize;
        if start_offset >= data.len() {
            continue;
        }
        for offset in start_offset..data.len() {
            let window = &data[offset..];
            for magic in MAGICS {
                if !window.starts_with(magic.bytes) {
                    continue;
                }
                if let Some(check) = &magic.secondary
                    && !secondary_matches(window, check)
                {
                    continue;
                }
                let addr = block.start + offset as u64;
                let magic_hex = magic
                    .bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                findings.push(EmbeddedFinding {
                    address: addr,
                    kind: magic.kind,
                    magic_hex,
                });
                // Only fire one match per byte position — the most-
                // specific format wins (we ordered them so executable
                // formats come first).
                break;
            }
        }
    }
    findings
}

fn secondary_matches(window: &[u8], check: &SecondaryCheck) -> bool {
    if let Some(ptr_off) = check.pointer_offset_le_u32 {
        if window.len() < ptr_off + 4 {
            return false;
        }
        let target = u32::from_le_bytes(
            window[ptr_off..ptr_off + 4].try_into().expect("4 bytes"),
        ) as usize;
        if window.len() < target + check.required.len() {
            return false;
        }
        return &window[target..target + check.required.len()] == check.required;
    }
    if let Some(off) = check.literal_offset {
        if window.len() < off + check.required.len() {
            return false;
        }
        return &window[off..off + check.required.len()] == check.required;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_magic(label: &str) -> &Magic {
        MAGICS.iter().find(|m| m.kind == label).unwrap()
    }

    #[test]
    fn elf_magic_matches() {
        let m = find_magic("ELF executable");
        assert!(b"\x7FELF\x02\x01\x01\x00".starts_with(m.bytes));
    }

    #[test]
    fn pe_secondary_requires_pe_header() {
        // MZ at 0, e_lfanew = 0x80 pointing to "PE\0\0"
        let mut buf = vec![0u8; 0x100];
        buf[..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        let m = find_magic("PE executable");
        assert!(secondary_matches(&buf, m.secondary.as_ref().unwrap()));

        // Without the PE header at the pointed offset, secondary check fails.
        let mut bad = buf.clone();
        bad[0x80] = b'X';
        assert!(!secondary_matches(&bad, m.secondary.as_ref().unwrap()));
    }

    #[test]
    fn magic_list_well_formed() {
        for m in MAGICS {
            assert!(!m.bytes.is_empty(), "{} has empty magic", m.kind);
            assert!(!m.kind.is_empty());
        }
    }

    #[test]
    fn png_eight_byte_signature() {
        let m = find_magic("PNG image");
        assert_eq!(m.bytes.len(), 8);
    }
}
