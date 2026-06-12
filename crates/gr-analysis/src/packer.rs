//! DIE / PEiD-style packer + protector detection.
//!
//! Matches the entry-point byte signature and section-name layout
//! against a curated table of known packers / protectors. Result is
//! a single `metadata.packer` string ("UPX 3.x", "ASPack 2.x",
//! "Themida", …) plus a `Suspicious` tag on the entry point with the
//! identified name.
//!
//! Two signal sources, combined:
//!
//! * **Entry-point byte signature** — most packers paste a fixed
//!   prologue at the OEP-stub (the entry the loader jumps to). e.g.
//!   UPX's `60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ??` (PUSHAD; MOV ESI,
//!   imm32; LEA EDI, [ESI - imm32]) is unmistakable. We use `??`
//!   wildcards for the varying immediate bytes.
//! * **Section-name layout** — UPX writes `.UPX0` / `.UPX1` /
//!   `.UPX2`; ASPack writes `.aspack` / `.adata`; MEW writes `.MEW`;
//!   FSG writes `.FSG!`; etc. The names are baked into the packer's
//!   stub and survive most casual tampering.
//!
//! We trust the section-name signal more than the byte signature
//! since renamed sections are uncommon for the common UPX-class
//! packers. Confidence is reported alongside.

use gr_program::tags::TagKind;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct PackerAnalyzer;

impl Analyzer for PackerAnalyzer {
    fn name(&self) -> &str {
        "Packer Detection"
    }
    fn description(&self) -> &str {
        "DIE/PEiD-style packer signature match (UPX, ASPack, Themida, …)"
    }
    fn priority(&self) -> u32 {
        // Same neighbourhood as Entropy (260) and Crypto (250) —
        // cheap header / entry-point scan, run early so downstream
        // analyzers can read `metadata.packer`.
        270
    }
    fn provides(&self) -> &'static [&'static str] {
        &["packer"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut hits: Vec<(&'static str, &'static str)> = Vec::new();

        // 1. Section-name evidence.
        let section_names: Vec<String> = program
            .info
            .sections
            .iter()
            .map(|s| s.name.clone())
            .collect();
        for sig in SECTION_SIGNATURES {
            if sig
                .required
                .iter()
                .all(|needle| section_names.iter().any(|n| n.eq_ignore_ascii_case(needle)))
            {
                hits.push((sig.label, "section-name"));
            }
        }

        // 2. Entry-point byte signature (up to 64 bytes).
        let entry = program.info.entry_point;
        let mut entry_bytes = vec![0u8; 64];
        let entry_ok = program.info.memory.read_bytes(entry, &mut entry_bytes).is_ok();
        if entry_ok {
            for sig in BYTE_SIGNATURES {
                if matches_signature(&entry_bytes, sig.bytes) {
                    hits.push((sig.label, "entry-point"));
                }
            }
        }

        // De-duplicate while preserving order.
        hits.dedup_by(|a, b| a.0 == b.0);

        if hits.is_empty() {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let primary = hits[0];
        program.metadata.set_property("packer", primary.0);
        program
            .metadata
            .set_property("packer_evidence", primary.1);

        program.tags.add_address(
            entry,
            TagKind::Suspicious,
            format!("packer: {} ({})", primary.0, primary.1),
            true,
        );

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: hits.len(),
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// `bytes`: the candidate window from the entry point. `sig`: a
/// pattern where `Some(b)` is an exact byte and `None` is a `??`
/// wildcard. Matches iff `bytes` is at least `sig.len()` long and
/// every `Some` position equals.
fn matches_signature(bytes: &[u8], sig: &[Option<u8>]) -> bool {
    if bytes.len() < sig.len() {
        return false;
    }
    for (i, slot) in sig.iter().enumerate() {
        if let Some(expected) = slot
            && bytes[i] != *expected
        {
            return false;
        }
    }
    true
}

struct ByteSignature {
    label: &'static str,
    bytes: &'static [Option<u8>],
}

struct SectionSignature {
    label: &'static str,
    /// Every name in this list must appear in the binary's section
    /// table (case-insensitive). One-element lists work as "any of"
    /// would; multi-element is "all of".
    required: &'static [&'static str],
}

const W: Option<u8> = None;
const fn b(x: u8) -> Option<u8> {
    Some(x)
}

/// Entry-point prologue signatures, one per packer family. Byte
/// values verified against publicly published OEP stubs.
static BYTE_SIGNATURES: &[ByteSignature] = &[
    // UPX 3.x / 4.x: PUSHAD ; MOV ESI, imm32 ; LEA EDI, [ESI - imm32]
    ByteSignature {
        label: "UPX",
        bytes: &[b(0x60), b(0xBE), W, W, W, W, b(0x8D), b(0xBE), W, W, W, W],
    },
    // FSG 2.0: BB ?? ?? ?? ?? BF ?? ?? ?? ?? BE ?? ?? ?? ??
    ByteSignature {
        label: "FSG",
        bytes: &[b(0xBB), W, W, W, W, b(0xBF), W, W, W, W, b(0xBE), W, W, W, W],
    },
    // MEW 1.x: E9 ?? ?? ?? FF (long jmp into stub)
    ByteSignature {
        label: "MEW",
        bytes: &[b(0xE9), W, W, W, b(0xFF)],
    },
    // ASPack 2.x: 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3
    ByteSignature {
        label: "ASPack",
        bytes: &[
            b(0x60), b(0xE8), b(0x03), b(0x00), b(0x00), b(0x00), b(0xE9), b(0xEB),
            b(0x04), b(0x5D), b(0x45), b(0x55), b(0xC3),
        ],
    },
    // Petite 2.x: B8 ?? ?? ?? ?? 66 9C 60 50
    ByteSignature {
        label: "Petite",
        bytes: &[b(0xB8), W, W, W, W, b(0x66), b(0x9C), b(0x60), b(0x50)],
    },
    // PECompact 2.x: B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00
    ByteSignature {
        label: "PECompact",
        bytes: &[
            b(0xB8), W, W, W, W, b(0x50), b(0x64), b(0xFF), b(0x35), b(0x00), b(0x00),
            b(0x00), b(0x00),
        ],
    },
    // Yoda's Crypter 1.x: 55 8B EC 53 56 57 60 E8 (and longer)
    ByteSignature {
        label: "Yoda's Crypter",
        bytes: &[
            b(0x55), b(0x8B), b(0xEC), b(0x53), b(0x56), b(0x57), b(0x60), b(0xE8),
        ],
    },
    // .NET Confuser: signature-based detection only — leave header
    // entries for section-name pass.
];

/// Section-name signatures. Many packers leave their section table
/// fingerprint intact since renaming would break the loader's
/// relocations.
static SECTION_SIGNATURES: &[SectionSignature] = &[
    SectionSignature {
        label: "UPX",
        required: &[".UPX0", ".UPX1"],
    },
    SectionSignature {
        label: "ASPack",
        required: &[".aspack"],
    },
    SectionSignature {
        label: "ASProtect",
        required: &[".aspr"],
    },
    SectionSignature {
        label: "MEW",
        required: &[".MEW"],
    },
    SectionSignature {
        label: "FSG",
        required: &[".FSG!"],
    },
    SectionSignature {
        label: "PECompact",
        required: &["PEC2"],
    },
    SectionSignature {
        label: "PEtite",
        required: &[".petite"],
    },
    SectionSignature {
        label: "Themida",
        required: &[".themida"],
    },
    SectionSignature {
        label: "VMProtect",
        required: &[".vmp0"],
    },
    SectionSignature {
        label: "Enigma Protector",
        required: &[".enigma1"],
    },
    SectionSignature {
        label: "NSPack",
        required: &["nsp0", "nsp1"],
    },
    SectionSignature {
        label: "Mpress",
        required: &[".MPRESS1"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upx_byte_signature_matches() {
        let mut buf = [0u8; 64];
        // 60 BE 00 10 40 00 8D BE 00 F0 FF FF
        buf[..12].copy_from_slice(&[
            0x60, 0xBE, 0x00, 0x10, 0x40, 0x00, 0x8D, 0xBE, 0x00, 0xF0, 0xFF, 0xFF,
        ]);
        assert!(matches_signature(
            &buf,
            BYTE_SIGNATURES.iter().find(|s| s.label == "UPX").unwrap().bytes
        ));
    }

    #[test]
    fn aspack_byte_signature_matches() {
        let mut buf = [0u8; 64];
        buf[..13].copy_from_slice(&[
            0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3,
        ]);
        assert!(matches_signature(
            &buf,
            BYTE_SIGNATURES
                .iter()
                .find(|s| s.label == "ASPack")
                .unwrap()
                .bytes
        ));
    }

    #[test]
    fn unrelated_bytes_dont_match() {
        let buf = [0x90u8; 64]; // nop sled
        for sig in BYTE_SIGNATURES {
            assert!(!matches_signature(&buf, sig.bytes), "{} matched nops", sig.label);
        }
    }

    #[test]
    fn empty_buf_doesnt_match() {
        assert!(!matches_signature(&[], BYTE_SIGNATURES[0].bytes));
    }

    #[test]
    fn wildcards_allow_any_byte() {
        // The UPX signature's wildcards must accept any byte.
        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];
        buf1[..12].copy_from_slice(&[0x60, 0xBE, 0x11, 0x22, 0x33, 0x44, 0x8D, 0xBE, 0xAA, 0xBB, 0xCC, 0xDD]);
        buf2[..12].copy_from_slice(&[0x60, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x8D, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE]);
        let upx = BYTE_SIGNATURES.iter().find(|s| s.label == "UPX").unwrap().bytes;
        assert!(matches_signature(&buf1, upx));
        assert!(matches_signature(&buf2, upx));
    }
}
