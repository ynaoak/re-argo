//! PE Authenticode signature reader.
//!
//! PE binaries can carry a code-signing blob in the "Certificate
//! Table" data directory (entry 4). The blob is one or more
//! `WIN_CERTIFICATE` records, each followed by a PKCS#7 SignedData
//! payload that contains the X.509 chain.
//!
//! We do a *minimal* parse — enough for the malware-triage user to
//! answer "is this signed, by whom, with what kind of certificate?":
//!
//! * Certificate-table presence + total size.
//! * Number of `WIN_CERTIFICATE` records and their revision /
//!   certificate-type fields.
//! * Heuristic CN= extraction by walking the PKCS#7 blob looking
//!   for the X.509 `commonName` OID (`2.5.4.3` → DER `55 04 03`)
//!   followed by the printable-string tag and contents. Same for
//!   `organizationName` (`2.5.4.10`) and `countryName` (`2.5.4.6`).
//!
//! The heuristic CN extraction is good enough for the "show me the
//! signer" use case without implementing a full ASN.1 / PKCS#7
//! parser. We surface every CN= / O= / C= we find so a single PKCS#7
//! with multiple cert chains lists the leaf + intermediates +
//! root.
//!
//! Results land in `metadata.signed` (true/false), `metadata.cert_count`,
//! `metadata.cert_subjects` (newline-joined CN=... list), and as
//! `Important` tag at the entry point so `tags` picks it up.

use reargo_loader::BinaryFormat;
use reargo_program::tags::TagKind;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct AuthenticodeAnalyzer;

impl Analyzer for AuthenticodeAnalyzer {
    fn name(&self) -> &str {
        "Authenticode"
    }
    fn description(&self) -> &str {
        "PE Authenticode code-signing detection + heuristic signer extraction"
    }
    fn priority(&self) -> u32 {
        // Cheap header-only scan. Same neighbourhood as the other
        // metadata-only analyzers (Imphash 290, Packer 270).
        285
    }
    fn provides(&self) -> &'static [&'static str] {
        &["authenticode"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if program.info.format != BinaryFormat::Pe {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        // Re-read the file. The loader doesn't surface raw bytes,
        // but `info` carries the same buffer in the form of memory
        // blocks — not the original file offset. The cert table
        // entry uses a *file offset* (not RVA), so we have to read
        // the original file again. Re-loading is cheap (cache hot).
        let path_opt = program
            .info
            .sections
            .first()
            .map(|_| program.name.clone());
        let Some(_) = path_opt else {
            return Ok(default_result(self.name()));
        };

        // The pragmatic path: re-parse the PE from `info.memory`
        // we already loaded. But the cert table's offset is a file
        // offset that's outside the section table — it isn't in
        // our memory blocks. Re-read the file from disk.
        let path = std::path::Path::new(&program.name);
        let bytes = match read_file_best_effort(path) {
            Some(b) => b,
            None => return Ok(default_result(self.name())),
        };

        let pe = match goblin::pe::PE::parse(&bytes) {
            Ok(pe) => pe,
            Err(_) => return Ok(default_result(self.name())),
        };
        let opt_header = match pe.header.optional_header {
            Some(h) => h,
            None => return Ok(default_result(self.name())),
        };
        let cert_dir = match opt_header.data_directories.get_certificate_table() {
            Some(d) => d,
            None => {
                program.metadata.set_property("signed", "false");
                return Ok(default_result(self.name()));
            }
        };

        if cert_dir.size == 0 {
            program.metadata.set_property("signed", "false");
            return Ok(default_result(self.name()));
        }

        let offset = cert_dir.virtual_address as usize;
        let size = cert_dir.size as usize;
        if offset + size > bytes.len() {
            program.metadata.set_property("signed", "true");
            program
                .metadata
                .set_property("authenticode_warning", "truncated cert table");
            return Ok(default_result(self.name()));
        }
        let cert_blob = &bytes[offset..offset + size];

        let records = parse_win_certificates(cert_blob);
        let subjects = extract_subjects(cert_blob);

        program.metadata.set_property("signed", "true");
        program
            .metadata
            .set_property("cert_count", records.len().to_string());
        program
            .metadata
            .set_property("cert_table_size", size.to_string());
        if !subjects.is_empty() {
            program
                .metadata
                .set_property("cert_subjects", subjects.join("\n"));
            program.tags.add_address(
                program.info.entry_point,
                TagKind::Important,
                format!("authenticode signed by: {}", subjects.join(" / ")),
                true,
            );
        } else {
            program.tags.add_address(
                program.info.entry_point,
                TagKind::Important,
                "authenticode signed (subject not extracted)".to_string(),
                true,
            );
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: subjects.len(),
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

fn read_file_best_effort(path: &std::path::Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinCertificate {
    pub length: u32,
    pub revision: u16,
    pub cert_type: u16,
}

/// Walk the certificate-table blob and return one entry per
/// `WIN_CERTIFICATE` record. Each record is 8-byte aligned.
pub fn parse_win_certificates(blob: &[u8]) -> Vec<WinCertificate> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 8 <= blob.len() {
        let length = u32::from_le_bytes(blob[pos..pos + 4].try_into().expect("4 bytes"));
        let revision = u16::from_le_bytes(blob[pos + 4..pos + 6].try_into().expect("2 bytes"));
        let cert_type = u16::from_le_bytes(blob[pos + 6..pos + 8].try_into().expect("2 bytes"));
        if length < 8 {
            break;
        }
        out.push(WinCertificate {
            length,
            revision,
            cert_type,
        });
        // Records are 8-byte aligned.
        let advance = (length as usize).max(8);
        let aligned = (advance + 7) & !7;
        pos = pos.saturating_add(aligned);
        if pos == 0 || pos > blob.len() {
            break;
        }
    }
    out
}

/// Scan the certificate blob for X.509 commonName / organizationName
/// / countryName attributes and return their string values in
/// `CN=…, O=…, C=…` form. Heuristic: we recognise the OID DER bytes
/// for each attribute, then read the following PrintableString /
/// UTF8String tag.
pub fn extract_subjects(blob: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 0;
    while i + 4 < blob.len() {
        // OID 2.5.4.3 → DER bytes: 06 03 55 04 03 (LEN=3, value=55 04 03)
        // OID 2.5.4.10 → 06 03 55 04 0A
        // OID 2.5.4.6  → 06 03 55 04 06
        if blob[i] == 0x06 && blob[i + 1] == 0x03 && blob[i + 2] == 0x55 && blob[i + 3] == 0x04 {
            let kind = match blob[i + 4] {
                0x03 => "CN",
                0x0A => "O",
                0x06 => "C",
                _ => {
                    i += 1;
                    continue;
                }
            };
            // After the OID, we expect a tag byte (0x13 PrintableString,
            // 0x0C UTF8String, 0x16 IA5String, 0x14 TeletexString).
            // ASN.1 allows the SET / SEQUENCE wrappers in between —
            // we scan forward up to 8 bytes for the string tag.
            let mut scan = i + 5;
            let mut found = false;
            while scan + 2 < blob.len() && scan < i + 16 {
                let tag = blob[scan];
                if matches!(tag, 0x13 | 0x0C | 0x16 | 0x14 | 0x1E) {
                    let len = blob[scan + 1] as usize;
                    if len > 0 && len < 256 && scan + 2 + len <= blob.len() {
                        let value = &blob[scan + 2..scan + 2 + len];
                        if let Ok(s) = std::str::from_utf8(value) {
                            let entry = format!("{}={}", kind, s.trim());
                            if seen.insert(entry.clone()) {
                                out.push(entry);
                            }
                            found = true;
                        }
                    }
                    break;
                }
                scan += 1;
            }
            i += if found { 6 } else { 1 };
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_blob() {
        let v: Vec<WinCertificate> = parse_win_certificates(&[]);
        assert!(v.is_empty());
    }

    #[test]
    fn parse_one_record() {
        // length=16 (record + padding), rev=0x0200, type=0x0002
        let mut blob = vec![
            0x10, 0x00, 0x00, 0x00,
            0x00, 0x02,
            0x02, 0x00,
        ];
        // Body bytes (8 bytes payload)
        blob.extend_from_slice(&[0; 8]);
        let v = parse_win_certificates(&blob);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].length, 16);
        assert_eq!(v[0].revision, 0x0200);
        assert_eq!(v[0].cert_type, 0x0002);
    }

    #[test]
    fn extract_cn_from_minimal_x509_chunk() {
        // Construct: OID 2.5.4.3 (CN) followed by PrintableString
        // tag 0x13, length 12, "Example Corp"
        let mut blob = vec![0x06, 0x03, 0x55, 0x04, 0x03];
        blob.push(0x13);
        blob.push(0x0C);
        blob.extend_from_slice(b"Example Corp");
        let subjects = extract_subjects(&blob);
        assert!(subjects.contains(&"CN=Example Corp".to_string()), "got {:?}", subjects);
    }

    #[test]
    fn extract_o_with_set_wrapper() {
        // 06 03 55 04 0A 31 09 13 07 SetSize..."BadCorp" → simulate one byte
        // skipping (a SET wrapper between OID and string).
        let mut blob = vec![0x06, 0x03, 0x55, 0x04, 0x0A];
        blob.extend_from_slice(&[0x31, 0x09]); // SET wrapper (skipped by our 16-byte scan)
        blob.push(0x13); // PrintableString tag
        blob.push(0x07);
        blob.extend_from_slice(b"BadCorp");
        let subjects = extract_subjects(&blob);
        assert!(subjects.contains(&"O=BadCorp".to_string()), "got {:?}", subjects);
    }

    #[test]
    fn extract_dedupes() {
        // Two CN= entries with same value should appear once.
        let one = {
            let mut b = vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04];
            b.extend_from_slice(b"Acme");
            b
        };
        let mut combined = one.clone();
        combined.extend_from_slice(&one);
        let subjects = extract_subjects(&combined);
        assert_eq!(subjects.iter().filter(|s| s.as_str() == "CN=Acme").count(), 1);
    }
}
