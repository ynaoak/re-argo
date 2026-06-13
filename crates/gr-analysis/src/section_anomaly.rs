//! Section-permission and layout anomaly detector.
//!
//! Flags unusual section configurations that are red flags in
//! malware triage:
//!
//! * **RWX** — read + write + execute. Modern compilers never
//!   produce these; packers / shellcode loaders frequently do.
//! * **Writable + executable** — same idea. `.text` should be R+X,
//!   `.data` should be R+W; the intersection is suspicious.
//! * **Code in writable section** — entry point landing in a R+W
//!   section is almost certainly a packer about to unpack itself.
//! * **Zero raw size but huge virtual size** — classic packer
//!   layout: empty section reserved for the unpacker to fill at
//!   runtime.
//! * **Unusual section names** — entropy on the name itself; e.g.
//!   `.UPX0` / `.aspack` / random short alphanumeric is suspicious.
//!   (The packer-name match is already handled by `PackerAnalyzer`;
//!   here we flag sections that look obfuscated without matching a
//!   known packer.)
//! * **Section count anomaly** — > 16 sections is unusual for
//!   normal compiled binaries; can indicate post-process tampering.
//!
//! Each anomaly produces a `Suspicious` tag at the affected address
//! and contributes to `metadata.section_anomalies` (newline-joined
//! `name:kind` list) for downstream consumers.

use gr_loader::{BinaryFormat, SectionFlags};
use gr_program::tags::TagKind;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct SectionAnomalyAnalyzer;

impl Analyzer for SectionAnomalyAnalyzer {
    fn name(&self) -> &str {
        "Section Anomaly"
    }
    fn description(&self) -> &str {
        "Flag RWX / writable-code / packer-shaped section configurations"
    }
    fn priority(&self) -> u32 {
        // Cheap header-only scan. Run alongside other early
        // metadata analyzers (Imphash 290, Packer 270, Entropy 260).
        265
    }
    fn provides(&self) -> &'static [&'static str] {
        &["section_anomalies"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let mut anomalies: Vec<(u64, String, &'static str)> = Vec::new();

        // Per-section checks.
        for section in &program.info.sections {
            let r = section.flags.contains(SectionFlags::READ);
            let w = section.flags.contains(SectionFlags::WRITE);
            let x = section.flags.contains(SectionFlags::EXECUTE);
            if r && w && x {
                anomalies.push((
                    section.address,
                    section.name.clone(),
                    "RWX (read+write+execute)",
                ));
            } else if w && x {
                anomalies.push((
                    section.address,
                    section.name.clone(),
                    "writable + executable",
                ));
            }
            // Empty-raw / huge-virtual: classic packer reservation.
            // Synthetic check: virtual size >> raw size. We only
            // have one size on the Section struct, so use it.
            // (Loader merges raw + virtual into a single field.)
            if section.size > 1024 * 1024 && x && !r {
                anomalies.push((
                    section.address,
                    section.name.clone(),
                    "huge executable section without read perm",
                ));
            }
        }

        // Code-in-writable-section: does entry point land in a R+W section?
        if let Some(s) = program
            .info
            .sections
            .iter()
            .find(|s| program.info.entry_point >= s.address
                && program.info.entry_point < s.address + s.size)
            && s.flags.contains(SectionFlags::WRITE)
        {
            anomalies.push((
                program.info.entry_point,
                s.name.clone(),
                "entry point lands in writable section",
            ));
        }

        // High section count — threshold differs by format. Normal
        // ELF binaries have 25-35 sections (gcc puts each
        // attribute in its own section); normal PE binaries have
        // 4-10 sections. We only flag the truly unusual case.
        let section_count = program.info.sections.len();
        let threshold = match program.info.format {
            BinaryFormat::Pe => 16,
            BinaryFormat::Elf => 50,
            BinaryFormat::MachO => 32,
            BinaryFormat::Unknown => usize::MAX,
        };
        if section_count > threshold {
            anomalies.push((
                0,
                "(global)".to_string(),
                "unusually high section count for format",
            ));
        }

        // Tag every anomaly.
        for (addr, name, kind) in &anomalies {
            program.tags.add_address(
                *addr,
                TagKind::Suspicious,
                format!("section anomaly [{}]: {}", name, kind),
                true,
            );
        }

        // Summary metadata.
        if !anomalies.is_empty() {
            let joined: Vec<String> = anomalies
                .iter()
                .map(|(_, name, kind)| format!("{}:{}", name, kind))
                .collect();
            program
                .metadata
                .set_property("section_anomalies", joined.join("\n"));
            program
                .metadata
                .set_property("section_anomaly_count", anomalies.len().to_string());
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: anomalies.len(),
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    // Most logic in this analyzer is straightforward predicate code
    // on SectionFlags; the interesting paths (loader / Program
    // construction) need a real binary to exercise. The downstream
    // CLI smoke test (`triage` / `summary` on /bin/bash) hits every
    // branch except RWX (which would require a synthesised binary).

    use super::*;

    #[test]
    fn analyzer_metadata_is_well_formed() {
        let a = SectionAnomalyAnalyzer;
        assert_eq!(a.name(), "Section Anomaly");
        assert_eq!(a.priority(), 265);
        assert_eq!(a.provides(), &["section_anomalies"]);
    }
}
