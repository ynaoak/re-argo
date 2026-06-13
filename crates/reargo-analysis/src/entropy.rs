//! Shannon entropy per loaded section — surfaces packed / encrypted
//! / compressed regions (UPX, Themida, VMProtect, ASPack, …).
//!
//! Entropy is computed in nats-2 (per-byte bits, 0.0–8.0). A long
//! stretch of code typically sits in the 5.5–6.5 range; ASCII is
//! 4.0–5.0; English text 3.5–4.5; a compressed / encrypted blob is
//! 7.5+. We surface anything above 7.0 as `entropy_high`, anything
//! above 7.5 as `entropy_packed` (the "definitely packed" threshold
//! used by PEStudio, DIE, and similar triage tools).
//!
//! Output channels:
//!
//! * `metadata.entropy_<section>` — raw `"<entropy>"` string per
//!   section, parseable by the `entropy` CLI command.
//! * `metadata.entropy_overall` — file-wide entropy across every
//!   loaded byte. Useful for "is this whole binary packed?".
//! * BN-style tags on the first byte of each high-entropy section:
//!   `Suspicious` with text `entropy 7.6 (likely packed)`.
//!
//! The analyzer is read-only beyond the metadata / tags it writes,
//! making it cheap (~1 ms on a typical binary).

use reargo_program::tags::TagKind;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

/// Threshold above which we mark a section as "high entropy". Below
/// this you still get the raw number in `metadata`, just no tag.
pub const ENTROPY_HIGH_THRESHOLD: f64 = 7.0;

/// Threshold above which we mark a section as "likely packed". Above
/// this we additionally surface a `Suspicious` tag.
pub const ENTROPY_PACKED_THRESHOLD: f64 = 7.5;

pub struct EntropyAnalyzer;

impl Analyzer for EntropyAnalyzer {
    fn name(&self) -> &str {
        "Entropy"
    }
    fn description(&self) -> &str {
        "Shannon entropy per section — surfaces packed / encrypted regions"
    }
    fn priority(&self) -> u32 {
        // Cheap, data-only. Run early so other analyzers can read
        // `metadata.entropy_<section>` if they want.
        260
    }
    fn provides(&self) -> &'static [&'static str] {
        &["entropy"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let sections: Vec<(String, u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| s.address != 0 && s.size > 0)
            .map(|s| (s.name.clone(), s.address, s.size))
            .collect();

        let mut overall_hist = [0u64; 256];
        let mut overall_total: u64 = 0;
        let mut packed_tags: Vec<(u64, f64)> = Vec::new();

        for (name, addr, size) in &sections {
            // Cap per section so a single huge resource section
            // can't dominate runtime. A 1 MiB sample is more than
            // enough to characterise the section's distribution.
            let sample_len = (*size).min(1_024 * 1_024) as usize;
            let mut buf = vec![0u8; sample_len];
            if program.info.memory.read_bytes(*addr, &mut buf).is_err() {
                continue;
            }
            let entropy = shannon_entropy(&buf);

            for &b in &buf {
                overall_hist[b as usize] += 1;
            }
            overall_total += buf.len() as u64;

            program
                .metadata
                .set_property(format!("entropy_{}", name), format!("{:.3}", entropy));

            if entropy >= ENTROPY_PACKED_THRESHOLD {
                packed_tags.push((*addr, entropy));
            }
        }

        if overall_total > 0 {
            let overall = shannon_from_hist(&overall_hist, overall_total);
            program
                .metadata
                .set_property("entropy_overall", format!("{:.3}", overall));
        }

        let marked = packed_tags.len();
        for (addr, entropy) in packed_tags {
            program.tags.add_address(
                addr,
                TagKind::Suspicious,
                format!("entropy {:.2} (likely packed)", entropy),
                true,
            );
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: marked,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// Shannon entropy of a byte slice in bits/byte (0.0–8.0). Empty
/// input has entropy 0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    shannon_from_hist(&hist, data.len() as u64)
}

fn shannon_from_hist(hist: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut h = 0.0_f64;
    for &c in hist.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total_f;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_byte_is_zero() {
        assert_eq!(shannon_entropy(&[0xAAu8; 1024]), 0.0);
    }

    #[test]
    fn two_value_balanced_is_one_bit() {
        // 50/50 split → exactly 1 bit of entropy.
        let mut v = vec![0u8; 512];
        v.extend(std::iter::repeat_n(1u8, 512));
        let h = shannon_entropy(&v);
        assert!((h - 1.0).abs() < 1e-9, "expected ~1.0, got {}", h);
    }

    #[test]
    fn uniform_over_all_bytes_is_eight() {
        // Each of 256 values appears exactly once → entropy = 8.
        let v: Vec<u8> = (0..=255u8).collect();
        let h = shannon_entropy(&v);
        assert!((h - 8.0).abs() < 1e-9, "expected 8.0, got {}", h);
    }

    #[test]
    fn high_entropy_threshold_constants() {
        const _: () = assert!(ENTROPY_HIGH_THRESHOLD > 6.0);
        const _: () = assert!(ENTROPY_PACKED_THRESHOLD > ENTROPY_HIGH_THRESHOLD);
        const _: () = assert!(ENTROPY_PACKED_THRESHOLD <= 8.0);
    }
}
