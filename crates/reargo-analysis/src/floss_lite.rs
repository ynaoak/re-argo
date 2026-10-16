//! FLOSS-lite: static obfuscated-string decoder.
//!
//! Malware frequently embeds C2 URLs / commands / API names XOR'd
//! against a one-byte key, or ROL'd by a small amount, to hide them
//! from a plain `strings` pass. FLOSS (FLARE Obfuscated String
//! Solver) recovers them via dataflow tracing + emulation; we take
//! the cheap shortcut that catches the most-common cases:
//!
//! 1. **Single-byte XOR brute force** — for each `key` in `1..=255`,
//!    XOR every byte in a data section with `key` and report any
//!    resulting run of printable ASCII characters ≥ N bytes long.
//! 2. **Single-byte ADD brute force** — same idea with `byte =
//!    byte.wrapping_add(key)`. Catches `byte + N` style stubs.
//! 3. **ROL brute force** — for each rotation `r in 1..=7`,
//!    `byte.rotate_left(r)` then check for printable runs.
//!
//! Output: one `DecodedString` per non-overlapping match, carrying
//! the byte offset, the decode method (XOR / ADD / ROL + key), and
//! the recovered string. The CLI command `floss <bin>` renders these
//! grouped by section; the analyzer also surfaces top hits as
//! Custom `obfuscated-string` tags so `tags --filter
//! obfuscated-string` produces the same listing.
//!
//! ## Heuristic filters (to prune noise)
//!
//! * Min length: configurable, default 6.
//! * At least 50% of bytes must be ASCII letters / digits (rejects
//!   pure-whitespace / pure-punctuation runs).
//! * Reject pure-repeated character runs (`AAAAAA`, `      `).
//! * Skip strings that already appear in `strings` output (i.e. the
//!   original bytes without decode). Those are visible without us.

use rayon::prelude::*;
use reargo_loader::SectionFlags;
use reargo_program::tags::TagKind;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub const DEFAULT_MIN_LENGTH: usize = 8;
pub const MAX_KEYS_PER_BYTE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedString {
    /// Virtual address of the first byte in the encoded blob.
    pub address: u64,
    /// Decoding method that recovered the string.
    pub method: DecodeMethod,
    /// The recovered (plaintext) string.
    pub plaintext: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMethod {
    Xor(u8),
    Add(u8),
    Rol(u8),
}

impl DecodeMethod {
    pub fn label(self) -> String {
        match self {
            Self::Xor(k) => format!("XOR(0x{:02X})", k),
            Self::Add(k) => format!("ADD(0x{:02X})", k),
            Self::Rol(r) => format!("ROL({})", r),
        }
    }
}

pub struct FlossLiteAnalyzer;

impl Analyzer for FlossLiteAnalyzer {
    fn name(&self) -> &str {
        "FLOSS-lite"
    }
    fn description(&self) -> &str {
        "Brute-force XOR / ADD / ROL decoded-string recovery on data sections"
    }
    fn priority(&self) -> u32 {
        // Run alongside StringSearchAnalyzer (200). Cheap brute-
        // force, ~ a few hundred ms on a 1 MiB rdata.
        210
    }
    fn provides(&self) -> &'static [&'static str] {
        &["decoded_strings"]
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        // Conservative defaults + min_length 12 (stricter than the
        // CLI default) so the pipeline doesn't pollute tag space
        // with brute-force noise. Users who want lower thresholds
        // invoke `floss` directly.
        let opts = FlossOptions {
            min_length: 12,
            ..FlossOptions::default()
        };
        let mut total = 0usize;
        let mut sample: Option<DecodedString> = None;

        let sections: Vec<(u64, u64)> = program
            .info
            .sections
            .iter()
            .filter(|s| {
                s.size > 0
                    && s.size <= 16 * 1024 * 1024
                    && !s.flags.contains(SectionFlags::EXECUTE)
            })
            .map(|s| (s.address, s.size))
            .collect();

        for (addr, size) in sections {
            let mut buf = vec![0u8; size as usize];
            if program.info.memory.read_bytes(addr, &mut buf).is_err() {
                continue;
            }
            let found = decode_section(&buf, addr, &opts);
            if sample.is_none()
                && let Some(d) = found.first()
            {
                sample = Some(d.clone());
            }
            total += found.len();
        }

        // Only emit a single `obfuscated-string` tag at the entry
        // point summarising the count. Per-string tags would flood
        // the tags report with low-confidence brute-force matches.
        if total > 0 {
            program.tags.add_address(
                program.info.entry_point,
                TagKind::Custom("obfuscated-string".to_string()),
                format!(
                    "FLOSS-lite recovered {} candidate string(s); use `floss <bin>` for details",
                    total
                ),
                true,
            );
            let _ = sample;
        }
        program
            .metadata
            .set_property("decoded_string_count", total.to_string());

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: total,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlossOptions {
    pub min_length: usize,
    /// Try XOR with every key in `1..=255` if `true`.
    pub try_xor: bool,
    /// Try `byte + k` ADD with every key in `1..=255` if `true`.
    pub try_add: bool,
    /// Try `rotate_left(r)` for `r in 1..=7` if `true`.
    pub try_rol: bool,
    /// Cap on the total number of decoded strings (per section).
    pub max_per_section: usize,
    /// Conservative mode: only emit a hit when the original bytes
    /// at the offset are *mostly non-printable* (≥ 50% non-printable
    /// in the matched window). This is the heuristic that
    /// separates real obfuscated strings (the only reason to encode
    /// them is to hide from `strings`) from the noise of
    /// brute-force XOR over already-printable text. Turn off via
    /// `--include-printable-source` when chasing edge cases.
    pub require_nonprintable_source: bool,
    /// Address dedup — for each offset, keep only the longest
    /// decoded plaintext. The default (`true`) keeps the CLI report
    /// readable; tests sometimes want every candidate.
    pub dedup_per_address: bool,
}

impl Default for FlossOptions {
    fn default() -> Self {
        Self {
            min_length: DEFAULT_MIN_LENGTH,
            try_xor: true,
            try_add: false, // ADD is rarer; default off to control noise.
            try_rol: true,
            max_per_section: 2048,
            require_nonprintable_source: true,
            dedup_per_address: true,
        }
    }
}

/// Find decoded strings in a single byte buffer. Public so callers
/// can use the engine outside of the analyzer pipeline (CLI `floss`
/// command).
pub fn decode_section(buf: &[u8], base_addr: u64, opts: &FlossOptions) -> Vec<DecodedString> {
    // Every (method, key) pass is independent: run them in parallel
    // batches, then append their hits in the fixed XOR → ADD → ROL,
    // ascending-key order with the same per-pass cap check as a serial
    // run (which stops at the first pass that overflows the cap; a
    // batch past that point is not started).
    let mut methods: Vec<DecodeMethod> = Vec::new();
    if opts.try_xor {
        methods.extend((1u8..=255).map(DecodeMethod::Xor));
    }
    if opts.try_add {
        methods.extend((1u8..=255).map(DecodeMethod::Add));
    }
    if opts.try_rol {
        methods.extend((1u8..=7).map(DecodeMethod::Rol));
    }
    let batch = rayon::current_num_threads().max(1) * 2;
    let mut hits: Vec<DecodedString> = Vec::new();
    for group in methods.chunks(batch) {
        let per_method: Vec<Vec<DecodedString>> = group
            .par_iter()
            .map(|&method| {
                let mut out = Vec::new();
                match method {
                    DecodeMethod::Xor(key) => scan_with(buf, base_addr, opts, &mut out, |b| b ^ key, method),
                    DecodeMethod::Add(key) => {
                        scan_with(buf, base_addr, opts, &mut out, |b| b.wrapping_add(key), method)
                    }
                    DecodeMethod::Rol(r) => {
                        scan_with(buf, base_addr, opts, &mut out, |b| b.rotate_left(r as u32), method)
                    }
                }
                out
            })
            .collect();
        for found in per_method {
            hits.extend(found);
            if hits.len() > opts.max_per_section {
                hits.truncate(opts.max_per_section);
                return hits;
            }
        }
    }

    // Dedupe in two passes:
    //   1) Drop duplicates by plaintext (same string decoded with
    //      multiple methods at different offsets — keep first).
    //   2) Per address, keep at most ONE hit (the longest plaintext).
    //      Otherwise a single encoded blob produces dozens of
    //      similar-looking variants when brute-forced with every
    //      key (the "@oNO@oNO" / "AnON" / "FXY" noise).
    hits.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.plaintext.cmp(&b.plaintext)));
    hits.dedup_by(|a, b| a.plaintext == b.plaintext);
    if !opts.dedup_per_address {
        return hits;
    }
    let mut by_addr: std::collections::BTreeMap<u64, DecodedString> = std::collections::BTreeMap::new();
    for d in hits {
        by_addr
            .entry(d.address)
            .and_modify(|existing| {
                if d.plaintext.len() > existing.plaintext.len() {
                    *existing = d.clone();
                }
            })
            .or_insert(d);
    }
    by_addr.into_values().collect()
}

fn scan_with(
    buf: &[u8],
    base_addr: u64,
    opts: &FlossOptions,
    out: &mut Vec<DecodedString>,
    decode: impl Fn(u8) -> u8,
    method: DecodeMethod,
) {
    // Decoded-byte printability per source byte value.
    let printable: [bool; 256] = std::array::from_fn(|b| is_printable(decode(b as u8)));
    let n = buf.len();
    // A zero minimum would count an empty run as a hit and never
    // advance; clamp to 1 (identical behaviour for every m >= 1).
    let m = opts.min_length.max(1);
    // Every maximal printable run of at least `m` bytes is examined,
    // in address order (a shorter run is skipped whole). `i` is always
    // the start of a maximal run (0 or just past a non-printable byte),
    // so a run of `m` from `i` needs `buf[i..i + m]` all printable:
    // test its last byte first and, when it is printable, look back
    // for the last non-printable one — the next run cannot start
    // before it. Most windows fail on the first byte tested.
    let mut i = 0;
    while i + m <= n {
        if m > 0 {
            if !printable[buf[i + m - 1] as usize] {
                i += m;
                continue;
            }
            if let Some(k) = (i..i + m - 1).rev().find(|&k| !printable[buf[k] as usize]) {
                i = k + 1;
                continue;
            }
        }
        let mut j = i + m;
        while j < n && printable[buf[j] as usize] {
            j += 1;
        }
        let run_len = j - i;
        if run_len >= m {
            // Conservative mode: the ORIGINAL bytes at this window
            // must be ≥ 50% non-printable. Real obfuscated strings
            // have encoded bytes that look like binary noise; if
            // the original is already mostly printable, the XOR
            // brute-force is just emitting alphabet-soup noise.
            if opts.require_nonprintable_source {
                let np = buf[i..j].iter().filter(|b| !is_printable(**b)).count();
                if np * 2 < run_len {
                    i = j;
                    continue;
                }
            }
            let decoded_bytes: Vec<u8> = buf[i..j].iter().map(|b| decode(*b)).collect();
            if let Ok(s) = std::str::from_utf8(&decoded_bytes)
                && passes_filter(s)
            {
                out.push(DecodedString {
                    address: base_addr + i as u64,
                    method,
                    plaintext: s.to_string(),
                });
            }
            // Skip past this run so we don't emit nested
            // sub-strings for the same key.
            i = j;
        } else {
            // Every start inside this short run ends at the same `j`,
            // so its runs are shorter still; `j` itself starts an
            // empty run. Resume after it.
            i = j + 1;
        }
    }
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t'
}

/// Reject runs that are unlikely to be meaningful strings.
///
/// The "decoded" candidate must (a) contain a run of at least 3
/// consecutive letters — a real "word" — to weed out the XOR
/// alphabet-soup noise that otherwise dominates the output; (b) have
/// a majority of letter / digit bytes; (c) not be a pure repeat of a
/// single character.
fn passes_filter(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.as_bytes()[0];
    if s.bytes().all(|b| b == first) {
        return false;
    }
    // Need at least 3 consecutive DISTINCT letters somewhere — a
    // "word" like "abc" or "GET" but not "VVV" or "aaa". This is
    // the single strongest filter against XOR brute-force noise on
    // real binaries.
    let bytes = s.as_bytes();
    let mut had_word = false;
    let mut i = 0;
    while i + 2 < bytes.len() {
        let a = bytes[i].to_ascii_lowercase();
        let b = bytes[i + 1].to_ascii_lowercase();
        let c = bytes[i + 2].to_ascii_lowercase();
        if a.is_ascii_alphabetic()
            && b.is_ascii_alphabetic()
            && c.is_ascii_alphabetic()
            && a != b
            && b != c
            && a != c
        {
            had_word = true;
            break;
        }
        i += 1;
    }
    if !had_word {
        return false;
    }
    let alnum = s.bytes().filter(|b| b.is_ascii_alphanumeric()).count();
    if alnum * 5 < s.len() * 3 {
        // < 60% alnum → mostly punctuation, skip.
        return false;
    }
    // Distinct-character variety check — rejects strings with too
    // few unique characters (mostly punctuation noise).
    let mut seen = [false; 256];
    for b in s.bytes() {
        seen[b as usize] = true;
    }
    let distinct = seen.iter().filter(|&&x| x).count();
    let min_distinct = if s.len() >= 16 { 6 } else { 4 };
    if distinct < min_distinct {
        return false;
    }
    // Periodicity check — rejects short-period repeats like
    // `@oNO@oNO@oNO...` that come from XOR-brute-forcing a repeating
    // original buffer (e.g. a 4-byte address table). For periods
    // 2..=8 we check whether the string is mostly the same N-byte
    // block repeated; if so, reject.
    let bytes = s.as_bytes();
    for period in 2..=8 {
        if bytes.len() < period * 2 {
            break;
        }
        let mut matches = 0usize;
        let total = bytes.len() - period;
        for k in 0..total {
            if bytes[k] == bytes[k + period] {
                matches += 1;
            }
        }
        // If ≥ 60% of bytes match the byte `period` away, treat
        // as periodic garbage. Real strings have low periodicity
        // for these small periods.
        if matches * 100 / total >= 60 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scan before the skip search: every start, one byte at a time.
    fn scan_naive(buf: &[u8], opts: &FlossOptions, out: &mut Vec<DecodedString>, decode: impl Fn(u8) -> u8, method: DecodeMethod) {
        let n = buf.len();
        let mut i = 0;
        while i + opts.min_length <= n {
            let mut j = i;
            while j < n && is_printable(decode(buf[j])) {
                j += 1;
            }
            let run_len = j - i;
            if run_len >= opts.min_length {
                if opts.require_nonprintable_source {
                    let np = buf[i..j].iter().filter(|b| !is_printable(**b)).count();
                    if np * 2 < run_len {
                        i = j;
                        continue;
                    }
                }
                let decoded_bytes: Vec<u8> = buf[i..j].iter().map(|b| decode(*b)).collect();
                if let Ok(s) = std::str::from_utf8(&decoded_bytes)
                    && passes_filter(s)
                {
                    out.push(DecodedString { address: 0x1000 + i as u64, method, plaintext: s.to_string() });
                }
                i = j;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn min_length_zero_terminates() {
        let mut buf = vec![0x01u8, 0x02, 0xff];
        buf.extend_from_slice(b"HelloWorldKey");
        buf.extend_from_slice(&[0x00, 0x80, 0x90]);
        let opts = FlossOptions { min_length: 0, try_add: true, ..FlossOptions::default() };
        let zero = decode_section(&buf, 0x1000, &opts);
        let one = decode_section(&buf, 0x1000, &FlossOptions { min_length: 1, ..opts });
        assert_eq!(zero.len(), one.len());
        assert!(zero.iter().all(|d| !d.plaintext.is_empty()));
        let mut out = Vec::new();
        scan_with(&buf, 0x1000, &opts, &mut out, |b| b, DecodeMethod::Xor(0));
        assert!(out.iter().all(|d| !d.plaintext.is_empty()));
    }

    #[test]
    fn skip_scan_matches_naive_scan() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        let mut hits = 0usize;
        for round in 0..200 {
            let len = (next() % 600) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|_| match next() % 4 {
                    0 => (next() % 256) as u8,
                    _ => b"abcdefghijklmnopqrstuvwxyzEXAMPLE/:.-_ 0123"[(next() % 43) as usize] ^ 0x5a,
                })
                .collect();
            for &(m, strict) in &[(1usize, false), (3, true), (6, false), (8, true), (12, false), (40, true)] {
                let opts = FlossOptions { min_length: m, require_nonprintable_source: strict, ..FlossOptions::default() };
                for key in [0x5au8, 0x01, 0xa0] {
                    let (mut fast, mut slow) = (Vec::new(), Vec::new());
                    scan_with(&buf, 0x1000, &opts, &mut fast, |b| b ^ key, DecodeMethod::Xor(key));
                    scan_naive(&buf, &opts, &mut slow, |b| b ^ key, DecodeMethod::Xor(key));
                    assert_eq!(fast, slow, "round {round} m {m} strict {strict} key {key:#x}");
                    hits += fast.len();
                }
            }
        }
        assert!(hits > 100, "the buffers should decode to some strings ({hits})");
    }

    #[test]
    fn xor_decode_recovers_string() {
        let plain = b"http://malicious.example/c2/getCmd";
        // Key 0xA0 produces non-printable encoded bytes (top bit set
        // on most characters), the realistic case the conservative
        // filter is tuned for.
        let key = 0xA0u8;
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        // Disable address-dedup so we see every key/plaintext pair
        // (the default would collapse all 34-byte decodings at
        // offset 0x1000 down to one).
        let opts = FlossOptions {
            dedup_per_address: false,
            max_per_section: 100_000,
            ..FlossOptions::default()
        };
        let found = decode_section(&encoded, 0x1000, &opts);
        let hit = found
            .iter()
            .find(|d| d.plaintext == String::from_utf8_lossy(plain))
            .expect("expected to recover plaintext");
        assert_eq!(hit.method, DecodeMethod::Xor(key));
        assert_eq!(hit.address, 0x1000);
    }

    #[test]
    fn xor_decode_lenient_mode_finds_printable_encoded() {
        // With `require_nonprintable_source = false`, even an
        // already-printable encoded buffer should be brute-forced.
        let plain = b"http://malicious.example/c2/getCmd";
        let key = 0x42u8;
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        let opts = FlossOptions {
            require_nonprintable_source: false,
            dedup_per_address: false,
            max_per_section: 100_000,
            ..FlossOptions::default()
        };
        let found = decode_section(&encoded, 0x1000, &opts);
        assert!(
            found
                .iter()
                .any(|d| d.plaintext == String::from_utf8_lossy(plain)
                    && d.method == DecodeMethod::Xor(key)),
            "expected the plaintext for the right key to be among the hits; got {:?}",
            found.iter().take(5).collect::<Vec<_>>()
        );
    }

    #[test]
    fn rol_decode_recovers_string() {
        let plain = b"GET /admin/login HTTP/1.1";
        let r = 3u32;
        let encoded: Vec<u8> = plain.iter().map(|b| b.rotate_right(r)).collect();
        let opts = FlossOptions {
            dedup_per_address: false,
            max_per_section: 100_000,
            ..FlossOptions::default()
        };
        let found = decode_section(&encoded, 0x2000, &opts);
        let hit = found
            .iter()
            .find(|d| d.plaintext == String::from_utf8_lossy(plain))
            .expect("expected to recover plaintext");
        assert_eq!(hit.method, DecodeMethod::Rol(r as u8));
    }

    #[test]
    fn plain_strings_not_emitted() {
        let plain = b"plain ascii text inside .rdata";
        let opts = FlossOptions::default();
        let found = decode_section(plain, 0x3000, &opts);
        assert!(
            !found.iter().any(|d| d.plaintext == String::from_utf8_lossy(plain)),
            "plain text should be skipped by plain_set"
        );
    }

    #[test]
    fn pure_repeat_rejected() {
        // 16 bytes of 0x41 (A) XOR'd with 0x01 → 16 bytes of 0x40 (@)
        let buf = [0x41u8; 16];
        let opts = FlossOptions::default();
        let found = decode_section(&buf, 0, &opts);
        // None of the runs should pass the pure-repeat filter.
        assert!(found.is_empty(), "pure repeats should be filtered: {:?}", found);
    }

    #[test]
    fn add_off_by_default() {
        let plain = b"hello world test ADD";
        let key = 0xC0u8;
        let encoded: Vec<u8> = plain.iter().map(|b| b.wrapping_sub(key)).collect();
        let opts = FlossOptions { dedup_per_address: false, max_per_section: 100_000, ..FlossOptions::default() };
        let found = decode_section(&encoded, 0, &opts);
        assert!(
            !found.iter().any(|d| d.plaintext == String::from_utf8_lossy(plain)),
            "ADD should be off by default"
        );

        let opts = FlossOptions { try_add: true, dedup_per_address: false, max_per_section: 100_000, ..FlossOptions::default() };
        let found = decode_section(&encoded, 0, &opts);
        assert!(found.iter().any(|d| d.method == DecodeMethod::Add(key)));
    }

    #[test]
    fn min_length_filter() {
        let plain = b"abcde"; // 5 bytes, below default min of 6
        let key = 0x55u8;
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        let opts = FlossOptions::default();
        let found = decode_section(&encoded, 0, &opts);
        assert!(found.is_empty(), "5-byte run should be below min_length");
    }

    #[test]
    fn passes_filter_basics() {
        assert!(!passes_filter(""));
        assert!(!passes_filter("AAAAAAAA"));
        assert!(!passes_filter("        "));
        assert!(!passes_filter("------!!"));
        assert!(!passes_filter("a1!b2@c3#")); // no 3-letter run
        assert!(!passes_filter("VVV-VVV-V")); // letters aren't distinct
        assert!(!passes_filter("aaaabbbbcccc")); // adjacent letters repeat
        assert!(!passes_filter("@oNO@oNO@oNO@oNO")); // periodic 4-byte garbage
        assert!(passes_filter("hello123"));
        assert!(passes_filter("GET /index.html"));
    }

    #[test]
    fn decode_method_labels() {
        assert_eq!(DecodeMethod::Xor(0x42).label(), "XOR(0x42)");
        assert_eq!(DecodeMethod::Add(0x05).label(), "ADD(0x05)");
        assert_eq!(DecodeMethod::Rol(3).label(), "ROL(3)");
    }
}
