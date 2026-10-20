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

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, Early, State};

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
    fn writes(&self) -> State {
        State::TAGS.union(State::METADATA)
    }
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
    fn start_early(&self, program: &mut Program) {
        // the sections' bytes are fixed for the run
        let sections = section_bytes(program);
        Early::<FlossLiteAnalyzer, usize>::start(program, move || count_decoded(sections, &pipeline_options()));
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let opts = pipeline_options();
        let total = match Early::<FlossLiteAnalyzer, usize>::take(program) {
            Some(total) => total,
            None => count_decoded(section_bytes(program), &opts),
        };

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

/// The pipeline's options: conservative defaults + min_length 12
/// (stricter than the CLI default) so the pipeline doesn't pollute tag
/// space with brute-force noise. Users who want lower thresholds
/// invoke `floss` directly.
fn pipeline_options() -> FlossOptions {
    FlossOptions { min_length: 12, ..FlossOptions::default() }
}

/// The address and bytes of every section the pipeline scans
/// (non-executable, non-empty, at most 16 MiB, readable).
fn section_bytes(program: &Program) -> Vec<(u64, Vec<u8>)> {
    program
        .info
        .sections
        .iter()
        .filter(|s| s.size > 0 && s.size <= 16 * 1024 * 1024 && !s.flags.contains(SectionFlags::EXECUTE))
        .filter_map(|s| {
            let mut buf = vec![0u8; s.size as usize];
            program.info.memory.read_bytes(s.address, &mut buf).ok()?;
            Some((s.address, buf))
        })
        .collect()
}

/// The number of strings [`decode_section`] finds in all of `sections`.
fn count_decoded(sections: Vec<(u64, Vec<u8>)>, opts: &FlossOptions) -> usize {
    sections.iter().map(|(addr, buf)| decode_section(buf, *addr, opts).len()).sum()
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
///
/// Each (method, key) pass examines every maximal run of bytes that
/// decode printable, of at least `min_length` bytes, in address order;
/// the hits of the passes are appended in the fixed XOR → ADD → ROL,
/// ascending-key order, and the first pass that takes them over
/// `max_per_section` ends the search (the hits are then returned
/// truncated, not deduplicated).
pub fn decode_section(buf: &[u8], base_addr: u64, opts: &FlossOptions) -> Vec<DecodedString> {
    decode_in_chunks(buf, base_addr, opts, CHUNK)
}

/// [`decode_section`], scanning the buffer `chunk` bytes per task.
fn decode_in_chunks(buf: &[u8], base_addr: u64, opts: &FlossOptions, chunk: usize) -> Vec<DecodedString> {
    // The count of source bytes that are not printable, by prefix: the
    // conservative check of every run of every pass in O(1).
    let nonprintable = (opts.require_nonprintable_source && u32::try_from(buf.len()).is_ok()).then(|| {
        let not_printable: [u32; 256] = std::array::from_fn(|b| u32::from(!is_printable(b as u8)));
        let mut prefix = Vec::with_capacity(buf.len() + 1);
        prefix.push(0);
        let mut count = 0u32;
        prefix.extend(buf.iter().map(|&b| {
            count += not_printable[b as usize];
            count
        }));
        prefix
    });
    let nonprintable = nonprintable.as_deref();
    // The passes of a method run 64 at a time, one bit of a word per
    // pass (see [`scan_chunk`]), over chunks of the buffer in parallel;
    // the groups run in order (XOR, ADD, ROL, by key), so the search stops
    // after the group whose passes reach the cap.
    let tried = |method: &DecodeMethod| match method {
        DecodeMethod::Xor(_) => opts.try_xor,
        DecodeMethod::Add(_) => opts.try_add,
        DecodeMethod::Rol(_) => opts.try_rol,
    };
    let mut hits: Vec<DecodedString> = Vec::new();
    for group in Group::all().iter().filter(|g| tried(&g.methods[0])) {
        let scan = |lo: usize| scan_chunk(buf, lo, (lo + chunk).min(buf.len()), nonprintable, opts, group);
        let found: Vec<Vec<Vec<(usize, usize)>>> = if buf.len() <= chunk {
            vec![scan(0)]
        } else {
            (0..buf.len()).step_by(chunk).collect::<Vec<_>>().into_par_iter().map(scan).collect()
        };
        // The rest of the filter for the passes in order, a batch at a time
        // in parallel, and their hits up to the cap: the passes past the
        // batch that reaches it are not looked at, nor are the strings
        // past it built.
        let runs = |q: usize| found.iter().flat_map(move |c| &c[q]);
        let pass_runs = |q: usize| -> Vec<(usize, usize)> {
            runs(q).copied().filter(|&(i, j)| passes_filter_rest(&buf[i..j], &group.classes[q])).collect()
        };
        let passes: Vec<usize> = (0..group.methods.len()).collect();
        for batch in passes.chunks(rayon::current_num_threads().max(1) * 2) {
            let per_pass: Vec<Vec<(usize, usize)>> = if buf.len() <= chunk {
                batch.iter().map(|&q| pass_runs(q)).collect()
            } else {
                batch.par_iter().map(|&q| pass_runs(q)).collect()
            };
            for (&q, runs) in batch.iter().zip(per_pass) {
                let method = group.methods[q];
                let room = opts.max_per_section - hits.len();
                hits.extend(runs.iter().take(room).map(|&(i, j)| DecodedString {
                    address: base_addr + i as u64,
                    method,
                    // printable ASCII: one char per byte
                    plaintext: buf[i..j].iter().map(|&b| char::from(method.decode(b))).collect(),
                }));
                if runs.len() > room {
                    return hits;
                }
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

/// The run starts a task of [`decode_section`] looks at (the runs may
/// extend past them, and its `w` holds a word per byte: 256 KiB).
const CHUNK: usize = 32 * 1024;

impl DecodeMethod {
    /// The decoded value of `b` (a bijection of the byte values).
    fn decode(self, b: u8) -> u8 {
        match self {
            Self::Xor(k) => b ^ k,
            Self::Add(k) => b.wrapping_add(k),
            Self::Rol(r) => b.rotate_left(u32::from(r)),
        }
    }
}

/// Up to 64 passes of one method scanned together.
struct Group {
    methods: Vec<DecodeMethod>,
    /// Per source byte value, bit `q` set when pass `q` decodes it printable.
    printable: [u64; 256],
    /// Per source byte value, bit `q` set when pass `q` decodes it to a letter.
    letter: [u64; 256],
    /// [`byte_classes`] of each pass.
    classes: Vec<[u8; 256]>,
}

impl Group {
    /// Every pass, in the order they are tried: XOR, ADD, ROL, by key; a
    /// group holds the passes of one method.
    fn all() -> &'static [Group] {
        static ALL: std::sync::OnceLock<Vec<Group>> = std::sync::OnceLock::new();
        ALL.get_or_init(|| {
            let xor: Vec<DecodeMethod> = (1u8..=255).map(DecodeMethod::Xor).collect();
            let add: Vec<DecodeMethod> = (1u8..=255).map(DecodeMethod::Add).collect();
            let rol: Vec<DecodeMethod> = (1u8..=7).map(DecodeMethod::Rol).collect();
            [xor, add, rol].iter().flat_map(|p| p.chunks(64)).map(Group::new).collect()
        })
    }

    fn new(methods: &[DecodeMethod]) -> Self {
        debug_assert!(methods.len() <= 64);
        let bits = |test: &dyn Fn(u8) -> bool| -> [u64; 256] {
            std::array::from_fn(|b| methods.iter().enumerate().fold(0u64, |bits, (q, d)| bits | (u64::from(test(d.decode(b as u8))) << q)))
        };
        let printable = bits(&is_printable);
        let letter = bits(&|d: u8| d.is_ascii_alphabetic());
        let classes = methods.iter().map(|&d| byte_classes(|b| d.decode(b))).collect();
        Group { methods: methods.to_vec(), printable, letter, classes }
    }

    /// The passes that decode `a`, `b`, `c` to letters pairwise distinct
    /// ignoring case, given that they decode them to letters. Two decoded
    /// letters are one ignoring case when they are equal or differ in bit 5
    /// only (`x ^ y` is 0 or 0x20), which for XOR is `a ^ b` alone, for ADD
    /// the difference `a - b` (0 or ±0x20) and for a rotation `a ^ b` rotated.
    fn distinct(&self, a: u8, b: u8, c: u8) -> u64 {
        let all = |ok: bool| 0u64.wrapping_sub(u64::from(ok));
        match self.methods[0] {
            DecodeMethod::Xor(_) => all(((a ^ b) & 0xdf != 0) & ((b ^ c) & 0xdf != 0) & ((a ^ c) & 0xdf != 0)),
            DecodeMethod::Add(_) => {
                let ok = |d: u8| (d & 0xdf != 0) & (d != 0xe0);
                all(ok(a.wrapping_sub(b)) & ok(b.wrapping_sub(c)) & ok(a.wrapping_sub(c)))
            }
            DecodeMethod::Rol(_) => self.methods.iter().enumerate().fold(0u64, |bits, (q, d)| {
                let ok = |x: u8, y: u8| (d.decode(x) ^ d.decode(y)) & 0xdf != 0;
                bits | (u64::from(ok(a, b) & ok(b, c) & ok(a, c)) << q)
            }),
        }
    }
}

/// The runs `(start, end)` of each pass of `group` (by its index) that
/// may hold a hit: the maximal printable runs of at least `min_length`
/// bytes starting in `buf[lo..hi]`, in address order, that pass the
/// conservative check and [`has_word`] (the rest of the filter,
/// [`passes_filter_rest`], is left to the caller). Every pass
/// at once, a bit each: `s[i]` is the set of passes decoding `buf[i]`
/// printable and `w[i]` the AND of `s[i..i + m]`, so a pass's run of at
/// least `m` bytes starts at `i` exactly when its bit is set in `w[i]` and
/// not in `s[i - 1]`, and ends at the first byte after it whose bit is
/// clear in `s`. On the way, `seen` collects the passes that decode 3
/// consecutive bytes since the start of their run to pairwise distinct
/// letters: the run's [`has_word`], the test that rejects most runs. A
/// byte is looked up once for the 64 passes, where a pass of its own
/// tests about a byte in four, and only the runs with a word are looked at
/// one by one.
fn scan_chunk(
    buf: &[u8],
    lo: usize,
    hi: usize,
    nonprintable: Option<&[u32]>,
    opts: &FlossOptions,
    group: &Group,
) -> Vec<Vec<(usize, usize)>> {
    let mut out: Vec<Vec<(usize, usize)>> = vec![Vec::new(); group.methods.len()];
    let n = buf.len();
    // A zero minimum would count an empty run as a hit and never
    // advance; clamp to 1 (identical behaviour for every m >= 1).
    let m = opts.min_length.max(1);
    if n < m {
        return out;
    }
    // the run starts looked at: those with `m` bytes in the buffer
    let last = hi.min(n - m + 1);
    if lo >= last {
        return out;
    }
    let (printable, letter) = (&group.printable, &group.letter);
    let mut w: Vec<u64> = buf[lo..last + m - 1].iter().map(|&b| printable[b as usize]).collect();
    window_and(&mut w, m, &mut Vec::new());
    // the passes in a run of at least `m` bytes, the start of each run, and
    // the passes whose run holds a word so far
    let mut active = 0u64;
    let mut start = [0usize; 64];
    let mut seen = 0u64;
    // the runs that end at `t` (its byte is not printable to them)
    let mut finish = |ends: u64, t: usize, seen: u64, start: &[usize; 64]| {
        let mut ends = ends & seen;
        while ends != 0 {
            let q = ends.trailing_zeros() as usize;
            ends &= ends - 1;
            let (i, j) = (start[q], t);
            // Conservative mode: the ORIGINAL bytes at this window
            // must be ≥ 50% non-printable. Real obfuscated strings
            // have encoded bytes that look like binary noise; if
            // the original is already mostly printable, the XOR
            // brute-force is just emitting alphabet-soup noise.
            if opts.require_nonprintable_source {
                let np = match nonprintable {
                    Some(p) => (p[j] - p[i]) as usize,
                    None => buf[i..j].iter().filter(|b| !is_printable(**b)).count(),
                };
                if np * 2 < j - i {
                    continue;
                }
            }
            out[q].push((i, j));
        }
    };
    let mut prev = 0;
    // one byte: `st` the passes it decodes printable for, `starts` the
    // runs starting at it
    macro_rules! step {
        ($t:expr, $st:expr, $starts:expr) => {{
            let (t, st): (usize, u64) = ($t, $st);
            let ends = active & !st;
            if ends != 0 {
                active &= st;
                finish(ends, t, seen, &start);
            }
            let mut starts: u64 = $starts;
            if starts != 0 {
                active |= starts;
                seen &= !starts;
                while starts != 0 {
                    start[starts.trailing_zeros() as usize] = t;
                    starts &= starts - 1;
                }
            }
            // a word at `t` for a pass of a run without one yet
            let open = active & !seen;
            if open != 0
                && let Some(&[a, b, c]) = buf.get(t..t + 3)
            {
                let l = open & letter[a as usize] & letter[b as usize] & letter[c as usize];
                if l != 0 {
                    seen |= l & group.distinct(a, b, c);
                }
            }
        }};
    }
    let mut k = 0;
    while k < w.len() {
        if active == 0 {
            // no run open: on to the next window of a run
            match w[k..].iter().position(|&x| x != 0) {
                Some(d) => k += d,
                None => {
                    k = w.len();
                    break;
                }
            }
            let t = lo + k;
            prev = if t == 0 { 0 } else { printable[buf[t - 1] as usize] };
        }
        let t = lo + k;
        let st = printable[buf[t] as usize];
        step!(t, st, w[k] & !prev);
        prev = st;
        k += 1;
    }
    // the runs still open, up to their ends
    let mut t = lo + k;
    while active != 0 {
        let st = buf.get(t).map_or(0, |&b| printable[b as usize]);
        step!(t, st, 0);
        t += 1;
    }
    out
}

/// In place, the AND of every `m` consecutive values of `v` (the first
/// `v.len() + 1 - m` values, then truncated to them; `1 <= m <=
/// v.len()`): the ANDs of the windows of a power of two `len` by
/// doubling, then two windows of `len` that cover `m` (they overlap
/// unless `m` is `2 * len`; AND is idempotent). `tmp` is scratch.
fn window_and(v: &mut Vec<u64>, m: usize, tmp: &mut Vec<u64>) {
    // `tmp[..k] = v[..k] & v[d..d + k]`, swapped into `v`
    let mut and_shifted = |v: &mut Vec<u64>, d: usize| {
        tmp.clear();
        tmp.extend(v.iter().zip(&v[d..]).map(|(x, y)| x & y));
        std::mem::swap(v, tmp);
    };
    let mut len = 1;
    while len * 2 <= m {
        and_shifted(v, len);
        len *= 2;
    }
    if m > len {
        and_shifted(v, m - len);
    }
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t'
}

/// The class of each source byte value after `decode`: its lower-case letter, [`DIGIT`], or 0.
fn byte_classes(decode: impl Fn(u8) -> u8) -> [u8; 256] {
    std::array::from_fn(|b| {
        let d = decode(b as u8);
        if d.is_ascii_alphabetic() {
            d.to_ascii_lowercase()
        } else if d.is_ascii_digit() {
            DIGIT
        } else {
            0
        }
    })
}

/// [`byte_classes`] of a digit (any value below `b'a'` but 0).
const DIGIT: u8 = 1;

/// Does `bytes` hold 3 consecutive letters, pairwise distinct ignoring case? (A byte that is
/// no letter ends every window holding it: the next one to try starts after it, so a run of
/// digits / punctuation is looked at one byte in three.) `class` is [`byte_classes`] of the
/// decoding: a letter is a class `>= b'a'`, compared by its class (lower case). The scan
/// tests it for every pass at once ([`scan_chunk`]); this is its definition.
#[cfg(test)]
fn has_word(bytes: &[u8], class: &[u8; 256]) -> bool {
    let letter = |b: u8| class[b as usize] >= b'a';
    let mut i = 0;
    while i + 2 < bytes.len() {
        if !letter(bytes[i + 2]) {
            i += 3;
            continue;
        }
        if !letter(bytes[i + 1]) {
            i += 2;
            continue;
        }
        if !letter(bytes[i]) {
            i += 1;
            continue;
        }
        let (a, b, c) = (class[bytes[i] as usize], class[bytes[i + 1] as usize], class[bytes[i + 2] as usize]);
        if a != b && b != c && a != c {
            return true;
        }
        i += 1;
    }
    false
}

/// [`passes_filter`] but its [`has_word`] (which [`scan_chunk`] tests on
/// its way), of the decoded `src`, computed on the source bytes: `class`
/// is [`byte_classes`] of the decoding, which must be a bijection — two
/// decoded bytes are then equal exactly when their source bytes are, so
/// the variety and periodicity tests read the source as they would the
/// decoded bytes. (No string is built for a rejected run; the pure-repeat
/// test of [`passes_filter`] is implied by a word.)
fn passes_filter_rest(src: &[u8], class: &[u8; 256]) -> bool {
    // < 60% alnum → mostly punctuation, skip (`alnum * 5 < len * 3`,
    // counted until the answer is known)
    let need = src.len() * 3;
    let mut alnum = 0usize;
    for (k, &b) in src.iter().enumerate() {
        if alnum * 5 >= need {
            break;
        }
        if (alnum + (src.len() - k)) * 5 < need {
            return false;
        }
        alnum += usize::from(class[b as usize] != 0);
    }
    if alnum * 5 < need {
        return false;
    }
    variety_and_period_ok(src)
}

/// The distinct-character and periodicity tests of [`passes_filter`] (byte equality only).
fn variety_and_period_ok(bytes: &[u8]) -> bool {
    // Distinct-character variety check — rejects strings with too
    // few unique characters (mostly punctuation noise).
    let min_distinct = if bytes.len() >= 16 { 6 } else { 4 };
    // counted until there are enough
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in bytes {
        if distinct >= min_distinct {
            break;
        }
        distinct += usize::from(!std::mem::replace(&mut seen[b as usize], true));
    }
    if distinct < min_distinct {
        return false;
    }
    // Periodicity check — rejects short-period repeats like
    // `@oNO@oNO@oNO...` that come from XOR-brute-forcing a repeating
    // original buffer (e.g. a 4-byte address table). For periods
    // 2..=8 we check whether the string is mostly the same N-byte
    // block repeated; if so, reject.
    for period in 2..=8 {
        if bytes.len() < period * 2 {
            break;
        }
        // If ≥ 60% of bytes match the byte `period` away, treat
        // as periodic garbage. Real strings have low periodicity
        // for these small periods. (`matches * 100 / total >= 60`,
        // that is `matches * 100 >= total * 60`, counted until the
        // answer is known.)
        let total = bytes.len() - period;
        let need = total * 60;
        let mut matches = 0usize;
        let mut k = 0;
        while k < total {
            if matches * 100 >= need {
                return false;
            }
            if (matches + (total - k)) * 100 < need {
                break;
            }
            // 64 comparisons at a time between the checks
            let end = (k + 64).min(total);
            matches += bytes[k..end].iter().zip(&bytes[k + period..end + period]).filter(|(a, b)| a == b).count();
            k = end;
        }
        if matches * 100 >= need {
            return false;
        }
    }
    true
}

/// Reject runs that are unlikely to be meaningful strings.
///
/// The "decoded" candidate must (a) contain a run of at least 3
/// consecutive letters — a real "word" — to weed out the XOR
/// alphabet-soup noise that otherwise dominates the output; (b) have
/// a majority of letter / digit bytes; (c) not be a pure repeat of a
/// single character. (The scan tests the same on the source bytes:
/// [`has_word`] on its way, then [`passes_filter_rest`].)
#[cfg(test)]
fn passes_filter(s: &str) -> bool {
    let class = byte_classes(|b| b);
    has_word(s.as_bytes(), &class) && passes_filter_rest(s.as_bytes(), &class)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scan before the skip search: every start, one byte at a time,
    /// with the filter on the decoded string.
    fn scan_naive(buf: &[u8], base_addr: u64, opts: &FlossOptions, out: &mut Vec<DecodedString>, method: DecodeMethod) {
        let decode = |b: u8| method.decode(b);
        let m = opts.min_length.max(1);
        let n = buf.len();
        let mut i = 0;
        while i + m <= n {
            let mut j = i;
            while j < n && is_printable(decode(buf[j])) {
                j += 1;
            }
            let run_len = j - i;
            if run_len >= m {
                if opts.require_nonprintable_source {
                    let np = buf[i..j].iter().filter(|b| !is_printable(**b)).count();
                    if np * 2 < run_len {
                        i = j;
                        continue;
                    }
                }
                let decoded_bytes: Vec<u8> = buf[i..j].iter().map(|b| decode(*b)).collect();
                if let Ok(s) = std::str::from_utf8(&decoded_bytes)
                    && passes_filter_reference(s)
                {
                    out.push(DecodedString { address: base_addr + i as u64, method, plaintext: s.to_string() });
                }
                i = j;
            } else {
                i += 1;
            }
        }
    }

    /// [`decode_section`] as it was: a pass per method ([`scan_naive`]), in order, up to the cap.
    fn decode_section_reference(buf: &[u8], base_addr: u64, opts: &FlossOptions) -> Vec<DecodedString> {
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
        let mut hits: Vec<DecodedString> = Vec::new();
        for method in methods {
            scan_naive(buf, base_addr, opts, &mut hits, method);
            if hits.len() > opts.max_per_section {
                hits.truncate(opts.max_per_section);
                return hits;
            }
        }
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
        assert_eq!(zero, decode_section_reference(&buf, 0x1000, &opts));
    }

    /// `passes_filter` before its counts stopped early.
    fn passes_filter_reference(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        let first = s.as_bytes()[0];
        if s.bytes().all(|b| b == first) {
            return false;
        }
        let bytes = s.as_bytes();
        let had_word = bytes.windows(3).any(|w| {
            let (a, b, c) = (w[0].to_ascii_lowercase(), w[1].to_ascii_lowercase(), w[2].to_ascii_lowercase());
            a.is_ascii_alphabetic() && b.is_ascii_alphabetic() && c.is_ascii_alphabetic() && a != b && b != c && a != c
        });
        if !had_word {
            return false;
        }
        let alnum = s.bytes().filter(|b| b.is_ascii_alphanumeric()).count();
        if alnum * 5 < s.len() * 3 {
            return false;
        }
        let mut seen = [false; 256];
        for b in s.bytes() {
            seen[b as usize] = true;
        }
        let distinct = seen.iter().filter(|&&x| x).count();
        if distinct < if s.len() >= 16 { 6 } else { 4 } {
            return false;
        }
        for period in 2..=8 {
            if bytes.len() < period * 2 {
                break;
            }
            let total = bytes.len() - period;
            let matches = (0..total).filter(|&k| bytes[k] == bytes[k + period]).count();
            if matches * 100 / total >= 60 {
                return false;
            }
        }
        true
    }

    /// `has_word` finds a window of 3 pairwise distinct letters where the byte-by-byte search
    /// does, in strings of letters, digits and punctuation and of every byte value.
    #[test]
    fn has_word_matches_windows() {
        let naive = |bytes: &[u8]| {
            bytes.windows(3).any(|w| {
                let (a, b, c) = (w[0].to_ascii_lowercase(), w[1].to_ascii_lowercase(), w[2].to_ascii_lowercase());
                a.is_ascii_alphabetic() && b.is_ascii_alphabetic() && c.is_ascii_alphabetic() && a != b && b != c && a != c
            })
        };
        let mut state = 0x51ed_270b_9a3c_44f1u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        let alphabets: [&[u8]; 4] = [b"0123456789aAbB.", b"aaAAbz9", b"@[`{AZaz", b"xY1"];
        let mut found = 0;
        for round in 0..40_000 {
            let len = (next() % 200) as usize;
            let bytes: Vec<u8> = match round % 5 {
                4 => (0..len).map(|_| next() as u8).collect(),
                r => (0..len).map(|_| alphabets[r][(next() as usize) % alphabets[r].len()]).collect(),
            };
            assert_eq!(has_word(&bytes, &byte_classes(|b| b)), naive(&bytes), "{bytes:?}");
            found += usize::from(has_word(&bytes, &byte_classes(|b| b)));
        }
        assert!(found > 1000, "{found}");
        // a word at the end, or cut off by it
        for at in [0usize, 61, 62, 63, 64, 125, 126, 127, 128] {
            let mut bytes = vec![b'1'; 200];
            bytes[at..at + 3].copy_from_slice(b"aBc");
            assert!(has_word(&bytes, &byte_classes(|b| b)) && has_word(&bytes[..at + 3], &byte_classes(|b| b)) && !has_word(&bytes[..at + 2], &byte_classes(|b| b)), "{at}");
        }
    }

    #[test]
    fn filter_matches_reference() {
        let mut state = 0x0bad_cafe_dead_beefu64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        let alphabets: [&[u8]; 4] = [b"abcdefghijKLMNOP0123", b"ab12", b"a.-_ /:b", b"xyzXYZ!@#$%^&*()09"];
        let mut passed = 0;
        for round in 0..20000 {
            let alphabet = alphabets[round % alphabets.len()];
            let len = (next() % 300) as usize;
            let period = 1 + (next() % 10) as usize;
            let block: Vec<u8> = (0..period).map(|_| alphabet[(next() as usize) % alphabet.len()]).collect();
            // a periodic string with some bytes changed
            let noise = next() % 100;
            let bytes: Vec<u8> = (0..len)
                .map(|k| if next() % 100 < noise { alphabet[(next() as usize) % alphabet.len()] } else { block[k % period] })
                .collect();
            let s = std::str::from_utf8(&bytes).expect("ascii");
            assert_eq!(passes_filter(s), passes_filter_reference(s), "{s:?}");
            passed += usize::from(passes_filter(s));
        }
        assert!(passed > 100, "some strings should pass ({passed})");
    }

    /// The options the comparisons below try (`max` small enough for the cap to cut some).
    fn option_sets(max: usize) -> Vec<FlossOptions> {
        let mut sets = Vec::new();
        for (k, &(m, strict)) in [(0usize, true), (1, false), (3, true), (6, false), (8, true), (12, true), (12, false), (40, true)].iter().enumerate() {
            sets.push(FlossOptions {
                min_length: m,
                require_nonprintable_source: strict,
                try_add: k % 2 == 1,
                try_rol: k % 3 != 2,
                dedup_per_address: k % 4 != 3,
                max_per_section: if k % 2 == 0 { max } else { 100_000 },
                ..FlossOptions::default()
            });
        }
        sets.push(FlossOptions { try_xor: false, try_add: true, ..FlossOptions::default() });
        sets
    }

    /// The group scan finds what a pass per method, one start at a time, does: the same hits in
    /// the same order, cut by the cap at the same place, on random buffers.
    #[test]
    fn group_scan_matches_naive_scan() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        let mut hits = 0usize;
        // small chunks, so runs cross their ends
        let chunk = 1000;
        for round in 0..48 {
            let len = match round % 4 {
                0 => (next() % 600) as usize,
                1 => chunk - 40 + (next() % 80) as usize,
                _ => (next() % 12_000) as usize,
            };
            let key = next() as u8;
            let buf: Vec<u8> = (0..len)
                .map(|k| match (k / 64 + round) % 5 {
                    // zeros, text, noise, encoded text
                    0 => 0,
                    1 => b"abcdefghijklmnopqrstuvwxyzEXAMPLE/:.-_ 0123"[(next() % 43) as usize],
                    2 => next() as u8,
                    _ => match next() % 4 {
                        0 => (next() % 256) as u8,
                        _ => b"abcdefghijklmnopqrstuvwxyzEXAMPLE/:.-_ 0123"[(next() % 43) as usize] ^ key,
                    },
                })
                .collect();
            for opts in option_sets(50 + (next() % 400) as usize) {
                let fast = decode_in_chunks(&buf, 0x1000, &opts, chunk);
                assert_eq!(fast, decode_section_reference(&buf, 0x1000, &opts), "round {round} {opts:?}");
                assert_eq!(fast, decode_section(&buf, 0x1000, &opts), "round {round} {opts:?}");
                hits += fast.len();
            }
        }
        assert!(hits > 1000, "the buffers should decode to some strings ({hits})");
    }

    /// The same on the bytes of a real binary (this test's own executable).
    #[test]
    fn group_scan_matches_naive_scan_on_real_bytes() {
        let exe = std::fs::read(std::env::current_exe().expect("exe")).expect("read exe");
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        let mut hits = 0usize;
        for round in 0..6 {
            let len = (next() % 40_000).min(exe.len());
            let at = next() % (exe.len() - len + 1);
            let buf = &exe[at..at + len];
            for opts in option_sets(200 + next() % 2000) {
                let fast = decode_in_chunks(buf, 0x40_0000, &opts, 4096);
                assert_eq!(fast, decode_section_reference(buf, 0x40_0000, &opts), "round {round} at {at:#x} len {len} {opts:?}");
                hits += fast.len();
            }
        }
        assert!(hits > 100, "the bytes should decode to some strings ({hits})");
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
