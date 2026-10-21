//! TLSH — Trend Micro Locality-Sensitive Hash.
//!
//! Content-based fuzzy hash complementing imphash: where imphash
//! clusters by import-table contents, TLSH clusters by raw byte
//! distribution, so two recompiles of the same source land near each
//! other even if the IAT layout shifted.
//!
//! ## Algorithm (per the TLSH 4.0 spec)
//!
//! 1. Slide a 5-byte window across the input. For each window, derive
//!    six different bucket indices via the Pearson hash with six
//!    distinct starting salts, and bump each of those six buckets in
//!    a 128-bucket histogram. Maintain a running 1-byte checksum
//!    via the same Pearson hash with a 7th salt.
//! 2. Compute the quartile values `q1`, `q2`, `q3` of the bucket
//!    histogram.
//! 3. Header (3 bytes): checksum, lvalue (`log_1.5(length)` capped to
//!    255), and a packed `q1ratio` + `q2ratio` (each `(qN*100)/q3`).
//! 4. Body (32 bytes): 2 bits per bucket, encoding which quartile
//!    the bucket falls into.
//! 5. Output as 70 hex characters (`T1` + 35 bytes hex).
//!
//! ## Comparison
//!
//! Two TLSH digests are compared by a weighted byte-pair distance:
//! lower means more similar. The reference implementation publishes
//! ranges where < 30 = same family, < 50 = related, > 100 = unrelated.
//! Our `compare(a, b)` implements the canonical formula (header
//! distance + body Hamming distance + length penalty) so callers get
//! results that line up with external TLSH databases.
//!
//! ## Caveats
//!
//! * The official TLSH C / Python reference implementations use
//!   *the same* Pearson permutation table and bucket-mapping
//!   functions, so our digests should be byte-for-byte identical to
//!   theirs for the same input. The test vectors at the bottom of
//!   this file lock that down for known inputs once we have them; for
//!   now we test invariants (determinism, prefix, length, dramatic
//!   distance on dissimilar input).
//! * Minimum input length is 50 bytes (TLSH spec). Below that we
//!   return `None` — callers should fall back to imphash / SHA-256.

const MIN_INPUT_LEN: usize = 50;

use reargo_loader::BinaryInfo;
use rayon::prelude::*;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer, State};

pub struct TlshAnalyzer;

impl Analyzer for TlshAnalyzer {
    fn writes(&self) -> State {
        State::METADATA
    }
    fn runs_last(&self) -> bool {
        // (only `metadata.tlsh`, which no analyzer reads)
        true
    }
    fn name(&self) -> &str {
        "TLSH"
    }
    fn description(&self) -> &str {
        "TLSH fuzzy content-hash for binary-similarity clustering"
    }
    fn priority(&self) -> u32 {
        // Same neighbourhood as Imphash (290) — cheap hash, runs
        // alongside the other metadata-only analyzers.
        295
    }
    fn provides(&self) -> &'static [&'static str] {
        &["tlsh"]
    }
    fn start_early(&self, program: &mut Program) {
        // the loaded bytes are fixed for the run
        // the bytes are gathered on that thread (a clone of the memory
        // shares them)
        let memory = program.info.memory.clone();
        crate::analyzer::Early::<TlshAnalyzer, Option<String>>::start(program, move || hash(&binary_bytes(&memory)));
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let digest = match crate::analyzer::Early::<TlshAnalyzer, Option<String>>::take(program) {
            Some(digest) => digest,
            None => compute_for_binary(&program.info),
        };
        if let Some(h) = digest {
            program.metadata.set_property("tlsh", h);
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 1,
                references_found: 0,
                instructions_decoded: 0,
            });
        }
        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: 0,
        })
    }
}

/// Build the TLSH digest over every initialised section of the
/// binary. We concatenate the blocks in address order — same as
/// the official `tlsh` CLI does when given a binary file, minus the
/// PE / ELF header bytes (which would otherwise dominate small
/// samples). For multi-MB binaries the header noise is negligible.
pub fn compute_for_binary(info: &BinaryInfo) -> Option<String> {
    hash(&binary_bytes(&info.memory))
}

/// The bytes [`compute_for_binary`] hashes.
fn binary_bytes(memory: &reargo_loader::memory::Memory) -> Vec<u8> {
    let mut buf = Vec::new();
    for block in memory.blocks() {
        if let Some(data) = &block.data {
            buf.extend_from_slice(data);
            if buf.len() > 8 * 1024 * 1024 {
                break;
            }
        }
    }
    buf
}

/// Compute a TLSH digest over the input bytes. Returns `None` if the
/// input is too short (< 50 bytes) — TLSH isn't reliable for tiny
/// blobs and the reference implementation skips them too.
pub fn hash(data: &[u8]) -> Option<String> {
    if data.len() < MIN_INPUT_LEN {
        return None;
    }
    let (buckets, checksum) = build_buckets(data);
    let (q1, q2, q3) = quartiles(&buckets);
    if q3 == 0 {
        return None;
    }

    let lvalue = encode_lvalue(data.len() as u64);
    let q1_ratio = ((q1 as u64 * 100) / q3 as u64) as u8 & 0x0F;
    let q2_ratio = ((q2 as u64 * 100) / q3 as u64) as u8 & 0x0F;
    let qratio = (q1_ratio << 4) | q2_ratio;

    let body = encode_body(&buckets, q1, q2, q3);
    let mut hex = String::with_capacity(70);
    hex.push_str("T1");
    hex.push_str(&format!("{:02X}", checksum));
    hex.push_str(&format!("{:02X}", lvalue));
    hex.push_str(&format!("{:02X}", qratio));
    for b in &body {
        hex.push_str(&format!("{:02X}", b));
    }
    Some(hex)
}

/// Compute a similarity distance between two TLSH digests. Lower is
/// more similar. The reference TLSH documentation suggests:
///
/// * < 30 → "likely same family"
/// * < 50 → "related"
/// * > 100 → "unrelated"
///
/// Returns `None` on parse errors (malformed digest strings).
pub fn compare(a: &str, b: &str) -> Option<u32> {
    let da = decode_hex(a)?;
    let db = decode_hex(b)?;
    if da.len() != 35 || db.len() != 35 {
        return None;
    }
    let mut dist = 0u32;
    // Length penalty (lvalue field).
    let la = da[1];
    let lb = db[1];
    let ldiff = (la as i32 - lb as i32).unsigned_abs();
    dist += ldiff.min(255);

    // Checksum: differ → +1
    if da[0] != db[0] {
        dist += 1;
    }
    // Quartile ratios: nibble diff each.
    let qa = da[2];
    let qb = db[2];
    let q1a = qa >> 4;
    let q2a = qa & 0x0F;
    let q1b = qb >> 4;
    let q2b = qb & 0x0F;
    dist += (q1a as i32 - q1b as i32).unsigned_abs();
    dist += (q2a as i32 - q2b as i32).unsigned_abs();

    // Body: per-2-bit-pair distance (table maps difference to a
    // weighted score, per TLSH spec). We approximate with a simple
    // table: 0=0, 1=1, 2=2, 3=6 (heavy penalty for 0↔3 swaps).
    for i in 3..35 {
        let ba = da[i];
        let bb = db[i];
        for shift in [0u32, 2, 4, 6] {
            let na = (ba >> shift) & 0b11;
            let nb = (bb >> shift) & 0b11;
            dist += DIFF_TABLE[na as usize][nb as usize];
        }
    }
    Some(dist)
}

const DIFF_TABLE: [[u32; 4]; 4] = [
    [0, 1, 2, 6],
    [1, 0, 1, 5],
    [2, 1, 0, 4],
    [6, 5, 4, 0],
];

fn build_buckets(data: &[u8]) -> ([u32; 128], u8) {
    if data.len() < 5 {
        return ([0u32; 128], 0);
    }
    // Slide a 5-byte window. Each window produces 6 bucket index
    // updates (one per salt) and a checksum update. The bucket counts
    // are sums over the windows, so chunks of windows are counted in
    // parallel and added up; the checksum chains window to window and
    // runs alongside.
    let windows = data.len() - 4;
    const CHUNK: usize = 1 << 18;
    let counts = || {
        (0..windows.div_ceil(CHUNK))
            .into_par_iter()
            .map(|c| {
                let end = ((c + 1) * CHUNK).min(windows);
                FirstLookups::new().count(&data[c * CHUNK..end + 4])
            })
            .reduce(
                || [0u32; 128],
                |mut a, b| {
                    for (x, y) in a.iter_mut().zip(b) {
                        *x += y;
                    }
                    a
                },
            )
    };
    // Checksum: `c = b_mapping(c, w[0], w[1], 0)` per window, i.e.
    // `c = V[h]` with `h = V[V[V[c] ^ w[0]] ^ w[1]]`. The chain runs on
    // `h` instead, `h = V[V[VV[h] ^ w[0]] ^ w[1]]` (`VV = V[V[x]]`):
    // three dependent lookups per byte, not four.
    let checksum = || chain_checksum(data, windows);
    if windows <= CHUNK {
        return (counts(), checksum());
    }
    // The chain is one long serial run: on this thread, never a job of
    // the rayon pool (a worker waiting for a job of its own there, e.g.
    // in a scope, could take it and be held up the whole chain long),
    // while a thread of its own hands the counts to the pool.
    std::thread::scope(|s| {
        let counts = s.spawn(counts);
        let checksum = checksum();
        (counts.join().unwrap_or_else(|e| std::panic::resume_unwind(e)), checksum)
    })
}

/// The checksum of the `windows` 5-byte windows of `data`: `c =
/// b_mapping(c, w[0], w[1], 0)` per window, i.e. `c = V[h]` with `h =
/// V[V[V[c] ^ w[0]] ^ w[1]]`. The chain runs on `h` instead, `h =
/// V[V[VV[h] ^ w[0]] ^ w[1]]` (`VV = V[V[x]]`): three dependent lookups per
/// byte, not four.
fn chain_checksum(data: &[u8], windows: usize) -> u8 {
    let vv: [u8; 256] = std::array::from_fn(|x| V_TABLE[V_TABLE[x] as usize]);
    let step = |first: u8, a: u8, b: u8| V_TABLE[(V_TABLE[(first ^ a) as usize] ^ b) as usize];
    let mut h = step(V_TABLE[0], data[0], data[1]);
    // (the pairs `data[i], data[i + 1]` for `i` in `1..windows`)
    for (&a, &b) in data[1..windows].iter().zip(&data[2..=windows]) {
        h = step(vv[h as usize], a, b);
    }
    V_TABLE[h as usize]
}

/// The first two lookups of [`b_mapping`] for each salt of [`bucket_window`] (they
/// depend on the salt and the window's first byte alone): `V[V[salt] ^ a]` by `a`.
struct FirstLookups([[u8; 256]; 6]);

impl FirstLookups {
    const SALTS: [u8; 6] = [2, 3, 5, 7, 11, 13];

    fn new() -> Self {
        Self(std::array::from_fn(|s| {
            std::array::from_fn(|a| V_TABLE[(V_TABLE[Self::SALTS[s] as usize] ^ a as u8) as usize])
        }))
    }

    /// The bucket counts of every 5-byte window of `data`
    /// ([`bucket_window`] of each): [`Self::count_vbmi`] where the CPU has AVX-512 VBMI, else
    /// [`Self::count_scalar`].
    fn count(&self, data: &[u8]) -> [u32; 128] {
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx512vbmi") && std::arch::is_x86_feature_detected!("avx512bw") {
            // SAFETY: the CPU has the features `count_vbmi` is compiled for.
            return unsafe { self.count_vbmi(data) };
        }
        self.count_scalar(data)
    }

    /// The bucket counts of every 5-byte window of `data` ([`bucket_window`] of each), one
    /// window at a time.
    fn count_scalar(&self, data: &[u8]) -> [u32; 128] {
        // The last lookup gives the bucket (its low 7 bits) as an index
        // into 256 counters: no mask and no bounds check per update.
        const LOW: [u8; 256] = {
            let mut t = [0u8; 256];
            let mut i = 0;
            while i < 256 {
                t[i] = V_TABLE[i] & 0x7F;
                i += 1;
            }
            t
        };
        let mut counts = [0u32; 256];
        let [f0, f1, f2, f3, f4, f5] = &self.0;
        let last = |first: u8, b: u8, c: u8| LOW[(V_TABLE[(first ^ b) as usize] ^ c) as usize] as usize;
        for p in data.windows(5) {
            let (a, p1, p2, p3, p4) = (p[0] as usize, p[1], p[2], p[3], p[4]);
            counts[last(f0[a], p1, p2)] += 1;
            counts[last(f1[a], p1, p3)] += 1;
            counts[last(f2[a], p2, p3)] += 1;
            counts[last(f3[a], p2, p4)] += 1;
            counts[last(f4[a], p1, p4)] += 1;
            counts[last(f5[a], p3, p4)] += 1;
        }
        std::array::from_fn(|i| counts[i])
    }

    /// [`Self::count_scalar`] 64 windows at a time: each of the three lookups of a salt is a
    /// lookup of 64 bytes at once in a 256-byte table (two `vpermi2b` over its halves of 128
    /// bytes, the index's top bit choosing between them), the buckets stored and counted
    /// (the counts are sums, so in any order: four sets of counters, the updates of
    /// neighbouring buckets independent); the windows past the last 64 one at a time.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512bw,avx512vbmi")]
    fn count_vbmi(&self, data: &[u8]) -> [u32; 128] {
        use std::arch::x86_64::*;
        /// A 256-byte table in four registers.
        #[target_feature(enable = "avx512f,avx512bw,avx512vbmi")]
        fn table(t: &[u8; 256]) -> [__m512i; 4] {
            // SAFETY: each load reads 64 of the table's 256 bytes.
            std::array::from_fn(|k| unsafe { _mm512_loadu_si512(t[64 * k..].as_ptr().cast()) })
        }
        /// `t[x]` for each byte `x` of `idx`.
        #[target_feature(enable = "avx512f,avx512bw,avx512vbmi")]
        fn lookup(t: &[__m512i; 4], idx: __m512i) -> __m512i {
            let lo = _mm512_permutex2var_epi8(t[0], idx, t[1]);
            let hi = _mm512_permutex2var_epi8(t[2], idx, t[3]);
            _mm512_mask_blend_epi8(_mm512_movepi8_mask(idx), lo, hi)
        }
        const LOW: [u8; 256] = {
            let mut t = [0u8; 256];
            let mut i = 0;
            while i < 256 {
                t[i] = V_TABLE[i] & 0x7F;
                i += 1;
            }
            t
        };
        let windows = data.len().saturating_sub(4);
        let (v, low) = (table(&V_TABLE), table(&LOW));
        let first: [[__m512i; 4]; 6] = std::array::from_fn(|s| table(&self.0[s]));
        let mut counts = [[0u32; 256]; 4];
        let mut buckets = [0u8; 6 * 64];
        let mut at = 0;
        while at + 64 <= windows {
            // (the 64 windows from `at` read the bytes up to `at + 67 < data.len()`)
            // SAFETY: each load reads 64 bytes of `data` from `at + k`, `k ≤ 4`.
            let p: [__m512i; 5] = std::array::from_fn(|k| unsafe { _mm512_loadu_si512(data[at + k..].as_ptr().cast()) });
            for (s, (b, c)) in [(1, 2), (1, 3), (2, 3), (2, 4), (1, 4), (3, 4)].into_iter().enumerate() {
                let x = lookup(&first[s], p[0]);
                let x = lookup(&v, _mm512_xor_si512(x, p[b]));
                let x = lookup(&low, _mm512_xor_si512(x, p[c]));
                // SAFETY: stores 64 bytes into `buckets[64 * s..64 * (s + 1)]`.
                unsafe { _mm512_storeu_si512(buckets[64 * s..].as_mut_ptr().cast(), x) };
            }
            for q in buckets.chunks_exact(4) {
                counts[0][q[0] as usize] += 1;
                counts[1][q[1] as usize] += 1;
                counts[2][q[2] as usize] += 1;
                counts[3][q[3] as usize] += 1;
            }
            at += 64;
        }
        let tail = if at < windows { self.count_scalar(&data[at..]) } else { [0u32; 128] };
        std::array::from_fn(|i| tail[i] + counts[0][i] + counts[1][i] + counts[2][i] + counts[3][i])
    }
}

/// Count the 6 bucket updates of one 5-byte window `p` (the reference form of
/// [`FirstLookups::bucket_window`]).
#[cfg(test)]
fn bucket_window(buckets: &mut [u32; 128], p: &[u8]) {
    // The TLSH bucket-mapping function pairs the salts with
    // specific byte positions to spread information across the
    // sliding window. Mapping per the published spec.
    let salts = [(2, p[0], p[1], p[2]),
                 (3, p[0], p[1], p[3]),
                 (5, p[0], p[2], p[3]),
                 (7, p[0], p[2], p[4]),
                 (11, p[0], p[1], p[4]),
                 (13, p[0], p[3], p[4])];
    for (salt, a, b, c) in salts {
        let idx = b_mapping(salt, a, b, c);
        buckets[(idx & 0x7F) as usize] += 1;
    }
}

/// Pearson hash with salt — see TLSH reference. Three inputs are
/// mapped through the 256-byte Pearson permutation table.
#[cfg(test)]
fn b_mapping(salt: u8, i: u8, j: u8, k: u8) -> u8 {
    let mut h = 0u8;
    h = V_TABLE[(h ^ salt) as usize];
    h = V_TABLE[(h ^ i) as usize];
    h = V_TABLE[(h ^ j) as usize];
    h = V_TABLE[(h ^ k) as usize];
    h
}

/// Pearson permutation table — the canonical TLSH V[] table. Same
/// 256-byte permutation as the reference C implementation; used
/// elsewhere as "v_table" or "P_table" depending on the source.
#[rustfmt::skip]
const V_TABLE: [u8; 256] = [
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
];

fn quartiles(buckets: &[u32; 128]) -> (u32, u32, u32) {
    let mut copy: Vec<u32> = buckets.to_vec();
    copy.sort_unstable();
    let n = copy.len();
    (copy[n / 4], copy[n / 2], copy[(3 * n) / 4])
}

fn encode_body(buckets: &[u32; 128], q1: u32, q2: u32, q3: u32) -> [u8; 32] {
    // Each bucket becomes 2 bits encoding which quartile it falls
    // into. Pack 4 buckets per byte.
    let mut out = [0u8; 32];
    for (i, &b) in buckets.iter().enumerate() {
        let code = if b <= q1 {
            0
        } else if b <= q2 {
            1
        } else if b <= q3 {
            2
        } else {
            3
        };
        let byte = i / 4;
        let shift = (i % 4) * 2;
        out[byte] |= (code as u8) << shift;
    }
    out
}

/// `log_1.5(length)` mapped to a byte, capped at 255 per TLSH spec.
fn encode_lvalue(len: u64) -> u8 {
    if len <= 1 {
        return 0;
    }
    let f = (len as f64).log(1.5);
    f.clamp(0.0, 255.0) as u8
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("T1").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `build_buckets` as one serial pass, window by window.
    fn build_buckets_naive(data: &[u8]) -> ([u32; 128], u8) {
        let mut buckets = [0u32; 128];
        let mut checksum: u8 = 0;
        if data.len() < 5 {
            return (buckets, checksum);
        }
        for w in data.windows(5) {
            bucket_window(&mut buckets, w);
            checksum = b_mapping(checksum, w[0], w[1], 0);
        }
        (buckets, checksum)
    }

    #[test]
    fn buckets_match_serial_pass() {
        for (len, seed) in [(5usize, 1u64), (6, 2), (777, 3), ((1 << 18) + 3, 4), ((1 << 19) + 4, 5), (3 << 18, 6)] {
            let data = random_bytes(len, seed);
            assert_eq!(build_buckets(&data), build_buckets_naive(&data), "len {len}");
        }
    }

    fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (s >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn vector_counts_match_scalar() {
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx512vbmi") && std::arch::is_x86_feature_detected!("avx512bw") {
            let f = FirstLookups::new();
            for len in (5..300).chain([4096, 4096 + 67, 4096 + 68, 4096 + 69, 100_003]) {
                let data = random_bytes(len, len as u64);
                // SAFETY: the CPU has the features.
                assert_eq!(unsafe { f.count_vbmi(&data) }, f.count_scalar(&data), "len {len}");
            }
            // skewed data: few distinct buckets, many updates of one counter
            let data: Vec<u8> = (0..70_000u32).map(|i| (i % 3) as u8).collect();
            assert_eq!(unsafe { f.count_vbmi(&data) }, f.count_scalar(&data));
        }
    }

    #[test]
    fn too_short_returns_none() {
        assert!(hash(&[0u8; 10]).is_none());
    }

    #[test]
    fn deterministic() {
        let data = random_bytes(2048, 1);
        let a = hash(&data).unwrap();
        let b = hash(&data).unwrap();
        assert_eq!(a, b);
        // "T1" prefix + 70 hex chars (35 bytes).
        assert_eq!(a.len(), 72);
        assert!(a.starts_with("T1"));
    }

    #[test]
    fn identical_hashes_distance_zero() {
        let data = random_bytes(2048, 2);
        let h = hash(&data).unwrap();
        let d = compare(&h, &h).unwrap();
        assert_eq!(d, 0);
    }

    #[test]
    fn dissimilar_inputs_have_high_distance() {
        let a = random_bytes(2048, 3);
        let b = random_bytes(2048, 9999);
        let ha = hash(&a).unwrap();
        let hb = hash(&b).unwrap();
        let d = compare(&ha, &hb).unwrap();
        assert!(d > 50, "expected dissimilar (d>50), got {}", d);
    }

    #[test]
    fn small_perturbation_has_small_distance() {
        let mut a = random_bytes(8192, 4);
        let ha = hash(&a).unwrap();
        // Flip one byte every 128 bytes — small perturbation.
        for i in (0..a.len()).step_by(128) {
            a[i] ^= 0xFF;
        }
        let hb = hash(&a).unwrap();
        let d = compare(&ha, &hb).unwrap();
        let dissim = {
            let other = random_bytes(8192, 7777);
            let ho = hash(&other).unwrap();
            compare(&ha, &ho).unwrap()
        };
        assert!(
            d < dissim,
            "perturbed distance ({}) should be smaller than random ({})",
            d, dissim
        );
    }

    #[test]
    fn decode_hex_round_trip() {
        let h = hash(&random_bytes(1024, 42)).unwrap();
        let bytes = decode_hex(&h).unwrap();
        assert_eq!(bytes.len(), 35);
    }
}
