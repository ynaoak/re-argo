//! Persistent on-disk cache of the analysis pipeline's results.
//!
//! Every command that needs the analysed program runs the whole
//! analyzer pipeline (seconds on a large binary, minutes on a huge one).
//! The results are stored here after the first run, so the second and
//! later commands on the same, unchanged binary only load the binary
//! (cheap) and read the results back.
//!
//! * **Location**: `$REARGO_CACHE_DIR`, else `$XDG_CACHE_HOME/re-argo`,
//!   else `$HOME/.cache/re-argo`; never next to the binary. One file per
//!   analysed binary path (`<hash of the canonical path>.rac`), replaced
//!   when the key no longer matches.
//! * **Key**: a BLAKE3 hash over [`CACHE_FORMAT`], the crate version, the
//!   bytes of the running `re-argo` executable (any rebuild changes it),
//!   the binary's canonical path and its full contents, and the file the
//!   PE header analyzers read relative to the working directory
//!   (`./<file name>`: absent, the binary itself, or another file's
//!   contents). The key is stored in the file and compared on load.
//!   The `<binary>.gra.json` override sidecar's contents are in the key
//!   too (absent / its bytes): editing it (`annotate`, `iterate --apply`)
//!   re-runs the pipeline once. The cache holds the results *before* the
//!   overrides; they are applied after loading, every run, as after a
//!   fresh analysis.
//! * **Pre-key** (Unix): hashing the executable and the binary costs tens
//!   of milliseconds, so the file also stores a second key built the same
//!   way from each of those files' `stat` (device, inode, size, mtime and
//!   ctime, to the nanosecond) instead of its bytes; the sidecar's bytes
//!   are read either way. A load whose pre-key matches skips the content
//!   hashing. The pre-key is only stored for files whose stat did not
//!   change while they were hashed and whose times are at least
//!   [`RACY`] older than the hashing: any later write to such a file
//!   gives it a newer ctime (which no user can set back), so an equal
//!   stat means equal bytes. Otherwise (or when the pre-key differs, e.g.
//!   after a `touch`) the full key decides, and a matching full key
//!   stores the then-current pre-key in the file's header.
//! * **Flags**: no command-line flag reaches the pipeline. `--thumb`
//!   only selects the lifters of `disasm` / `pcode` / `decompile` / …,
//!   which run after the analysis and are not cached.
//! * **Off switch**: the global `--no-cache` flag or `REARGO_NO_CACHE=1`.
//! * **Layout**: the results are split into sections — the large maps
//!   (instructions, functions, symbols, references, comments, tags) in
//!   chunks of [`CHUNK`] entries, the rest in one — each its own bincode
//!   payload in its own zstd frame ([`ZSTD_LEVEL`], with zstd's content
//!   checksum), so the sections are encoded, compressed, read,
//!   decompressed and decoded in parallel, and the maps are rebuilt from
//!   their sorted entries in one pass.
//! * **Eviction**: after a write the directory is trimmed to
//!   `$REARGO_CACHE_MAX_BYTES` (default [`DEFAULT_MAX_BYTES`], `0` =
//!   unlimited) by deleting the least recently used `.rac` files (mtime,
//!   refreshed on every hit), never the one just written.
//! * **Integrity**: a header (magic, format, key, pre-key, the section
//!   table, BLAKE3 of the header without the pre-key) is checked before
//!   anything is decoded, the file's length must be the header's plus the
//!   sections', each section must decompress (checksum included) to its
//!   recorded length and decode exactly; a file that does not pass is
//!   ignored and rewritten. Files are written to a temporary name and
//!   renamed into place, so a reader never sees a partial file (only the
//!   pre-key is ever rewritten in place; a torn pre-key just does not
//!   match). A failure to read or write the cache never fails the command
//!   (a write failure is a warning on stderr).

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use bincode::Options;
use rayon::prelude::*;
use reargo_program::comments::{CommentManager, CommentType};
use reargo_program::metadata::ProgramMetadata;
use reargo_program::program::AnalysisState;
use reargo_program::{Function, Listing, Program, Reference, ReferenceManager, Symbol, SymbolTable, Tag, TagManager};
use serde::{Deserialize, Serialize};

/// Bump whenever the stored layout changes in a way the executable hash
/// would not catch on its own (it always changes with the code, so this
/// is a belt-and-braces version tag).
pub const CACHE_FORMAT: u32 = 3;

/// zstd level of the stored sections.
pub const ZSTD_LEVEL: i32 = 1;

/// Default cap on the cache directory's total size (2 GiB).
pub const DEFAULT_MAX_BYTES: u64 = 2 << 30;

/// Entries per section of a chunked map.
pub const CHUNK: usize = 16384;

/// How much older than the content hashing a file's mtime / ctime must
/// be for its stat to stand for its bytes (covers coarse filesystem
/// timestamps, down to FAT's 2 s).
pub const RACY: Duration = Duration::from_secs(3);

const EXT: &str = "rac";

const MAGIC: &[u8; 16] = b"REARGO-ANACACHE\0";
// Header layout: magic | format u32 | key [32] | pre-key [32] |
// section count u32 | per section (kind u32, raw length u64, stored
// length u64) | BLAKE3 of all of it but the pre-key.
const KEY_AT: usize = 20;
const PREKEY_AT: usize = 52;
const COUNT_AT: usize = 84;
const TABLE_AT: usize = 88;
const TABLE_ENTRY: usize = 4 + 8 + 8;
const MAX_SECTIONS: usize = 1 << 20;
/// No section decompresses to more than this (a sanity bound on the
/// allocation a damaged table could ask for).
const MAX_RAW: u64 = 1 << 34;

fn header_len(sections: usize) -> usize {
    TABLE_AT + sections * TABLE_ENTRY + 32
}

/// Section kinds.
const K_INSNS: u32 = 0;
const K_FUNCS: u32 = 1;
const K_SYM_ADDR: u32 = 2;
const K_SYM_NAME: u32 = 3;
const K_REFS_FROM: u32 = 4;
const K_REFS_TO: u32 = 5;
const K_COMMENTS: u32 = 6;
const K_TAGS_ADDR: u32 = 7;
const K_MISC: u32 = 8;

/// The payload encoding: bincode with variable-length integers (most
/// addresses and counts are small, so this roughly halves the file
/// compared with fixed-width integers).
fn codec() -> impl bincode::Options {
    bincode::DefaultOptions::new().with_varint_encoding().with_little_endian()
}

static DISABLED_BY_FLAG: AtomicBool = AtomicBool::new(false);

/// `--no-cache`: bypass the cache (neither read nor written) for this run.
pub fn disable() {
    DISABLED_BY_FLAG.store(true, Ordering::Relaxed);
}

fn enabled() -> bool {
    if DISABLED_BY_FLAG.load(Ordering::Relaxed) {
        return false;
    }
    !matches!(std::env::var("REARGO_NO_CACHE"), Ok(v) if !v.is_empty() && v != "0")
}

/// The cache directory, or `None` when no location can be derived.
pub fn cache_dir() -> Option<PathBuf> {
    let non_empty = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(d) = non_empty("REARGO_CACHE_DIR") {
        return Some(d);
    }
    if let Some(d) = non_empty("XDG_CACHE_HOME") {
        return Some(d.join("re-argo"));
    }
    non_empty("HOME").map(|h| h.join(".cache").join("re-argo"))
}

/// A file's identity and times (`stat`), standing for its bytes in the
/// pre-key.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    raw: [u8; 56],
    /// The later of mtime and ctime, in nanoseconds since the epoch.
    newest_ns: i128,
}

#[cfg(unix)]
fn stamp(path: &Path) -> std::io::Result<Stamp> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path)?;
    let fields = [
        m.dev(),
        m.ino(),
        m.size(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ];
    let mut raw = [0u8; 56];
    for (i, v) in fields.iter().enumerate() {
        raw[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    let ns = |s: i64, n: i64| s as i128 * 1_000_000_000 + n as i128;
    let newest_ns = ns(m.mtime(), m.mtime_nsec()).max(ns(m.ctime(), m.ctime_nsec()));
    Ok(Stamp { raw, newest_ns })
}

/// No pre-key where ctime is not the inode change time.
#[cfg(not(unix))]
fn stamp(_path: &Path) -> std::io::Result<Stamp> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// The pre-key and the stamps it was built from.
struct PreKey {
    key: [u8; 32],
    stamps: Vec<(PathBuf, Stamp)>,
}

/// The full key, and whether the pre-key computed before it stands for
/// the same bytes (see the module documentation).
struct FullKey {
    key: [u8; 32],
    pre_trusted: bool,
}

/// Where the results for one binary live, and the keys they must carry.
pub struct Entry {
    file: PathBuf,
    path: PathBuf,
    canonical: PathBuf,
    exe: PathBuf,
    pre: Option<PreKey>,
    full: OnceLock<Option<FullKey>>,
}

impl Entry {
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// The full key (hashing the files' bytes), computed once; `None`
    /// (with a warning) when it cannot be.
    fn full_key(&self) -> Option<&FullKey> {
        self.full
            .get_or_init(|| {
                let start = SystemTime::now();
                let mut files = Vec::new();
                let mut h = blake3::Hasher::new();
                field(&mut h, "kind", b"content");
                let r = derive_key(&self.path, &self.canonical, &self.exe, &mut h, &mut |h, p| {
                    hash_file(h, p)?;
                    files.push(p.to_path_buf());
                    Ok(())
                });
                match r {
                    Ok(()) => {
                        let pre_trusted = self.pre.as_ref().is_some_and(|pre| pre_trusted(pre, &files, start));
                        Some(FullKey { key: *h.finalize().as_bytes(), pre_trusted })
                    }
                    Err(e) => {
                        eprintln!("[cache] WARNING: not using the analysis cache: {e}");
                        None
                    }
                }
            })
            .as_ref()
    }
}

/// Whether `pre` stands for the bytes hashed from `files` starting at
/// `start`: the same files, each with the same stat now, and times older
/// than `start` by [`RACY`].
fn pre_trusted(pre: &PreKey, files: &[PathBuf], start: SystemTime) -> bool {
    let Ok(start) = start.duration_since(SystemTime::UNIX_EPOCH) else {
        return false;
    };
    let limit = start.saturating_sub(RACY).as_nanos() as i128;
    pre.stamps.len() == files.len()
        && pre.stamps.iter().zip(files).all(|((p, s), f)| {
            p == f && s.newest_ns < limit && stamp(p).is_ok_and(|now| now == *s)
        })
}

/// The cache entry for `path`, or `None` when the cache is off or the
/// entry cannot be located (the command then runs uncached).
pub fn entry_for(path: &Path) -> Option<Entry> {
    if !enabled() {
        return None;
    }
    let dir = cache_dir()?;
    let located = std::fs::canonicalize(path).and_then(|c| Ok((c, std::env::current_exe()?)));
    match located {
        Ok((canonical, exe)) => {
            let name = blake3::hash(canonical.as_os_str().as_encoded_bytes());
            let file = dir.join(format!("{}.{EXT}", &name.to_hex()[..32]));
            let pre = pre_key(path, &canonical, &exe);
            Some(Entry { file, path: path.to_path_buf(), canonical, exe, pre, full: OnceLock::new() })
        }
        Err(e) => {
            eprintln!("[cache] WARNING: not using the analysis cache: {e}");
            None
        }
    }
}

fn pre_key(path: &Path, canonical: &Path, exe: &Path) -> Option<PreKey> {
    let mut stamps = Vec::new();
    let mut h = blake3::Hasher::new();
    field(&mut h, "kind", b"stamp");
    derive_key(path, canonical, exe, &mut h, &mut |h, p| {
        let s = stamp(p)?;
        h.update(&s.raw);
        stamps.push((p.to_path_buf(), s));
        Ok(())
    })
    .ok()?;
    Some(PreKey { key: *h.finalize().as_bytes(), stamps })
}

/// A file's length and bytes, into the key.
fn hash_file(hasher: &mut blake3::Hasher, path: &Path) -> std::io::Result<()> {
    let len = std::fs::metadata(path)?.len();
    let data = std::fs::read(path)?;
    // A file that changed size while it was read is no stable input.
    if data.len() as u64 != len {
        return Err(std::io::Error::other("file changed while it was hashed"));
    }
    hasher.update(&len.to_le_bytes());
    if data.len() >= 1 << 20 {
        hasher.update_rayon(&data);
    } else {
        hasher.update(&data);
    }
    Ok(())
}

fn field(hasher: &mut blake3::Hasher, tag: &str, bytes: &[u8]) {
    hasher.update(tag.as_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Hash every input of the analysis into `h`: `file` adds a file (its
/// bytes for the key, its stat for the pre-key).
fn derive_key(
    path: &Path,
    canonical: &Path,
    exe: &Path,
    h: &mut blake3::Hasher,
    file: &mut dyn FnMut(&mut blake3::Hasher, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    field(h, "format", &CACHE_FORMAT.to_le_bytes());
    field(h, "version", env!("CARGO_PKG_VERSION").as_bytes());

    // The build: the running executable, so a rebuild with any change to
    // an analyzer never reads results of the old code.
    h.update(b"exe");
    file(h, exe)?;

    field(h, "path", canonical.as_os_str().as_encoded_bytes());
    h.update(b"binary");
    file(h, canonical)?;

    // The PE Rich-header and Authenticode analyzers read the file named
    // like the binary relative to the working directory
    // (`Program::name`), so that file is an input too.
    if let Some(name) = path.file_name() {
        let local = Path::new(name);
        match std::fs::canonicalize(local) {
            Ok(c) if c == canonical => field(h, "cwd-name", b"same"),
            Ok(c) => {
                h.update(b"cwd-name:other");
                file(h, &c)?;
            }
            Err(_) => field(h, "cwd-name", b"absent"),
        }
    }

    // The user-override sidecar. No analyzer reads it today (it is
    // applied after the pipeline, also after a cache load), but keying on
    // it means no future change can ever pair stale results with an
    // edited sidecar.
    match std::fs::read(reargo_program::OverrideSet::sidecar_path(canonical)) {
        Ok(bytes) => field(h, "sidecar", &bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => field(h, "sidecar", b"\0absent"),
        Err(e) => return Err(e),
    }
    if canonical != path {
        match std::fs::read(reargo_program::OverrideSet::sidecar_path(path)) {
            Ok(bytes) => field(h, "sidecar-arg", &bytes),
            Err(_) => field(h, "sidecar-arg", b"\0absent"),
        }
    }
    Ok(())
}

/// One stored section: what it holds, its decoded length, and where its
/// zstd frame is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Section {
    kind: u32,
    raw_len: u64,
    offset: u64,
    stored_len: u64,
}

/// A checked header.
#[derive(Debug, PartialEq, Eq)]
struct Header {
    key: [u8; 32],
    prekey: [u8; 32],
    sections: Vec<Section>,
}

/// BLAKE3 of a header's bytes but the pre-key (rewritten in place).
fn header_hash(head: &[u8]) -> blake3::Hash {
    let mut h = blake3::Hasher::new();
    h.update(&head[..PREKEY_AT]);
    h.update(&head[COUNT_AT..]);
    h.finalize()
}

/// The header of a cache file of `file_len` bytes, read from `r`, when it
/// is intact and describes exactly the rest of the file.
fn read_header(r: &mut impl Read, file_len: u64) -> Option<Header> {
    let mut head = vec![0u8; TABLE_AT];
    r.read_exact(&mut head).ok()?;
    if &head[..16] != MAGIC || u32::from_le_bytes(head[16..20].try_into().ok()?) != CACHE_FORMAT {
        return None;
    }
    let count = u32::from_le_bytes(head[COUNT_AT..TABLE_AT].try_into().ok()?) as usize;
    if count > MAX_SECTIONS || header_len(count) as u64 > file_len {
        return None;
    }
    head.resize(header_len(count), 0);
    r.read_exact(&mut head[TABLE_AT..]).ok()?;
    let (body, hash) = head.split_at(header_len(count) - 32);
    if header_hash(body).as_bytes() != hash {
        return None;
    }
    let mut offset = header_len(count) as u64;
    let mut sections = Vec::with_capacity(count);
    for e in body[TABLE_AT..].chunks_exact(TABLE_ENTRY) {
        let kind = u32::from_le_bytes(e[..4].try_into().ok()?);
        let raw_len = u64::from_le_bytes(e[4..12].try_into().ok()?);
        let stored_len = u64::from_le_bytes(e[12..20].try_into().ok()?);
        if raw_len > MAX_RAW || stored_len > file_len {
            return None;
        }
        sections.push(Section { kind, raw_len, offset, stored_len });
        offset = offset.checked_add(stored_len)?;
    }
    if offset != file_len {
        return None;
    }
    Some(Header {
        key: head[KEY_AT..PREKEY_AT].try_into().ok()?,
        prekey: head[PREKEY_AT..COUNT_AT].try_into().ok()?,
        sections,
    })
}

/// Read `buf.len()` bytes at `offset` (positioned: the sections are read
/// from several threads at once).
#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        match std::os::windows::fs::FileExt::seek_read(file, buf, offset) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_at(_file: &File, _buf: &mut [u8], _offset: u64) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// The analysis results outside the large maps (one section).
#[derive(Serialize)]
struct MiscRef<'a> {
    metadata: &'a ProgramMetadata,
    call_renderings: &'a BTreeMap<u64, String>,
    jumps: &'a [Reference],
    tags_by_function: &'a BTreeMap<u64, Vec<Tag>>,
}

#[derive(Deserialize)]
struct Misc {
    metadata: ProgramMetadata,
    call_renderings: BTreeMap<u64, String>,
    jumps: Vec<Reference>,
    tags_by_function: BTreeMap<u64, Vec<Tag>>,
}

/// The hand-rolled encoding of the two largest maps — the instructions
/// and the references, a few hundred thousand entries each — which
/// decodes several times faster than through serde: addresses as
/// zigzag-varint deltas (an instruction from the end of the one before,
/// a reference's ends from its map key), enums as one byte.
mod packed {
    use reargo_arch::{DecodedInstruction, FlowType};
    use reargo_program::reference::RefList;
    use reargo_program::{RefType, Reference};

    pub struct Writer(pub Vec<u8>);

    impl Writer {
        fn u8(&mut self, v: u8) {
            self.0.push(v);
        }
        fn varint(&mut self, mut v: u64) {
            while v >= 0x80 {
                self.0.push(v as u8 | 0x80);
                v >>= 7;
            }
            self.0.push(v as u8);
        }
        /// `v - base`, zigzag-encoded (wrapping: any two u64 round-trip).
        fn delta(&mut self, v: u64, base: u64) {
            let d = v.wrapping_sub(base) as i64;
            self.varint(((d << 1) ^ (d >> 63)) as u64);
        }
        fn bytes(&mut self, b: &[u8]) {
            self.varint(b.len() as u64);
            self.0.extend_from_slice(b);
        }
    }

    pub struct Reader<'a> {
        b: &'a [u8],
    }

    impl<'a> Reader<'a> {
        pub fn new(b: &'a [u8]) -> Self {
            Self { b }
        }
        pub fn at_end(&self) -> bool {
            self.b.is_empty()
        }
        fn u8(&mut self) -> Option<u8> {
            let (&v, rest) = self.b.split_first()?;
            self.b = rest;
            Some(v)
        }
        fn varint(&mut self) -> Option<u64> {
            let mut v = 0u64;
            for shift in (0..64).step_by(7) {
                let byte = self.u8()?;
                v |= u64::from(byte & 0x7f) << shift;
                if byte < 0x80 {
                    return Some(v);
                }
            }
            None
        }
        fn delta(&mut self, base: u64) -> Option<u64> {
            let z = self.varint()?;
            let d = ((z >> 1) as i64) ^ -((z & 1) as i64);
            Some(base.wrapping_add(d as u64))
        }
        fn bytes(&mut self) -> Option<&'a [u8]> {
            let n = usize::try_from(self.varint()?).ok()?;
            if n > self.b.len() {
                return None;
            }
            let (v, rest) = self.b.split_at(n);
            self.b = rest;
            Some(v)
        }
        fn string(&mut self) -> Option<String> {
            Some(std::str::from_utf8(self.bytes()?).ok()?.to_owned())
        }
        /// A count of entries of at least `min_size` bytes each (bounds
        /// the allocation a damaged count could ask for).
        fn count(&mut self, min_size: usize) -> Option<usize> {
            let n = usize::try_from(self.varint()?).ok()?;
            (n.checked_mul(min_size)? <= self.b.len()).then_some(n)
        }
    }

    const FLOWS: [FlowType; 7] = [
        FlowType::Fall,
        FlowType::UnconditionalJump,
        FlowType::ConditionalJump,
        FlowType::Call,
        FlowType::IndirectCall,
        FlowType::IndirectJump,
        FlowType::Return,
    ];

    const REF_TYPES: [RefType; 10] = [
        RefType::UnconditionalCall,
        RefType::ConditionalCall,
        RefType::IndirectCall,
        RefType::UnconditionalJump,
        RefType::ConditionalJump,
        RefType::IndirectJump,
        RefType::DataRead,
        RefType::DataWrite,
        RefType::DataReadWrite,
        RefType::FallThrough,
    ];

    fn flow_code(f: FlowType) -> u8 {
        match f {
            FlowType::Fall => 0,
            FlowType::UnconditionalJump => 1,
            FlowType::ConditionalJump => 2,
            FlowType::Call => 3,
            FlowType::IndirectCall => 4,
            FlowType::IndirectJump => 5,
            FlowType::Return => 6,
        }
    }

    fn ref_code(t: RefType) -> u8 {
        match t {
            RefType::UnconditionalCall => 0,
            RefType::ConditionalCall => 1,
            RefType::IndirectCall => 2,
            RefType::UnconditionalJump => 3,
            RefType::ConditionalJump => 4,
            RefType::IndirectJump => 5,
            RefType::DataRead => 6,
            RefType::DataWrite => 7,
            RefType::DataReadWrite => 8,
            RefType::FallThrough => 9,
        }
    }

    /// Instructions, in address order.
    pub fn encode_insns(insns: &[(&u64, &Box<DecodedInstruction>)]) -> Vec<u8> {
        let mut w = Writer(Vec::with_capacity(insns.len() * 10));
        w.varint(insns.len() as u64);
        let mut prev_end = 0u64;
        for &(&addr, insn) in insns {
            // The key is the instruction's address (`Listing`), but the
            // two are stored apart all the same.
            w.delta(addr, prev_end);
            w.delta(insn.address, addr);
            w.varint(u64::from(insn.length));
            w.bytes(&insn.bytes);
            w.u8(flow_code(insn.flow_type));
            match insn.branch_target {
                None => w.u8(0),
                Some(t) => {
                    w.u8(1);
                    w.delta(t, insn.address);
                }
            }
            let (lazy, text) = insn.cache_text();
            w.u8(lazy);
            if let Some((mnemonic, operands)) = text {
                w.u8(1);
                w.bytes(mnemonic.as_bytes());
                w.bytes(operands.as_bytes());
            } else {
                w.u8(0);
            }
            prev_end = insn.address.wrapping_add(u64::from(insn.length));
        }
        w.0
    }

    pub fn decode_insns(raw: &[u8]) -> Option<Vec<(u64, Box<DecodedInstruction>)>> {
        let mut r = Reader::new(raw);
        let n = r.count(8)?;
        let mut out = Vec::with_capacity(n);
        let mut prev_end = 0u64;
        for _ in 0..n {
            let key = r.delta(prev_end)?;
            let address = r.delta(key)?;
            let length = u32::try_from(r.varint()?).ok()?;
            let bytes = smallvec::SmallVec::from_slice(r.bytes()?);
            let flow = *FLOWS.get(usize::from(r.u8()?))?;
            let branch = match r.u8()? {
                0 => None,
                1 => Some(r.delta(address)?),
                _ => return None,
            };
            let lazy = r.u8()?;
            let text = match r.u8()? {
                0 => None,
                1 => Some((r.string()?, r.string()?)),
                _ => return None,
            };
            let insn = DecodedInstruction::from_cache_parts(address, length, bytes, flow, branch, lazy, text);
            out.push((key, Box::new(insn)));
            prev_end = address.wrapping_add(u64::from(length));
        }
        r.at_end().then_some(out)
    }

    /// A references map (from / to), in key order.
    pub fn encode_refs(refs: &[(&u64, &RefList)]) -> Vec<u8> {
        let mut w = Writer(Vec::with_capacity(refs.len() * 8));
        w.varint(refs.len() as u64);
        let mut prev = 0u64;
        for &(&key, list) in refs {
            w.delta(key, prev);
            w.varint(list.len() as u64);
            for r in list.iter() {
                w.delta(r.from, key);
                w.delta(r.to, key);
                w.u8(ref_code(r.ref_type));
            }
            prev = key;
        }
        w.0
    }

    pub fn decode_refs(raw: &[u8]) -> Option<Vec<(u64, RefList)>> {
        let mut r = Reader::new(raw);
        let n = r.count(2)?;
        let mut out = Vec::with_capacity(n);
        let mut prev = 0u64;
        for _ in 0..n {
            let key = r.delta(prev)?;
            let m = r.count(3)?;
            let mut list = RefList::with_capacity(m);
            for _ in 0..m {
                let from = r.delta(key)?;
                let to = r.delta(key)?;
                let ref_type = *REF_TYPES.get(usize::from(r.u8()?))?;
                list.push(Reference { from, to, ref_type });
            }
            out.push((key, list));
            prev = key;
        }
        r.at_end().then_some(out)
    }
}

thread_local! {
    /// Per-thread buffers for a section's stored and decompressed bytes
    /// (reused section after section: fresh ones would fault in tens of
    /// megabytes of new pages per load) and the zstd context.
    static SECTION_BUFS: std::cell::RefCell<(Vec<u8>, Vec<u8>, Option<zstd::bulk::Decompressor<'static>>)> =
        const { std::cell::RefCell::new((Vec::new(), Vec::new(), None)) };
}

/// Read, decompress and decode section `s` of `file` (`None` when it is
/// damaged: unreadable, a zstd error or checksum mismatch, another
/// length than recorded, or bytes `decode` rejects).
fn decode_section<T>(file: &File, s: &Section, decode: impl FnOnce(&[u8]) -> Option<T>) -> Option<T> {
    SECTION_BUFS.with_borrow_mut(|(stored, raw, dctx)| {
        stored.clear();
        stored.resize(usize::try_from(s.stored_len).ok()?, 0);
        read_at(file, stored, s.offset).ok()?;
        let raw_len = usize::try_from(s.raw_len).ok()?;
        raw.clear();
        raw.reserve_exact(raw_len);
        let d = match dctx {
            Some(d) => d,
            None => dctx.insert(zstd::bulk::Decompressor::new().ok()?),
        };
        // The buffer's capacity may exceed `raw_len`; a longer frame
        // is caught by the length check.
        let n = d.decompress_to_buffer(&stored[..], raw).ok()?;
        if n != raw_len || raw.len() != raw_len {
            return None;
        }
        decode(raw)
    })
}

/// Decode one section as a `T` (bincode, every byte consumed).
fn decode_as<T: serde::de::DeserializeOwned>(file: &File, s: &Section) -> Option<T> {
    decode_section(file, s, |raw| codec().deserialize(raw).ok())
}

/// The entries of the sections `of` kind, chunk by chunk (decoded in
/// parallel).
fn decode_chunks<T: serde::de::DeserializeOwned + Send>(file: &File, of: &[Section]) -> Option<Vec<Vec<T>>> {
    of.par_iter().with_max_len(1).map(|s| decode_as::<Vec<T>>(file, s)).collect()
}

/// The map stored in the sections `of` kind (stored in key order, so
/// building it is one linear pass).
fn decode_map<K, V>(file: &File, of: &[Section]) -> Option<BTreeMap<K, V>>
where
    K: Ord + serde::de::DeserializeOwned + Send,
    V: serde::de::DeserializeOwned + Send,
{
    sorted_map(decode_chunks::<(K, V)>(file, of)?)
}

/// As [`decode_map`], for a map in a [`packed`] encoding.
fn decode_packed_map<K: Ord + Send, V: Send>(
    file: &File,
    of: &[Section],
    decode: fn(&[u8]) -> Option<Vec<(K, V)>>,
) -> Option<BTreeMap<K, V>> {
    let chunks: Option<Vec<Vec<(K, V)>>> =
        of.par_iter().with_max_len(1).map(|s| decode_section(file, s, decode)).collect();
    sorted_map(chunks?)
}

fn sorted_map<K: Ord, V>(chunks: Vec<Vec<(K, V)>>) -> Option<BTreeMap<K, V>> {
    let mut all = Vec::with_capacity(chunks.iter().map(Vec::len).sum());
    for c in chunks {
        all.extend(c);
    }
    Some(all.into_iter().collect())
}

/// The analysis state stored in the `sections` of `file`. The maps are
/// independent: each is decoded and built while the others are, and the
/// chunks of one map are decoded in parallel too.
fn decode_state(file: &File, sections: &[Section]) -> Option<AnalysisState> {
    let mut by_kind: Vec<Vec<Section>> = vec![Vec::new(); K_MISC as usize + 1];
    for s in sections {
        by_kind.get_mut(s.kind as usize)?.push(*s);
    }
    let [misc_section] = by_kind[K_MISC as usize][..] else {
        return None;
    };
    let of = |k: u32| &by_kind[k as usize][..];
    let (mut insns, mut funcs, mut refs_from, mut refs_to) = (None, None, None, None);
    let (mut sym_addr, mut sym_name, mut comments, mut tags_addr, mut misc) = (None, None, None, None, None);
    rayon::scope(|sc| {
        sc.spawn(|_| insns = decode_packed_map(file, of(K_INSNS), packed::decode_insns));
        sc.spawn(|_| refs_from = decode_packed_map(file, of(K_REFS_FROM), packed::decode_refs));
        sc.spawn(|_| refs_to = decode_packed_map(file, of(K_REFS_TO), packed::decode_refs));
        sc.spawn(|_| tags_addr = decode_map::<u64, Vec<Tag>>(file, of(K_TAGS_ADDR)));
        sc.spawn(|_| comments = decode_map::<(u64, CommentType), String>(file, of(K_COMMENTS)));
        sc.spawn(|_| funcs = decode_map::<u64, Function>(file, of(K_FUNCS)));
        sc.spawn(|_| sym_addr = decode_map::<u64, Vec<Symbol>>(file, of(K_SYM_ADDR)));
        sc.spawn(|_| {
            sym_name = decode_chunks::<(String, Vec<u64>)>(file, of(K_SYM_NAME))
                .map(|c| c.into_iter().flatten().collect::<HashMap<_, _>>())
        });
        sc.spawn(|_| misc = decode_as::<Misc>(file, &misc_section));
    });
    let misc = misc?;
    Some(AnalysisState {
        listing: Listing::from_cache_parts(insns?, funcs?),
        symbol_table: SymbolTable::from_cache_parts((sym_addr?, sym_name?)),
        references: ReferenceManager::from_cache_parts(refs_from?, refs_to?, misc.jumps),
        comments: CommentManager::from_cache_parts(comments?),
        metadata: misc.metadata,
        call_renderings: misc.call_renderings,
        tags: TagManager::from_cache_parts(tags_addr?, misc.tags_by_function),
    })
}

/// Read the stored results for `entry` into `program` (a fresh
/// `Program::from_binary` of the binary). `false` — and `program`
/// untouched — when there is no valid entry for this key.
pub fn load(entry: &Entry, program: &mut Program) -> bool {
    let Ok(mut file) = File::open(&entry.file) else {
        return false;
    };
    let Some(len) = file.metadata().ok().map(|m| m.len()) else {
        return false;
    };
    let Some(header) = read_header(&mut file, len) else {
        return false;
    };
    let pre_hit = entry.pre.as_ref().is_some_and(|p| p.key == header.prekey);
    if !pre_hit {
        match entry.full_key() {
            Some(full) if full.key == header.key => {
                if full.pre_trusted
                    && let Some(pre) = &entry.pre
                {
                    write_prekey(&entry.file, &pre.key);
                }
            }
            _ => return false,
        }
    }
    let Some(state) = decode_state(&file, &header.sections) else {
        return false;
    };
    program.restore_analysis_state(state);
    touch(&entry.file);
    true
}

/// Store `key` as the pre-key of the cache file `path` (best effort).
fn write_prekey(path: &Path, key: &[u8; 32]) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
        let _ = f.seek(std::io::SeekFrom::Start(PREKEY_AT as u64)).and_then(|_| f.write_all(key));
    }
}

/// Mark `file` as just used (mtime = now) for the LRU eviction. Best
/// effort: a read-only cache simply keeps its old times.
fn touch(file: &Path) {
    if let Ok(f) = std::fs::OpenOptions::new().append(true).open(file) {
        let _ = f.set_modified(SystemTime::now());
    }
}

/// The size cap from `$REARGO_CACHE_MAX_BYTES` (`0` = unlimited).
fn max_bytes() -> u64 {
    match std::env::var("REARGO_CACHE_MAX_BYTES") {
        Ok(v) => v.trim().parse().unwrap_or(DEFAULT_MAX_BYTES),
        Err(_) => DEFAULT_MAX_BYTES,
    }
}

/// Whether `path` is one of our cache files: `.rac` extension and the
/// magic at its start.
fn is_cache_file(path: &Path) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some(EXT) {
        return false;
    }
    let mut magic = [0u8; 16];
    File::open(path).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == MAGIC
}

/// Delete the least recently used cache files in `dir` until their total
/// size is at most `cap` (0 = unlimited), never `keep`. Returns the
/// number of files deleted. Errors are ignored: eviction is best effort.
fn evict(dir: &Path, keep: &Path, cap: u64) -> usize {
    if cap == 0 {
        return 0;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut files = Vec::new();
    let mut total = 0u64;
    for e in rd.flatten() {
        let path = e.path();
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() || path.extension().and_then(|x| x.to_str()) != Some(EXT) {
            continue;
        }
        if path != keep && !is_cache_file(&path) {
            continue;
        }
        total += md.len();
        if path != keep {
            files.push((md.modified().unwrap_or(std::time::UNIX_EPOCH), md.len(), path));
        }
    }
    if total <= cap {
        return 0;
    }
    files.sort();
    let mut removed = 0;
    for (_, len, path) in files {
        if total <= cap {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total -= len;
            removed += 1;
        }
    }
    removed
}

/// An encoder of one section.
type Job<'a> = (u32, Box<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync + 'a>);

fn encode<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>, String> {
    codec().serialize(v).map_err(|e| format!("encode: {e}"))
}

/// One section per [`CHUNK`] entries of `items`.
fn chunk_jobs<'a, T: Serialize + Sync>(jobs: &mut Vec<Job<'a>>, kind: u32, items: &'a [T]) {
    for c in items.chunks(CHUNK) {
        jobs.push((kind, Box::new(move || encode(c))));
    }
}

/// As [`chunk_jobs`], in a [`packed`] encoding.
fn packed_jobs<'a, T: Sync>(jobs: &mut Vec<Job<'a>>, kind: u32, items: &'a [T], encode: fn(&[T]) -> Vec<u8>) {
    for c in items.chunks(CHUNK) {
        jobs.push((kind, Box::new(move || Ok(encode(c)))));
    }
}

fn compress(raw: &[u8]) -> Result<Vec<u8>, String> {
    let err = |e: std::io::Error| format!("compress: {e}");
    let mut c = zstd::bulk::Compressor::new(ZSTD_LEVEL).map_err(err)?;
    c.set_parameter(zstd::zstd_safe::CParameter::ChecksumFlag(true)).map_err(err)?;
    c.compress(raw).map_err(err)
}

/// The cache file's bytes: the header, then each `(kind, raw length,
/// stored bytes)` section.
fn file_header(key: &[u8; 32], prekey: &[u8; 32], sections: &[(u32, u64, Vec<u8>)]) -> Vec<u8> {
    let mut head = Vec::with_capacity(header_len(sections.len()));
    head.extend_from_slice(MAGIC);
    head.extend_from_slice(&CACHE_FORMAT.to_le_bytes());
    head.extend_from_slice(key);
    head.extend_from_slice(prekey);
    head.extend_from_slice(&(sections.len() as u32).to_le_bytes());
    for (kind, raw_len, stored) in sections {
        head.extend_from_slice(&kind.to_le_bytes());
        head.extend_from_slice(&raw_len.to_le_bytes());
        head.extend_from_slice(&(stored.len() as u64).to_le_bytes());
    }
    let hash = header_hash(&head);
    head.extend_from_slice(hash.as_bytes());
    head
}

/// Store `program`'s analysis results (before the override sidecar is
/// applied) for `entry`. Errors are for a warning only.
pub fn store(entry: &Entry, program: &Program) -> Result<(), String> {
    // No key: the warning is out already, and nothing can be stored.
    let Some(full) = entry.full_key() else {
        return Ok(());
    };
    let prekey = match &entry.pre {
        Some(pre) if full.pre_trusted => pre.key,
        _ => [0u8; 32],
    };
    let state = program.analysis_state();
    let (insns, funcs) = state.listing.cache_parts();
    let (sym_addr, sym_name) = state.symbol_table.cache_parts();
    let (refs_from, refs_to, jumps) = state.references.cache_parts();
    let (tags_addr, tags_func) = state.tags.cache_parts();
    let insns: Vec<_> = insns.iter().collect();
    let funcs: Vec<_> = funcs.iter().collect();
    let sym_addr: Vec<_> = sym_addr.iter().collect();
    let sym_name: Vec<_> = sym_name.iter().collect();
    let refs_from: Vec<_> = refs_from.iter().collect();
    let refs_to: Vec<_> = refs_to.iter().collect();
    let comments: Vec<_> = state.comments.cache_parts().iter().collect();
    let tags_addr: Vec<_> = tags_addr.iter().collect();
    let misc = MiscRef {
        metadata: state.metadata,
        call_renderings: state.call_renderings,
        jumps,
        tags_by_function: tags_func,
    };

    let mut jobs: Vec<Job<'_>> = Vec::new();
    packed_jobs(&mut jobs, K_INSNS, &insns, packed::encode_insns);
    chunk_jobs(&mut jobs, K_FUNCS, &funcs);
    chunk_jobs(&mut jobs, K_SYM_ADDR, &sym_addr);
    chunk_jobs(&mut jobs, K_SYM_NAME, &sym_name);
    packed_jobs(&mut jobs, K_REFS_FROM, &refs_from, packed::encode_refs);
    packed_jobs(&mut jobs, K_REFS_TO, &refs_to, packed::encode_refs);
    chunk_jobs(&mut jobs, K_COMMENTS, &comments);
    chunk_jobs(&mut jobs, K_TAGS_ADDR, &tags_addr);
    jobs.push((K_MISC, Box::new(|| encode(&misc))));

    let sections: Vec<(u32, u64, Vec<u8>)> = jobs
        .par_iter()
        .with_max_len(1)
        .map(|(kind, job)| {
            let raw = job()?;
            Ok((*kind, raw.len() as u64, compress(&raw)?))
        })
        .collect::<Result<_, String>>()?;
    let head = file_header(&full.key, &prekey, &sections);

    let dir = entry.file.parent().ok_or("cache path has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = entry.file.with_extension(format!("tmp.{}", std::process::id()));
    let written = File::create(&tmp).and_then(|mut f| {
        f.write_all(&head)?;
        for (_, _, stored) in &sections {
            f.write_all(stored)?;
        }
        Ok(())
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write {}: {e}", tmp.display()));
    }
    std::fs::rename(&tmp, &entry.file).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename to {}: {e}", entry.file.display())
    })?;
    evict(dir, &entry.file, max_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_rejects_damaged_files() {
        let key = [7u8; 32];
        let sections = vec![(K_INSNS, 10u64, vec![1u8; 5]), (K_MISC, 3u64, vec![2u8; 4])];
        let mut f = file_header(&key, &[9u8; 32], &sections);
        let head_len = f.len();
        for (_, _, s) in &sections {
            f.extend_from_slice(s);
        }
        let read = |b: &[u8]| read_header(&mut &b[..], b.len() as u64);
        let h = read(&f).expect("intact header");
        assert_eq!(h.key, key);
        assert_eq!(h.prekey, [9u8; 32]);
        assert_eq!(
            h.sections,
            vec![
                Section { kind: K_INSNS, raw_len: 10, offset: head_len as u64, stored_len: 5 },
                Section { kind: K_MISC, raw_len: 3, offset: head_len as u64 + 5, stored_len: 4 },
            ]
        );
        // The pre-key is rewritten in place: not covered by the hash.
        let mut g = f.clone();
        g[PREKEY_AT..COUNT_AT].copy_from_slice(&[0u8; 32]);
        assert_eq!(read(&g).unwrap().prekey, [0u8; 32]);
        // Truncated, or longer than the sections.
        assert_eq!(read(&f[..f.len() - 1]), None);
        assert_eq!(read(&f[..10]), None);
        let mut g = f.clone();
        g.push(0);
        assert_eq!(read(&g), None);
        // Any flipped header byte but the pre-key's: the key, the format,
        // the table, the hash.
        for at in [0, 16, KEY_AT + 3, COUNT_AT, TABLE_AT + 5, head_len - 1] {
            let mut g = f.clone();
            g[at] ^= 1;
            assert_eq!(read(&g), None, "flipped byte {at}");
        }
    }

    #[test]
    fn sections_round_trip_and_damage_is_caught() {
        let raw = encode(&vec![(1u64, "a".to_string()), (2, "b".to_string())]).unwrap();
        let stored = compress(&raw).unwrap();
        let dir = std::env::temp_dir().join(format!("reargo-sections-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("s.bin");
        let section = Section { kind: K_COMMENTS, raw_len: raw.len() as u64, offset: 0, stored_len: stored.len() as u64 };
        let decode = |bytes: &[u8], s: &Section| {
            std::fs::write(&p, bytes).unwrap();
            decode_as::<Vec<((u64, CommentType), String)>>(&File::open(&p).unwrap(), s)
        };
        // Wrong type for the bytes: not decodable as comments.
        assert!(decode(&stored, &section).is_none());
        let raw = encode(&vec![((1u64, CommentType::Eol), "a".to_string())]).unwrap();
        let stored = compress(&raw).unwrap();
        let section = Section { stored_len: stored.len() as u64, raw_len: raw.len() as u64, ..section };
        assert_eq!(decode(&stored, &section).map(|v| v.len()), Some(1));
        // A flipped stored byte never yields other content (zstd's
        // checksum covers it; a frame-header flag may change nothing), a
        // wrong recorded length is rejected.
        let want = decode(&stored, &section);
        let mut rejected = 0;
        for at in 0..stored.len() {
            for bit in [0x01, 0x20, 0x80] {
                let mut b = stored.clone();
                b[at] ^= bit;
                match decode(&b, &section) {
                    None => rejected += 1,
                    got => assert_eq!(got, want, "flipped byte {at}"),
                }
            }
        }
        assert!(rejected > stored.len() * 2, "most flips are caught: {rejected}");
        for raw_len in [section.raw_len - 1, section.raw_len + 1] {
            assert!(decode(&stored, &Section { raw_len, ..section }).is_none());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn packed_maps_round_trip_and_reject_damage() {
        use reargo_arch::{DecodedInstruction, FlowType};
        use reargo_program::RefType;
        use reargo_program::reference::RefList;
        let insns: Vec<(u64, Box<DecodedInstruction>)> = vec![
            (0x1000, Box::new(DecodedInstruction::new(0x1000, 2, "jne".into(), "0xff0".into(),
                smallvec::smallvec![0x75, 0xee], FlowType::ConditionalJump, Some(0xff0)))),
            (0x1002, Box::new(DecodedInstruction::new(0x1002, 1, "ret".into(), String::new(),
                smallvec::smallvec![0xc3], FlowType::Return, None))),
            // A gap, a key far from the one before, a branch far below.
            (u64::MAX - 4, Box::new(DecodedInstruction::new(u64::MAX - 4, 5, "call".into(), "0x10".into(),
                smallvec::smallvec![0xe8, 1, 2, 3, 4], FlowType::Call, Some(0x10)))),
        ];
        let borrowed: Vec<(&u64, &Box<DecodedInstruction>)> = insns.iter().map(|(k, v)| (k, v)).collect();
        let raw = packed::encode_insns(&borrowed);
        let back = packed::decode_insns(&raw).expect("decodes");
        assert_eq!(back.len(), insns.len());
        for ((k, a), (k2, b)) in insns.iter().zip(&back) {
            assert_eq!(k, k2);
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
            assert_eq!(a.cache_text(), b.cache_text());
        }
        assert!(packed::decode_insns(&raw[..raw.len() - 1]).is_none(), "truncated");
        let mut longer = raw.clone();
        longer.push(0);
        assert!(packed::decode_insns(&longer).is_none(), "trailing bytes");

        let r = |from, to, t| reargo_program::Reference::new(from, to, t);
        let refs: Vec<(u64, RefList)> = vec![
            (0x10, smallvec::smallvec![r(0x10, 0x2000, RefType::UnconditionalCall), r(0x10, 0x15, RefType::FallThrough)]),
            (0x4000, smallvec::smallvec![r(0x4000, 0x8, RefType::DataReadWrite)]),
            (u64::MAX, RefList::new()),
        ];
        let borrowed: Vec<(&u64, &RefList)> = refs.iter().map(|(k, v)| (k, v)).collect();
        let raw = packed::encode_refs(&borrowed);
        let back = packed::decode_refs(&raw).expect("decodes");
        assert_eq!(format!("{refs:?}"), format!("{back:?}"));
        assert!(packed::decode_refs(&raw[..raw.len() - 1]).is_none());
        let mut bad = raw.clone();
        let type_at = raw.iter().rposition(|&b| b == 8).unwrap(); // DataReadWrite
        bad[type_at] = 10; // no such reference type
        assert!(packed::decode_refs(&bad).is_none());
    }

    fn cache_file(dir: &Path, name: &str, size: usize, mtime_secs: u64) -> PathBuf {
        let p = dir.join(name);
        let mut data = MAGIC.to_vec();
        data.resize(size, 0);
        std::fs::write(&p, data).unwrap();
        let f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime_secs)).unwrap();
        p
    }

    #[test]
    fn evict_removes_lru_keeps_new_and_foreign_files() {
        let dir = std::env::temp_dir().join(format!("reargo-evict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = cache_file(&dir, "a.rac", 100, 1_000);
        let mid = cache_file(&dir, "b.rac", 100, 2_000);
        let new = cache_file(&dir, "c.rac", 100, 3_000);
        let foreign = dir.join("d.rac"); // right extension, no magic
        std::fs::write(&foreign, vec![1u8; 500]).unwrap();
        let other = dir.join("notes.txt");
        std::fs::write(&other, vec![1u8; 500]).unwrap();

        assert_eq!(evict(&dir, &new, 0), 0, "0 = unlimited");
        assert_eq!(evict(&dir, &new, 1000), 0, "under the cap");
        assert_eq!(evict(&dir, &new, 250), 1);
        assert!(!old.exists() && mid.exists() && new.exists());
        // Cap below the new entry alone: everything else goes, it stays.
        assert_eq!(evict(&dir, &new, 10), 1);
        assert!(!mid.exists() && new.exists());
        assert!(foreign.exists() && other.exists(), "foreign files untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn touch_refreshes_mtime() {
        let dir = std::env::temp_dir().join(format!("reargo-touch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = cache_file(&dir, "a.rac", 40, 1_000);
        touch(&p);
        let m = std::fs::metadata(&p).unwrap().modified().unwrap();
        assert!(m > std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn pre_key_follows_the_stat_and_is_trusted_only_for_settled_files() {
        let dir = std::env::temp_dir().join(format!("reargo-prekey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("bin");
        std::fs::write(&bin, b"one").unwrap();
        let exe = std::env::current_exe().unwrap();
        let canonical = std::fs::canonicalize(&bin).unwrap();
        let a = pre_key(&bin, &canonical, &exe).unwrap();
        assert_eq!(a.key, pre_key(&bin, &canonical, &exe).unwrap().key, "deterministic");
        let files: Vec<PathBuf> = a.stamps.iter().map(|(p, _)| p.clone()).collect();
        // Just written: too recent to stand for its bytes.
        assert!(!pre_trusted(&a, &files, SystemTime::now()));
        // As if hashed long after the last write: trusted.
        let later = SystemTime::now() + RACY + Duration::from_secs(1);
        assert!(pre_trusted(&a, &files, later));
        // Rewritten (same size, even with the old mtime put back): the
        // stat differs (ctime), so does the pre-key, and the old one is
        // no longer trusted.
        let mtime = std::fs::metadata(&bin).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&bin, b"two").unwrap();
        std::fs::OpenOptions::new().append(true).open(&bin).unwrap().set_modified(mtime).unwrap();
        let b = pre_key(&bin, &canonical, &exe).unwrap();
        assert_ne!(a.key, b.key);
        assert!(!pre_trusted(&a, &files, later));
        // A sidecar is read in full.
        std::fs::write(reargo_program::OverrideSet::sidecar_path(&canonical), b"{}").unwrap();
        assert_ne!(b.key, pre_key(&bin, &canonical, &exe).unwrap().key);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
