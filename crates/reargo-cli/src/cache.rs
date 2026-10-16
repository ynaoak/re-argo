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
//! * **Flags**: no command-line flag reaches the pipeline. `--thumb`
//!   only selects the lifters of `disasm` / `pcode` / `decompile` / …,
//!   which run after the analysis and are not cached.
//! * **Off switch**: the global `--no-cache` flag or `REARGO_NO_CACHE=1`.
//! * **Compression**: the bincode payload is zstd-compressed
//!   ([`ZSTD_LEVEL`]); the header's length and BLAKE3 cover the stored
//!   (compressed) bytes, so corruption is caught before decompressing.
//! * **Eviction**: after a write the directory is trimmed to
//!   `$REARGO_CACHE_MAX_BYTES` (default [`DEFAULT_MAX_BYTES`], `0` =
//!   unlimited) by deleting the least recently used `.rac` files (mtime,
//!   refreshed on every hit), never the one just written.
//! * **Integrity**: a header (magic, format, key, payload length, BLAKE3
//!   of the stored payload) is checked before the payload is decoded; a file
//!   that does not pass is ignored and rewritten. Files are written to a
//!   temporary name and renamed into place, so a reader never sees a
//!   partial file. A failure to read or write the cache never fails the
//!   command (a write failure is a warning on stderr).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use bincode::Options;
use reargo_program::Program;
use reargo_program::program::{AnalysisState, AnalysisStateRef};

/// Bump whenever the stored layout changes in a way the executable hash
/// would not catch on its own (it always changes with the code, so this
/// is a belt-and-braces version tag).
pub const CACHE_FORMAT: u32 = 2;

/// zstd level of the stored payload.
pub const ZSTD_LEVEL: i32 = 1;

/// Default cap on the cache directory's total size (2 GiB).
pub const DEFAULT_MAX_BYTES: u64 = 2 << 30;

const EXT: &str = "rac";

const MAGIC: &[u8; 16] = b"REARGO-ANACACHE\0";
const HEADER_LEN: usize = 16 + 4 + 32 + 8 + 32;

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

/// Where the results for one binary live, and the key they must carry.
pub struct Entry {
    file: PathBuf,
    key: [u8; 32],
}

impl Entry {
    pub fn file(&self) -> &Path {
        &self.file
    }
}

/// The cache entry for `path`, or `None` when the cache is off or the
/// key cannot be computed (the command then runs uncached).
pub fn entry_for(path: &Path) -> Option<Entry> {
    if !enabled() {
        return None;
    }
    let dir = cache_dir()?;
    match compute_key(path) {
        Ok((key, canonical)) => {
            let name = blake3::hash(canonical.as_os_str().as_encoded_bytes());
            let file = dir.join(format!("{}.{EXT}", &name.to_hex()[..32]));
            Some(Entry { file, key })
        }
        Err(e) => {
            eprintln!("[cache] WARNING: not using the analysis cache: {e}");
            None
        }
    }
}

fn hash_file(hasher: &mut blake3::Hasher, path: &Path) -> std::io::Result<()> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    hasher.update(&len.to_le_bytes());
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    // A file that changed size while it was read is no stable input.
    if total != len {
        return Err(std::io::Error::other("file changed while it was hashed"));
    }
    Ok(())
}

fn field(hasher: &mut blake3::Hasher, tag: &str, bytes: &[u8]) {
    hasher.update(tag.as_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn compute_key(path: &Path) -> std::io::Result<([u8; 32], PathBuf)> {
    let canonical = std::fs::canonicalize(path)?;
    let mut h = blake3::Hasher::new();
    field(&mut h, "format", &CACHE_FORMAT.to_le_bytes());
    field(&mut h, "version", env!("CARGO_PKG_VERSION").as_bytes());

    // The build: the running executable's own bytes, so a rebuild with
    // any change to an analyzer never reads results of the old code.
    let exe = std::env::current_exe()?;
    h.update(b"exe");
    hash_file(&mut h, &exe)?;

    field(&mut h, "path", canonical.as_os_str().as_encoded_bytes());
    h.update(b"binary");
    hash_file(&mut h, &canonical)?;

    // The PE Rich-header and Authenticode analyzers read the file named
    // like the binary relative to the working directory
    // (`Program::name`), so that file is an input too.
    if let Some(name) = path.file_name() {
        let local = Path::new(name);
        match std::fs::canonicalize(local) {
            Ok(c) if c == canonical => field(&mut h, "cwd-name", b"same"),
            Ok(c) => {
                h.update(b"cwd-name:other");
                hash_file(&mut h, &c)?;
            }
            Err(_) => field(&mut h, "cwd-name", b"absent"),
        }
    }

    // The user-override sidecar. No analyzer reads it today (it is
    // applied after the pipeline, also after a cache load), but keying on
    // it means no future change can ever pair stale results with an
    // edited sidecar.
    match std::fs::read(reargo_program::OverrideSet::sidecar_path(&canonical)) {
        Ok(bytes) => field(&mut h, "sidecar", &bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => field(&mut h, "sidecar", b"\0absent"),
        Err(e) => return Err(e),
    }
    if canonical != path {
        match std::fs::read(reargo_program::OverrideSet::sidecar_path(path)) {
            Ok(bytes) => field(&mut h, "sidecar-arg", &bytes),
            Err(_) => field(&mut h, "sidecar-arg", b"\0absent"),
        }
    }
    Ok((*h.finalize().as_bytes(), canonical))
}

/// Read the stored results for `entry` into `program` (a fresh
/// `Program::from_binary` of the binary). `false` — and `program`
/// untouched — when there is no valid entry for this key.
pub fn load(entry: &Entry, program: &mut Program) -> bool {
    let Ok(data) = std::fs::read(&entry.file) else {
        return false;
    };
    let Some(payload) = check(&data, &entry.key) else {
        return false;
    };
    let Ok(raw) = zstd::stream::decode_all(payload) else {
        return false;
    };
    match codec().deserialize::<AnalysisState>(&raw) {
        Ok(state) => {
            program.restore_analysis_state(state);
            touch(&entry.file);
            true
        }
        Err(_) => false,
    }
}

/// Mark `file` as just used (mtime = now) for the LRU eviction. Best
/// effort: a read-only cache simply keeps its old times.
fn touch(file: &Path) {
    if let Ok(f) = std::fs::OpenOptions::new().append(true).open(file) {
        let _ = f.set_modified(std::time::SystemTime::now());
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
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == MAGIC
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

/// The payload of a cache file, when its header is intact and matches
/// `key`.
fn check<'a>(data: &'a [u8], key: &[u8; 32]) -> Option<&'a [u8]> {
    if data.len() < HEADER_LEN || &data[..16] != MAGIC {
        return None;
    }
    let format = u32::from_le_bytes(data[16..20].try_into().ok()?);
    if format != CACHE_FORMAT || &data[20..52] != key {
        return None;
    }
    let len = u64::from_le_bytes(data[52..60].try_into().ok()?);
    let payload = &data[HEADER_LEN..];
    if payload.len() as u64 != len {
        return None;
    }
    if blake3::hash(payload).as_bytes() != &data[60..92] {
        return None;
    }
    Some(payload)
}

/// Store `program`'s analysis results (before the override sidecar is
/// applied) for `entry`. Errors are for a warning only.
pub fn store(entry: &Entry, program: &Program) -> Result<(), String> {
    let state: AnalysisStateRef<'_> = program.analysis_state();
    let raw = codec().serialize(&state).map_err(|e| format!("encode: {e}"))?;
    let payload = zstd::stream::encode_all(&raw[..], ZSTD_LEVEL).map_err(|e| format!("compress: {e}"))?;
    drop(raw);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&CACHE_FORMAT.to_le_bytes());
    out.extend_from_slice(&entry.key);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(blake3::hash(&payload).as_bytes());
    out.extend_from_slice(&payload);
    drop(payload);

    let dir = entry.file.parent().ok_or("cache path has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = entry.file.with_extension(format!("tmp.{}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, &out) {
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
    fn check_rejects_damaged_files() {
        let key = [7u8; 32];
        let payload = b"payload bytes";
        let mut f = Vec::new();
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&CACHE_FORMAT.to_le_bytes());
        f.extend_from_slice(&key);
        f.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        f.extend_from_slice(blake3::hash(payload).as_bytes());
        f.extend_from_slice(payload);
        assert_eq!(check(&f, &key), Some(&payload[..]));
        // Another key.
        assert_eq!(check(&f, &[8u8; 32]), None);
        // Truncated.
        assert_eq!(check(&f[..f.len() - 1], &key), None);
        assert_eq!(check(&f[..10], &key), None);
        // A flipped payload byte.
        let mut g = f.clone();
        *g.last_mut().unwrap() ^= 1;
        assert_eq!(check(&g, &key), None);
        // Another format.
        let mut g = f.clone();
        g[16] ^= 1;
        assert_eq!(check(&g, &key), None);
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
}
