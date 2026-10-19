//! The on-disk analysis cache (`src/cache.rs`): a second command on the
//! same binary reads the stored results instead of running the pipeline,
//! and prints exactly what a fresh analysis prints; changing the binary
//! or its override sidecar invalidates the entry.
//!
//! A small C program is compiled with the system `gcc` (skipped when not
//! present). Each test uses its own cache directory (`REARGO_CACHE_DIR`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SRC: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int score(const char *s) {
    int n = 0;
    for (; *s; s++) n += (*s == 'a') ? 3 : 1;
    return n;
}
int main(int argc, char **argv) {
    char buf[32];
    snprintf(buf, sizeof buf, "%s", argc > 1 ? argv[1] : "abc");
    if (strlen(buf) > 20) abort();
    printf("%d\n", score(buf));
    return 0;
}
"#;

const HIT: &str = "[cache] analysis results loaded from";

/// A fresh scratch directory holding a compiled copy of `SRC`.
fn setup(name: &str) -> Option<(PathBuf, PathBuf)> {
    let ok = Command::new("gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        return None;
    }
    let dir = std::env::temp_dir().join(format!("reargo_cache_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let src = dir.join("prog.c");
    let bin = dir.join("prog");
    std::fs::write(&src, SRC).ok()?;
    let st = Command::new("gcc")
        .args(["-O1", "-fno-inline"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .ok()?;
    st.success().then_some((dir, bin))
}

fn re_argo(cache: &Path, args: &[&str], bin: &Path, extra: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_re-argo"))
        .env("REARGO_CACHE_DIR", cache)
        .env_remove("REARGO_NO_CACHE")
        .args(args)
        .arg(bin)
        .args(extra)
        .output()
        .expect("run re-argo");
    assert!(
        out.status.success(),
        "re-argo {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// `export` to `out` and return the JSON plus the run's stderr.
fn export(cache: &Path, bin: &Path, out: &Path, no_cache: bool) -> (String, String) {
    let mut args = vec!["export"];
    if no_cache {
        args.insert(0, "--no-cache");
    }
    let o = re_argo(cache, &args, bin, &["-o", out.to_str().unwrap()]);
    (std::fs::read_to_string(out).expect("read export"), stderr(&o))
}

#[test]
fn second_run_reads_the_cache_and_prints_the_same() {
    let Some((dir, bin)) = setup("hit") else {
        eprintln!("analysis cache test skipped: no gcc available");
        return;
    };
    let cache = dir.join("cache");
    let out = dir.join("out.json");

    let (cold, cold_err) = export(&cache, &bin, &out, false);
    assert!(cold.contains("\"functions\""), "unexpected export output");
    assert!(!cold_err.contains(HIT), "first run cannot hit: {cold_err}");
    // (the analysis entries; beside them the executable's digest, once it is settled)
    assert!(cache.is_dir(), "cache dir written");
    assert_eq!(cache_files(&cache).len(), 1, "one cache file per binary");

    let (warm, warm_err) = export(&cache, &bin, &out, false);
    assert!(warm_err.contains(HIT), "second run should hit the cache: {warm_err}");
    assert!(warm == cold, "cached export differs from the fresh one");

    // `--no-cache` runs the pipeline and agrees too.
    let (fresh, fresh_err) = export(&cache, &bin, &out, true);
    assert!(!fresh_err.contains(HIT), "--no-cache must not read the cache");
    assert!(fresh == cold);

    // Other commands read the same entry and agree with a fresh run.
    for args in [&["functions"][..], &["tags"][..], &["summary"][..], &["decompile"][..]] {
        let extra: Vec<String> = if args[0] == "decompile" {
            vec!["--address".to_string(), main_address(&cache, &bin)]
        } else {
            Vec::new()
        };
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        let warm = re_argo(&cache, args, &bin, &extra);
        assert!(stderr(&warm).contains(HIT), "{args:?} should hit the cache");
        let mut no_cache_args = vec!["--no-cache"];
        no_cache_args.extend_from_slice(args);
        let fresh = re_argo(&cache, &no_cache_args, &bin, &extra);
        assert!(warm.stdout == fresh.stdout, "{args:?}: cached output differs from a fresh run");
    }

    // A damaged cache file is ignored (and rewritten).
    // (the analysis entry: `decompile` also caches its `this-index` here)
    let file = std::fs::read_dir(&cache)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "rac"))
        .expect("an analysis cache entry");
    let mut bytes = std::fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&file, &bytes).unwrap();
    let (again, again_err) = export(&cache, &bin, &out, false);
    assert!(!again_err.contains(HIT), "a corrupt cache file must not be used");
    assert!(again == cold);
    let (_, healed_err) = export(&cache, &bin, &out, false);
    assert!(healed_err.contains(HIT), "the damaged entry should have been rewritten");

    let _ = std::fs::remove_dir_all(&dir);
}

fn main_address(cache: &Path, bin: &Path) -> String {
    let o = re_argo(cache, &["functions"], bin, &[]);
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    text.lines()
        .find_map(|l| {
            let mut it = l.split_whitespace();
            let addr = it.next()?;
            (it.next()? == "main").then(|| addr.to_string())
        })
        .expect("main in the function list")
}

#[test]
fn changed_binary_or_sidecar_never_reads_stale_results() {
    let Some((dir, bin)) = setup("stale") else {
        eprintln!("analysis cache test skipped: no gcc available");
        return;
    };
    let cache = dir.join("cache");
    let out = dir.join("out.json");
    let (cold, _) = export(&cache, &bin, &out, false);
    let (_, warm_err) = export(&cache, &bin, &out, false);
    assert!(warm_err.contains(HIT));

    // The override sidecar's contents are part of the key: editing it
    // misses once (the pipeline runs again), then the new entry hits, and
    // both agree with a fresh analysis.
    let main = main_address(&cache, &bin);
    re_argo(&cache, &["annotate"], &bin, &["--rename", &format!("{main}=renamed_by_sidecar")]);
    let (renamed, renamed_err) = export(&cache, &bin, &out, false);
    assert!(!renamed_err.contains(HIT), "an edited sidecar must not hit the old entry");
    assert!(renamed.contains("renamed_by_sidecar"), "sidecar rename missing");
    assert!(renamed != cold);
    assert!(renamed_err.contains("[overrides] applied"), "{renamed_err}");
    let (renamed2, renamed2_err) = export(&cache, &bin, &out, false);
    assert!(renamed2_err.contains(HIT), "the sidecar's entry should hit: {renamed2_err}");
    assert!(renamed2 == renamed);
    let (fresh, _) = export(&cache, &bin, &out, true);
    assert!(renamed == fresh, "cached results + sidecar differ from a fresh analysis");
    let _ = std::fs::remove_file(reargo_program::OverrideSet::sidecar_path(&bin));
    let (back, back_err) = export(&cache, &bin, &out, false);
    assert!(!back_err.contains(HIT), "removing the sidecar changes the key");
    assert!(back == cold, "removing the sidecar restores the plain results");

    // Changing the binary's bytes (here: a trailing byte the loader
    // ignores) changes the key: the next run analyses again.
    let mut bytes = std::fs::read(&bin).unwrap();
    bytes.push(0);
    std::fs::write(&bin, &bytes).unwrap();
    let (changed, changed_err) = export(&cache, &bin, &out, false);
    assert!(!changed_err.contains(HIT), "a changed binary must not hit the cache");
    let (fresh, _) = export(&cache, &bin, &out, true);
    assert!(changed == fresh);
    let (_, rehit_err) = export(&cache, &bin, &out, false);
    assert!(rehit_err.contains(HIT), "the new binary's results are cached in turn");

    // Still one file: the entry for a path is replaced, not added to.
    assert_eq!(cache_files(&cache).len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn analyze_always_runs_the_pipeline_and_no_cache_env_bypasses() {
    let Some((dir, bin)) = setup("analyze") else {
        eprintln!("analysis cache test skipped: no gcc available");
        return;
    };
    let cache = dir.join("cache");
    let a1 = re_argo(&cache, &["analyze"], &bin, &[]);
    let a2 = re_argo(&cache, &["analyze"], &bin, &[]);
    for a in [&a1, &a2] {
        assert!(!stderr(a).contains(HIT), "analyze must run the pipeline");
        assert!(stderr(a).contains("[Coverage]"), "per-analyzer lines expected");
    }
    // ... and leaves the cache warm for the next command.
    let f = re_argo(&cache, &["functions"], &bin, &[]);
    assert!(stderr(&f).contains(HIT));

    // REARGO_NO_CACHE=1 neither reads nor writes.
    let other = dir.join("cache2");
    for _ in 0..2 {
        let o = Command::new(env!("CARGO_BIN_EXE_re-argo"))
            .env("REARGO_CACHE_DIR", &other)
            .env("REARGO_NO_CACHE", "1")
            .arg("functions")
            .arg(&bin)
            .output()
            .unwrap();
        assert!(o.status.success());
        assert!(!stderr(&o).contains(HIT));
    }
    assert!(!other.exists(), "REARGO_NO_CACHE=1 must not write a cache");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Offset of the first section in a cache file: magic 16 + format 4 +
/// key 32 + pre-key 32 + section count 4, 28 bytes per section, BLAKE3 32.
fn header_len(file: &[u8]) -> usize {
    let count = u32::from_le_bytes(file[84..88].try_into().unwrap()) as usize;
    88 + 28 * count + 32
}

fn cache_files(cache: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(cache)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "rac"))
        .collect();
    v.sort();
    v
}

#[test]
fn sections_are_zstd_compressed_and_damage_is_detected_in_the_stored_bytes() {
    let Some((dir, bin)) = setup("zstd") else {
        eprintln!("analysis cache test skipped: no gcc available");
        return;
    };
    let cache = dir.join("cache");
    let out = dir.join("out.json");
    let (cold, _) = export(&cache, &bin, &out, false);
    let file = cache_files(&cache).pop().expect("cache file");
    let bytes = std::fs::read(&file).unwrap();
    let head = header_len(&bytes);
    assert_eq!(&bytes[head..head + 4], &[0x28, 0xb5, 0x2f, 0xfd], "zstd frame magic");
    // The compressed round trip hits and matches.
    let (warm, warm_err) = export(&cache, &bin, &out, false);
    assert!(warm_err.contains(HIT) && warm == cold);

    // A flipped byte in the middle of the compressed payload, a
    // truncation: both ignored, then the entry is rewritten and hits.
    for damage in 0..2 {
        let mut b = bytes.clone();
        if damage == 0 {
            let mid = head + (b.len() - head) / 2;
            b[mid] ^= 0x55;
        } else {
            b.truncate(b.len() - 7);
        }
        std::fs::write(&file, &b).unwrap();
        let (again, again_err) = export(&cache, &bin, &out, false);
        assert!(!again_err.contains(HIT), "damage {damage} must not be used");
        assert!(again == cold);
        let (_, healed_err) = export(&cache, &bin, &out, false);
        assert!(healed_err.contains(HIT), "damage {damage}: entry should be rewritten");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn size_cap_evicts_the_least_recently_used_entry_but_keeps_the_newest() {
    let Some((dir, bin)) = setup("evict") else {
        eprintln!("analysis cache test skipped: no gcc available");
        return;
    };
    let bin2 = dir.join("prog2");
    std::fs::copy(&bin, &bin2).unwrap();
    let cache = dir.join("cache");
    let run = |b: &Path, cap: Option<&str>| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_re-argo"));
        c.env("REARGO_CACHE_DIR", &cache).env_remove("REARGO_NO_CACHE");
        match cap {
            Some(v) => c.env("REARGO_CACHE_MAX_BYTES", v),
            None => c.env_remove("REARGO_CACHE_MAX_BYTES"),
        };
        let o = c.arg("functions").arg(b).output().unwrap();
        assert!(o.status.success(), "{}", stderr(&o));
        stderr(&o)
    };
    // Unlimited (0): both stay.
    run(&bin, Some("0"));
    std::thread::sleep(std::time::Duration::from_millis(50));
    run(&bin2, Some("0"));
    let files = cache_files(&cache);
    assert_eq!(files.len(), 2, "cap 0 = unlimited");
    // A foreign file with our extension but no magic is never deleted.
    let foreign = cache.join("foreign.rac");
    std::fs::write(&foreign, b"not ours").unwrap();

    // Use `bin` again: it becomes the most recently used (mtime touched
    // on the hit), so `bin2`'s entry is the one to go.
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(run(&bin, Some("0")).contains(HIT));
    let size_of = |p: &PathBuf| std::fs::metadata(p).unwrap().len();
    let total: u64 = files.iter().map(size_of).sum();
    let newest_alone = files.iter().map(size_of).max().unwrap();
    assert!(newest_alone < total);

    // Rewrite bin2's entry under a cap that holds only one file: bin2
    // (just written) stays, bin's older entry is evicted.
    std::fs::write(&bin2, {
        let mut b = std::fs::read(&bin2).unwrap();
        b.push(0);
        b
    })
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    run(&bin2, Some(&newest_alone.max(size_of(&files[0])).to_string()));
    let left = cache_files(&cache);
    assert!(foreign.exists(), "foreign file untouched");
    assert_eq!(left.len(), 2, "one cache entry + the foreign file: {left:?}");
    assert!(run(&bin2, Some("0")).contains(HIT), "the newest entry survived");
    assert!(!run(&bin, Some("0")).contains(HIT), "the older entry was evicted");

    // An unparsable cap falls back to the default and evicts nothing.
    run(&bin2, Some("lots"));
    assert!(cache_files(&cache).len() >= 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The stored pre-key (all zeros: none) of the one cache file in `cache`.
fn stored_prekey(cache: &Path) -> Vec<u8> {
    let file = cache_files(cache).pop().expect("cache file");
    std::fs::read(&file).unwrap()[52..84].to_vec()
}

#[cfg(unix)]
#[test]
fn stat_pre_key_hits_settled_files_and_any_rewrite_misses() {
    let Some((dir, bin)) = setup("prekey") else {
        eprintln!("analysis cache test skipped: no gcc available");
        return;
    };
    let cache = dir.join("cache");
    let out = dir.join("out.json");
    let (cold, _) = export(&cache, &bin, &out, false);
    // Just compiled: its stat cannot stand for its bytes yet.
    assert!(stored_prekey(&cache).iter().all(|&b| b == 0), "no pre-key for a fresh binary");
    let (warm, warm_err) = export(&cache, &bin, &out, false);
    assert!(warm_err.contains(HIT) && warm == cold, "the full key hits");

    // Settled (older than the racy window): the next full-key hit stores
    // the pre-key, and later loads hit through it.
    std::thread::sleep(std::time::Duration::from_millis(3500));
    let (warm, warm_err) = export(&cache, &bin, &out, false);
    assert!(warm_err.contains(HIT) && warm == cold);
    let prekey = stored_prekey(&cache);
    assert!(prekey.iter().any(|&b| b != 0), "pre-key stored once the files settled");
    let (warm, warm_err) = export(&cache, &bin, &out, false);
    assert!(warm_err.contains(HIT) && warm == cold, "the pre-key hits");

    // The same size, a byte flipped in place, the old mtime put back: the
    // ctime changed, so the pre-key misses and the full key decides.
    let meta = std::fs::metadata(&bin).unwrap();
    let mut bytes = std::fs::read(&bin).unwrap();
    let at = bytes.len() - 1;
    bytes[at] ^= 0xff;
    std::fs::write(&bin, &bytes).unwrap();
    std::fs::OpenOptions::new().append(true).open(&bin).unwrap().set_modified(meta.modified().unwrap()).unwrap();
    let (changed, changed_err) = export(&cache, &bin, &out, false);
    assert!(!changed_err.contains(HIT), "a rewritten binary must miss");
    let (fresh, _) = export(&cache, &bin, &out, true);
    assert!(changed == fresh);

    // A modified copy moved over the binary (a new inode) misses too.
    let (_, rehit_err) = export(&cache, &bin, &out, false);
    assert!(rehit_err.contains(HIT));
    let copy = dir.join("prog.copy");
    std::fs::copy(&bin, &copy).unwrap();
    let mut bytes = std::fs::read(&copy).unwrap();
    bytes[at] ^= 0x0f;
    std::fs::write(&copy, &bytes).unwrap();
    std::fs::rename(&copy, &bin).unwrap();
    let (moved, moved_err) = export(&cache, &bin, &out, false);
    assert!(!moved_err.contains(HIT), "a binary replaced by a modified copy must miss");
    let (fresh, _) = export(&cache, &bin, &out, true);
    assert!(moved == fresh);

    // The sidecar is read in full by the pre-key too.
    std::thread::sleep(std::time::Duration::from_millis(3500));
    export(&cache, &bin, &out, false);
    let (_, hit_err) = export(&cache, &bin, &out, false);
    assert!(hit_err.contains(HIT) && stored_prekey(&cache).iter().any(|&b| b != 0));
    let main = main_address(&cache, &bin);
    re_argo(&cache, &["annotate"], &bin, &["--rename", &format!("{main}=renamed_after_settling")]);
    let (renamed, renamed_err) = export(&cache, &bin, &out, false);
    assert!(!renamed_err.contains(HIT), "an edited sidecar must not hit the old entry");
    assert!(renamed.contains("renamed_after_settling"));

    let _ = std::fs::remove_dir_all(&dir);
}
