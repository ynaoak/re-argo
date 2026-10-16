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
    let entries = std::fs::read_dir(&cache).expect("cache dir written").count();
    assert_eq!(entries, 1, "one cache file per binary");

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
    let file = std::fs::read_dir(&cache).unwrap().next().unwrap().unwrap().path();
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
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1);

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
