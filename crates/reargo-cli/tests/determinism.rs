//! The analysis must give the same result every time it runs on the
//! same binary: no dependence on the per-process `HashMap` seed or on
//! how rayon schedules its threads.
//!
//! A small C program with many libc imports is compiled with the system
//! `gcc` (skipped when not present). Its `@plt` stubs all jump into the
//! shared PLT0 stub, and its functions share code, so which function
//! claims a shared block depends on the order the analysis visits them —
//! the order that used to come from a `HashMap` (`SymbolTable`).
//!
//! * In-process: two analyses of the binary must agree (every `HashMap`
//!   gets fresh random keys, even within one process).
//! * Cross-process: `re-argo export` run several times must write the
//!   same bytes (each process has its own hash seed).

use std::path::{Path, PathBuf};
use std::process::Command;

const SRC: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

static int count_upper(const char *s) {
    int n = 0;
    for (; *s; s++) if (isupper((unsigned char)*s)) n++;
    return n;
}
static char *dup_rev(const char *s) {
    size_t n = strlen(s);
    char *r = malloc(n + 1);
    if (!r) abort();
    for (size_t i = 0; i < n; i++) r[i] = s[n - 1 - i];
    r[n] = 0;
    return r;
}
static void report(const char *tag, long v) {
    if (v < 0) { fprintf(stderr, "%s: bad %ld\n", tag, v); exit(2); }
    printf("%s=%ld\n", tag, v);
}
static long sum_args(int argc, char **argv) {
    long t = 0;
    for (int i = 1; i < argc; i++) t += strtol(argv[i], NULL, 10);
    return t;
}
int main(int argc, char **argv) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s-%d", argc > 1 ? argv[1] : "none", argc);
    char *r = dup_rev(buf);
    report("upper", count_upper(r));
    report("sum", sum_args(argc, argv));
    if (strcmp(r, buf) == 0) puts("palindrome");
    memset(buf, 0, sizeof buf);
    report("pid", (long)getpid());
    report("time", (long)(time(NULL) & 0xff));
    free(r);
    return 0;
}
"#;

fn compile(name: &str) -> Option<PathBuf> {
    let ok = Command::new("gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        return None;
    }
    let dir = std::env::temp_dir();
    let src_path = dir.join(format!("{name}.c"));
    let bin_path = dir.join(name);
    std::fs::write(&src_path, SRC).ok()?;
    let st = Command::new("gcc")
        .args(["-O2", "-fno-inline"])
        .arg(&src_path)
        .arg("-o")
        .arg(&bin_path)
        .status()
        .ok()?;
    st.success().then_some(bin_path)
}

/// Everything the pipeline produces, in the order the program model
/// yields it (that order must be deterministic too).
fn analysis_dump(path: &Path) -> String {
    analysis_dump_with(path, reargo_analysis::AnalysisManager::new())
}

fn analysis_dump_with(path: &Path, manager: reargo_analysis::AnalysisManager) -> String {
    use std::fmt::Write;
    let mut program = reargo_program::Program::from_binary(path).expect("load");
    let _ = manager.run_all(&mut program);
    let mut out = String::new();
    for f in program.listing.functions() {
        writeln!(out, "F {f:?}").unwrap();
    }
    for r in program.references.all_refs() {
        writeln!(out, "R {r}").unwrap();
    }
    for s in program.symbol_table.iter() {
        writeln!(out, "S {s:?}").unwrap();
    }
    for c in program.comments.iter() {
        writeln!(out, "C {c:?}").unwrap();
    }
    for (a, t) in program.tags.iter_addresses() {
        writeln!(out, "TA {a:x} {t:?}").unwrap();
    }
    for (a, t) in program.tags.iter_functions() {
        writeln!(out, "TF {a:x} {t:?}").unwrap();
    }
    for (a, s) in &program.call_renderings {
        writeln!(out, "CR {a:x} {s}").unwrap();
    }
    for (k, v) in &program.metadata.properties {
        writeln!(out, "M {k}={v}").unwrap();
    }
    out
}

/// The first line where `a` and `b` differ, for a readable failure.
fn first_difference(a: &str, b: &str) -> String {
    for (i, (la, lb)) in a.lines().zip(b.lines()).enumerate() {
        if la != lb {
            return format!("line {}:\n  run 1: {la}\n  run 2: {lb}", i + 1);
        }
    }
    format!("line counts {} vs {}", a.lines().count(), b.lines().count())
}

#[test]
fn analysis_is_deterministic_in_process() {
    let Some(bin) = compile("det_inproc") else {
        eprintln!("determinism test skipped: no gcc available");
        return;
    };
    let first = analysis_dump(&bin);
    assert!(
        first.lines().any(|l| l.starts_with("F ")),
        "no functions found"
    );
    for _ in 0..2 {
        let again = analysis_dump(&bin);
        assert!(
            first == again,
            "analysis differs between runs: {}",
            first_difference(&first, &again)
        );
    }
}

/// The pipeline overlaps analyzers (prepares ahead, at the same time):
/// what it gives must be what running each analyzer alone in order
/// gives. Checked on the compiled program and, when present, on
/// `/usr/bin/ls` (more code, more of every analyzer's work).
#[test]
fn overlapped_pipeline_matches_serial() {
    let mut bins: Vec<PathBuf> = compile("det_overlap").into_iter().collect();
    if Path::new("/usr/bin/ls").exists() {
        bins.push(PathBuf::from("/usr/bin/ls"));
    }
    for bin in bins {
        let overlapped = analysis_dump(&bin);
        let serial = analysis_dump_with(&bin, reargo_analysis::AnalysisManager::new().without_overlap());
        assert!(
            overlapped == serial,
            "{}: overlapped analysis differs from the serial one: {}",
            bin.display(),
            first_difference(&overlapped, &serial)
        );
    }
}

#[test]
fn export_is_deterministic_across_processes() {
    let Some(bin) = compile("det_xproc") else {
        eprintln!("determinism test skipped: no gcc available");
        return;
    };
    let exe = env!("CARGO_BIN_EXE_re-argo");
    let mut outputs = Vec::new();
    for i in 0..4 {
        let out = std::env::temp_dir().join(format!("det_xproc.{i}.json"));
        // Every run must analyse: the on-disk cache would hand runs 1..
        // the results of run 0.
        let st = Command::new(exe)
            .env("REARGO_NO_CACHE", "1")
            .arg("export")
            .arg(&bin)
            .arg("-o")
            .arg(&out)
            .output()
            .expect("run re-argo export");
        assert!(
            st.status.success(),
            "export failed: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        outputs.push(std::fs::read_to_string(&out).expect("read export"));
    }
    assert!(
        outputs[0].contains("\"functions\""),
        "unexpected export output"
    );
    for (i, o) in outputs.iter().enumerate().skip(1) {
        assert!(
            *o == outputs[0],
            "export of run {} differs from run 0: {}",
            i,
            first_difference(&outputs[0], o)
        );
    }
}
