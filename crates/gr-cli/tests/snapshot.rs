//! End-to-end snapshot tests for analysis output on synthetic ELF
//! binaries. Each test:
//!
//! 1. Writes a tiny C source to a temp file.
//! 2. Compiles it with the system `gcc` (skipped when not present).
//! 3. Strips the resulting binary.
//! 4. Runs the analysis pipeline (`gr_program::Program` + the full
//!    `AnalysisManager`).
//! 5. Asserts that a representative subset of annotations land.
//!
//! These exist so refactors to the analyzer pipeline (priority
//! changes, propagation tweaks, lifter behaviour…) can't silently
//! regress the user-visible end-to-end behaviour. They're skipped
//! in environments without a working C toolchain so they don't
//! break CI on unrelated platforms.

use std::path::{Path, PathBuf};
use std::process::Command;

fn have_gcc() -> bool {
    Command::new("gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn compile_and_strip(src: &str, name: &str) -> Option<PathBuf> {
    if !have_gcc() {
        return None;
    }
    let src_path = std::env::temp_dir().join(format!("{}.c", name));
    let bin_path = std::env::temp_dir().join(name);
    let stripped_path = std::env::temp_dir().join(format!("{}_s", name));
    std::fs::write(&src_path, src).ok()?;
    let st = Command::new("gcc")
        .args(["-O0", "-no-pie", "-fstack-protector"])
        .arg(&src_path)
        .arg("-o")
        .arg(&bin_path)
        .status()
        .ok()?;
    if !st.success() {
        return None;
    }
    let st = Command::new("strip")
        .args(["--strip-all", "-o"])
        .arg(&stripped_path)
        .arg(&bin_path)
        .status()
        .ok()?;
    if !st.success() {
        return None;
    }
    Some(stripped_path)
}

fn analyze(path: &Path) -> Option<gr_program::Program> {
    let mut program = gr_program::Program::from_binary(path).ok()?;
    let manager = gr_analysis::AnalysisManager::new();
    let _ = manager.run_all(&mut program);
    Some(program)
}

#[test]
fn stripped_printf_binary_recovers_main_and_renders_call() {
    let Some(bin) = compile_and_strip(
        r#"
            #include <stdio.h>
            int main(int argc, char **argv) {
                printf("hello %d\n", 42);
                return 0;
            }
        "#,
        "snap_printf",
    ) else {
        eprintln!("snapshot test skipped: no gcc available");
        return;
    };
    let program = analyze(&bin).expect("analyse");

    // main must come back named.
    let main_addr = program
        .listing
        .functions()
        .find(|f| f.name == "main")
        .map(|f| f.entry_point)
        .expect("main not recovered from stripped binary");

    // At least one call rendering must be a properly-typed printf.
    let renderings: Vec<&String> = program.call_renderings.values().collect();
    assert!(
        renderings.iter().any(|r| r.starts_with("printf(\"hello %d")),
        "expected printf rendering, got: {:?}",
        renderings
    );

    // CRT helpers from the gcc/glibc set should also be named.
    let names: std::collections::BTreeSet<String> =
        program.listing.functions().map(|f| f.name.clone()).collect();
    for expected in &["frame_dummy", "deregister_tm_clones"] {
        assert!(
            names.iter().any(|n| n == expected),
            "expected `{}` to be recovered; functions: {:?}",
            expected,
            names
        );
    }
    let _ = main_addr;
}

#[test]
fn stripped_panic_binary_propagates_message_across_calls() {
    let Some(bin) = compile_and_strip(
        r#"
            #include <stdio.h>
            #include <stdlib.h>
            void die_with_message(const char *msg) {
                fprintf(stderr, "fatal: %s\n", msg);
                exit(1);
            }
            void check_alloc(void *p) {
                if (!p) die_with_message("out of memory");
            }
            int main(int argc, char **argv) {
                char *buf = malloc(1024);
                check_alloc(buf);
                return argc;
            }
        "#,
        "snap_panic",
    ) else {
        return;
    };
    let program = analyze(&bin).expect("analyse");

    // Cross-function constant propagation must have moved
    // "out of memory" from check_alloc → die_with_message →
    // fprintf inside die_with_message.
    let renderings: Vec<&String> = program.call_renderings.values().collect();
    assert!(
        renderings
            .iter()
            .any(|r| r.contains("\"out of memory\"") && r.starts_with("fprintf(")),
        "expected fprintf rendering with propagated string; got: {:?}",
        renderings
    );
}
