# RE-Argo

CLI-native reverse-engineering + malware-triage toolkit in Rust. Built atop a Ghidra-equivalent multi-arch analysis pipeline, with a binary-clustering / capability-detection / IoC-extraction layer on top.

This document is the **AI agent operations reference**. It documents every CLI command with enough specificity that an LLM can choose the right command, supply correct flags, parse the output, and chain commands without trial-and-error. Binary name: `re-argo`.

---

## Quick reference: pick the command by goal

| Goal | Command |
|---|---|
| "What is this binary?" (format, arch, runtime, libc, language) | `info <bin>` |
| "One-screen malware-triage report" | `triage <bin>` |
| "Show me everything at a glance" | `summary <bin>` |
| "Run the full analysis pipeline (does everything)" | `analyze <bin>` |
| "List every function the analyzer found" | `functions <bin>` |
| "Find anything by name (function/symbol/comment/tag)" | `find <bin> <query>` |
| "Categorised findings (crypto, suspicious, library, …)" | `tags <bin>` / `tags --list-types` |
| "Disassemble at an address" | `disasm <bin> --start 0x401000 -n 32` |
| "Show pseudocode for a function" | `decompile <bin> --address 0x401000` |
| "Who calls this address? (reverse callgraph)" | `backtrace <bin> 0x401000` |
| "Show the callgraph near this address" | `callgraph <bin> --around 0x401000 --depth 2` |
| "Memory layout of the binary" | `memmap <bin>` |
| "Per-function McCabe / fan-in / fan-out metrics" | `metrics <bin> --sort mccabe --top 25` |
| "Dump CFG of a function as Graphviz DOT" | `cfg <bin> 0x401000` |
| "Cross-references to/from an address" | `xrefs <bin> 0x401000` |
| "Fast xref to an address on a HUGE binary (no full analysis)" | `xref-scan <bin> 0x401000` |
| "Recover a C++ class name + vmethods from a vtable slot (PIE)" | `vtable <bin> 0x401000` |
| "Find a function's entry from an interior address (no full analysis)" | `func-start <bin> 0x401000` |
| "List every C++ class in a stripped PIE binary (RTTI browser)" | `classes <bin> [--filter Foo] [--derives Base --slot 6]` |
| "Class of `this` / the parameters of a non-virtual method, from its callers" | `this-index <bin> [-a 0x401000]` |
| "Classify what an address is (code/data/import/vtable/string)" | `whatis <bin> 0x401000` |
| "Map an object's field layout from a constructor/method" | `members <bin> 0x401000 [--base rbx]` |
| "All call sites with resolved arguments" | `callsites <bin>` |
| "Strings in the binary" | `strings <bin> --min-length 6` |
| "Search for bytes or text" | `search <bin> --hex "48 8b ?? 24"` / `--text "password"` |
| "Hexdump at an address" | `hexdump <bin> 0x401000 64` |
| "Symbols (loader-side or analyzer-recovered)" | `symbols <bin> [-k func] [--all] [--name VTbl]` |
| "Imports / exports" | `imports <bin>` / `imports <bin> --exports` |
| "Sections" | `sections <bin>` |
| "Coverage of analysis (% of executable bytes decoded)" | `coverage <bin> [--annotated]` |
| "Wall-clock benchmark of analysis + slowest analyzers" | `bench <bin> [--top 15]` |
| "List the analyzer pipeline" | `workflow [--declared-only]` |
| "Inspect / export the built-in signature DB" | `signatures [--library libc] [--export sigs.json]` |
| "Emit machine-readable analysis to JSON" | `export <bin> -o out.json` |
| "Emit Ghidra-compatible XML" | `export-xml <bin> -o out.xml` |
| "Track tainted args to dangerous sinks" | `taint <bin> --address 0x401000` |
| "Diff two binaries byte / symbol level" | `diff <a> <b>` |
| "Diff two binaries SSA / function level" | `semantic-diff <a> <b>` |
| "Bulk-decompile every function" | `decompile-all <bin> -o out/` |
| "Emulate code" | `emulate <bin> --start 0x401000 -n 1000` |
| "GDB remote debugging" | `gdbserver <bin> --listen 127.0.0.1:1234` |
| "Show P-code IR (low-level)" | `pcode <bin> --start 0x401000 -n 16` |
| "Search byte / text patterns" | `search <bin> --hex "55 48 89 e5"` |
| "Patch a binary" | `patch <bin> 0x401000 --bytes "90 90 90" -o patched` |
| "Carve 1 function out of a huge binary (for GUI Ghidra)" | `carve <bin> --address 0x401000 -o func.elf` |
| "Persist manual corrections to a sidecar" | `annotate <bin> --rename 0x401000=my_main --func 0x401080` |
| "Auto-correct fixpoint loop" | `iterate <bin> --apply --max-rounds 5` |
| "Run multi-command script" | `script <bin> queries.grs` |
| "Speak MCP to a host like Claude Code" | `mcp <bin>` |
| "Per-section entropy (detect packing)" | `entropy <bin>` |
| "Find ROP / JOP / COP gadgets (x86 / x64)" | `rop <bin> --kinds all --useful-only --contains "pop rdi"` |
| "Extract IoCs (URLs / IPs / registry keys / mutexes)" | `ioc <bin>` |
| "What does this binary do? (Capa-style)" | `capa <bin>` |
| "Is this packed? Which packer?" | `packer <bin>` |
| "Find embedded files (PE / ZIP / PNG / …) in the binary" | `embedded <bin>` |
| "Flag dangerous-API call sites (Cwe_checker-style)" | `vuln <bin>` |
| "Scan with a YARA ruleset (lite subset)" | `yara <bin> rules.yar` |
| "Compare two binaries by content similarity (TLSH)" | `tlsh-diff <a> <b>` |
| "Decode obfuscated strings (XOR / ROL)" | `floss <bin>` |
| "List the classes in a Java JAR / .class" | `jvm classes <jar> [--filter Foo] [--resources]` |
| "Show a Java class (header, fields, method signatures)" | `jvm class <jar> a.b.C` |
| "Disassemble a Java class / method (javap -c style)" | `jvm disasm <jar> a.b.C [--method name]` |
| "Find string literals in a JAR and the methods that push them" | `jvm strings <jar> --pattern http [--constants]` |
| "Who references this Java class / method / field?" | `jvm xrefs <jar> a.b.C.name` |
| "Call tree: what does this Java method call?" | `jvm callees <jar> a.b.C.name --depth 3` |
| "Reverse call tree: who calls this Java method?" | `jvm callers <jar> a.b.C.name --depth 3` |
| "Classes extending / implementing a Java class or interface" | `jvm subtypes <jar> a.b.Base` |

---

## How to call the CLI

```bash
cargo run --release -- <command> <args>     # development build
target/release/re-argo <command> <args> # after a release build
```

All commands accept `--thumb` (global flag, before the subcommand or after) to decode ARM code in Thumb mode. Most users on x86_64 / aarch64 binaries can ignore it. `--no-cache` (global) bypasses the on-disk analysis cache (see below).

Hex addresses can be written as `0x401000`, `401000`, or `0X401000`.

### Analysis cache (`--no-cache`, `REARGO_CACHE_DIR`)

Every command that needs the analysed program (`functions`, `decompile`, `xrefs`, `tags`, `export`, `summary`, `triage`, `callsites`, `metrics`, `find`, `cfg`, `callgraph`, `backtrace`, `decompile-all`, `taint`, `coverage`, `capa`, `vuln`, `ioc`, `packer`, `entropy`, `iterate`, `diff`, `semantic-diff`, `carve --address`, `symbols --all`, `mcp` — at startup and on each re-analysis after a correction —, …; `decompile --fast` analyses only its function and is uncached) stores the analyzer pipeline's results on disk after the first run and reads them back on later runs on the same, unchanged binary: the pipeline is skipped, the output is byte-identical. Measured (release build, 4 cores, median of 9; cold = empty cache, analyses and writes the entry; warm = reads it): `functions` on `/usr/bin/ls` 0.11 s → 0.008 s, `/usr/bin/bash` 0.58 s → 0.037 s, `python3.12` 1.13 s → 0.078 s, `cmake` 2.4 s → 0.14 s; `export` warm: bash 0.050 s, python3.12 0.098 s, cmake 0.134 s; `decompile -a` on `python3.12` 0.14 s (the decompilation itself is most of it). Before cache format 3 the warm load was 4–5× slower (python3.12 `functions` 0.37 s, cmake 0.70 s).

* **Where**: `$REARGO_CACHE_DIR`, else `$XDG_CACHE_HOME/re-argo`, else `~/.cache/re-argo` — never next to the binary. One `<hash of the binary's canonical path>.rac` file per analysed path, replaced when the key changes (see **Size cap** below). Each section is zstd-compressed (level 1): a file is roughly the binary's size (ls 0.3 MB, bash 4.1 MB, python3.12 8.3 MB, cmake 14.6 MB).
* **Size cap / eviction**: after a write the cache directory is trimmed to `REARGO_CACHE_MAX_BYTES` (default 2 GiB = 2147483648; `0` = unlimited; an unparsable value means the default) by deleting the least recently used `*.rac` files, by mtime — a cache hit refreshes the file's mtime — until the total is under the cap. The entry just written is never deleted, and only files with our `.rac` extension *and* magic are counted or removed. Eviction and the mtime touch are best effort and never fail the command.
* **Key** (stored in the file and compared on every load, so a stale hit is impossible): a cache-format number, the re-argo version, a BLAKE3 hash of the running `re-argo` executable itself (any rebuild invalidates every entry), the binary's canonical path and a BLAKE3 hash of its full contents, the contents of the `<binary>.gra.json` override sidecar (or its absence), and the file `./<binary file name>` relative to the working directory (absent / the binary itself / its contents — the PE Rich-header and Authenticode analyzers read it). **Pre-key** (Unix): hashing the executable and the binary costs ~30 ms on a large one, so the file also stores a second key built the same way from those files' `stat` (device, inode, size, mtime and ctime to the nanosecond; the sidecar is still read in full); a load whose pre-key matches skips the content hashing. It is stored only for files whose stat did not change while they were hashed and whose mtime / ctime are at least 3 s (`RACY`) older than the hashing — any later write gives a file a newer ctime, which cannot be set back, so an equal stat means equal bytes; otherwise (a file just built or copied, or after `touch`) the full key decides, and a full-key hit writes the then-current pre-key into the file's header (in place, only into a file that still holds that key). So the first runs within 3 s of a rebuild hash in full, later ones do not.
* **Sidecar**: an `annotate` / `iterate --apply` edit changes the key, so the next command re-runs the pipeline once. The cache holds the results *before* the overrides; the sidecar is applied on top on every run, exactly as after a fresh analysis. **Flags**: no flag reaches the pipeline — `--thumb` only selects the lifters of `disasm` / `pcode` / `decompile` / …, which run after it, so it is not in the key.
* **Bypass**: global `--no-cache` (`re-argo --no-cache functions <bin>`) or `REARGO_NO_CACHE=1` — the pipeline runs and the cache is neither read nor written.
* **stderr**: a hit prints `[cache] analysis results loaded from <file>` instead of the per-analyzer lines (stdout is unchanged); `triage` stays silent.
* **Always run the pipeline**: `analyze` (it prints the per-analyzer lines; it also *refreshes* the entry, so `analyze` warms the cache for the commands after it) and `bench` (it measures the pipeline; it neither reads nor writes the cache). `script` keeps its own in-process analysis (uncached). The loader-only commands (`info`, `sections`, `symbols` without `--all`, `disasm`, `pcode`, `xref-scan`, `func-start`, `carve --start`, `classes`, `vtable`, `whatis`, `members`, `strings`, `search`, `hexdump`, `rop`, `embedded`, `floss`, `yara`, every `jvm …` subcommand, …) never ran the pipeline and are unaffected.
* **What is stored** (`CACHE_FORMAT` 3): the listing (decoded instructions — an x86 instruction without its text, which is formatted again from its bytes on first use, as after decoding — + functions with bodies / frames / signatures), symbol table, references, comments, metadata, call renderings and tags, split into sections: each large map (instructions, functions, symbols by address / name, references from / to, comments, address tags) in chunks of 16384 entries, the rest (metadata, call renderings, the jump log, function tags) in one; each section is its own zstd frame (with zstd's content checksum). Instructions and references use a hand-rolled packed encoding (zigzag-varint address deltas, one-byte enums: decodes several times faster than serde and is ~40 % smaller); the rest is bincode (varint). The header holds magic, format, key, pre-key, the section table (kind, entry count, decoded and stored length) and a BLAKE3 of the header without the pre-key. On load the sections are read (positioned reads), decompressed into per-thread buffers and decoded in parallel (rayon), each map rebuilt from its sorted entries in one pass (the packed chunks decode straight into one presized vector), all while the binary itself loads. A truncated / corrupt / foreign file fails the header check (the file length must equal the header's plus the sections'), a zstd error / checksum mismatch, a length or entry-count mismatch or a decode error, and is ignored and rewritten; files are written to a temporary name and renamed into place; a cache read or write failure never fails the command (a write failure is a `[cache] WARNING` on stderr). Rebuilt on load instead of stored: the binary itself (`info`, memory, `arch`: the loader runs as usual), `data_types` (re-imported from DWARF, as the Type Recovery analyzer does) and the analyzers' in-run scratch `analysis_cache`. Writing is parallel too (encode + compress per section): a cold run is faster than before format 3 (python3.12 1.40 → 1.13 s).
* **Exit**: a one-shot command leaves its analysed `Program` to the process exit instead of freeing it (`reargo_program::program::leak_on_drop`, set in `main` for every command but `mcp`, `script`, `debug`, `gdbserver` and `iterate`, which analyse again and again): freeing millions of small objects, many allocated on other threads, cost 25–50 ms.
* Code: `crates/reargo-cli/src/cache.rs` (keys, file format, packed codec), `Program::analysis_state` / `restore_analysis_state` (`crates/reargo-program/src/program.rs`) and the `cache_parts` / `from_cache_parts` of `Listing`, `SymbolTable`, `ReferenceManager`, `CommentManager`, `TagManager`, `DecodedInstruction`; bump `CACHE_FORMAT` when the stored layout changes. Tests: `crates/reargo-cli/tests/analysis_cache.rs` and the unit tests in `cache.rs`.

---

## Build, test, lint

```bash
cargo build              # debug build of the entire workspace
cargo build --release    # release build of the entire workspace
cargo test --workspace   # ~600 tests across all crates
cargo clippy --workspace --all-targets -- -D warnings
```

Optional profile-guided build: `tools/pgo.sh [TRAINING_BIN ...]` (default `/usr/bin/ls /usr/bin/bash`) builds an instrumented binary, trains it with `analyze` + `decompile-all` (`--no-cache`), then rebuilds with the merged profile into `target/pgo/re-argo` (~7 min). Needs `rustup component add llvm-tools` (the script prints this and exits 1 if `llvm-profdata` is missing). Measured gain on bash / python3.12 is only ~3-4% wall time. Always pass `--no-cache` when benchmarking, otherwise you measure on-disk cache hits.

---

## Common workflows (multi-command recipes)

### Triage a stripped binary

```bash
re-argo info <bin>              # format / arch / runtime
re-argo summary <bin>           # 1-screen overview
re-argo functions <bin>         # see what's named
re-argo tags <bin> --list-types # categorised findings
re-argo find <bin> "main"       # find the entry-likely func
re-argo decompile <bin> --address <main_addr>
```

### Investigate suspected crypto

```bash
re-argo tags <bin> --filter crypto
# → "address  crypto  0x402020  crypto: AES S-box (forward)"
re-argo xrefs <bin> 0x402020    # who uses the S-box?
re-argo backtrace <bin> <user_addr>   # who reaches that user?
```

### Hunt a suspected vulnerable function

```bash
re-argo find <bin> "strcpy"     # locate the unsafe call
re-argo backtrace <bin> <strcpy_plt_addr>   # reverse reach
re-argo taint <bin> --address <reachable_func>
re-argo decompile <bin> --address <reachable_func>
```

### Find anti-debug

```bash
re-argo tags <bin> --filter anti_debug
re-argo workflow                 # show the anti-debug analyzer is enabled
```

### Compare two builds

```bash
re-argo diff old.bin new.bin           # symbol / byte level
re-argo semantic-diff old.bin new.bin  # SSA / function level
```

### Bulk extract decompiled C for offline review

```bash
re-argo decompile-all <bin> -o /tmp/decomp --skip-errors
ls /tmp/decomp/*.c
```

### Restore stripped function names from a community symbol list

```bash
re-argo annotate <bin> --import community_symbols.json
re-argo functions <bin>                 # names now flow through every subsequent command
re-argo iterate <bin> --apply           # let the heuristic correction loop finish the job
```

### Analyse a Java application (JAR)

```bash
re-argo jvm classes app.jar --filter auth          # find the interesting classes
re-argo jvm strings app.jar --pattern http         # string literal → "a.b.Cls.method(desc):line @pc N"
re-argo jvm xrefs app.jar com.example.net.Client.send   # who touches it?
re-argo jvm callers app.jar com.example.net.Client.send --depth 3   # reverse call tree
re-argo jvm disasm app.jar com.example.net.Client --method send     # javap -c style bytecode
```

---

## Output format conventions

These conventions are stable across commands; the AI should rely on them when parsing.

### Address columns

* Hex with `0x` prefix and lower-case digits: `0x401234`.
* Right-padded with spaces, never zero-extended in narrow columns.
* In headers, "Address" or "addr" or "0x" label.

### Function references

* Function entries print as `name (0xADDR)` — e.g. `printf@plt (0x401050)`.
* Auto-discovered functions without symbols are `FUN_<addr>` — e.g. `FUN_004011f0`.
* PLT thunks have `@plt` suffix; GLIBC versioned imports `@GLIBC_2.34`.

### Section / annotation headers

* Sections listed start at column 0 with name, address, size, perms (rwx).
* `summary`, `metrics`, `tags` etc. each use a `-`-rule separator (72 chars) before tabular data.

### Tag scope and kind enums

`tags` produces one of these `scope` values: `address` (instruction / data byte) or `function` (entry).

Built-in `kind` slugs: `important`, `suspicious`, `library`, `crypto`, `bug`, `crash`, `noreturn`, `wrapper`, `recursive`, `loop`, `stack_protected`, `anti_debug`, `exception`. Anything else is a user/plugin Custom kind.

### JSON output (`export`)

Top-level keys: `name`, `format`, `arch`, `bits`, `entry_point`, `functions[]`, `symbols[]`, `references[]`, `comments[]`, `tags{}`, `references_count`, `instructions_count`, `has_dwarf`, `dwarf_functions`, `analyzers_run[]`, `version`, `dynamic_libs[]`, `import_count`.

Each function: `{address, name, block_count, call_count, stack_size}`.

Each symbol: `{address, name, kind}` (`kind` ∈ `Function | ExternalFunction | Data | Label`).

Each comment: `{address, kind, text}` (`kind` ∈ `Eol | Pre | Post | Plate | Repeatable`).

---

## Command reference

### Discovery / triage

#### `info <FILE>`

Display format, architecture, bits, entry point, section count, symbol count, plus compiler / runtime fingerprints when detected, plus high-signal triage values (`imphash`, `packer`, `entropy_overall`) when the cheap analyzers can detect them.

Example output keys: `Format`, `Architecture`, `Bits`, `Entry Point`, `language`, `runtime`, `libc_version`, `pe_product`, `pe_version`, `build_id`, `compiler`, `imphash`, `tlsh`, `richhash`, `signed`, `cert_subjects`, `packer`, `entropy_overall`, `section_anomaly_count`.

#### `triage <FILE>`

One-screen malware-triage report. Runs the full analysis pipeline and prints a digestible summary combining format / arch / entry, identity (compiler / language / runtime), hashes (`imphash`, `tlsh`), code-signing info (Authenticode subjects for PE), packer + overall entropy, capa rule matches (top 10), CWE findings grouped by id, IoCs grouped by kind, and tag counts. Designed for "what is this and should I worry about it?" in one pass — typically the first command to run on an unknown sample.

#### `summary <FILE>`

One-screen digest: format / entry / runtime identity / function counts (total, named %, no-return, thunks) / annotation densities / hottest functions by fan-in / recursive-cluster count / **Triage block** (packer, entropy_overall, imphash, capa rule count, CWE finding count, IoC count) / **Tags by kind** breakdown. The triage / tags blocks consolidate the work the cheap analyzers produced, so users see the at-a-glance findings without invoking each individual `packer` / `capa` / `vuln` / `ioc` command separately.

#### `sections <FILE>`

Tabular `Name  Address  Size  Flags` for every loaded section.

#### `memmap <FILE>`

Same data as `sections` but address-sorted with a log₂-scaled size bar suitable for skimming. Tiny `.comment` and big `.text` stay both legible.

#### `symbols <FILE> [-k func|data|import|export] [--all] [-n SUBSTR]`

Loader-side symbols by default (fast, no analysis required).

| Flag | Purpose |
|---|---|
| `-k func` | Only `Function` / `ExternalFunction` entries |
| `-k data` | Only `Data` entries |
| `-k import` | Imports (from `.dynsym` / IAT) |
| `-k export` | Exports |
| `--all` | Run full analysis first; include RTTI / VTable names, analyzer-recovered, sidecar overrides |
| `-n SUBSTR` | Case-insensitive substring filter |

Without `--all`, a stripped binary may look empty even after `analyze` since analyzer-recovered names live in the in-memory program model, not the loader's symbol list.

#### `imports <FILE> [--exports]`

List imports (default) or exports (`--exports`). Output is one line per entry; for PE includes IAT slot address and library name.

#### `strings <FILE> [-m N] [--all]`

Find printable strings (default minimum length 4) in data sections (or `--all` sections).

### Analysis pipeline

#### `analyze <FILE>`

Run the **full** 68-analyzer pipeline on the binary. Most other commands run the pipeline implicitly, so `analyze` is mainly used to:
1. Verify each analyzer's contribution (per-analyzer line is printed to stderr)
2. Warm (refresh) the on-disk analysis cache for subsequent commands — `analyze` itself always runs the pipeline, never reads the cache (see **Analysis cache**)
3. Run only the pipeline without picking a specific output

#### `functions <FILE>`

Tabular list of every discovered function: address, name, block count.

#### `metrics <FILE> [--sort COL] [--top N]`

Per-function McCabe / blocks / instruction count / fan-in / fan-out / stack size.

Sort columns: `mccabe` (default), `blocks`, `insns`, `fan_in`, `fan_out`, `stack`.

Output:
```
Address            Name                              insns blocks mccabe  fanIn fanOut    stack
0x0000000000401196 main                                 41      4      3      0      4        8
```

#### `bench <FILE> [--top N]`

Wall-clock + per-stage breakdown of the analysis (always runs the pipeline; the analysis cache is not used). Output keys: `Load`, `Analysis (total)`, `Analyzers OK / Err`, `Functions`, `Instructions`, `References`, `Comments`.

Followed by a per-analyzer table (after a 72-char `-` rule), slowest first: `Analyzer  ms  % total  status` (`ms` 1 decimal, `% total` of `Analysis (total)`, `status` ok/err). `--top N` limits it to the N slowest (default 15, 0 = all). Some analyzers' work overlaps other analyzers' (see **Pipeline overlap** below): a row counts that part's own time too, so the rows can add up to more than `Analysis (total)`.

**Pipeline overlap** (`crates/reargo-analysis/src/manager.rs`, `analyzer.rs`): the analyzers run in priority order, but the output is computed as if each ran alone in that order while some of their work runs at the same time. (1) `Analyzer::start_early`: an analyzer whose result depends only on the loaded binary (FLOSS-lite, TLSH, Entropy, String Search, IoC Extractor) computes it on another thread from the start of the run and applies it at its own place. (2) Split analyzers: `prepare(&Program)` (read-only) + `apply(&mut Program, …)`, declaring what `prepare` reads (`prepare_reads`) and what they write (`writes`, as `State` flags: `CODE`, `FUNC_NAME`, `SYMBOLS`, `REFERENCES`, `COMMENTS`, `TAGS`, `METADATA`, …; default: everything). The pipeline is cut into runs (a split analyzer whose reads an earlier analyzer of the run writes starts the next one); each split analyzer's `prepare` runs at the start of the earliest run that prepares anyway from which no analyzer up to its own place writes any of its reads — so a long `prepare` (the Call Site Annotator's shared lift) starts runs earlier and fills the cores the runs in between leave idle —, the `prepare`s of a run at the same time (rayon), then every analyzer of the run runs in order (`apply` with the prepared result, or `analyze` for the others). Declared reads / writes are coarse on purpose (`INSNS` = the listing's instructions, `FUNCS` = the function set and bodies — adding a function, even with an empty body, writes it and the `FUNC_*` fields: `State::FUNCTIONS`); `prepare` cannot take from `analysis_cache`; it may only look for an entry that has a `State` flag of its own, declared in its `prepare_reads` and in the `writes` of every analyzer that stores or takes that entry — the Call Site Annotator's `prepare` checks for stored call-site results (`State::SHARED_LIFT`, written by the annotator and Format Varargs, which store / take them) and, when there are some, computes at `apply` instead; the unit tests in `manager.rs` check that no `prepare` is placed before an analyzer writing what it reads. A wrong declaration breaks the output: when splitting an analyzer or changing what one reads / writes, keep the declarations exact and check the `export` md5s and the test `overlapped_pipeline_matches_serial` (`crates/reargo-cli/tests/determinism.rs`, which compares against `AnalysisManager::without_overlap()`). Critical path at 4 threads (the shared lift of the Call Site Annotator's `prepare` was its longest stretch, ~250 ms of python3.12's ~760): its jobs run in chunks cut by their lifts (`range_lift::span_chunks`, below), the early analyzers read borrowed section bytes, CRT Pattern / Linear Sweep / Format Varargs / Call Site work runs in parallel. Measured (`bench`, median of 15 alternating, wall, same build path, before → after): 4 threads x86 python3.12 847 → 776 ms, cmake 1741 → 1493, perl 674 → 621, bash 458 → 423, arm64 python3.12 368 → 362; 1 thread python3.12 2131 → 2046, cmake 4398 → 4054; peak RSS within ±4 %. Range-lift runs (`range_lift::span_chunks`, used by Stack Frame, the shared lift and the call-site walks): a function's linear lift runs well past its end, over the functions after it, which one run lifts once, so a job costs the instructions it lifts that the run had not (its end estimated at 4 bytes an instruction) plus its own work; each run is filled up to an even share (total / (threads × 16)) and then ended, within the next 64 jobs and half a share, before the job whose lift the run covers least — not right after a large function, whose lift the next run would redo. python3.12 single-instruction lifts at 4 threads: Stack Frame 766k → 613k, shared lift 888k → 736k (1 thread 664k → 582k, 870k → 705k). The runs were already balanced (Stack Frame's per-thread busy time within ~8 %; its own serial part ~3 ms of ~90, P-code Reference's dedup / add ~5 ms): Stack Frame and the shared lift are CPU-bound, at 4 threads the cores are saturated there. Measured (`bench`, alternating, same build path, `Analysis (total)` medians, before → after): 1 thread python3.12 2122 → 2063 ms, cmake 3892 → 3808, bash 973 → 941; 2 threads python3.12 1198 → 1122, cmake 2238 → 2215; 4 threads within noise (±3 % between sessions: python3.12 787 → 784 / 782 → 806, cmake 1429 → 1455 / 1492 → 1469, perl 593 → 575, bash 421 → 421); peak RSS within ±3 %.

**Function Discovery in parallel** (`crates/reargo-analysis/src/discovery.rs`, `discover_parallel`; also Late Discovery, which runs the same pass): the recursive-descent walk itself stays serial on the calling thread, in its own order — what it walks depends on what earlier functions of the run visited — but with more than one thread (`RAYON_NUM_THREADS` > 1), once it has read `HELP_AFTER` (65536) instructions, `threads − 1` threads of their own (not the rayon pool's: the early analyzers keep the pool busy then, and the walk never waits for them) decode ahead of it: they take the entries the walk may reach (the calls it found, the functions jumped or run into, claimed in a lock-free paged bitmap) and decode the code each reaches; the walk reads an instruction from those decodes when one is there (next to the one it read before, else in the code decoded from the entry at the address), else decodes it itself. Decoding is a pure function of the bytes and the address, so the output is the serial one whatever the threads did (`export` / `decompile-all` identical at 1, 2 and 4 threads). From then on too, the references are added (`ReferenceManager::add_all`, in the order found) and the bodies' address sets made on two more threads while the walk goes on; at the end the decoding threads hand over the decodes the walk read (at the addresses it visited), which are listed in one pass (`Listing::add_unlisted_instructions`), and free the rest on their own heaps, then return the memory they freed (`reargo_analysis::set_release_free_memory`, set by the CLI to mimalloc's `mi_collect(true)`: mimalloc keeps freed memory for a second, which would otherwise show in the peak RSS). A walk shorter than `HELP_AFTER` runs with none of it (no threads). Instruction text (`DecodedInstruction`'s mnemonic / operands) is shared (`Arc`), so the AArch64 / Thumb decode memos hand out copies without allocating, and the ARM / AArch64 Capstone handle is no longer one lock all threads wait on: a thread that finds it in use takes a spare instance built the same way (`SafeCapstone::with_builder`). Measured (`bench`, 4 cores, median of 15 alternating runs, `Analysis (total)` before → after, both built from the same path): 4 threads — arm64 python3.12 483 → 392 ms (Function Discovery 287 → 194), arm64 bash 259 → 223 (168 → 135), x86 cmake 2081 → 1849 (Late Discovery 462 → 298), x86 bash 534 → 502 (88 → 79), python3.12 974 → 936 (154 → 121), perl 739 → 722; 2 threads — arm64 python3.12 539 → 464, x86 cmake 3082 → 2818; small binaries (ls, armhf bash / python3.12, arm64 cmake: walks under `HELP_AFTER`) unchanged; 1 thread unchanged or faster (the shared text: arm64 bash 371 → 322). Peak RSS within +4 %. FLOSS-lite (an early analyzer) once bounded the x86 python3.12 gain (~275 ms of CPU finishing after Discovery); its 64-pass bitwise scan now takes ~60 ms of CPU at 1 thread and no longer delays the pipeline. Caveat when measuring: FLOSS-lite's parallel scan varies by up to ~30 % at 4 threads between builds of the same code from different directories (code / data layout), so compare binaries built from the same path.

**Late Discovery in parallel** (same file): a walk that starts from many entries (≥ `SEED_START` = 512 functions not listed or without a body — Late Discovery, which fills the bodies of the functions Linear Sweep / CRT / EH frame added; cmake: 1.07M instructions walked against 3.4k in the first run) starts the decoding threads at once instead of after `HELP_AFTER`, seeded with the walk's own queue in its order (then the calls found), so they decode ahead of where it goes (cmake: ~97 % of the walk's reads from their decodes, against ~70 %). The walk marks each decode it reads (a flag in the decode, instead of the threads filtering by its `visited` set at the end); a thread hands over the decodes the walk read cut into parts of the code (`Shared::cuts`, equal spans), which the listing puts in order with the listed ones on a thread per part before building the map once (since the round **Critical path at 4 threads, round 2**, below, by rank, unsorted; it was a sort in each thread and a merge). The references are added with `ReferenceManager::add_all_unpooled` (no rayon `join`: from a thread outside the pool it waited for a busy pool, ~20 ms of cmake's first Discovery run), the walk's `Visited` set is indexed over the executable code (no hashing), and a body's set is made by a run-adaptive sort by address (`body_set`; the walk's ranges ascend within each block). Also: `LiftCache`'s address map is a direct-mapped index in pages of 1024 addresses with the last page remembered (`AddrIndex`: 99 % of `index_of` calls are misses that lift; the map was a small part of its cost, −44M instructions on python3.12), the Anti-Debug plate scan walks each body's ranges against the sorted findings (it ran a `BTreeSet` range query per instruction range: 28–69 ms serial at 4 threads on cmake → ~2–3 ms) and Pattern Function finds its prologue candidates with `memchr::memmem` (20–29 → ~11 ms). Measured (`bench`, same build path, medians, `Analysis (total)`, base → new): 4 threads (21 alternating) cmake 1634 → 1496 ms (Late Discovery 324 → 223), python3.12 816 → 774, perl 604 → 557, bash 439 → 400, arm64 python3.12 352 → 324; 2 threads (11) cmake 2496 → 2330, python3.12 1259 → 1188, bash 626 → 611; 1 thread (9) cmake 4378 → 4134, python3.12 2262 → 2128, bash 1219 → 1148; CPU time (user + sys) equal or lower; peak RSS within +2.3 % (cmake 4 threads 667 → 682 MB); instructions (callgrind, 1 thread) python3.12 12.53G → 12.30G, cmake 23.20G → 22.60G. Tried and dropped: listing the walk's own decodes through a hash map at 1 thread (the hashing, rehash and final sort cost more than the `BTreeMap` inserts saved: Late Discovery 1.66G → 2.02G instructions).

**Decoder reuse and cheaper call-site preparation**: `Architecture::instruction_decoder` gives a decoder that decodes each address exactly as `decode_instruction` does; the x86 one keeps one iced decoder over the memory block of the last address and positions it (`decode_instruction` read the bytes into a buffer and built a decoder per instruction), falling back to `decode_instruction` where the bytes differ (past a block's data, a block without data, near a block that starts inside another) — used by the discovery walk and the threads decoding ahead of it (cmake: ~560 → ~265 instructions per decode). Linear Sweep's candidate walks decode through a `DecodeCursor` and ask `X86Lifter::ends_alone_with` for an instruction's length and whether its lift alone ends the flow, memoised per thread by the instruction without its displacement / branch target (`alike_key`, as the facts memo is: alike instructions lift alike), and look an address up in the listing only for a `ret` / indirect jump / indirect call (the listing's instructions are the decodes of the same bytes); the known bodies' intervals are built while the prologue boundaries are scanned (cmake walk: 1.25G → 0.40G instructions). Consecutive range-lift runs that one rayon job takes share one `LiftCache` (`map_init`: the shared lift, `map_with_lifter`, the resolver's round-0 lifts). Also: `ByteConst::intersect` finds the equal bytes with a SWAR mask, `x87::is_x87` is a table by mnemonic (built from `kind` of every code), join points of an ascending lift are marked by binary search instead of a hashed target set, `external_entries_at` of an ascending lift steps through `ReferenceManager::refs_to_range` beside the lifted addresses (the resolver's rewalks; the `JumpIndex` form merges its targets the same way and takes the lift's `increasing`), `range_has_indirect_call` decodes through a block decoder, and TLSH counts its buckets with the first two Pearson lookups of each salt in a table by the window's first byte. Tried and dropped: finer range-lift runs (`threads × 64`; no gain), two-byte TLSH tables (fewer instructions, slower: L2 misses). Measured (same build path; callgrind at 1 thread, base → new): python3.12 12.31G → 11.50G instructions (Call Site Annotator `prepare` 4.73G → 4.45G), cmake 22.61G → 20.63G (`prepare` 12.28G → 11.69G); `bench` `Analysis (total)` medians, 4 threads (21 alternating): cmake 1546 → 1453 ms, python3.12 817 → 791, perl 575 → 557, bash 369 → 370, arm64 python3.12 (11) 323 → 310; 2 threads (11): cmake 2294 → 2170, python3.12 1174 → 1168; 1 thread (7): cmake 4078 → 3727, python3.12 1968 → 1904, bash 1045 → 939; CPU time (user + sys) 1.8–8.4 % lower; peak RSS within +3.5 % (per-thread memo tables).

**Call-site flow states and one pass over the shared lift** (`vsa.rs`, `byteconst.rs`, `blockflow.rs`, `shared_lift.rs`, `callsite.rs`): the flow states hold few values (cmake: about one register and 0.05 temporaries at a join), so VSA's `State` keeps its registers as small lists sorted by base (`regs`: known bytes inline, `abs`: the `Set` / `Range` low parts) and its temporaries in a sorted `Vec`, instead of `BTreeMap`s, and `eval` computes the abstract value only when an input holds one (a constant or Top otherwise, as the general case gives it); `cfg_const`'s state uses `RegList` (the same sorted list for `RegFile`'s registers) and `ByteMem` is a sorted `Vec`. A dense array of every general-purpose and flag register (`RegFile`-like) was tried for VSA first: +0.5G instructions on cmake (clones, joins and comparisons of the whole array at every edge). `LiftShape` keeps each instruction's `InsnShape` flags as one byte; `LiftMarks` finds once, for an increasing lift, the instruction each jump targets (searched outwards from the jump, `find_near`), the external entries and the calls the function owns, which the round-0 walk (`walk_prefix`), the blocks (`Cfg::build_marked`) and the calls they keep (`keep_owned_calls`) all read (each found them again before, the walk with a `BTreeSet` lookup per lifted instruction). The round-0 walk keeps its `WalkPrefix` (per instruction up to the last owned call: join point, owned call; and whether the lift was plain, made instruction by instruction through the cache), and the resolver's rewalks lift only that prefix (`lift_range` of that many instructions is the whole lift's first ones when it is plain, else the whole budget is lifted and cut) and walk it with those flags, without the lift's external entries or shape (the rewalk lifts are no longer kept whole between rounds). Checked: randomised tests of the new states against the map ones (`state_matches_map_state`, `list_storage_matches_maps`) and of the marked blocks / walk against the shaped ones, and per function against the unfused results on 14 x86 binaries with a temporary checker. Measured (same build path; callgrind at 1 thread, base → new): cmake 20.71G → 18.35G instructions (Call Site Annotator `prepare` 11.69G → ~9.3G), python3.12 11.59G → 10.65G; `bench` `Analysis (total)` medians, 4 threads (21 alternating): cmake 1490 → 1328 ms, python3.12 792 → 761, perl 599 → 562, bash 408 → 385, arm64 python3.12 (15) 327 → 332 (x86 only; noise); 2 threads (11): cmake 2380 → 2196, python3.12 1238 → 1147; 1 thread (9): cmake 4357 → 4045, python3.12 2146 → 2027, bash 1054 → 974; CPU time (user + sys) 5–12 % lower; peak RSS cmake 669 → 571 MB at 4 threads (576 → 454 at 1), others within ±3 %.

**Shapes from the lift cache, fused lift facts, flows up to the owned calls' reach** (`x86.rs` `LiftCache`, `lift.rs` `RangeShapes`, `blockflow.rs`, `shared_lift.rs`): the shared lift's per-function passes over the whole lift (a function is lifted linearly for `lift_budget` instructions, well past its end: cmake 9.6M lifted instructions for 1.05M in the functions) were most of `compute_lifted`'s own cost. `LiftCache` keeps each entry's `InsnShape` by field (`addr`, `sflags`, `target`) with the ascending list of the entries that have flags (`special`), and a range whose instructions are consecutive entries (98 % of cmake's: a function's lift continues the one before it) gets them as a borrowed `RangeShapes` (copied otherwise; `increasing` from the first and last address, a range being a chain); `LiftShape` borrows its addresses and flags (`Cow`) and keeps `special`, so `LiftMarks` (calls, the `AFTER_END` mark after a block end) and `Cfg::build_marked` (block starts found eight marks at a time) step through only the marked instructions. The flows (`cfg_const`, VSA) walk only the blocks that can reach a call the function owns, and those can only be before `LiftMarks::reach`: the end of the block of the last owned call, when no jump after that block targets an instruction up to that call (every path back would take one; else the whole lift) — `Cfg::build_marked_upto` builds only those blocks (cmake: 2.0M of the 9.6M instructions), the snapshots are the same, in order. The lift's `reads_outside_pf` and `InsnShape` are found in `finish_ops`'s pass over the ops (`lift_decoded_facts`; the views it adds are register copies, no flag or control op), and `index_of` pushes the lift where it matches the result. Checked: per function against the shapes, blocks, external entries and full-lift flows of the old code on 24 x86 binaries with a temporary checker, plus `shape_from_cached_shapes_matches_ops`, `flows_up_to_the_reach_match_flows_over_all`, `lift_facts_match_ops`. Measured (same build path; callgrind at 1 thread, base → new): cmake 18.25G → 16.94G instructions, python3.12 10.57G → 9.98G; `bench` `Analysis (total)` medians, 4 threads (21 alternating): cmake 1351 → 1304 ms, python3.12 791 → 769, perl 575 → 562, bash 386 → 378, arm64 python3.12 (31) 343 → 341 (x86 only; noise); 2 threads (11): cmake 2134 → 2063, bash 606 → 554, python3.12 1119 → 1134 (noise); 1 thread (9): cmake 3574 → 3557, python3.12 2184 → 1981, bash 974 → 904 (this VM's timings vary by ±5 % between runs); CPU time (user + sys) 0–7 % lower; peak RSS within ±2 % (cmake 4 threads 585 → 593 MB, 1 thread 458 → 452). Tried and dropped: lazy lifts in the shared lift (an instruction alike one lifted before — by its bytes but for the displacement / branch offset — kept only decoded, lifted when first read): 1.4M of cmake's 1.9M such entries were read later anyway, and the memo lookups cost more than the 0.48M lifts saved (+0.2–0.3G instructions); searching a jump reference's source or a block's jump target outwards from the jump (galloping) instead of by binary search (more instructions).

**Facts from the decode, lifts only where read** (`x86.rs` `X86Lifter::decoded_facts`, `LiftCache::lazy`, `RangeInsn`, `lift_prefixes_lazy`; `shared_lift.rs`, `blockflow.rs`): the shared lift's range walks read of each instruction only its length, `InsnShape` (calls, jumps and their target, block ends), x87-ness and whether it reads a PF it does not write; its passes read the ops of far fewer (the round-0 walk up to the last owned call, the flows' blocks up to the reach, Argument Arity / Calling Convention's prefixes: cmake 1.1M of the 1.9M instructions its caches hold). `decoded_facts` gives those facts from the iced decode for an instruction whose lift cannot fail and is not x87 (`None` otherwise, and the instruction is lifted as before): not x87, the lift fails only on an operand it cannot lift (an unmapped register, a far pointer, a string operand), so every operand being a mapped GPR / XMM register, an immediate, a memory operand or a near branch means it lifts; its control ops are `call` (`CALL`, `CALLIND` for an operand), `jmp` (`BRANCH` to a near target, else `BRANCHIND`), `ret` and the 16 conditional jumps; `jp`/`jnp`/`setp`/`setnp`/`cmovp`/`cmovnp`/`lahf` read PF (an SSE compare writes it first). A `LiftCache::lazy()` cache (the shared lift's) keeps such an instruction decoded and lifts it when first read (a `OnceCell` per entry, `RangeInsn` the `Borrow<LiftedInstruction>` view the passes get); the parity look-back reads only the instructions it steps back over, and `LiftShape::from_shapes` reads an instruction's ops only for several jump targets (it borrowed every call / jump before). Other caches lift every entry as before (Stack Frame's is lazy too since the next round, below). Checked: `decoded_facts_match_lift` (random bytes, biased to prefixes / escapes / jumps, in 64- and 32-bit mode, and every instruction of the test executable's own code: the decode facts equal the lift's), `lazy_ranges_equal_range_lift` (lazy ranges read in random orders equal `lift_range`, with x87, PF readers and failing instructions), and a temporary checker that lifted every lazy entry and compared on 67 x86-64 binaries / libraries (16.5M instructions). Also: a block's state is moved onto its fall-through edge instead of cloned (`propagate_cfg`). Measured (same build path; callgrind at 1 thread, base → new): cmake 16.95G → 16.32G instructions (single-instruction lifts, `lift_decoded_facts`, 2.47G → 1.71G), python3.12 9.97G → 9.73G; `bench` `Analysis (total)` medians, 4 threads (21 alternating): cmake 1310 → 1263 ms, python3.12 732 → 728, perl 584 → 562, bash 383 → 377, arm64 python3.12 (31) 324 → 325 (x86 only; noise); 2 threads (11): cmake 2119 → 2037, python3.12 1070 → 1047, bash 546 → 541; 1 thread (9): cmake 3427 → 3255, python3.12 2102 → 1887, bash 1012 → 982; CPU time (user + sys) cmake 5.7 % lower at 4 threads, others within ±1 %; peak RSS within +2 % (cmake 4 threads 553 → 563 MB: a decoded instruction kept per lazy entry). Tried and dropped: skipping the hash look-ups of the call-site walk's frame sets while they are empty (−0.08 % instructions).

**Walk-local discovery decodes, lazy Stack Frame lifts, radix-sorted references** (`discovery.rs` `Decodes` / `body_set`, `x86.rs` `RangeInsn::lifted_unless_no_const`, `pcoderef.rs` `scan_range`, `stack.rs` `compute_ahead`, `reference.rs` `sort_keyed`): (1) The discovery walk no longer inserts each instruction it decodes into the listing's `BTreeMap` (cmake's Late Discovery: 1.07M inserts, ~600 instructions each with the `Box`): `Listed` decodes every address it is asked for (decoding is pure; an address listed before the run or decoded earlier in it is decoded again rather than looked up — about the same cost) and keeps the new decodes per page of 4096 addresses, a bit per address marking those listed (a page's listed ones read once, by a range of the listing's keys, when the page is first used) or decoded; at the end the pages' decodes are put in address order through a table by the offset in the page (no comparison sort: the walk's order sorted by `sort_by_key` cost 0.4G) and listed in one pass (`Listing::add_unlisted_instructions`); with threads decoding ahead, the walk's own decodes are cut at `Shared::cuts` and merged as one more run per part. A body's set (`body_set`) is made from the runs of chained instructions (each block's), taken in order of their first address and appended, or — a block start walked again — found among those before; anything else (a block run into the middle of an instruction) falls back to the sort (the run-adaptive sort sorted block-sized runs with its quicksort). (2) Stack Frame's lift cache is lazy (`map_with_lazy_lifter`, `with_budgets_lazy`): its budgets' consumers read only a prefix (Argument Arity up to the first call, Indirect Call Resolver up to the last `CALLIND`, Calling Convention 50 instructions, stack / propagation 200) except P-code Reference's scan, whose budget (the body's bytes, ≥ 500) is the largest; `scan_range` asks `RangeInsn::lifted_unless_no_const` for each instruction, which, for one not lifted yet, answers from its decode whether its lift can hold a constant in a section as a `COPY`'s source or a `LOAD` / `STORE`'s address — the lift puts only `0` / `1` (flags), the immediates (and their low 32 / 16 / 8 bits) and the displacement (and its low 32 bits) of a memory operand without an index whose base is none or `rip` there — and lifts it only then (`SectionMap::contains` tests the sections' span first). cmake: 0.54M eager lifts → 0.08M eager + 0.26M more lazy ones (−0.21M lifts). (3) The references grouped by source / target (`add_grouped`) are ordered by an LSD radix sort on the key (passes of ≤ 12 bits, when ≥ 4096 keys span < 2^32; stable over the ascending indices, so the order of `sort_unstable` on `(key, index)`): 291M → 67M instructions on cmake. Checked: the `export` / `decompile-all` / `callsites` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake, arm64 python3.12), `body_set_matches_sorting`, `decodes_sorted_by_address`, `sort_keyed_matches_sort_unstable`, `const_ref_values_cover_lift` (every constant those ops hold is one `any_const_ref_value` tries: 1.2M random instructions biased to moffs / immediate / rip-relative / SIB forms in 64- and 32-bit mode, and the test executable's code; once over 47M random and 150M instructions of 230 x86-64 binaries / libraries), and temporary checkers on 86 x86-64 binaries at 1 and 4 threads (the listing after each discovery run equal to the one before plus every address the walk visited; each function's `scan_range` equal to `scan_lifted` of the fully lifted range; each body set equal to the sorted one). Measured (same build path; callgrind at 1 thread, base → new): cmake 16.31G → 15.59G instructions (Late Discovery 1.35G → 1.03G), python3.12 9.73G → 9.48G; `bench` `Analysis (total)` medians, 4 threads: cmake (31 alternating) 1291 → 1258 ms, python3.12 (21) 733 → 718, perl (21) 556 → 536, bash (31) 390 → 390, arm64 python3.12 (21) 332 → 332; 2 threads: cmake (11) 1919 → 1853, python3.12 (21) 1147 → 1111, bash (11) 566 → 544; 1 thread (9): cmake 3363 → 3147, python3.12 1980 → 1880, bash 953 → 939; CPU time (user + sys) 1–7 % lower; peak RSS within ±4 % (medians). Not done: Dead Code's per-function walk (2.6 % of cmake's instructions, no unreachable block found on cmake / python3.12) and the call-site walks are the next items.

**Dead work skipped in the call-site walk, tail analyzers by table** (`callsite.rs` `walk_prefix` / `resolve_call_sites_iterative_from`, `string_xref.rs`, `tagger.rs`, `capa.rs`, `deadcode.rs`, `arch.rs` `InstructionDecoder::decode_flow`, `x86.rs` `AddrIndex`): (1) The round-0 walk and the rewalks (`walk_prefix`) step over a run from a join point up to the next one that holds no call the function owns once the two things a `Tracker::reset` keeps — `escaped` and `rbp_written`, only ever set — are both set: the next join resets everything else, so the run's effect is never read (cmake: `Tracker::apply` −0.1G). The resolver reads each round's deduplicated view of the call sites once (its count, then the next round's summaries or the result), its sets sized up front; the annotator looks up each call target's signature once. (2) String XRef reads its probe in place from the block (the longest of its probe lengths the block's data holds, as `read_bytes` picks it), finds the NUL with `memchr` and counts the non-printable bytes by table, stopping past a fifth; the Tagger finds its eight case-insensitive needles in one pass over the text (a table of the needles by first byte, the second byte checked first; `ci_needles_found`, as `to_ascii_lowercase().contains` finds them) instead of a lowered copy and eight searches; Capa searches each needle once over the strings joined with NULs (`Haystack`: the first match is in the first string holding the needle; per-string search when a string or the needle holds a NUL) instead of once per import / comment, and borrows the tag kinds before copying the distinct ones; Dead Code merges a body's ranges in one pass when they come sorted (else the sort), skips the sorts of sorted input and marks the block starts it reaches by index (a stack: reachability does not depend on the order). (3) A discovery walk reads only the length, flow and target of an instruction listed or decoded before (`decode_flow`: the iced decode without building a `DecodedInstruction`). (4) `AddrIndex` keeps up to 128 emptied pages for reuse instead of allocating and filling new ones. Checked: the `export` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake, arm64 python3.12), `decompile-all` (bash, python3.12; 1 / 4 threads), `callsites` / `tags` / `capa` (python3.12, cmake), warm-cache runs equal to cold ones; `marked_walk_with_frame_registers_matches_shaped_walk` (random lifts writing `rbp` and passing stack addresses: ~1500 runs stepped over), `ci_needles_match_lowered_contains`, `haystack_finds_the_first_holder`, `body_merge_matches_merge_ranges`, `instruction_decoder_matches_decode_instruction` (now also `decode_flow`). Measured (same build path; callgrind at 1 thread, base → new): cmake 15.59G → 14.58G instructions, python3.12 9.48G → 9.08G; process wall / CPU (user + sys) medians, alternating: cmake 4 threads (25) 1.12 → 1.10 s, CPU 3.23 → 3.16 s; python3.12 4 threads (21) 0.70 → 0.69 s, CPU 2.04 → 1.98; cmake 2 threads (11) 1.79 → 1.77 s; 1 thread (11): cmake 2.96 → 2.88 s, python3.12 1.67 → 1.61; peak RSS within +3 %. Tried and dropped: the listing's instructions inline (`BTreeMap<u64, DecodedInstruction>`: +0.27G instructions on cmake, the 80-byte values moved through the discovery runs, merges and the rebuilt map) or in a chunked arena indexed from the map (+0.32G: the runs still carry them by value; worth it only with per-walk arenas in discovery, at most the ~0.1G of the `Box` allocations); a 64 KiB table for TLSH's last two lookups (no fewer instructions); presizing Discovery's body vectors and `LiftMarks`' call lists (more instructions / RSS).

**Owned-only snapshots, resolver walks reused across rounds** (`shared_lift.rs` `compute_lifted`, `blockflow.rs` `propagate_cfg_with` / `FlowScratch`, `func_lift.rs` `external_entries_sorted_into`, `callsite.rs` `rewalk_functions`, `x86.rs` `X86Lifter::lift_range_lazy`): (1) The shared lift's per-function results no longer go through `BTreeSet`s: the external entries of an increasing lift are the ascending list the jump index finds (kept in a per-thread buffer, the result an exact `Box<[u64]>`), and the addresses whose ownership a cached result is checked against are the lift's call list itself (`LiftMarks::calls`: ascending, with the answer of `owns`; sorted and deduplicated for a lift that does not increase) — the `cfg_const` / VSA snapshots are of call instructions of the lift, so they add none. The flows record a snapshot only at a call the function owns (`OWNED_CALL` mark; the others were made and dropped by `retain`), and `propagate_cfg_with` keeps its edge lists, work list and visit counts in a `FlowScratch` per thread (the per-block `Vec`s keep their capacity; their states are dropped at the end of each run); `LiftShape::from_shapes` / `LiftMarks::new` size `branches` / `calls` / `owned_calls` from the flagged instructions. (2) The resolver's rounds reuse a function's walk of the round before when its parameter summary is the same (a walk reads only its own function's summary: cmake 537 of 811 rewalks), and a plain prefix (`WalkPrefix::plain`) is lifted by `lift_range_lazy`: decoded, the instructions whose facts the decode gives lifted when the walk first reads them (`LazyInsn`, `OnceLock`: the lifts are shared between the rounds' threads), the range lifted as `lift_range` does (`LazyRange::Eager`) when it holds an x87 instruction or a PF reader (cmake: the first rewalk round reads 33.8k of the 48.9k prefix instructions). Checked: the `export` / `decompile-all` / `callsites` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake, arm64 python3.12), `lift_range_lazy_equals_range_lift` (random code with x87, PF readers and failing instructions, read in random orders, with and without the integer PF), and temporary checkers on 116 x86-64 binaries / libraries (the owned-only snapshots equal the filtered full ones, every snapshot address is in the call list) and 453 (every rewalk and every reused walk equal to a fresh eager lift and walk). Measured (same build path; callgrind at 1 thread, base → new): cmake 13.91G → 13.53G instructions, python3.12 8.78G → 8.62G; process medians, alternating, base → new: 4 threads (21) cmake wall 1.12 → 1.09 s, CPU (user + sys) 3.22 → 3.16 s, python3.12 0.68 → 0.66 s, CPU 1.97 → 1.93, bash 0.34 → 0.34, perl 0.49 → 0.50; 2 threads (11) cmake 1.72 → 1.66 s, python3.12 0.96 → 0.97; 1 thread (9) cmake 2.80 → 2.76 s, python3.12 1.73 → 1.64; peak RSS within +2.5 % (medians). Tried and dropped: keeping the `LiftShape` / `LiftMarks` / `Cfg` vectors in per-thread buffers too (−4M instructions: refilling reused buffers with zeros cost what the allocations saved), finding the jump targets of `LiftMarks` by one pass over the addresses after sorting them (+65M: the sort), a branchless binary search over the whole lift or a tighter gallop for `find_near` (no fewer instructions).

**Lift-cache entries keep their index, positions from the cache's address index** (`x86.rs` `LiftCache` / `AddrIndex`, `lift.rs` `RangeShapes::positions` / `PositionFinder`, `blockflow.rs` `LiftMarks`, `func_lift.rs` `external_entries_increasing`): (1) `LiftMarks` finds the instruction each jump targets, and the lift's external entries, through the lift cache's `AddrIndex` when the shapes are borrowed from the cache (the range's instructions are the entries `base..base + len`, so an address's position is its entry less `base` when that is below `len` — what the binary search gives; the index's pages over the range looked up once per lift), and `JumpIndex::external_entries_increasing` asks it whether a jump's target and source are lifted (it stepped through the addresses and binary-searched the sources); `find_near` stays for lifts not from a cache. (2) A `LiftCache` entry keeps its index for the cache's life: the arrays by position (`meta`, `addr`, `sflags`, `target`) start at `base`, dropping the dead front moves only them (25 bytes an entry) and raises `base`; the lifts and decodes sit in a ring by index (a power of two, filled as entries come, doubled when the entries fill it; a slot is used again only once its entry left the arrays), so nothing is renumbered — the map, the links and the flagged list hold indices that never change (an index below `base` reads as none; the map frees a page whose last index is below `base`); a cache past 2^31 indices is renumbered from 0 at a `trim` (`rebase`). Positions, compaction points and the links followed are exactly the old cache's (`cache_matches_old_cache` runs random walks / trims / drops against a copy of it, `x86/old_cache.rs`, including the rebase). Checked: the `export` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake, arm64 python3.12), `decompile-all` (bash, python3.12; 1 / 4 threads), `callsites` (python3.12, cmake), `cache_positions_match_binary_search`, `external_entries_through_cache_index_match`. Measured (same build path; callgrind at 1 thread, base → new): cmake 13.53G → 13.28G instructions (`LiftCache::compact` + its memmoves ~150M → ~1M, `find_near` ~100M, external entries 128M → 54M), python3.12 8.62G → 8.49G; process medians, alternating, 4 threads (21): cmake wall 0.99 → 0.96 s, CPU 2.80 → 2.76 s, python3.12 0.58 → 0.57 s, perl 0.456 → 0.453, bash 0.292 → 0.294, arm64 python3.12 0.283 → 0.291 (x86 only; noise); 2 threads (11): cmake 1.48 → 1.48, python3.12 0.86 → 0.83; 1 thread (9): cmake 2.42 → 2.41, python3.12 1.41 → 1.41, bash 0.74 → 0.73; peak RSS +0.3–3 % (the ring touches up to its power-of-two length). Tried and dropped: a ring sized from the arrays' capacity and initialised when made (+RSS), passing the lift into its slot by value (a memcpy per entry: +0.1G instructions).

**Cheaper single lifts and flow ops, TLSH buckets by vector lookups** (`x86.rs` `finish_ops` / `zero_extend_gpr32_writes` / `decoded_facts` / `LiftCache::index_of`, `byteconst.rs`, `vsa.rs`, `cfg_const.rs`, `callsite.rs`, `tlsh.rs`): (1) A lift whose facts the decode gave (the lazy entries' lifts, `lift_entry`, `LazyInsn`) finishes its ops without recomputing the facts (`finish_ops::<false>`); the pass over the ops marks the ops that write a GPR view or read / write a high byte (a bit per op, every op from the 64th on), and `zero_extend_gpr32_writes` moves the unmarked runs over as they are instead of looking at each op again. (2) `decoded_facts` reads a table by iced `Code` (x87, call, jmp, ret, the conditional jumps, the PF readers, the float → integer conversions) and by register (mapped GPR, XMM, none) built once from `is_x87` / `iced_reg_to_varnode` / `iced_xmm_offset`, instead of the mnemonic match, the x87 table and the register map per operand; the block decoder's common case is inlined into its callers (`decode_in_block`, the rest out of line) and a lazy cache decodes straight into the entry's ring slot (`decode_in_block_into`); `index_of` looks the address's index page up once. A dropped entry's lift is dropped in place (it was moved out first) and the ring keeps its slot mask. (3) The flow states (`cfg_const`'s `RegList`, VSA's registers) find the written register once (the read then the write each searched the list) and skip an unknown value written over a register they do not hold; `eval` reads its inputs through an inlined helper (a call per input before); `byte_mask` is a table; the cheap ops (no output, a view refresh, `is_unmodeled`) return before the call in VSA / `cfg_const` / the call-site `Tracker` (`apply` inlined, `apply_output` / `apply_store` out of line). (4) TLSH counts 64 windows at a time where the CPU has AVX-512 VBMI (`count_vbmi`, runtime detection): each of a salt's three lookups is two `vpermi2b` over the 256-byte table's halves, the buckets stored and counted into four sets of counters; the other windows and other CPUs take the scalar loop (`count_scalar`; valgrind has no AVX-512, so callgrind counts the scalar one). Checked: the `export` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake, arm64 python3.12), `decompile-all` (bash, python3.12; 1 / 4 threads), `callsites` / `info` (python3.12, cmake), `tlsh-diff` on five pairs, `decoded_facts_match_lift`, `cache_matches_old_cache`, `vector_counts_match_scalar`. Measured (same build path; callgrind at 1 thread, base → new): cmake 13.28G → 12.54G instructions (`lift_decoded_facts` 670M → 587M in `lift_decoded` / `zero_extend_gpr32_writes` / `scratch::finish`; `index_of` + `decode_in_block` 837M → 640M; VSA `apply` 535M → 462M, `cfg_const` `apply` 383M → 315M and `Tracker::apply` 271M → 263M before their cheap ops went into the callers' loops (then 355M / 218M / 178M out of line, −0.09G in all), `trim` 115M → 77M), python3.12 8.49G → 8.18G; TLSH of cmake (two hashes, `tlsh-diff`, 1 thread) 0.21 → 0.16 s user; process medians, alternating, base → new: 4 threads (21) cmake wall 1.18 → 1.15 s, CPU (user + sys) 3.40 → 3.20 s, python3.12 0.73 → 0.70 s, CPU 2.06 → 1.95, perl 0.57 → 0.54, bash (31) 0.40 → 0.39, arm64 python3.12 0.37 → 0.35 (TLSH); 2 threads (11) cmake 1.80 → 1.71 s, python3.12 1.02 → 0.98, bash 0.52 → 0.53 (noise); 1 thread (9) cmake 2.73 → 2.63 s, python3.12 1.66 → 1.65, bash 0.79 → 0.80; peak RSS within +2.6 %. Tried and dropped: the flows' reads through a trait inlined into `eval` (LLVM outlined `eval`'s input closure instead: +44M), `eval` restructured to read at three places (+17M), VSA's abstract evaluation out of line (+55M), `bit_mask` by table (−9M on cmake, +2M on python3.12), `walk_cached` with a loop of its own over the links (+5M / +15M).

**Tighter lift-cache walks, flagged-only targets, jump blocks from the CFG** (`x86.rs` `LiftCache` / `walk_cached` / `follow_links`, `lift.rs` `RangeShapes`, `blockflow.rs` `Cfg` / `LiftShape` / `LiftMarks` / `propagate_cfg_with`, `byteconst.rs` `is_view_refresh`): (1) `walk_cached` follows the cache's links in a loop of its own (`follow_links`: the arrays by position borrowed, the indices written into the spare room of the result, no lift in between) and goes straight to `index_of` after an entry just lifted (it has no link yet); the cache keeps an entry's `InsnShape` target only for the entries with flags (`special_target`, beside `special`: one push and 8 bytes less an entry), and a borrowed `RangeShapes` hands out the targets of its flagged instructions (`special_shapes`). (2) `Cfg` keeps the block each jump of the blocks goes to (`br_block` / `br_at`, in the order of `LiftShape::branches`, which is the order of the `BRANCH` / `CBRANCH` ops with a RAM target), so `propagate_cfg_with` reads the successor of a jump instead of binary-searching its target among the block starts (checked against that search in debug builds); `build_marked_upto_with` finds a target's block in a per-thread table set at the block starts (`block_at`); the blocks entered from somewhere unknown are listed (`unknown_blocks`), the edge states are compared in place and moved only onto an edge they change, `LiftShape` borrows the cache's list of flagged instructions, `LiftMarks::new` makes one pass over them, and `is_view_refresh` reads the inputs once and combines its tests without branches. Checked: the `export` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake, arm64 python3.12), `decompile-all` (bash, python3.12; 1 / 4 threads), `callsites` (python3.12, cmake), `cache_matches_old_cache`, the workspace tests. Measured (same build path; callgrind at 1 thread, base → new): cmake 12.64G → 12.47G instructions (`walk_cached` 361M → 291M, `index_of` 608M → 581M, `compute_lifted` with its inlined flows 1106M → 1053M), python3.12 8.22G → 8.13G; process medians, alternating, base → new: 4 threads (41) cmake wall 1.176 → 1.171 s, CPU (user + sys) 3.32 → 3.29 s, python3.12 0.703 → 0.695 s, bash 0.357 → 0.357, perl 0.527 → 0.517, arm64 python3.12 0.349 → 0.350 (noise); 2 threads (21) cmake 1.74 → 1.72 s, python3.12 1.02 → 1.01, bash 0.539 → 0.536; 1 thread (31) cmake 2.79 → 2.72 s, python3.12 1.57 → 1.54, bash 0.767 → 0.774; peak RSS within +2.4 % (this VM's timings vary by ±5 % between sessions). Tried and dropped: `index_of` forced inline into the walks (−0.1G instructions more on cmake, no wall gain and slower on bash), `index_of` returning the entry's `Meta` (+26M). Measured, not adopted: one decode memo shared by the lift caches of Stack Frame and the shared lift (cmake: 2.43M cache decodes of 1.86M distinct addresses, so at most ~0.57M decodes, ~0.1G instructions, saved, for ~48 bytes kept per address, ~90 MB: over the RSS budget); iced has no cheaper length-only decode (`NO_INVALID_CHECK` changes what decodes).

**Cheaper single lifts** (`x86.rs` `lift_iced` / `finish_ops` / `zero_extend_gpr32_writes` / `scratch` / `REG_TABLE`, `x86/bits.rs` `is_bits`): (1) `finish_ops` looks at an op's inputs only for the facts or when the instruction may touch `ah` / `ch` / `dh` / `bh` (`may_touch_high_byte`: such a register operand, or `div` / `idiv` / `lahf` / `sahf`), and `zero_extend_gpr32_writes` writes into the result's room through a small writer (`OpsOut`: each op moved once, given its order as it is written, no copy through the stack, no renumbering pass; the views a GPR write adds in `gpr_views`); `scratch::finish` moves the ops one at a time (a fixed-size copy, `append` called `memcpy` for the two or three ops of a lift). (2) `lift_iced` reads where an instruction goes from a table by iced `Code` (`route`: x87, float → integer conversion, the bit lift; the XMM operand test through the register table), so `x87::kind` and `lift_bits` run only for their instructions; the ops are pushed with an inlined `push_op` (`Vec::push` stayed out of line: ~2.2M calls); `iced_reg_to_varnode` is a table built at compile time (was a `OnceLock` per call); the scratch buffers are one thread-local (`take` inlined, `give`'s rare paths cold). Checked: the `export` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake, arm64 python3.12), `decompile-all` (bash, python3.12; 1 / 4 threads), `callsites` (python3.12, cmake), `pcode` over 30000 instructions at two places of each `.text`, `finish_matches_old` (random instructions, also x87 with a stack depth, and the test executable's code: the ops, their capacity and the facts against the old `finish_ops` in `x86/old_finish.rs`; no lift of an instruction `may_touch_high_byte` rules out has a high byte), `routes_match_lifts` (every `Code`). Measured (same build path; callgrind at 1 thread, base → new): cmake 12.36G → 12.03G instructions (`LiftCache::lift_entry` inclusive 1.31G → 1.00G: `zero_extend_gpr32_writes` 261M → 144M, `scratch::finish` / `take` / `give` 130M → 51M out of line (the rest inlined into `lift_decoded`, 296M → 302M with them), the out-of-line `push_mut` 65M, `x87::kind` 30M and `lift_bits` 54M → 10M), python3.12 8.09G → 7.89G, arm64 python3.12 3.861G → 3.858G; process medians, alternating, base → new: 4 threads (52) cmake wall 1.162 → 1.141 s, CPU (user + sys) 3.26 → 3.17 s, python3.12 0.708 → 0.712 (noise), bash 0.376 → 0.373, perl 0.539 → 0.528, arm64 python3.12 0.367 → 0.355 (noise: x86 only); 2 threads (11) cmake 1.89 → 1.77 s, python3.12 1.03 → 1.05, bash 0.548 → 0.565 (noise); 1 thread (21) cmake 2.92 → 2.85 s, python3.12 1.75 → 1.73, bash 0.878 → 0.884; peak RSS within +3 % (python3.12 4 threads 334 → 342 MB).

**Byte scans from section slices, memoised return tails** (`crt.rs` `candidate_owners`, `rtti.rs` `slots_filter_map`, `addrtable.rs` `scan_section`, `vtable.rs`, `dataref.rs`, `pcoderef.rs` `SectionMap`, `indirect.rs`, `tagger.rs` `ci_needles_found`, `strings.rs`; `reargo-decompile` `structure.rs` `return_tail_into` / `Structurer::is_tail`, `cfg.rs` `is_epilogue_insn`, `reargo-lift` `lift.rs` `InsnText::may_be_epilogue_text`): a fresh profile (self costs grouped by function) showed the small analyzers' scans costing more than their lifts: (1) CRT / main Recovery's owner scan tries only the `E8` / `FF` bytes `memchr` finds (it tried every byte of every block); RTTI, Address Table and VTable read their pointer slots from one `Memory::slice` of the section when one block holds them all (slot by slot otherwise: the same values), RTTI skips its vtable pass when no `type_info` was found and looks up only values within the `type_info`s' address span, Address Table tests a pointer against the sections' ranges merged (a binary search, was a scan of every section), Data Reference rejects a window outside the sections' span before the range scan (as Scalar Reference did), P-code Reference's `SectionMap::classify` is a binary search over the intervals its answer is constant on (each the first section holding it, as the scan picked), the Indirect Call analyzer looks a site's references up once (once per import before), the Tagger's needle search tests a needle's second byte by table before its loop (`SECOND`), and String Search's printable test is a table. (2) Decompile: `return_tail` counts a block's instructions only up to the first past its limits and makes no list for the callers that only ask whether there is a tail (`is_return_tail`), whose answers the `Structurer` keeps per block (`tails`; it was asked ~135 times a function); `is_epilogue_insn` trims only a text that does not start and end with a visible ASCII character, and `may_be_epilogue_text` rules out an `add` / `lea` / `mov` whose first operand is not `rsp` without formatting its text (`epilogue_precheck_admits_every_epilogue_text`: random `mov` / `add` / `lea` / `pop` / `ret` / `leave` encodings with prefixes, 64- and 32-bit). Checked: the `export` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake, arm64 python3.12), `decompile-all` C and `--rust` (bash, python3.12; 1 / 2 / 4 threads), `decompile --ssa` of every bash function, `callsites` (python3.12, cmake), `merged_ranges_match_any_section`, `classify_matches_first_holding_range`, the workspace tests. Measured (same build path; callgrind at 1 thread, base → new): python3.12 7.89G → 7.28G instructions (CRT owner scan ~173M → ~46M, RTTI `prepare` 212M → 105M, Address Table 189M → 69M, Indirect Call 131M → 11M, Data Reference 127M → 39M, Tagger 223M → 185M, VTable 47M → 22M, `find_strings` 102M → 69M), cmake 12.03G → 11.77G (CRT owner scan ~268M → ~131M, Address Table 90M → 33M, RTTI 99M → 59M); `decompile-all` python3.12 (warm cache) 20.81G → 19.99G (`return_tail` 449M self → 41M, `trim_matches` 126M → 0, instruction texts no longer formatted for the epilogue test ~0.15G); process medians, alternating, base → new: analysis 4 threads (21) cmake wall 0.98 → 0.97 s, CPU (user + sys) 2.79 → 2.76 s, python3.12 0.62 → 0.60 s, CPU 1.75 → 1.71, bash 0.31 → 0.31 (CPU 0.83 → 0.80), perl 0.47 → 0.46, arm64 python3.12 0.31 → 0.30 (CPU 0.84 → 0.78); 2 threads (11) cmake 1.59 → 1.56 s, python3.12 0.93 → 0.88, bash 0.51 → 0.49; 1 thread (9–15) cmake 2.53 → 2.55 s (noise: mean 2.53 → 2.50), python3.12 1.47 → 1.38, bash 0.70 → 0.69; `decompile-all` (warm cache) 4 threads (11) python3.12 1.51 → 1.49 s, CPU 5.45 → 5.39, bash 0.56 → 0.52, 1 thread (5) python3.12 5.04 → 4.89 s; peak RSS within ±5 % (medians; cmake 2 threads 521 → 538 MB, perl 268 → 256). Tried and dropped: merging the call-site snapshots of all functions by one stable sort and a bulk map build instead of an entry per snapshot (+22M instructions on cmake: the sort and the moves cost more than the searches).

**Sorted listing for the late walks, flag constants asked once** (`reargo-program` `listing.rs` `Listing::sorted_instructions` / `for_each_sorted_body_instruction`; `loops.rs`, `complexity.rs`, `deadcode.rs`, `panic_like.rs`, `wrapper.rs`, `anti_debug.rs`, `magic_div.rs`, `float_const.rs`, `filler.rs`; `reargo-lift` `x86.rs` `ConstKeep`, `pcoderef.rs` `scan_range`): a fresh profile (self costs by function, cmake 11.87G instructions at 1 thread) showed the analyzers after the last one that lists instructions walking the listing's `BTreeMap` again and again — Dead Code, Loop Detection, Complexity, Panic-Like and Wrapper per function body (`for_each_body_instruction`: a tree lookup per run of ranges and a tree step per instruction), Anti-Debug, Magic Division and Float Constant over all of it (the last two collecting a `Vec` first: 50M). `Listing` now keeps, once asked (`sorted_instructions`), its instructions in address order as two arrays (addresses, pointers to the boxed instructions: 16 bytes an instruction, one walk of the map to make); every method that lists an instruction drops it, and `for_each_body_instruction` reads it once made (a binary search per run of ranges, from the run before, then the array in order: the same instructions, order, repetitions and first-of-range marks as the tree walk). The analyzers from Loop Detection (785) on ask for it (nothing lists an instruction after Linear Sweep, 740); the earlier ones keep the tree walk (a snapshot made before a listing change would be made twice). Filler Bytes reads a filler byte from the section's slice instead of a block lookup per byte. P-code Reference's lazy filter asks `keep(0) || keep(1)` (the flag constants every lift may hold) once per range (`ConstKeep`) instead of per instruction. Checked: the `export` md5s at 1 / 2 / 4 threads (x86 ls / bash / python3.12 / perl / cmake; the arm64 python3.12 of earlier rounds was not on this machine), `decompile-all` C and `--rust` (ls, bash, python3.12; 1 / 2 / 4 threads) and `callsites` (python3.12, cmake) against a base build, `sorted_body_walk_matches_map_walk` (random bodies — unsorted, overlapping, empty and adjacent ranges — against the tree walk; a listed instruction drops the snapshot), `body_walk_matches_range_lookups`, `const_ref_values_cover_lift` (now also `ConstKeep` against `any_const_ref_value`), the workspace tests. Measured (same build path; callgrind at 1 thread, base → new): cmake 11.874G → 11.688G instructions (Loop Detection 173M → 139M self, Complexity 93M → 65M, Dead Code 223M → 201M, Panic-Like 68M → 43M, Anti-Debug 43M → 28M, Filler Bytes 108M → 72M inclusive, the `Vec` collects 50M → 0; the snapshot costs 42M), python3.12 7.368G → 7.287G, bash 3.375G → 3.329G; process medians, alternating, base → new (this VM's timings drift by ±5 % between sessions; two sessions): analysis 4 threads cmake (31) 1.141 → 1.110 s, CPU (user + sys) 3.13 → 3.07 s ((21) 1.173 → 1.192), python3.12 (31) 0.650 → 0.647 s ((21) 0.770 → 0.770), perl (21) 0.561 → 0.546, bash (21) 0.390 → 0.381; 1 thread (15) cmake 2.78 → 2.74 s, python3.12 1.644 → 1.635, perl 1.240 → 1.233, bash 0.867 → 0.878; `decompile-all` (warm cache, 4 threads, 21; no decompiler change) python3.12 1.564 → 1.586 s, bash 0.572 → 0.587 (noise); peak RSS +1–5 % (the snapshot: cmake 437 → 458 MB at 1 thread, 562 → 570 at 4). Tried and dropped (measured, no gain): in the decompiler, a per-thread table indexed by `(space, offset, size)` for `build_ssa`'s slot ids instead of the recent-key cache and the hash map (python3.12 `decompile-all` 19.992G → 19.989G instructions: the 256-entry cache already answers most lookups), and CSE's redirect lookups skipped while no value is redirected (−0.003G); `compute_lifted`'s flow-state copies (~77M of memcpy on cmake) and the `realloc`s (~0.2G, spread over many vectors: Discovery's body vectors, presized before, were rejected) were looked at and left. Not done: `build_ssa` (1.73G self), CSE (1.07G), DCE (0.65G) and `CalleeParams::summary` (0.51G) on python3.12 `decompile-all` have no single hot spot left in their own code — the cost is spread over the per-op work (hashing of value keys, `SmallVec` pushes, bounds-checked indexing).

**The tail after the shared lift, at 4 threads** (`analyzer.rs` `State::STRING_SYMBOLS`, `exception.rs`, `anti_debug.rs`, `vuln.rs`, `callsite_annotate.rs` `annotations` / `merge_all`, `callsite.rs` `seeding_summaries` / `keep_closed_callers` / `dedup_site_refs`, `loops.rs`, `tagger.rs`, `capa.rs` `Haystack`, `format_varargs.rs`, `shared_lift.rs`, `func_lift.rs` `map_functions` / `body_size`, `stack.rs`, `pcoderef.rs`, `indirect_resolve.rs`, `arity.rs`, `discovery.rs` `sort_by_address`; `reargo-program` `comments.rs` `CommentBatch`, `tags.rs` `AddressTagBatch`, `reference.rs`; `reargo-decompile` `pipeline.rs`; `reargo-cli` `cmd_decompile_all`): a per-analyzer timeline (wall, process CPU and so parallelism of each analyzer and each run's `prepare` phase; a temporary tracer, removed) showed cmake at 4 threads using ~2.8 of the 4 cores: the run of 16 `prepare`s around the Call Site Annotator (~450 ms) was near saturated, but the ~210 ms after it ran at ~1.3 cores — the annotator's `apply` formatting its comments, Format Varargs, Argument Arity, Loop Detection's and the Tagger's map inserts, Exception Flow, and a run of its own for Anti-Debug / Vulnerability Patterns, which read `SYMBOLS` and so could not prepare before the annotator (it adds `s_<address>` symbols). (1) Those symbols are a flag of their own, `STRING_SYMBOLS` (part of `SYMBOLS`, the only symbols the annotator writes); Anti-Debug, Vulnerability Patterns and Exception Flow (now split: `prepare` finds the EH helpers' calls and plates, `apply` checks the comment slots and the `@plt` names) read `SYMBOLS.difference(STRING_SYMBOLS)` — they look symbols up by names of their own, none `s_<hex>` — and prepare in the annotator's run. (2) The annotator formats its comments and renderings in `prepare` (in parallel; the program is as at its place: its run starts there; the sites are distinct, so no comment it sets is one it checks), `apply` only inserts them. (3) Loop Detection and the Tagger build their comment / tag maps in `prepare` (`CommentBatch`: the first item of each key; `AddressTagBatch`: grouped by address); `apply` merges them into the program's map, the smaller into the larger (the program's own first, as one by one). (4) Format Varargs scans its sites in parallel (in order), and a shared lift whose results are all still valid skips the runs. (5) The resolver: a site list whose call sites strictly increase has no repeats (a function walks only the calls it owns, between its entry and the next one), so it is kept without a hash set; the seeding summaries and `keep_closed_callers` read the sites in parts in parallel (what a parameter is passed does not depend on the order of the calls); the CFG tracker's and VSA's snapshots merge at the same time, each built at once when no address repeats (else merged in turn), and are freed on another thread. (6) The lift budgets sum each body's ranges (one per instruction) once and in parallel (`map_functions`; Stack Frame made three sums a function), the jump references are sorted by target with the radix sort (`sort_keyed`), a discovery helper still decoding when the walk ends sorts what the walk read by radix (`sort_by_address`), a shared-lift run is a rayon job of its own (`with_max_len(1)`: the last runs spread over the threads instead of one thread finishing a block of them), Capa's comment haystack is built and searched in parts. (7) `decompile-all`: the comment map and the size order are made in parallel (48 → 19 ms of setup on python3.12), stdout goes through one 1 MiB buffer, and a one-shot process leaves the batch's memos and the results to the exit (`program::leaks_on_drop`). Checked: the `export` md5s at 1 / 2 / 4 / 4 threads (x86 ls / bash / python3.12 / perl / cmake; the arm64 python3.12 was not on this machine), `decompile-all` C and `--rust` (ls, bash, python3.12; 1 / 2 / 4 / 4 threads), `--no-structs` / `--structs-per-function` / `-o` (bash, ls), `decompile --ssa` of every bash function, `callsites` (python3.12, cmake, bash; 1 / 4 threads), `semantic-diff`, `tags` / `capa` / `ioc`, and the `analyze` lines against a base build from the same path; `overlapped_pipeline_matches_serial`, `merged_snapshots_match_merging_in_turn`, `seeding_summaries_match_one_pass`, `sort_by_address_matches_stable_sort`, `large_haystack_finds_the_first_holder`, `address_batch_matches_one_by_one`, `set_all_if_absent_matches_one_by_one` (now also the batch), `many_jumps_sorted_by_target_match_the_walk`, the workspace tests. Measured (same build path; process medians, alternating, base → new; two sessions): 4 threads cmake (21) 1.116 → 1.036 s (−7.1 %), (25) 1.094 → 0.987 (−9.8 %), CPU (user + sys) 3.08 → 3.08 / 3.02 → 2.92; python3.12 (21) 0.699 → 0.668 (−4.3 %), (25) 0.677 → 0.648 (−4.2 %); perl 0.512 → 0.475 / 0.484 → 0.462; bash 0.360 → 0.333 / 0.358 → 0.330 (−7.6 % both); 2 threads (11) cmake 1.53 → 1.55, python3.12 0.97 → 0.94; 1 thread (9–11) cmake 2.60 → 2.71 / 2.71 → 2.64, python3.12 1.46 → 1.45 / 1.40 → 1.41 (noise); callgrind at 1 thread cmake 11.689G → 11.677G, python3.12 7.241G → 7.234G instructions; `decompile-all` (warm cache, 4 threads, 21) python3.12 1.525 → 1.502 / 1.449 → 1.417 s, bash 0.568 → 0.547 / 0.592 → 0.580 (within this VM's ±5 %); peak RSS −3 to +1 %. Tried and dropped: an ordered work-stealing scheduler for the range-lift runs (each worker a block of runs in order with one lift cache, stealing the back half of the largest block): no wall gain, CPU +4 % and peak RSS +7–21 % (caches held across steals, then a fresh one per steal); Format Varargs's results computed ahead by the annotator (its exactness rests on the shared lift's validity check, the cost it would save). Not done: FLOSS-lite's early computation sometimes outlasts its place (cmake 0–36 ms waited: the pool is busy with discovery then), the listing's `BTreeMap` rebuild at the end of each discovery run (~15–25 ms serial on cmake's Late Discovery), and the Tagger / Capa run (~22 ms, CPU-bound at ~2.8 cores).

**Critical path at 4 threads, round 2** (`manager.rs` / `analyzer.rs` `Analyzer::runs_last`, `tlsh.rs` `build_buckets` / `chain_checksum`, `discovery.rs` `speculate_loop`; `reargo-program` `listing.rs` `add_unlisted_instructions_cut` / `put_in_order`, `symbol.rs` `SymbolTable::add_all`; `references.rs` `add_unless_keyed`, `addrtable.rs`, `dataref.rs`, `strings.rs`, `string_rename.rs`, `linear_sweep.rs`, `complexity.rs`, `capa.rs` `import_haystack`; `reargo-decompile` `pipeline.rs` `decompile_all_with_options`): a fresh per-analyzer / per-phase timeline (wall, process CPU, parallelism; a temporary tracer, removed) showed: (1) the first `prepare` run (Filler Bytes … TLS Variable) held for up to ~50 ms on cmake: the rayon worker running the scope, waiting for its jobs, took TLSH's checksum — one ~60 ms serial chain, the second half of a `rayon::join` started from the early thread — and ran it to its end. TLSH now runs the chain on its own thread and hands only the counts to a thread of its own (`std::thread::scope`, not the pool), the chain is a function of its own (as a closure it compiled to ~17 instructions a byte, not ~10), and TLSH `runs_last`: an analyzer whose writes no analyzer reads (`metadata.tlsh`; properties are kept by key) runs after the last analyzer, its result still listed at its place (only with the overlap: `without_overlap` runs it in place, so `overlapped_pipeline_matches_serial` checks the move); Stack Frame now starts at ~45–55 ms on cmake instead of ~75–95. (2) Late Discovery's end (walk end → listing built) took 70–100 ms on cmake: each decoding thread sorted all its decodes (~0.5M, 20–45 ms under contention) when it ran out of entries — near the walk's end —, then the parts were merged, concatenated (a fresh 16 MB copy, serial) and the map built. Now a thread hands over the decodes the walk read in the order decoded (cut by `Shared::cuts`), and the listing puts each part in order on a thread of its own by rank (`put_in_order`: a bit per address over the part's span, the bits before each word counted, an address's place its rank, the first instruction of an address in priority order kept — the listed ones, then the runs in order —; a stable sort for a sparse span) straight into its share of one buffer (`MaybeUninit` slots, the unused ones `None`, one `set_len`), which the map is collected from in place (`filter_map`, unlike `flatten`, reuses the buffer): 45–50 ms, the map build (~15 ms) the rest. (3) Smaller serial pieces made parallel or overlapped: Capa's import haystack is one sort of (lower-cased, name) pairs over one lower-cased buffer (was two sorts and a `String` per name: 11 → ~6 ms of its ~20 ms run at 4 threads), Complexity formats its properties in `prepare`, String-Hint Rename builds its name set while the candidates' strings are found and makes the bodies' runs in parallel, Linear Sweep's covered bodies likewise, Address Table / Data Reference add their references in bulk (`add_unless_keyed`: present looked up in parallel, the first of each repeat kept, `add_all`: the lists of `add_unless` one at a time), String Search / Scalar Reference add their symbols with `SymbolTable::add_all` (the name map filled on a thread of its own), and `decompile-all`'s setup (maps, comments, callee memo, size order) runs as one `rayon::join` (17–22 → 9–11 ms on python3.12). `decompile-all`'s loop was checked for imbalance and contention: the threads' busy times end within ~2 ms (largest first), and its ~10 % more CPU at 4 threads than at 1 is the machine's (four single-thread runs side by side take as much more), not locks. Checked: the `export` md5s at 1 / 2 / 4 / 4 threads (x86 ls / bash / python3.12 / perl / cmake; the arm64 python3.12 was not on this machine), `decompile-all` C and `--rust` (ls, bash, python3.12; 1 / 2 / 4 / 4 threads), `--no-structs` / `--structs-per-function` / `-o` (bash), `decompile --ssa` of every bash function, `callsites` / `tags` / `capa` / `ioc` (bash, python3.12, cmake; 1 / 4 threads) and the `analyze` lines against a base build from the same path; `overlapped_pipeline_matches_serial`, `many_unlisted_instructions_in_parts_match_one_by_one` (dense and sparse parts, runs in any order, cut at their lowest addresses or given cuts), `keyed_bulk_add_matches_add_unless`, `add_all_matches_add`, `import_haystack_matches_two_sorts`, the workspace tests. Measured (same build path; process medians, alternating, base → new; two sessions): 4 threads cmake (21) 1.019 → 0.974 s (−4.4 %), (31) 0.990 → 0.962 (−2.8 %), CPU (user + sys) 3.02 → 2.98 / 2.97 → 2.92; python3.12 0.631 → 0.637 / 0.627 → 0.596 (noise); bash 0.356 → 0.347 / 0.318 → 0.312; perl 0.467 → 0.463 / 0.443 → 0.448 (noise); 2 threads (11) cmake 1.59 → 1.50, python3.12 0.90 → 0.89; 1 thread (11) cmake 2.73 → 2.57, python3.12 1.47 → 1.41; callgrind at 1 thread cmake 11.672G → 11.660G, python3.12 7.278G → 7.284G instructions; `decompile-all` (warm cache, 4 threads, 15) python3.12 1.419 → 1.420 s, bash 0.541 → 0.540 (no change); peak RSS −6 to +3 %. Tried and dropped: an LSD radix sort (12- or 8-bit digits) or a sort by each run's first address for the decoding threads' order (no faster than `sort_unstable` on ~0.5M triples: memory-bound), the bulk listing path for fewer new instructions than listed ones (python3.12's Late Discovery: 16 → 13 ms, not worth the extra copy at 1 thread), TLSH at the lowest thread priority (`setpriority`, nice 19) with its counts serial: +2–3 % on cmake / python3.12 (and THP stays off, see `no_thp`). Not done: the listing's `BTreeMap` build at the end of a discovery run (~15 ms serial on cmake: its node allocations), Late Discovery's reference thread (`add_all_unpooled`, sometimes ending ~20 ms after the walk), the Tagger / Capa run (~20 ms at ~2.6 cores: its reads are written by the analyzers right before it), the per-analyzer `apply`s between Stack Frame and Late Discovery (~50 ms at ~1.5 cores on python3.12, each a few ms of map inserts).

For profiling, `cargo build --profile profiling` builds release-optimised code with line tables (`target/profiling/re-argo`) for `perf` / `cargo flamegraph`.

Lift sharing (measured, not adopted): Stack Frame and the Call Site Annotator lift the same instructions (python3.12: 638k / 810k single-instruction lifts, of 569k / 680k distinct addresses — the budgets run well past each function's end). A lift is cheaper to materialise now (`PcodeOp` 112 B, `LiftedInstruction` 112 B, ops built in reused per-thread buffers and kept in exact-sized vectors: ~3.9 ops, ~0.55 KB per kept lift; `cargo run --release -p reargo-lift --example liftbench`: ~220 ns/insn lifted and dropped, ~320 ns through a `LiftCache`), and a range the cache cannot lend (an x87 instruction, or the integer PF needed) is built from the cached single lifts instead of lifted afresh per budget. Keeping Stack Frame's lifts for the annotator was measured again on top of that (the opt-in store of branch `claude/shared-lift-cache`): python3.12 1067 -> 1156 ms, peak RSS 324 -> 721 MB; bash 552 -> 566 ms, 196 -> 360 MB (`bench --no-cache`, median of 9). Keeping ~0.55 KB per instruction alive costs more in page faults and cache misses than lifting again; a compact store (~91 B/insn) decodes as slowly as a lift. Not worth retrying without a lift representation an order of magnitude smaller. Also measured without gain (cores are saturated in those windows): larger `range_lift::CHUNK` (fewer lifts at run boundaries, worse balance) and Stack Frame as a split analyzer (its prepare overlapping CRT Pattern / Data Reference / Address Table's).

IR compaction (measured, not adopted): a packed `PcodeOps` arena (72 B `Copy` records behind an `OpRef` view) cost +4.8% instructions in decompile and +4.3% in analysis, wall time noise or worse; `SeqNum` without its address −0.23% (noise); the SSA op / varnode size does not matter (doubled to 128 B, wall unchanged: `build_ssa` is instruction-bound, not memory-bound). Lift reuse across decompiles: ~50% of decompile lifts repeat an earlier one, but only 5.7% recur on the same thread within 4096 lifts, and a global memo would hold ≈250 MB (110 MB packed) against a ~36 MB budget.

#### `coverage <FILE> [--annotated]`

Percentage of executable bytes the analysis decoded, plus per-section breakdown. With `--annotated` also reports comment density and call-rendering count.

#### `workflow [--declared-only]`

List every analyzer in priority order with their declared `provides → consumes` capabilities. With `--declared-only`, skip analyzers whose capabilities are still defaulting to empty.

Validates the pipeline at the end (`Workflow validation: OK` or per-analyzer warnings).

### Findings + categorisation

#### `tags <FILE> [--filter KIND] [--list-types]`

Categorised analyzer findings (Binary-Ninja-style).

| Flag | Purpose |
|---|---|
| `--list-types` | Per-kind count summary across address + function scopes |
| `--filter KIND` | Only tags of this kind (`crypto`, `suspicious`, `library`, `anti_debug`, `noreturn`, `wrapper`, `important`, `loop`, `recursive`, `stack_protected`, `exception`, `bug`, `crash`) |

Output: `scope kind address auto text`.

#### `find <FILE> <QUERY> [--limit N]`

BN-style Command Palette equivalent — cross-search functions, symbols, comments, and tags (case-insensitive substring). Returns one section per category.

#### `signatures [--library LIB] [--export PATH]`

Inspect / export the built-in signature database (~312 entries spanning libc / Win32 / POSIX / libstdc++).

| Flag | Purpose |
|---|---|
| `--library libc` | Filter listing to entries from this library |
| `--export sigs.json` | Write the entire DB to a JSON file (type-archive workflow) |

### Code views

#### `disasm <FILE> [-s ADDR] [-n N] [-A]`

Disassemble N instructions starting at ADDR (defaults to entry point). Format: `0xADDR  bytes  mnemonic operands`.
With `-A`/`--annotate`, append a `; addr=...` comment classifying each referenced address (the branch
target and `[...h]` rip-relative memory operands) as an import (`floorf@plt`), a vtable + demangled
class (`vtable[NodeGraphBiomeSource<Pos2d>]`), code (`fn`), a string, or data — an IDA/Ghidra-style
inline comment column that makes stripped C++ readable without manually cross-referencing addresses.

#### `pcode <FILE> [-s ADDR] [-n N]`

Show lifted P-code IR — the low-level intermediate the analysis stack runs on. Output is one line per P-code op grouped by source instruction.

##### x86-64 lifting coverage

The x86 lifter (`reargo-lift/src/x86.rs`) covers the integer + SSE/scalar-float
instruction mix found in optimised C++ binaries: ALU (add/sub/and/or/xor/not/neg/
inc/dec, **adc/sbb**, **rol/ror**, shifts that set ZF/SF), **one-operand mul/imul**
(full-width D:A product — the MT19937/LCG multiply) and div/idiv, sign-extension
(movsx/movsxd, cbw/cwde/cdqe, cwd/cdq/cqo), **bt**, **setcc/cmovcc** (via a shared
`cc_condition`), **xchg**, atomics (**xadd**, **cmpxchg** — modelled, `lock` is a
dataflow no-op), control flow (jcc incl. **jp/jnp** once `comisd`/`ucomisd` set PF =
`isnan(a)||isnan(b)`), direct/indirect calls (CALLIND with vfn-index annotation),
and SSE: scalar + packed float add/sub/mul/div/sqrt/cmp-to-mask, conversions
(cvt\*2si incl. memory source, cvtdq2ps/cvttps2dq, cvtpd2ps), bitwise
(andps/orps/xorps/andnps + pand/por/pxor/pandn), packed-int (paddd/psubd/**pmuludq**/
psrad), shuffles/unpacks and packed float (lane-exact named intrinsics), the half-register
moves movlps/movhps/movlpd/movhpd, and the **x87** FPU (`src/x86/x87.rs`, WS89: a static
register stack from `lift_range`, 80-bit values, compares to flags, `fistp` rounding by the
control word; lifted one instruction alone, without the range, an x87 instruction that touches
the stack stays unmodelled).

Instructions best left opaque-but-named — lane-precise byte SIMD (`pmovmskb`,
`pcmpeqb`) and bit-scan (`bsr`/`bsf`) — are emitted as **named intrinsics** via
`reargo_core::pcode::intrinsic`: a `CallOther` carrying a tag const + operands + an
output, rendered `out = name(args)` (with `bsr`/`bsf` also setting ZF), so dataflow
stays intact without a verbose unrolled expansion. A genuinely unmodelled op renders
`__unmodeled_insn()` and `int3` renders `__builtin_trap()` — distinct, never
conflated. Validated: across 291 BE world-gen functions (biome node-graph, features,
structure placement, RNG, and the 3-dimension chunk generators) every instruction is
either fully lifted or a named intrinsic — zero opaque `CallOther`.

#### `decompile <FILE> [-a ADDR] [--ssa] [--rust] [-A] [--fast] [--no-structs] [--no-this-index]`

Decompile a function to pseudocode.

| Flag | Purpose |
|---|---|
| `-a ADDR` | Function address (hex). Defaults to entry point |
| `--ssa` | Dump the optimised SSA IR instead of C |
| `--rust` | Emit Rust-style pseudocode instead of C |
| `-A`/`--annotate` | Append a `// 0xADDR=...` comment to each line classifying its address literals |
| `--no-structs` | Print every memory access as `*(T*)(p + k)`: no struct fields, struct definitions, typed pointers or `p->vfn_6(…)` calls (see **Structs**) |
| `--no-this-index` | Do not use the whole-binary index of the classes the callers pass (`this-index`; built once per binary, ~4 s on a 230 MB binary, then read from the cache in ~5 ms) |

Output includes inline `// <comment>` lines from the analysis annotations and call-rendering substitutions (`printf("hi", 42)` instead of `printf@plt()`).

How to read the structured output (x86-64 System V):

* **Control flow** is structured with the post-dominator tree: an `if` closes at its immediate post-dominator, loops are natural loops (`while (c)`, `do … while (c)`, or `while (true)` with `break` / `continue`); a loop whose header is the function's first instruction (WS92: `0x1000: … add rdi, 8; cmp rdi, rsi; jne 0x1000`, or a tail call to itself through the prologue) carries its values round like any other (`rdi = rdi + 8;` in the body), and its stack slots stay named. A `goto label_X;` remains only where the flow cannot nest (irreducible loops, a jump out of two loops, a block shared by two arms that is not their join). A `goto` to a short tail that ends the function (≤ 6 instructions and at most one call, ending in a `ret`, a trap or a call that never returns: `unlock(m); return x;`, `0x4172b40("vector");`) is printed as a copy of the tail instead, and so is a short shared region (≤ 2 blocks / 6 instructions, no call) whose every way out is the end of the enclosing region, `break` / `continue` or a return tail — the same block can therefore appear twice. A block that is only a `jmp` is threaded through. `int3` / `ud2` / `hlt` end the flow.
* **`for` loops** (WS97): a loop whose last block steps registers by constants (`R = R + k`, no other instruction of the loop writing the register or a part of it) prints the steps as the update clause when its test reads one of them: `for (; rdi != rsi; rdi += 0x18) { … }`, `for (rax = 0; rsi != rax; rax++)`, `for (; rbp != 0; r15 += 0x80c, rbp--)`. The update clause runs where the updates did (the end of the body, before the test); a statement after an update in that block reads the stepped value as `R + k` (`rdi = rdi + 0x10; rcx = *(uint32_t*)(rdi - 4);` is `rcx = *(uint32_t*)(rdi + 0xc);` in a `for (…; rdi += 0x10)`). The init clause is the statements `R = X;` right before the loop (past up to two register assignments they do not depend on). A `while` with a `continue` or with statements in its header stays a `while`; a `do … while` becomes a `for` only when its first test is proved to hold — the test with the induction variables at their entry values follows from the condition of a branch every way into the loop passes (`if (rdi != rsi) { do { … rdi += 8 } while (rdi != rsi); }`, `rsi != 0` for `rax = 0; … while (rsi != rax)`, `(int64_t)rsi > 0` for `while ((int64_t)rsi > (int64_t)rax)`), or from constants (`rdi != rdi + 0x128`); `rdx = rdi + (rsi << 3)` after `if (rsi == 0)` stays a `do … while` (`rsi << 3` may be 0). Rust (`--rust`): such a `do … while` is `while c { … }` (updates in place), and `R < n` (unsigned, `R` stepped by one, `n` unchanged in the loop, `R` not read after it) is `for R in a..n`.
* **Calls that never return** end the flow: `_Unwind_Resume`, `abort`, `exit`, `__stack_chk_fail`, `__assert_fail`, `__cxa_throw`, … by import name, and any function whose every path ends in a trap or such a call (found from its code, following calls up to 6 levels, cached per run; unknown counts as returning). The code behind such a call (a landing pad, a cold path, the next function) is not printed as its continuation, so `if (n > max) { throw_length_error(); }` is a guard with no join. Exception landing pads are only reached by unwinding; see **Landing pads**.
* **Tail calls**: a `jmp` out of the function prints as `rax = f(…); return rax;` (or `f(…); return;`); the frame restore before it is not printed. A conditional jump out of it (`cmp al, 1; jne free@plt` before the prologue) prints as `if (al != 1) { free@plt(rdi); return; }`, and an indirect `jmp` that is no jump-table dispatch (no scaled index in it or the straight-line instructions right before it — a scaled load before a branch does not count: `jmp [rax+0x20]` through a vtable) as `rax = (*tmp_510)(rdi);  // vfn[4] (vtable+0x20)` + `return rax;`. The function ends where its `.eh_frame` FDE does, so a `jmp` into the next function is such a tail call, not that function's code.
* **Conditions**: the statements that only compute a branch's condition (the pure ops right before it whose results nothing else reads) are folded into it: `cmp edi, 5; jbe` prints `if (edi <= 5)`, not `var_201 = edi < 5; …; if (tmp_464)`. The flags of a `cmp a, b` read as the comparison itself (`a == b`, `a <= b`, signed `(int32_t)a > (int32_t)b`; a negated integer comparison flips its operator, a float one stays negated with a constant on the right — `!(x > 0.0f)` — and becomes `x <= 0.0f` only when neither side can be a NaN (a non-NaN constant, an integer converted); after `ucomiss a, b` / `comisd`, `ja` reads `b < a`, `jae` `b <= a`, `jbe` `!(b < a)` and `jb` `!(b <= a)`, false / true for a NaN like the CPU). ZF after a float compare is "equal or unordered" and PF "unordered" as on the CPU; the parity check next to it folds: `jne T; jp T` (either order) is one `if (a != b)`, `jp F; je T` reads `a == b` past the parity jump, `cmovne` + `cmovp` is one `(a != b) ? s : d`, `setnp r1; sete r2; and r2, r1` is `r2 = a == b;` (`setp; setne; or`: `a != b`), `jne F; jnp T` with `F` right after the `jnp` is `if (a == b)` to `T`, and `ucomisd x, x` + `jp` is `isnan(x)`; with instructions between the two jumps (they run only when the first does not jump) `jne T; …; jp T` is `if ((a < b) || (b < a))` (ordered and not equal) and then `if (isnan(a) || isnan(b))`; `jbe` / `ja` after the compare reads its `a == b` also when an operand is overwritten in between; a lone `je` (no parity check) prints `(a == b) || (isnan(a) || isnan(b))`. `test r, r` reads `r`. A temporary still printed is read elsewhere too (by another branch, a later block, or a call). Flags read away from their `cmp` (`cmp; je L; jl M` puts the `jl` in the next block, `ZF || SF != OF` read by a `setle`) are the comparison too, when no instruction in between writes over the compared registers; a compared register the subtraction itself overwrites (`sub dword [m], 1; jle`) is kept as `old_1 = tmp_510;` where the flags were computed and read as `(int32_t)old_1 <= 1`. When every reader of a signed compare's overflow flag combines it with the sign flag of the same `cmp` (`cmp esi, ecx; cmovl …; mov ecx, [m]; cmovge …`, or at a join: `cmp a1, b1; jne L; cmp a2, b2; L: jl M`, each `cmp`'s flags joined edge by edge; a `test` on one of the paths, whose OF is 0, contributes the sign of what it tested, `(int64_t)rdi < 0`), the comparison is computed once at each `cmp` and read where the flags were: `lt_0 = (int32_t)esi < (int32_t)ecx; … ecx = lt_0 ? ecx : esi;`, `lt_0 = (int64_t)rdi < (int64_t)rsi; if (rdi == rsi) { lt_0 = (int64_t)rdx < (int64_t)rcx; } if (lt_0)`. An overflow or carry flag still read on its own prints as GCC's exact builtin: `ovf_0 = __builtin_sub_overflow_p((int32_t)a, (int32_t)b, (int32_t)0);` (`__builtin_add_overflow_p(a, b, (uint64_t)0)` for a carry; Rust `(a as i32).overflowing_sub(b as i32).1`). A comparison further up the block folds too when the statements printed between it and the branch write nothing it reads (WS89; no register of it, nor memory when it loads): `var_206 = rax == 0; rcx = *(uint64_t*)rsp; if (!var_206)` is `rcx = *(uint64_t*)rsp; if (rax != 0)`; and so does a comparison of registers / constants in an earlier block that only this branch reads, when its operands keep their values on every path to it (`cmp r12, r13; je L; jb M`: the `jb` reads `r12 < r13`). A flag still printed is a `bool` of its own, named by what it computes (WS90): `lt_N` (`a < b`, signed or not), `le_N`, `eq_N`, `ne_N`, `neg_N` (the sign flag, `x < 0`), `carry_N`, `ovf_N`, else `cond_N` — one name per value (the versions a phi joins share it), so `lt_0` and `lt_1` are two compares, not one register; the numbers count up per kind in the order the function first names them. It is read by several branches / selects, or its operands change before it is read. `var_201` / `var_206` (the machine flags) remain only for a flag whose value comes in from the function's entry. Consecutive tests that jump to the same place merge into one `if (a || b)` / `if (a && b)` when the later test's block holds nothing but its compare; its statements are folded into the condition expression too, only the first test's other statements print before the `if`. A `while (true) { …; if (!c) break; … }` becomes `while (c)` when the header's statements all fold.
* **Switches**: a jump table (`cmp r, N; ja default; lea rcx, [table]; movsxd rax, [rcx+rax*4]; add rax, rcx; jmp rax`, or `jmp [table+rax*8]`) prints as `switch (r13d) { case 0: … case 1: case 3: … default: … }`; the table computation does not print. Also recognised: the window reusing the compared register (`movsxd rsi, [rdi+rsi*4]`; a leftover `tmp_6f00 = rsi; … switch (tmp_6f00)` means the computed target is read later), `jbe dispatch` with the default falling through, a signed bound (`jg`), a byte / word table choosing the slot (`movzx eax, byte [B+rax]`, case `i` = `T[B[i]]`), a table base set once before a loop (`lea r9, [T]`), and no bounds check right before the dispatch: then the index's unsigned range on every path to it decides (a forward data flow over the instructions: `cmp r, N; ja/jae/jb/jbe` bounds `r` on each edge, so do `jg/jge/jl/jle` against a non-negative `N` for a value known non-negative and `test r, r; js/jns`; copies and zero extensions share the bound, `r ± c` moves it when it does not wrap, constants / `and` / `shr` / narrow loads are bounded, calls and other writes are not; a value spilled to the stack and reloaded (`mov [rsp+0x28], rsi` … `mov rsi, [rsp+0x28]`) is the same value, unless the function takes an address of the frame at or below that slot; the cases of the other tables are edges that bound their index, a block no edge reaches is unknown (alignment `nop` / `int3` padding after a jump is never run), and a loop that keeps changing a value makes it unknown) — `cmp edi, 3; ja default` blocks earlier, or comparing `r12d` with the index in `rsi = r12d` spilled and reloaded, gives 4 cases; with no bound found it is an enum switch: no `default:`, the table runs while its entries are instructions of the function, up to the next table the function loads, or as far as the index's range on the paths to it or a `shr r32, k` / `and r, m` computing it right before allows (an `int3` right after the function's code, where an enum switch sends its impossible values, is a case `__builtin_trap();`, and the next function's entry a tail call to it). A byte loaded from a struct field (`movzx eax, byte [rsi+8]`) is the index, not a slot table. A conditional jump falling into the dispatch that does not compare the index (a loop's `cmp [r10+0xc], ebp; jg`) is no bounds check. The table base may be a callee-saved register loaded once (its epilogue `pop` does not count), loaded with the same constant more than once, loaded with different tables on different paths (the constant last written before the dispatch, accepted only when every entry is an instruction of the function), or a register the function also uses for other values (each constant address it gets is tried, and kept when — with that table's cases as edges — the register holds it on every path to the dispatch). A default outside the function (a `.cold` part) is a tail call like a case there. A case outside the function (a `.cold` part) prints as a tail call `rax = 0x…(); return rax;`. In a loop, `break` ends a case; leaving the loop from a case is a `goto` (or a return tail). A table not recognised stays `goto *rax;  // indirect jump` and its cases are not printed.
* **setcc** folds its condition like a branch: `cmp r13b, 1; setne al` is `al = r13b != 1;`, `ucomiss xmm1, [m]; seta [rbx+0x25]` is `*(uint8_t*)(rbx + 0x25) = tmp_700 < xmm1_d;` (a byte register or a stored byte taking a flag or a comparison's temporary).
* **Rust output** (`--rust`) names the same stack slots (`local_30`, `local_30 as u32`, `unsafe { *(&raw mut local_30 as *mut u32) = 1; }`, `&raw mut local_48`, `local_18.as_mut_ptr()`) and folds `setcc` / `cmov` conditions the same way: `al = (rcx != rax) as u8;`, `rdx = if rdx < rsi { rsi } else { rdx };`.
* **cmov** prints as `edi = ((int32_t)edi < (int32_t)esi) ? esi : edi;` (`SELECT`; the lifter emits it directly, a negated condition as the flag with the arms swapped: `cmovne` = `(a == b) ? dst : src`); the condition folds like a branch condition — its temporaries / flags in the block, also when two `cmov`s read one flag — when no instruction in between writes what it reads; else it names the flag (`eq_0 ? …`) or a temporary still printed. SSE `maxss` / `minss` print the same way: `xmm0_d = (xmm1_d < xmm0_d) ? xmm0_d : xmm1_d`.
* **Partial registers**: a write to a register's low byte / word / scalar XMM lane prints as that write (`al = rax == rsi;`, `al = 1;`) — the register names alias, so a later `rax` includes it; with known upper bytes it is the widening (`xor eax, eax; mov al, sil` -> `rax = (uint64_t)al;`). `ah`/`bh`/`ch`/`dh` read byte 1 (`ah = (uint8_t)(rax >> 8);`).
* **Constants** are printed where they are used: `mov edi, 5; call f` is `f(5)` and `mov ecx, 7; mov [rdi], ecx` is `*(uint32_t*)rdi = 7;` (no `edi = 5;` line). A constant a float op reads prints as a float (`x <= 0.0f`, `+ 1.0f`), an added negative constant as a subtraction (`rcx - 6`).
* **A register named in an expression** means its value at that point: a condition never reads a register the statement before it overwrote (`ebx = ebx - 1; if (ebx == 0)` for `dec ebx; je`).
* **Lifter** (x86): flags follow the Intel SDM and are checked against the CPU (`crates/reargo-lift/tests/x86_vs_cpu.rs`): `shl`/`shr`/`sar`/`rol`/`ror`/`shld`/`shrd` set CF/OF (a register count of 0 changes nothing: `ZF = (cl & 0x1f) != 0 ? … : ZF`), `imul`/`mul` CF = OF = the product overflowed, `adc`/`sbb` OF; `rcl`/`rcr`, `bt`/`bts`/`btr`/`btc` (also the bit string `bt [m], r`, whose signed offset may pick another word), `tzcnt`/`lzcnt`/`popcnt` (`tzcnt(x)`, `lzcount(x)`, `popcount(x)`), `bswap(x)`, `clc`/`stc`/`cmc` are modelled, and PF (`(popcount((uint8_t)r) & 1) == 0`; a function whose code reads no PF drops its computation at lift time) with `setp`/`cmovp`/`jp`. Packed integer SIMD is lane-exact as named intrinsics on the whole register: `xmm5 = paddb(xmm5, xmm0)`, `paddd`/`psubd`/`paddq`/`psubq`, `pminub`, `pmaxub`, `pcmpeqd`, `pcmpgtb`, `pavgb`, `pmullw`, `pmaddwd`, `pmuludq`, `psadbw`, `packuswb`, the unpacks (`punpckldq`, `unpcklps`, …), `pshufb`, `movhlps`/`movlhps`; a shuffle takes its immediate last (`xmm0 = pshufd(xmm1, 0x4e)`, `shufps(xmm0, xmm1, 0x44)`), a shift its count (`psrld(xmm0, 3)`, or a register whose low quadword is the count; `pslldq`/`psrldq` shift bytes), `eax = pextrw(xmm0, 3)`, `xmm0 = pinsrw(xmm0, ecx, 5)`. Packed float is lane-exact the same way: `xmm0 = mulps(xmm0, xmm1)`, `addps`/`subps`/`divps`/`minps`/`maxps` and the `…pd` forms, `sqrtps(x)`, the conversions `cvtdq2ps`/`cvttps2dq`/`cvtps2dq`/`cvtps2pd`/`cvtpd2ps`/`cvttpd2dq`/`cvtpd2dq`/`cvtdq2pd` (`xmm1 = cvttps2dq(x)`), `cmpps(a, b, imm)` / `cmppd` (a mask per lane). `movlps`/`movlpd` load the low quadword (`xmm0_q = *(uint64_t*)m`), `movhps`/`movhpd` the high one (`xmm0 = movhps(xmm0, *(uint64_t*)m)`), and their stores write the low / high quadword (`*(uint64_t*)m = (uint64_t)(xmm0 >> 64)`). The 64-bit one-operand `mul`/`imul` (`rdx:rax`) and their CF/OF are checked against the CPU too. The bitwise SSE ops act on the whole register (`xmm3 = xmm3 & xmm5`, `(~xmm2) & xmm3` for `andnps`). SSE3 / SSSE3 / SSE4.1 lane ops are intrinsics the same way (checked against the CPU): `rcpps` / `rsqrtps` / `rcpss` / `rsqrtss` (approximations: the emulator runs the instruction itself, so its bits are the host CPU's), `haddps`/`hsubps`/`addsubps` (and `…pd`), `movddup`/`movshdup`/`movsldup`, `pabsb/w/d`, `phaddw/d`, `phsubw/d`, `psignb/w/d`, `pmaddubsw`, `pmulhrsw`, `palignr(dst, src, imm)`, `blendps`/`blendpd`/`pblendw(dst, src, imm)`, `dpps`/`dppd` (which NaN comes out of NaN inputs is the CPU's own), `insertps`, `roundps(src, imm)` / `roundss(dst, src, imm)`, `pmuldq`, `pmovzx*` / `pmovsx*` (`xmm0 = pmovzxbw(*(uint64_t*)p)`); `eax = movmskps(xmm1)` / `movmskpd`, and SSE4.2 `eax = crc32(eax, cl)` (CRC-32C). A `div` reads the dividend register directly: `edx = eax % ebx; eax = eax / ebx;`.
* **x87** (`long double`): the register stack is lifted with its depth worked out per instruction (a data flow over the function's jumps from an empty stack at the entry), so the values are named by their place from the bottom of the stack — `st0` is the first value pushed, `st1` the next (not `ST(0)` / `ST(1)`, which move with every push) — and a push or pop moves nothing: `fld tbyte [rbx]; fld tbyte [rax]; faddp` is `st0 = *(long double*)rbx; st1 = *(long double*)rax; st0 = st0 + st1;`, `fxch st(1)` is `swap(st1, st0);` (Rust `core::mem::swap(&mut st1, &mut st0);`). Values are 80-bit (`long double`, `f80` in the Rust output) and checked against the CPU (the emulator runs the x87 instruction itself); `fld dword`/`fild` convert exactly (`st1 = (long double)*(uint32_t*)m`), stores round to nearest, `fldz` / `fld1` are `(long double)0.0` / `(long double)1.0`. `fucomi` / `fcomi` set ZF / PF / CF as `ucomisd` does (so `jbe`, `fcmovnb` fold like SSE compares: `st2 = (st0 <= st1) ? st0 : st2`); `fcom` / `fucom` / `ftst` set the condition codes `fpu_c0` / `fpu_c2` / `fpu_c3` that `fnstsw ax` (with TOP) and `sahf` move into the flags. `fistp` rounds as the control word says: the `fnstcw; or 0xc00; fldcw; fistp; fldcw` truncation is followed through memory, so it prints `local_20 = (int64_t)st0;`; a rounding not known is `fist(st0, fpucw)`. `fnstcw` / `fldcw` show as `local_3a = fpucw;` / `fpucw = local_3a;`. A callee whose `long double` result the caller pops (`fstp` right after the call) prints `st0 = ldexpl@plt(0x40);`, a function that leaves a value on the stack at `ret` returns `long double`. Arithmetic is at 64-bit precision, rounded to nearest (the control word's precision / rounding are not applied to it). An instruction whose depth is not known (paths arriving with different depths, code reached only through an unrecovered jump) stays `__unmodeled_insn()`.
* **Atomics**: `lock cmpxchg [m], r` prints as the GCC builtin it is: `eq_0 = __atomic_compare_exchange((uint64_t*)(r14 + 0x28), &rax, r13);` — true and `*m = r13` when `*m` held `rax`, else false and `rax = *m` (`&eax` for a 32-bit operand). When only the next branch reads the flag the call is the condition: `if (__atomic_compare_exchange(…)) {`, `} while (!__atomic_compare_exchange(…));`. `lock xadd` is the load / store pair of the next bullet.
* **Epilogues**: the frame restore before a `ret` (`pop`, `add rsp`, the return-address load) is not printed; the prologue's pushes are.
* **Return type**: `long double` (`return st0;`) when the function leaves an x87 value on the stack at `ret`, or (WS90) when every `ret` straight follows a call (`jmp g`, `call g; pop rbx; ret`) to a callee not known to return in `rax` / `xmm0` and the direct callers pop a value off the x87 stack after calling it (`call f; fstp tbyte [rbx]`): `st0 = g(); return st0;`; `float` / `double` (`return xmm0_d;`) when the function last wrote a scalar float into `xmm0`, else `uint64_t` (`rax`) or `void`; a copy of an argument register into `rax` (`mov rax, rbx` with `rbx = rdi`: a struct returned in memory returns its address, `return this;`) is the function writing it (WS92), so a float left in `xmm0` by a call does not make it `double`. When every `ret` only passes on an unknown callee's result (`return g();`), or leaves a value the function also stored, or the function computed both `rax` and `xmm0` (which was written last is a weak hint), the direct callers decide: one that reads `eax` keeps `uint64_t`, `xmm0` makes it `float` / `double`, callers that ignore it make it `void` (a byte scan for `call rel32`, 10–35 ms on a 230 MB binary, only for those functions); for `return g();` with no deciding caller (a virtual method), the direct callers of `g` decide the same way (up to 4 callees, all agreeing); otherwise the last write stands.
* **Idioms**: `x << n | x >> (w - n)` prints `rotl(x, n)` (`rotr` for a `ror`). A temporary computed only to be copied into a register prints as the register's own statement: `mov rdi, [rbx]` is `rdi = *(uint64_t*)rbx;`, `lea rcx, [rsp+0x30]` is `rcx = rsp + 0x30;` (not `tmp_500 = …; rdi = tmp_500;`). A carry read as a number after a `cmp` (`sbb`, `adc`) prints the comparison inside the arithmetic: `cmp rdi, 0x1f4; sbb rdx, -1` is `rdx = (rdx + 1) - ((uint64_t)(rdi < 0x1f4));`, `cmp edi, esi; sbb eax, eax` is `eax = -((uint32_t)(edi < esi));` (`x - 0` prints `x`, `0 - x` `-x`, and a 32 / 64-bit constant `-k` added or subtracted the opposite `k`). Casts (WS90): an extension of an operand that already has the source type casts once (`(uint64_t)eax`, `(uint32_t)*(uint8_t*)p`, not `(uint64_t)(uint32_t)eax`), the unsigned widening casts under an unsigned cast go (`(uint64_t)(uint8_t)x` for `(uint64_t)(uint32_t)((uint32_t)(uint8_t)x)`), the low bytes of a zero extension are the value extended (`(uint8_t)((uint32_t)*(uint8_t*)p)` is `*(uint8_t*)p`), a constant the signed type holds prints bare (`(int32_t)edi < 5`), and a signed comparison's operand drops an integer cast of the same width under its signed cast (`(int32_t)*(uint64_t*)(rsp + 0x18)`: the value modulo 2^32 as two's complement either way, as GCC / Clang convert). A dereference or a cast folded into a condition prints without parentheses.
* **Addresses and loaded values** print inside the access that uses them: `mov [rsp+0xa0], rsi` is `*(uint64_t*)(rsp + 0xa0) = rsi;`, `add eax, [rbx+0x350]` is `eax = eax + *(uint32_t*)(rbx + 0x350);`, `add dword [rax+8], 1` is `*(uint32_t*)(rax + 8) = *(uint32_t*)(rax + 8) + 1;` — for a temporary read in the same block by loads / stores / plain operations, a call's target or arguments (`rax = (**(uint64_t*)(rax + 0x30))(rdi);`), a named intrinsic's operands (`xmm1 = cvttps2dq(*(uint128_t*)(rsp + 0x30));`) or a `cmov`'s arms (one reader, or two when it is a register plus a constant) whose registers do not change before the reader, a load also with no store or call in between. An indexed address read twice prints in both (`r9d = ((uint32_t*)rdx)[rcx]; rcx = (rdx + (rcx << 2)) + 4;`). An access whose scaled index matches its size is an array element (WS97): `*(uint64_t*)(rdi + (rsi << 3))` is `((uint64_t*)rdi)[rsi]`, a constant of whole elements moves the element (`((uint32_t*)rbx)[rax - 1]` for `*(uint32_t*)((rbx + (rax << 2)) - 4)`), a global table too (`((uint64_t*)0xd838d00)[rcx]`), a byte at `p + i` with `i` a loop counter is `((uint8_t*)p)[i]`; a scale that is not the size (`*(uint32_t*)(p + (i << 3))`, a field of a struct array element) stays raw (Rust: `*(rdi as *const u64).wrapping_add(rsi as usize)`), and a loaded value a flag kept as a statement compares prints in it (`eq_0 = rcx == *(uint64_t*)0xdfbea80;`) — when the comparison is read later in its block (it may fold into a condition there), only if the value cannot change up to the block's end. A temporary copied to a register and also read by stores prints as that register (`lock xadd` of a reference count: `rax = *(uint64_t*)(rdi + 0x10); *(uint64_t*)(rdi + 0x10) = rax - 1;`) when nothing reads or writes the register between the load and the copy. A `tmp_…` still printed has another reader (a condition, a third access) or a register changing in between. The Rust output (`--rust`) prints them the same way.
* **Stack slots** are named when their address is provably the entry `rsp` plus a constant `k` (the stack pointer followed from the entry through `push` / `sub` / `add` and copies, whichever register holds it): `local_<-k>` in hex (`local_30`), the same name at every access of the slot, typed by the widest access starting there. A narrower access at its start casts it (`eax = (uint32_t)local_30;`, `*(uint32_t*)&local_30 = 1;`), one further in goes through its address (`*(uint32_t*)((uint8_t*)&local_30 + 0x4) = 1;`), a frame address is the slot's (`rdi = &local_48;`), and a region only addressed is an array up to the next slot (`uint8_t local_18[0x10];`, `rax = local_18;`). The prologue's pushes print as `local_8 = rbx;`; the stack pointer's own updates are not printed when only these read them (an `and rsp, -32`, a `lea rdi, [rsp+rax]` keep `rsp` named). Above the return address are the stack arguments: `arg_8` is the first (`entry rsp + 8`), each a parameter after the register ones (`f(…, uint64_t r9, uint32_t arg_10)`); an argument region only addressed is `uint8_t arg_8[]` (a `va_list`'s overflow area, an aggregate passed in memory). A landing pad starts with the stack pointer of the call that threw — the one at every call of the body, when they agree — so its slots are the body's (`rdi = &local_58;`).
* **Calls**: `rax = f(…)` / `xmm0 = f(…)` — the return register the callee is found to use (or the one the caller reads; for an import / unresolved indirect call, the one register the caller reads other than as a later call's argument, the other then shows as `__clobbered`). Arguments come from the callee's own code when it is known; an indirect call through a constant function pointer / vtable slot becomes a direct call, and a virtual call on `this` inside a method found in a vtable gets the union of the parameter sets of that slot's implementations (`// vfn[6] (vtable+0x30) e.g. 0x4c19c40`).
* **Imports**: a call to a libc / libm / pthread import (or a one-instruction thunk `jmp import@plt`, printed with the import's name) takes the import's known prototype — its arguments (`pthread_mutex_unlock@plt(rdi)`) and return register (`rax = memcpy@plt(…)`, `xmm0 = sqrtf@plt(xmm0)`); a variadic one (`printf`, `snprintf`, `open`, …) its fixed arguments at least. Other unknown callees take the System V prefix of the registers set up for the call, where a register only partly written (`setne sil`) whose byte the function reads itself is no argument.
* **Signature**: each register class lists its parameters up to the highest one read (`f(rdi, rsi)` even when only `rsi` is used).
* **Structs** (WS91; `--no-structs` turns it off): the pointers of a function are typed by unification — the values one pointer flows through (copies, the versions a phi joins) and the pointers loaded from / stored to one field of one type share a type — and an access `*(T*)(p + k)` through such a pointer (a register or a loaded pointer; not a stack address, which prints as a slot, nor a constant) is `p->field_k` (hex offset), the vtable pointer at offset 0 `p->_vptr`. It is a presentation change only: an access prints as a field where its address prints in place (the base itself, or `p + k` inlined into the access), so `p` is the value at the access; `(uint32_t)p->field_8` / `*(uint32_t*)&p->field_8 = v` is a narrower access at a field's start; a register set to a field's address is `rdi = &rbx->field_98;` (not for a register stepped in place, `rsi = rsi + 4`, unless it is passed to a call). The struct definitions print before the function (`struct struct_0 { uint32_t field_10; // +0x10 … };`, the gaps as `uint8_t _gap_8[0x8];` so the offsets hold): per start, the widest access (≤ 16 bytes), kept when it does not overlap a field kept before (most accessed first, a 16-byte copy last); an access inside a wider field, a negative offset, an indexed element, or an access past the step of a pointer that walks an array (`p = p + 8` of its own type: `// array element: a pointer to it steps by 0x8`) stays `*(T*)(…)`. A field's type is a hint: `struct X*` when the values loaded from / stored to it are pointers of type X (`void*` when dereferenced but no struct), `float` / `double` when every access reads / writes a float, `void** _vptr`, else an unsigned integer of its size. A parameter or register that points to one struct wherever the body assigns it is declared `struct X*`. Across calls: a pointer passed to a callee gets the fields the callee accesses through that parameter, after the function's own (`uint64_t field_20; // +0x20 (used by 0x2000)`). Classes (RTTI): `this` of a method listed in a class's primary vtable is that class (the base of all classes listing it; the struct is named after it, `struct NodeGraphBiomeSource<Pos2d> {  // class from RTTI, vtable 0xd8c4fc8`), so is a mangled method name's (`_ZNK5Shape4areaEv`; `// class from the symbol`), a pointer passed as `this` to such a method (the most derived class), and an object a constructor stores a vtable into (`rdi->_vptr = 0xd8c4fc8;  // vtable of NodeGraphBiomeSource<Pos2d>`), here or in a callee it is passed to (WS92: `C::C(rax)`, a function storing a vtable at offset 0 of its argument; with several — a base class's constructor, an inlined one — the most derived); an object loaded from a field of an object of a known class, when a virtual call is made on it, has the class that class's constructors store in that field (WS92: the functions storing the class's vtable, found by a byte scan for references to it — `lea r, [vtable]` — and the `.eh_frame_hdr` entry covering each, followed for `obj->field_k = new C(…)` or an inlined construction; a base constructor called on `this` one level down); a mangled name types the parameters (WS92: `Scene::add(Circle*, Shape const&)` gives `struct Circle* rsi, struct Shape* rdx`; `// class from the symbol`) and so does a callee's mangled name for the pointer passed to it (`draw(Circle*)`) — stripped binaries have none. WS93: in an x86-64 binary with an `.eh_frame_hdr`, the classes the callers pass (the `this-index` index) type `this` when neither its name nor a vtable does, the other parameters and the results of direct calls (`rax = f(…)` of a function returning objects of one class), and an object loaded from a field of an object of a known class, a virtual call made on it, has the class the index joins over every store into that field when the class's constructors do not say (`this->field_8->vfn_1()` in a non-virtual helper that only `Holder`'s methods call: `= Shape::method_at_1200`); WS94: else, an object loaded from a field of a parameter, a virtual call made on it, has the class every caller put in that field of the object it passes (the index's param fields). The unification does not join, at a phi or through a field, values known to be objects of two classes neither of which derives from the other (WS92: a register reused for two objects); each keeps its class, the joined value has none. a method returning a struct in memory (every `ret` returns `rdi`) has `this` in `rsi`. **Virtual calls**: `rax = rdi->vfn_6(rsi);  // vfn[6] (vtable+0x30)` when the slot is read through the vtable pointer loaded from `rdi` in the same block with no store or call in between and the first argument is the object (the call's `this` is not repeated; the vtable pointer load prints in the call); with the object's class known, the slot's function is named: `= BiomeSource3d::method_at_43fadc0` (its symbol, demangled, when there is one), and a `this` call in a method keeps `e.g. 0x…`. Otherwise the call prints as before: `(**(uint64_t*)(rax + 0x30))(rdi);  // vfn[6] (vtable+0x30)` (also slot 0, `vfn[0]`). WS96: an object loaded from an element of a vector of a class known (`this->field_20[i]`, `*(begin + (i << 3))`, a pointer stepped from begin or `end[-1]`), a virtual call made on it, has the vector's element class from the index, and the class's struct prints the vector's three pointers as `struct Shape** field_20; // +0x20 std::vector<Shape*> begin (end +0x28, capacity +0x30)` (`end of …`, `capacity of …` for the other two). A store to the function's own stack slot between the vtable-pointer load and the call (a spill) does not count. Rust: `unsafe { (*rdi).field_10 }`, `unsafe { (*rdi).vfn_6(rsi) }`, `rdi = unsafe { &raw mut (*rbx).field_98 };` (WS92), `#[repr(C)] struct …`.
* **Landing pads**: when the function has an LSDA (`.gcc_except_table`), each exception landing pad is printed after the body as `/* landing pad 0x41cc1c6: cleanup for the calls at 0x41cc0da..0x41cc113 */ { …; _Unwind_Resume@plt(rdi); }` (`catch (...)`, `catch (std::exception)` for a typed one, `exception specification`); `rax` on entry is the exception object. A jump from a pad back into the body is a `goto` to a label there.

With `-A`, every line that still carries a raw `0x...` literal (an unresolved
call target, vtable pointer, or data reference the renderer couldn't name) gets
a trailing comment classifying it with the same scheme as `disasm -A`:
`import@plt` / `vtable[class]` / `fn` / `string` / `data:<section>`. Literals
below `0x1000` (stack/struct offsets, small constants) are skipped. This makes
the residual addresses in carved-function output readable without cross-referencing.

#### `decompile-all <FILE> [-o DIR] [--rust] [--skip-errors] [--no-structs] [--structs-per-function] [--no-this-index]`

Decompile every discovered function in parallel. With `-o`, writes `<dir>/<name>.c` (and `.rs` if `--rust`); without, streams to stdout with `// === <name> @ 0x<addr> ===` headers. The struct of a C++ class is printed once, its fields merged over every function (first on stdout as `// === structs ===`, `<dir>/structs.h` / `structs.rs` with `-o`); a function's anonymous structs print with it. `--structs-per-function` prints all of a function's struct definitions with it; `--no-structs` as for `decompile`.

#### `cfg <FILE> <ADDRESS>`

Emit a DOT graph of a single function's basic-block control flow. Pipe to `dot -Tpng > out.png` or graphviz.com.

### References / call relationships

#### `members <FILE> <ADDRESS> [--insns N] [--base REG]`

Map an object's field layout from a constructor or method — **no full analysis**. Lists every
`[reg + offset]` member access in the function, grouped by base register and offset, with total /
write / lea counts and a sample instruction. A C++ `this` pointer is a stable base register, so this
reconstructs the object's member layout (which offset holds which sub-object), filling the gap the
decompiler's struct recovery leaves on large constructors. `--base rbx` filters to one register;
scan stops at the first `ret` or `--insns` (default 400). Pairs with `vtable`/`classes` to resolve
"what type is at obj+0xNNN" while tracing an object graph. `--sub` instead reports the **sub-object
construction map** (`offset -> ctor`): it detects both the in-place `lea rdi,[this+off]; call ctor`
and the factory `call make_X(); mov [base+off], rax` patterns, reconstructing the composition tree
so you can find which sub-constructor owns a deep field and recurse. (Caveat: the `lea rdi; call`
pattern can't distinguish a constructor from any other method called on the sub-object — verify.)

#### `whatis <FILE> <ADDRESS>`

Classify what an address is — **no full analysis** — by combining the navigation lookups into one
answer: the containing section + `rwx` perms (and `+offset` into it); for code, the enclosing
function entry (via `func-start`); an import (PLT) name; for a vtable (a `[base-8 -> type_info]`
RELATIVE-reloc chain) the demangled class; a printable string; and a demangled `type_info` name
string. The fast first question to ask about any unknown address before reaching for `vtable` /
`func-start` / `imports` individually.

#### `classes <FILE> [--filter SUBSTR] [--derives SUBSTR] [--slot N]... [--limit N]`

List every C++ class in a stripped **PIE** binary — a Ghidra-style RTTI class browser. Scans the
RELATIVE relocations for Itanium `type_info` name strings, demangles them, and resolves each
class's vtable address. `--filter` keeps only classes whose demangled name contains the substring;
`--limit` caps the count (0 = all). Loader-only; inventories tens of thousands of classes in
~1 s. Use it to locate any class instantly, then `vtable <base>` for its methods, or
`vtable --name <substr>` for a single class's full vtable.

`--derives <substr>` keeps only classes that (transitively) derive from a class whose name contains
the substring, following the Itanium RTTI base pointers (`__si_class_type_info` at `ti+16`,
`__vmi_class_type_info` base array from `ti+24`). `--slot N` (repeatable) appends the target of
vtable slot N to each line — together they list every override of one virtual in one call, e.g.
`classes bds --derives StructureFeature --slot 6` = all 15 BE `isFeatureChunk` implementations.

#### `this-index <FILE> [-a ADDR]... [--rebuild] [--check]`

The classes of `this` (and of the other pointer parameters) of the functions of a stripped x86-64
binary, inferred from their callers (WS93) — the index `decompile` uses. Built once per binary from
the `.eh_frame_hdr` function ranges (BDS 1.26.33.2: 504,513 functions, ~5 s; 1.2 MB) and cached in
`$REARGO_CACHE_DIR`, else `%LOCALAPPDATA%/re-argo` / `$XDG_CACHE_HOME/re-argo` / `~/.cache/re-argo`
(named after the binary and a fingerprint of it; `--rebuild` ignores it). Without `-a` it prints
statistics; `-a ADDR` prints the classes of a function's parameters, of the fields of the objects
passed as them (`param 0 +0x48: …`, WS94) and of its result, or, for a class's vtable address, the
classes of its pointer fields / member objects.

How: each function is decoded linearly and followed with a forward data flow (registers, stack
pointer, 8-byte stack slots): what it passes to each direct call / tail jump (its own argument + k,
a call result, a field loaded from a pointer, a stack object), the vtables it stores, the pointers it
stores into fields, what it returns. Seeds: a method listed in primary vtables (RTTI) has that class
as `this`, a function storing a vtable into its argument (constructor / destructor) that class. A
parameter's class is the join (nearest common base) of what **every** direct caller passes; one
caller passing something unknown, an exported function, an address taken (`lea`, a data pointer),
no direct caller or a vtable listing it makes it unknown. A stack object is the object its first
call made (a constructor's seed, an inlined constructor's / destructor's vtable store, the seeds of
the calls made on it) until its slot is written again. So it is "the class of the objects the callers
are seen to pass": for a base-class method only ever called on one derived class it is that derived
class. WS94 — param fields: the class of the pointer at `+k` of the object every caller passes as a
parameter (a stack object's slot at the call — a pointer of known class, or the address of another
stack object whose vtable is known, e.g. a `std::function`'s `__f_` -> its `__func<Lambda>`; the
caller's own parameter + o, transitively; a call result / loaded object: what the caller stores
there, else the field class of its class), for the offsets the function (or a callee it passes the
object to) loads and uses as a pointer; a load `[arg + k]` then has that class unless the function
itself writes something else there (any non-pointer write of any width, a write at an unknown
offset). Shared libraries (WS94): pointers written by absolute relocations against the image's own
symbols (`R_X86_64_64`; its exported vtables / `type_info`s) are read like RELATIVE ones, and a call
through the image's own PLT stub (its GOT slot bound to a function of the image) is a call to that
function. `--check` (a binary with symbols) compares it with the class of each method's mangled name
(a static method, or a method returning a class by value whose `ret`s do not all return `rdi`,
shows as "unrelated": the check compares `rdi`).
Effects (WS95) and vectors (WS96): what a callee stores into the objects its parameters reach is
composed bottom-up into its callers (setters, emplace, swap, out-of-line constructors). Allocators
(`malloc`, `operator new` by import name; in a stripped binary a function returning one call's
result that ≥ 8 functions construct objects in, and the slots of a global allocator object it calls)
return fresh memory; deallocators (`operator delete` by name, or by shape: it only hands its argument
to unknown code, and ≥ 8 deleting destructors give it `this`) have no effects. Fresh memory whose
pointers are stored into an object's fields is that field's buffer: what is stored into it (an
inlined or out-of-line `push_back` / `emplace_back` slow path, `reserve`, `assign`, a copy
constructor's `memcpy`) are the container's elements; pointers into one buffer at `+o`, `+o+8`,
`+o+16` are a `std::vector`'s `{begin, end, capacity}`. **Element classes** `(class, begin offset) ->
class`: the join of what is stored through any of the three fields' pointers (by the class's
functions and their callees), unknown when unknown code writes the buffer (an escape, a fill, a
number) or the begin is re-pointed to a buffer of unknown elements (the end / capacity fields stay in
the begin's buffer, the container's invariant); only such triples have element classes.
`this-index` prints `element classes N (vectors M)` and `-a <vtable>` the `element +0x…` lines.
`REARGO_ELEM_EXPLAIN=0x<vtable>` / `REARGO_ELEM_STATS=1` (with `--rebuild`) print what each function
contributes / the buffers by cause.
`REARGO_THIS_EXPLAIN=0x…,0x… this-index <bin> --rebuild` prints what each caller passes as `this`.

#### `func-start <FILE> <ADDRESS> [--max-back N]`

Find the entry of the function containing `ADDRESS` **without full analysis** — for huge stripped
binaries where an arbitrary `carve --start` window bisects the function (it treats its own first byte
as an entry). Backward-scans for a function boundary (`ret` / `int3` / `nop` padding) then verifies a
clean linear decode from the candidate to `ADDRESS`, rejecting candidates whose path crosses a
`ret`/unconditional-jump boundary. Prints the entry and a ready-to-run `carve --address` line.
`--max-back` bounds the backward scan (default 8192). Heuristic — can mis-fire if a `0xC3`/`0xCC`/
`0x90` byte sits mid-instruction; verify the prologue with `disasm` when in doubt. Pairs with
`xref-scan` (find a reference site) → `func-start` (find its enclosing function) → `carve` +
`decompile`.

#### `xref-scan <FILE> <TARGET> [--limit N]`

Fast cross-reference scan to `TARGET` **without the full analysis pipeline** — for multi-hundred-MB
binaries (e.g. the 222 MB BDS server) where `xrefs` is impractical. Linear-disassembles the
executable sections and reports each instruction whose resolved operand points at `TARGET`:
`[BRANCH]` (direct call/jmp), `[RIPMEM]` (rip-relative memory ref), `[IMM]` (absolute immediate).
Also **relocation-aware**: reports `[PTRREL]` vtable / function-pointer slots whose target comes
from a PIE `R_X86_64_RELATIVE` reloc addend (invisible to a byte search, since the on-disk slot is
zero) — so virtually-dispatched functions with no direct call site are still found. `--limit`
bounds the code-hit count (default 200; 0 = unlimited). Loader-only, ~1.5 s on a 222 MB image.

#### `vtable <FILE> <ADDRESS>`

Recover the C++ vtable around `ADDRESS` (Itanium ABI, PIE). Given any address inside a vtable — e.g.
a `[PTRREL]` slot reported by `xref-scan` — it walks back to the vtable base via RELATIVE
relocations, reads the RTTI `type_info`, demangles the class name, and lists the virtual method
targets (with the queried slot marked). Works on a stripped PIE binary because the slots come from
`.rela.dyn` addends, not the (zero) on-disk bytes. Reverse-lookup recipe to go from a class *name* to
its vtable: `search --text <Name>` → mangled `type_info` name string → `xref-scan` that (gives
`type_info+8`) → `xref-scan` the `type_info` (gives `vtable_base-8`) → `vtable <base>`. Or skip the
chase entirely: **`vtable <bin> --name <substr>`** scans the RTTI name strings, matches the
demangled class name against the substring, and prints every matching class's vtable + vmethods in
one shot (the address arg is optional when `--name` is given).

#### `xrefs <FILE> <ADDRESS>`

Cross-references to and from the given address. Output:
```
References TO (N):
  0xADDR [TYPE] from <name>
References FROM (N):
  0xADDR [TYPE] to <name>
```

Types: `CALL`, `JUMP`, `READ`, `WRITE`, `READWRITE`, `FALL`, etc.

#### `callgraph <FILE> [--dot] [--scc] [--around ADDR] [--depth N]`

Show the program's call graph.

| Flag | Purpose |
|---|---|
| `--dot` | DOT output |
| `--scc` | Print strongly-connected components (mutual / direct recursion) |
| `--around ADDR` | Restrict to the BFS neighbourhood around `ADDR` |
| `--depth N` | Neighbourhood radius (only relevant with `--around`, default 2) |

#### `backtrace <FILE> <ADDRESS> [--depth N] [--max-paths N]`

Print every reverse-callgraph path leading INTO `ADDRESS`. Paths sorted shortest first, with cycle detection. Default depth 6, default max-paths 256.

#### `callsites <FILE> [-t ADDR] [-n N] [-i N] [--callbacks]`

Every Call site with statically-resolved argument values: the full 8-byte value of `rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9` (`mov esi, 0x2a` gives `rsi = 0x2a`, `lea rax, [str]; mov rdi, rax` the address; a write to `al` / `ah` changes only that byte), `?` when not proven. The walk is straight-line: values do not cross a jump target or a call (a stack slot does, unless a stack address escaped); a parameter is seeded from its callers only when every direct call passes the same constant and the function is not exported, address-taken or jumped to. The `CallSiteAnnotator` (decompile's `printf("hello %d\n", 42)`) also fills `?` from a CFG join of the block states.

| Flag | Purpose |
|---|---|
| `-t ADDR` | Only call sites whose target matches `ADDR` |
| `-n N` | Only call sites that resolved ≥ N args (default 0) |
| `-i N` | Inter-procedural propagation iterations (default 3) |
| `--callbacks` | Only show sites passing a known function entry as an arg (callback registries) |

### Data / strings

#### `hexdump <FILE> <ADDRESS> [LENGTH]`

Hex dump at address (default length 256 bytes). Standard 16-byte-row format with ASCII gutter.

#### `search <FILE> [--hex PAT] [--text PAT] [-n N]`

Search for byte / text patterns. `--hex "48 8b ?? 24"` accepts `??` wildcards. `--text "password"` accepts regex.

### Diff

#### `diff <A> <B>`

Compare two binaries at byte / symbol-table level.

#### `semantic-diff <A> <B> [-k KINDS]`

Compare at SSA / decompiled-function level. Reports per function: `identical`, `renamed`, `tweaked`, `modified`, `added`, `removed`. Default filter: everything except identical. Override with `-k renamed,tweaked,modified`.

### Export

#### `export <FILE> [-o PATH]`

JSON dump of the analysis. See "JSON output" above for keys.

#### `export-xml <FILE> [-o PATH]`

Ghidra-compatible XML format.

### Emulation / debugging

#### `emulate <FILE> [-s ADDR] [-n STEPS] [-b ADDR …]`

Step the P-code emulator up to `-n` steps from `-s`, breaking at any `-b` addresses (repeatable).

#### `gdbserver <FILE> [-s ADDR] [-l HOST:PORT]`

Open a GDB RSP server for the emulator. Default listen `127.0.0.1:1234`. Compatible with `gdb-multiarch` and `lldb` (via remote).

#### `debug <FILE> [-s ADDR]`

Interactive REPL: step, breakpoints, registers, memory. Useful for hands-on triage; AI agents normally prefer `emulate` because it's deterministic.

### Manual correction layer

#### `annotate <FILE> [--rename ADDR=NAME] [--func ADDR] [--not-func ADDR] [--cc ADDR=CONV] [--comment ADDR=TEXT] [--import FILE] [--keep-mangled] [--list] [--clear]`

Edit the persistent override sidecar `<binary>.gra.json` that re-applies on every subsequent analysis.

| Flag | Purpose |
|---|---|
| `--rename ADDR=NAME` | Set a permanent name for an address (repeatable) |
| `--func ADDR` | Force-define a function at ADDR (repeatable) |
| `--not-func ADDR` | Remove a bogus auto-discovered function (repeatable) |
| `--cc ADDR=CONV` | Set calling convention (repeatable) |
| `--comment ADDR=TEXT` | Attach a plate comment (repeatable) |
| `--import FILE` | Bulk import `(offset, name)` pairs from JSON / "addr name" text. Auto-demangles C++ / Rust (use `--keep-mangled` to preserve mangled form) |
| `--list` | Print the current overrides and exit |
| `--clear` | Remove all overrides |

#### `iterate <FILE> [--apply] [--max-rounds N]`

Auto-correction fixpoint. Each round runs analysis, surfaces probable analyser mistakes (calls to undiscovered functions, false-positive tiny functions, …), persists them to the sidecar if `--apply`, and re-runs. Without `--apply` it's a dry-run that just prints proposals. Default max-rounds 5.

#### `carve <FILE> [--address ADDR] [--start ADDR] [--end ADDR] [--size N] [--format elf|raw] [-o OUT]`

Extract a single function (or an arbitrary VA range) into a small standalone file so a size-limited tool — notably GUI Ghidra, whose importer truncates / chokes on very large images (e.g. the ~222 MB Minecraft Bedrock server) — can analyse just the bytes of interest. The carved bytes keep their **original virtual address**, so RIP-relative operands and call targets still resolve to the correct addresses.

Range selection (pick exactly one):

| Flags | Behaviour |
|---|---|
| `--address ADDR` | Run analysis, carve the discovered function's full extent (entry → last body byte) |
| `--address ADDR --size N` | Function entry + explicit byte length (skips analysis — fast on huge binaries) |
| `--start ADDR --end ADDR` | Arbitrary half-open VA range (skips analysis) |
| `--start ADDR --size N` | Arbitrary range by length (skips analysis) |

Output container (`--format`):

* `elf` (default) — a minimal ELF placed at the original VA. Ghidra and re-argo both auto-detect arch + base, so the carved function round-trips with **zero manual setup**: `re-argo carve big --start 0x… --size N -o f.elf` then `re-argo decompile f.elf --address 0x…`. Emitted for any source arch (even a PE source), since Ghidra loads ELF for every architecture. For x86-64, the carve also **bundles the function's referenced read-only constant pool / jump tables** as extra `.rodataN` segments at their original VAs (coalesced, capped 256 KB), so float-constant resolution and other rodata-dependent analysis work on the carve without analysing the whole image — e.g. the BDS noise functions decompile with `f32 const 0.015625 (= 1/64)` annotations.
* `raw` — the bytes verbatim; the command prints the Ghidra "Raw Binary" import parameters (SLEIGH language id + base address) to type into the import dialog.

Default output path is `<file>.carved.<addr>.elf` (or `.bin` for `raw`). Use the fast `--start/--size` form on multi-hundred-MB binaries — it never runs the analysis pipeline, only the loader. The `--address`-only form must analyse the whole binary to find the function's extent.

### Scripting / integration

#### `script <FILE> <SCRIPT.grs>`

Run a sequence of analysis commands from a `.grs` script file.

#### `mcp <FILE>`

Speak Model Context Protocol over stdio. Loads the binary, runs analysis, then reads newline-delimited JSON-RPC 2.0 requests on stdin and answers on stdout. Tools exposed: `list_functions`, `decompile_function`, `disassemble`, `find_xrefs`, `list_symbols`, `get_program_info`. Designed for embedding re-argo into AI hosts (Claude Code, etc.).

### Other

#### `registers <FILE>`

List the registers known to the architecture (varnode offsets, sizes).

#### `patch <FILE> <ADDR> [--bytes "BB BB …"] [--asm "INSTR"] [-o OUT]`

Patch a binary file. Either supply raw `--bytes` (hex, space-separated) or `--asm` (single instruction to assemble). With `-o` writes a copy; without, overwrites in place. `analyze`-like passes on the patched binary verify the result.

#### `taint <FILE> [-a ADDR] [-p N]`

Mark `N` parameter registers as tainted at function `ADDR` and propagate through SSA to dangerous sinks (libc functions known to mishandle untrusted input). Useful for vulnerability triage.

### Capability detection (cross-tool inspiration)

#### `entropy <FILE>`

Per-section Shannon entropy report (bits/byte, 0.0–8.0). Sections above 7.0 are flagged `high entropy`; above 7.5 `likely packed`. Use as the first triage step on samples of suspected packers (UPX, Themida, VMProtect, ASPack, …). Also surfaces `metadata.entropy_<section>` for the JSON `export`.

#### `rop <FILE> [--depth N] [--max-insns N] [--useful-only] [--contains TEXT] [--limit N] [--kinds rop|jop|cop|all]`

Find ROP / JOP / COP gadgets in executable sections (x86 / x64 only). Walks every terminator (`ret` for ROP, `jmp reg`/`jmp [mem]` for JOP, `call reg`/`call [mem]` for COP), disassembles backwards, and prints the resulting instruction sequences in ROPgadget / ropper format.

| Flag | Purpose |
|---|---|
| `--depth N` | Bytes to walk back from each terminator (default 20) |
| `--max-insns N` | Maximum instructions in each gadget (default 6) |
| `--useful-only` | Filter to mnemonics actually useful for ROP (pop / mov / xor / add / …) |
| `--contains TEXT` | Substring filter applied to the gadget text |
| `--limit N` | Maximum gadgets to print (default 200, 0 = unlimited) |
| `--kinds` | Gadget kinds: `rop` (default), `jop`, `cop`, or comma-list, or `all` |

Use `--contains "pop rdi"` to find arg-1 set-up gadgets directly. Output rows are prefixed with `[rop]` / `[jop]` / `[cop]` to identify the terminator. ARM / MIPS / RISC-V binaries return an empty list.

#### `capa <FILE> [--namespace SUBSTR]`

Capa-style capability report. Built-in rules match against discovered imports, strings, and tags; each match is one rule namespace + name, e.g. `host-interaction/file-system/read-file`. Filter by namespace substring (`--namespace persistence`).

#### `packer <FILE>`

DIE / PEiD-style packer detection. Matches the entry-point byte signature and section-name layout against a curated table (UPX, ASPack, FSG, MEW, PECompact, Petite, Themida, VMProtect, ASProtect, Enigma, NSPack, Mpress, Yoda's Crypter). Surfaces the matched packer in `metadata.packer` and the evidence channel (`entry-point` or `section-name`) in `metadata.packer_evidence`. Also surfaces a `Suspicious` tag on the entry point so the regular `tags` report picks it up.

#### `embedded <FILE> [--limit N]`

Binwalk-style embedded-file scan. Walks every initialized byte looking for the magic-byte prefixes of common formats — ELF / PE / Mach-O droppers, ZIP / GZIP / 7z / RAR / XZ / Zstandard / BZIP2 archives, PNG / JPEG / GIF / PDF / SQLite resources, Java class files, POSIX tar. Output: `address kind magic` rows. Useful for triaging malware droppers, firmware blobs with embedded resources, and installers with appended archives.

#### `vuln <FILE>`

Cwe_checker-style vulnerability pattern report. Tags functions that call known-dangerous APIs with the matching CWE id:

* **CWE-78** — `system`, `popen`, `exec*`, `WinExec`, `ShellExecute*`
* **CWE-120** — unchecked `strcpy` / `strcat` / `wcscpy` / `wcscat` / `lstrcpy*` / `StrCpy*`
* **CWE-134** — `sprintf` / `vsprintf` (buffer + format)
* **CWE-242** — `gets`
* **CWE-330** — predictable RNG (`rand` / `random`)
* **CWE-426** — `LoadLibrary*` (DLL hijack risk)
* **CWE-676** — `strtok`, `tmpnam`, `mktemp`, `alloca`

Read the JSON `export`'s `tags{}` map (kind = `bug`) for the machine-parseable form.

#### `ioc <FILE> [--kind KIND]`

Indicator-of-compromise extractor. Classifies every discovered string into one of: `url`, `ipv4`, `ipv6`, `email`, `registry-key`, `named-pipe`, `mutex`, `win-path`, `posix-path`, `eth-addr`, `btc-addr`, `user-agent`, `domain`. Each match is also surfaced as a Custom `ioc` tag at the string address — `tags --filter ioc` produces the same listing for downstream consumers. The full list is also written to `metadata.iocs` for JSON export.

| Flag | Purpose |
|---|---|
| `--kind KIND` | Show only this kind (e.g. `--kind url`, `--kind registry-key`) |

#### `tlsh-diff <FILE_A> <FILE_B>`

Compare two binaries by TLSH (Trend Micro Locality-Sensitive Hash). Lower distance means more similar:

* `< 30` → likely same family
* `< 50` → related
* `> 100` → unrelated

Useful for malware-family clustering and "is this a recompile of that?" sanity checks. Complements `imphash` (which clusters by IAT identity) with content-based similarity that survives small recompiles. Both hashes are also surfaced in `metadata.imphash` and `metadata.tlsh` for JSON export.

PE binaries additionally get **Authenticode signature info** surfaced via `metadata.signed` / `metadata.cert_count` / `metadata.cert_subjects` (the latter is a newline-joined `CN=…, O=…, C=…` list extracted heuristically from the PKCS#7 blob). The `triage` and `info` commands print these alongside the hashes.

#### `floss <FILE> [--min-length N] [--with-add] [--limit N] [--include-printable-source]`

FLOSS-lite obfuscated-string decoder. Brute-force XOR (and optionally ROL / ADD) decode of every read-only data section, surfacing strings that don't appear in a plain `strings` pass because they're stored encoded. Real malware often XOR-encodes its C2 URLs / config blobs against a single-byte key; this command catches that pattern.

| Flag | Purpose |
|---|---|
| `--min-length N` | Minimum decoded-string length (default 8; 0 is treated as 1). Higher values cut noise. |
| `--with-add` | Also try ADD-decode (default off — ADD is rarer and noisier) |
| `--limit N` | Print only the first N hits (default 200, 0 = unlimited) |
| `--include-printable-source` | Drop the conservative "encoded bytes must be non-printable" filter — noisier but catches the edge case where the encoded form also happens to be printable |

Tradeoffs: the default filter chain (3 distinct consecutive letters, ≥ 60% alnum, ≥ 4 distinct chars overall, non-periodic, encoded source mostly non-printable) keeps the false-positive rate manageable but still produces noise on large binaries — expect hundreds of "candidate" lines on a /bin/* target. Real obfuscated strings stand out (URLs / paths / API names). Raise `--min-length` or invoke with `--with-add` only when chasing specific encodings.

The pipeline-wide analyzer surfaces `metadata.decoded_string_count` and adds a single summary `obfuscated-string` Custom tag at the entry point — per-string tags would flood the tags report, so detailed inspection goes through this CLI command.

#### `yara <FILE> <RULES.yar> [--sample N]`

Scan the binary with a YARA-lite ruleset. Supports a strict subset of the YARA rule language:

* Text strings: `$x = "literal"` (case-sensitive) and `nocase` modifier.
* Hex strings: `$x = { 4D 5A ?? ?? 50 45 }` with `??` full-byte, `4?` high-nibble, `?A` low-nibble wildcards.
* Conditions: `$x`, `not E`, `E and E`, `E or E`, parens, `any of them`, `all of them`, `N of them`.
* Comments: `// line` and `/* block */`.
* `meta:` blocks are parsed but ignored.

Unsupported syntax (`wide`, `fullword`, regex strings, `for any i in (...)`, imports/sections helpers, `filesize`) errors out at parse time with a clear message — callers can fall back to the full YARA binary.

| Flag | Purpose |
|---|---|
| `--sample N` | Show only the first N string-match offsets per rule (default 5) |

Output is one block per matched rule with per-string hit counts and the first N offsets. Useful for malware-family classification using community rulesets that fit the supported subset.

### Java / JVM bytecode

The `jvm` group analyses Java class files. Every subcommand takes a `.jar` / `.zip` / `.class` file (the container is detected by magic bytes, not by extension). These are **loader-only** commands: they parse the class path on every run and never touch the native analyzer pipeline, so they are unaffected by the analysis cache and `--no-cache`. Class names are dotted (`a.b.C`) or internal (`a/b/C`); nested classes use `$` (`a.b.C$Inner`). `--limit` defaults to 200 (0 = unlimited) where present.

#### `jvm classes <FILE> [--filter TEXT] [--resources] [--limit N]`

List the classes in a JAR (or a single `.class`): name, method count, field count, superclass (`(interface)` marker). `--filter` is a case-insensitive substring of the dotted name; `--resources` lists the non-class entries (JSON, images, shaders, …) instead.

```
Classes in rt.jar: 6 found (19470 total)
  class                                                            meth  fld  extends
  java.util.ArrayList                                                50    7  java.util.AbstractList
```

#### `jvm class <FILE> <CLASS>`

One class: access flags, kind, class-file version (and Java release), superclass, interfaces, source file, generic signature, direct-subtype count, then every field (with `static final` constant values) and every method as a Java-style signature plus its JVM descriptor and code size.

#### `jvm disasm <FILE> <CLASS> [--method NAME]`

`javap -c`-style disassembly: per method `max_stack` / `max_locals` / code size, `// line N` markers from the line-number table, one instruction per row (`pc: mnemonic operand`, constant-pool operands resolved to names), and the exception table. `--method` keeps only methods with that name (all overloads). pc values are **decimal** bytecode offsets, as in `javap`.

```
  public int size()  [()I]
    max_stack=1 max_locals=1 code=5 bytes
    // line 284
       0: aload_0
       1: getfield        #2 java/util/ArrayList.size:I
       4: ireturn
```

#### `jvm strings <FILE> [--pattern TEXT] [--constants] [--limit N]`

String literals (`ldc`) with the method and line that push each one. `--pattern` is a case-insensitive substring filter; `--constants` additionally lists `static final String` constant fields (`ConstantValue`), which have no `ldc` site.

```
  "Index: "     com.sun.org.apache.xerces.internal.impl.dv.util.ByteListImpl.get(I)Ljava/lang/Object;:100 @pc 38
```

#### `jvm xrefs <FILE> <TARGET> [--limit N]`

Every bytecode site that references a class, method or field (invokes, `getfield` / `putfield` / `getstatic` / `putstatic`, `new` / `checkcast` / `instanceof` / `anewarray`, `ldc` class constants). `TARGET` forms:

| Form | Matches |
|---|---|
| `a.b.C` | any use of the class |
| `a.b.C.name` | method or field `name` of that owner, any overload |
| `a.b.C.name(I)V` | exactly that descriptor (overload) |
| `*.name` | `name` on any owner |

A spec without `(` is a class target when it names a class in the JAR **or** its last segment starts with an upper-case letter (the Java naming convention, which is how classes outside the JAR — JDK, libraries — are recognised, e.g. `java.io.File`); otherwise the last segment is the member name and the rest the owner (`java.util.List.add` = owner `java.util.List`, member `add`). A constant field with an upper-case name (`a.b.C.FOO`) therefore reads as a class unless the JAR defines no such class and you write `*.FOO`.

```
References to java.util.ArrayList.grow: 1 found
  java.util.ArrayList.ensureExplicitCapacity(I)V:241 @pc 22    invokespecial   java.util.ArrayList.grow:(I)V
```

#### `jvm callees <FILE> <METHOD> [--depth N] [--external]`

Methods called by `METHOD` (`a.b.C.method` or `a.b.C.method(desc)`; all overloads of an unqualified name are printed), as an indented tree. Default `--depth 1` (direct calls only). Calls into classes outside the JAR are hidden unless `--external` is given, and then carry an `[external]` marker and are not expanded. A method already expanded earlier in the tree is marked `[seen]` and not expanded again (recursion guard).

```
Callees of java.util.ArrayList.add(Ljava/lang/Object;)Z
  invokespecial   java.util.ArrayList.ensureCapacityInternal(I)V (line 464)
    invokestatic    java.util.ArrayList.calculateCapacity([Ljava/lang/Object;I)I (line 233)
```

#### `jvm callers <FILE> <METHOD> [--depth N] [--via-external]`

Reverse call tree: methods that call `METHOD`, one row per calling method in `pkg.Cls.method(desc):line @pc N` form. Virtual dispatch counts: a call whose owner is a supertype or subtype of the target's class is included and marked `[via a.b.Owner]`. Supertypes outside the JAR (`Runnable`, `kotlin.jvm.functions.Function1`, …) are skipped unless `--via-external` — every lambda shares them, so following them lists every caller of every lambda. `[seen]` marks a method already visited in the tree. Default `--depth 1`.

#### `jvm subtypes <FILE> <CLASS>`

Classes extending / implementing `CLASS` (class or interface, transitive), as a tree indented by depth; interfaces carry an `(interface)` marker.

**Output notes (all `jvm` commands)**

* A call/reference **site** prints as `pkg.Cls.method(desc):line @pc N` — the descriptor keeps obfuscated overloads (`a`, `a`, `a`) apart; `:line` is omitted when the class has no line-number table. `N` is the decimal bytecode offset of the instruction, the same number `disasm` and `javap -c` show.
* Markers: `[external]` (callee outside the JAR, `callees --external`), `[seen]` (already expanded / visited), `[via X]` (`callers`: reached through supertype/subtype `X` of the target's owner).
* Class entries that fail to parse are skipped with one `warning: N class entries failed to parse` line on stderr; the rest of the JAR is still analysed.
* Lists stop at `--limit` with `... N more (raise --limit to see them)`.


---

## Workspace structure

| Crate | Purpose |
|-------|---------|
| `reargo-core` | Address model (Segmented / Overlay / Map), P-code IR (74 opcodes), 31+ data types, SpaceId constants |
| `reargo-loader` | ELF / PE / Mach-O / COFF / raw binary, DWARF, PDB, FLIRT, relocations, source map, hashing |
| `reargo-arch` | 6 architectures (x86 / ARM / RISC-V / MIPS / PPC / SPARC), .cspec / .pspec / .ldefs parsers, register overlap map, assembler |
| `reargo-program` | Program model, symbols, references, comments, **tags**, **call_renderings**, bookmarks, undo / redo, diff, SARIF, metadata, history |
| `reargo-analysis` | 68 analyzers (function discovery, signatures, CRT patterns, linear sweep, VSA, CFG const tracker, tag categoriser, RTTI, vtable, calling conv, coverage, anti-debug, exception, crypto, …) |
| `reargo-lift` | x86 / AArch64 / ARM32+Thumb / MIPS32 / RV32IMC / PPC32 / SPARC32 → P-code lifter (memory operands, flags / conditions, branches, compressed / Thumb insns) |
| `reargo-emulator` | Full P-code emulator, breakpoints, watchpoints, traces, snapshots, GDB RSP client+server, syscalls, hooks |
| `reargo-decompile` | CFG / SSA / dominator / dataflow, 6 optimisation passes (DCE / fold / propagate / strength / algebra / CSE), struct / array type recovery, taint analysis, **annotation pass-through to C/Rust**, **signature-aware call rendering**, SARIF |
| `reargo-sleigh` | SLEIGH runtime: PackedDecode, DecisionNode, ContextDB, .sla zlib decode, ParserWalker |
| `reargo-jvm` | Java class-file parser + JAR loader (constant pool, bytecode decoder / `javap -c` formatter, descriptors, cross-reference / call-graph / subtype index); independent of the native pipeline, used by `re-argo jvm …` |
| `reargo-cli` | ~40 CLI commands (see top of this file) |

## Architecture decisions

- **SpaceId::CONST / RAM / REGISTER / UNIQUE** constants — no magic numbers
- **SmallVec<[VarnodeData; 3]>** for PcodeOp inputs
- **Arena-based SSA** with `VarId` / `OpIdx` type aliases
- **goblin** for binary parsing, **iced-x86** for x86, **capstone** for ARM / MIPS / PPC / SPARC / RISC-V
- **gimli** for DWARF, **quick-xml** for Ghidra XML specs, **flate2** for .sla decompression
- **serde** for JSON / SARIF serialisation
- **petgraph** for CFG / callgraph (Tarjan SCC, dominator computation)
- Edition 2024, `thiserror` for error types
- Analyser pipeline: priority-sorted `Vec<Box<dyn Analyzer>>`. Analyzers declare optional `provides()` / `consumes()` capability lists; `workflow --declared-only` validates ordering.

## Common gotchas (for the AI agent)

1. **Hex addresses are required for `<ADDRESS>` arguments.** `0x401000` or `401000`, not `4198400`.
2. **`symbols` defaults to loader-side only.** On stripped binaries, pass `--all` to see analyzer-recovered names.
3. **`cargo run` rebuilds on every invocation.** Build once (`cargo build --release`) then call `target/release/re-argo` directly to avoid the rebuild cost. The CLI is idempotent; the first command on a binary runs the analysis pipeline, later ones read its results from the on-disk analysis cache (a rebuilt `re-argo` starts with a cold cache).
4. **`--thumb` is only relevant for 32-bit ARM binaries.** x86_64 / aarch64 binaries should not pass it.
5. **`analyze` runs the same pipeline `decompile`, `xrefs`, `tags` etc. already run internally**, and the results persist between invocations in the on-disk analysis cache (`~/.cache/re-argo`, see **Analysis cache**): only the first command on an unchanged binary pays for the pipeline. `analyze` always re-runs it (per-analyzer lines on stderr) and refreshes the cache; `--no-cache` / `REARGO_NO_CACHE=1` bypass it. Editing the `<binary>.gra.json` override sidecar (part of the key) re-runs the pipeline once.
6. **`find <bin> <query>` is case-insensitive substring** — use it before more specific queries; it's the fastest way to locate a name across functions / symbols / comments / tags in one shot.
7. **`backtrace`'s default depth is 6**. For hub functions in large binaries, you'll likely need `--depth 12 --max-paths 1024`.
8. **`decompile`'s output includes inline analyzer comments.** Lines starting with `// printf(format=…)` or `// stack-protected` are the annotations; the actual code line is the next one.
9. **`tags --filter` uses the canonical kind slug** (`anti_debug`, not `Anti-Debug`).
10. **`signatures --export <PATH>`** writes the built-in DB to JSON. Edit and re-attach via `annotate --import` to layer a project-specific type archive. Direct in-process `attach` is on the roadmap but not yet wired into the CLI.
11. **x86 SSE / scalar-float is lifted to FLOAT_* p-code.** `addsd/mulss/divps/cvtsi2sd/comisd/movaps/…` decompile to real `xmm0 = xmm0 * xmm1` / `(float)` / compare expressions, and `pcode` shows `FLOAT_MULT`/`FLOAT_ADD`. XMM registers print as `xmm0..xmm15`. Packed ops (`…ps`/`…pd`, integer SIMD, shuffles) are lane-exact named intrinsics (`xmm0 = mulps(xmm0, xmm1)`, `pshufd(xmm1, 0x4e)`), checked against the CPU; see **Lifter** under `decompile`. This makes float-dominated code (e.g. game world-gen noise) decompilable where it previously produced opaque traps.
