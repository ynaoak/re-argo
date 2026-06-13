# RE-Argo

CLI-native reverse-engineering + malware-triage toolkit in Rust. Built atop a Ghidra-equivalent multi-arch analysis pipeline, with a binary-clustering / capability-detection / IoC-extraction layer on top. CLI-first, library-first — no GUI. Binary name: `re-argo`.

This document is the **AI agent operations reference**. It documents every CLI command with enough specificity that an LLM can choose the right command, supply correct flags, parse the output, and chain commands without trial-and-error.

---

## Quick reference: pick the command by goal

| Goal | Command |
|---|---|
| "What is this binary?" (format, arch, runtime, libc, language) | `info <bin>` |
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
| "All call sites with resolved arguments" | `callsites <bin>` |
| "Strings in the binary" | `strings <bin> --min-length 6` |
| "Search for bytes or text" | `search <bin> --hex "48 8b ?? 24"` / `--text "password"` |
| "Hexdump at an address" | `hexdump <bin> 0x401000 64` |
| "Symbols (loader-side or analyzer-recovered)" | `symbols <bin> [-k func] [--all] [--name VTbl]` |
| "Imports / exports" | `imports <bin>` / `imports <bin> --exports` |
| "Sections" | `sections <bin>` |
| "Coverage of analysis (% of executable bytes decoded)" | `coverage <bin> [--annotated]` |
| "Wall-clock benchmark of analysis" | `bench <bin>` |
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
| "Persist manual corrections to a sidecar" | `annotate <bin> --rename 0x401000=my_main --func 0x401080` |
| "Auto-correct fixpoint loop" | `iterate <bin> --apply --max-rounds 5` |
| "Run multi-command script" | `script <bin> queries.grs` |
| "Speak MCP to a host like Claude Code" | `mcp <bin>` |

---

## How to call the CLI

```bash
cargo run --release -- <command> <args>     # development build
target/release/re-argo <command> <args> # after a release build
```

All commands accept `--thumb` (global flag, before the subcommand or after) to decode ARM code in Thumb mode. Most users on x86_64 / aarch64 binaries can ignore it.

Hex addresses can be written as `0x401000`, `401000`, or `0X401000`.

---

## Build, test, lint

```bash
cargo build              # debug build of the entire workspace
cargo build --release    # release build of the entire workspace
cargo test --workspace   # ~600 tests across all crates
cargo clippy --workspace --all-targets -- -D warnings
```

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

Display format, architecture, bits, entry point, section count, symbol count, plus compiler / runtime fingerprints when detected.

Example output keys: `Format`, `Architecture`, `Bits`, `Entry Point`, `language`, `runtime`, `libc_version`, `pe_product`, `pe_version`, `build_id`, `compiler`.

#### `summary <FILE>`

One-screen digest: format / entry / runtime identity / function counts (total, named %, no-return, thunks) / annotation densities / hottest functions by fan-in / recursive-cluster count.

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
2. Warm the in-memory cache for subsequent commands
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

#### `bench <FILE>`

Wall-clock + per-stage breakdown of the analysis. Output keys: `Load`, `Analysis (total)`, `Analyzers OK / Err`, `Functions`, `Instructions`, `References`, `Comments`.

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

#### `disasm <FILE> [-s ADDR] [-n N]`

Disassemble N instructions starting at ADDR (defaults to entry point). Format: `0xADDR  bytes  mnemonic operands`.

#### `pcode <FILE> [-s ADDR] [-n N]`

Show lifted P-code IR — the low-level intermediate the analysis stack runs on. Output is one line per P-code op grouped by source instruction.

#### `decompile <FILE> [-a ADDR] [--ssa] [--rust]`

Decompile a function to pseudocode.

| Flag | Purpose |
|---|---|
| `-a ADDR` | Function address (hex). Defaults to entry point |
| `--ssa` | Dump the optimised SSA IR instead of C |
| `--rust` | Emit Rust-style pseudocode instead of C |

Output includes inline `// <comment>` lines from the analysis annotations and call-rendering substitutions (`printf("hi", 42)` instead of `printf@plt()`).

#### `decompile-all <FILE> [-o DIR] [--rust] [--skip-errors]`

Decompile every discovered function in parallel. With `-o`, writes `<dir>/<name>.c` (and `.rs` if `--rust`); without, streams to stdout with `// === <name> @ 0x<addr> ===` headers.

#### `cfg <FILE> <ADDRESS>`

Emit a DOT graph of a single function's basic-block control flow. Pipe to `dot -Tpng > out.png` or graphviz.com.

### References / call relationships

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

Every Call site with statically-resolved argument values.

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
3. **`cargo run` rebuilds on every invocation.** Build once (`cargo build --release`) then call `target/release/re-argo` directly to avoid the rebuild cost. The CLI is idempotent and re-runs the analysis pipeline per invocation.
4. **`--thumb` is only relevant for 32-bit ARM binaries.** x86_64 / aarch64 binaries should not pass it.
5. **`analyze` runs the same pipeline `decompile`, `xrefs`, `tags` etc. already run internally.** Use it when you want the per-analyzer summary line on stderr, not to "warm up" a cache (there is no persistent cache between invocations — except for the `<binary>.gra.json` override sidecar).
6. **`find <bin> <query>` is case-insensitive substring** — use it before more specific queries; it's the fastest way to locate a name across functions / symbols / comments / tags in one shot.
7. **`backtrace`'s default depth is 6**. For hub functions in large binaries, you'll likely need `--depth 12 --max-paths 1024`.
8. **`decompile`'s output includes inline analyzer comments.** Lines starting with `// printf(format=…)` or `// stack-protected` are the annotations; the actual code line is the next one.
9. **`tags --filter` uses the canonical kind slug** (`anti_debug`, not `Anti-Debug`).
10. **`signatures --export <PATH>`** writes the built-in DB to JSON. Edit and re-attach via `annotate --import` to layer a project-specific type archive. Direct in-process `attach` is on the roadmap but not yet wired into the CLI.
