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
`type_info+8`) → `xref-scan` the `type_info` (gives `vtable_base-8`) → `vtable <base>`.

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
| `--min-length N` | Minimum decoded-string length (default 8). Higher values cut noise. |
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
11. **x86 SSE / scalar-float is lifted to FLOAT_* p-code.** `addsd/mulss/divps/cvtsi2sd/comisd/movaps/…` decompile to real `xmm0 = xmm0 * xmm1` / `(float)` / compare expressions, and `pcode` shows `FLOAT_MULT`/`FLOAT_ADD`. XMM registers print as `xmm0..xmm15`. Caveats: packed (`…ps`) ops are modeled as a single whole-register FLOAT op (not per-lane SIMD) and shuffles (`shufps`/`unpcklps`/…) as a Copy of the source — good enough to keep dataflow connected and read the math, but not bit-exact for lane permutes. Unmodeled SSE (min/max, andn, integer-SIMD) still falls to `CallOther`. This makes float-dominated code (e.g. game world-gen noise) decompilable where it previously produced opaque traps.
