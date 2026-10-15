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

#### `bench <FILE> [--top N]`

Wall-clock + per-stage breakdown of the analysis. Output keys: `Load`, `Analysis (total)`, `Analyzers OK / Err`, `Functions`, `Instructions`, `References`, `Comments`.

Followed by a per-analyzer table (after a 72-char `-` rule), slowest first: `Analyzer  ms  % total  status` (`ms` 1 decimal, `% total` of `Analysis (total)`, `status` ok/err). `--top N` limits it to the N slowest (default 15, 0 = all).

For profiling, `cargo build --profile profiling` builds release-optimised code with line tables (`target/profiling/re-argo`) for `perf` / `cargo flamegraph`.

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
psrad), shuffles/unpacks and packed float (lane-exact named intrinsics), and the half-register
moves movlps/movhps/movlpd/movhpd.

Instructions best left opaque-but-named — lane-precise byte SIMD (`pmovmskb`,
`pcmpeqb`) and bit-scan (`bsr`/`bsf`) — are emitted as **named intrinsics** via
`reargo_core::pcode::intrinsic`: a `CallOther` carrying a tag const + operands + an
output, rendered `out = name(args)` (with `bsr`/`bsf` also setting ZF), so dataflow
stays intact without a verbose unrolled expansion. A genuinely unmodelled op renders
`__unmodeled_insn()` and `int3` renders `__builtin_trap()` — distinct, never
conflated. Validated: across 291 BE world-gen functions (biome node-graph, features,
structure placement, RNG, and the 3-dimension chunk generators) every instruction is
either fully lifted or a named intrinsic — zero opaque `CallOther`.

#### `decompile <FILE> [-a ADDR] [--ssa] [--rust] [-A]`

Decompile a function to pseudocode.

| Flag | Purpose |
|---|---|
| `-a ADDR` | Function address (hex). Defaults to entry point |
| `--ssa` | Dump the optimised SSA IR instead of C |
| `--rust` | Emit Rust-style pseudocode instead of C |
| `-A`/`--annotate` | Append a `// 0xADDR=...` comment to each line classifying its address literals |

Output includes inline `// <comment>` lines from the analysis annotations and call-rendering substitutions (`printf("hi", 42)` instead of `printf@plt()`).

How to read the structured output (x86-64 System V):

* **Control flow** is structured with the post-dominator tree: an `if` closes at its immediate post-dominator, loops are natural loops (`while (c)`, `do … while (c)`, or `while (true)` with `break` / `continue`). A `goto label_X;` remains only where the flow cannot nest (irreducible loops, a jump out of two loops, a block shared by two arms that is not their join). A `goto` to a short tail that ends the function (≤ 6 instructions and at most one call, ending in a `ret`, a trap or a call that never returns: `unlock(m); return x;`, `0x4172b40("vector");`) is printed as a copy of the tail instead, and so is a short shared region (≤ 2 blocks / 6 instructions, no call) whose every way out is the end of the enclosing region, `break` / `continue` or a return tail — the same block can therefore appear twice. A block that is only a `jmp` is threaded through. `int3` / `ud2` / `hlt` end the flow.
* **Calls that never return** end the flow: `_Unwind_Resume`, `abort`, `exit`, `__stack_chk_fail`, `__assert_fail`, `__cxa_throw`, … by import name, and any function whose every path ends in a trap or such a call (found from its code, following calls up to 6 levels, cached per run; unknown counts as returning). The code behind such a call (a landing pad, a cold path, the next function) is not printed as its continuation, so `if (n > max) { throw_length_error(); }` is a guard with no join. Exception landing pads are only reached by unwinding; see **Landing pads**.
* **Tail calls**: a `jmp` out of the function prints as `rax = f(…); return rax;` (or `f(…); return;`); the frame restore before it is not printed. A conditional jump out of it (`cmp al, 1; jne free@plt` before the prologue) prints as `if (al != 1) { free@plt(rdi); return; }`, and an indirect `jmp` that is no jump-table dispatch (no scaled index in it or the straight-line instructions right before it — a scaled load before a branch does not count: `jmp [rax+0x20]` through a vtable) as `rax = (*tmp_510)(rdi);  // vfn[4] (vtable+0x20)` + `return rax;`. The function ends where its `.eh_frame` FDE does, so a `jmp` into the next function is such a tail call, not that function's code.
* **Conditions**: the statements that only compute a branch's condition (the pure ops right before it whose results nothing else reads) are folded into it: `cmp edi, 5; jbe` prints `if (edi <= 5)`, not `var_201 = edi < 5; …; if (tmp_464)`. The flags of a `cmp a, b` read as the comparison itself (`a == b`, `a <= b`, signed `(int32_t)a > (int32_t)b`; a negated integer comparison flips its operator, a float one stays negated with a constant on the right — `!(x > 0.0f)` — and becomes `x <= 0.0f` only when neither side can be a NaN (a non-NaN constant, an integer converted); after `ucomiss a, b` / `comisd`, `ja` reads `b < a`, `jae` `b <= a`, `jbe` `!(b < a)` and `jb` `!(b <= a)`, false / true for a NaN like the CPU). ZF after a float compare is "equal or unordered" and PF "unordered" as on the CPU; the parity check next to it folds: `jne T; jp T` (either order) is one `if (a != b)`, `jp F; je T` reads `a == b` past the parity jump, `cmovne` + `cmovp` is one `(a != b) ? s : d`, `setnp r1; sete r2; and r2, r1` is `r2 = a == b;` (`setp; setne; or`: `a != b`), `jne F; jnp T` with `F` right after the `jnp` is `if (a == b)` to `T`, and `ucomisd x, x` + `jp` is `isnan(x)`; with instructions between the two jumps (they run only when the first does not jump) `jne T; …; jp T` is `if ((a < b) || (b < a))` (ordered and not equal) and then `if (isnan(a) || isnan(b))`; `jbe` / `ja` after the compare reads its `a == b` also when an operand is overwritten in between; a lone `je` (no parity check) prints `(a == b) || (isnan(a) || isnan(b))`. `test r, r` reads `r`. A temporary still printed is read elsewhere too (by another branch, a later block, or a call). Flags read away from their `cmp` (`cmp; je L; jl M` puts the `jl` in the next block, `ZF || SF != OF` read by a `setle`) are the comparison too, when no instruction in between writes over the compared registers; a compared register the subtraction itself overwrites (`sub dword [m], 1; jle`) is kept as `old_1 = tmp_510;` where the flags were computed and read as `(int32_t)old_1 <= (int32_t)1`. `INT_SBORROW` / `!var_207 != !var_20b` in the output mean that check failed. Consecutive tests that jump to the same place merge into one `if (a || b)` / `if (a && b)` when the later test's block holds nothing but its compare; its statements are folded into the condition expression too, only the first test's other statements print before the `if`. A `while (true) { …; if (!c) break; … }` becomes `while (c)` when the header's statements all fold.
* **Switches**: a jump table (`cmp r, N; ja default; lea rcx, [table]; movsxd rax, [rcx+rax*4]; add rax, rcx; jmp rax`, or `jmp [table+rax*8]`) prints as `switch (r13d) { case 0: … case 1: case 3: … default: … }`; the table computation does not print. Also recognised: the window reusing the compared register (`movsxd rsi, [rdi+rsi*4]`; a leftover `tmp_6f00 = rsi; … switch (tmp_6f00)` means the computed target is read later), `jbe dispatch` with the default falling through, a signed bound (`jg`), a byte / word table choosing the slot (`movzx eax, byte [B+rax]`, case `i` = `T[B[i]]`), a table base set once before a loop (`lea r9, [T]`), and no bounds check right before the dispatch: then the index's unsigned range on every path to it decides (a forward data flow over the instructions: `cmp r, N; ja/jae/jb/jbe` bounds `r` on each edge, so do `jg/jge/jl/jle` against a non-negative `N` for a value known non-negative and `test r, r; js/jns`; copies and zero extensions share the bound, `r ± c` moves it when it does not wrap, constants / `and` / `shr` / narrow loads are bounded, calls and other writes are not; a value spilled to the stack and reloaded (`mov [rsp+0x28], rsi` … `mov rsi, [rsp+0x28]`) is the same value, unless the function takes an address of the frame at or below that slot; the cases of the other tables are edges that bound their index, a block no edge reaches is unknown (alignment `nop` / `int3` padding after a jump is never run), and a loop that keeps changing a value makes it unknown) — `cmp edi, 3; ja default` blocks earlier, or comparing `r12d` with the index in `rsi = r12d` spilled and reloaded, gives 4 cases; with no bound found it is an enum switch: no `default:`, the table runs while its entries are instructions of the function, up to the next table the function loads, or as far as the index's range on the paths to it or a `shr r32, k` / `and r, m` computing it right before allows (an `int3` right after the function's code, where an enum switch sends its impossible values, is a case `__builtin_trap();`, and the next function's entry a tail call to it). A byte loaded from a struct field (`movzx eax, byte [rsi+8]`) is the index, not a slot table. A conditional jump falling into the dispatch that does not compare the index (a loop's `cmp [r10+0xc], ebp; jg`) is no bounds check. The table base may be a callee-saved register loaded once (its epilogue `pop` does not count), loaded with the same constant more than once, loaded with different tables on different paths (the constant last written before the dispatch, accepted only when every entry is an instruction of the function), or a register the function also uses for other values (each constant address it gets is tried, and kept when — with that table's cases as edges — the register holds it on every path to the dispatch). A default outside the function (a `.cold` part) is a tail call like a case there. A case outside the function (a `.cold` part) prints as a tail call `rax = 0x…(); return rax;`. In a loop, `break` ends a case; leaving the loop from a case is a `goto` (or a return tail). A table not recognised stays `goto *rax;  // indirect jump` and its cases are not printed.
* **setcc** folds its condition like a branch: `cmp r13b, 1; setne al` is `al = r13b != 1;`, `ucomiss xmm1, [m]; seta [rbx+0x25]` is `*(uint8_t*)(rbx + 0x25) = tmp_700 < xmm1_d;` (a byte register or a stored byte taking a flag or a comparison's temporary).
* **Rust output** (`--rust`) names the same stack slots (`local_30`, `local_30 as u32`, `unsafe { *(&raw mut local_30 as *mut u32) = 1; }`, `&raw mut local_48`, `local_18.as_mut_ptr()`) and folds `setcc` / `cmov` conditions the same way: `al = (rcx != rax) as u8;`, `rdx = if rdx < rsi { rsi } else { rdx };`.
* **cmov** prints as `edi = ((int32_t)edi < (int32_t)esi) ? esi : edi;` (`SELECT`; the lifter emits it directly, a negated condition as the flag with the arms swapped: `cmovne` = `(a == b) ? dst : src`); the condition folds like a branch condition — its temporaries / flags in the block, also when two `cmov`s read one flag — when no instruction in between writes what it reads; else it names the flag (`var_206 ? …`) or a temporary still printed. SSE `maxss` / `minss` print the same way: `xmm0_d = (xmm1_d < xmm0_d) ? xmm0_d : xmm1_d`.
* **Partial registers**: a write to a register's low byte / word / scalar XMM lane prints as that write (`al = rax == rsi;`, `al = 1;`) — the register names alias, so a later `rax` includes it; with known upper bytes it is the widening (`xor eax, eax; mov al, sil` -> `rax = (uint64_t)al;`). `ah`/`bh`/`ch`/`dh` read byte 1 (`ah = (uint8_t)(rax >> 8);`).
* **Constants** are printed where they are used: `mov edi, 5; call f` is `f(5)` and `mov ecx, 7; mov [rdi], ecx` is `*(uint32_t*)rdi = 7;` (no `edi = 5;` line). A constant a float op reads prints as a float (`x <= 0.0f`, `+ 1.0f`), an added negative constant as a subtraction (`rcx - 6`).
* **A register named in an expression** means its value at that point: a condition never reads a register the statement before it overwrote (`ebx = ebx - 1; if (ebx == 0)` for `dec ebx; je`).
* **Lifter** (x86): flags follow the Intel SDM and are checked against the CPU (`crates/reargo-lift/tests/x86_vs_cpu.rs`): `shl`/`shr`/`sar`/`rol`/`ror`/`shld`/`shrd` set CF/OF (a register count of 0 changes nothing: `ZF = (cl & 0x1f) != 0 ? … : ZF`), `imul`/`mul` CF = OF = the product overflowed, `adc`/`sbb` OF; `rcl`/`rcr`, `bt`/`bts`/`btr`/`btc` (also the bit string `bt [m], r`, whose signed offset may pick another word), `tzcnt`/`lzcnt`/`popcnt` (`tzcnt(x)`, `lzcount(x)`, `popcount(x)`), `bswap(x)`, `clc`/`stc`/`cmc` are modelled, and PF (`(popcount((uint8_t)r) & 1) == 0`; a function whose code reads no PF drops its computation at lift time) with `setp`/`cmovp`/`jp`. Packed integer SIMD is lane-exact as named intrinsics on the whole register: `xmm5 = paddb(xmm5, xmm0)`, `paddd`/`psubd`/`paddq`/`psubq`, `pminub`, `pmaxub`, `pcmpeqd`, `pcmpgtb`, `pavgb`, `pmullw`, `pmaddwd`, `pmuludq`, `psadbw`, `packuswb`, the unpacks (`punpckldq`, `unpcklps`, …), `pshufb`, `movhlps`/`movlhps`; a shuffle takes its immediate last (`xmm0 = pshufd(xmm1, 0x4e)`, `shufps(xmm0, xmm1, 0x44)`), a shift its count (`psrld(xmm0, 3)`, or a register whose low quadword is the count; `pslldq`/`psrldq` shift bytes), `eax = pextrw(xmm0, 3)`, `xmm0 = pinsrw(xmm0, ecx, 5)`. Packed float is lane-exact the same way: `xmm0 = mulps(xmm0, xmm1)`, `addps`/`subps`/`divps`/`minps`/`maxps` and the `…pd` forms, `sqrtps(x)`, the conversions `cvtdq2ps`/`cvttps2dq`/`cvtps2dq`/`cvtps2pd`/`cvtpd2ps`/`cvttpd2dq`/`cvtpd2dq`/`cvtdq2pd` (`xmm1 = cvttps2dq(x)`), `cmpps(a, b, imm)` / `cmppd` (a mask per lane). `movlps`/`movlpd` load the low quadword (`xmm0_q = *(uint64_t*)m`), `movhps`/`movhpd` the high one (`xmm0 = movhps(xmm0, *(uint64_t*)m)`), and their stores write the low / high quadword (`*(uint64_t*)m = (uint64_t)(xmm0 >> 64)`). The 64-bit one-operand `mul`/`imul` (`rdx:rax`) and their CF/OF are checked against the CPU too. The bitwise SSE ops act on the whole register (`xmm3 = xmm3 & xmm5`, `(~xmm2) & xmm3` for `andnps`). SSE3 / SSSE3 / SSE4.1 lane ops are intrinsics the same way (checked against the CPU): `rcpps` / `rsqrtps` / `rcpss` / `rsqrtss` (approximations: the emulator runs the instruction itself, so its bits are the host CPU's), `haddps`/`hsubps`/`addsubps` (and `…pd`), `movddup`/`movshdup`/`movsldup`, `pabsb/w/d`, `phaddw/d`, `phsubw/d`, `psignb/w/d`, `pmaddubsw`, `pmulhrsw`, `palignr(dst, src, imm)`, `blendps`/`blendpd`/`pblendw(dst, src, imm)`, `dpps`/`dppd` (which NaN comes out of NaN inputs is the CPU's own), `insertps`, `roundps(src, imm)` / `roundss(dst, src, imm)`, `pmuldq`, `pmovzx*` / `pmovsx*` (`xmm0 = pmovzxbw(*(uint64_t*)p)`); `eax = movmskps(xmm1)` / `movmskpd`, and SSE4.2 `eax = crc32(eax, cl)` (CRC-32C). x87 instructions are still `__unmodeled_insn()`. A `div` reads the dividend register directly: `edx = eax % ebx; eax = eax / ebx;`.
* **Epilogues**: the frame restore before a `ret` (`pop`, `add rsp`, the return-address load) is not printed; the prologue's pushes are.
* **Return type**: `float` / `double` (`return xmm0_d;`) when the function last wrote a scalar float into `xmm0`, else `uint64_t` (`rax`) or `void`. When every `ret` only passes on an unknown callee's result (`return g();`), or leaves a value the function also stored, or the function computed both `rax` and `xmm0` (which was written last is a weak hint), the direct callers decide: one that reads `eax` keeps `uint64_t`, `xmm0` makes it `float` / `double`, callers that ignore it make it `void` (a byte scan for `call rel32`, 10–35 ms on a 230 MB binary, only for those functions); for `return g();` with no deciding caller (a virtual method), the direct callers of `g` decide the same way (up to 4 callees, all agreeing); otherwise the last write stands.
* **Idioms**: `x << n | x >> (w - n)` prints `rotl(x, n)` (`rotr` for a `ror`). A temporary computed only to be copied into a register prints as the register's own statement: `mov rdi, [rbx]` is `rdi = *(uint64_t*)rbx;`, `lea rcx, [rsp+0x30]` is `rcx = rsp + 0x30;` (not `tmp_500 = …; rdi = tmp_500;`).
* **Addresses and loaded values** print inside the access that uses them: `mov [rsp+0xa0], rsi` is `*(uint64_t*)(rsp + 0xa0) = rsi;`, `add eax, [rbx+0x350]` is `eax = eax + *(uint32_t*)(rbx + 0x350);`, `add dword [rax+8], 1` is `*(uint32_t*)(rax + 8) = *(uint32_t*)(rax + 8) + 1;` — for a temporary read in the same block by loads / stores / plain operations, a call's target or arguments (`rax = (**(uint64_t*)(rax + 0x30))(rdi);`), a named intrinsic's operands (`xmm1 = cvttps2dq(*(uint128_t*)(rsp + 0x30));`) or a `cmov`'s arms (one reader, or two when it is a register plus a constant) whose registers do not change before the reader, a load also with no store or call in between. An indexed address read twice prints in both (`r9d = *(uint32_t*)(rdx + (rcx << 2)); rcx = (rdx + (rcx << 2)) + 4;`), and a loaded value a flag kept as a statement compares prints in it (`var_206 = rcx == *(uint64_t*)0xdfbea80;`) — when the comparison is read later in its block (it may fold into a condition there), only if the value cannot change up to the block's end. A temporary copied to a register and also read by stores prints as that register (`lock xadd` of a reference count: `rax = *(uint64_t*)(rdi + 0x10); *(uint64_t*)(rdi + 0x10) = rax - 1;`) when nothing reads or writes the register between the load and the copy. A `tmp_…` still printed has another reader (a condition, a third access) or a register changing in between. The Rust output (`--rust`) prints them the same way.
* **Stack slots** are named when their address is provably the entry `rsp` plus a constant `k` (the stack pointer followed from the entry through `push` / `sub` / `add` and copies, whichever register holds it): `local_<-k>` in hex (`local_30`), the same name at every access of the slot, typed by the widest access starting there. A narrower access at its start casts it (`eax = (uint32_t)local_30;`, `*(uint32_t*)&local_30 = 1;`), one further in goes through its address (`*(uint32_t*)((uint8_t*)&local_30 + 0x4) = 1;`), a frame address is the slot's (`rdi = &local_48;`), and a region only addressed is an array up to the next slot (`uint8_t local_18[0x10];`, `rax = local_18;`). The prologue's pushes print as `local_8 = rbx;`; the stack pointer's own updates are not printed when only these read them (an `and rsp, -32`, a `lea rdi, [rsp+rax]` keep `rsp` named). Above the return address are the stack arguments: `arg_8` is the first (`entry rsp + 8`), each a parameter after the register ones (`f(…, uint64_t r9, uint32_t arg_10)`); an argument region only addressed is `uint8_t arg_8[]` (a `va_list`'s overflow area, an aggregate passed in memory). A landing pad starts with the stack pointer of the call that threw — the one at every call of the body, when they agree — so its slots are the body's (`rdi = &local_58;`).
* **Calls**: `rax = f(…)` / `xmm0 = f(…)` — the return register the callee is found to use (or the one the caller reads; for an import / unresolved indirect call, the one register the caller reads other than as a later call's argument, the other then shows as `__clobbered`). Arguments come from the callee's own code when it is known; an indirect call through a constant function pointer / vtable slot becomes a direct call, and a virtual call on `this` inside a method found in a vtable gets the union of the parameter sets of that slot's implementations (`// vfn[6] (vtable+0x30) e.g. 0x4c19c40`).
* **Imports**: a call to a libc / libm / pthread import (or a one-instruction thunk `jmp import@plt`, printed with the import's name) takes the import's known prototype — its arguments (`pthread_mutex_unlock@plt(rdi)`) and return register (`rax = memcpy@plt(…)`, `xmm0 = sqrtf@plt(xmm0)`); a variadic one (`printf`, `snprintf`, `open`, …) its fixed arguments at least. Other unknown callees take the System V prefix of the registers set up for the call, where a register only partly written (`setne sil`) whose byte the function reads itself is no argument.
* **Signature**: each register class lists its parameters up to the highest one read (`f(rdi, rsi)` even when only `rsi` is used).
* **Landing pads**: when the function has an LSDA (`.gcc_except_table`), each exception landing pad is printed after the body as `/* landing pad 0x41cc1c6: cleanup for the calls at 0x41cc0da..0x41cc113 */ { …; _Unwind_Resume@plt(rdi); }` (`catch (...)`, `catch (std::exception)` for a typed one, `exception specification`); `rax` on entry is the exception object. A jump from a pad back into the body is a `goto` to a label there.

With `-A`, every line that still carries a raw `0x...` literal (an unresolved
call target, vtable pointer, or data reference the renderer couldn't name) gets
a trailing comment classifying it with the same scheme as `disasm -A`:
`import@plt` / `vtable[class]` / `fn` / `string` / `data:<section>`. Literals
below `0x1000` (stack/struct offsets, small constants) are skipped. This makes
the residual addresses in carved-function output readable without cross-referencing.

#### `decompile-all <FILE> [-o DIR] [--rust] [--skip-errors]`

Decompile every discovered function in parallel. With `-o`, writes `<dir>/<name>.c` (and `.rs` if `--rust`); without, streams to stdout with `// === <name> @ 0x<addr> ===` headers.

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
11. **x86 SSE / scalar-float is lifted to FLOAT_* p-code.** `addsd/mulss/divps/cvtsi2sd/comisd/movaps/…` decompile to real `xmm0 = xmm0 * xmm1` / `(float)` / compare expressions, and `pcode` shows `FLOAT_MULT`/`FLOAT_ADD`. XMM registers print as `xmm0..xmm15`. Packed ops (`…ps`/`…pd`, integer SIMD, shuffles) are lane-exact named intrinsics (`xmm0 = mulps(xmm0, xmm1)`, `pshufd(xmm1, 0x4e)`), checked against the CPU; see **Lifter** under `decompile`. This makes float-dominated code (e.g. game world-gen noise) decompilable where it previously produced opaque traps.
