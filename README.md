# RE-Argo

**CLI-native reverse-engineering + malware-triage toolkit, written in Rust.**

Originally started as a Rust reimplementation of [NSA Ghidra](https://github.com/NationalSecurityAgency/ghidra)'s analysis pipeline; has since grown into a focused **RE + triage** workbench with a binary-clustering / capability-detection / IoC-extraction layer on top of multi-arch lifting and decompilation. No GUI — CLI first, library first, AI-agent first.

> The name **Argo** echoes the mythological ship that sailed into uncharted waters: RE-Argo is the instrument you take into an unknown binary. **RE** = Reverse Engineering.

> **For AI agents and operators**: see [CLAUDE.md](CLAUDE.md) for the complete CLI-operations reference (every command, every flag, output conventions, multi-command recipes, common gotchas). This README is the human-readable overview.

> **Website**: a static landing page + HTML documentation live under [`docs/`](docs/index.html) (GitHub Pages-ready — point Pages at the `docs/` folder of `main`).

## Features

### Analysis core (Ghidra-style)

- **6 architectures**: x86 / x64, ARM / AArch64, RISC-V, MIPS, PowerPC, SPARC
- **Full P-code IR**: 74 opcodes with emulation support
- **68 analyzers** in priority order: function discovery (recursive descent + linear sweep), 312-entry signature DB (libc / POSIX / Win32 / libstdc++), CRT pattern recognition, VSA + multi-block constant tracker, RTTI / VTable recovery, calling-convention inference, anti-debug / crypto / loop / exception / wrapper / no-return propagation, BN-style tag categorisation, hot-function detection, dead-code, callgraph SCC, complexity metrics
- **Decompiler**: SSA construction, 6 optimisation passes, type inference, C / Rust pseudocode output with **inline analyzer comments + signature-aware call rendering** (`printf("hi %d", 42)` instead of `printf@plt()`)
- **Debug info**: DWARF (functions, types, parameters, line numbers, source-file plates), PDB headers / types
- **SLEIGH runtime**: packed format reader, decision trees, context database, zlib decompression
- **Binary formats**: ELF, PE (with `.pdata` / TLS callbacks / IAT / `.rsrc` VS_VERSIONINFO / Rich Header), Mach-O (with ObjC classes / methods / ivars / protocols), COFF, raw binary
- **Debugger foundation**: GDB RSP protocol (client + server), breakpoints, watchpoints, syscall emulation, state snapshots
- **MCP integration**: Model Context Protocol over stdio for AI hosts (Claude Code, etc.)

### Malware-triage layer (RE-Argo's distinctive surface)

- **One-screen triage**: `triage` runs the full pipeline and prints format / arch / identity / hashes / packer / capa / CWE / IoCs / tag counts in a single digestible report
- **Family clustering**: imphash, TLSH (content-fuzzy), RichHash (MSVC toolchain), all surfaced in `info` / `triage`
- **Capability detection**: 20-rule Capa-style engine matching against imports / strings / tags
- **YARA-lite**: parse and match a strict subset of YARA rules (text + hex with wildcards, boolean conditions, `N of them` quantifiers)
- **FLOSS-lite**: brute-force XOR / ROL / ADD obfuscated-string decoder
- **IoC extraction**: 13-kind classifier (URL / IPv4 / IPv6 / email / registry-key / named-pipe / mutex / posix-path / win-path / ETH / BTC / user-agent / domain)
- **Packer ID**: DIE / PEiD-style signatures for UPX / ASPack / Themida / VMProtect / MEW / FSG / PECompact / NSPack / Mpress / Yoda / …
- **CWE-aware vuln patterns**: tags functions calling dangerous APIs (CWE-78 / -120 / -134 / -242 / -330 / -426 / -676)
- **Section anomalies**: RWX / writable-code / packer-shaped layout detection
- **Authenticode**: PE code-signing presence + heuristic CN= / O= subject extraction
- **Entropy**: per-section Shannon entropy + packer threshold flagging
- **ROP / JOP / COP gadgets**: x86 / x64 gadget finder with ROPgadget-style output
- **Embedded files**: Binwalk-lite scan for ELF / PE / Mach-O / ZIP / GZIP / 7z / PNG / JPEG / PDF / SQLite resources

## Quick Start

```bash
# Build (binary lands at target/release/re-argo)
cargo build --release

# One-screen malware-triage
target/release/re-argo triage <binary>

# Triage a binary the long way
target/release/re-argo info <binary>
target/release/re-argo summary <binary>

# Browse discovered functions
target/release/re-argo functions <binary>
target/release/re-argo metrics <binary> --top 25

# Cross-search by name / symbol / comment / tag
target/release/re-argo find <binary> "printf"

# Disassemble
target/release/re-argo disasm <binary> -n 50

# Decompile
target/release/re-argo decompile <binary> --address 0x401000

# Reverse callgraph — who calls into this address?
target/release/re-argo backtrace <binary> 0x401000

# Categorised findings (crypto / suspicious / library / …)
target/release/re-argo tags <binary> --list-types

# Capa-style capabilities
target/release/re-argo capa <binary>

# Extract IoCs (URLs / IPs / registry keys / …)
target/release/re-argo ioc <binary>

# Scan with a YARA-lite ruleset
target/release/re-argo yara <binary> rules.yar

# Compare two binaries by TLSH content-fuzzy hash
target/release/re-argo tlsh-diff <a> <b>

# Memory map
target/release/re-argo memmap <binary>

# Export everything to JSON
target/release/re-argo export <binary> -o out.json
```

For the full command surface, every flag, output formats, and multi-command recipes, see [CLAUDE.md](CLAUDE.md).

## CLI Commands (overview)

50+ subcommands across the following groups:

| Group | Commands |
|---|---|
| Triage | `info`, `triage`, `summary`, `sections`, `memmap`, `symbols`, `imports`, `strings` |
| Analysis | `analyze`, `functions`, `metrics`, `bench`, `coverage`, `workflow` |
| Findings | `tags`, `find`, `signatures` |
| Code views | `disasm`, `pcode`, `decompile`, `decompile-all`, `cfg` |
| Cross-refs | `xrefs`, `callgraph`, `backtrace`, `callsites` |
| Data / search | `hexdump`, `search` |
| Diff | `diff`, `semantic-diff` |
| Export | `export`, `export-xml` |
| Emulation | `emulate`, `gdbserver`, `debug` |
| Capability | `entropy`, `rop` (ROP/JOP/COP), `capa`, `packer`, `embedded`, `vuln`, `ioc`, `yara`, `tlsh-diff`, `floss` |
| Manual correction | `annotate`, `iterate`, `carve` |
| Integration | `script`, `mcp`, `patch`, `taint`, `registers` |

## Architecture

```
re-argo (reargo-cli)
  ├── reargo-decompile (SSA, optimisation, C/Rust output)
  │     ├── reargo-lift (x86 / ARM / RISC-V / ... → P-code)
  │     └── reargo-sleigh (SLEIGH runtime)
  ├── reargo-analysis (68 analyzers + triage layer)
  │     └── reargo-program (Program model + Tags)
  ├── reargo-arch (6 architectures, .cspec / .pspec)
  ├── reargo-loader (ELF / PE / Mach-O / COFF, DWARF, PDB)
  ├── reargo-emulator (P-code emulation, debugger, GDB RSP)
  └── reargo-core (addresses, P-code IR, data types)
```

## Crates

All Rust crates share the `reargo-*` prefix; the published CLI binary is `re-argo`. The crates aren't exposed via `cargo install` or the CLI surface — only the `re-argo` binary is.

| Crate | Purpose |
|-------|---------|
| `reargo-core` | Address model, P-code IR (74 ops), data types |
| `reargo-loader` | ELF / PE / Mach-O / COFF, DWARF, PDB, FLIRT, relocations, MD5 / FNV / CRC32 hashing |
| `reargo-arch` | 6 architectures, .cspec / .pspec / .ldefs parsers, assembler |
| `reargo-program` | Program model, symbols, references, comments, **tags**, **call_renderings**, undo / redo, diff, SARIF, metadata |
| `reargo-analysis` | 68 analyzers — function discovery, signatures, VSA, CRT patterns, tags, capa / yara / floss / packer / vuln / ioc / authenticode / TLSH / imphash / richhash / rop, … |
| `reargo-lift` | Multi-arch → P-code lifter |
| `reargo-emulator` | P-code emulator, debugger, GDB RSP |
| `reargo-decompile` | SSA, optimisation, structuring, C / Rust output with annotations |
| `reargo-sleigh` | SLEIGH specification runtime |
| `reargo-cli` | The `re-argo` CLI binary (50+ subcommands) |

## Building

```bash
cargo build              # debug
cargo build --release    # release; binary at target/release/re-argo
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Ghidra reference

The `ghidra/` git submodule contains the original NSA Ghidra source for cross-reference during analyzer development.

## License

Apache-2.0
