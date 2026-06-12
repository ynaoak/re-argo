# ghidra-rust

A Rust reimplementation of [NSA Ghidra](https://github.com/NationalSecurityAgency/ghidra)'s core binary analysis pipeline. CLI-first, library-first — no GUI.

> **For AI agents and operators**: see [CLAUDE.md](CLAUDE.md) for the complete CLI-operations reference (every command, every flag, output conventions, multi-command recipes, common gotchas). This README is the human-readable overview.

## Features

- **~20,000+ lines** of Rust across 10 crates
- **600+ tests**, clippy clean across `--all-targets -- -D warnings`
- **6 architectures**: x86 / x64, ARM / AArch64, RISC-V, MIPS, PowerPC, SPARC
- **68 analyzers** in the AnalysisManager pipeline: function discovery (recursive descent + linear sweep), 312-entry signature DB (libc / POSIX / Win32 / libstdc++), CRT pattern recognition, VSA + multi-block constant tracker, RTTI / VTable recovery, calling-convention inference, anti-debug / crypto / loop / exception / wrapper / no-return propagation, BN-style tag categorisation, hot-function detection, dead-code, callgraph SCC, complexity metrics
- **Full P-code IR**: 74 opcodes with emulation support
- **Decompiler**: SSA construction, 6 optimisation passes, type inference, C / Rust pseudocode output with **inline analyzer comments + signature-aware call rendering** (`printf("hi %d", 42)` instead of `printf@plt()`)
- **Debug info**: DWARF (functions, types, parameters, line numbers, source-file plates), PDB headers / types
- **SLEIGH runtime**: packed format reader, decision trees, context database, zlib decompression
- **Binary formats**: ELF, PE (with `.pdata` / TLS callbacks / IAT / `.rsrc` VS_VERSIONINFO), Mach-O (with ObjC classes / methods / ivars / protocols), COFF, raw binary
- **Debugger foundation**: GDB RSP protocol (client + server), breakpoints, watchpoints, syscall emulation, state snapshots
- **MCP integration**: speak Model Context Protocol over stdio to embed ghidra-rust into AI hosts (Claude Code, etc.)

## Quick Start

```bash
# Build
cargo build --release

# Triage a binary
target/release/ghidra-rust info <binary>
target/release/ghidra-rust summary <binary>

# Browse discovered functions
target/release/ghidra-rust functions <binary>
target/release/ghidra-rust metrics <binary> --top 25

# Cross-search by name / symbol / comment / tag
target/release/ghidra-rust find <binary> "printf"

# Disassemble
target/release/ghidra-rust disasm <binary> -n 50

# Decompile
target/release/ghidra-rust decompile <binary> --address 0x401000

# Reverse callgraph — who calls into this address?
target/release/ghidra-rust backtrace <binary> 0x401000

# Categorised findings (crypto / suspicious / library / …)
target/release/ghidra-rust tags <binary> --list-types

# Memory map
target/release/ghidra-rust memmap <binary>

# Export everything to JSON
target/release/ghidra-rust export <binary> -o out.json
```

For the full command surface, every flag, output formats, and multi-command recipes, see [CLAUDE.md](CLAUDE.md).

## CLI Commands (overview)

40+ subcommands organised into eight groups:

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
| Capability | `entropy`, `rop` (ROP/JOP/COP), `capa`, `packer`, `embedded`, `vuln`, `ioc` |
| Manual correction | `annotate`, `iterate` |
| Integration | `script`, `mcp`, `patch`, `taint`, `registers` |

## Architecture

```
gr-cli ────────────────────────────────────────────────┐
  ├── gr-decompile (SSA, optimisation, C/Rust output)  │
  │     ├── gr-lift (x86 / ARM / RISC-V / ... → P-code) │
  │     └── gr-sleigh (SLEIGH runtime)                  │
  ├── gr-analysis (68 analyzers)                        │
  │     └── gr-program (Program model + Tags)           │
  ├── gr-arch (6 architectures, .cspec / .pspec)        │
  ├── gr-loader (ELF / PE / Mach-O / COFF, DWARF, PDB)  │
  ├── gr-emulator (P-code emulation, debugger, GDB RSP) │
  └── gr-core (addresses, P-code IR, data types)        │
─────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Purpose |
|-------|---------|
| `gr-core` | Address model, P-code IR (74 ops), data types |
| `gr-loader` | ELF / PE / Mach-O / COFF, DWARF, PDB, FLIRT, relocations |
| `gr-arch` | 6 architectures, .cspec / .pspec / .ldefs parsers, assembler |
| `gr-program` | Program model, symbols, references, comments, **tags**, **call_renderings**, undo / redo, diff, SARIF, metadata |
| `gr-analysis` | 68 analyzers (function discovery, signatures, VSA, CRT patterns, tags, …) |
| `gr-lift` | Multi-arch → P-code lifter |
| `gr-emulator` | P-code emulator, debugger, GDB RSP |
| `gr-decompile` | SSA, optimisation, structuring, C / Rust output with annotations |
| `gr-sleigh` | SLEIGH specification runtime |
| `gr-cli` | 40+ CLI subcommands |

## Building

```bash
cargo build              # debug
cargo build --release    # release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Ghidra Reference

The `ghidra/` git submodule contains the original NSA Ghidra source for reference.

## License

Apache-2.0
