# ghidra-rust

A Rust reimplementation of [NSA Ghidra](https://github.com/NationalSecurityAgency/ghidra)'s core binary analysis pipeline. CLI-first, library-first — no GUI.

## Features

- **20,000+ lines** of Rust across 10 crates
- **252 tests**, clippy clean
- **6 architectures**: x86/x64, ARM/AArch64, RISC-V, MIPS, PowerPC, SPARC
- **30 analyzers**: function discovery, string search, stack analysis, VTable detection, calling convention inference, and more
- **Full P-code IR**: all 74 opcodes with emulation support
- **Decompiler**: SSA construction, 10 optimization rules, type inference, C/Rust pseudocode output
- **Debug info**: DWARF (functions, types, parameters, line numbers), PDB headers/types
- **SLEIGH runtime**: packed format reader, decision trees, context database, zlib decompression
- **Binary formats**: ELF, PE, Mach-O, COFF, raw binary
- **Debugger foundation**: GDB RSP protocol, breakpoints, watchpoints, syscall emulation, state snapshots

## Quick Start

```bash
# Build
cargo build --release

# Analyze a binary
cargo run -- analyze /path/to/binary

# Disassemble
cargo run -- disasm /path/to/binary -n 50

# Decompile entry point
cargo run -- decompile /path/to/binary

# Show P-code
cargo run -- pcode /path/to/binary -n 20

# Emulate with breakpoints
cargo run -- emulate /path/to/binary --break 0x401000 -n 1000

# Export analysis to JSON
cargo run -- export /path/to/binary

# Export to Ghidra-compatible XML
cargo run -- export-xml /path/to/binary
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `info` | Display binary file information |
| `sections` | List sections |
| `symbols` | List symbols (filterable by kind) |
| `disasm` | Disassemble instructions |
| `registers` | List architecture registers |
| `hexdump` | Hex dump at address |
| `analyze` | Run full analysis pipeline |
| `functions` | List discovered functions |
| `xrefs` | Show cross-references |
| `callgraph` | Display call graph (with DOT export) |
| `pcode` | Show P-code IR |
| `decompile` | Decompile to C pseudocode |
| `export` | Export analysis to JSON |
| `export-xml` | Export to Ghidra XML |
| `emulate` | Emulate with P-code |

## Architecture

```
gr-cli ─────────────────────────────────────────────┐
  ├── gr-decompile (SSA, optimization, C/Rust output)│
  │     ├── gr-lift (x86 → P-code)                   │
  │     └── gr-sleigh (SLEIGH runtime)                │
  ├── gr-analysis (30 analyzers)                      │
  │     └── gr-program (Program model)                │
  ├── gr-arch (6 architectures, .cspec/.pspec)        │
  ├── gr-loader (ELF/PE/Mach-O/COFF, DWARF, PDB)     │
  ├── gr-emulator (P-code emulation, debugger)        │
  └── gr-core (addresses, P-code IR, data types)      │
──────────────────────────────────────────────────────┘
```

## Crates

| Crate | Lines | Description |
|-------|-------|-------------|
| `gr-core` | ~1,800 | Address model, P-code IR (74 ops), data types |
| `gr-loader` | ~2,500 | Binary loaders, DWARF, PDB, FLIRT, relocations |
| `gr-arch` | ~2,200 | 6 architectures, .cspec/.pspec/.ldefs parsers |
| `gr-program` | ~1,500 | Program model, symbols, references, undo/redo |
| `gr-analysis` | ~2,000 | 30 analysis passes |
| `gr-lift` | ~1,100 | x86 → P-code lifter |
| `gr-emulator` | ~2,000 | P-code emulator, debugger, GDB RSP |
| `gr-decompile` | ~2,500 | SSA, optimization, structuring, C/Rust output |
| `gr-sleigh` | ~1,800 | SLEIGH specification runtime |
| `gr-cli` | ~700 | Command-line interface |

## Building

```bash
cargo build
cargo test
cargo clippy
```

## Ghidra Reference

The `ghidra/` git submodule contains the original NSA Ghidra source for reference.

## License

Apache-2.0
