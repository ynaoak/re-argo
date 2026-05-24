# ghidra-rust

Rust reimplementation of Ghidra's core binary analysis pipeline. CLI-first, library-first — no GUI.

## Build & Test

```bash
cargo build
cargo test
cargo clippy
```

## CLI Commands

```bash
cargo run -- info <binary>
cargo run -- sections <binary>
cargo run -- symbols <binary> [--kind func|data|import|export]
cargo run -- disasm <binary> [--start <hex-addr>] [-n <count>]
cargo run -- registers <binary>
cargo run -- hexdump <binary> <hex-address> [length]
cargo run -- analyze <binary>
cargo run -- functions <binary>
cargo run -- xrefs <binary> <hex-address>
cargo run -- callgraph <binary> [--dot]
cargo run -- pcode <binary> [--start <hex-addr>] [-n <count>]
cargo run -- decompile <binary> [--address <hex-addr>] [--ssa]
cargo run -- export <binary> [-o <output.json>]
cargo run -- export-xml <binary> [-o <output.xml>]
cargo run -- emulate <binary> [--start <hex-addr>] [-n <steps>] [--break <hex-addr>]
```

## Workspace Structure

| Crate | Purpose |
|-------|---------|
| `gr-core` | Address model (Segmented/Overlay/Map), P-code IR (74 opcodes), 31+ data types, SpaceId constants |
| `gr-loader` | ELF/PE/Mach-O/COFF/raw binary, DWARF, PDB, FLIRT, relocations, source map, hashing |
| `gr-arch` | 6 architectures (x86/ARM/RISC-V/MIPS/PPC/SPARC), .cspec/.pspec/.ldefs parsers, register overlap map, assembler |
| `gr-program` | Program model, symbols, references, comments, bookmarks, undo/redo, diff, SARIF, metadata, history |
| `gr-analysis` | 30 analyzers (function discovery, strings, stack, VTable, calling convention, coverage, ...) |
| `gr-lift` | x86 → P-code lifter (30+ instructions, memory operands, EFLAGS) |
| `gr-emulator` | Full P-code emulator, breakpoints, watchpoints, traces, snapshots, GDB RSP, syscalls, hooks |
| `gr-decompile` | CFG/SSA/dominator/dataflow, 10 optimization rules, type inference, C/Rust output, SARIF |
| `gr-sleigh` | SLEIGH runtime: PackedDecode, DecisionNode, ContextDB, .sla zlib decode, ParserWalker |
| `gr-cli` | 15 CLI commands |

## Architecture Decisions

- **SpaceId::CONST/RAM/REGISTER/UNIQUE** constants — no magic numbers
- **SmallVec<[VarnodeData; 3]>** for PcodeOp inputs
- **Arena-based SSA** with VarId/OpIdx type aliases
- **goblin** for binary parsing, **iced-x86** for x86, **capstone** for ARM/MIPS/PPC/SPARC/RISC-V
- **gimli** for DWARF, **quick-xml** for Ghidra XML specs, **flate2** for .sla decompression
- **serde** for JSON/SARIF serialization
- Edition 2024, `thiserror` for error types
