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
cargo run -- decompile <binary> [--address <hex-addr>] [--ssa] [--rust]
cargo run -- taint <binary> [--address <hex-addr>] [--params <n>]
cargo run -- export <binary> [-o <output.json>]
cargo run -- export-xml <binary> [-o <output.xml>]
cargo run -- emulate <binary> [--start <hex-addr>] [-n <steps>] [--break <hex-addr>]
cargo run -- gdbserver <binary> [--start <hex-addr>] [--listen 127.0.0.1:1234]
cargo run -- debug <binary> [--start <hex-addr>]
cargo run -- strings <binary> [--min-length <n>] [--all]
cargo run -- diff <binary_a> <binary_b>
cargo run -- imports <binary> [--exports]
cargo run -- coverage <binary>
cargo run -- search <binary> [--hex "48 8b ?? 24"] [--text "password"]
cargo run -- patch <binary> <hex-addr> --bytes "90 90 90" [-o <output>]
cargo run -- script <binary> <script.grs>
```

## Workspace Structure

| Crate | Purpose |
|-------|---------|
| `gr-core` | Address model (Segmented/Overlay/Map), P-code IR (74 opcodes), 31+ data types, SpaceId constants |
| `gr-loader` | ELF/PE/Mach-O/COFF/raw binary, DWARF, PDB, FLIRT, relocations, source map, hashing |
| `gr-arch` | 6 architectures (x86/ARM/RISC-V/MIPS/PPC/SPARC), .cspec/.pspec/.ldefs parsers, register overlap map, assembler |
| `gr-program` | Program model, symbols, references, comments, bookmarks, undo/redo, diff, SARIF, metadata, history |
| `gr-analysis` | 30 analyzers (function discovery, strings, stack, VTable, calling convention, coverage, ...) |
| `gr-lift` | x86/AArch64/MIPS32/RV32IMC → P-code lifter (memory operands, EFLAGS/NZCV, branches, compressed insns) |
| `gr-emulator` | Full P-code emulator, breakpoints, watchpoints, traces, snapshots, GDB RSP client+server, syscalls, hooks |
| `gr-decompile` | CFG/SSA/dominator/dataflow, 6 optimization passes (DCE/fold/propagate/strength/algebra/CSE), struct/array type recovery, taint analysis, C/Rust output, SARIF |
| `gr-sleigh` | SLEIGH runtime: PackedDecode, DecisionNode, ContextDB, .sla zlib decode, ParserWalker |
| `gr-cli` | 25 CLI commands |

## Architecture Decisions

- **SpaceId::CONST/RAM/REGISTER/UNIQUE** constants — no magic numbers
- **SmallVec<[VarnodeData; 3]>** for PcodeOp inputs
- **Arena-based SSA** with VarId/OpIdx type aliases
- **goblin** for binary parsing, **iced-x86** for x86, **capstone** for ARM/MIPS/PPC/SPARC/RISC-V
- **gimli** for DWARF, **quick-xml** for Ghidra XML specs, **flate2** for .sla decompression
- **serde** for JSON/SARIF serialization
- Edition 2024, `thiserror` for error types
