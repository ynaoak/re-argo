# `carve` command — design / work memo

## Problem

Analysing the Minecraft Bedrock dedicated-server binary (~222 MB) statically
is blocked because GUI Ghidra's importer truncates / chokes on images that
large. The most promising static route is to **carve out a single function's
bytes into a small standalone binary** so the size limit is sidestepped and the
target function decompiles without truncation. This memo records the design of
a `carve` CLI subcommand that does exactly that, so the work survives a session
break.

## What it does

Extract a single function (or an arbitrary VA range) from a large binary into a
small standalone file, **keeping the original virtual address** so RIP-relative
operands and call targets still display the correct addresses.

### Range selection (mutually exclusive entry points)

| Flags | Behaviour | Cost |
|---|---|---|
| `--address ADDR` | Run analysis, find the function at/containing ADDR, carve its full extent `[min body range, max body range)`. | Full pipeline (slow on 222 MB) |
| `--address ADDR --size N` | Function entry + explicit byte length. Skips analysis. | Fast (loader only) |
| `--start ADDR --end ADDR` | Arbitrary half-open VA range. Skips analysis. | Fast |
| `--start ADDR --size N` | Arbitrary range by length. Skips analysis. | Fast |

Bytes are read from the loader's memory model byte-by-byte, zero-filling any
uninitialised holes (so ranges that touch `.bss`-like gaps don't fail).

### Output containers (`--format`)

* `raw` (default): the bytes verbatim. The command prints the Ghidra "Raw
  Binary" import parameters — SLEIGH language id + base address — to type in.
* `elf`: a minimal single-PT_LOAD / single-`.text` ELF placed at the original
  VA. Ghidra and ghidra-rust both auto-detect arch + base, so the carved
  function round-trips with zero manual setup:
  `ghidra-rust carve big --start 0x... --size N -o f.elf --format elf` →
  `ghidra-rust decompile f.elf --address 0x...`.

The ELF container is emitted for any source arch (even a PE source) because
Ghidra loads ELF for every architecture; ELF is the universal carve wrapper.

## Implementation

* `crates/gr-cli/src/carve.rs` — `ghidra_language_id()` (arch→SLEIGH id) and
  `build_min_elf()` (32/64-bit, LE/BE ELF synthesiser).
* `crates/gr-cli/src/main.rs` — `Carve` subcommand variant + `cmd_carve()`.

### Minimal ELF layout

```
ehdr | phdr[1: PT_LOAD R+X @ base] | <text data> | .shstrtab | shdr[3: NULL/.text/.shstrtab]
```

`.text` is `SHT_PROGBITS`, `sh_addr = base` so ghidra-rust's loader (which
builds memory blocks from PROGBITS sections with `sh_addr != 0`) maps it; the
`PT_LOAD` header feeds the address map. `e_entry = entry`, `e_type = ET_EXEC`.

## Status

Implemented this session. Verified with `cargo build` + a round-trip carve of a
self-built ELF.
