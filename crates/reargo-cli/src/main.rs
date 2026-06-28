mod carve;
mod mcp;
mod symbol_import;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use reargo_analysis::{AnalysisManager, CallGraph};
use reargo_analysis::strings::{find_strings, is_data_section};
use reargo_arch::arch::{create_architecture, create_architecture_with_options};
use reargo_lift::aarch64::Aarch64Lifter;
use reargo_lift::arm32::{Arm32Lifter, ArmRegion, MappedArmLifter};
use reargo_lift::mips::MipsLifter;
use reargo_lift::ppc::PpcLifter;
use reargo_lift::riscv::RiscVLifter;
use reargo_lift::sparc::SparcLifter;
use reargo_lift::x86::X86Lifter;
use reargo_lift::{LiftContext, PcodeLift};
use reargo_loader::{BinaryLoader, Memory, SectionFlags, SymbolKind};
use reargo_program::{Program, ProgramDiff, ProjectSummary};

#[derive(Parser)]
#[command(name = "re-argo", version, about = "RE-Argo — CLI-native RE + malware-triage toolkit")]
struct Cli {
    /// Decode ARM code in Thumb (T16/T32) mode instead of A32
    #[arg(long, global = true)]
    thumb: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display binary file information
    Info {
        /// Path to the binary file
        file: PathBuf,
    },
    /// List sections in the binary
    Sections {
        /// Path to the binary file
        file: PathBuf,
    },
    /// List symbols in the binary.
    ///
    /// By default surfaces only loader-side symbols (.symtab /
    /// .dynsym / exports / imports) -- fast, no analysis required.
    /// Pass `--all` to additionally run the full analysis pass and
    /// include every symbol the analyzers added (RTTI vtable /
    /// typeinfo names, demangled forms, sidecar overrides, ...).
    /// Without `--all`, a stripped binary will look empty even
    /// after `analyze`, because what `analyze` recovered lives in
    /// the in-memory program model, not the loader's symbol list.
    Symbols {
        /// Path to the binary file
        file: PathBuf,
        /// Filter by symbol kind (func, data, import, export)
        #[arg(short, long)]
        kind: Option<String>,
        /// Include analysis-added symbols (runs full analyze).
        #[arg(short, long)]
        all: bool,
        /// Only show symbols whose name contains this substring
        /// (case-insensitive). Useful for `--all --name vtable`
        /// after running RTTI recovery.
        #[arg(short, long, value_name = "SUBSTR")]
        name: Option<String>,
    },
    /// Disassemble instructions
    Disasm {
        /// Path to the binary file
        file: PathBuf,
        /// Start address (hex). Defaults to entry point
        #[arg(short, long, value_parser = parse_hex)]
        start: Option<u64>,
        /// Number of instructions to disassemble
        #[arg(short = 'n', long, default_value = "32")]
        count: usize,
    },
    /// List registers for the binary's architecture
    Registers {
        /// Path to the binary file
        file: PathBuf,
    },
    /// Run full analysis on a binary
    Analyze {
        /// Path to the binary file
        file: PathBuf,
    },
    /// List discovered functions
    Functions {
        /// Path to the binary file
        file: PathBuf,
    },
    /// Print per-function complexity metrics
    Metrics {
        /// Path to the binary file
        file: PathBuf,
        /// Sort by this column (mccabe, blocks, insns, fan_in, fan_out, stack)
        #[arg(long, default_value = "mccabe")]
        sort: String,
        /// Show only the top N functions after sorting
        #[arg(long, default_value_t = 25)]
        top: usize,
    },
    /// Print a one-screen summary of the top analysis findings
    Summary {
        /// Path to the binary file
        file: PathBuf,
    },
    /// List categorised analyzer findings (Binary-Ninja-style tags)
    Tags {
        /// Path to the binary file
        file: PathBuf,
        /// Show only tags of this kind (`crypto`, `suspicious`, `library`, …)
        #[arg(long)]
        filter: Option<String>,
        /// Print the per-kind count summary instead of individual tags
        #[arg(long)]
        list_types: bool,
    },
    /// Measure end-to-end analysis wall time + per-analyzer breakdown
    Bench {
        /// Path to the binary file
        file: PathBuf,
    },
    /// List analyzer pipeline (BN-style Workflow) and warn on dependency issues
    Workflow {
        /// Limit to analyzers that have declared provides/consumes
        #[arg(long)]
        declared_only: bool,
    },
    /// Export / inspect the built-in signature database (type-archive workflow)
    Signatures {
        /// When set, write the built-in database to this file as JSON
        #[arg(long)]
        export: Option<PathBuf>,
        /// Filter the listing by library name (libc / Win32 / POSIX / …)
        #[arg(long)]
        library: Option<String>,
    },
    /// Cross-search functions, symbols, strings, and comments (BN-style Command Palette)
    Find {
        /// Path to the binary file
        file: PathBuf,
        /// Substring to grep for (case-insensitive)
        query: String,
        /// Limit the result count
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Emit a DOT graph of a function's control flow
    Cfg {
        /// Path to the binary file
        file: PathBuf,
        /// Function entry address (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,
    },
    /// Show cross-references to/from an address
    Xrefs {
        /// Path to the binary file
        file: PathBuf,
        /// Target address (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,
    },
    /// Show call graph
    Callgraph {
        /// Path to the binary file
        file: PathBuf,
        /// Output DOT format
        #[arg(long)]
        dot: bool,
        /// Print strongly-connected components (mutual / direct recursion)
        #[arg(long)]
        scc: bool,
        /// Restrict the callgraph to the BFS neighbourhood around this address
        #[arg(long, value_parser = parse_hex)]
        around: Option<u64>,
        /// Neighbourhood radius (hops). Only relevant with --around
        #[arg(long, default_value_t = 2)]
        depth: usize,
    },
    /// Print every reverse-callgraph path that reaches the target address
    Backtrace {
        /// Path to the binary file
        file: PathBuf,
        /// Target address (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,
        /// Maximum hops to walk back from the target
        #[arg(long, default_value_t = 6)]
        depth: usize,
        /// Maximum number of distinct paths to enumerate (hub
        /// functions easily exceed the default)
        #[arg(long, default_value_t = 256)]
        max_paths: usize,
    },
    /// ASCII layout of every loaded section + permission bits
    Memmap {
        /// Path to the binary file
        file: PathBuf,
    },
    /// Show P-code for instructions at an address
    Pcode {
        /// Path to the binary file
        file: PathBuf,
        /// Start address (hex). Defaults to entry point
        #[arg(short, long, value_parser = parse_hex)]
        start: Option<u64>,
        /// Number of instructions to lift
        #[arg(short = 'n', long, default_value = "16")]
        count: usize,
    },
    /// Decompile a function to pseudocode
    Decompile {
        /// Path to the binary file
        file: PathBuf,
        /// Function address (hex). Defaults to entry point
        #[arg(short, long, value_parser = parse_hex)]
        address: Option<u64>,
        /// Show SSA dump instead of C output
        #[arg(long)]
        ssa: bool,
        /// Output Rust-style pseudocode instead of C
        #[arg(long)]
        rust: bool,
    },
    /// Decompile every discovered function in parallel
    DecompileAll {
        /// Path to the binary file
        file: PathBuf,
        /// Output directory. Each function becomes
        /// `<dir>/<name>.c` (and `.rs` if --rust is set).
        /// If omitted, results are streamed to stdout with
        /// "// === <name> @ 0x<addr> ===" headers.
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
        /// Also emit Rust-style pseudocode alongside C
        #[arg(long)]
        rust: bool,
        /// Skip empty / unimplemented function decompiles instead of
        /// writing an error file
        #[arg(long)]
        skip_errors: bool,
    },
    /// Taint analysis: track parameters to dangerous sinks
    Taint {
        /// Path to the binary file
        file: PathBuf,
        /// Function address (hex). Defaults to entry point
        #[arg(short, long, value_parser = parse_hex)]
        address: Option<u64>,
        /// Number of parameter registers to treat as tainted
        #[arg(short, long, default_value = "6")]
        params: usize,
    },
    /// Export analysis results to JSON
    Export {
        /// Path to the binary file
        file: PathBuf,
        /// Output JSON file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Export analysis results as Ghidra-compatible XML
    ExportXml {
        /// Path to the binary file
        file: PathBuf,
        /// Output XML file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Emulate instructions from an address
    Emulate {
        /// Path to the binary file
        file: PathBuf,
        /// Start address (hex). Defaults to entry point
        #[arg(short, long, value_parser = parse_hex)]
        start: Option<u64>,
        /// Max steps to execute
        #[arg(short = 'n', long, default_value = "100")]
        steps: u64,
        /// Breakpoint addresses (hex, can specify multiple)
        #[arg(short = 'b', long = "break", value_parser = parse_hex)]
        breakpoints: Vec<u64>,
    },
    /// Start a GDB remote (RSP) server for the emulator
    Gdbserver {
        /// Path to the binary file
        file: PathBuf,
        /// Start address (hex). Defaults to entry point
        #[arg(short, long, value_parser = parse_hex)]
        start: Option<u64>,
        /// Listen address (host:port)
        #[arg(short, long, default_value = "127.0.0.1:1234")]
        listen: String,
    },
    /// Interactive debugger (step, breakpoints, registers, memory)
    Debug {
        /// Path to the binary file
        file: PathBuf,
        /// Start address (hex). Defaults to entry point
        #[arg(short, long, value_parser = parse_hex)]
        start: Option<u64>,
    },
    /// Hex dump at a given address
    Hexdump {
        /// Path to the binary file
        file: PathBuf,
        /// Start address (hex, e.g. 0x1000)
        #[arg(value_parser = parse_hex)]
        address: u64,
        /// Number of bytes to dump
        #[arg(default_value = "256")]
        length: usize,
    },
    /// Find strings in the binary
    Strings {
        /// Path to the binary file
        file: PathBuf,
        /// Minimum string length
        #[arg(short, long, default_value = "4")]
        min_length: usize,
        /// Search all sections, not just data sections
        #[arg(long)]
        all: bool,
    },
    /// Diff two binaries (compare analysis results)
    Diff {
        /// Path to the first binary
        file_a: PathBuf,
        /// Path to the second binary
        file_b: PathBuf,
    },
    /// Compare two binaries at the SSA / decompiled-function level.
    ///
    /// Unlike `diff` (which is byte-level / symbol-table level),
    /// `semantic-diff` runs `decompile_all` on both inputs, hashes
    /// each function's optimized SSA in an address-independent way,
    /// and reports per-function: identical / renamed / tweaked /
    /// modified / added / removed.
    SemanticDiff {
        /// Path to the first binary
        file_a: PathBuf,
        /// Path to the second binary
        file_b: PathBuf,
        /// Only show entries whose kind matches the filter. Comma-
        /// separated list of: identical, renamed, tweaked, modified,
        /// added, removed. Default: all except identical.
        #[arg(short, long, default_value = "renamed,tweaked,modified,added,removed")]
        kinds: String,
    },
    /// List imports and exports
    Imports {
        /// Path to the binary file
        file: PathBuf,
        /// Show exports instead of imports
        #[arg(long)]
        exports: bool,
    },
    /// Show analysis coverage statistics
    Coverage {
        /// Path to the binary file
        file: PathBuf,
        /// Also report annotation density (comments per discovered instruction)
        #[arg(long)]
        annotated: bool,
    },
    /// Search for byte patterns in the binary
    Search {
        /// Path to the binary file
        file: PathBuf,
        /// Hex byte pattern (e.g. "48 8b ?? 24" with ?? as wildcards)
        #[arg(long)]
        hex: Option<String>,
        /// Text/regex pattern to search for
        #[arg(long)]
        text: Option<String>,
        /// Maximum number of results
        #[arg(short = 'n', long, default_value = "50")]
        max_results: usize,
    },
    /// Run a script of analysis commands
    Script {
        /// Path to the binary file
        file: PathBuf,
        /// Path to the script file (.grs)
        script: PathBuf,
    },
    /// Speak the Model Context Protocol (MCP) over stdio.
    ///
    /// Loads the binary, runs analysis, then sits on stdin reading
    /// newline-delimited JSON-RPC 2.0 requests from an MCP client
    /// (e.g. Claude Code) and answers them. Tools exposed include
    /// list_functions, decompile_function, disassemble, find_xrefs,
    /// list_symbols, get_program_info.
    Mcp {
        /// Path to the binary file
        file: PathBuf,
    },
    /// Edit the persistent user-override sidecar (`<binary>.gra.json`).
    ///
    /// Corrections recorded here are re-applied automatically every
    /// time the binary is analysed -- they survive re-analysis and
    /// propagate to every command (decompile, functions, xrefs, ...).
    /// This is the interactive manual-correction layer: fix what the
    /// auto-analysis got wrong and have it stick.
    Annotate {
        /// Path to the binary file
        file: PathBuf,
        /// Rename: `ADDR=NAME` (hex addr). Repeatable.
        #[arg(long, value_name = "ADDR=NAME")]
        rename: Vec<String>,
        /// Force-define a function at ADDR (hex). Repeatable.
        #[arg(long = "func", value_name = "ADDR", value_parser = parse_hex)]
        force_func: Vec<u64>,
        /// Remove a bogus auto-discovered function at ADDR (hex).
        /// Repeatable.
        #[arg(long = "not-func", value_name = "ADDR", value_parser = parse_hex)]
        not_func: Vec<u64>,
        /// Set calling convention: `ADDR=CONV`. Repeatable.
        #[arg(long, value_name = "ADDR=CONV")]
        cc: Vec<String>,
        /// Attach a plate comment: `ADDR=TEXT`. Repeatable.
        #[arg(long, value_name = "ADDR=TEXT")]
        comment: Vec<String>,
        /// Bulk-import (offset, name) pairs from FILE and merge into
        /// the rename map. Accepts JSON (object map or array of
        /// records) and "ADDR NAME" text. Mangled C++ / Rust names
        /// are demangled unless `--keep-mangled` is passed. The
        /// primary use case is loading a community-maintained
        /// symbol database (e.g. LeviLamina's BDS function list) so
        /// every command shows readable names instead of FUN_xxx.
        #[arg(long, value_name = "FILE")]
        import: Option<PathBuf>,
        /// With --import, store the mangled name verbatim instead of
        /// running it through the demangler.
        #[arg(long, requires = "import")]
        keep_mangled: bool,
        /// Print the current override set and exit (no edits).
        #[arg(long)]
        list: bool,
        /// Remove all overrides (delete the sidecar).
        #[arg(long)]
        clear: bool,
    },
    /// Auto-iterate analyser-correction proposals to a fixpoint.
    ///
    /// Each round:
    ///   1. Analyse the binary (auto + current sidecar overrides).
    ///   2. Run the heuristic correction engine to surface
    ///      probable analyser mistakes (calls to undiscovered
    ///      functions, false-positive tiny functions, ...).
    ///   3. If `--apply`, persist new corrections to the
    ///      `<binary>.gra.json` sidecar and re-analyse next round.
    ///   4. Stop when a round produces zero new proposals
    ///      (converged) or `--max-rounds` is hit.
    ///
    /// Without `--apply` the loop runs ONCE and just prints
    /// proposals (dry run) -- useful for previewing what the
    /// auto-driver would do.
    Iterate {
        /// Path to the binary file
        file: PathBuf,
        /// Persist proposals to the sidecar and iterate. Without
        /// this flag, just print a single round of proposals.
        #[arg(long)]
        apply: bool,
        /// Maximum rounds before giving up (default 5).
        #[arg(long, default_value = "5")]
        max_rounds: usize,
    },
    /// List every Call site with statically-resolved argument values.
    ///
    /// For each Call instruction the tool walks back through the
    /// caller's lifted P-code, tracking the most recent constant
    /// write to each calling-convention argument register. Output is
    /// one line per call site: address, target (when direct), and
    /// the resolved register values. Foundational data for tracking
    /// parser-registry / callback chains across functions.
    Callsites {
        /// Path to the binary file
        file: PathBuf,
        /// Only show call sites whose target matches this function
        /// address (hex). Useful for "who calls register_parser?".
        #[arg(short, long, value_parser = parse_hex)]
        target: Option<u64>,
        /// Only show call sites that resolved at least N arguments.
        #[arg(short = 'n', long, default_value = "0")]
        min_resolved: usize,
        /// Inter-procedural propagation iterations. 0 = intra-
        /// function only. 1+ = propagate resolved arguments into
        /// callees and re-resolve, letting chains like
        /// `register_parser(my_cb) -> list_add(my_cb) -> ...`
        /// surface end-to-end. Stops early at fixpoint.
        #[arg(short = 'i', long, default_value = "3")]
        iters: usize,
        /// Callback-mode: only list call sites where at least one
        /// resolved argument value matches the entry point of a
        /// known function (i.e., a function pointer is being
        /// passed in). Surfaces parser-registry / callback-table
        /// patterns directly. Implies inter-procedural propagation.
        #[arg(long)]
        callbacks: bool,
    },
    /// Per-section Shannon entropy report.
    ///
    /// Surfaces packed / encrypted regions (UPX, Themida, VMProtect,
    /// ASPack, …). Sections above 7.0 bits/byte are flagged as
    /// high-entropy; above 7.5 as likely packed.
    Entropy {
        /// Path to the binary file
        file: PathBuf,
    },
    /// Find ROP / JOP / COP gadgets in executable sections (x86 / x64 only).
    ///
    /// Walks every executable section, locates each terminator
    /// (`ret` for ROP, indirect `jmp` for JOP, indirect `call` for
    /// COP), and disassembles backwards to enumerate the valid
    /// instruction sequences ending at the terminator. Output
    /// matches the ROPgadget / ropper format.
    Rop {
        /// Path to the binary file
        file: PathBuf,
        /// Bytes to walk back from each terminator (controls how long
        /// a gadget can be)
        #[arg(long, default_value_t = 20)]
        depth: usize,
        /// Maximum number of instructions in each gadget (excluding
        /// the trailing terminator)
        #[arg(long, default_value_t = 6)]
        max_insns: usize,
        /// Filter to gadgets made of useful mnemonics (pop / mov /
        /// xor / add / sub / push / xchg / lea / …)
        #[arg(long)]
        useful_only: bool,
        /// Substring filter applied to the gadget text (e.g. "pop rdi")
        #[arg(long)]
        contains: Option<String>,
        /// Maximum gadgets to print (0 = unlimited)
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Gadget kinds to search for. Comma-separated list of
        /// `rop`, `jop`, `cop`. Default `rop` matches classic
        /// ROPgadget behaviour; pass `all` for ROP + JOP + COP.
        #[arg(long, default_value = "rop")]
        kinds: String,
    },
    /// Capa-style capability rule report.
    ///
    /// Matches built-in rules against discovered imports, strings,
    /// and tags. Surfaces high-level verbs like "encrypts data using
    /// AES" or "captures keyboard input" — what does this binary do?
    Capa {
        /// Path to the binary file
        file: PathBuf,
        /// Filter rules whose namespace contains this substring
        #[arg(long)]
        namespace: Option<String>,
    },
    /// DIE / PEiD-style packer signature detection (UPX, ASPack, Themida, …)
    Packer {
        /// Path to the binary file
        file: PathBuf,
    },
    /// Scan loaded memory for embedded files (Binwalk-style).
    ///
    /// Looks for ELF / PE / Mach-O droppers, ZIP / GZIP / 7z
    /// archives, PNG / JPEG / PDF resources inside `.rsrc` / data
    /// sections.
    Embedded {
        /// Path to the binary file
        file: PathBuf,
        /// Maximum number of findings to print (0 = unlimited)
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Cwe_checker-style vulnerability pattern report.
    ///
    /// Tags functions that call known-dangerous APIs (`gets`,
    /// unchecked `strcpy`, `system`, predictable RNG, …) with the
    /// matching CWE id.
    Vuln {
        /// Path to the binary file
        file: PathBuf,
    },
    /// Extract indicators-of-compromise (URLs, IPs, registry keys, …)
    /// from discovered strings.
    ///
    /// Each finding is also surfaced as a Custom `ioc` tag at the
    /// string address, so `tags --filter ioc` produces the same
    /// listing.
    Ioc {
        /// Path to the binary file
        file: PathBuf,
        /// Filter results to one kind (`url`, `ipv4`, `ipv6`,
        /// `registry-key`, `named-pipe`, `mutex`, `win-path`,
        /// `posix-path`, `email`, `eth-addr`, `btc-addr`,
        /// `user-agent`, `domain`)
        #[arg(long)]
        kind: Option<String>,
    },
    /// Scan a binary with a YARA-lite ruleset.
    ///
    /// Supports a strict subset of YARA: text + hex strings (with
    /// `??` / `?A` / `A?` wildcards), `nocase` modifier, boolean
    /// conditions (`and` / `or` / `not`, parentheses), and
    /// quantifiers (`any of them`, `all of them`, `N of them`).
    /// Reports one line per matched rule plus the offsets of each
    /// contributing string. Unsupported syntax (`wide`, regex,
    /// loops) errors out instead of silently skipping.
    Yara {
        /// Path to the binary file
        file: PathBuf,
        /// Path to the `.yar` rule file
        rules: PathBuf,
        /// Show the first N string-match offsets per rule (default 5)
        #[arg(long, default_value_t = 5)]
        sample: usize,
    },
    /// FLOSS-lite obfuscated string decoder.
    ///
    /// Brute-force XOR / ROL (optionally ADD) decode of every
    /// read-only data section. Surfaces strings that don't appear
    /// in a plain `strings` pass because they're stored encoded.
    Floss {
        /// Path to the binary file
        file: PathBuf,
        /// Minimum decoded-string length (default 8)
        #[arg(long, default_value_t = 8)]
        min_length: usize,
        /// Also try ADD-decode (default off — ADD is rarer and noisier)
        #[arg(long)]
        with_add: bool,
        /// Print only the first N hits (0 = unlimited)
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Disable the conservative "encoded bytes must be non-printable"
        /// filter. Off by default — turn on to chase obfuscated
        /// strings whose encoded form happens to be printable too.
        /// Substantially noisier.
        #[arg(long)]
        include_printable_source: bool,
    },
    /// Compare two binaries by TLSH fuzzy hash.
    ///
    /// Lower distance = more similar. Per the TLSH reference: < 30
    /// likely same family, < 50 related, > 100 unrelated.
    TlshDiff {
        /// First binary
        file_a: PathBuf,
        /// Second binary
        file_b: PathBuf,
    },
    /// One-screen malware-triage report.
    ///
    /// Runs the full analysis pipeline and prints a digestible
    /// summary combining: format / arch / entry, identity
    /// (compiler / language / runtime / imphash), packer / entropy,
    /// capability rules matched, dangerous-API call sites, IoCs by
    /// kind, and tag counts. Designed for "what is this and should I
    /// worry about it?" in one pass.
    Triage {
        /// Path to the binary file
        file: PathBuf,
    },
    /// Patch a binary file
    Patch {
        /// Path to the binary file
        file: PathBuf,
        /// Address to patch (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,
        /// Hex bytes to write (e.g. "90 90 90")
        #[arg(long)]
        bytes: Option<String>,
        /// Assembly instruction to assemble and write
        #[arg(long)]
        asm: Option<String>,
        /// Output file path (default: overwrites input)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Carve a single function (or VA range) into a small standalone file.
    ///
    /// Sidesteps the size limit that makes GUI Ghidra truncate / choke
    /// on very large images (e.g. the ~222 MB Minecraft Bedrock server)
    /// by extracting only the bytes of interest while keeping their
    /// original virtual address, so RIP-relative operands and call
    /// targets still resolve correctly.
    ///
    /// Range selection (pick one): `--address` carves a discovered
    /// function's full extent (runs analysis); `--address --size`,
    /// `--start --end`, or `--start --size` carve an explicit range
    /// without analysis (fast on huge binaries).
    ///
    /// `--format elf` (default) emits a minimal ELF placed at the
    /// original VA that Ghidra and RE-Argo auto-load with no manual
    /// setup; `--format raw` emits the bytes verbatim and prints the
    /// Ghidra "Raw Binary" import parameters.
    Carve {
        /// Path to the binary file
        file: PathBuf,
        /// Function entry address to carve (hex). Runs analysis to find
        /// the function extent unless `--size` is also given.
        #[arg(long, value_parser = parse_hex)]
        address: Option<u64>,
        /// Start of an explicit VA range to carve (hex)
        #[arg(long, value_parser = parse_hex)]
        start: Option<u64>,
        /// End of the VA range, exclusive (hex). Use with `--start`.
        #[arg(long, value_parser = parse_hex)]
        end: Option<u64>,
        /// Number of bytes to carve. Use with `--address` or `--start`.
        #[arg(long)]
        size: Option<u64>,
        /// Container format: `elf` (default, auto-loads) or `raw`.
        #[arg(long, default_value = "elf")]
        format: String,
        /// Output file path (default: `<file>.carved.<addr>.elf` / `.bin`)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Fast cross-reference scan to an address WITHOUT full analysis.
    ///
    /// Linear-disassembles the executable sections and reports every
    /// instruction whose resolved operand points at TARGET: rip-relative
    /// memory refs, direct call/jmp targets, and absolute immediates.
    /// Scales to multi-hundred-MB binaries where `xrefs` (which needs the
    /// full analysis pipeline) is impractical.
    XrefScan {
        /// Path to the binary file
        file: PathBuf,
        /// Target address to find references to (hex)
        #[arg(value_parser = parse_hex)]
        target: u64,
        /// Maximum hits to report (0 = unlimited)
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| format!("invalid hex address: {}", e))
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Info { file } => cmd_info(&file),
        Commands::Sections { file } => cmd_sections(&file),
        Commands::Symbols { file, kind, all, name } => cmd_symbols(&file, kind.as_deref(), all, name.as_deref()),
        Commands::Disasm {
            file,
            start,
            count,
        } => cmd_disasm(&file, start, count, cli.thumb),
        Commands::Registers { file } => cmd_registers(&file),
        Commands::Analyze { file } => cmd_analyze(&file),
        Commands::Functions { file } => cmd_functions(&file),
        Commands::Metrics { file, sort, top } => cmd_metrics(&file, &sort, top),
        Commands::Summary { file } => cmd_summary(&file),
        Commands::Tags { file, filter, list_types } => cmd_tags(&file, filter.as_deref(), list_types),
        Commands::Bench { file } => cmd_bench(&file),
        Commands::Find { file, query, limit } => cmd_find(&file, &query, limit),
        Commands::Signatures { export, library } => cmd_signatures(export.as_deref(), library.as_deref()),
        Commands::Workflow { declared_only } => cmd_workflow(declared_only),
        Commands::Cfg { file, address } => cmd_cfg(&file, address),
        Commands::Xrefs { file, address } => cmd_xrefs(&file, address),
        Commands::Callgraph {
            file,
            dot,
            scc,
            around,
            depth,
        } => cmd_callgraph(&file, dot, scc, around, depth),
        Commands::Backtrace { file, address, depth, max_paths } => cmd_backtrace(&file, address, depth, max_paths),
        Commands::Memmap { file } => cmd_memmap(&file),
        Commands::Pcode {
            file,
            start,
            count,
        } => cmd_pcode(&file, start, count, cli.thumb),
        Commands::Decompile { file, address, ssa, rust } => cmd_decompile(&file, address, ssa, rust, cli.thumb),
        Commands::DecompileAll { file, output_dir, rust, skip_errors } => cmd_decompile_all(&file, output_dir.as_deref(), rust, skip_errors, cli.thumb),
        Commands::Taint { file, address, params } => cmd_taint(&file, address, params, cli.thumb),
        Commands::Export { file, output } => cmd_export(&file, output.as_deref()),
        Commands::ExportXml { file, output } => cmd_export_xml(&file, output.as_deref()),
        Commands::Emulate { file, start, steps, breakpoints } => cmd_emulate(&file, start, steps, &breakpoints, cli.thumb),
        Commands::Gdbserver { file, start, listen } => cmd_gdbserver(&file, start, &listen, cli.thumb),
        Commands::Debug { file, start } => cmd_debug(&file, start, cli.thumb),
        Commands::Hexdump {
            file,
            address,
            length,
        } => cmd_hexdump(&file, address, length),
        Commands::Strings { file, min_length, all } => cmd_strings(&file, min_length, all),
        Commands::Diff { file_a, file_b } => cmd_diff(&file_a, &file_b),
        Commands::SemanticDiff { file_a, file_b, kinds } => cmd_semantic_diff(&file_a, &file_b, &kinds, cli.thumb),
        Commands::Imports { file, exports } => cmd_imports(&file, exports),
        Commands::Coverage { file, annotated } => cmd_coverage(&file, annotated),
        Commands::Script { file, script } => cmd_script(&file, &script, cli.thumb),
        Commands::Mcp { file } => mcp::run_stdio(&file, cli.thumb),
        Commands::Annotate { file, rename, force_func, not_func, cc, comment, import, keep_mangled, list, clear } =>
            cmd_annotate(&file, &rename, &force_func, &not_func, &cc, &comment, import.as_deref(), keep_mangled, list, clear),
        Commands::Iterate { file, apply, max_rounds } => cmd_iterate(&file, apply, max_rounds),
        Commands::Callsites { file, target, min_resolved, iters, callbacks } => cmd_callsites(&file, target, min_resolved, iters, callbacks, cli.thumb),
        Commands::Search { file, hex, text, max_results } => cmd_search(&file, hex.as_deref(), text.as_deref(), max_results),
        Commands::Patch { file, address, bytes, asm, output } => cmd_patch(&file, address, bytes.as_deref(), asm.as_deref(), output.as_deref()),
        Commands::Carve { file, address, start, end, size, format, output } =>
            cmd_carve(&file, address, start, end, size, &format, output.as_deref(), cli.thumb),
        Commands::XrefScan { file, target, limit } => cmd_xref_scan(&file, target, limit),
        Commands::Entropy { file } => cmd_entropy(&file),
        Commands::Rop { file, depth, max_insns, useful_only, contains, limit, kinds } =>
            cmd_rop(&file, depth, max_insns, useful_only, contains.as_deref(), limit, &kinds),
        Commands::Capa { file, namespace } => cmd_capa(&file, namespace.as_deref()),
        Commands::Packer { file } => cmd_packer(&file),
        Commands::Embedded { file, limit } => cmd_embedded(&file, limit),
        Commands::Vuln { file } => cmd_vuln(&file),
        Commands::Ioc { file, kind } => cmd_ioc(&file, kind.as_deref()),
        Commands::Triage { file } => cmd_triage(&file),
        Commands::TlshDiff { file_a, file_b } => cmd_tlsh_diff(&file_a, &file_b),
        Commands::Floss { file, min_length, with_add, limit, include_printable_source } =>
            cmd_floss(&file, min_length, with_add, limit, include_printable_source),
        Commands::Yara { file, rules, sample } => cmd_yara(&file, &rules, sample),
    }
}

fn cmd_info(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // We need a Program (not just BinaryInfo) so the fingerprint
    // analyzer can populate metadata cheaply — it only reads .comment
    // and .note.gnu.build-id; no disassembly or lifting.
    let mut program = reargo_program::Program::from_binary(path)?;
    let info = &program.info;
    println!("File:         {}", path.display());
    println!("Format:       {}", info.format);
    println!("Architecture: {}", info.arch);
    println!("Bits:         {}", info.bits);
    println!("Endian:       {:?}", info.endian);
    println!("Entry Point:  0x{:x}", info.entry_point);
    println!("Sections:     {}", info.sections.len());
    println!("Symbols:      {}", info.symbols.len());

    let fp = reargo_analysis::fingerprint::CompilerFingerprintAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&fp, &mut program);
    let rfp = reargo_analysis::runtime_fp::RuntimeFingerprintAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&rfp, &mut program);
    let pe = reargo_analysis::pe_enrich::PeEnrichmentAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&pe, &mut program);
    // Imphash, packer, and overall entropy are all cheap analyses
    // that surface high-signal triage info. We run them here so
    // `info` shows them without a full pipeline run.
    let imp = reargo_analysis::imphash::ImphashAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&imp, &mut program);
    let tl = reargo_analysis::tlsh::TlshAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&tl, &mut program);
    let rh = reargo_analysis::rich_header::RichHeaderAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&rh, &mut program);
    let auth = reargo_analysis::authenticode::AuthenticodeAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&auth, &mut program);
    let ent = reargo_analysis::entropy::EntropyAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&ent, &mut program);
    let pkr = reargo_analysis::packer::PackerAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&pkr, &mut program);
    let sa = reargo_analysis::section_anomaly::SectionAnomalyAnalyzer;
    let _ = reargo_analysis::Analyzer::analyze(&sa, &mut program);

    let p = &program.metadata.properties;
    if !p.is_empty() {
        println!();
        for key in [
            "compiler",
            "language",
            "runtime",
            "libc_version",
            "build_id",
            "pe_product",
            "pe_version",
            "imphash",
            "tlsh",
            "richhash",
            "signed",
            "cert_subjects",
            "packer",
            "entropy_overall",
        ] {
            if let Some(v) = p.get(key) {
                println!("{:<16} {}", format!("{}:", key), v);
            }
        }
    }
    Ok(())
}

fn cmd_sections(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
    println!(
        "{:<30} {:>16} {:>12} Flags",
        "Name", "Address", "Size"
    );
    println!("{}", "-".repeat(70));
    for section in &info.sections {
        let flags = format!(
            "{}{}{}",
            if section.flags.contains(reargo_loader::SectionFlags::READ) {
                "r"
            } else {
                "-"
            },
            if section.flags.contains(reargo_loader::SectionFlags::WRITE) {
                "w"
            } else {
                "-"
            },
            if section.flags.contains(reargo_loader::SectionFlags::EXECUTE) {
                "x"
            } else {
                "-"
            },
        );
        println!(
            "{:<30} {:>16} {:>12} {}",
            section.name,
            format!("0x{:x}", section.address),
            format!("0x{:x}", section.size),
            flags
        );
    }
    Ok(())
}

fn cmd_symbols(
    path: &Path,
    kind_filter: Option<&str>,
    include_analysis: bool,
    name_filter: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{:<8} {:>16} {:>8} Name",
        "Kind", "Address", "Size"
    );
    println!("{}", "-".repeat(60));

    let kind_match = kind_filter.map(|k| match k.to_lowercase().as_str() {
        "func" | "function" => Some(SymbolKind::Function),
        "data" => Some(SymbolKind::Data),
        "import" => Some(SymbolKind::Import),
        "export" => Some(SymbolKind::Export),
        _ => None,
    });

    let name_lc = name_filter.map(|s| s.to_lowercase());
    let name_pass = |name: &str| -> bool {
        match &name_lc {
            Some(n) => name.to_lowercase().contains(n),
            None => true,
        }
    };

    if !include_analysis {
        let info = BinaryLoader::load(path)?;
        for sym in &info.symbols {
            if let Some(ref filter) = kind_match
                && let Some(expected) = filter
                && sym.kind != *expected
            {
                continue;
            }
            if !name_pass(&sym.name) {
                continue;
            }
            println!(
                "{:<8} {:>16} {:>8} {}",
                format!("{}", sym.kind),
                format!("0x{:x}", sym.address),
                sym.size,
                sym.name
            );
        }
        return Ok(());
    }

    // `--all`: run the full analysis pipeline and emit every
    // symbol the program model has, deduped by (addr, name).
    // This is what surfaces RTTI vtable / typeinfo names that
    // the analyzers added but the loader-only path can't see.
    let program = analyze_binary(path)?;
    use reargo_program::symbol::SymbolType as PSymType;
    let to_kind = |ty: PSymType| -> SymbolKind {
        match ty {
            PSymType::Function => SymbolKind::Function,
            PSymType::ExternalFunction => SymbolKind::Import,
            PSymType::ExternalData => SymbolKind::Import,
            PSymType::Data | PSymType::Label => SymbolKind::Data,
        }
    };
    let mut seen: std::collections::HashSet<(u64, String)> =
        std::collections::HashSet::new();
    let mut rows: Vec<(u64, SymbolKind, String)> = Vec::new();
    for sym in program.symbol_table.iter() {
        let kind = to_kind(sym.symbol_type);
        if let Some(ref filter) = kind_match
            && let Some(expected) = filter
            && kind != *expected
        {
            continue;
        }
        if !name_pass(&sym.name) {
            continue;
        }
        if !seen.insert((sym.address, sym.name.clone())) {
            continue;
        }
        rows.push((sym.address, kind, sym.name.clone()));
    }
    rows.sort_by_key(|(a, _, _)| *a);
    for (addr, kind, name) in rows {
        println!(
            "{:<8} {:>16} {:>8} {}",
            format!("{}", kind),
            format!("0x{:x}", addr),
            0,
            name
        );
    }
    Ok(())
}

fn cmd_hexdump(
    path: &Path,
    address: u64,
    length: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
    let mut buf = vec![0u8; length];
    let bytes_read = match info.memory.read_bytes(address, &mut buf) {
        Ok(()) => length,
        Err(_) => {
            let mut count = 0;
            for (i, slot) in buf.iter_mut().enumerate().take(length) {
                match info.memory.read_byte(address + i as u64) {
                    Some(b) => {
                        *slot = b;
                        count = i + 1;
                    }
                    None => break,
                }
            }
            count
        }
    };

    if bytes_read == 0 {
        println!("No data at address 0x{:x}", address);
        return Ok(());
    }

    for row_start in (0..bytes_read).step_by(16) {
        let row_addr = address + row_start as u64;
        print!("  {:08x}  ", row_addr);

        for col in 0..16 {
            let idx = row_start + col;
            if idx < bytes_read {
                print!("{:02x} ", buf[idx]);
            } else {
                print!("   ");
            }
            if col == 7 {
                print!(" ");
            }
        }

        print!(" |");
        for col in 0..16 {
            let idx = row_start + col;
            if idx < bytes_read {
                let c = buf[idx];
                if c.is_ascii_graphic() || c == b' ' {
                    print!("{}", c as char);
                } else {
                    print!(".");
                }
            }
        }
        println!("|");
    }

    Ok(())
}

fn cmd_disasm(path: &Path, start: Option<u64>, count: usize, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
    let arch = create_architecture_with_options(info.arch, thumb)?;
    let address = start.unwrap_or(info.entry_point);

    println!(
        "Disassembly of {} ({}) at 0x{:x}:\n",
        path.display(),
        arch.name(),
        address
    );

    let instructions = arch.decode_linear(&info.memory, address, count)?;
    for insn in &instructions {
        println!("{}", insn);
    }

    if instructions.is_empty() {
        println!("  (no instructions decoded at 0x{:x})", address);
    }
    Ok(())
}

fn cmd_registers(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
    let arch = create_architecture(info.arch)?;

    println!("Registers for {} ({}):\n", path.display(), arch.name());
    println!(
        "{:<12} {:>6} {:>10} {:>6}  Aliases",
        "Name", "Size", "Offset", "Space"
    );
    println!("{}", "-".repeat(55));

    for reg in arch.registers() {
        let aliases = if reg.aliases.is_empty() {
            String::new()
        } else {
            reg.aliases.join(", ")
        };
        println!(
            "{:<12} {:>4}B  0x{:06x} {:>6}  {}",
            reg.name,
            reg.varnode.size,
            reg.varnode.offset,
            reg.varnode.space.0,
            aliases
        );
    }

    if let Some(sp) = arch.stack_pointer() {
        println!("\nStack pointer: {}", sp.name);
    }

    if let Some(cc) = arch.default_calling_convention() {
        println!("Default calling convention: {}", cc.name);
    }

    Ok(())
}

fn create_lifter(
    arch: reargo_loader::Architecture,
    bits: u32,
    endian: reargo_core::address::Endian,
    thumb: bool,
) -> Option<Box<dyn PcodeLift>> {
    match arch {
        reargo_loader::Architecture::X86 | reargo_loader::Architecture::X86_64 => {
            if bits == 64 { Some(Box::new(X86Lifter::new_64())) } else { Some(Box::new(X86Lifter::new_32())) }
        }
        reargo_loader::Architecture::Arm64 => Some(Box::new(Aarch64Lifter::new())),
        reargo_loader::Architecture::Arm => Some(Box::new(if thumb {
            Arm32Lifter::new_thumb(endian)
        } else {
            Arm32Lifter::new(endian)
        })),
        reargo_loader::Architecture::Mips => Some(Box::new(MipsLifter::new_32(endian))),
        reargo_loader::Architecture::Riscv32 => Some(Box::new(RiscVLifter::new_rv32())),
        reargo_loader::Architecture::PowerPc => Some(Box::new(PpcLifter::new_32(endian))),
        reargo_loader::Architecture::Sparc => Some(Box::new(SparcLifter::new_32())),
        _ => None,
    }
}

/// Build the per-address ARM/Thumb region map from ELF `$a`/`$t`/`$d` mapping
/// symbols (names may carry a `.N` suffix).
fn arm_region_mapping(info: &reargo_loader::BinaryInfo) -> Vec<(u64, ArmRegion)> {
    let mut mapping = Vec::new();
    for sym in &info.symbols {
        let region = if sym.name == "$a" || sym.name.starts_with("$a.") {
            ArmRegion::Arm
        } else if sym.name == "$t" || sym.name.starts_with("$t.") {
            ArmRegion::Thumb
        } else if sym.name == "$d" || sym.name.starts_with("$d.") {
            ArmRegion::Data
        } else {
            continue;
        };
        mapping.push((sym.address, region));
    }
    mapping
}

/// Select a lifter for a loaded binary. For ARM, mapping symbols drive
/// automatic A32/Thumb switching unless `force_thumb` overrides to all-Thumb.
fn make_lifter(info: &reargo_loader::BinaryInfo, force_thumb: bool) -> Option<Box<dyn PcodeLift>> {
    if info.arch == reargo_loader::Architecture::Arm && !force_thumb {
        let mapping = arm_region_mapping(info);
        if !mapping.is_empty() {
            return Some(Box::new(MappedArmLifter::new(info.endian, mapping)));
        }
    }
    create_lifter(info.arch, info.bits, info.endian, force_thumb)
}

fn analyze_binary(path: &Path) -> Result<Program, Box<dyn std::error::Error>> {
    let mut program = Program::from_binary(path)?;
    let manager = AnalysisManager::new();
    let results = manager.run_all(&mut program);
    for r in &results {
        match r {
            Ok(r) => eprintln!(
                "[{}] {} functions, {} refs, {} instructions",
                r.analyzer_name, r.functions_found, r.references_found, r.instructions_decoded
            ),
            Err(e) => eprintln!("[ERROR] {}", e),
        }
    }

    // Apply the user-override sidecar (`<binary>.gra.json`) LAST, so
    // manual corrections win over auto-analysis and propagate to
    // every command that loads the binary -- the interactive
    // manual-correction layer a mature reversing workflow needs.
    match reargo_program::OverrideSet::load_for_binary(path) {
        Ok(overrides) if !overrides.is_empty() => {
            let n = overrides.apply(&mut program);
            eprintln!(
                "[overrides] applied {} of {} corrections from {}",
                n,
                overrides.len(),
                reargo_program::OverrideSet::sidecar_path(path).display()
            );
        }
        Ok(_) => {}
        Err(e) => eprintln!("[overrides] WARNING: {}", e),
    }

    Ok(program)
}

fn cmd_analyze(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    println!("\nAnalysis complete: {}", path.display());
    println!("  Functions:    {}", program.listing.function_count());
    println!("  Instructions: {}", program.listing.instruction_count());
    println!("  References:   {}", program.references.len());
    println!("  Symbols:      {}", program.symbol_table.len());
    Ok(())
}

fn cmd_functions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    println!(
        "\n{:<18} {:<40} {:>8}",
        "Address", "Name", "Blocks"
    );
    println!("{}", "-".repeat(70));
    for func in program.listing.functions() {
        println!(
            "0x{:016x} {:<40} {:>8}",
            func.entry_point,
            func.name,
            func.body.len(),
        );
    }
    println!("\nTotal: {} functions", program.listing.function_count());
    Ok(())
}

fn cmd_metrics(
    path: &Path,
    sort: &str,
    top: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    // Collect (entry, name, metrics) for every function whose
    // ComplexityAnalyzer summary was written into metadata.
    let mut rows: Vec<(u64, String, reargo_analysis::complexity::FunctionMetrics)> = Vec::new();
    for f in program.listing.functions() {
        let key = format!("func_{:x}_metrics", f.entry_point);
        let Some(raw) = program.metadata.get_property(&key) else {
            continue;
        };
        let Some(m) = reargo_analysis::complexity::parse_metrics(raw) else {
            continue;
        };
        rows.push((f.entry_point, f.name.clone(), m));
    }

    let key_of = |m: &reargo_analysis::complexity::FunctionMetrics| -> i64 {
        match sort {
            "mccabe" => m.cyclomatic as i64,
            "blocks" => m.basic_blocks as i64,
            "insns" => m.instructions as i64,
            "fan_in" => m.fan_in as i64,
            "fan_out" => m.fan_out as i64,
            "stack" => m.stack_size as i64,
            _ => m.cyclomatic as i64,
        }
    };
    rows.sort_by_key(|(_, _, m)| -key_of(m));
    if rows.len() > top {
        rows.truncate(top);
    }

    println!(
        "\n{:<18} {:<32} {:>6} {:>6} {:>6} {:>6} {:>7} {:>8}",
        "Address", "Name", "insns", "blocks", "mccabe", "fanIn", "fanOut", "stack"
    );
    println!("{}", "-".repeat(95));
    for (addr, name, m) in &rows {
        let display_name = if name.len() > 32 {
            format!("{}…", &name[..31])
        } else {
            name.clone()
        };
        println!(
            "0x{:016x} {:<32} {:>6} {:>6} {:>6} {:>6} {:>7} {:>8}",
            addr,
            display_name,
            m.instructions,
            m.basic_blocks,
            m.cyclomatic,
            m.fan_in,
            m.fan_out,
            m.stack_size
        );
    }
    println!("\nShowing top {} sorted by {}", rows.len(), sort);
    Ok(())
}

fn cmd_summary(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let info = &program.info;

    println!("=== {} ===", path.display());
    println!("  Format         {} / {} ({} bit)", info.format, info.arch, info.bits);
    println!("  Entry          0x{:x}", info.entry_point);

    // Runtime / language summary from metadata.
    let p = &program.metadata.properties;
    let interesting_keys = [
        "language", "runtime", "compiler", "libc_version",
        "pe_product", "pe_version", "build_id",
    ];
    let mut had_meta = false;
    for k in interesting_keys {
        if let Some(v) = p.get(k) {
            if !had_meta {
                println!();
                println!("Identity:");
                had_meta = true;
            }
            println!("  {:<14} {}", k, v);
        }
    }

    // Function counts: total / named / with metrics.
    let total = program.listing.function_count();
    let named = program
        .listing
        .functions()
        .filter(|f| !f.name.starts_with("FUN_"))
        .count();
    let no_return = program.listing.functions().filter(|f| f.no_return).count();
    let thunks = program.listing.functions().filter(|f| f.is_thunk).count();
    println!();
    println!("Functions:");
    println!("  total          {}", total);
    println!("  named          {} ({:.0}%)",
        named,
        if total > 0 { 100.0 * named as f64 / total as f64 } else { 0.0 });
    println!("  no-return      {}", no_return);
    println!("  thunks         {}", thunks);

    // Comment / annotation totals.
    let mut by_kind: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for c in program.comments.iter() {
        *by_kind.entry(format!("{:?}", c.comment_type)).or_default() += 1;
    }
    if !by_kind.is_empty() {
        println!();
        println!("Annotations:");
        for (k, v) in &by_kind {
            println!("  {:<14} {}", k.to_ascii_lowercase(), v);
        }
    }

    // Hot functions — top 5 by fan-in inferred from metrics.
    let mut top: Vec<(u64, String, usize)> = Vec::new();
    for f in program.listing.functions() {
        let key = format!("func_{:x}_metrics", f.entry_point);
        if let Some(raw) = p.get(&key)
            && let Some(m) = reargo_analysis::complexity::parse_metrics(raw)
        {
            top.push((f.entry_point, f.name.clone(), m.fan_in));
        }
    }
    top.sort_by_key(|(_, _, fan)| std::cmp::Reverse(*fan));
    let to_show: Vec<_> = top
        .into_iter()
        .filter(|(_, _, fi)| *fi >= 3)
        .take(8)
        .collect();
    if !to_show.is_empty() {
        println!();
        println!("Hottest:");
        for (addr, name, fan) in &to_show {
            println!("  0x{:<12x} called by {} functions  {}", addr, fan, name);
        }
    }

    // SCC clusters from metadata.
    let mut scc_keys: Vec<&String> = p.keys().filter(|k| k.starts_with("scc_")).collect();
    scc_keys.sort();
    if !scc_keys.is_empty() {
        println!();
        println!("Recursive clusters: {}", scc_keys.len());
        for k in scc_keys.iter().take(4) {
            if let Some(v) = p.get(*k) {
                println!("  {}", v);
            }
        }
        if scc_keys.len() > 4 {
            println!("  …{} more", scc_keys.len() - 4);
        }
    }

    // Triage findings — surface the work the packer / entropy / capa
    // / vuln / ioc / imphash analyzers did so users don't have to
    // invoke each command separately.
    let packer = p.get("packer");
    let imphash = p.get("imphash");
    let entropy_overall = p.get("entropy_overall");
    let capa_lines = p.get("capa_rules").map(|s| s.lines().count()).unwrap_or(0);
    let ioc_count: usize = p
        .get("ioc_count")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let bug_count = program
        .tags
        .iter_functions()
        .filter(|(_, t)| matches!(t.kind, reargo_program::TagKind::Bug))
        .count();

    if packer.is_some()
        || imphash.is_some()
        || entropy_overall.is_some()
        || capa_lines > 0
        || ioc_count > 0
        || bug_count > 0
    {
        println!();
        println!("Triage:");
        if let Some(v) = packer {
            let evidence = p
                .get("packer_evidence")
                .map(|e| format!(" ({})", e))
                .unwrap_or_default();
            println!("  packer         {}{}", v, evidence);
        }
        if let Some(v) = entropy_overall {
            println!("  entropy        {} bits/byte (overall)", v);
        }
        if let Some(v) = imphash {
            println!("  imphash        {}", v);
        }
        if let Some(v) = p.get("richhash") {
            println!("  richhash       {}", v);
        }
        if let Some(v) = p.get("section_anomaly_count") {
            println!("  anomalies      {} section(s) flagged", v);
        }
        if capa_lines > 0 {
            println!("  capabilities   {} rule(s) matched", capa_lines);
            if let Some(raw) = p.get("capa_rules") {
                for r in raw.lines().take(3) {
                    println!("                 {}", r);
                }
                if capa_lines > 3 {
                    println!("                 …{} more", capa_lines - 3);
                }
            }
        }
        if bug_count > 0 {
            println!("  cwe-findings   {} dangerous-API call site(s)", bug_count);
        }
        if ioc_count > 0 {
            println!("  iocs           {} extracted (urls / paths / registry / …)", ioc_count);
        }
    }

    // Tag totals — already populated by the pipeline. Render the
    // full kind breakdown so users see at-a-glance what categories
    // fired without invoking `tags --list-types`.
    let tag_counts = program.tags.counts_by_kind();
    if !tag_counts.is_empty() {
        println!();
        println!("Tags by kind:");
        for (k, n) in &tag_counts {
            println!("  {:<14} {}", k, n);
        }
    }

    Ok(())
}

fn cmd_tags(
    path: &Path,
    filter: Option<&str>,
    list_types: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    if list_types {
        // Per-kind counts across both address + function scopes.
        let counts = program.tags.counts_by_kind();
        println!("\nTag categories in {}:", path.display());
        println!("{}", "-".repeat(48));
        println!("  {:<20} {:>8}", "kind", "count");
        for (k, n) in &counts {
            println!("  {:<20} {:>8}", k, n);
        }
        println!();
        println!("  Total tags: {}", program.tags.len());
        return Ok(());
    }

    let filter_kind = filter.map(reargo_program::TagKind::parse);

    println!("\nTags in {}", path.display());
    println!("{}", "-".repeat(72));
    println!("  scope      kind       address            auto   text");
    let mut shown = 0usize;
    for (addr, t) in program.tags.iter_addresses() {
        if let Some(k) = &filter_kind
            && &t.kind != k
        {
            continue;
        }
        println!(
            "  {:<10} {:<10} 0x{:<16x} {:<6} {}",
            "address",
            t.kind.as_str(),
            addr,
            t.auto,
            t.text
        );
        shown += 1;
    }
    for (addr, t) in program.tags.iter_functions() {
        if let Some(k) = &filter_kind
            && &t.kind != k
        {
            continue;
        }
        println!(
            "  {:<10} {:<10} 0x{:<16x} {:<6} {}",
            "function",
            t.kind.as_str(),
            addr,
            t.auto,
            t.text
        );
        shown += 1;
    }
    println!();
    println!("Showing {} tag{}", shown, if shown == 1 { "" } else { "s" });
    Ok(())
}

fn cmd_workflow(declared_only: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mgr = reargo_analysis::AnalysisManager::new();

    println!("Analyzer pipeline (priority order):");
    println!("{}", "-".repeat(72));
    println!("  prio  name                              provides → consumes");

    for (name, prio, provides, consumes) in mgr.workflow_listing() {
        if declared_only && provides.is_empty() && consumes.is_empty() {
            continue;
        }
        let p = provides.join(",");
        let c = consumes.join(",");
        println!(
            "  {:>4}  {:<32}  {} → {}",
            prio,
            name,
            if p.is_empty() { "-" } else { p.as_str() },
            if c.is_empty() { "-" } else { c.as_str() },
        );
    }

    let warnings = mgr.validate_workflow();
    if warnings.is_empty() {
        println!();
        println!("Workflow validation: OK (no dependency issues detected)");
    } else {
        println!();
        println!("Workflow validation: {} warning(s)", warnings.len());
        for (consumer, dep, problem) in &warnings {
            println!("  ⚠  {} consumes `{}` — {}", consumer, dep, problem);
        }
    }
    Ok(())
}

fn cmd_signatures(
    export: Option<&Path>,
    library: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = reargo_analysis::signatures::SignatureDatabase::new();
    if let Some(p) = export {
        db.save_to_file(p)?;
        println!(
            "Exported {} signatures to {}",
            db.signature_count(),
            p.display()
        );
        return Ok(());
    }

    println!("Built-in signature database: {} entries", db.signature_count());
    println!("{}", "-".repeat(72));
    println!("  library  name                      return       params");

    let mut shown = 0usize;
    for sig in db.iter_signatures() {
        if let Some(lib) = library
            && !sig.library.eq_ignore_ascii_case(lib)
        {
            continue;
        }
        let params = sig
            .parameters
            .iter()
            .map(|(n, t)| format!("{}: {}", n, t))
            .collect::<Vec<_>>()
            .join(", ");
        let name_col = if sig.no_return {
            format!("{} [noreturn]", sig.name)
        } else {
            sig.name.clone()
        };
        println!(
            "  {:<8} {:<25} {:<12} ({})",
            sig.library, name_col, sig.return_type, params
        );
        shown += 1;
    }
    println!();
    println!("Showing {} signatures", shown);
    Ok(())
}

fn cmd_find(
    path: &Path,
    query: &str,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let q = query.to_ascii_lowercase();

    println!("\nSearch results for `{}` in {}", query, path.display());
    println!("{}", "-".repeat(72));

    let mut hits = 0usize;

    // Functions
    let mut func_hits = 0usize;
    for f in program.listing.functions() {
        if hits >= limit {
            break;
        }
        if f.name.to_ascii_lowercase().contains(&q) {
            if func_hits == 0 {
                println!("\n[functions]");
            }
            println!("  0x{:<16x} {}", f.entry_point, f.name);
            func_hits += 1;
            hits += 1;
        }
    }

    // Symbols
    let mut sym_hits = 0usize;
    for s in program.symbol_table.iter() {
        if hits >= limit {
            break;
        }
        if s.name.to_ascii_lowercase().contains(&q) {
            if sym_hits == 0 {
                println!("\n[symbols]");
            }
            println!(
                "  0x{:<16x} {:<10} {}",
                s.address,
                format!("{:?}", s.symbol_type),
                s.name
            );
            sym_hits += 1;
            hits += 1;
        }
    }

    // Comments
    let mut com_hits = 0usize;
    for c in program.comments.iter() {
        if hits >= limit {
            break;
        }
        if c.text.to_ascii_lowercase().contains(&q) {
            if com_hits == 0 {
                println!("\n[comments]");
            }
            println!(
                "  0x{:<16x} {:<6} {}",
                c.address,
                format!("{:?}", c.comment_type),
                c.text
            );
            com_hits += 1;
            hits += 1;
        }
    }

    // Tags
    let mut tag_hits = 0usize;
    for (addr, t) in program.tags.iter_addresses() {
        if hits >= limit {
            break;
        }
        if t.kind.as_str().contains(&q) || t.text.to_ascii_lowercase().contains(&q) {
            if tag_hits == 0 {
                println!("\n[tags]");
            }
            println!("  0x{:<16x} {:<10} {}", addr, t.kind.as_str(), t.text);
            tag_hits += 1;
            hits += 1;
        }
    }
    for (addr, t) in program.tags.iter_functions() {
        if hits >= limit {
            break;
        }
        if t.kind.as_str().contains(&q) || t.text.to_ascii_lowercase().contains(&q) {
            if tag_hits == 0 {
                println!("\n[tags]");
            }
            println!("  0x{:<16x} {:<10} {}  [function-scope]", addr, t.kind.as_str(), t.text);
            tag_hits += 1;
            hits += 1;
        }
    }

    println!();
    println!(
        "{} hits (functions: {}, symbols: {}, comments: {}, tags: {})",
        hits, func_hits, sym_hits, com_hits, tag_hits
    );
    Ok(())
}

fn cmd_bench(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Measure the wall time of three stages independently so we can
    // see which one dominates: load → discovery → full analysis.
    let t0 = std::time::Instant::now();
    let mut program = reargo_program::Program::from_binary(path)?;
    let load_ms = t0.elapsed().as_millis();

    // The manager runs every registered analyzer in priority order.
    // We grab the elapsed before / after each one by re-instantiating
    // the pipeline and running it ourselves.
    let manager = reargo_analysis::AnalysisManager::new();

    let t1 = std::time::Instant::now();
    let results = manager.run_all(&mut program);
    let analysis_ms = t1.elapsed().as_millis();

    println!("Bench: {}", path.display());
    println!("  Load              {} ms", load_ms);
    println!("  Analysis (total)  {} ms", analysis_ms);

    // Just count refs / functions / comments contributed end-to-end.
    let total_funcs = program.listing.function_count();
    let total_insns = program.listing.instruction_count();
    let total_refs = program.references.len();
    let total_comments = program.comments.len();
    let analyzers_ok = results.iter().filter(|r| r.is_ok()).count();
    let analyzers_err = results.iter().filter(|r| r.is_err()).count();
    println!("  Analyzers OK / Err {} / {}", analyzers_ok, analyzers_err);
    println!("  Functions          {}", total_funcs);
    println!("  Instructions       {}", total_insns);
    println!("  References         {}", total_refs);
    println!("  Comments           {}", total_comments);
    Ok(())
}

fn cmd_cfg(path: &Path, address: u64) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let Some(func) = program.listing.get_function(address) else {
        eprintln!("cfg: no function at 0x{:x}", address);
        return Ok(());
    };

    // Compute basic blocks from instruction-level flow info. A new
    // block starts at: function entry, any branch target, and the
    // instruction immediately after any branch.
    use std::collections::{BTreeMap, BTreeSet};
    let mut block_starts: BTreeSet<u64> = BTreeSet::new();
    block_starts.insert(func.entry_point);
    let ranges: Vec<(u64, u64)> = func
        .body
        .ranges()
        .map(|r| (r.start.offset, r.start.offset + r.size))
        .collect();
    let mut insns: Vec<&reargo_arch::DecodedInstruction> = Vec::new();
    for (s, e) in &ranges {
        for ins in program.listing.instructions_in_range(*s, *e) {
            insns.push(ins);
        }
    }
    insns.sort_by_key(|i| i.address);

    use reargo_arch::FlowType;
    let mut after_branch = false;
    for ins in &insns {
        if after_branch {
            block_starts.insert(ins.address);
        }
        match ins.flow_type {
            FlowType::ConditionalJump | FlowType::UnconditionalJump => {
                if let Some(t) = ins.branch_target {
                    block_starts.insert(t);
                }
                after_branch = true;
            }
            FlowType::Return => after_branch = true,
            _ => after_branch = false,
        }
    }

    // Build edges by walking instructions in block order.
    let starts: Vec<u64> = block_starts.iter().copied().collect();
    let mut edges: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut block_for_addr: BTreeMap<u64, u64> = BTreeMap::new();
    let mut cursor = 0usize;
    for ins in &insns {
        while cursor + 1 < starts.len() && starts[cursor + 1] <= ins.address {
            cursor += 1;
        }
        block_for_addr.insert(ins.address, starts[cursor]);
    }
    for ins in &insns {
        let from_block = *block_for_addr.get(&ins.address).unwrap_or(&0);
        match ins.flow_type {
            FlowType::ConditionalJump => {
                if let Some(t) = ins.branch_target {
                    edges.insert((from_block, t));
                }
                let fall = ins.address + ins.length as u64;
                if block_for_addr.contains_key(&fall) {
                    edges.insert((from_block, fall));
                }
            }
            FlowType::UnconditionalJump => {
                if let Some(t) = ins.branch_target {
                    edges.insert((from_block, t));
                }
            }
            FlowType::Return => {}
            _ => {
                let next = ins.address + ins.length as u64;
                if block_for_addr
                    .get(&next)
                    .is_some_and(|b| *b != from_block)
                {
                    edges.insert((from_block, next));
                }
            }
        }
    }

    println!("digraph \"{}\" {{", func.name);
    println!("    node [shape=box, fontname=\"Courier\"];");
    for &b in &starts {
        let header = if b == func.entry_point {
            format!("{} (entry)", func.name)
        } else {
            format!("0x{:x}", b)
        };
        println!("    \"0x{:x}\" [label=\"{}\"];", b, header);
    }
    for (from, to) in &edges {
        println!("    \"0x{:x}\" -> \"0x{:x}\";", from, to);
    }
    println!("}}");
    println!(
        "// {} basic blocks, {} edges, McCabe={}",
        starts.len(),
        edges.len(),
        edges.len() as i64 - starts.len() as i64 + 2
    );
    Ok(())
}

fn cmd_xrefs(path: &Path, address: u64) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let refs_to = program.references.get_refs_to(address);
    let refs_from = program.references.get_refs_from(address);

    if let Some(sym) = program.symbol_table.primary_at(address) {
        println!("Cross-references for {} (0x{:x}):\n", sym.name, address);
    } else {
        println!("Cross-references for 0x{:x}:\n", address);
    }

    if refs_to.is_empty() {
        println!("  References TO: (none)");
    } else {
        println!("  References TO ({}):", refs_to.len());
        for r in refs_to {
            let from_name = program
                .symbol_table
                .primary_at(r.from)
                .map(|s| s.name.as_str())
                .or_else(|| {
                    program.listing.function_containing(r.from).map(|f| f.name.as_str())
                })
                .unwrap_or("???");
            println!("    0x{:x} [{}] from {}", r.from, r.ref_type, from_name);
        }
    }

    println!();

    if refs_from.is_empty() {
        println!("  References FROM: (none)");
    } else {
        println!("  References FROM ({}):", refs_from.len());
        for r in refs_from {
            let to_name = program
                .symbol_table
                .primary_at(r.to)
                .map(|s| s.name.as_str())
                .unwrap_or("???");
            println!("    0x{:x} [{}] to {}", r.to, r.ref_type, to_name);
        }
    }
    Ok(())
}

fn cmd_callgraph(
    path: &Path,
    dot: bool,
    scc: bool,
    around: Option<u64>,
    depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let cg = CallGraph::build(&program);

    // When --around is set, restrict every downstream display
    // (DOT, plain text, even SCC) to the BFS-neighbourhood. Lets a
    // 50k-function callgraph shrink to the user-relevant
    // neighbourhood without the rest of the command surface
    // changing.
    let slice: Option<Vec<(u64, String)>> = around.map(|c| cg.neighborhood(c, depth));

    if dot {
        match &slice {
            Some(keep) => print!("{}", cg.to_dot_filtered(keep)),
            None => print!("{}", cg.to_dot()),
        }
        return Ok(());
    }

    if scc {
        let clusters = cg.recursive_clusters();
        println!(
            "Found {} recursive cluster{} in call graph",
            clusters.len(),
            if clusters.len() == 1 { "" } else { "s" }
        );
        for (i, members) in clusters.iter().enumerate() {
            println!("\n  cluster {} ({} func{}):",
                i,
                members.len(),
                if members.len() == 1 { "" } else { "s" });
            for (addr, name) in members {
                println!("    0x{:x}  {}", addr, name);
            }
        }
        return Ok(());
    }

    if let Some(keep) = &slice {
        let keep_set: std::collections::BTreeSet<u64> =
            keep.iter().map(|(a, _)| *a).collect();
        println!(
            "Call graph slice ({} nodes within depth {} of 0x{:x}):\n",
            keep.len(),
            depth,
            around.unwrap_or(0)
        );
        for func in program.listing.functions() {
            if !keep_set.contains(&func.entry_point) {
                continue;
            }
            let callees: Vec<_> = cg
                .callees_of(func.entry_point)
                .into_iter()
                .filter(|c| keep_set.contains(&c.address))
                .collect();
            if callees.is_empty() {
                continue;
            }
            println!("  {} (0x{:x}):", func.name, func.entry_point);
            for callee in &callees {
                println!("    -> {} (0x{:x})", callee.name, callee.address);
            }
        }
        return Ok(());
    }

    println!(
        "Call graph: {} nodes, {} edges\n",
        cg.node_count(),
        cg.edge_count()
    );
    for func in program.listing.functions() {
        let callees = cg.callees_of(func.entry_point);
        if callees.is_empty() {
            continue;
        }
        println!("  {} (0x{:x}):", func.name, func.entry_point);
        for callee in &callees {
            println!("    -> {} (0x{:x})", callee.name, callee.address);
        }
    }
    Ok(())
}

fn cmd_backtrace(
    path: &Path,
    address: u64,
    depth: usize,
    max_paths: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let cg = CallGraph::build(&program);

    let paths = cg.paths_to(address, depth, max_paths);
    if paths.is_empty() {
        let known = cg.callers_of(address).len();
        println!(
            "No backtrace paths to 0x{:x} (function not in callgraph; direct callers known: {})",
            address, known
        );
        return Ok(());
    }

    let target_name = program.function_name_at(address);
    println!(
        "Backtrace paths to {} (0x{:x}), max depth {}:",
        target_name, address, depth
    );
    println!("{}", "-".repeat(72));

    // Sort by path length so the shortest paths print first — they're
    // the most useful for "how does an entry point reach this?"
    let mut paths = paths;
    paths.sort_by_key(|p| p.len());

    for (i, path) in paths.iter().enumerate() {
        println!();
        // Print root → … → target so it reads top-down.
        let rendered: Vec<String> = path
            .iter()
            .rev()
            .map(|(a, n)| format!("{} (0x{:x})", n, a))
            .collect();
        println!("  [{}] {}", i + 1, rendered.join(" → "));
    }
    println!();
    println!("Showing {} path(s)", paths.len());
    Ok(())
}

fn cmd_memmap(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;

    let total: u64 = info.sections.iter().map(|s| s.size).sum();
    if total == 0 {
        println!("No sections in {}", path.display());
        return Ok(());
    }

    // Sort by load address so the map reads as a linear memory
    // layout. The loader's natural order is section-header order;
    // for ELF that's usually address-sorted already, but PE / Mach-O
    // can reorder things (resources after code, etc.) and we want
    // the same picture across formats.
    let mut sections = info.sections.clone();
    sections.sort_by_key(|s| s.address);

    println!("Memory map of {}", path.display());
    println!("{}", "-".repeat(72));
    println!("  {:<22} {:<18} {:>10}  perm  size-bar", "name", "range", "size");

    for s in &sections {
        if s.size == 0 {
            continue;
        }
        let perm = format!(
            "{}{}{}",
            if s.flags.contains(SectionFlags::READ) {
                "r"
            } else {
                "-"
            },
            if s.flags.contains(SectionFlags::WRITE) {
                "w"
            } else {
                "-"
            },
            if s.flags.contains(SectionFlags::EXECUTE) {
                "x"
            } else {
                "-"
            },
        );
        // Logarithmic bar so a 30-byte .comment and a 1-MiB .text
        // stay visually distinguishable without the bar going off
        // the right edge.
        let bar_len = if s.size <= 1 {
            1
        } else {
            ((s.size as f64).log2() as usize).clamp(1, 30)
        };
        let bar: String = "█".repeat(bar_len);
        let range = format!("0x{:x}..0x{:x}", s.address, s.address + s.size);
        println!(
            "  {:<22} {:<18} {:>10}  {}   {}",
            s.name, range, s.size, perm, bar
        );
    }

    println!();
    println!(
        "Total: {} sections, {} bytes",
        sections.iter().filter(|s| s.size > 0).count(),
        total
    );
    Ok(())
}

fn cmd_pcode(path: &Path, start: Option<u64>, count: usize, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;

    let lifter = match make_lifter(&info, thumb) {
        Some(l) => l,
        None => {
            eprintln!("P-code lifting not yet supported for {}", info.arch);
            return Ok(());
        }
    };

    let address = start.unwrap_or(info.entry_point);
    println!("P-code listing at 0x{:x} ({}):\n", address, info.arch);

    let lifted = lifter.lift_range(&info.memory, address, count)?;
    for insn in &lifted {
        print!("{}", insn.display_pcode());
    }

    let total_ops: usize = lifted.iter().map(|l| l.ops.len()).sum();
    println!("\n{} instructions -> {} P-code operations", lifted.len(), total_ops);
    Ok(())
}

fn cmd_decompile(path: &Path, address: Option<u64>, show_ssa: bool, show_rust: bool, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let lifter = match make_lifter(&program.info, thumb) {
        Some(l) => l,
        None => {
            eprintln!("Decompilation not yet supported for {}", program.info.arch);
            return Ok(());
        }
    };

    let entry = address.unwrap_or(program.entry_point());

    let result = reargo_decompile::decompile_function(lifter.as_ref(), &program, entry)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    if show_ssa {
        print!("{}", result.ssa_dump);
    } else {
        if !result.recovered_structs.is_empty() {
            for def in &result.recovered_structs {
                println!("{}\n", def);
            }
        }
        if show_rust {
            print!("{}", result.rust_code);
        } else {
            print!("{}", result.c_code);
        }
    }

    eprintln!(
        "\n// {} instructions, {} p-code ops, {} blocks, {} live ops after optimization ({})",
        result.stats.instructions_lifted,
        result.stats.pcode_ops,
        result.stats.basic_blocks,
        result.stats.live_ops_after,
        result.stats.optimization,
    );
    Ok(())
}

fn cmd_decompile_all(
    path: &Path,
    output_dir: Option<&Path>,
    show_rust: bool,
    skip_errors: bool,
    thumb: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let lifter = match make_lifter(&program.info, thumb) {
        Some(l) => l,
        None => {
            eprintln!("Decompilation not yet supported for {}", program.info.arch);
            return Ok(());
        }
    };

    if let Some(dir) = output_dir {
        std::fs::create_dir_all(dir)?;
    }

    let results = reargo_decompile::decompile_all(lifter.as_ref(), &program);

    let mut ok = 0usize;
    let mut err = 0usize;
    for (entry, result) in &results {
        let name = program.function_name_at(*entry);
        match result {
            Ok(r) => {
                ok += 1;
                match output_dir {
                    Some(dir) => {
                        // Sanitize: file names should not contain
                        // path separators or shell-hostile chars.
                        // The function name might be something like
                        // `std::vec::Vec<T>::push` -- replace `<>:`
                        // etc. with `_` so the resulting file name is
                        // valid on every platform CI runs on.
                        let safe = sanitize_filename(&name);
                        let stem = format!("{}_{:08x}", safe, entry);
                        let c_path = dir.join(format!("{}.c", stem));
                        std::fs::write(&c_path, &r.c_code)?;
                        if show_rust {
                            let rs_path = dir.join(format!("{}.rs", stem));
                            std::fs::write(&rs_path, &r.rust_code)?;
                        }
                    }
                    None => {
                        println!("// === {} @ 0x{:x} ===", name, entry);
                        print!("{}", r.c_code);
                        if show_rust {
                            println!("// --- rust ---");
                            print!("{}", r.rust_code);
                        }
                        println!();
                    }
                }
            }
            Err(e) => {
                err += 1;
                if !skip_errors {
                    eprintln!("// decompile failed @ 0x{:x} ({}): {}", entry, name, e);
                }
            }
        }
    }

    eprintln!(
        "// decompile-all: {} ok, {} errors, {} total in {}",
        ok,
        err,
        results.len(),
        match output_dir {
            Some(d) => d.display().to_string(),
            None => "stdout".to_string(),
        }
    );
    Ok(())
}

/// Filename-safe form of a function name: replace anything that's
/// not `[A-Za-z0-9_.-]` with `_`. Conservative across Linux / macOS
/// / Windows file systems.
fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("anon");
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn cmd_annotate(
    file: &Path,
    rename: &[String],
    force_func: &[u64],
    not_func: &[u64],
    cc: &[String],
    comment: &[String],
    import: Option<&Path>,
    keep_mangled: bool,
    list: bool,
    clear: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use reargo_program::OverrideSet;

    let sidecar = OverrideSet::sidecar_path(file);

    if clear {
        if sidecar.exists() {
            std::fs::remove_file(&sidecar)?;
            println!("Removed {}", sidecar.display());
        } else {
            println!("No override sidecar to remove.");
        }
        return Ok(());
    }

    let mut overrides = OverrideSet::load_for_binary(file)?;

    // Parse "ADDR=VALUE" once; the value may itself contain '=' so
    // split only on the first occurrence.
    let parse_kv = |s: &str| -> Result<(u64, String), String> {
        let (addr_s, val) = s
            .split_once('=')
            .ok_or_else(|| format!("expected ADDR=VALUE, got '{}'", s))?;
        let addr = parse_hex(addr_s.trim())?;
        Ok((addr, val.to_string()))
    };

    let mut edits = 0;
    for r in rename {
        let (addr, name) = parse_kv(r)?;
        overrides.names.insert(addr, name);
        edits += 1;
    }
    for &addr in force_func {
        if !overrides.force_functions.contains(&addr) {
            overrides.force_functions.push(addr);
            edits += 1;
        }
    }
    for &addr in not_func {
        if !overrides.remove_functions.contains(&addr) {
            overrides.remove_functions.push(addr);
            edits += 1;
        }
    }
    for c in cc {
        let (addr, conv) = parse_kv(c)?;
        overrides.calling_conventions.insert(addr, conv);
        edits += 1;
    }
    for c in comment {
        let (addr, text) = parse_kv(c)?;
        overrides.comments.insert(addr, text);
        edits += 1;
    }

    if let Some(import_path) = import {
        let data = std::fs::read_to_string(import_path)
            .map_err(|e| format!("read {}: {}", import_path.display(), e))?;
        let entries = symbol_import::parse(&data, import_path)?;
        let (added, demangled) =
            symbol_import::merge_into(&mut overrides, entries, !keep_mangled);
        edits += added;
        println!(
            "imported {} name(s) from {} ({} demangled)",
            added,
            import_path.display(),
            demangled
        );
    }

    if edits > 0 {
        overrides.save(&sidecar)?;
        println!(
            "Recorded {} edit(s); {} total corrections in {}",
            edits,
            overrides.len(),
            sidecar.display()
        );
    }

    if list || edits == 0 {
        print_overrides(&overrides, &sidecar);
    }
    Ok(())
}

fn cmd_callsites(
    path: &Path,
    target: Option<u64>,
    min_resolved: usize,
    iters: usize,
    callbacks_only: bool,
    thumb: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let lifter = match make_lifter(&program.info, thumb) {
        Some(l) => l,
        None => {
            eprintln!("callsites: no lifter for {}", program.info.arch);
            return Ok(());
        }
    };

    // Callback mode requires the propagator; bump iters if the
    // caller passed 0. (Defaults to 3 either way, but be explicit.)
    let effective_iters = if callbacks_only { iters.max(3) } else { iters };

    let sites = if effective_iters == 0 {
        reargo_analysis::callsite::resolve_call_sites(lifter.as_ref(), &program)
    } else {
        reargo_analysis::callsite::resolve_call_sites_iterative(
            lifter.as_ref(),
            &program,
            effective_iters,
        )
    }
    .map_err(|e| -> Box<dyn std::error::Error> { format!("{:?}", e).into() })?;

    // Build the set of known function entry points once -- used to
    // tag resolved-arg values that happen to point at a discovered
    // function ("this arg is a callback to func X").
    use std::collections::HashSet;
    let func_entries: HashSet<u64> = program
        .listing
        .functions()
        .map(|f| f.entry_point)
        .collect();

    let is_callback_value = |v: u64| -> bool { func_entries.contains(&v) };

    let filtered: Vec<_> = sites
        .iter()
        .filter(|s| {
            if let Some(t) = target
                && s.call_target != Some(t)
            {
                return false;
            }
            if s.args.iter().filter(|a| a.value.is_some()).count() < min_resolved {
                return false;
            }
            if callbacks_only
                && !s
                    .args
                    .iter()
                    .any(|a| matches!(a.value, Some(v) if is_callback_value(v)))
            {
                return false;
            }
            true
        })
        .collect();

    println!(
        "{} call sites total, {} after filter",
        sites.len(),
        filtered.len()
    );
    println!("{}", "-".repeat(72));

    for site in &filtered {
        let target_str = match site.call_target {
            Some(t) => {
                let name = program.function_name_at(t);
                format!("0x{:08x} ({})", t, name)
            }
            None => "indirect".to_string(),
        };
        let caller_name = program.function_name_at(site.caller_function);
        println!(
            "0x{:08x}  in {}  ->  {}",
            site.call_site, caller_name, target_str
        );
        for arg in &site.args {
            match arg.value {
                Some(v) => {
                    // Annotate by lookup priority: function entry
                    // beats general symbol. Function callbacks get
                    // a [callback] tag to make the parser-registry
                    // pattern obvious at a glance.
                    let name = program.symbol_table.primary_at(v).map(|s| s.name.clone());
                    let tag = if is_callback_value(v) { " [callback]" } else { "" };
                    match name {
                        Some(n) => println!("    {:>3} = 0x{:x}  // {}{}", arg.reg_name, v, n, tag),
                        None => println!("    {:>3} = 0x{:x}{}", arg.reg_name, v, tag),
                    }
                }
                None => {
                    if min_resolved == 0 {
                        println!("    {:>3} = ?", arg.reg_name);
                    }
                }
            }
        }
        println!();
    }
    Ok(())
}

fn print_overrides(o: &reargo_program::OverrideSet, sidecar: &Path) {
    if o.is_empty() {
        println!("No overrides recorded ({} absent or empty).", sidecar.display());
        return;
    }
    println!("Override set ({}):", sidecar.display());
    if !o.force_functions.is_empty() {
        println!("  force functions:");
        for a in &o.force_functions {
            println!("    0x{:08x}", a);
        }
    }
    if !o.remove_functions.is_empty() {
        println!("  remove functions:");
        for a in &o.remove_functions {
            println!("    0x{:08x}", a);
        }
    }
    if !o.names.is_empty() {
        println!("  renames:");
        for (a, n) in &o.names {
            println!("    0x{:08x} = {}", a, n);
        }
    }
    if !o.calling_conventions.is_empty() {
        println!("  calling conventions:");
        for (a, c) in &o.calling_conventions {
            println!("    0x{:08x} = {}", a, c);
        }
    }
    if !o.comments.is_empty() {
        println!("  comments:");
        for (a, c) in &o.comments {
            println!("    0x{:08x} = {}", a, c);
        }
    }
}

/// Drive the heuristic correction-proposal engine to a fixpoint.
///
/// `apply == false` is the dry-run preview: analyse once, print
/// proposals, exit. `apply == true` is the active loop:
/// analyse, propose, persist new proposals to the sidecar,
/// re-analyse, repeat until a round yields nothing new or
/// `max_rounds` is hit. Convergence (zero new proposals after the
/// previous round's mutations took effect) is the natural stop.
fn cmd_iterate(
    path: &Path,
    apply: bool,
    max_rounds: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use reargo_analysis::iterate::{propose_corrections_ctx, Correction};
    use reargo_program::OverrideSet;

    let sidecar = OverrideSet::sidecar_path(path);

    // Dry-run path: a single proposal pass, no mutations.
    if !apply {
        eprintln!("[iterate] dry-run -- showing one round of proposals, no edits");
        let program = analyze_binary(path)?;
        let existing = OverrideSet::load_for_binary(path).unwrap_or_default();
        let proposals = propose_corrections_ctx(&program, Some(&existing));
        print_proposals(&proposals);
        eprintln!(
            "[iterate] {} proposals (dry-run). Re-run with --apply to persist + iterate.",
            proposals.len()
        );
        return Ok(());
    }

    // Active loop: track per-round novelty against everything we
    // have proposed so far (including any pre-existing sidecar
    // entries) so the fixpoint check is "did this round add
    // anything we hadn't already recorded?"
    let mut overrides = OverrideSet::load_for_binary(path)?;
    let starting_total = overrides.len();
    let mut total_new: usize = 0;

    for round in 1..=max_rounds {
        eprintln!("[iterate] === round {}/{} ===", round, max_rounds);
        // Snapshot the current sidecar contents so the diff at the
        // end of this round is "what got added by THIS round".
        let before_total = overrides.len();

        // Persist whatever the previous round added so this round's
        // analyse-binary picks it up.
        if round > 1 || starting_total != before_total {
            overrides.save(&sidecar)?;
        }

        let program = analyze_binary(path)?;
        let proposals = propose_corrections_ctx(&program, Some(&overrides));

        if proposals.is_empty() {
            eprintln!("[iterate] no proposals; converged at round {}", round);
            break;
        }

        // Merge only the proposals that aren't already in the
        // sidecar (avoid infinite-loop loops where the same
        // suggestion keeps coming back).
        let mut accepted: Vec<&Correction> = Vec::new();
        let mut staged = overrides.clone();
        for c in &proposals {
            let before = correction_in_set(c, &staged);
            c.apply_to(&mut staged);
            let after = correction_in_set(c, &staged);
            if !before && after {
                accepted.push(c);
            }
        }

        if accepted.is_empty() {
            eprintln!(
                "[iterate] round {}: {} proposals, all already in sidecar; converged",
                round,
                proposals.len()
            );
            break;
        }

        eprintln!(
            "[iterate] round {}: applied {} new corrections ({} proposed total)",
            round,
            accepted.len(),
            proposals.len()
        );
        for c in &accepted {
            eprintln!(
                "  + 0x{:08x}  {:?}  -- {}",
                c.addr(),
                c.kind,
                c.reason
            );
        }
        overrides = staged;
        total_new += accepted.len();
    }

    // Final persist + summary. Only write the sidecar when this run
    // actually added corrections -- otherwise a clean binary (zero
    // proposals) would litter an empty `<binary>.gra.json`. Any
    // mid-loop additions were already persisted at the start of the
    // following round, so skipping here when `total_new == 0` loses
    // nothing.
    if total_new > 0 {
        overrides.save(&sidecar)?;
    }
    eprintln!(
        "[iterate] done. {} new corrections added this run; {} total in sidecar.",
        total_new,
        overrides.len()
    );
    Ok(())
}

fn correction_in_set(c: &reargo_analysis::iterate::Correction, set: &reargo_program::OverrideSet) -> bool {
    use reargo_analysis::iterate::CorrectionKind;
    match &c.kind {
        CorrectionKind::ForceFunction { addr } => set.force_functions.contains(addr),
        CorrectionKind::NotFunction { addr } => set.remove_functions.contains(addr),
        CorrectionKind::Rename { addr, name } => set.names.get(addr) == Some(name),
        CorrectionKind::SetCallingConvention { addr, cc } => {
            set.calling_conventions.get(addr) == Some(cc)
        }
    }
}

fn print_proposals(proposals: &[reargo_analysis::iterate::Correction]) {
    if proposals.is_empty() {
        println!("(no proposals)");
        return;
    }
    for c in proposals {
        println!(
            "  0x{:08x}  {:?}\n    reason: {}",
            c.addr(),
            c.kind,
            c.reason
        );
    }
}

fn cmd_taint(path: &Path, address: Option<u64>, params: usize, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let lifter = match make_lifter(&program.info, thumb) {
        Some(l) => l,
        None => {
            eprintln!("Taint analysis not yet supported for {}", program.info.arch);
            return Ok(());
        }
    };

    // System V AMD64 parameter-passing order (REGISTER-space offsets).
    const SYSV_PARAM_REGS: [(u64, &str); 6] = [
        (0x38, "rdi"), (0x30, "rsi"), (0x10, "rdx"),
        (0x08, "rcx"), (0x80, "r8"), (0x88, "r9"),
    ];
    let n = params.min(SYSV_PARAM_REGS.len());
    let offsets: Vec<u64> = SYSV_PARAM_REGS[..n].iter().map(|(o, _)| *o).collect();

    let entry = address.unwrap_or(program.entry_point());
    let report = reargo_decompile::analyze_taint(lifter.as_ref(), &program, entry, &offsets)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let names: Vec<&str> = SYSV_PARAM_REGS[..n].iter().map(|(_, name)| *name).collect();
    println!("Taint analysis at 0x{:x}", entry);
    println!("  Tainted sources: {} ({})", n, names.join(", "));
    println!("  Tainted values:  {}", report.tainted_values);
    println!("{}", "-".repeat(60));

    if report.sinks.is_empty() {
        println!("  No tainted data reaches a dangerous sink.");
    } else {
        println!("  {} tainted sink(s) found:", report.sinks.len());
        for sink in &report.sinks {
            println!("    0x{:x}  {}", sink.address, sink.kind.describe());
        }
    }
    Ok(())
}

fn cmd_export(path: &Path, output: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let summary = ProjectSummary::from_program(&program);

    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            PathBuf::from(format!("{}.grp.json", stem))
        });

    summary.save_to_file(&out_path)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    println!("Exported to: {}", out_path.display());
    println!("  Functions:  {}", summary.functions.len());
    println!("  Symbols:    {}", summary.symbols.len());
    println!("  References: {}", summary.references_count);
    if summary.has_dwarf {
        println!("  DWARF:      {} functions", summary.dwarf_functions);
    }
    Ok(())
}

fn cmd_export_xml(path: &Path, output: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let xml = reargo_program::export::export_ghidra_xml(&program);

    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            PathBuf::from(format!("{}.xml", stem))
        });

    std::fs::write(&out_path, &xml)?;
    println!("Exported XML to: {} ({} bytes)", out_path.display(), xml.len());
    Ok(())
}

fn cmd_emulate(path: &Path, start: Option<u64>, max_steps: u64, breakpoints: &[u64], thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;

    let is_64 = info.bits == 64;
    let lifter = match make_lifter(&info, thumb) {
        Some(l) => l,
        None => {
            eprintln!("Emulation not yet supported for {}", info.arch);
            return Ok(());
        }
    };

    let entry = start.unwrap_or(info.entry_point);
    let mut emu = reargo_emulator::Emulator::new();
    let mut bp_mgr = reargo_emulator::BreakpointManager::new();

    for &bp_addr in breakpoints {
        let id = bp_mgr.add(bp_addr);
        eprintln!("Breakpoint {} at 0x{:x}", id, bp_addr);
    }

    for block in info.memory.blocks() {
        if let Some(data) = &block.data {
            emu.state.load_memory_bytes(block.start, data);
        }
    }

    emu.state.write_register(0x20, if is_64 { 8 } else { 4 }, if is_64 { 0x7FFF_FFFF_FFF0 } else { 0xFFFF_FFF0 });

    println!("Emulating from 0x{:x} (max {} steps)\n", entry, max_steps);

    let mut addr = entry;
    let mut total_steps = 0u64;
    let mut lift_ctx = LiftContext::default();

    while total_steps < max_steps {
        if bp_mgr.check(addr) {
            println!("  ** Breakpoint hit at 0x{:x} **", addr);
            break;
        }
        let lifted = match lifter.lift_instruction_ctx(&info.memory, addr, &mut lift_ctx) {
            Ok(l) => l,
            Err(e) => { println!("  [0x{:x}] decode error: {}", addr, e); break; }
        };
        let next_addr = addr + lifted.length as u64;
        let mut branched = false;

        print!("  0x{:08x}  {}", addr, lifted.mnemonic);
        for op in &lifted.ops {
            match emu.execute_op(op) {
                Ok(()) => {}
                Err(reargo_emulator::emulator::EmulatorError::Branch(t)) => { println!(" -> branch 0x{:x}", t); addr = t; branched = true; break; }
                Err(reargo_emulator::emulator::EmulatorError::Call(t)) => { println!(" -> call 0x{:x}", t); addr = next_addr; branched = true; break; }
                Err(reargo_emulator::emulator::EmulatorError::Return(v)) => { println!(" -> return 0x{:x}\nReturned after {} steps", v, total_steps+1); return Ok(()); }
                Err(e) => { println!(" -> error: {}", e); return Ok(()); }
            }
        }
        if !branched { println!(); addr = next_addr; }
        total_steps += 1;
    }

    println!("\nStopped after {} steps at 0x{:x}", total_steps, addr);
    for (name, val) in emu.state.dump_registers() {
        if val != 0 { println!("  {:<6} = 0x{:016x}", name, val); }
    }
    Ok(())
}

/// A live emulator wired up as a GDB debug target.
struct EmulatorTarget {
    emu: reargo_emulator::Emulator,
    lifter: Box<dyn PcodeLift>,
    memory: Memory,
    pc: u64,
    breakpoints: std::collections::BTreeSet<u64>,
    exited: bool,
    lift_ctx: LiftContext,
}

impl EmulatorTarget {
    const MAX_CONTINUE_STEPS: u64 = 10_000_000;

    /// Execute a single instruction at the current PC, advancing it.
    fn step_one(&mut self) -> reargo_emulator::StopReason {
        if self.exited {
            return reargo_emulator::StopReason::Exited(0);
        }
        let lifted = match self.lifter.lift_instruction_ctx(&self.memory, self.pc, &mut self.lift_ctx) {
            Ok(l) => l,
            Err(_) => {
                self.exited = true;
                return reargo_emulator::StopReason::Signal(4); // SIGILL
            }
        };
        let next = self.pc + lifted.length as u64;
        for op in &lifted.ops {
            match self.emu.execute_op(op) {
                Ok(()) => {}
                Err(reargo_emulator::emulator::EmulatorError::Branch(t)) => { self.pc = t; return reargo_emulator::StopReason::Trap; }
                Err(reargo_emulator::emulator::EmulatorError::Call(t)) => { self.pc = t; return reargo_emulator::StopReason::Trap; }
                Err(reargo_emulator::emulator::EmulatorError::Return(_)) => { self.exited = true; return reargo_emulator::StopReason::Exited(0); }
                Err(_) => { self.exited = true; return reargo_emulator::StopReason::Signal(11); } // SIGSEGV
            }
        }
        self.pc = next;
        reargo_emulator::StopReason::Trap
    }

    fn current_pc(&self) -> u64 {
        self.pc
    }

    fn has_exited(&self) -> bool {
        self.exited
    }

    /// Disassemble `count` instructions starting at `addr` (or current PC).
    fn disassemble(&self, addr: Option<u64>, count: usize) -> Vec<(u64, String)> {
        let mut at = addr.unwrap_or(self.pc);
        let mut out = Vec::new();
        for _ in 0..count {
            match self.lifter.lift_instruction(&self.memory, at) {
                Ok(insn) => {
                    out.push((at, insn.mnemonic.clone()));
                    if insn.length == 0 {
                        break;
                    }
                    at += insn.length as u64;
                }
                Err(_) => break,
            }
        }
        out
    }
}

/// Build an emulator debug target from a loaded binary, taking ownership of its memory.
fn build_emulator_target(
    info: reargo_loader::BinaryInfo,
    entry: u64,
    thumb: bool,
) -> Option<EmulatorTarget> {
    let lifter = make_lifter(&info, thumb)?;
    let is_64 = info.bits == 64;
    let mut emu = reargo_emulator::Emulator::new();
    for block in info.memory.blocks() {
        if let Some(data) = &block.data {
            emu.state.load_memory_bytes(block.start, data);
        }
    }
    emu.state.write_register(0x20, if is_64 { 8 } else { 4 }, if is_64 { 0x7FFF_FFFF_FFF0 } else { 0xFFFF_FFF0 });
    Some(EmulatorTarget {
        emu,
        lifter,
        memory: info.memory,
        pc: entry,
        breakpoints: std::collections::BTreeSet::new(),
        exited: false,
        lift_ctx: LiftContext::default(),
    })
}

impl reargo_emulator::DebugTarget for EmulatorTarget {
    fn read_registers(&self) -> Vec<u8> {
        let mut state = self.emu.state.clone();
        state.write_register(reargo_emulator::gdbserver::AMD64_PC_OFFSET, 8, self.pc);
        reargo_emulator::gdbserver::amd64_read_registers(&state)
    }

    fn write_registers(&mut self, data: &[u8]) {
        reargo_emulator::gdbserver::amd64_write_registers(&mut self.emu.state, data);
        self.pc = self.emu.state.read_register(reargo_emulator::gdbserver::AMD64_PC_OFFSET, 8);
    }

    fn read_memory(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len as u64)
            .map(|i| self.memory.read_byte(addr + i).unwrap_or(0))
            .collect()
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) {
        self.emu.state.load_memory_bytes(addr, data);
    }

    fn resume(&mut self, step: bool) -> reargo_emulator::StopReason {
        if step {
            return self.step_one();
        }
        for _ in 0..Self::MAX_CONTINUE_STEPS {
            let reason = self.step_one();
            if !matches!(reason, reargo_emulator::StopReason::Trap) {
                return reason;
            }
            if self.breakpoints.contains(&self.pc) {
                return reargo_emulator::StopReason::Trap;
            }
        }
        reargo_emulator::StopReason::Trap
    }

    fn add_breakpoint(&mut self, addr: u64) {
        self.breakpoints.insert(addr);
    }

    fn remove_breakpoint(&mut self, addr: u64) {
        self.breakpoints.remove(&addr);
    }
}

fn cmd_gdbserver(path: &Path, start: Option<u64>, listen: &str, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
    let arch = info.arch;
    let entry = start.unwrap_or(info.entry_point);

    let target = match build_emulator_target(info, entry, thumb) {
        Some(t) => t,
        None => {
            eprintln!("Emulation not yet supported for {}", arch);
            return Ok(());
        }
    };

    println!("GDB server listening on {} (entry 0x{:x})", listen, entry);
    println!("Connect with: gdb -ex 'target remote {}'", listen);
    reargo_emulator::gdbserver::serve(listen, target)?;
    println!("GDB client disconnected.");
    Ok(())
}

fn cmd_debug(path: &Path, start: Option<u64>, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    use reargo_emulator::DebugTarget as _;
    use reargo_emulator::tui;

    let info = BinaryLoader::load(path)?;
    let arch = info.arch;
    let entry = start.unwrap_or(info.entry_point);

    let mut target = match build_emulator_target(info, entry, thumb) {
        Some(t) => t,
        None => {
            eprintln!("Emulation not yet supported for {}", arch);
            return Ok(());
        }
    };

    println!("Interactive debugger ({}). Type 'help' for commands.", arch);
    print_current_location(&target);

    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        print!("(dbg 0x{:x})> ", target.current_pc());
        std::io::stdout().flush().ok();

        line.clear();
        if stdin.read_line(&mut line)? == 0 {
            break; // EOF
        }

        match reargo_emulator::parse_debug_command(&line) {
            reargo_emulator::DebugCommand::Quit => break,
            reargo_emulator::DebugCommand::Empty => {}
            reargo_emulator::DebugCommand::Help => println!("{}", tui::debug_help()),
            reargo_emulator::DebugCommand::Step => {
                let reason = target.resume(true);
                report_stop(&target, reason);
            }
            reargo_emulator::DebugCommand::Continue => {
                let reason = target.resume(false);
                report_stop(&target, reason);
            }
            reargo_emulator::DebugCommand::Registers => {
                print_registers(&target);
            }
            reargo_emulator::DebugCommand::Breakpoint(addr) => {
                target.add_breakpoint(addr);
                println!("Breakpoint set at 0x{:x}", addr);
            }
            reargo_emulator::DebugCommand::DeleteBreakpoint(addr) => {
                target.remove_breakpoint(addr);
                println!("Breakpoint removed at 0x{:x}", addr);
            }
            reargo_emulator::DebugCommand::Examine { addr, len } => {
                let at = addr.unwrap_or(target.current_pc());
                let bytes = target.read_memory(at, len);
                print!("{}", tui::format_memory_dump(&bytes, at, 16));
            }
            reargo_emulator::DebugCommand::Disassemble { addr, count } => {
                for (a, text) in target.disassemble(addr, count) {
                    let marker = if a == target.current_pc() { "=>" } else { "  " };
                    println!("{} 0x{:08x}  {}", marker, a, text);
                }
            }
            reargo_emulator::DebugCommand::Info => print_current_location(&target),
            reargo_emulator::DebugCommand::Unknown(s) => {
                println!("Unknown command: '{}' (type 'help')", s);
            }
        }
    }
    Ok(())
}

fn print_current_location(target: &EmulatorTarget) {
    if target.has_exited() {
        println!("Program has exited.");
        return;
    }
    let disasm = target.disassemble(None, 1);
    if let Some((addr, text)) = disasm.first() {
        println!("=> 0x{:08x}  {}", addr, text);
    }
}

fn report_stop(target: &EmulatorTarget, reason: reargo_emulator::StopReason) {
    match reason {
        reargo_emulator::StopReason::Trap => print_current_location(target),
        reargo_emulator::StopReason::Exited(code) => println!("Program exited (code {})", code),
        reargo_emulator::StopReason::Signal(s) => println!("Stopped on signal {}", s),
    }
}

fn print_registers(target: &EmulatorTarget) {
    use reargo_emulator::DebugTarget as _;
    let block = target.read_registers();
    let names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
    for (i, name) in names.iter().enumerate() {
        let start = i * 8;
        if start + 8 <= block.len() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&block[start..start + 8]);
            let val = u64::from_le_bytes(buf);
            print!("{:<4}= 0x{:016x}  ", name, val);
            if (i + 1) % 3 == 0 {
                println!();
            }
        }
    }
    println!();
}

fn cmd_strings(path: &Path, min_length: usize, all_sections: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;

    println!("{:<18} {:>6} String", "Address", "Length");
    println!("{}", "-".repeat(70));

    let mut total = 0;
    for section in &info.sections {
        if !all_sections && !is_data_section(&section.name) {
            continue;
        }
        let mut buf = vec![0u8; section.size as usize];
        if info.memory.read_bytes(section.address, &mut buf).is_err() {
            continue;
        }
        let found = find_strings(&buf, section.address);
        for (addr, s) in &found {
            if s.len() >= min_length {
                let display = if s.len() > 80 { format!("{}...", &s[..77]) } else { s.clone() };
                println!("0x{:016x} {:>6} {}", addr, s.len(), display);
                total += 1;
            }
        }
    }

    println!("\nTotal: {} strings", total);
    Ok(())
}

fn cmd_semantic_diff(
    path_a: &Path,
    path_b: &Path,
    kinds_filter: &str,
    thumb: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use reargo_decompile::semantic_diff::{compare_programs, FunctionDiffKind};

    let allowed: std::collections::HashSet<&str> =
        kinds_filter.split(',').map(|s| s.trim()).collect();
    let kind_matches = |k: FunctionDiffKind| -> bool {
        let s = match k {
            FunctionDiffKind::Identical => "identical",
            FunctionDiffKind::Renamed => "renamed",
            FunctionDiffKind::Tweaked => "tweaked",
            FunctionDiffKind::Modified => "modified",
            FunctionDiffKind::Added => "added",
            FunctionDiffKind::Removed => "removed",
        };
        allowed.contains(s)
    };

    eprintln!("Analyzing {}...", path_a.display());
    let prog_a = analyze_binary(path_a)?;
    eprintln!("Analyzing {}...", path_b.display());
    let prog_b = analyze_binary(path_b)?;

    let lifter_a = match make_lifter(&prog_a.info, thumb) {
        Some(l) => l,
        None => {
            eprintln!("semantic-diff: no lifter for {}", prog_a.info.arch);
            return Ok(());
        }
    };
    let lifter_b = match make_lifter(&prog_b.info, thumb) {
        Some(l) => l,
        None => {
            eprintln!("semantic-diff: no lifter for {}", prog_b.info.arch);
            return Ok(());
        }
    };

    // Decompile both sides up-front so the diff loop can hash from
    // cached SSA without re-running the pipeline per call.
    eprintln!("Decompiling {}...", path_a.display());
    let res_a = reargo_decompile::decompile_all(lifter_a.as_ref(), &prog_a);
    eprintln!("Decompiling {}...", path_b.display());
    let res_b = reargo_decompile::decompile_all(lifter_b.as_ref(), &prog_b);

    // Build (addr, name) lists and the hash-callback closures from
    // the cached results.
    let funcs_a: Vec<(u64, String)> = prog_a
        .listing
        .functions()
        .map(|f| (f.entry_point, f.name.clone()))
        .collect();
    let funcs_b: Vec<(u64, String)> = prog_b
        .listing
        .functions()
        .map(|f| (f.entry_point, f.name.clone()))
        .collect();

    // Index decompile results by entry-point so the hash closures
    // are O(1). The DecompileResult doesn't currently expose the
    // SsaFunction (the pipeline drops it after emit), so as a
    // first-cut MVP we hash on the C code instead -- structurally
    // equivalent SSA produces structurally equivalent emit output.
    // A follow-up can stash the SSA on DecompileResult for tighter
    // hashes.
    use rustc_hash::FxHashMap;
    let by_a: FxHashMap<u64, &str> = res_a
        .iter()
        .filter_map(|(ep, r)| r.as_ref().ok().map(|r| (*ep, r.c_code.as_str())))
        .collect();
    let by_b: FxHashMap<u64, &str> = res_b
        .iter()
        .filter_map(|(ep, r)| r.as_ref().ok().map(|r| (*ep, r.c_code.as_str())))
        .collect();

    // Strip leading "/* @ 0x... */" comments and any "// 0x..."
    // addresses from the C output to make the hash address-
    // independent. For the structural form, also normalise all
    // hex literals to "0x_". For the exact form, keep them.
    let normalize_struct = |c: &str| -> String {
        let mut out = String::with_capacity(c.len());
        let mut iter = c.chars().peekable();
        while let Some(ch) = iter.next() {
            if ch == '0' && iter.peek() == Some(&'x') {
                iter.next();
                while iter.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                    iter.next();
                }
                out.push_str("0x_");
            } else {
                out.push(ch);
            }
        }
        out
    };

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hash_a = |ep: u64| -> Option<(u64, u64)> {
        let c = by_a.get(&ep)?;
        let mut s = DefaultHasher::new();
        normalize_struct(c).hash(&mut s);
        let mut e = DefaultHasher::new();
        c.hash(&mut e);
        Some((s.finish(), e.finish()))
    };
    let mut hash_b = |ep: u64| -> Option<(u64, u64)> {
        let c = by_b.get(&ep)?;
        let mut s = DefaultHasher::new();
        normalize_struct(c).hash(&mut s);
        let mut e = DefaultHasher::new();
        c.hash(&mut e);
        Some((s.finish(), e.finish()))
    };

    let diffs = compare_programs(&funcs_a, &funcs_b, &mut hash_a, &mut hash_b);

    let mut by_kind: std::collections::BTreeMap<&str, Vec<&reargo_decompile::FunctionDiff>> =
        std::collections::BTreeMap::new();
    for d in &diffs {
        if !kind_matches(d.kind) {
            continue;
        }
        let label = match d.kind {
            FunctionDiffKind::Identical => "identical",
            FunctionDiffKind::Renamed => "renamed",
            FunctionDiffKind::Tweaked => "tweaked",
            FunctionDiffKind::Modified => "modified",
            FunctionDiffKind::Added => "added",
            FunctionDiffKind::Removed => "removed",
        };
        by_kind.entry(label).or_default().push(d);
    }

    println!(
        "Semantic diff: {} vs {}",
        path_a.display(),
        path_b.display()
    );
    for (kind, entries) in &by_kind {
        println!("\n[{}] ({})", kind, entries.len());
        for d in entries {
            match d.kind {
                FunctionDiffKind::Renamed => {
                    println!(
                        "  {} (0x{:x}) -> {} (0x{:x})",
                        d.name_a.as_deref().unwrap_or("?"),
                        d.addr_a.unwrap_or(0),
                        d.name_b.as_deref().unwrap_or("?"),
                        d.addr_b.unwrap_or(0),
                    );
                }
                FunctionDiffKind::Added => {
                    println!(
                        "  + {} (0x{:x})",
                        d.name_b.as_deref().unwrap_or("?"),
                        d.addr_b.unwrap_or(0)
                    );
                }
                FunctionDiffKind::Removed => {
                    println!(
                        "  - {} (0x{:x})",
                        d.name_a.as_deref().unwrap_or("?"),
                        d.addr_a.unwrap_or(0)
                    );
                }
                _ => {
                    println!(
                        "  {} (0x{:x} -> 0x{:x})",
                        d.name_a.as_deref().unwrap_or("?"),
                        d.addr_a.unwrap_or(0),
                        d.addr_b.unwrap_or(0)
                    );
                }
            }
        }
    }
    println!(
        "\nTotal: {} entries, {} kinds shown.",
        diffs.iter().filter(|d| kind_matches(d.kind)).count(),
        by_kind.len()
    );
    Ok(())
}

fn cmd_diff(path_a: &Path, path_b: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Analyzing {}...", path_a.display());
    let prog_a = analyze_binary(path_a)?;
    let summary_a = ProjectSummary::from_program(&prog_a);

    eprintln!("Analyzing {}...", path_b.display());
    let prog_b = analyze_binary(path_b)?;
    let summary_b = ProjectSummary::from_program(&prog_b);

    let diff = ProgramDiff::compare(&summary_a, &summary_b);

    println!("\nDiff: {} vs {}", path_a.display(), path_b.display());
    println!("{}", "-".repeat(60));
    println!("{}", diff.summary());

    if !diff.added_functions.is_empty() {
        println!("\nAdded functions ({}):", diff.added_functions.len());
        for addr in &diff.added_functions {
            let name = summary_b.functions.iter()
                .find(|f| f.address == *addr)
                .map(|f| f.name.as_str())
                .unwrap_or("???");
            println!("  + 0x{:x} {}", addr, name);
        }
    }

    if !diff.removed_functions.is_empty() {
        println!("\nRemoved functions ({}):", diff.removed_functions.len());
        for addr in &diff.removed_functions {
            let name = summary_a.functions.iter()
                .find(|f| f.address == *addr)
                .map(|f| f.name.as_str())
                .unwrap_or("???");
            println!("  - 0x{:x} {}", addr, name);
        }
    }

    if !diff.modified_functions.is_empty() {
        println!("\nModified functions ({}):", diff.modified_functions.len());
        for (addr, desc) in &diff.modified_functions {
            println!("  ~ 0x{:x} {}", addr, desc);
        }
    }

    if !diff.has_changes() {
        println!("\n  No differences found.");
    }
    Ok(())
}

fn cmd_imports(path: &Path, show_exports: bool) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;

    if show_exports {
        let exports: Vec<_> = info.symbols.iter()
            .filter(|s| s.kind == SymbolKind::Export)
            .collect();
        println!("{:<18} {:>8} Name", "Address", "Size");
        println!("{}", "-".repeat(60));
        for sym in &exports {
            println!("0x{:016x} {:>8} {}", sym.address, sym.size, sym.name);
        }
        println!("\nTotal: {} exports", exports.len());
    } else {
        println!("{:<18} Name", "Address");
        println!("{}", "-".repeat(60));

        if !info.imports.is_empty() {
            for imp in &info.imports {
                println!("0x{:016x} {}", imp.plt_address, imp.name);
            }
            println!("\nTotal: {} imports", info.imports.len());
        } else {
            let imports: Vec<_> = info.symbols.iter()
                .filter(|s| s.kind == SymbolKind::Import)
                .collect();
            for sym in &imports {
                println!("0x{:016x} {}", sym.address, sym.name);
            }
            println!("\nTotal: {} imports", imports.len());
        }

        if !info.dynamic.needed_libs.is_empty() {
            println!("\nRequired libraries:");
            for lib in &info.dynamic.needed_libs {
                println!("  {}", lib);
            }
        }
    }
    Ok(())
}

fn cmd_coverage(path: &Path, annotated: bool) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let total_code: u64 = program.info.sections.iter()
        .filter(|s| s.flags.contains(SectionFlags::EXECUTE))
        .map(|s| s.size)
        .sum();
    let analyzed = program.listing.instruction_count() as u64;
    let coverage = if total_code > 0 { analyzed as f64 / total_code as f64 * 100.0 } else { 0.0 };

    println!("Analysis coverage for {}:", path.display());
    println!("{}", "-".repeat(50));
    println!("  Executable bytes: {}", total_code);
    println!("  Analyzed bytes:   {}", analyzed);
    println!("  Coverage:         {:.1}%", coverage);
    println!("  Functions:        {}", program.listing.function_count());
    println!("  Instructions:     {}", program.listing.instruction_count());

    if annotated {
        // Annotation density: how many decoded instruction addresses
        // host at least one CommentManager entry, by kind.
        let insn_addrs: std::collections::BTreeSet<u64> = program
            .listing
            .instructions()
            .map(|i| i.address)
            .collect();
        let mut annotated_insn = std::collections::BTreeSet::new();
        let mut total_comments = 0usize;
        for c in program.comments.iter() {
            total_comments += 1;
            if insn_addrs.contains(&c.address) {
                annotated_insn.insert(c.address);
            }
        }
        let pct = if !insn_addrs.is_empty() {
            100.0 * annotated_insn.len() as f64 / insn_addrs.len() as f64
        } else {
            0.0
        };
        println!();
        println!("  Comments:         {}", total_comments);
        println!("  Annotated insns:  {} ({:.1}%)", annotated_insn.len(), pct);
        println!("  Call renderings:  {}", program.call_renderings.len());
    }

    println!("\nPer-section breakdown:");
    println!("  {:<25} {:>10} {:>10} {:>8}", "Section", "Size", "Flags", "Type");
    println!("  {}", "-".repeat(58));
    for section in &program.info.sections {
        let flags = format!(
            "{}{}{}",
            if section.flags.contains(SectionFlags::READ) { "r" } else { "-" },
            if section.flags.contains(SectionFlags::WRITE) { "w" } else { "-" },
            if section.flags.contains(SectionFlags::EXECUTE) { "x" } else { "-" },
        );
        let stype = if section.flags.contains(SectionFlags::EXECUTE) { "code" } else { "data" };
        println!("  {:<25} {:>10} {:>10} {:>8}", section.name, section.size, flags, stype);
    }
    Ok(())
}

fn parse_hex_pattern(pattern: &str) -> Vec<Option<u8>> {
    pattern
        .split_whitespace()
        .map(|token| {
            if token == "??" || token == "?" {
                None
            } else {
                u8::from_str_radix(token, 16).ok()
            }
        })
        .collect()
}

fn search_pattern(data: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for i in 0..=(data.len() - pattern.len()) {
        let mut matched = true;
        for (j, p) in pattern.iter().enumerate() {
            if let Some(byte) = p
                && data[i + j] != *byte {
                    matched = false;
                    break;
                }
        }
        if matched {
            matches.push(i);
        }
    }
    matches
}

fn cmd_search(
    path: &Path,
    hex_pattern: Option<&str>,
    text_pattern: Option<&str>,
    max_results: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;

    if hex_pattern.is_none() && text_pattern.is_none() {
        eprintln!("Specify --hex or --text pattern");
        return Ok(());
    }

    println!("{:<18} {:>8} {:>20} Match", "Address", "Offset", "Section");
    println!("{}", "-".repeat(70));

    let mut total = 0;

    for section in &info.sections {
        let mut buf = vec![0u8; section.size as usize];
        if info.memory.read_bytes(section.address, &mut buf).is_err() {
            continue;
        }

        if let Some(hex) = hex_pattern {
            let pattern = parse_hex_pattern(hex);
            let matches = search_pattern(&buf, &pattern);
            for offset in matches {
                if total >= max_results { break; }
                let addr = section.address + offset as u64;
                let context: Vec<String> = buf[offset..std::cmp::min(offset + pattern.len() + 4, buf.len())]
                    .iter()
                    .take(16)
                    .map(|b| format!("{:02x}", b))
                    .collect();
                println!(
                    "0x{:016x} {:>8} {:>20} {}",
                    addr,
                    format!("+0x{:x}", offset),
                    section.name,
                    context.join(" ")
                );
                total += 1;
            }
        }

        if let Some(text) = text_pattern {
            let text_bytes = text.as_bytes();
            let pattern: Vec<Option<u8>> = text_bytes.iter().map(|b| Some(*b)).collect();
            let matches = search_pattern(&buf, &pattern);
            for offset in matches {
                if total >= max_results { break; }
                let addr = section.address + offset as u64;
                let end = std::cmp::min(offset + text_bytes.len() + 16, buf.len());
                let display: String = buf[offset..end]
                    .iter()
                    .take(60)
                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                    .collect();
                println!(
                    "0x{:016x} {:>8} {:>20} \"{}\"",
                    addr,
                    format!("+0x{:x}", offset),
                    section.name,
                    display
                );
                total += 1;
            }
        }
    }

    println!("\nTotal: {} matches", total);
    Ok(())
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    s.split_whitespace()
        .map(|token| u8::from_str_radix(token, 16).map_err(|e| format!("invalid hex byte '{}': {}", token, e)))
        .collect()
}

fn cmd_patch(
    path: &Path,
    address: u64,
    hex_bytes: Option<&str>,
    _asm_str: Option<&str>,
    output: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = std::fs::read(path)?;
    let info = BinaryLoader::load(path)?;

    let patch_bytes = if let Some(hex) = hex_bytes {
        parse_hex_bytes(hex)?
    } else {
        eprintln!("Specify --bytes with hex byte values");
        return Ok(());
    };

    let file_offset = find_file_offset(&info, address, &data)?;

    if file_offset + patch_bytes.len() > data.len() {
        return Err("patch extends beyond file boundary".into());
    }

    println!("Patching {} at 0x{:x} (file offset 0x{:x}):", path.display(), address, file_offset);
    print!("  Before: ");
    for i in 0..patch_bytes.len() {
        print!("{:02x} ", data[file_offset + i]);
    }
    println!();

    data[file_offset..file_offset + patch_bytes.len()].copy_from_slice(&patch_bytes);

    print!("  After:  ");
    for b in &patch_bytes {
        print!("{:02x} ", b);
    }
    println!();

    let out_path = output.unwrap_or(path);
    std::fs::write(out_path, &data)?;
    println!("Written to: {}", out_path.display());
    Ok(())
}

/// Read `[start, end)` from the loaded memory model, zero-filling any
/// uninitialised holes so ranges that touch `.bss`-like gaps still succeed.
fn read_va_span(info: &reargo_loader::BinaryInfo, start: u64, end: u64) -> Vec<u8> {
    let len = end.saturating_sub(start);
    let mut out = vec![0u8; len as usize];
    for (i, slot) in out.iter_mut().enumerate() {
        if let Some(b) = info.memory.read_byte(start + i as u64) {
            *slot = b;
        }
    }
    out
}

fn cmd_xref_scan(
    path: &Path,
    target: u64,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
    let hits = reargo_analysis::xref_scan::scan_xrefs(&info, target, limit);
    println!("References to 0x{:x} ({} found):", target, hits.len());
    if hits.is_empty() {
        println!("  (none — not an x86 image, target unmapped, or no direct reference)");
    }
    for h in &hits {
        println!("  0x{:016x} [{}] {}", h.addr, h.kind.label(), h.text);
    }
    if limit != 0 && hits.len() >= limit {
        println!("  ... (stopped at --limit {}; pass --limit 0 for all)", limit);
    }
    Ok(())
}

/// Collect the read-only constant-pool / jump-table regions a carved x86-64
/// function references via rip-relative addressing, as standalone read-only
/// carve segments. This makes a single-function carve self-contained for
/// rodata-dependent decompilation (notably float-constant resolution).
fn collect_const_segments(
    info: &reargo_loader::BinaryInfo,
    code: &[u8],
    code_start: u64,
    code_end: u64,
    bits: u32,
) -> Vec<carve::CarveSegment> {
    use reargo_loader::SectionFlags;
    // Initialized, non-executable sections are valid constant sources.
    let ro_ranges: Vec<(u64, u64)> = info
        .sections
        .iter()
        .filter(|s| s.address != 0 && s.size > 0 && !s.flags.contains(SectionFlags::EXECUTE))
        .map(|s| (s.address, s.address + s.size))
        .collect();

    let mut windows: Vec<(u64, u64)> = Vec::new();
    for (addr, sz) in reargo_analysis::float_const::rip_relative_data_targets(code, code_start, bits)
    {
        if addr >= code_start && addr < code_end {
            continue; // already present in the code segment
        }
        if !ro_ranges.iter().any(|(s, e)| addr >= *s && addr < *e) {
            continue; // not a read-only data reference (skip GOT/bss/exec)
        }
        let w = (sz.max(8)) as u64;
        windows.push((addr & !7, (addr + w + 7) & !7));
    }
    if windows.is_empty() {
        return Vec::new();
    }
    windows.sort();
    // Coalesce windows within 64 bytes of each other.
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (lo, hi) in windows {
        if let Some(last) = merged.last_mut()
            && lo <= last.1 + 64
        {
            if hi > last.1 {
                last.1 = hi;
            }
            continue;
        }
        merged.push((lo, hi));
    }

    const MAX_TOTAL: u64 = 256 * 1024;
    const MAX_SEGS: usize = 64;
    let mut segs = Vec::new();
    let mut total = 0u64;
    for (lo, hi) in merged {
        if segs.len() >= MAX_SEGS {
            break;
        }
        // Clamp to the containing section so a window never spans a gap.
        let (slo, shi) = match ro_ranges.iter().find(|(s, e)| lo >= *s && lo < *e) {
            Some((s, e)) => ((*s).max(lo), (*e).min(hi)),
            None => (lo, hi),
        };
        if shi <= slo {
            continue;
        }
        let span = shi - slo;
        if total + span > MAX_TOTAL {
            break;
        }
        total += span;
        segs.push(carve::CarveSegment {
            vaddr: slo,
            exec: false,
            data: read_va_span(info, slo, shi),
        });
    }
    segs
}

#[allow(clippy::too_many_arguments)]
fn cmd_carve(
    path: &Path,
    address: Option<u64>,
    start: Option<u64>,
    end: Option<u64>,
    size: Option<u64>,
    format: &str,
    output: Option<&Path>,
    thumb: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let format = format.to_ascii_lowercase();
    if format != "elf" && format != "raw" {
        return Err(format!("unknown --format '{}': expected 'elf' or 'raw'", format).into());
    }

    let info = BinaryLoader::load(path)?;

    // Resolve the [carve_start, carve_end) virtual-address range and the
    // entry address to record in the carved file.
    let (carve_start, carve_end, entry): (u64, u64, u64) = match (address, start, end, size) {
        // Function entry, extent discovered by analysis.
        (Some(addr), None, None, None) => {
            eprintln!("[carve] running analysis to find the extent of the function at 0x{:x} ...", addr);
            let program = analyze_binary(path)?;
            let func = program
                .listing
                .get_function(addr)
                .or_else(|| program.listing.function_containing(addr))
                .ok_or_else(|| -> Box<dyn std::error::Error> {
                    format!(
                        "no function found at or containing 0x{:x}; pass --size N to carve a fixed length without analysis",
                        addr
                    )
                    .into()
                })?;
            if func.body.is_empty() {
                return Err(format!(
                    "function at 0x{:x} has no discovered body; pass --size N to carve a fixed length",
                    func.entry_point
                )
                .into());
            }
            let lo = func.body.ranges().map(|r| r.start.offset).min().unwrap();
            let hi = func.body.ranges().map(|r| r.end_offset()).max().unwrap();
            (lo, hi, func.entry_point)
        }
        // Function entry + explicit length (no analysis).
        (Some(addr), None, None, Some(n)) => (addr, addr + n, addr),
        // Explicit range by end.
        (None, Some(s), Some(e), None) => {
            if e <= s {
                return Err("--end must be greater than --start".into());
            }
            (s, e, s)
        }
        // Explicit range by length.
        (None, Some(s), None, Some(n)) => (s, s + n, s),
        _ => {
            return Err(
                "specify exactly one of: --address ADDR | --address ADDR --size N | --start S --end E | --start S --size N"
                    .into(),
            );
        }
    };

    let data = read_va_span(&info, carve_start, carve_end);
    if data.is_empty() {
        return Err("carve range is empty".into());
    }
    let nonzero = data.iter().filter(|&&b| b != 0).count();
    if nonzero == 0 {
        eprintln!(
            "[carve] WARNING: every byte in 0x{:x}..0x{:x} is zero/uninitialised — wrong address or unmapped range?",
            carve_start, carve_end
        );
    }

    let default_ext = if format == "elf" { "elf" } else { "bin" };
    let default_name = format!(
        "{}.carved.{:x}.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("out"),
        carve_start,
        default_ext
    );
    let out_path: PathBuf = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| path.with_file_name(default_name));

    let bytes_written: Vec<u8> = if format == "elf" {
        let mut segments = vec![carve::CarveSegment {
            vaddr: carve_start,
            exec: true,
            data: data.clone(),
        }];
        // Bundle the function's referenced constant pool / jump tables so the
        // carve is self-contained for rodata-dependent decompilation.
        if info.bits == 64 {
            let consts = collect_const_segments(&info, &data, carve_start, carve_end, info.bits);
            if !consts.is_empty() {
                let bytes: u64 = consts.iter().map(|s| s.data.len() as u64).sum();
                eprintln!(
                    "[carve] bundled {} read-only constant-pool segment(s) ({} bytes) referenced by the function",
                    consts.len(),
                    bytes
                );
                segments.extend(consts);
            }
        }
        carve::build_min_elf_segments(info.arch, info.bits, info.endian, entry, &segments)
    } else {
        data.clone()
    };
    std::fs::write(&out_path, &bytes_written)?;

    let lang = carve::ghidra_language_id(info.arch, info.endian, thumb);
    println!("Carved 0x{:x}..0x{:x} ({} bytes) from {}", carve_start, carve_end, data.len(), path.display());
    println!("  Entry:    0x{:x}", entry);
    println!("  Format:   {}", format);
    println!("  Written:  {} ({} bytes)", out_path.display(), bytes_written.len());
    if format == "elf" {
        println!();
        println!("Auto-loads at the original VA — no manual setup:");
        println!("  re-argo decompile {} --address 0x{:x}", out_path.display(), entry);
        println!("  (or drag into GUI Ghidra; arch + base are detected from the ELF header)");
    } else {
        println!();
        println!("Import into GUI Ghidra as \"Raw Binary\":");
        println!("  Language:      {}", lang);
        println!("  Base address:  0x{:x}", carve_start);
        println!("  Then disassemble at 0x{:x}", entry);
    }
    Ok(())
}

fn cmd_script(path: &Path, script_path: &Path, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    let script = std::fs::read_to_string(script_path)
        .map_err(|e| format!("cannot read script: {}", e))?;

    let info = BinaryLoader::load(path)?;
    let mut program = Program::from_binary(path)?;
    let manager = AnalysisManager::new();

    for (line_num, line) in script.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let cmd = parts[0];
        let args = parts.get(1).unwrap_or(&"").trim();

        match cmd {
            "analyze" => {
                let results = manager.run_all(&mut program);
                for r in &results {
                    match r {
                        Ok(r) => println!("[{}] {} functions, {} refs", r.analyzer_name, r.functions_found, r.references_found),
                        Err(e) => eprintln!("[ERROR] {}", e),
                    }
                }
            }
            "info" => {
                println!("Format: {}, Arch: {}, Entry: 0x{:x}", info.format, info.arch, info.entry_point);
            }
            "functions" => {
                for func in program.listing.functions() {
                    println!("0x{:x} {}", func.entry_point, func.name);
                }
            }
            "symbols" => {
                for sym in program.symbol_table.iter() {
                    println!("0x{:x} {:?} {}", sym.address, sym.symbol_type, sym.name);
                }
            }
            "xrefs" => {
                if let Ok(addr) = parse_hex(args) {
                    let refs = program.references.get_refs_to(addr);
                    for r in refs {
                        println!("  0x{:x} -> 0x{:x} [{}]", r.from, r.to, r.ref_type);
                    }
                }
            }
            "strings" => {
                for section in &info.sections {
                    if !is_data_section(&section.name) { continue; }
                    let mut buf = vec![0u8; section.size as usize];
                    if info.memory.read_bytes(section.address, &mut buf).is_err() { continue; }
                    for (addr, s) in find_strings(&buf, section.address) {
                        println!("0x{:x} \"{}\"", addr, s);
                    }
                }
            }
            "decompile" => {
                if let Some(lifter) = make_lifter(&info, thumb) {
                    let addr = parse_hex(args).unwrap_or(info.entry_point);
                    match reargo_decompile::decompile_function(lifter.as_ref(), &program, addr) {
                        Ok(result) => print!("{}", result.c_code),
                        Err(e) => eprintln!("decompile error: {}", e),
                    }
                }
            }
            "export" => {
                let out = if args.is_empty() { "script_output.json" } else { args };
                let summary = reargo_program::ProjectSummary::from_program(&program);
                summary.save_to_file(Path::new(out))
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                println!("Exported to {}", out);
            }
            "print" => {
                println!("{}", args);
            }
            "hexdump" => {
                let hex_parts: Vec<&str> = args.splitn(2, ' ').collect();
                if let Some(addr) = hex_parts.first().and_then(|s| parse_hex(s).ok()) {
                    let len: usize = hex_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(64);
                    let mut buf = vec![0u8; len];
                    if info.memory.read_bytes(addr, &mut buf).is_ok() {
                        for (i, chunk) in buf.chunks(16).enumerate() {
                            let row_addr = addr + (i * 16) as u64;
                            print!("  {:08x}  ", row_addr);
                            for b in chunk { print!("{:02x} ", b); }
                            println!();
                        }
                    }
                }
            }
            _ => {
                eprintln!("script:{}: unknown command '{}'", line_num + 1, cmd);
            }
        }
    }

    println!("\nScript completed: {} commands processed", script.lines().filter(|l| {
        let l = l.trim();
        !l.is_empty() && !l.starts_with('#')
    }).count());
    Ok(())
}

fn cmd_entropy(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    println!("\nShannon entropy (bits/byte) for {}:", path.display());
    println!("{}", "-".repeat(72));
    println!("  {:<24} {:>10} {:>8} verdict", "section", "size", "entropy");

    let mut shown = 0usize;
    for section in &program.info.sections {
        if section.size == 0 || section.address == 0 {
            continue;
        }
        let key = format!("entropy_{}", section.name);
        let Some(raw) = program.metadata.get_property(&key) else {
            continue;
        };
        let h: f64 = raw.parse().unwrap_or(0.0);
        let verdict = if h >= reargo_analysis::entropy::ENTROPY_PACKED_THRESHOLD {
            "likely packed"
        } else if h >= reargo_analysis::entropy::ENTROPY_HIGH_THRESHOLD {
            "high entropy"
        } else if h <= 1.0 {
            "near-zero"
        } else {
            ""
        };
        println!(
            "  {:<24} {:>10} {:>8.3} {}",
            section.name, section.size, h, verdict
        );
        shown += 1;
    }
    if let Some(overall) = program.metadata.get_property("entropy_overall") {
        println!("\n  overall entropy: {}", overall);
    }
    println!("\nShowing {} section{}", shown, if shown == 1 { "" } else { "s" });
    Ok(())
}

fn cmd_rop(
    path: &Path,
    depth: usize,
    max_insns: usize,
    useful_only: bool,
    contains: Option<&str>,
    limit: usize,
    kinds_spec: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = reargo_loader::BinaryLoader::load(path)?;

    let kinds: &'static [reargo_analysis::rop::GadgetKind] = match kinds_spec.to_ascii_lowercase().as_str() {
        "all" | "rop,jop,cop" | "rop,cop,jop" | "jop,rop,cop" | "jop,cop,rop"
        | "cop,rop,jop" | "cop,jop,rop" => reargo_analysis::rop::ALL_KINDS,
        "rop" => &[reargo_analysis::rop::GadgetKind::Rop],
        "jop" => &[reargo_analysis::rop::GadgetKind::Jop],
        "cop" => &[reargo_analysis::rop::GadgetKind::Cop],
        "rop,jop" | "jop,rop" => &[reargo_analysis::rop::GadgetKind::Rop, reargo_analysis::rop::GadgetKind::Jop],
        "rop,cop" | "cop,rop" => &[reargo_analysis::rop::GadgetKind::Rop, reargo_analysis::rop::GadgetKind::Cop],
        "jop,cop" | "cop,jop" => &[reargo_analysis::rop::GadgetKind::Jop, reargo_analysis::rop::GadgetKind::Cop],
        other => return Err(format!("unknown gadget kind spec: {}", other).into()),
    };

    let opts = reargo_analysis::rop::RopOptions {
        depth_bytes: depth,
        max_insns,
        useful_only,
        kinds,
    };
    let mut gadgets = reargo_analysis::rop::find_gadgets(&info, opts);

    if let Some(needle) = contains {
        let needle_l = needle.to_ascii_lowercase();
        gadgets.retain(|g| g.text.to_ascii_lowercase().contains(&needle_l));
    }

    let total = gadgets.len();
    println!("\nGadgets in {} ({}): {} found", path.display(), kinds_spec, total);
    println!("{}", "-".repeat(72));

    let to_show = if limit == 0 {
        gadgets.len()
    } else {
        gadgets.len().min(limit)
    };
    for g in gadgets.iter().take(to_show) {
        println!("0x{:016x} [{}] {}", g.address, g.kind.label(), g.text);
    }
    if to_show < total {
        println!("\n... {} more (raise --limit to see them)", total - to_show);
    }
    Ok(())
}

fn cmd_capa(path: &Path, namespace: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let rules = program
        .metadata
        .get_property("capa_rules")
        .unwrap_or("")
        .lines()
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>();

    println!("\nCapa capabilities in {}:", path.display());
    println!("{}", "-".repeat(72));
    if rules.is_empty() {
        println!("  (no rules matched)");
        return Ok(());
    }

    let mut shown = 0usize;
    for r in &rules {
        if let Some(ns) = namespace
            && !r.contains(ns)
        {
            continue;
        }
        println!("  {}", r);
        shown += 1;
    }

    println!("\nShowing {} of {} rules matched", shown, rules.len());
    Ok(())
}

fn cmd_packer(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    println!("\nPacker detection for {}:", path.display());
    println!("{}", "-".repeat(72));

    match program.metadata.get_property("packer") {
        Some(label) => {
            let evidence = program
                .metadata
                .get_property("packer_evidence")
                .unwrap_or("unknown");
            println!("  packer:    {}", label);
            println!("  evidence:  {}", evidence);
            if let Some(overall) = program.metadata.get_property("entropy_overall") {
                println!("  entropy:   {} (overall)", overall);
            }
        }
        None => {
            println!("  (no known packer signature matched)");
            if let Some(overall) = program.metadata.get_property("entropy_overall") {
                println!("  overall entropy: {}", overall);
            }
        }
    }
    Ok(())
}

fn cmd_embedded(path: &Path, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    let info = reargo_loader::BinaryLoader::load(path)?;
    let findings = reargo_analysis::embedded::scan(&info, 1);

    println!("\nEmbedded files in {}: {} found", path.display(), findings.len());
    println!("{}", "-".repeat(72));
    println!("  {:<18} {:<32} magic", "address", "kind");

    let to_show = if limit == 0 { findings.len() } else { findings.len().min(limit) };
    for f in findings.iter().take(to_show) {
        println!(
            "  0x{:016x} {:<32} {}",
            f.address, f.kind, f.magic_hex
        );
    }
    if to_show < findings.len() {
        println!("\n... {} more (raise --limit to see them)", findings.len() - to_show);
    }
    Ok(())
}

fn cmd_vuln(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let bug_tags: Vec<_> = program
        .tags
        .iter_functions()
        .filter(|(_, t)| matches!(t.kind, reargo_program::TagKind::Bug))
        .collect();

    println!("\nVulnerability patterns in {}: {} finding(s)", path.display(), bug_tags.len());
    println!("{}", "-".repeat(72));
    if bug_tags.is_empty() {
        println!("  (no dangerous-API calls flagged)");
        return Ok(());
    }
    println!("  {:<18} {:<10} detail", "function", "cwe");
    for (addr, tag) in &bug_tags {
        // Tag text format: "CWE-XXX: label (name)"
        let (cwe, rest) = match tag.text.split_once(": ") {
            Some((c, r)) => (c, r),
            None => ("", tag.text.as_str()),
        };
        println!("  0x{:016x} {:<10} {}", addr, cwe, rest);
    }
    Ok(())
}

fn cmd_ioc(path: &Path, kind_filter: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let raw = program.metadata.get_property("iocs").unwrap_or("");
    let lines: Vec<&str> = raw.lines().filter(|l| !l.is_empty()).collect();

    println!("\nIoCs in {}: {} finding(s)", path.display(), lines.len());
    println!("{}", "-".repeat(72));
    if lines.is_empty() {
        println!("  (no IoCs matched)");
        return Ok(());
    }
    println!("  {:<18} {:<14} value", "address", "kind");

    let mut shown = 0usize;
    for line in &lines {
        // Format from analyzer: "0x{addr} {kind} {value}"
        let mut parts = line.splitn(3, ' ');
        let (Some(addr), Some(kind), Some(value)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if let Some(want) = kind_filter
            && kind != want
        {
            continue;
        }
        println!("  {:<18} {:<14} {}", addr, kind, value);
        shown += 1;
    }
    println!("\nShowing {} of {} IoC(s)", shown, lines.len());
    Ok(())
}

fn cmd_floss(
    path: &Path,
    min_length: usize,
    with_add: bool,
    limit: usize,
    include_printable_source: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = reargo_loader::BinaryLoader::load(path)?;
    let opts = reargo_analysis::floss_lite::FlossOptions {
        min_length,
        try_xor: true,
        try_add: with_add,
        try_rol: true,
        max_per_section: 4096,
        require_nonprintable_source: !include_printable_source,
        dedup_per_address: true,
    };
    let mut all: Vec<reargo_analysis::floss_lite::DecodedString> = Vec::new();
    for section in &info.sections {
        if section.size == 0
            || section.size > 16 * 1024 * 1024
            || section.flags.contains(reargo_loader::SectionFlags::EXECUTE)
        {
            continue;
        }
        let mut buf = vec![0u8; section.size as usize];
        if info.memory.read_bytes(section.address, &mut buf).is_err() {
            continue;
        }
        let found = reargo_analysis::floss_lite::decode_section(&buf, section.address, &opts);
        all.extend(found);
    }

    println!(
        "\nFLOSS-lite decoded strings in {} ({} found):",
        path.display(),
        all.len()
    );
    println!("{}", "-".repeat(72));
    if all.is_empty() {
        println!("  (no obfuscated strings recovered)");
        return Ok(());
    }
    println!("  {:<18} {:<14} value", "address", "method");
    let to_show = if limit == 0 { all.len() } else { all.len().min(limit) };
    for d in all.iter().take(to_show) {
        println!(
            "  0x{:016x} {:<14} {:?}",
            d.address,
            d.method.label(),
            d.plaintext
        );
    }
    if to_show < all.len() {
        println!("\n... {} more (raise --limit to see them)", all.len() - to_show);
    }
    Ok(())
}

fn cmd_tlsh_diff(a: &Path, b: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let info_a = reargo_loader::BinaryLoader::load(a)?;
    let info_b = reargo_loader::BinaryLoader::load(b)?;
    let ha = reargo_analysis::tlsh::compute_for_binary(&info_a)
        .ok_or("could not compute TLSH for first binary (too small?)")?;
    let hb = reargo_analysis::tlsh::compute_for_binary(&info_b)
        .ok_or("could not compute TLSH for second binary (too small?)")?;
    let dist = reargo_analysis::tlsh::compare(&ha, &hb)
        .ok_or("could not compute TLSH distance")?;
    let verdict = if dist < 30 {
        "likely same family"
    } else if dist < 50 {
        "related"
    } else if dist > 100 {
        "unrelated"
    } else {
        "weakly similar"
    };
    println!("\nTLSH comparison:");
    println!("  {:<24} {}", a.display(), ha);
    println!("  {:<24} {}", b.display(), hb);
    println!();
    println!("  distance: {} ({})", dist, verdict);
    Ok(())
}

fn cmd_yara(
    bin_path: &Path,
    rules_path: &Path,
    sample: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules_src = std::fs::read_to_string(rules_path)?;
    let rules = reargo_analysis::yara_lite::parse_rules(&rules_src)
        .map_err(|e| format!("YARA parse error in {}: {}", rules_path.display(), e))?;
    let info = reargo_loader::BinaryLoader::load(bin_path)?;
    let matches = reargo_analysis::yara_lite::scan(&info, &rules);

    println!(
        "\nYARA matches in {} ({} rule(s) loaded, {} matched):",
        bin_path.display(),
        rules.len(),
        matches.len()
    );
    println!("{}", "-".repeat(72));
    if matches.is_empty() {
        println!("  (no rules matched)");
        return Ok(());
    }
    for m in &matches {
        println!("  rule: {}", m.rule);
        for (name, hits) in &m.string_hits {
            if hits.is_empty() {
                continue;
            }
            let shown: Vec<String> = hits
                .iter()
                .take(sample)
                .map(|h| format!("0x{:x}", h))
                .collect();
            let extra = if hits.len() > sample {
                format!(" (+{} more)", hits.len() - sample)
            } else {
                String::new()
            };
            println!(
                "    ${} ({} hit{}): {}{}",
                name,
                hits.len(),
                if hits.len() == 1 { "" } else { "s" },
                shown.join(", "),
                extra
            );
        }
    }
    Ok(())
}

fn cmd_triage(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Suppress per-analyzer log lines so the triage report is the
    // only thing on stdout/stderr. We capture stderr by directing it
    // to a sink — fall back to default if redirection isn't
    // available.
    let program = analyze_binary_quiet(path)?;
    let info = &program.info;
    let p = &program.metadata.properties;

    println!("=== Triage: {} ===", path.display());
    println!("  format        {} / {} ({} bit)", info.format, info.arch, info.bits);
    println!("  entry         0x{:x}", info.entry_point);
    println!("  sections      {}", info.sections.len());
    println!("  imports       {}", info.imports.len());

    // Identity
    let identity_keys = ["compiler", "language", "runtime", "libc_version", "build_id"];
    let identity: Vec<(&str, &String)> = identity_keys
        .iter()
        .filter_map(|k| p.get(*k).map(|v| (*k, v)))
        .collect();
    if !identity.is_empty() {
        println!();
        println!("Identity:");
        for (k, v) in identity {
            println!("  {:<14} {}", k, v);
        }
    }

    // Hashes
    let imphash = p.get("imphash");
    let tlsh = p.get("tlsh");
    let richhash = p.get("richhash");
    if imphash.is_some() || tlsh.is_some() || richhash.is_some() {
        println!();
        println!("Hashes:");
        if let Some(h) = imphash {
            println!("  imphash       {}", h);
        }
        if let Some(h) = tlsh {
            println!("  tlsh          {}", h);
        }
        if let Some(h) = richhash {
            println!("  richhash      {}", h);
            if let Some(n) = p.get("rich_records") {
                println!("                ({} Rich Header records)", n);
            }
        }
    }

    // Section anomalies
    if let Some(count) = p.get("section_anomaly_count") {
        println!();
        println!("Section anomalies ({}):", count);
        if let Some(raw) = p.get("section_anomalies") {
            for line in raw.lines().take(10) {
                println!("  {}", line);
            }
        }
    }

    // Code signing
    if let Some(signed) = p.get("signed") {
        println!();
        println!("Code signing:");
        println!("  signed        {}", signed);
        if let Some(count) = p.get("cert_count") {
            println!("  certificates  {}", count);
        }
        if let Some(subjects) = p.get("cert_subjects") {
            println!("  subjects:");
            for line in subjects.lines() {
                println!("    {}", line);
            }
        }
    }

    // Packer + entropy
    let entropy_overall = p.get("entropy_overall");
    let packer = p.get("packer");
    if packer.is_some() || entropy_overall.is_some() {
        println!();
        println!("Packer / Entropy:");
        if let Some(v) = packer {
            let ev = p
                .get("packer_evidence")
                .map(|e| format!(" ({})", e))
                .unwrap_or_default();
            println!("  packer        {}{}", v, ev);
        } else {
            println!("  packer        (none detected)");
        }
        if let Some(v) = entropy_overall {
            let h: f64 = v.parse().unwrap_or(0.0);
            let verdict = if h >= reargo_analysis::entropy::ENTROPY_PACKED_THRESHOLD {
                " (likely packed)"
            } else if h >= reargo_analysis::entropy::ENTROPY_HIGH_THRESHOLD {
                " (high entropy)"
            } else {
                ""
            };
            println!("  entropy       {} bits/byte{}", v, verdict);
        }
    }

    // Capabilities
    if let Some(raw) = p.get("capa_rules") {
        let lines: Vec<&str> = raw.lines().filter(|l| !l.is_empty()).collect();
        println!();
        println!("Capabilities ({}):", lines.len());
        for line in lines.iter().take(10) {
            println!("  {}", line);
        }
        if lines.len() > 10 {
            println!("  …{} more", lines.len() - 10);
        }
    }

    // CWE findings (vuln)
    let bugs: Vec<_> = program
        .tags
        .iter_functions()
        .filter(|(_, t)| matches!(t.kind, reargo_program::TagKind::Bug))
        .collect();
    if !bugs.is_empty() {
        let mut by_cwe: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for (_, t) in &bugs {
            let cwe = t.text.split_once(": ").map(|(c, _)| c).unwrap_or("CWE-?");
            *by_cwe.entry(cwe.to_string()).or_default() += 1;
        }
        println!();
        println!("CWE findings ({}):", bugs.len());
        for (cwe, n) in &by_cwe {
            println!("  {:<10} {}", cwe, n);
        }
    }

    // IoCs grouped by kind
    if let Some(raw) = p.get("iocs") {
        let mut by_kind: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        let total: usize = raw.lines().filter(|l| !l.is_empty()).count();
        for line in raw.lines() {
            let mut parts = line.splitn(3, ' ');
            let (_, Some(kind), _) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            *by_kind.entry(kind.to_string()).or_default() += 1;
        }
        if !by_kind.is_empty() {
            println!();
            println!("IoCs ({}):", total);
            for (k, n) in &by_kind {
                println!("  {:<14} {}", k, n);
            }
        }
    }

    // Tag counts overall (already drives downstream reports)
    let tag_counts = program.tags.counts_by_kind();
    if !tag_counts.is_empty() {
        println!();
        println!("Tags by kind:");
        for (k, n) in &tag_counts {
            println!("  {:<14} {}", k, n);
        }
    }

    Ok(())
}

/// Same as `analyze_binary` but suppresses the per-analyzer log spam
/// on stderr — the `triage` command is meant to be a clean
/// one-screen report.
fn analyze_binary_quiet(path: &Path) -> Result<reargo_program::Program, Box<dyn std::error::Error>> {
    let mut program = reargo_program::Program::from_binary(path)?;
    let manager = reargo_analysis::AnalysisManager::new();
    let _ = manager.run_all(&mut program);
    // Apply overrides silently too.
    if let Ok(overrides) = reargo_program::OverrideSet::load_for_binary(path)
        && !overrides.is_empty()
    {
        overrides.apply(&mut program);
    }
    Ok(program)
}

fn find_file_offset(info: &reargo_loader::BinaryInfo, address: u64, data: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    for section in &info.sections {
        if address >= section.address && address < section.address + section.size {
            let section_offset = address - section.address;
            for block in info.memory.blocks() {
                if block.start == section.address
                    && let Some(block_data) = &block.data
                    && let Some(pos) = data.windows(block_data.len().min(64))
                        .position(|w| w == &block_data[..w.len()])
                {
                    return Ok(pos + section_offset as usize);
                }
            }
            return Err(format!("cannot map address 0x{:x} to file offset", address).into());
        }
    }
    Err(format!("address 0x{:x} not in any section", address).into())
}
