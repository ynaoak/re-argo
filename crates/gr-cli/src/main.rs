mod mcp;
mod symbol_import;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use gr_analysis::{AnalysisManager, CallGraph};
use gr_analysis::strings::{find_strings, is_data_section};
use gr_arch::arch::{create_architecture, create_architecture_with_options};
use gr_lift::aarch64::Aarch64Lifter;
use gr_lift::arm32::{Arm32Lifter, ArmRegion, MappedArmLifter};
use gr_lift::mips::MipsLifter;
use gr_lift::ppc::PpcLifter;
use gr_lift::riscv::RiscVLifter;
use gr_lift::sparc::SparcLifter;
use gr_lift::x86::X86Lifter;
use gr_lift::{LiftContext, PcodeLift};
use gr_loader::{BinaryLoader, Memory, SectionFlags, SymbolKind};
use gr_program::{Program, ProgramDiff, ProjectSummary};

#[derive(Parser)]
#[command(name = "ghidra-rust", version, about = "Binary analysis tool powered by ghidra-rust")]
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
        Commands::Cfg { file, address } => cmd_cfg(&file, address),
        Commands::Xrefs { file, address } => cmd_xrefs(&file, address),
        Commands::Callgraph { file, dot, scc } => cmd_callgraph(&file, dot, scc),
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
        Commands::Coverage { file } => cmd_coverage(&file),
        Commands::Script { file, script } => cmd_script(&file, &script, cli.thumb),
        Commands::Mcp { file } => mcp::run_stdio(&file, cli.thumb),
        Commands::Annotate { file, rename, force_func, not_func, cc, comment, import, keep_mangled, list, clear } =>
            cmd_annotate(&file, &rename, &force_func, &not_func, &cc, &comment, import.as_deref(), keep_mangled, list, clear),
        Commands::Iterate { file, apply, max_rounds } => cmd_iterate(&file, apply, max_rounds),
        Commands::Callsites { file, target, min_resolved, iters, callbacks } => cmd_callsites(&file, target, min_resolved, iters, callbacks, cli.thumb),
        Commands::Search { file, hex, text, max_results } => cmd_search(&file, hex.as_deref(), text.as_deref(), max_results),
        Commands::Patch { file, address, bytes, asm, output } => cmd_patch(&file, address, bytes.as_deref(), asm.as_deref(), output.as_deref()),
    }
}

fn cmd_info(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // We need a Program (not just BinaryInfo) so the fingerprint
    // analyzer can populate metadata cheaply — it only reads .comment
    // and .note.gnu.build-id; no disassembly or lifting.
    let mut program = gr_program::Program::from_binary(path)?;
    let info = &program.info;
    println!("File:         {}", path.display());
    println!("Format:       {}", info.format);
    println!("Architecture: {}", info.arch);
    println!("Bits:         {}", info.bits);
    println!("Endian:       {:?}", info.endian);
    println!("Entry Point:  0x{:x}", info.entry_point);
    println!("Sections:     {}", info.sections.len());
    println!("Symbols:      {}", info.symbols.len());

    let fp = gr_analysis::fingerprint::CompilerFingerprintAnalyzer;
    let _ = gr_analysis::Analyzer::analyze(&fp, &mut program);
    let rfp = gr_analysis::runtime_fp::RuntimeFingerprintAnalyzer;
    let _ = gr_analysis::Analyzer::analyze(&rfp, &mut program);
    let pe = gr_analysis::pe_enrich::PeEnrichmentAnalyzer;
    let _ = gr_analysis::Analyzer::analyze(&pe, &mut program);
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
        ] {
            if let Some(v) = p.get(key) {
                println!("{:<13} {}", format!("{}:", key), v);
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
            if section.flags.contains(gr_loader::SectionFlags::READ) {
                "r"
            } else {
                "-"
            },
            if section.flags.contains(gr_loader::SectionFlags::WRITE) {
                "w"
            } else {
                "-"
            },
            if section.flags.contains(gr_loader::SectionFlags::EXECUTE) {
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
    use gr_program::symbol::SymbolType as PSymType;
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
    arch: gr_loader::Architecture,
    bits: u32,
    endian: gr_core::address::Endian,
    thumb: bool,
) -> Option<Box<dyn PcodeLift>> {
    match arch {
        gr_loader::Architecture::X86 | gr_loader::Architecture::X86_64 => {
            if bits == 64 { Some(Box::new(X86Lifter::new_64())) } else { Some(Box::new(X86Lifter::new_32())) }
        }
        gr_loader::Architecture::Arm64 => Some(Box::new(Aarch64Lifter::new())),
        gr_loader::Architecture::Arm => Some(Box::new(if thumb {
            Arm32Lifter::new_thumb(endian)
        } else {
            Arm32Lifter::new(endian)
        })),
        gr_loader::Architecture::Mips => Some(Box::new(MipsLifter::new_32(endian))),
        gr_loader::Architecture::Riscv32 => Some(Box::new(RiscVLifter::new_rv32())),
        gr_loader::Architecture::PowerPc => Some(Box::new(PpcLifter::new_32(endian))),
        gr_loader::Architecture::Sparc => Some(Box::new(SparcLifter::new_32())),
        _ => None,
    }
}

/// Build the per-address ARM/Thumb region map from ELF `$a`/`$t`/`$d` mapping
/// symbols (names may carry a `.N` suffix).
fn arm_region_mapping(info: &gr_loader::BinaryInfo) -> Vec<(u64, ArmRegion)> {
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
fn make_lifter(info: &gr_loader::BinaryInfo, force_thumb: bool) -> Option<Box<dyn PcodeLift>> {
    if info.arch == gr_loader::Architecture::Arm && !force_thumb {
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
    match gr_program::OverrideSet::load_for_binary(path) {
        Ok(overrides) if !overrides.is_empty() => {
            let n = overrides.apply(&mut program);
            eprintln!(
                "[overrides] applied {} of {} corrections from {}",
                n,
                overrides.len(),
                gr_program::OverrideSet::sidecar_path(path).display()
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
    let mut rows: Vec<(u64, String, gr_analysis::complexity::FunctionMetrics)> = Vec::new();
    for f in program.listing.functions() {
        let key = format!("func_{:x}_metrics", f.entry_point);
        let Some(raw) = program.metadata.get_property(&key) else {
            continue;
        };
        let Some(m) = gr_analysis::complexity::parse_metrics(raw) else {
            continue;
        };
        rows.push((f.entry_point, f.name.clone(), m));
    }

    let key_of = |m: &gr_analysis::complexity::FunctionMetrics| -> i64 {
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
    let mut insns: Vec<&gr_arch::DecodedInstruction> = Vec::new();
    for (s, e) in &ranges {
        for ins in program.listing.instructions_in_range(*s, *e) {
            insns.push(ins);
        }
    }
    insns.sort_by_key(|i| i.address);

    use gr_arch::FlowType;
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
) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let cg = CallGraph::build(&program);

    if dot {
        print!("{}", cg.to_dot());
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

    let result = gr_decompile::decompile_function(lifter.as_ref(), &program, entry)
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

    let results = gr_decompile::decompile_all(lifter.as_ref(), &program);

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
    use gr_program::OverrideSet;

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
        gr_analysis::callsite::resolve_call_sites(lifter.as_ref(), &program)
    } else {
        gr_analysis::callsite::resolve_call_sites_iterative(
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

fn print_overrides(o: &gr_program::OverrideSet, sidecar: &Path) {
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
    use gr_analysis::iterate::{propose_corrections_ctx, Correction};
    use gr_program::OverrideSet;

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

fn correction_in_set(c: &gr_analysis::iterate::Correction, set: &gr_program::OverrideSet) -> bool {
    use gr_analysis::iterate::CorrectionKind;
    match &c.kind {
        CorrectionKind::ForceFunction { addr } => set.force_functions.contains(addr),
        CorrectionKind::NotFunction { addr } => set.remove_functions.contains(addr),
        CorrectionKind::Rename { addr, name } => set.names.get(addr) == Some(name),
        CorrectionKind::SetCallingConvention { addr, cc } => {
            set.calling_conventions.get(addr) == Some(cc)
        }
    }
}

fn print_proposals(proposals: &[gr_analysis::iterate::Correction]) {
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
    let report = gr_decompile::analyze_taint(lifter.as_ref(), &program, entry, &offsets)
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
    let xml = gr_program::export::export_ghidra_xml(&program);

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
    let mut emu = gr_emulator::Emulator::new();
    let mut bp_mgr = gr_emulator::BreakpointManager::new();

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
                Err(gr_emulator::emulator::EmulatorError::Branch(t)) => { println!(" -> branch 0x{:x}", t); addr = t; branched = true; break; }
                Err(gr_emulator::emulator::EmulatorError::Call(t)) => { println!(" -> call 0x{:x}", t); addr = next_addr; branched = true; break; }
                Err(gr_emulator::emulator::EmulatorError::Return(v)) => { println!(" -> return 0x{:x}\nReturned after {} steps", v, total_steps+1); return Ok(()); }
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
    emu: gr_emulator::Emulator,
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
    fn step_one(&mut self) -> gr_emulator::StopReason {
        if self.exited {
            return gr_emulator::StopReason::Exited(0);
        }
        let lifted = match self.lifter.lift_instruction_ctx(&self.memory, self.pc, &mut self.lift_ctx) {
            Ok(l) => l,
            Err(_) => {
                self.exited = true;
                return gr_emulator::StopReason::Signal(4); // SIGILL
            }
        };
        let next = self.pc + lifted.length as u64;
        for op in &lifted.ops {
            match self.emu.execute_op(op) {
                Ok(()) => {}
                Err(gr_emulator::emulator::EmulatorError::Branch(t)) => { self.pc = t; return gr_emulator::StopReason::Trap; }
                Err(gr_emulator::emulator::EmulatorError::Call(t)) => { self.pc = t; return gr_emulator::StopReason::Trap; }
                Err(gr_emulator::emulator::EmulatorError::Return(_)) => { self.exited = true; return gr_emulator::StopReason::Exited(0); }
                Err(_) => { self.exited = true; return gr_emulator::StopReason::Signal(11); } // SIGSEGV
            }
        }
        self.pc = next;
        gr_emulator::StopReason::Trap
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
    info: gr_loader::BinaryInfo,
    entry: u64,
    thumb: bool,
) -> Option<EmulatorTarget> {
    let lifter = make_lifter(&info, thumb)?;
    let is_64 = info.bits == 64;
    let mut emu = gr_emulator::Emulator::new();
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

impl gr_emulator::DebugTarget for EmulatorTarget {
    fn read_registers(&self) -> Vec<u8> {
        let mut state = self.emu.state.clone();
        state.write_register(gr_emulator::gdbserver::AMD64_PC_OFFSET, 8, self.pc);
        gr_emulator::gdbserver::amd64_read_registers(&state)
    }

    fn write_registers(&mut self, data: &[u8]) {
        gr_emulator::gdbserver::amd64_write_registers(&mut self.emu.state, data);
        self.pc = self.emu.state.read_register(gr_emulator::gdbserver::AMD64_PC_OFFSET, 8);
    }

    fn read_memory(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len as u64)
            .map(|i| self.memory.read_byte(addr + i).unwrap_or(0))
            .collect()
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) {
        self.emu.state.load_memory_bytes(addr, data);
    }

    fn resume(&mut self, step: bool) -> gr_emulator::StopReason {
        if step {
            return self.step_one();
        }
        for _ in 0..Self::MAX_CONTINUE_STEPS {
            let reason = self.step_one();
            if !matches!(reason, gr_emulator::StopReason::Trap) {
                return reason;
            }
            if self.breakpoints.contains(&self.pc) {
                return gr_emulator::StopReason::Trap;
            }
        }
        gr_emulator::StopReason::Trap
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
    gr_emulator::gdbserver::serve(listen, target)?;
    println!("GDB client disconnected.");
    Ok(())
}

fn cmd_debug(path: &Path, start: Option<u64>, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    use gr_emulator::DebugTarget as _;
    use gr_emulator::tui;

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

        match gr_emulator::parse_debug_command(&line) {
            gr_emulator::DebugCommand::Quit => break,
            gr_emulator::DebugCommand::Empty => {}
            gr_emulator::DebugCommand::Help => println!("{}", tui::debug_help()),
            gr_emulator::DebugCommand::Step => {
                let reason = target.resume(true);
                report_stop(&target, reason);
            }
            gr_emulator::DebugCommand::Continue => {
                let reason = target.resume(false);
                report_stop(&target, reason);
            }
            gr_emulator::DebugCommand::Registers => {
                print_registers(&target);
            }
            gr_emulator::DebugCommand::Breakpoint(addr) => {
                target.add_breakpoint(addr);
                println!("Breakpoint set at 0x{:x}", addr);
            }
            gr_emulator::DebugCommand::DeleteBreakpoint(addr) => {
                target.remove_breakpoint(addr);
                println!("Breakpoint removed at 0x{:x}", addr);
            }
            gr_emulator::DebugCommand::Examine { addr, len } => {
                let at = addr.unwrap_or(target.current_pc());
                let bytes = target.read_memory(at, len);
                print!("{}", tui::format_memory_dump(&bytes, at, 16));
            }
            gr_emulator::DebugCommand::Disassemble { addr, count } => {
                for (a, text) in target.disassemble(addr, count) {
                    let marker = if a == target.current_pc() { "=>" } else { "  " };
                    println!("{} 0x{:08x}  {}", marker, a, text);
                }
            }
            gr_emulator::DebugCommand::Info => print_current_location(&target),
            gr_emulator::DebugCommand::Unknown(s) => {
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

fn report_stop(target: &EmulatorTarget, reason: gr_emulator::StopReason) {
    match reason {
        gr_emulator::StopReason::Trap => print_current_location(target),
        gr_emulator::StopReason::Exited(code) => println!("Program exited (code {})", code),
        gr_emulator::StopReason::Signal(s) => println!("Stopped on signal {}", s),
    }
}

fn print_registers(target: &EmulatorTarget) {
    use gr_emulator::DebugTarget as _;
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
    use gr_decompile::semantic_diff::{compare_programs, FunctionDiffKind};

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
    let res_a = gr_decompile::decompile_all(lifter_a.as_ref(), &prog_a);
    eprintln!("Decompiling {}...", path_b.display());
    let res_b = gr_decompile::decompile_all(lifter_b.as_ref(), &prog_b);

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

    let mut by_kind: std::collections::BTreeMap<&str, Vec<&gr_decompile::FunctionDiff>> =
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

fn cmd_coverage(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
                    match gr_decompile::decompile_function(lifter.as_ref(), &program, addr) {
                        Ok(result) => print!("{}", result.c_code),
                        Err(e) => eprintln!("decompile error: {}", e),
                    }
                }
            }
            "export" => {
                let out = if args.is_empty() { "script_output.json" } else { args };
                let summary = gr_program::ProjectSummary::from_program(&program);
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

fn find_file_offset(info: &gr_loader::BinaryInfo, address: u64, data: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
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
