use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use gr_analysis::{AnalysisManager, CallGraph};
use gr_arch::arch::create_architecture;
use gr_lift::x86::X86Lifter;
use gr_lift::PcodeLift;
use gr_loader::{BinaryLoader, SymbolKind};
use gr_program::Program;

#[derive(Parser)]
#[command(name = "ghidra-rust", version, about = "Binary analysis tool powered by ghidra-rust")]
struct Cli {
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
    /// List symbols in the binary
    Symbols {
        /// Path to the binary file
        file: PathBuf,
        /// Filter by symbol kind (func, data, import, export)
        #[arg(short, long)]
        kind: Option<String>,
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
    /// Decompile a function to C pseudocode
    Decompile {
        /// Path to the binary file
        file: PathBuf,
        /// Function address (hex). Defaults to entry point
        #[arg(short, long, value_parser = parse_hex)]
        address: Option<u64>,
        /// Show SSA dump instead of C output
        #[arg(long)]
        ssa: bool,
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
        Commands::Symbols { file, kind } => cmd_symbols(&file, kind.as_deref()),
        Commands::Disasm {
            file,
            start,
            count,
        } => cmd_disasm(&file, start, count),
        Commands::Registers { file } => cmd_registers(&file),
        Commands::Analyze { file } => cmd_analyze(&file),
        Commands::Functions { file } => cmd_functions(&file),
        Commands::Xrefs { file, address } => cmd_xrefs(&file, address),
        Commands::Callgraph { file, dot } => cmd_callgraph(&file, dot),
        Commands::Pcode {
            file,
            start,
            count,
        } => cmd_pcode(&file, start, count),
        Commands::Decompile { file, address, ssa } => cmd_decompile(&file, address, ssa),
        Commands::Hexdump {
            file,
            address,
            length,
        } => cmd_hexdump(&file, address, length),
    }
}

fn cmd_info(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
    println!("File:         {}", path.display());
    println!("Format:       {}", info.format);
    println!("Architecture: {}", info.arch);
    println!("Bits:         {}", info.bits);
    println!("Endian:       {:?}", info.endian);
    println!("Entry Point:  0x{:x}", info.entry_point);
    println!("Sections:     {}", info.sections.len());
    println!("Symbols:      {}", info.symbols.len());
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

fn cmd_symbols(path: &Path, kind_filter: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
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

    for sym in &info.symbols {
        if let Some(ref filter) = kind_match
            && let Some(expected) = filter
                && sym.kind != *expected {
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

fn cmd_disasm(path: &Path, start: Option<u64>, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;
    let arch = create_architecture(info.arch)?;
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

fn cmd_callgraph(path: &Path, dot: bool) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;
    let cg = CallGraph::build(&program);

    if dot {
        print!("{}", cg.to_dot());
    } else {
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
    }
    Ok(())
}

fn cmd_pcode(path: &Path, start: Option<u64>, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let info = BinaryLoader::load(path)?;

    let is_64 = info.bits == 64;
    let lifter: Box<dyn PcodeLift> = match info.arch {
        gr_loader::Architecture::X86 | gr_loader::Architecture::X86_64 => {
            if is_64 {
                Box::new(X86Lifter::new_64())
            } else {
                Box::new(X86Lifter::new_32())
            }
        }
        other => {
            eprintln!("P-code lifting not yet supported for {}", other);
            return Ok(());
        }
    };

    let address = start.unwrap_or(info.entry_point);
    println!("P-code listing at 0x{:x} ({}):\n", address, if is_64 { "x86_64" } else { "x86" });

    let lifted = lifter.lift_range(&info.memory, address, count)?;
    for insn in &lifted {
        print!("{}", insn.display_pcode());
    }

    let total_ops: usize = lifted.iter().map(|l| l.ops.len()).sum();
    println!("\n{} instructions -> {} P-code operations", lifted.len(), total_ops);
    Ok(())
}

fn cmd_decompile(path: &Path, address: Option<u64>, show_ssa: bool) -> Result<(), Box<dyn std::error::Error>> {
    let program = analyze_binary(path)?;

    let is_64 = program.info.bits == 64;
    let lifter: Box<dyn PcodeLift> = match program.info.arch {
        gr_loader::Architecture::X86 | gr_loader::Architecture::X86_64 => {
            if is_64 {
                Box::new(X86Lifter::new_64())
            } else {
                Box::new(X86Lifter::new_32())
            }
        }
        other => {
            eprintln!("Decompilation not yet supported for {}", other);
            return Ok(());
        }
    };

    let entry = address.unwrap_or(program.entry_point());

    let result = gr_decompile::decompile_function(lifter.as_ref(), &program, entry)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    if show_ssa {
        print!("{}", result.ssa_dump);
    } else {
        print!("{}", result.c_code);
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
