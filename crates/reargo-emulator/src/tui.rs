// Terminal UI helpers for the debugger.

/// A parsed interactive-debugger command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugCommand {
    /// Execute a single instruction.
    Step,
    /// Run until a breakpoint or program exit.
    Continue,
    /// Show register values.
    Registers,
    /// Set a breakpoint at an address.
    Breakpoint(u64),
    /// Remove a breakpoint at an address.
    DeleteBreakpoint(u64),
    /// Examine memory: optional address (default current PC), length in bytes.
    Examine { addr: Option<u64>, len: usize },
    /// Disassemble: optional address (default current PC), instruction count.
    Disassemble { addr: Option<u64>, count: usize },
    /// Show current location / status.
    Info,
    /// Print command help.
    Help,
    /// Exit the debugger.
    Quit,
    /// Blank line — repeat nothing.
    Empty,
    /// Unrecognised input.
    Unknown(String),
}

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

/// Parse one line of debugger input into a [`DebugCommand`].
pub fn parse_debug_command(line: &str) -> DebugCommand {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return DebugCommand::Empty;
    }
    let mut parts = trimmed.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let args: Vec<&str> = parts.collect();

    match cmd {
        "s" | "step" | "si" => DebugCommand::Step,
        "c" | "continue" | "cont" => DebugCommand::Continue,
        "r" | "reg" | "regs" | "registers" => DebugCommand::Registers,
        "i" | "info" => DebugCommand::Info,
        "h" | "help" | "?" => DebugCommand::Help,
        "q" | "quit" | "exit" => DebugCommand::Quit,
        "b" | "break" | "bp" => match args.first().and_then(|a| parse_num(a)) {
            Some(addr) => DebugCommand::Breakpoint(addr),
            None => DebugCommand::Unknown(trimmed.into()),
        },
        "db" | "delete" | "rbp" => match args.first().and_then(|a| parse_num(a)) {
            Some(addr) => DebugCommand::DeleteBreakpoint(addr),
            None => DebugCommand::Unknown(trimmed.into()),
        },
        "x" | "examine" => {
            let addr = args.first().and_then(|a| parse_num(a));
            let len = args.get(1).and_then(|a| a.parse::<usize>().ok()).unwrap_or(64);
            DebugCommand::Examine { addr, len }
        }
        "d" | "disas" | "disasm" | "disassemble" => {
            let addr = args.first().and_then(|a| parse_num(a));
            let count = args.get(1).and_then(|a| a.parse::<usize>().ok()).unwrap_or(8);
            DebugCommand::Disassemble { addr, count }
        }
        _ => DebugCommand::Unknown(trimmed.into()),
    }
}

/// Help text listing the interactive debugger commands.
pub fn debug_help() -> &'static str {
    "Commands:\n\
     \x20 s, step          Execute one instruction\n\
     \x20 c, continue      Run until breakpoint or exit\n\
     \x20 r, regs          Show registers\n\
     \x20 b <addr>         Set breakpoint\n\
     \x20 db <addr>        Delete breakpoint\n\
     \x20 x <addr> [len]   Examine memory\n\
     \x20 d [addr] [n]     Disassemble n instructions\n\
     \x20 i, info          Show current location\n\
     \x20 h, help          Show this help\n\
     \x20 q, quit          Exit the debugger"
}

pub struct DebugPrompt {
    pub address: u64,
    pub function_name: Option<String>,
    pub step_count: u64,
}

impl DebugPrompt {
    pub fn render(&self) -> String {
        let func = self.function_name.as_deref().unwrap_or("???");
        format!("[{} @ 0x{:x} step#{}]> ", func, self.address, self.step_count)
    }
}

pub fn format_register_table(regs: &[(String, u64)], columns: usize) -> String {
    let mut out = String::new();
    let non_zero: Vec<_> = regs.iter().filter(|(_, v)| *v != 0).collect();
    for (i, (name, val)) in non_zero.iter().enumerate() {
        out.push_str(&format!("{:<6}= 0x{:016x}  ", name, val));
        if (i + 1) % columns == 0 { out.push('\n'); }
    }
    if !out.ends_with('\n') { out.push('\n'); }
    out
}

pub fn format_memory_dump(data: &[u8], base_addr: u64, width: usize) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(width).enumerate() {
        let addr = base_addr + (i * width) as u64;
        out.push_str(&format!("0x{:08x}  ", addr));
        for b in chunk {
            out.push_str(&format!("{:02x} ", b));
        }
        for _ in chunk.len()..width {
            out.push_str("   ");
        }
        out.push_str(" |");
        for &b in chunk {
            if b.is_ascii_graphic() || b == b' ' {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

pub fn format_disasm_line(addr: u64, bytes: &[u8], mnemonic: &str, operands: &str) -> String {
    let hex: String = bytes.iter().take(8).map(|b| format!("{:02x} ", b)).collect();
    format!("0x{:08x}  {:<24} {} {}", addr, hex, mnemonic, operands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prompt() {
        let prompt = DebugPrompt {
            address: 0x401000,
            function_name: Some("main".into()),
            step_count: 42,
        };
        let rendered = prompt.render();
        assert!(rendered.contains("main"));
        assert!(rendered.contains("401000"));
        assert!(rendered.contains("42"));
    }

    #[test]
    fn register_table() {
        let regs = vec![
            ("RAX".into(), 0xDEAD), ("RBX".into(), 0),
            ("RCX".into(), 0xBEEF), ("RDX".into(), 0),
        ];
        let table = format_register_table(&regs, 2);
        assert!(table.contains("RAX"));
        assert!(table.contains("RCX"));
        assert!(!table.contains("RBX")); // zero filtered
    }

    #[test]
    fn memory_dump_format() {
        let data = [0x48, 0x89, 0xe5, 0x90];
        let dump = format_memory_dump(&data, 0x1000, 16);
        assert!(dump.contains("0x00001000"));
        assert!(dump.contains("48 89 e5 90"));
    }

    #[test]
    fn disasm_line() {
        let line = format_disasm_line(0x1000, &[0x90], "nop", "");
        assert!(line.contains("0x00001000"));
        assert!(line.contains("90"));
        assert!(line.contains("nop"));
    }

    #[test]
    fn parse_basic_commands() {
        assert_eq!(parse_debug_command("s"), DebugCommand::Step);
        assert_eq!(parse_debug_command("step"), DebugCommand::Step);
        assert_eq!(parse_debug_command("c"), DebugCommand::Continue);
        assert_eq!(parse_debug_command("regs"), DebugCommand::Registers);
        assert_eq!(parse_debug_command("q"), DebugCommand::Quit);
        assert_eq!(parse_debug_command(""), DebugCommand::Empty);
        assert_eq!(parse_debug_command("   "), DebugCommand::Empty);
    }

    #[test]
    fn parse_breakpoint() {
        assert_eq!(parse_debug_command("b 0x401000"), DebugCommand::Breakpoint(0x401000));
        assert_eq!(parse_debug_command("break 401000"), DebugCommand::Breakpoint(0x401000));
        assert_eq!(parse_debug_command("db 0x401000"), DebugCommand::DeleteBreakpoint(0x401000));
        // Missing argument is an error.
        assert!(matches!(parse_debug_command("b"), DebugCommand::Unknown(_)));
    }

    #[test]
    fn parse_examine() {
        assert_eq!(
            parse_debug_command("x 0x1000 32"),
            DebugCommand::Examine { addr: Some(0x1000), len: 32 }
        );
        assert_eq!(
            parse_debug_command("x"),
            DebugCommand::Examine { addr: None, len: 64 }
        );
    }

    #[test]
    fn parse_disassemble() {
        assert_eq!(
            parse_debug_command("d 0x1000 4"),
            DebugCommand::Disassemble { addr: Some(0x1000), count: 4 }
        );
        assert_eq!(
            parse_debug_command("disasm"),
            DebugCommand::Disassemble { addr: None, count: 8 }
        );
    }

    #[test]
    fn parse_unknown() {
        assert!(matches!(parse_debug_command("frobnicate"), DebugCommand::Unknown(_)));
    }
}
