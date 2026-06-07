//! Minimal Model Context Protocol (MCP) server over stdio.
//!
//! Speaks JSON-RPC 2.0 with newline-delimited framing -- the
//! transport every MCP client over stdio expects. Implements the
//! three core methods (`initialize`, `tools/list`, `tools/call`)
//! plus a small set of tools that wrap our existing `gr_*` library
//! API:
//!
//! * `get_program_info` -- arch, entry, section count, etc.
//! * `list_functions`   -- every discovered function (entry + name).
//! * `list_symbols`     -- symbol table dump (with optional kind filter).
//! * `disassemble`      -- N instructions from an address.
//! * `decompile_function` -- C pseudocode for a function.
//! * `find_xrefs`       -- refs to / from an address.
//!
//! Designed for use with LLM-based clients (Claude Code, ...). The
//! binary is loaded *once* at startup; every tool call hits cached
//! `Program` state. Analysis is run lazily on the first tool that
//! needs it.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use gr_analysis::AnalysisManager;
use gr_program::Program;

/// JSON-RPC 2.0 request envelope. `id` is optional because
/// notifications (no response expected) also flow through here.
#[derive(Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

/// JSON-RPC 2.0 response envelope. Either `result` or `error` is
/// populated; serde_json's untagged behaviour is fine for clients.
#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// Server state: the loaded binary plus the thumb flag for ARM.
/// Lives for the process lifetime since stdio-based MCP servers are
/// single-tenant per invocation. The lifter is rebuilt per-call --
/// the construct is cheap (a struct init), and per-call building
/// avoids needing Send+Sync bounds on the trait object.
struct Server {
    program: Program,
    thumb: bool,
}

impl Server {
    fn new(path: &Path, thumb: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Load + analyse up-front. The MCP transport is "long-lived
        // process answering one binary's questions," so paying the
        // analysis cost once at startup is the right shape.
        let mut program = crate::analyze_binary(path)?;
        let manager = AnalysisManager::new();
        let _ = manager.run_all(&mut program);
        Ok(Server { program, thumb })
    }

    /// Handle one JSON-RPC request. Returns `Some(response_json)`
    /// for requests, `None` for notifications (id-less messages).
    fn handle(&self, req: RpcRequest) -> Option<String> {
        if req.jsonrpc != "2.0" {
            return Some(error_response(req.id, -32600, "invalid jsonrpc version"));
        }
        let id_present = !req.id.is_null();
        let result = match req.method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "ghidra-rust",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": { "tools": {} },
            })),
            "tools/list" => Ok(json!({ "tools": tool_list() })),
            "tools/call" => self.handle_tool_call(&req.params),
            // Notifications -- silent ack.
            "notifications/initialized" | "notifications/cancelled" => {
                return None;
            }
            other => Err(format!("method not found: {}", other)),
        };

        if !id_present {
            return None;
        }
        Some(match result {
            Ok(v) => ok_response(req.id, v),
            Err(msg) => error_response(req.id, -32601, &msg),
        })
    }

    fn handle_tool_call(&self, params: &Value) -> Result<Value, String> {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("missing 'name'")?;
        let args = params.get("arguments").cloned().unwrap_or(Value::Null);

        let content = match name {
            "get_program_info" => tool_program_info(&self.program),
            "list_functions" => tool_list_functions(&self.program, &args),
            "list_symbols" => tool_list_symbols(&self.program, &args),
            "disassemble" => tool_disassemble(&self.program, &args),
            "decompile_function" => tool_decompile(self, &args),
            "find_xrefs" => tool_find_xrefs(&self.program, &args),
            other => return Err(format!("unknown tool: {}", other)),
        }?;

        // MCP wraps tool results in a content array of typed parts.
        // Text is the universal lowest-common-denominator format.
        Ok(json!({
            "content": [{ "type": "text", "text": content }],
            "isError": false,
        }))
    }
}

/// Drive the server: blocking read loop over stdin, write responses
/// to stdout, write trace info to stderr.
pub fn run_stdio(path: &Path, thumb: bool) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[mcp] loading {}", path.display());
    let server = Server::new(path, thumb)?;
    eprintln!("[mcp] ready; {} functions discovered", server.program.listing.functions().count());

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let reader = BufReader::new(stdin.lock());
    for line in reader.lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            Ok(_) => continue,
            Err(_) => break,
        };
        let req: RpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err = error_response(Value::Null, -32700, &format!("parse error: {}", e));
                writeln!(stdout, "{}", err)?;
                stdout.flush()?;
                continue;
            }
        };
        if let Some(reply) = server.handle(req) {
            writeln!(stdout, "{}", reply)?;
            stdout.flush()?;
        }
    }
    Ok(())
}

fn ok_response(id: Value, result: Value) -> String {
    serde_json::to_string(&RpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    })
    .unwrap_or_else(|_| "{}".into())
}

fn error_response(id: Value, code: i64, msg: &str) -> String {
    serde_json::to_string(&RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: msg.into(),
        }),
    })
    .unwrap_or_else(|_| "{}".into())
}

fn tool_list() -> Value {
    json!([
        {
            "name": "get_program_info",
            "description": "High-level info about the loaded binary (architecture, entry point, section count).",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "list_functions",
            "description": "Every function discovered by analysis. Returns entry-point address + name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "max": {"type": "integer", "description": "Cap on entries returned (default 1000)."}
                }
            }
        },
        {
            "name": "list_symbols",
            "description": "Symbols from the symbol table, optionally filtered by kind.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "description": "One of: function, data, import, export."},
                    "max":  {"type": "integer", "description": "Cap on entries returned (default 1000)."}
                }
            }
        },
        {
            "name": "disassemble",
            "description": "Disassemble N instructions starting at an address.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Hex string e.g. 0x1234."},
                    "count":   {"type": "integer", "description": "Instruction count (default 16)."}
                },
                "required": ["address"]
            }
        },
        {
            "name": "decompile_function",
            "description": "Return C pseudocode for the function at an address.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Function entry point as hex string."},
                    "rust":    {"type": "boolean", "description": "Emit Rust-style pseudocode instead of C."}
                },
                "required": ["address"]
            }
        },
        {
            "name": "find_xrefs",
            "description": "References to and from a given address.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Hex string."}
                },
                "required": ["address"]
            }
        },
    ])
}

fn tool_program_info(program: &Program) -> Result<String, String> {
    Ok(format!(
        "arch: {}\nbits: {}\nentry: 0x{:x}\nsections: {}\nfunctions: {}\nsymbols: {}",
        program.info.arch,
        program.info.bits,
        program.entry_point(),
        program.info.sections.len(),
        program.listing.functions().count(),
        program.symbol_table.iter().count(),
    ))
}

fn tool_list_functions(program: &Program, args: &Value) -> Result<String, String> {
    let max = args.get("max").and_then(|v| v.as_u64()).unwrap_or(1000) as usize;
    let mut out = String::new();
    let total = program.listing.functions().count();
    for (n, func) in program.listing.functions().enumerate() {
        if n >= max {
            out.push_str(&format!("... ({} more truncated)\n", total - n));
            break;
        }
        out.push_str(&format!("0x{:08x}  {}\n", func.entry_point, func.name));
    }
    Ok(out)
}

fn tool_list_symbols(program: &Program, args: &Value) -> Result<String, String> {
    use gr_program::symbol::SymbolType;
    let kind_filter = args.get("kind").and_then(|v| v.as_str());
    let max = args.get("max").and_then(|v| v.as_u64()).unwrap_or(1000) as usize;

    let matches_kind = |st: SymbolType| -> bool {
        let Some(k) = kind_filter else { return true };
        matches!(
            (k, st),
            ("function", SymbolType::Function)
                | ("data", SymbolType::Data)
                | (
                    "import",
                    SymbolType::ExternalFunction | SymbolType::ExternalData
                )
                | ("export", SymbolType::Function)
        )
    };

    let mut out = String::new();
    let mut n = 0usize;
    for sym in program.symbol_table.iter() {
        if !matches_kind(sym.symbol_type) {
            continue;
        }
        if n >= max {
            out.push_str("... (truncated)\n");
            break;
        }
        out.push_str(&format!(
            "0x{:08x}  {:?}  {}\n",
            sym.address, sym.symbol_type, sym.name
        ));
        n += 1;
    }
    Ok(out)
}

fn parse_addr(args: &Value, field: &str) -> Result<u64, String> {
    let s = args
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing '{}'", field))?;
    crate::parse_hex(s).map_err(|e| format!("bad address: {}", e))
}

fn tool_disassemble(program: &Program, args: &Value) -> Result<String, String> {
    let addr = parse_addr(args, "address")?;
    let count = args.get("count").and_then(|v| v.as_u64()).unwrap_or(16) as usize;

    let mut out = String::new();
    let mut n = 0usize;
    for insn in program.listing.instructions_in_range(addr, addr + 0x10000) {
        if n >= count {
            break;
        }
        out.push_str(&format!(
            "0x{:08x}  {} ({}B)\n",
            insn.address, insn.mnemonic, insn.length
        ));
        n += 1;
    }
    if n == 0 {
        out.push_str("(no instructions; address may need an analyze pass)\n");
    }
    Ok(out)
}

fn tool_decompile(server: &Server, args: &Value) -> Result<String, String> {
    let addr = parse_addr(args, "address")?;
    let rust = args.get("rust").and_then(|v| v.as_bool()).unwrap_or(false);
    let lifter = crate::make_lifter(&server.program.info, server.thumb)
        .ok_or_else(|| format!("no lifter for {}", server.program.info.arch))?;
    let res = gr_decompile::decompile_function(lifter.as_ref(), &server.program, addr)
        .map_err(|e| format!("decompile failed: {}", e))?;
    Ok(if rust { res.rust_code } else { res.c_code })
}

fn tool_find_xrefs(program: &Program, args: &Value) -> Result<String, String> {
    let addr = parse_addr(args, "address")?;
    let mut out = String::new();
    out.push_str(&format!("xrefs at 0x{:x}:\n", addr));
    out.push_str("  to (incoming):\n");
    let to: Vec<_> = program.references.get_refs_to(addr).iter().collect();
    let _ = to.len();
    if to.is_empty() {
        out.push_str("    (none)\n");
    } else {
        for r in &to {
            out.push_str(&format!("    from 0x{:08x}  {:?}\n", r.from, r.ref_type));
        }
    }
    out.push_str("  from (outgoing):\n");
    let from: Vec<_> = program.references.get_refs_from(addr).iter().collect();
    if from.is_empty() {
        out.push_str("    (none)\n");
    } else {
        for r in &from {
            out.push_str(&format!("    to   0x{:08x}  {:?}\n", r.to, r.ref_type));
        }
    }
    Ok(out)
}
