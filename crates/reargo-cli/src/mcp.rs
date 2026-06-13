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
//! And the **AI-driven correction loop** tools, which let an agent
//! iteratively improve the analysis through conversation:
//!
//! * `assess_function`     -- quality metrics for one function
//!   (truncation, unresolved call targets, ...).
//! * `propose_corrections` -- heuristic engine's list of probable
//!   analyser mistakes, each with a reason.
//! * `apply_override`      -- record a correction into the
//!   `<binary>.gra.json` sidecar (force/remove/rename/cc).
//! * `reanalyze`           -- re-run analysis so the corrected
//!   model is visible to the next query.
//!
//! The agent loop is: propose_corrections -> (review) ->
//! apply_override -> reanalyze -> assess_function -> repeat until
//! satisfied. The same corrections persist to the sidecar so they
//! survive across sessions and feed every other command.
//!
//! Designed for use with LLM-based clients (Claude Code, ...). The
//! binary is loaded *once* at startup; correction tools mutate the
//! in-memory `Program` (via reanalyze) and the on-disk sidecar.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use reargo_program::Program;

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
    /// Path to the loaded binary. Needed so the AI-driven
    /// correction loop can re-analyse after writing override
    /// corrections to the `<binary>.gra.json` sidecar.
    path: std::path::PathBuf,
    thumb: bool,
}

impl Server {
    fn new(path: &Path, thumb: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Load + analyse up-front. The MCP transport is "long-lived
        // process answering one binary's questions," so paying the
        // analysis cost once at startup is the right shape.
        // analyze_binary already runs the full analyzer manager AND
        // applies any existing override sidecar.
        let program = crate::analyze_binary(path)?;
        Ok(Server {
            program,
            path: path.to_path_buf(),
            thumb,
        })
    }

    /// Re-run the full analysis pass (auto + sidecar overrides) from
    /// scratch. Called after the AI applies a correction so the next
    /// query sees the corrected model. Returns the new function
    /// count for a confirmation message.
    fn reanalyze(&mut self) -> Result<usize, String> {
        let program = crate::analyze_binary(&self.path).map_err(|e| e.to_string())?;
        self.program = program;
        Ok(self.program.listing.functions().count())
    }

    /// Handle one JSON-RPC request. Returns `Some(response_json)`
    /// for requests, `None` for notifications (id-less messages).
    fn handle(&mut self, req: RpcRequest) -> Option<String> {
        if req.jsonrpc != "2.0" {
            return Some(error_response(req.id, -32600, "invalid jsonrpc version"));
        }
        let id_present = !req.id.is_null();
        let result = match req.method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "re-argo",
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

    fn handle_tool_call(&mut self, params: &Value) -> Result<Value, String> {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("missing 'name'")?
            .to_string();
        let args = params.get("arguments").cloned().unwrap_or(Value::Null);

        let content = match name.as_str() {
            "get_program_info" => tool_program_info(&self.program),
            "list_functions" => tool_list_functions(&self.program, &args),
            "list_symbols" => tool_list_symbols(&self.program, &args),
            "disassemble" => tool_disassemble(&self.program, &args),
            "decompile_function" => tool_decompile(self, &args),
            "find_xrefs" => tool_find_xrefs(&self.program, &args),
            // --- AI-driven correction loop ---
            "assess_function" => tool_assess_function(&self.program, &args),
            "propose_corrections" => tool_propose_corrections(self),
            "apply_override" => tool_apply_override(self, &args),
            "reanalyze" => tool_reanalyze(self),
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
    let mut server = Server::new(path, thumb)?;
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
        {
            "name": "assess_function",
            "description": "Quality assessment of one function: instruction/byte/call counts, whether it appears truncated at the first call, and any call targets that aren't yet defined as functions. Use this to decide whether a function needs correction.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Function entry point (hex)."}
                },
                "required": ["address"]
            }
        },
        {
            "name": "propose_corrections",
            "description": "Run the heuristic correction engine across the whole program and return concrete proposed corrections (force-function, remove-function, ...) each with a reason. The starting point for the AI correction loop: propose -> review -> apply_override -> reanalyze -> repeat.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "apply_override",
            "description": "Record a manual correction into the persistent <binary>.gra.json sidecar. kind is one of: force_function, not_function, rename, set_cc. Does NOT re-analyse by itself -- call reanalyze afterwards (or set reanalyze=true) to see the effect.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "description": "force_function | not_function | rename | set_cc"},
                    "address": {"type": "string", "description": "Target address (hex)."},
                    "value": {"type": "string", "description": "For rename: the new name. For set_cc: the convention. Ignored otherwise."},
                    "reanalyze": {"type": "boolean", "description": "Re-run analysis immediately after recording (default false)."}
                },
                "required": ["kind", "address"]
            }
        },
        {
            "name": "reanalyze",
            "description": "Re-run the full analysis pass (auto-analysis + all sidecar overrides). Call after apply_override to make the corrected model visible to subsequent queries.",
            "inputSchema": { "type": "object", "properties": {} }
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
    use reargo_program::symbol::SymbolType;
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
    let res = reargo_decompile::decompile_function(lifter.as_ref(), &server.program, addr)
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

// ============================================================
// AI-driven correction loop tools
// ============================================================

fn tool_assess_function(program: &Program, args: &Value) -> Result<String, String> {
    let addr = parse_addr(args, "address")?;
    match reargo_analysis::iterate::assess_function(program, addr) {
        Some(a) => {
            let mut out = String::new();
            out.push_str(&a.one_line());
            out.push('\n');
            if !a.unresolved_call_targets.is_empty() {
                out.push_str("  unresolved call targets (candidates for force_function):\n");
                for t in &a.unresolved_call_targets {
                    out.push_str(&format!("    0x{:08x}\n", t));
                }
            }
            if a.ends_on_call {
                out.push_str(
                    "  NOTE: body ends on a Call -- discovery may have truncated this function.\n",
                );
            }
            Ok(out)
        }
        None => Err(format!("no function at 0x{:x}", addr)),
    }
}

fn tool_propose_corrections(server: &Server) -> Result<String, String> {
    // Feed the current sidecar in as context so we don't re-propose
    // corrections that fight ones already recorded.
    let existing = reargo_program::OverrideSet::load_for_binary(&server.path).unwrap_or_default();
    let proposals =
        reargo_analysis::iterate::propose_corrections_ctx(&server.program, Some(&existing));
    if proposals.is_empty() {
        return Ok("No corrections proposed; analysis looks clean by the current heuristics.".into());
    }
    let mut out = format!("{} correction(s) proposed:\n", proposals.len());
    for c in &proposals {
        out.push_str(&format!(
            "  0x{:08x}  {:?}\n    reason: {}\n",
            c.addr(),
            c.kind,
            c.reason
        ));
    }
    out.push_str(
        "\nApply with apply_override (kind = force_function / not_function / rename / set_cc), then reanalyze.\n",
    );
    Ok(out)
}

fn tool_apply_override(server: &mut Server, args: &Value) -> Result<String, String> {
    use reargo_program::OverrideSet;

    let kind = args
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or("missing 'kind'")?;
    let addr = parse_addr(args, "address")?;
    let value = args.get("value").and_then(|v| v.as_str());
    let do_reanalyze = args
        .get("reanalyze")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut set = OverrideSet::load_for_binary(&server.path)?;
    match kind {
        "force_function" => {
            if !set.force_functions.contains(&addr) {
                set.force_functions.push(addr);
            }
        }
        "not_function" => {
            if !set.remove_functions.contains(&addr) {
                set.remove_functions.push(addr);
            }
        }
        "rename" => {
            let name = value.ok_or("rename requires 'value' (the new name)")?;
            set.names.insert(addr, name.to_string());
        }
        "set_cc" => {
            let cc = value.ok_or("set_cc requires 'value' (the convention)")?;
            set.calling_conventions.insert(addr, cc.to_string());
        }
        other => return Err(format!("unknown kind '{}'", other)),
    }

    let sidecar = OverrideSet::sidecar_path(&server.path);
    set.save(&sidecar)?;

    let mut out = format!(
        "Recorded {} at 0x{:08x} into {} ({} total corrections).",
        kind,
        addr,
        sidecar.display(),
        set.len()
    );
    if do_reanalyze {
        let n = server.reanalyze()?;
        out.push_str(&format!("\nRe-analysed: {} functions now defined.", n));
    } else {
        out.push_str("\nCall reanalyze to apply.");
    }
    Ok(out)
}

fn tool_reanalyze(server: &mut Server) -> Result<String, String> {
    let n = server.reanalyze()?;
    Ok(format!("Re-analysed; {} functions defined.", n))
}
