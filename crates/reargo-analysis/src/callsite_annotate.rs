//! Annotate call sites with resolved arguments from the signature DB.
//!
//! Closes the loop opened by `SignatureDatabase` and `callsite::resolve_call_sites`:
//! for every direct call whose target name we recognise (libc, POSIX, Win32, …),
//! pair the resolved-constant register values with the named parameter list and
//! emit a pre-comment at the call instruction:
//!
//! ```text
//! call 0x401040            ; printf(format="Hello %s\n", arg=0x402004)
//! ```
//!
//! This is the same kind of inline call-site hint IDA writes via TIL and
//! Binary Ninja writes via its type library / view tag — the highest-impact
//! thing a 200-line signature DB can power.
//!
//! Behaviour
//! * Only x86_64 SysV today (matches `callsite.rs`); other archs no-op.
//! * Does not overwrite a pre-comment that already exists at the call site —
//!   user / earlier-analyzer notes win.
//! * For pointer-typed args whose constant value lands inside a readable
//!   section, dereferences up to 64 bytes and previews them as a C-style
//!   string literal when ≥ 2 printable bytes appear before the first NUL.

use reargo_lift::PcodeLift;
use reargo_program::comments::CommentType;
use reargo_program::symbol::{SourceType, Symbol, SymbolType};
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::callsite::resolve_call_sites_iterative;
use crate::signatures::{FunctionSignature, SignatureDatabase};

pub struct CallSiteAnnotator;

impl Analyzer for CallSiteAnnotator {
    fn name(&self) -> &str {
        "Call Site Annotator"
    }
    fn description(&self) -> &str {
        "Writes parameter-name and string-preview comments at call sites with known signatures"
    }
    fn priority(&self) -> u32 {
        // After Signatures (700) so by_name lookups see the full DB,
        // before the CrossReferenceReport analyzer (which prints comments).
        750
    }
    fn provides(&self) -> &'static [&'static str] {
        &["call_renderings", "callsite_comments"]
    }
    fn consumes(&self) -> &'static [&'static str] {
        &["functions", "signatures"]
    }

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, reargo_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let lifter: Box<dyn PcodeLift + Sync> = Box::new(reargo_lift::x86::X86Lifter::new_64());
        // Iterative inter-procedural resolver: a function whose
        // parameter has a *single* observed value across all
        // observed call sites is treated as a compile-time constant
        // inside that function. Round-by-round propagation pushes
        // constants through callback chains like
        //   register_parser(my_parser) -> list_add(my_parser) -> …
        // 4 rounds is enough for everything we've measured.
        let mut sites = resolve_call_sites_iterative(&*lifter, program, 4)?;

        // Layer multi-block CFG-aware constant propagation on top:
        // anywhere the iterative resolver came back with `?` for an
        // arg register, ask the CFG tracker whether it can pin a
        // value by joining predecessor states. This is the "format
        // string set in one block, used in the next" pattern that
        // the linear resolver misses.
        let cfg_constants = crate::cfg_const::build_call_constants(&*lifter, program);
        // VSA runs on the same lifted P-code stream but tracks
        // abstract value sets / ranges instead of point constants.
        // When the iterative + cfg_const passes both gave `?`, ask
        // VSA whether the value's still pinned (single set / degenerate
        // range), which catches arguments built from a conditional
        // join with two equal-valued predecessors that the point
        // tracker can't represent.
        let vsa_constants = crate::vsa::run_vsa(&*lifter, program);
        for site in sites.iter_mut() {
            let snap = cfg_constants.get(&site.call_site);
            let vsa_snap = vsa_constants.get(&site.call_site);
            for arg in site.args.iter_mut() {
                if arg.value.is_some() {
                    continue;
                }
                if let Some(snap) = snap
                    && let Some(v) = snap.get(&arg.reg_offset)
                {
                    arg.value = Some(*v);
                    continue;
                }
                if let Some(vs) = vsa_snap
                    && let Some(av) = vs.get(&arg.reg_offset)
                    && let Some(v) = av.as_single()
                {
                    arg.value = Some(v);
                }
            }
        }
        let sites = sites;

        use std::sync::OnceLock;
        static DB: OnceLock<SignatureDatabase> = OnceLock::new();
        let db = DB.get_or_init(SignatureDatabase::new);

        let mut annotated = 0usize;
        let mut string_promotions: Vec<u64> = Vec::new();
        for site in &sites {
            let Some(target) = site.call_target else {
                continue;
            };
            let Some(sym) = program.symbol_table.primary_at(target) else {
                continue;
            };
            let Some(sig) = db.lookup_by_name(&sym.name) else {
                continue;
            };
            if program
                .comments
                .get(site.call_site, CommentType::Pre)
                .is_some()
            {
                continue;
            }
            let (text, rendering) = format_call(sig, site, program, &mut string_promotions);
            program.comments.set(site.call_site, CommentType::Pre, text);
            // Store the C-syntax form for the decompiler emitters to
            // pick up — they otherwise emit `printf@plt()` with no
            // arguments.
            program.call_renderings.insert(site.call_site, rendering);
            annotated += 1;
        }

        // Light type-propagation: every address we successfully read as
        // a C string here was *proven* to be string data (a signature
        // declared its containing argument `char*` and we got a valid
        // NUL-terminated printable run out of it). Promote those bytes
        // to a `s_XXXX` Data symbol so xref reports and decompiler
        // output show them as strings instead of bare integers.
        string_promotions.sort_unstable();
        string_promotions.dedup();
        for addr in string_promotions {
            if program.symbol_table.primary_at(addr).is_some() {
                continue;
            }
            program.symbol_table.add(Symbol::new(
                format!("s_{:x}", addr),
                addr,
                SymbolType::Data,
                SourceType::Analysis,
            ));
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: annotated,
        })
    }
}

/// Returns `(human_annotation, c_call_rendering)`. The annotation
/// has the IDA-style `param=value` labels for the EOL/Pre comment
/// stream; the rendering has the bare value list the C decompiler
/// emits in place of the `<callee>@plt()` stub.
fn format_call(
    sig: &FunctionSignature,
    site: &crate::callsite::CallSite,
    program: &Program,
    string_promotions: &mut Vec<u64>,
) -> (String, String) {
    let mut out = format!("{}(", sig.name);
    let mut render = format!("{}(", sig.name);
    let n = sig.parameters.len().min(site.args.len());
    let mut first = true;
    for i in 0..n {
        let (pname, ptype) = &sig.parameters[i];
        let val = site.args[i].value;
        if !first {
            out.push_str(", ");
            render.push_str(", ");
        }
        first = false;
        out.push_str(pname);
        out.push('=');
        match val {
            Some(v) if is_pointer_type(ptype) => {
                if let Some(s) = read_c_string(program, v) {
                    let lit = format!("\"{}\"", escape(&s));
                    out.push_str(&lit);
                    render.push_str(&lit);
                    string_promotions.push(v);
                } else {
                    let hex = format!("0x{:x}", v);
                    out.push_str(&hex);
                    render.push_str(&hex);
                }
            }
            Some(v) => {
                let hex = format!("0x{:x}", v);
                out.push_str(&hex);
                render.push_str(&hex);
            }
            None => {
                out.push('?');
                render.push_str(&fallback_arg_name(i));
            }
        }
    }

    // printf-family vararg expansion. IDA / Binary Ninja both parse
    // the format string when it's a known constant and use the
    // conversion-spec list to type each subsequent register. We do the
    // same: walk the format, peel one register off the SysV arg list
    // per `%X` spec, and pretty-print each in its derived type.
    if sig.parameters.len() <= n
        && let Some(fmt_idx) = printf_family_format_index(&sig.name)
        && fmt_idx < site.args.len()
        && let Some(fmt_addr) = site.args[fmt_idx].value
        && let Some(fmt) = read_c_string(program, fmt_addr)
    {
        // Format string itself is a known string — propagate.
        string_promotions.push(fmt_addr);
        let specs = parse_format_specs(&fmt);
        let extra_start = fmt_idx + 1;
        let avail = site.args.len().saturating_sub(extra_start);
        for (k, spec) in specs.iter().take(avail).enumerate() {
            let arg = &site.args[extra_start + k];
            if !first {
                out.push_str(", ");
                render.push_str(", ");
            }
            first = false;
            let formatted = match arg.value {
                Some(v) if spec.is_string => match read_c_string(program, v) {
                    Some(s) => {
                        string_promotions.push(v);
                        format!("\"{}\"", escape(&s))
                    }
                    None => format!("0x{:x}", v),
                },
                Some(v) if spec.is_pointer => format!("0x{:x}", v),
                Some(v) if spec.is_char => {
                    let c = (v as u8) as char;
                    if c.is_ascii_graphic() || c == ' ' {
                        format!("'{}'", c)
                    } else {
                        format!("0x{:x}", v)
                    }
                }
                Some(v) if spec.is_signed => format!("{}", v as i64),
                Some(v) => format!("{}", v),
                None => "?".into(),
            };
            out.push_str(&formatted);
            if formatted == "?" {
                render.push_str(&fallback_vararg_name(k));
            } else {
                render.push_str(&formatted);
            }
        }
        if specs.len() > avail {
            out.push_str(", …");
            render.push_str(", /* … */");
        }
    } else if sig.parameters.len() > n {
        out.push_str(", …");
        render.push_str(", /* … */");
    }

    out.push(')');
    render.push(')');
    if sig.no_return {
        out.push_str("  // noreturn");
    }
    (out, render)
}

fn fallback_arg_name(idx: usize) -> String {
    static REG_NAMES: &[&str] = &["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    REG_NAMES
        .get(idx)
        .map(|n| (*n).to_string())
        .unwrap_or_else(|| format!("arg{}", idx))
}

fn fallback_vararg_name(idx: usize) -> String {
    format!("vararg{}", idx)
}

/// Return the index of the format-string parameter when `name` is a
/// printf-style function. The args after the format are varargs typed
/// by the conversion specs.
fn printf_family_format_index(name: &str) -> Option<usize> {
    match name {
        // index 0 = first arg
        "printf" | "scanf" => Some(0),
        "fprintf" | "fscanf" | "sprintf" | "sscanf" | "dprintf" => Some(1),
        "snprintf" => Some(2),
        "syslog" => Some(1),
        "err" | "errx" | "warn" | "warnx" => Some(1),
        _ => None,
    }
}

/// A C-format conversion spec — only enough fields to colour the
/// printed register dump downstream. We deliberately don't try to
/// reconstruct width / precision / length-mod here — those don't
/// change how the user sees the resolved value, just how printf
/// internally formats it.
#[derive(Debug, Default, Clone, Copy)]
struct FormatSpec {
    is_string: bool,
    is_char: bool,
    is_pointer: bool,
    is_signed: bool,
}

/// Walk a printf-style format string and emit one `FormatSpec` per
/// conversion. Recognises `%%` as a literal and skips flags / width /
/// precision / length modifiers between `%` and the conversion char.
fn parse_format_specs(fmt: &str) -> Vec<FormatSpec> {
    let bytes = fmt.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'%' {
            i += 1;
            continue;
        }
        // skip flags
        while i < bytes.len() && matches!(bytes[i], b'-' | b'+' | b' ' | b'#' | b'0' | b'\'') {
            i += 1;
        }
        // skip width
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'*' {
            i += 1;
        }
        // skip precision
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        // skip length modifiers
        while i < bytes.len()
            && matches!(bytes[i], b'h' | b'l' | b'L' | b'q' | b'j' | b'z' | b't')
        {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let mut spec = FormatSpec::default();
        match bytes[i] {
            b's' | b'S' => spec.is_string = true,
            b'p' | b'n' => spec.is_pointer = true,
            b'c' | b'C' => spec.is_char = true,
            b'd' | b'i' => spec.is_signed = true,
            b'u' | b'o' | b'x' | b'X' | b'b' => {}
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => {}
            _ => {}
        }
        out.push(spec);
        i += 1;
    }
    out
}

fn is_pointer_type(t: &str) -> bool {
    // Loose: anything ending in `*` or starting with `char`-shaped
    // strings or POSIX `const char*` aliases.
    let t = t.trim();
    t.ends_with('*')
        || t.contains("char *")
        || t == "char*"
        || t == "const char*"
        || t == "LPCSTR"
        || t == "LPCWSTR"
        || t == "LPSTR"
        || t == "LPWSTR"
}

fn read_c_string(program: &Program, addr: u64) -> Option<String> {
    // Loader memory blocks come from individual sections, so a 64-byte
    // probe straddles into unmapped territory and fails when the string
    // lives near a section boundary. Try a few decreasing windows and
    // accept the largest one we can actually read.
    let mut buf = [0u8; 64];
    // Finer-grained fallback: skipping straight from 16 to 8 (the
    // old behaviour) caused 13-byte strings like "out of memory" to
    // truncate to "out of m" when the parent section was 29 bytes
    // long and reading 16 straddled the boundary.
    let read_len = [64, 48, 32, 24, 16, 14, 12, 10, 8, 6, 4]
        .into_iter()
        .find(|&n| program.info.memory.read_bytes(addr, &mut buf[..n]).is_ok())?;
    let slice = &buf[..read_len];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if nul < 2 {
        return None;
    }
    let s = &slice[..nul];
    if !s.iter().all(|&b| (b' '..=b'~').contains(&b) || b == b'\n' || b == b'\t') {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_type_detection() {
        assert!(is_pointer_type("const char*"));
        assert!(is_pointer_type("char*"));
        assert!(is_pointer_type("void*"));
        assert!(is_pointer_type("FILE*"));
        assert!(is_pointer_type("LPCSTR"));
        assert!(!is_pointer_type("int"));
        assert!(!is_pointer_type("size_t"));
    }

    #[test]
    fn escape_basics() {
        assert_eq!(escape("hi\n"), "hi\\n");
        assert_eq!(escape("a\"b"), "a\\\"b");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn parse_specs_basic() {
        let s = parse_format_specs("Got %d, msg %s, hex %x\n");
        assert_eq!(s.len(), 3);
        assert!(s[0].is_signed);
        assert!(s[1].is_string);
        assert!(!s[2].is_string && !s[2].is_signed);
    }

    #[test]
    fn parse_specs_percent_literal_ignored() {
        let s = parse_format_specs("100%% done, %d files");
        assert_eq!(s.len(), 1);
        assert!(s[0].is_signed);
    }

    #[test]
    fn parse_specs_width_precision_length() {
        // padding flags, width, precision, and length modifier all skipped
        let s = parse_format_specs("%-10.3lld %0*hd");
        assert_eq!(s.len(), 2);
        assert!(s[0].is_signed);
        assert!(s[1].is_signed);
    }

    #[test]
    fn parse_specs_pointer_and_char() {
        let s = parse_format_specs("%p '%c'");
        assert!(s[0].is_pointer);
        assert!(s[1].is_char);
    }

    #[test]
    fn family_index() {
        assert_eq!(printf_family_format_index("printf"), Some(0));
        assert_eq!(printf_family_format_index("fprintf"), Some(1));
        assert_eq!(printf_family_format_index("snprintf"), Some(2));
        assert_eq!(printf_family_format_index("strcmp"), None);
    }
}
