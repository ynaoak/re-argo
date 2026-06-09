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

use gr_lift::PcodeLift;
use gr_program::comments::CommentType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::callsite::resolve_call_sites;
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

    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        if !matches!(program.info.arch, gr_loader::Architecture::X86_64) {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let lifter: Box<dyn PcodeLift + Sync> = Box::new(gr_lift::x86::X86Lifter::new_64());
        let sites = resolve_call_sites(&*lifter, program)?;

        use std::sync::OnceLock;
        static DB: OnceLock<SignatureDatabase> = OnceLock::new();
        let db = DB.get_or_init(SignatureDatabase::new);

        let mut annotated = 0usize;
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
            let text = format_call(sig, site, program);
            program.comments.set(site.call_site, CommentType::Pre, text);
            annotated += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: annotated,
        })
    }
}

fn format_call(
    sig: &FunctionSignature,
    site: &crate::callsite::CallSite,
    program: &Program,
) -> String {
    let mut out = format!("{}(", sig.name);
    let n = sig.parameters.len().min(site.args.len());
    let mut first = true;
    for i in 0..n {
        let (pname, ptype) = &sig.parameters[i];
        let val = site.args[i].value;
        if !first {
            out.push_str(", ");
        }
        first = false;
        out.push_str(pname);
        out.push('=');
        match val {
            Some(v) if is_pointer_type(ptype) => {
                if let Some(s) = read_c_string(program, v) {
                    out.push_str(&format!("\"{}\"", escape(&s)));
                } else {
                    out.push_str(&format!("0x{:x}", v));
                }
            }
            Some(v) => out.push_str(&format!("0x{:x}", v)),
            None => out.push('?'),
        }
    }
    if sig.parameters.len() > n {
        out.push_str(", …");
    }
    out.push(')');
    if sig.no_return {
        out.push_str("  // noreturn");
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
    let read_len = [64, 32, 16, 8, 4]
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
}
