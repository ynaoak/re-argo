//! Infer per-call-site argument counts for variadic functions.
//!
//! When the format string at a printf-family call site is a constant,
//! the conversion-spec count tells us *exactly* how many varargs the
//! caller passed at that site. This is the missing piece that lets
//! reports like coverage and xref distinguish between
//!     printf("hi\n")
//!     printf("%d %d %d %d\n", a, b, c, d)
//! without rerunning the format parser.
//!
//! For each known call site we:
//!
//! 1. Compute the inferred vararg count from the format string.
//! 2. Append a synthetic pre-comment line like
//!    `; printf: 4 varargs from format` *only when no annotation
//!    already covers that site* — CallSiteAnnotator already pretty-
//!    prints the resolved values when it can; this is the dry,
//!    machine-readable companion.
//! 3. Compute the *maximum* inferred vararg count seen at any call
//!    site for each variadic function in the binary and stash it
//!    into `program.metadata.properties` as
//!    `varargs_<name>_max = N` — useful when picking the right
//!    function signature variant later.

use std::collections::BTreeMap;

use reargo_lift::PcodeLift;
use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::callsite::resolve_call_sites;

pub struct FormatVarargsAnalyzer;

impl Analyzer for FormatVarargsAnalyzer {
    fn name(&self) -> &str {
        "Format Varargs"
    }
    fn description(&self) -> &str {
        "Counts conversion specs per call site to infer vararg arity for printf-family callers"
    }
    fn priority(&self) -> u32 {
        // After CallSiteAnnotator (750) so we coexist with the
        // pretty-printed annotation.
        780
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
        let sites = resolve_call_sites(&*lifter, program)?;

        let mut per_callee_max: BTreeMap<String, usize> = BTreeMap::new();
        let mut emitted = 0usize;

        for site in &sites {
            let Some(target) = site.call_target else {
                continue;
            };
            let Some(sym) = program.symbol_table.primary_at(target) else {
                continue;
            };
            let raw_name = sym.name.strip_suffix("@plt").unwrap_or(&sym.name).to_string();
            let Some(fmt_idx) = printf_family_format_index(&raw_name) else {
                continue;
            };
            if fmt_idx >= site.args.len() {
                continue;
            }
            let Some(fmt_addr) = site.args[fmt_idx].value else {
                continue;
            };
            let Some(fmt) = read_c_string(program, fmt_addr) else {
                continue;
            };
            let count = count_format_specs(&fmt);

            let entry = per_callee_max.entry(raw_name.clone()).or_insert(0);
            if count > *entry {
                *entry = count;
            }

            // Compact, post-pre annotation. Goes on Post slot so it
            // doesn't fight CallSiteAnnotator's Pre comment.
            if program.comments.get(site.call_site, CommentType::Post).is_none() {
                program.comments.set(
                    site.call_site,
                    CommentType::Post,
                    format!("{}: {} varargs from format", raw_name, count),
                );
                emitted += 1;
            }
        }

        for (name, max_count) in &per_callee_max {
            program.metadata.set_property(
                format!("varargs_{}_max", name),
                max_count.to_string(),
            );
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: emitted,
        })
    }
}

fn printf_family_format_index(name: &str) -> Option<usize> {
    match name {
        "printf" | "scanf" => Some(0),
        "fprintf" | "fscanf" | "sprintf" | "sscanf" | "dprintf" => Some(1),
        "snprintf" => Some(2),
        "syslog" => Some(1),
        "err" | "errx" | "warn" | "warnx" => Some(1),
        _ => None,
    }
}

fn read_c_string(program: &Program, addr: u64) -> Option<String> {
    let mut buf = [0u8; 64];
    let n = [64, 32, 16, 8, 4]
        .into_iter()
        .find(|&n| program.info.memory.read_bytes(addr, &mut buf[..n]).is_ok())?;
    let nul = buf[..n].iter().position(|&b| b == 0)?;
    if nul < 2 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..nul]).into_owned())
}

/// Count the number of conversion specs in a printf-style format
/// string. `%%` does not count.
fn count_format_specs(fmt: &str) -> usize {
    let b = fmt.as_bytes();
    let mut count = 0usize;
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            break;
        }
        if b[i] == b'%' {
            i += 1;
            continue;
        }
        // flags
        while i < b.len() && matches!(b[i], b'-' | b'+' | b' ' | b'#' | b'0' | b'\'') {
            i += 1;
        }
        // width
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i < b.len() && b[i] == b'*' {
            i += 1;
        }
        // precision
        if i < b.len() && b[i] == b'.' {
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
        }
        // length modifiers
        while i < b.len()
            && matches!(b[i], b'h' | b'l' | b'L' | b'q' | b'j' | b'z' | b't')
        {
            i += 1;
        }
        if i < b.len()
            && matches!(
                b[i],
                b'd' | b'i'
                    | b'u'
                    | b'o'
                    | b'x'
                    | b'X'
                    | b'b'
                    | b's'
                    | b'S'
                    | b'p'
                    | b'n'
                    | b'c'
                    | b'C'
                    | b'e'
                    | b'E'
                    | b'f'
                    | b'F'
                    | b'g'
                    | b'G'
                    | b'a'
                    | b'A'
            )
        {
            count += 1;
        }
        i += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_basic() {
        assert_eq!(count_format_specs("hello"), 0);
        assert_eq!(count_format_specs("%d"), 1);
        assert_eq!(count_format_specs("%d %s %x"), 3);
        assert_eq!(count_format_specs("%-10.3lld done %p"), 2);
    }

    #[test]
    fn percent_percent_is_zero() {
        assert_eq!(count_format_specs("100%% done"), 0);
        assert_eq!(count_format_specs("%% %d %%"), 1);
    }

    #[test]
    fn malformed_trailing_percent() {
        assert_eq!(count_format_specs("got: %"), 0);
        assert_eq!(count_format_specs("got: %l"), 0);
    }
}
