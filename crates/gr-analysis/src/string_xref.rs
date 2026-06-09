//! Surface every code reference into a printable C string as an
//! inline EOL comment showing the literal it loads.
//!
//! IDA Pro and Binary Ninja both decorate every `lea reg, [strX]`
//! (or `mov reg, &strX`) with a one-line preview of the string at
//! the right-hand side of the disassembly view. We have the
//! references — produced by `StringReferenceAnalyzer`,
//! `PcodeReferenceAnalyzer`, and `ScalarReferenceAnalyzer` — but
//! never turned them into user-facing annotations. This analyzer
//! closes that loop:
//!
//! ```text
//!   lea  rdi, [rip+0xe15]   ; "Got %d args, msg: %s\n"
//! ```
//!
//! Behaviour
//! * Walks every `Reference` whose `from` address is an instruction.
//! * Tries to read a NUL-terminated, mostly-printable byte run from
//!   the `to` address (loader memory, capped at 64 bytes, falling
//!   back through 32 / 16 / 8 / 4 byte probes so we still see strings
//!   near a section boundary).
//! * Emits an EOL comment unless one is already set there.
//! * Caps the visible preview at 48 chars + ellipsis to keep
//!   listings legible.

use gr_program::comments::CommentType;
use gr_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct StringXrefAnnotator;

impl Analyzer for StringXrefAnnotator {
    fn name(&self) -> &str {
        "String XRef Annotator"
    }
    fn description(&self) -> &str {
        "Adds EOL string previews at every code reference into a C string"
    }
    fn priority(&self) -> u32 {
        // After everything that creates references / strings; right
        // alongside CallSiteAnnotator (which writes pre-comments).
        // EOL and pre slots don't clash, so the two analyzers can
        // coexist on the same instruction.
        760
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        // Snapshot the (from, to) pairs once so we don't hold an
        // immutable borrow on `program.references` while writing
        // comments.
        let edges: Vec<(u64, u64)> = program
            .references
            .all_refs()
            .map(|r| (r.from, r.to))
            .collect();

        // We only want to annotate from-sites that are actually
        // instructions — references from data sections (relocs,
        // vtable entries…) belong to a different surface.
        let mut emitted = 0usize;
        for (from, to) in edges {
            if program
                .listing
                .instructions_in_range(from, from + 1)
                .next()
                .is_none()
            {
                continue;
            }
            if program.comments.get(from, CommentType::Eol).is_some() {
                continue;
            }
            let Some(preview) = read_c_string(program, to) else {
                continue;
            };
            let trimmed = truncate_preview(&preview, 48);
            program
                .comments
                .set(from, CommentType::Eol, format!("\"{}\"", escape(&trimmed)));
            emitted += 1;
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: 0,
            references_found: 0,
            instructions_decoded: emitted,
        })
    }
}

fn read_c_string(program: &Program, addr: u64) -> Option<String> {
    let mut buf = [0u8; 64];
    let read_len = [64, 32, 16, 8, 4]
        .into_iter()
        .find(|&n| program.info.memory.read_bytes(addr, &mut buf[..n]).is_ok())?;
    let slice = &buf[..read_len];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if nul < 3 {
        return None;
    }
    let s = &slice[..nul];
    let printable = s
        .iter()
        .filter(|&&b| (b' '..=b'~').contains(&b) || b == b'\n' || b == b'\t')
        .count();
    // Require ≥ 80 % printable so we don't drag random binary blobs
    // (vtable padding, function pointers, etc.) into the comment
    // stream just because they happened to be referenced.
    if printable * 5 < s.len() * 4 {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

fn truncate_preview(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars).collect();
    out.push('…');
    out
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_unchanged() {
        assert_eq!(truncate_preview("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_ellipsised() {
        let s: String = "0123456789".chars().cycle().take(60).collect();
        let cut = truncate_preview(&s, 20);
        assert_eq!(cut.chars().count(), 21); // 20 + ellipsis
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn escape_handles_newlines_and_quotes() {
        assert_eq!(escape("hi\n\"world\""), "hi\\n\\\"world\\\"");
    }
}
