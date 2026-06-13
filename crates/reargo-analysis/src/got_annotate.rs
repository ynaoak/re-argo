//! Annotate GOT / IAT slots with their resolved import names and
//! propagate the name to every code reference that loads the slot.
//!
//! The loader emits each `ImportEntry { name, plt_address,
//! got_address }` into `program.info.imports`. We use that table to:
//!
//! 1. Set a *plate* comment at the GOT slot so dumps of `.got` /
//!    `.got.plt` show the symbolic identity inline:
//!
//!    ```text
//!      0x404020  PLT slot -> printf
//!    ```
//!
//! 2. Walk every reference *into* a GOT slot and decorate the
//!    referring instruction with an EOL hint:
//!
//!    ```text
//!      mov rax, [rip+0x2f3d]   ; &printf@GOT
//!    ```
//!
//! Both annotations defer to whatever is already there — user
//! overrides and earlier analyzer comments win.

use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};

pub struct GotAnnotator;

impl Analyzer for GotAnnotator {
    fn name(&self) -> &str {
        "GOT Annotator"
    }
    fn description(&self) -> &str {
        "Annotates GOT / IAT slots with the import they resolve and decorates loads"
    }
    fn priority(&self) -> u32 {
        // After CallSiteAnnotator / StringXref so we don't overwrite
        // their EOL comments on instructions that load through the
        // GOT for both a string and an import resolution.
        770
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        // Index GOT addresses → import names. Use BTreeMap so iteration
        // is deterministic for tests and reproducible builds.
        let by_got: std::collections::BTreeMap<u64, String> = program
            .info
            .imports
            .iter()
            .map(|imp| (imp.got_address, imp.name.clone()))
            .collect();

        if by_got.is_empty() {
            return Ok(AnalysisResult {
                analyzer_name: self.name().into(),
                functions_found: 0,
                references_found: 0,
                instructions_decoded: 0,
            });
        }

        let mut emitted = 0usize;

        // (1) Plate comments on each GOT slot.
        for (&got_addr, name) in &by_got {
            if program.comments.get(got_addr, CommentType::Plate).is_some() {
                continue;
            }
            program
                .comments
                .set(got_addr, CommentType::Plate, format!("GOT slot -> {}", name));
            emitted += 1;
        }

        // (2) EOL comments at code that loads through the GOT slot.
        let edges: Vec<(u64, u64)> = program
            .references
            .all_refs()
            .filter(|r| by_got.contains_key(&r.to))
            .map(|r| (r.from, r.to))
            .collect();

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
            let Some(name) = by_got.get(&to) else {
                continue;
            };
            program
                .comments
                .set(from, CommentType::Eol, format!("&{}@GOT", name));
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
