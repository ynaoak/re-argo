//! User-override overlay: persistent manual corrections that survive
//! re-analysis and propagate through the whole program model.
//!
//! Auto-analysis is never perfect -- it truncates large functions,
//! invents bogus function starts on stripped binaries, and misses
//! real entries the pattern matcher can't see. A mature reversing
//! workflow leans on the analyst's ability to *correct* the machine
//! and have those corrections stick. This module is that layer,
//! without a GUI: corrections live in a `<binary>.gra.json` sidecar
//! and are re-applied on every load, so every command (decompile,
//! functions, xrefs, ...) sees the corrected model.
//!
//! Supported corrections (v1):
//!
//! * `force_functions` -- define a function entry auto-analysis missed.
//! * `remove_functions` -- delete a bogus auto-discovered function
//!   (purge pattern-matcher false positives).
//! * `names` -- rename a function / address; the manual name wins
//!   over every analysis name.
//! * `calling_conventions` -- pin a function's calling convention.
//! * `comments` -- attach a persistent plate comment.
//!
//! The set is intentionally a plain serde struct so the sidecar is
//! a human-editable JSON file -- the analyst can diff it, check it
//! into version control next to their notes, or hand-edit it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::comments::CommentType;
use crate::function::Function;
use crate::program::Program;
use crate::symbol::SymbolType;

/// A set of manual corrections to overlay on a program's
/// auto-analysis. All maps are keyed by address (hex in the JSON via
/// the standard integer encoding).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverrideSet {
    /// Addresses to force-define as function entry points.
    #[serde(default)]
    pub force_functions: Vec<u64>,
    /// Addresses whose auto-discovered function should be removed.
    #[serde(default)]
    pub remove_functions: Vec<u64>,
    /// Address -> overriding name (function and symbol).
    #[serde(default)]
    pub names: BTreeMap<u64, String>,
    /// Address -> calling-convention name (e.g. "__fastcall").
    #[serde(default)]
    pub calling_conventions: BTreeMap<u64, String>,
    /// Address -> persistent plate comment.
    #[serde(default)]
    pub comments: BTreeMap<u64, String>,
}

impl OverrideSet {
    /// Sidecar path for a binary: `<binary>.gra.json`. Kept beside
    /// the binary so it travels with it and is obvious to find.
    pub fn sidecar_path(binary: &Path) -> PathBuf {
        let mut s = binary.as_os_str().to_os_string();
        s.push(".gra.json");
        PathBuf::from(s)
    }

    /// Load the override set for `binary` from its sidecar, returning
    /// an empty set if the sidecar doesn't exist. Only a genuine
    /// read / parse error surfaces as `Err`.
    pub fn load_for_binary(binary: &Path) -> Result<Self, String> {
        let path = Self::sidecar_path(binary);
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load(&path)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let s = std::str::from_utf8(&data).map_err(|e| format!("utf8: {}", e))?;
        serde_json::from_str(s).map_err(|e| format!("parse {}: {}", path.display(), e))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(path, json).map_err(|e| format!("write {}: {}", path.display(), e))
    }

    /// `true` if the set carries no corrections.
    pub fn is_empty(&self) -> bool {
        self.force_functions.is_empty()
            && self.remove_functions.is_empty()
            && self.names.is_empty()
            && self.calling_conventions.is_empty()
            && self.comments.is_empty()
    }

    /// Total number of individual corrections, for status reporting.
    pub fn len(&self) -> usize {
        self.force_functions.len()
            + self.remove_functions.len()
            + self.names.len()
            + self.calling_conventions.len()
            + self.comments.len()
    }

    /// Apply every correction to `program`. Intended to run *after*
    /// the full analysis pass so manual corrections win over the
    /// machine. Returns the number of corrections actually applied
    /// (e.g. a remove of a never-discovered function counts 0).
    ///
    /// Ordering matters: remove before force/rename so a user who
    /// both removes a bogus function at X and forces a real one at
    /// the same X (rare) ends with the forced one.
    pub fn apply(&self, program: &mut Program) -> usize {
        let mut applied = 0;

        // 1. Remove bogus functions + their symbols.
        for &addr in &self.remove_functions {
            let mut hit = false;
            if program.listing.remove_function(addr).is_some() {
                hit = true;
            }
            if program.symbol_table.remove_at(addr) > 0 {
                hit = true;
            }
            if hit {
                applied += 1;
            }
        }

        // 2. Force-create functions auto-analysis missed. A bare
        //    entry is enough: the decompiler lifts from the entry
        //    and recovers the body via reachability, and the
        //    function shows up in listings immediately.
        for &addr in &self.force_functions {
            if !program.listing.has_function(addr) {
                let name = self
                    .names
                    .get(&addr)
                    .cloned()
                    .unwrap_or_else(|| format!("FUN_{:08x}", addr));
                program
                    .listing
                    .add_function(Function::new(addr, name.clone()));
                program
                    .symbol_table
                    .set_primary(addr, name, SymbolType::Function);
                applied += 1;
            }
        }

        // 3. Renames: authoritative over every analysis name.
        for (&addr, name) in &self.names {
            if let Some(func) = program.listing.get_function_mut(addr) {
                func.name = name.clone();
            }
            program
                .symbol_table
                .set_primary(addr, name.clone(), SymbolType::Function);
            applied += 1;
        }

        // 4. Calling conventions.
        for (&addr, cc) in &self.calling_conventions {
            if let Some(func) = program.listing.get_function_mut(addr) {
                func.calling_convention = Some(cc.clone());
                applied += 1;
            }
        }

        // 5. Persistent plate comments.
        for (&addr, text) in &self.comments {
            program.comments.set(addr, CommentType::Plate, text.clone());
            applied += 1;
        }

        applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_path_appends_suffix() {
        let p = OverrideSet::sidecar_path(Path::new("/bin/ls"));
        assert_eq!(p, PathBuf::from("/bin/ls.gra.json"));
    }

    #[test]
    fn roundtrip_json() {
        let mut o = OverrideSet::default();
        o.names.insert(0x1140, "parse_header".into());
        o.force_functions.push(0x2000);
        o.remove_functions.push(0x3000);
        o.calling_conventions.insert(0x1140, "__fastcall".into());
        o.comments.insert(0x1140, "entry point of parser".into());

        let json = serde_json::to_string(&o).unwrap();
        let back: OverrideSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.names.get(&0x1140).map(|s| s.as_str()), Some("parse_header"));
        assert_eq!(back.force_functions, vec![0x2000]);
        assert_eq!(back.remove_functions, vec![0x3000]);
        assert_eq!(back.len(), 5);
        assert!(!back.is_empty());
    }

    #[test]
    fn empty_set_is_empty() {
        assert!(OverrideSet::default().is_empty());
        assert_eq!(OverrideSet::default().len(), 0);
    }

    #[test]
    fn missing_fields_default() {
        // A sidecar that only sets `names` must parse, leaving the
        // other correction lists empty.
        let json = r#"{"names":{"4416":"main"}}"#;
        let o: OverrideSet = serde_json::from_str(json).unwrap();
        assert_eq!(o.names.get(&4416).map(|s| s.as_str()), Some("main"));
        assert!(o.force_functions.is_empty());
        assert!(o.comments.is_empty());
    }
}
