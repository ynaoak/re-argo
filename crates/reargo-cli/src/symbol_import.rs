//! Bulk symbol-name import for the `annotate --import` flow.
//!
//! Why this matters: every stripped C++ binary worth reversing
//! (BDS, V8, Skia, anything shipped from a vendor build) has had
//! `.symtab` and DWARF dropped. The community fills that gap by
//! publishing per-version (offset, mangled-name) lists -- the
//! LeviLamina / Endstone / PNX ecosystem maintains these for
//! Bedrock servers, and similar lists exist for every other
//! widely-reversed binary. Without a way to bulk-load such a list,
//! every command in this tool ends up showing FUN_00ca3a000 even
//! when the analyst knows it's `NetherBiomeSource::getBiome`.
//!
//! This module is the parser for those lists. It feeds the existing
//! user-override sidecar (`<binary>.gra.json`), so once imported the
//! names propagate through every command (decompile, functions,
//! xrefs, ...) exactly the way a hand-typed `--rename` would.
//!
//! Two formats so common community dumps need at most a one-liner
//! conversion:
//!
//! * **JSON** -- either a flat `{ "0xADDR": "name", ... }` map, or
//!   an array of records `[{"offset": ..., "name": "..."}, ...]`.
//!   Offsets may be hex strings (`"0x4416"`) or integers.
//! * **Text** -- `<offset> <name>` per line. Offset hex
//!   (with/without `0x` prefix) or decimal. Comments start with
//!   `#`, `;`, or `//`. Blank lines skipped.
//!
//! Mangled C++/Rust names go through the same demangler the
//! `DemangleAnalyzer` uses, so an imported `_ZN6Server4tickEv`
//! becomes `Server::tick()` automatically. Opt out via
//! `--keep-mangled` for cases where the analyst wants exact match
//! against the original mangled string.

use std::path::Path;

use reargo_program::OverrideSet;
use serde::Deserialize;

/// One (offset, name) pair parsed out of an import file. Kept
/// lightweight so the parser can stream into a Vec without the
/// caller needing to know the source format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub offset: u64,
    pub name: String,
}

/// JSON record form: `{"offset": ..., "name": "..."}`. The offset
/// is either a hex string (with or without `0x`) or an integer.
#[derive(Debug, Deserialize)]
struct JsonRecord {
    #[serde(alias = "addr", alias = "address")]
    offset: serde_json::Value,
    #[serde(alias = "symbol")]
    name: String,
}

/// Auto-detect format and parse. Detection rules in priority order:
///
/// 1. File extension `.json` -> JSON.
/// 2. First non-whitespace char is `{` or `[` -> JSON.
/// 3. Otherwise -> text format.
pub fn parse(data: &str, source_path: &Path) -> Result<Vec<Entry>, String> {
    let is_json = source_path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        || data
            .trim_start()
            .chars()
            .next()
            .is_some_and(|c| c == '{' || c == '[');

    if is_json {
        parse_json(data)
    } else {
        parse_text(data)
    }
}

fn parse_json(data: &str) -> Result<Vec<Entry>, String> {
    let v: serde_json::Value =
        serde_json::from_str(data).map_err(|e| format!("json parse: {}", e))?;

    match v {
        serde_json::Value::Object(map) => {
            let mut out = Vec::with_capacity(map.len());
            for (k, v) in map {
                let name = v
                    .as_str()
                    .ok_or_else(|| format!("json: value for key {:?} is not a string", k))?;
                let offset = parse_offset_str(&k)
                    .ok_or_else(|| format!("json: invalid offset key {:?}", k))?;
                out.push(Entry {
                    offset,
                    name: name.to_string(),
                });
            }
            Ok(out)
        }
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.into_iter().enumerate() {
                let rec: JsonRecord = serde_json::from_value(item)
                    .map_err(|e| format!("json: record {}: {}", i, e))?;
                let offset = match &rec.offset {
                    serde_json::Value::String(s) => parse_offset_str(s)
                        .ok_or_else(|| format!("json: record {}: bad offset {:?}", i, s))?,
                    serde_json::Value::Number(n) => n
                        .as_u64()
                        .ok_or_else(|| format!("json: record {}: offset not u64", i))?,
                    other => return Err(format!("json: record {}: offset is {:?}", i, other)),
                };
                out.push(Entry {
                    offset,
                    name: rec.name,
                });
            }
            Ok(out)
        }
        other => Err(format!("json: expected object or array, got {:?}", other)),
    }
}

fn parse_text(data: &str) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    for (lineno, raw) in data.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        let mut parts = line.splitn(2, |c: char| c.is_whitespace());
        let off_s = parts.next().unwrap_or("");
        let name = parts
            .next()
            .ok_or_else(|| format!("line {}: missing name", lineno + 1))?
            .trim();
        if name.is_empty() {
            return Err(format!("line {}: empty name", lineno + 1));
        }
        let offset = parse_offset_str(off_s)
            .ok_or_else(|| format!("line {}: bad offset {:?}", lineno + 1, off_s))?;
        out.push(Entry {
            offset,
            name: name.to_string(),
        });
    }
    Ok(out)
}

/// Accept `0x4416`, `4416` (decimal), or `0X4416`. Returning None
/// is reserved for genuinely malformed input -- empty / non-digits.
fn parse_offset_str(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        // Fall back through hex first so bare `4416` from a hexdump
        // round-trips; decimal lookalikes (e.g. dlsym dumps that
        // already include "0x") have hit the strip_prefix arm.
        u64::from_str_radix(s, 16).ok().or_else(|| s.parse().ok())
    }
}

/// Apply parsed entries to an override set's `names` map,
/// optionally demangling. Returns `(added, demangled)` -- `added`
/// counts new + changed entries (overwriting an existing rename
/// is intentional), `demangled` is how many had their name
/// rewritten by the demangler.
pub fn merge_into(
    overrides: &mut OverrideSet,
    entries: Vec<Entry>,
    demangle: bool,
) -> (usize, usize) {
    let mut added = 0;
    let mut demangled = 0;
    for e in entries {
        let final_name = if demangle {
            match reargo_analysis::demangle::try_demangle(&e.name) {
                Some(d) => {
                    demangled += 1;
                    d
                }
                None => e.name,
            }
        } else {
            e.name
        };
        let prev = overrides.names.insert(e.offset, final_name.clone());
        if prev.as_deref() != Some(&final_name) {
            added += 1;
        }
    }
    (added, demangled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn parse_text_basic() {
        let src = "\
            # bds 1.26.21.1 names\n\
            0x1140 _ZN6Server4tickEv\n\
            0x1180  start_server  \n\
            ;; commented out\n\
            // also a comment\n\
            \n\
            4500 plain_decimal_offset\n\
        ";
        let entries = parse(src, &p("syms.txt")).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].offset, 0x1140);
        assert_eq!(entries[0].name, "_ZN6Server4tickEv");
        assert_eq!(entries[1].offset, 0x1180);
        assert_eq!(entries[1].name, "start_server");
        // Bare `4500` is hex-first to round-trip hexdumps.
        assert_eq!(entries[2].offset, 0x4500);
    }

    #[test]
    fn parse_text_rejects_missing_name() {
        let src = "0x1140\n";
        assert!(parse(src, &p("syms.txt")).is_err());
    }

    #[test]
    fn parse_json_flat_map() {
        let src = r#"{
            "0x1140": "_ZN6Server4tickEv",
            "0x1180": "start_server"
        }"#;
        let mut entries = parse(src, &p("syms.json")).unwrap();
        entries.sort_by_key(|e| e.offset);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].offset, 0x1140);
        assert_eq!(entries[1].name, "start_server");
    }

    #[test]
    fn parse_json_array_of_records() {
        let src = r#"[
            {"offset": "0x1140", "name": "_ZN6Server4tickEv"},
            {"address": 4480,    "symbol": "start_server"}
        ]"#;
        let entries = parse(src, &p("syms.json")).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].offset, 0x1140);
        assert_eq!(entries[1].offset, 4480);
        assert_eq!(entries[1].name, "start_server");
    }

    #[test]
    fn parse_autodetects_json_without_extension() {
        let src = r#"{"0x10": "f"}"#;
        let entries = parse(src, &p("syms.dump")).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn merge_demangles_when_enabled() {
        let mut o = OverrideSet::default();
        let entries = vec![
            Entry {
                offset: 0x1140,
                name: "_ZN3foo3barEi".into(),
            },
            Entry {
                offset: 0x1180,
                name: "start_server".into(),
            },
        ];
        let (added, demangled) = merge_into(&mut o, entries, true);
        assert_eq!(added, 2);
        assert_eq!(demangled, 1);
        let demangled_name = o.names.get(&0x1140).unwrap();
        assert!(demangled_name.contains("foo"));
        assert!(demangled_name.contains("bar"));
        assert_eq!(o.names.get(&0x1180).map(String::as_str), Some("start_server"));
    }

    #[test]
    fn merge_keeps_mangled_when_disabled() {
        let mut o = OverrideSet::default();
        let entries = vec![Entry {
            offset: 0x1140,
            name: "_ZN3foo3barEi".into(),
        }];
        let (added, demangled) = merge_into(&mut o, entries, false);
        assert_eq!(added, 1);
        assert_eq!(demangled, 0);
        assert_eq!(o.names.get(&0x1140).map(String::as_str), Some("_ZN3foo3barEi"));
    }

    #[test]
    fn merge_idempotent_when_unchanged() {
        let mut o = OverrideSet::default();
        let entries = vec![Entry {
            offset: 0x1140,
            name: "foo".into(),
        }];
        let (added, _) = merge_into(&mut o, entries.clone(), false);
        assert_eq!(added, 1);
        let (added2, _) = merge_into(&mut o, entries, false);
        assert_eq!(added2, 0);
    }
}
