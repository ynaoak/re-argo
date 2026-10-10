//! Exception landing pads (WS82): what each one handles, for which calls.
//!
//! A landing pad is reached only by unwinding — no branch of the function leads to it — so
//! the structurer, which walks from the entry, never printed it. The LSDA
//! (`.gcc_except_table`, [`reargo_loader::landing_pads`]) says which calls unwind to which
//! pad and what it does; the pads are printed after the function's body under that note.

use std::collections::BTreeMap;

use reargo_loader::{EhAction, Memory, Section};

/// The call ranges unwinding to a landing pad, and what it does.
type Pad = (Vec<(u64, u64)>, Vec<EhAction>);

/// A landing pad's address and its note (`cleanup for the calls at 0x41cc0da..0x41cc113`).
pub type Handler = (u64, String);

/// The landing pads of the function at `entry`, in address order; empty without an LSDA.
pub fn handlers(memory: &Memory, sections: &[Section], symbols: &BTreeMap<u64, String>, entry: u64) -> Vec<Handler> {
    let Some(hdr) = sections.iter().find(|s| s.name == ".eh_frame_hdr").map(|s| s.address) else {
        return Vec::new();
    };
    let Some(sites) = reargo_loader::landing_pads(memory, hdr, entry) else { return Vec::new() };
    // landing pad -> (the call ranges unwinding to it, its actions)
    let mut pads: BTreeMap<u64, Pad> = BTreeMap::new();
    for s in sites.iter().filter(|s| s.landing_pad != 0) {
        let e = pads.entry(s.landing_pad).or_default();
        e.0.push((s.start, s.start + s.len));
        for a in &s.actions {
            if !e.1.contains(a) {
                e.1.push(*a);
            }
        }
    }
    pads.into_iter()
        .map(|(lp, (ranges, actions))| {
            let what: Vec<String> = actions.iter().map(|a| action_text(memory, symbols, a)).collect();
            let what = if what.is_empty() { "cleanup".to_string() } else { what.join(", ") };
            let mut calls: Vec<String> = ranges.iter().take(3).map(|(a, b)| format!("0x{a:x}..0x{b:x}")).collect();
            if ranges.len() > 3 {
                calls.push(format!("+{} more", ranges.len() - 3));
            }
            (lp, format!("{what} for the calls at {}", calls.join(", ")))
        })
        .collect()
}

fn action_text(memory: &Memory, symbols: &BTreeMap<u64, String>, a: &EhAction) -> String {
    match *a {
        EhAction::Cleanup => "cleanup".into(),
        EhAction::Filter => "exception specification".into(),
        EhAction::Catch { typeinfo, indirect } => {
            let ti = if indirect { crate::vcall::pointer_at(memory, typeinfo).unwrap_or(0) } else { typeinfo };
            if ti == 0 && !indirect {
                return "catch (...)".into();
            }
            format!("catch ({})", type_name(memory, symbols, ti).unwrap_or_else(|| format!("typeinfo 0x{ti:x}")))
        }
    }
}

/// The C++ name of the type whose `std::type_info` is at `ti`: its symbol, or the mangled
/// name its second word points to.
fn type_name(memory: &Memory, symbols: &BTreeMap<u64, String>, ti: u64) -> Option<String> {
    if ti == 0 {
        return None;
    }
    if let Some(n) = symbols.get(&ti)
        && let Some(m) = n.strip_prefix("_ZTI")
    {
        return Some(demangle_type(m).unwrap_or_else(|| n.clone()));
    }
    let name = crate::vcall::pointer_at(memory, ti + 8)?;
    let mut s = Vec::new();
    for i in 0..256 {
        match memory.read_byte(name + i)? {
            0 => break,
            c => s.push(c),
        }
    }
    let s = String::from_utf8(s).ok()?;
    Some(demangle_type(&s).unwrap_or(s))
}

/// An Itanium-mangled type name (`St9exception`, `N9Namespace5ClassE`, `5Class`) as C++
/// (`std::exception`, `Namespace::Class`, `Class`); `None` for anything else (templates…).
pub fn demangle_type(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut parts: Vec<String> = Vec::new();
    let nested = b.first() == Some(&b'N');
    if nested {
        i += 1;
    }
    loop {
        if b.get(i..i + 2) == Some(b"St") {
            parts.push("std".into());
            i += 2;
            continue;
        }
        if nested && b.get(i) == Some(&b'E') && i + 1 == b.len() {
            break;
        }
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let n: usize = s.get(start..i)?.parse().ok()?;
        parts.push(s.get(i..i + n)?.to_string());
        i += n;
        if !nested {
            break;
        }
    }
    (i + usize::from(nested) == b.len() && !parts.is_empty()).then(|| parts.join("::"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_plain_and_nested_type_names() {
        assert_eq!(demangle_type("St9exception").as_deref(), Some("std::exception"));
        assert_eq!(demangle_type("N9Namespace5ClassE").as_deref(), Some("Namespace::Class"));
        assert_eq!(demangle_type("NSt3__112system_errorE").as_deref(), Some("std::__1::system_error"));
        assert_eq!(demangle_type("5Class").as_deref(), Some("Class"));
        assert_eq!(demangle_type("I"), None);
    }
}
