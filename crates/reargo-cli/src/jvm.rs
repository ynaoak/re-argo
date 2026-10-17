//! `re-argo jvm …` — Java class-file / JAR analysis.
//!
//! Loader-only commands: they parse the class path on every run and
//! never touch the native analyzer pipeline or its cache.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use reargo_jvm::bytecode::{self, format_insn};
use reargo_jvm::classfile::{ClassFile, MemberKind, access_keywords, quote};
use reargo_jvm::descriptor::{field_type, method_signature};
use reargo_jvm::index::{Target, internal_name};
use reargo_jvm::{ClassPath, Reference, Site};
use rustc_hash::FxHashSet;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum JvmCmd {
    /// List the classes in a JAR (or a single .class file)
    Classes {
        /// Path to a .jar / .zip / .class file
        file: PathBuf,
        /// Only classes whose name contains this text (case-insensitive)
        #[arg(long)]
        filter: Option<String>,
        /// List non-class resources (JSON, images, shaders, …) instead
        #[arg(long)]
        resources: bool,
        /// Maximum number of rows to print (0 = unlimited)
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Show one class: header, fields and method signatures
    Class {
        file: PathBuf,
        /// Class name, dotted (`a.b.C`) or internal (`a/b/C`)
        class: String,
    },
    /// Disassemble the bytecode of a class (javap -c style)
    Disasm {
        file: PathBuf,
        class: String,
        /// Only methods with this name
        #[arg(long)]
        method: Option<String>,
    },
    /// String literals (`ldc`) and the methods that push them
    Strings {
        file: PathBuf,
        /// Only strings containing this text (case-insensitive)
        #[arg(long)]
        pattern: Option<String>,
        /// Also list `static final String` constant fields
        #[arg(long)]
        constants: bool,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Who references a class, method or field.
    ///
    /// Target forms: `a.b.C` (any use of the class), `a.b.C.name`,
    /// `a.b.C.name(I)V` (exact overload), `*.name` (any owner).
    Xrefs {
        file: PathBuf,
        target: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Methods called by a method, as a tree
    Callees {
        file: PathBuf,
        /// `a.b.C.method` or `a.b.C.method(desc)`
        method: String,
        /// Tree depth (1 = direct calls only)
        #[arg(long, default_value_t = 1)]
        depth: usize,
        /// Include calls into classes outside the JAR (JDK, libraries)
        #[arg(long)]
        external: bool,
    },
    /// Methods that call a method, as a reverse tree.
    ///
    /// Calls through a supertype or subtype of the owner count too
    /// (virtual dispatch), and are marked `[via a.b.Owner]`. Supertypes
    /// outside the JAR (`Runnable`, `kotlin.jvm.functions.Function1`, …)
    /// are skipped unless `--via-external`: every lambda shares them,
    /// so they would list every caller of every lambda.
    Callers {
        file: PathBuf,
        method: String,
        #[arg(long, default_value_t = 1)]
        depth: usize,
        /// Also follow calls through supertypes outside the JAR
        #[arg(long)]
        via_external: bool,
    },
    /// Classes extending / implementing a class or interface, as a tree
    Subtypes { file: PathBuf, class: String },
}

pub fn run(cmd: JvmCmd) -> CmdResult {
    match cmd {
        JvmCmd::Classes { file, filter, resources, limit } => cmd_classes(&file, filter.as_deref(), resources, limit),
        JvmCmd::Class { file, class } => cmd_class(&file, &class),
        JvmCmd::Disasm { file, class, method } => cmd_disasm(&file, &class, method.as_deref()),
        JvmCmd::Strings { file, pattern, constants, limit } => cmd_strings(&file, pattern.as_deref(), constants, limit),
        JvmCmd::Xrefs { file, target, limit } => cmd_xrefs(&file, &target, limit),
        JvmCmd::Callees { file, method, depth, external } => cmd_callees(&file, &method, depth, external),
        JvmCmd::Callers { file, method, depth, via_external } => cmd_callers(&file, &method, depth, via_external),
        JvmCmd::Subtypes { file, class } => cmd_subtypes(&file, &class),
    }
}

fn load(path: &Path) -> Result<ClassPath, Box<dyn std::error::Error>> {
    let cp = ClassPath::load(path)?;
    if !cp.errors.is_empty() {
        eprintln!("warning: {} class entries failed to parse (first: {}: {})", cp.errors.len(), cp.errors[0].0, cp.errors[0].1);
    }
    Ok(cp)
}

fn find_class<'a>(cp: &'a ClassPath, name: &str) -> Result<&'a ClassFile, Box<dyn std::error::Error>> {
    cp.class(name).ok_or_else(|| format!("class not found: {name} (try `re-argo jvm classes --filter`)").into())
}

fn header(title: String) {
    println!("\n{title}");
    println!("{}", "-".repeat(72));
}

fn more(shown: usize, total: usize) {
    if shown < total {
        println!("\n... {} more (raise --limit to see them)", total - shown);
    }
}

fn shown(limit: usize, total: usize) -> usize {
    if limit == 0 { total } else { total.min(limit) }
}

/// `a.b.C.method(I)V:42 @pc 17` — the descriptor keeps obfuscated
/// overloads (`a`, `a`, `a`) apart.
fn site_text(cp: &ClassPath, s: &Site) -> String {
    let line = s.line.map(|l| format!(":{l}")).unwrap_or_default();
    let desc = &cp.classes[s.class].methods[s.method].descriptor;
    format!("{}{desc}{line} @pc {}", cp.site_name(s), s.pc)
}

fn reference_text(r: &Reference) -> String {
    match r {
        Reference::Method { opcode, target } | Reference::Field { opcode, target } => {
            format!("{:<15} {}.{}:{}", bytecode::mnemonic(*opcode), target.owner.replace('/', "."), target.name, target.descriptor)
        }
        Reference::Class { opcode, name } => format!("{:<15} {}", bytecode::mnemonic(*opcode), name.replace('/', ".")),
        Reference::Str(s) => format!("{:<15} {}", "ldc", quote(s)),
        Reference::Dynamic { name, descriptor } => format!("{:<15} {name}{descriptor}", "invokedynamic"),
    }
}

fn cmd_classes(path: &Path, filter: Option<&str>, resources: bool, limit: usize) -> CmdResult {
    let cp = load(path)?;
    let needle = filter.map(str::to_lowercase);
    let keep = |s: &str| needle.as_ref().is_none_or(|n| s.to_lowercase().contains(n.as_str()));
    if resources {
        let rows: Vec<&String> = cp.resources.iter().filter(|r| keep(r)).collect();
        header(format!("Resources in {}: {} found", path.display(), rows.len()));
        let n = shown(limit, rows.len());
        for r in &rows[..n] {
            println!("  {r}");
        }
        more(n, rows.len());
        return Ok(());
    }
    let needle = filter.map(|f| f.to_lowercase().replace('/', "."));
    let keep = |s: &str| needle.as_ref().is_none_or(|n| s.to_lowercase().contains(n.as_str()));
    let rows: Vec<&ClassFile> = cp.classes.iter().filter(|c| keep(&c.dotted_name())).collect();
    header(format!("Classes in {}: {} found ({} total)", path.display(), rows.len(), cp.classes.len()));
    println!("  {:<64} {:>4} {:>4}  extends", "class", "meth", "fld");
    let n = shown(limit, rows.len());
    for c in &rows[..n] {
        let kind = if c.is_interface() { " (interface)" } else { "" };
        let sup = c.super_name.as_deref().unwrap_or("-").replace('/', ".");
        println!("  {:<64} {:>4} {:>4}  {sup}{kind}", c.dotted_name(), c.methods.len(), c.fields.len());
    }
    more(n, rows.len());
    Ok(())
}

fn cmd_class(path: &Path, name: &str) -> CmdResult {
    let cp = load(path)?;
    let c = find_class(&cp, name)?;
    header(format!("Class {}", c.dotted_name()));
    println!("  Access:      {}", access_keywords(c.access, MemberKind::Class));
    println!("  Kind:        {}", if c.is_interface() { "interface" } else { "class" });
    println!("  Version:     {}.{} ({})", c.major_version, c.minor_version, c.java_version());
    println!("  Extends:     {}", c.super_name.as_deref().unwrap_or("-").replace('/', "."));
    if !c.interfaces.is_empty() {
        let names: Vec<String> = c.interfaces.iter().map(|i| i.replace('/', ".")).collect();
        println!("  Implements:  {}", names.join(", "));
    }
    if let Some(s) = &c.source_file {
        println!("  Source file: {s}");
    }
    if let Some(s) = &c.signature {
        println!("  Signature:   {s}");
    }
    println!("  Subtypes:    {} direct", cp.direct_subtypes(&c.name).len());

    println!("\n  Fields ({}):", c.fields.len());
    for f in &c.fields {
        let acc = access_keywords(f.access, MemberKind::Field);
        let value = f.constant_value.map(|i| format!(" = {}", c.display_constant(i))).unwrap_or_default();
        println!("    {}{} {}{value}", if acc.is_empty() { String::new() } else { format!("{acc} ") }, field_type(&f.descriptor), f.name);
    }
    println!("\n  Methods ({}):", c.methods.len());
    for m in &c.methods {
        let acc = access_keywords(m.access, MemberKind::Method);
        let size = m.code.as_ref().map(|k| format!("{} bytes", k.bytecode.len())).unwrap_or_else(|| "no code".into());
        println!(
            "    {}{}  [{}]  ({size})",
            if acc.is_empty() { String::new() } else { format!("{acc} ") },
            method_signature(&m.name, &m.descriptor),
            m.descriptor
        );
    }
    Ok(())
}

fn cmd_disasm(path: &Path, name: &str, method: Option<&str>) -> CmdResult {
    let cp = load(path)?;
    let c = find_class(&cp, name)?;
    let methods: Vec<_> = c.methods.iter().filter(|m| method.is_none_or(|n| m.name == n)).collect();
    if methods.is_empty() {
        return Err(format!("no method named {} in {}", method.unwrap_or("?"), c.dotted_name()).into());
    }
    header(format!("Bytecode of {}: {} method(s)", c.dotted_name(), methods.len()));
    for m in methods {
        let acc = access_keywords(m.access, MemberKind::Method);
        println!("\n  {}{}  [{}]", if acc.is_empty() { String::new() } else { format!("{acc} ") }, method_signature(&m.name, &m.descriptor), m.descriptor);
        let Some(code) = &m.code else {
            println!("    (no code)");
            continue;
        };
        println!("    max_stack={} max_locals={} code={} bytes", code.max_stack, code.max_locals, code.bytecode.len());
        let insns = match bytecode::decode(&code.bytecode) {
            Ok(i) => i,
            Err(e) => {
                println!("    (decode error: {e})");
                continue;
            }
        };
        let mut last_line = None;
        for insn in &insns {
            let line = code.line_at(insn.pc);
            if line.is_some() && line != last_line {
                println!("    // line {}", line.unwrap_or_default());
                last_line = line;
            }
            println!("  {}", format_insn(insn, c));
        }
        if !code.exceptions.is_empty() {
            println!("    exception table:");
            for e in &code.exceptions {
                let ty = e.catch_type.as_deref().map(|t| t.replace('/', ".")).unwrap_or_else(|| "any".into());
                println!("      [{}, {}) -> {}  {ty}", e.start_pc, e.end_pc, e.handler_pc);
            }
        }
    }
    Ok(())
}

fn cmd_strings(path: &Path, pattern: Option<&str>, constants: bool, limit: usize) -> CmdResult {
    let cp = load(path)?;
    let needle = pattern.map(str::to_lowercase);
    let keep = |s: &str| needle.as_ref().is_none_or(|n| s.to_lowercase().contains(n.as_str()));
    let hits = cp.find_references(|r| matches!(r, Reference::Str(s) if keep(s)));
    header(format!("String literals in {}: {} found", path.display(), hits.len()));
    let n = shown(limit, hits.len());
    for (site, r) in &hits[..n] {
        if let Reference::Str(s) = r {
            println!("  {:<56} {}", quote(s), site_text(&cp, site));
        }
    }
    more(n, hits.len());
    if constants {
        let consts: Vec<_> = cp.constant_strings().into_iter().filter(|(_, _, s)| keep(s)).collect();
        header(format!("String constant fields: {} found", consts.len()));
        let n = shown(limit, consts.len());
        for (ci, fi, s) in &consts[..n] {
            let c = &cp.classes[*ci];
            println!("  {:<56} {}.{}", quote(s), c.dotted_name(), c.fields[*fi].name);
        }
        more(n, consts.len());
    }
    Ok(())
}

fn cmd_xrefs(path: &Path, spec: &str, limit: usize) -> CmdResult {
    let cp = load(path)?;
    let target = Target::parse(spec, &cp);
    let hits = cp.find_references(|r| target.matches(r));
    let what = match &target {
        Target::Class(c) => format!("class {}", c.replace('/', ".")),
        Target::Member { owner, name, descriptor } => format!(
            "{}.{name}{}",
            owner.as_deref().map(|o| o.replace('/', ".")).unwrap_or_else(|| "*".into()),
            descriptor.as_deref().unwrap_or("")
        ),
    };
    header(format!("References to {what}: {} found", hits.len()));
    let n = shown(limit, hits.len());
    for (site, r) in &hits[..n] {
        println!("  {:<60} {}", site_text(&cp, site), reference_text(r));
    }
    more(n, hits.len());
    Ok(())
}

/// Methods named by a `a.b.C.method[(desc)]` spec, as (class, method) indices.
fn resolve_spec(cp: &ClassPath, spec: &str) -> Result<Vec<(usize, usize)>, Box<dyn std::error::Error>> {
    let Target::Member { owner: Some(owner), name, descriptor } = Target::parse(spec, cp) else {
        return Err(format!("expected a method like a.b.C.method or a.b.C.method(I)V, got {spec}").into());
    };
    let ci = cp.class_index(&owner).ok_or_else(|| format!("class not found: {}", owner.replace('/', ".")))?;
    let found: Vec<(usize, usize)> = cp.classes[ci]
        .methods
        .iter()
        .enumerate()
        .filter(|(_, m)| m.name == name && descriptor.as_ref().is_none_or(|d| *d == m.descriptor))
        .map(|(mi, _)| (ci, mi))
        .collect();
    if found.is_empty() {
        return Err(format!("no method {name} in {}", owner.replace('/', ".")).into());
    }
    Ok(found)
}

fn method_label(cp: &ClassPath, ci: usize, mi: usize) -> String {
    let c = &cp.classes[ci];
    let m = &c.methods[mi];
    format!("{}.{}{}", c.dotted_name(), m.name, m.descriptor)
}

fn cmd_callees(path: &Path, spec: &str, depth: usize, external: bool) -> CmdResult {
    let cp = load(path)?;
    for (ci, mi) in resolve_spec(&cp, spec)? {
        header(format!("Callees of {}", method_label(&cp, ci, mi)));
        let mut seen = FxHashSet::default();
        seen.insert((ci, mi));
        callee_tree(&cp, ci, mi, 1, depth.max(1), external, &mut seen);
    }
    Ok(())
}

fn callee_tree(cp: &ClassPath, ci: usize, mi: usize, level: usize, max: usize, external: bool, seen: &mut FxHashSet<(usize, usize)>) {
    let mut listed = FxHashSet::default();
    for (site, r) in cp.method_references(ci, mi) {
        let Reference::Method { opcode, target } = r else { continue };
        if !listed.insert(target.clone()) {
            continue;
        }
        let resolved = cp.resolve_method(&target.owner, &target.name, &target.descriptor);
        if resolved.is_none() && !external {
            continue;
        }
        let indent = "  ".repeat(level);
        let line = site.line.map(|l| format!(" (line {l})")).unwrap_or_default();
        let label = match resolved {
            Some((rc, rm)) => method_label(cp, rc, rm),
            None => format!("{}.{}{} [external]", target.owner.replace('/', "."), target.name, target.descriptor),
        };
        let recursed = resolved.is_some_and(|r| !seen.insert(r));
        println!("{indent}{:<15} {label}{line}{}", bytecode::mnemonic(opcode), if recursed { " [seen]" } else { "" });
        if let (Some((rc, rm)), false) = (resolved, recursed)
            && level < max
        {
            callee_tree(cp, rc, rm, level + 1, max, external, seen);
        }
    }
}

fn cmd_callers(path: &Path, spec: &str, depth: usize, via_external: bool) -> CmdResult {
    let cp = load(path)?;
    // One pass over the class path, then walk the reverse edges.
    let calls = cp.find_references(|r| matches!(r, Reference::Method { .. }));
    for (ci, mi) in resolve_spec(&cp, spec)? {
        header(format!("Callers of {}", method_label(&cp, ci, mi)));
        let mut seen = FxHashSet::default();
        seen.insert((ci, mi));
        caller_tree(&cp, &calls, ci, mi, 1, depth.max(1), via_external, &mut seen);
    }
    Ok(())
}

/// Owner classes through which a call can reach `cls`'s method:
/// the class itself, its subtypes and its supertypes (only those inside
/// the JAR unless `via_external`).
fn dispatch_owners(cp: &ClassPath, ci: usize, via_external: bool) -> FxHashSet<String> {
    let mut owners: FxHashSet<String> = cp.all_subtypes(&cp.classes[ci].name).into_iter().map(|(i, _)| cp.classes[i].name.clone()).collect();
    let mut stack = vec![cp.classes[ci].name.clone()];
    while let Some(n) = stack.pop() {
        let inside = cp.class(&n);
        if (inside.is_none() && !via_external) || !owners.insert(n.clone()) {
            continue;
        }
        if let Some(c) = inside {
            stack.extend(c.super_name.iter().cloned());
            stack.extend(c.interfaces.iter().cloned());
        }
    }
    owners
}

#[allow(clippy::too_many_arguments)]
fn caller_tree(
    cp: &ClassPath,
    calls: &[(Site, Reference)],
    ci: usize,
    mi: usize,
    level: usize,
    max: usize,
    via_external: bool,
    seen: &mut FxHashSet<(usize, usize)>,
) {
    let c = &cp.classes[ci];
    let m = &c.methods[mi];
    let owners = dispatch_owners(cp, ci, via_external);
    let mut listed = FxHashSet::default();
    for (site, r) in calls {
        let Reference::Method { target, .. } = r else { continue };
        if target.name != m.name || target.descriptor != m.descriptor || !owners.contains(&target.owner) {
            continue;
        }
        if !listed.insert((site.class, site.method)) {
            continue;
        }
        let via = if target.owner != c.name { format!(" [via {}]", target.owner.replace('/', ".")) } else { String::new() };
        let recursed = !seen.insert((site.class, site.method));
        println!("{}{}{via}{}", "  ".repeat(level), site_text(cp, site), if recursed { " [seen]" } else { "" });
        if !recursed && level < max {
            caller_tree(cp, calls, site.class, site.method, level + 1, max, via_external, seen);
        }
    }
}

fn cmd_subtypes(path: &Path, name: &str) -> CmdResult {
    let cp = load(path)?;
    let subs = cp.all_subtypes(name);
    header(format!("Subtypes of {}: {} found", internal_name(name).replace('/', "."), subs.len()));
    for (ci, depth) in subs {
        let c = &cp.classes[ci];
        let kind = if c.is_interface() { " (interface)" } else { "" };
        println!("{}{}{kind}", "  ".repeat(depth), c.dotted_name());
    }
    Ok(())
}
