//! Whole-class-path queries: load every class of a JAR (or a single
//! class file), then walk bytecode for references — method calls,
//! field accesses, class uses and string literals.

use std::path::Path;

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::bytecode::{self, Insn};
use crate::classfile::{ClassFile, Constant, Member, MemberRef};
use crate::jar::Jar;
use crate::{JvmError, Result};

/// What an instruction refers to.
#[derive(Debug, Clone, PartialEq)]
pub enum Reference {
    /// `invoke{virtual,special,static,interface}`.
    Method { opcode: u8, target: MemberRef },
    /// `{get,put}{field,static}`.
    Field { opcode: u8, target: MemberRef },
    /// `new`, `checkcast`, `instanceof`, `anewarray`,
    /// `multianewarray`, or an `ldc` of a class literal.
    Class { opcode: u8, name: String },
    /// `ldc` of a string literal.
    Str(String),
    /// `invokedynamic` call site (lambda, string concat, …).
    Dynamic { name: String, descriptor: String },
}

/// Where a reference sits: class index into [`ClassPath::classes`],
/// method index into that class's `methods`, bytecode pc and source
/// line (when the class kept a `LineNumberTable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Site {
    pub class: usize,
    pub method: usize,
    pub pc: u32,
    pub line: Option<u16>,
}

pub struct ClassPath {
    pub classes: Vec<ClassFile>,
    by_name: FxHashMap<String, usize>,
    /// Entries that looked like classes but failed to parse.
    pub errors: Vec<(String, JvmError)>,
    /// Non-class entries (resources) of the JAR.
    pub resources: Vec<String>,
}

impl ClassPath {
    /// Load a `.class` file or a JAR / ZIP, chosen by magic bytes.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        match data.get(..4) {
            Some([0xCA, 0xFE, 0xBA, 0xBE]) => Ok(Self::from_classes(vec![ClassFile::parse(&data)?], Vec::new(), Vec::new())),
            Some([b'P', b'K', 3, 4]) | Some([b'P', b'K', 5, 6]) => Self::from_jar(&Jar::from_bytes(data)?),
            _ => Err(JvmError::UnknownInput(path.display().to_string())),
        }
    }

    pub fn from_jar(jar: &Jar) -> Result<Self> {
        let parsed: Vec<(String, Result<ClassFile>)> = jar
            .entries()
            .par_iter()
            .filter(|e| e.name.ends_with(".class") && !e.is_dir())
            .map(|e| (e.name.clone(), jar.read(e).and_then(|b| ClassFile::parse(&b))))
            .collect();
        let mut classes = Vec::with_capacity(parsed.len());
        let mut errors = Vec::new();
        for (name, r) in parsed {
            match r {
                // Multi-release JARs ship per-version copies under
                // META-INF/versions/N/; keep the base one.
                Ok(cf) if name.starts_with("META-INF/versions/") => drop(cf),
                Ok(cf) => classes.push(cf),
                Err(e) => errors.push((name, e)),
            }
        }
        let resources = jar.entries().iter().filter(|e| !e.is_dir() && !e.name.ends_with(".class")).map(|e| e.name.clone()).collect();
        Ok(Self::from_classes(classes, errors, resources))
    }

    pub fn from_classes(mut classes: Vec<ClassFile>, errors: Vec<(String, JvmError)>, resources: Vec<String>) -> Self {
        classes.sort_by(|a, b| a.name.cmp(&b.name));
        let by_name = classes.iter().enumerate().map(|(i, c)| (c.name.clone(), i)).collect();
        Self { classes, by_name, errors, resources }
    }

    /// Look a class up by internal (`a/b/C`) or dotted (`a.b.C`) name.
    pub fn class(&self, name: &str) -> Option<&ClassFile> {
        self.class_index(name).map(|i| &self.classes[i])
    }

    pub fn class_index(&self, name: &str) -> Option<usize> {
        self.by_name.get(&internal_name(name)).copied()
    }

    /// Find `name` + `descriptor` on `class` or its superclasses /
    /// interfaces inside this class path (the JVM's resolution order,
    /// minus classes that live outside the JAR).
    pub fn resolve_method(&self, class: &str, name: &str, descriptor: &str) -> Option<(usize, usize)> {
        let mut seen = FxHashSet::default();
        let mut queue = vec![class.to_string()];
        while let Some(c) = queue.pop() {
            if !seen.insert(c.clone()) {
                continue;
            }
            let Some(ci) = self.class_index(&c) else { continue };
            let cf = &self.classes[ci];
            if let Some(mi) = cf.methods.iter().position(|m| m.name == name && m.descriptor == descriptor) {
                return Some((ci, mi));
            }
            queue.extend(cf.interfaces.iter().rev().cloned());
            queue.extend(cf.super_name.clone());
        }
        None
    }

    /// Classes that directly extend or implement `name`.
    pub fn direct_subtypes(&self, name: &str) -> Vec<usize> {
        let n = internal_name(name);
        (0..self.classes.len())
            .filter(|&i| {
                let c = &self.classes[i];
                c.super_name.as_deref() == Some(n.as_str()) || c.interfaces.contains(&n)
            })
            .collect()
    }

    /// Every transitive subtype of `name` in tree pre-order, with its
    /// depth (1 = direct).
    pub fn all_subtypes(&self, name: &str) -> Vec<(usize, usize)> {
        let mut children: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
        for (i, c) in self.classes.iter().enumerate() {
            for p in c.super_name.iter().chain(c.interfaces.iter()) {
                children.entry(p.as_str()).or_default().push(i);
            }
        }
        let kids = |n: &str| children.get(n).map(Vec::as_slice).unwrap_or_default().to_vec();
        let mut out = Vec::new();
        let mut seen = FxHashSet::default();
        let mut stack: Vec<(usize, usize)> = kids(&internal_name(name)).into_iter().rev().map(|ci| (ci, 1)).collect();
        while let Some((ci, depth)) = stack.pop() {
            if !seen.insert(ci) {
                continue;
            }
            out.push((ci, depth));
            stack.extend(kids(&self.classes[ci].name).into_iter().rev().map(|k| (k, depth + 1)));
        }
        out
    }

    /// Decoded instructions of a method (empty when it has no code or
    /// the bytecode is malformed).
    pub fn insns(member: &Member) -> Vec<Insn> {
        member.code.as_ref().and_then(|c| bytecode::decode(&c.bytecode).ok()).unwrap_or_default()
    }

    /// All references made from one method.
    pub fn method_references(&self, class: usize, method: usize) -> Vec<(Site, Reference)> {
        let cf = &self.classes[class];
        let m = &cf.methods[method];
        let Some(code) = &m.code else { return Vec::new() };
        let mut out = Vec::new();
        for insn in Self::insns(m) {
            let Some(r) = reference_of(&insn, cf) else { continue };
            out.push((Site { class, method, pc: insn.pc, line: code.line_at(insn.pc) }, r));
        }
        out
    }

    /// Every reference in the class path that satisfies `pred`, in
    /// class / method / pc order.
    pub fn find_references<F>(&self, pred: F) -> Vec<(Site, Reference)>
    where
        F: Fn(&Reference) -> bool + Sync,
    {
        let mut out: Vec<(Site, Reference)> = (0..self.classes.len())
            .into_par_iter()
            .flat_map_iter(|ci| {
                (0..self.classes[ci].methods.len()).flat_map(move |mi| self.method_references(ci, mi)).collect::<Vec<_>>()
            })
            .filter(|(_, r)| pred(r))
            .collect();
        out.sort_by_key(|(s, _)| (s.class, s.method, s.pc));
        out
    }

    /// `pkg.Cls.method` for a site.
    pub fn site_name(&self, site: &Site) -> String {
        let cf = &self.classes[site.class];
        format!("{}.{}", cf.dotted_name(), cf.methods[site.method].name)
    }

    /// Strings stored in `ConstantValue` attributes of `static final`
    /// fields — compile-time constants that `ldc` sites inline, so the
    /// field itself is the only trace left in the declaring class.
    pub fn constant_strings(&self) -> Vec<(usize, usize, String)> {
        let mut out = Vec::new();
        for (ci, cf) in self.classes.iter().enumerate() {
            for (fi, f) in cf.fields.iter().enumerate() {
                if let Some(s) = f.constant_value.and_then(|i| cf.string(i)) {
                    out.push((ci, fi, s.to_string()));
                }
            }
        }
        out
    }
}

/// `a.b.C` → `a/b/C` (internal names pass through).
pub fn internal_name(name: &str) -> String {
    name.replace('.', "/")
}

fn reference_of(insn: &Insn, cf: &ClassFile) -> Option<Reference> {
    use bytecode::*;
    let idx = insn.cp_index()?;
    Some(match insn.opcode {
        INVOKEVIRTUAL | INVOKESPECIAL | INVOKESTATIC | INVOKEINTERFACE => Reference::Method { opcode: insn.opcode, target: cf.member_ref(idx)? },
        GETSTATIC | PUTSTATIC | GETFIELD | PUTFIELD => Reference::Field { opcode: insn.opcode, target: cf.member_ref(idx)? },
        NEW | CHECKCAST | INSTANCEOF | ANEWARRAY | MULTIANEWARRAY => Reference::Class { opcode: insn.opcode, name: cf.class_name(idx)?.to_string() },
        INVOKEDYNAMIC => match cf.constant(idx)? {
            Constant::InvokeDynamic { name_and_type, .. } => {
                let (n, d) = cf.name_and_type(*name_and_type)?;
                Reference::Dynamic { name: n.to_string(), descriptor: d.to_string() }
            }
            _ => return None,
        },
        LDC | LDC_W => match cf.constant(idx)? {
            Constant::String { .. } => Reference::Str(cf.string(idx)?.to_string()),
            Constant::Class { .. } => Reference::Class { opcode: insn.opcode, name: cf.class_name(idx)?.to_string() },
            _ => return None,
        },
        _ => return None,
    })
}

/// A user-supplied reference target, parsed from forms like
/// `a.b.C`, `a.b.C.method`, `a.b.C.method(I)V`, `*.method` or `a/b/C`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Any use of the class: `new`/casts plus calls / field accesses
    /// whose owner is the class.
    Class(String),
    /// A method or field by owner (`None` = any owner), name and
    /// optional descriptor.
    Member { owner: Option<String>, name: String, descriptor: Option<String> },
}

impl Target {
    /// Parse `spec`; a spec naming a class in `cp` is a class target,
    /// otherwise the part after the last `.` is a member name.
    pub fn parse(spec: &str, cp: &ClassPath) -> Target {
        let (head, descriptor) = match spec.find('(') {
            Some(p) => (&spec[..p], Some(spec[p..].to_string())),
            None => (spec, None),
        };
        // Classes outside the JAR (`java.io.File`) are recognised by an
        // upper-case simple name, the Java naming convention.
        let last = head.rsplit(['.', '/']).next().unwrap_or(head);
        let looks_like_class = head.contains(['.', '/']) && last.starts_with(|c: char| c.is_ascii_uppercase());
        if descriptor.is_none() && !head.starts_with("*.") && (cp.class_index(head).is_some() || looks_like_class) {
            return Target::Class(internal_name(head));
        }
        match head.rfind(['.', '/']) {
            Some(p) => {
                let owner = &head[..p];
                let owner = (owner != "*").then(|| internal_name(owner));
                Target::Member { owner, name: head[p + 1..].to_string(), descriptor }
            }
            None => Target::Member { owner: None, name: head.to_string(), descriptor },
        }
    }

    pub fn matches(&self, r: &Reference) -> bool {
        match (self, r) {
            (Target::Class(c), Reference::Class { name, .. }) => name == c || name.trim_start_matches('[').trim_start_matches('L').trim_end_matches(';') == c,
            (Target::Class(c), Reference::Method { target, .. } | Reference::Field { target, .. }) => target.owner == *c,
            (Target::Member { owner, name, descriptor }, Reference::Method { target, .. } | Reference::Field { target, .. }) => {
                target.name == *name
                    && owner.as_ref().is_none_or(|o| *o == target.owner)
                    && descriptor.as_ref().is_none_or(|d| *d == target.descriptor)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classfile::testutil::ClassBuilder;
    use crate::classfile::{ACC_PUBLIC, ACC_STATIC};
    use crate::jar::testutil::build_zip;

    fn sample() -> ClassPath {
        // a/Base.helper()V ; a/Child extends a/Base, main() calls helper,
        // pushes "export.moc3", news a/Base, reads a/Base.count.
        let mut base = ClassBuilder::new("a/Base", "java/lang/Object");
        base.add_method(ACC_PUBLIC, "helper", "()V", &[0xb1], 1);
        let base = base.build();

        let mut child = ClassBuilder::new("a/Child", "a/Base");
        let call = child.method_ref("a/Child", "helper", "()V");
        let s = child.string("export.moc3");
        let cls = child.class("a/Base");
        let fld = child.field_ref("a/Base", "count", "I");
        let code = [
            0x2a, 0xb6, (call >> 8) as u8, call as u8, // aload_0; invokevirtual helper
            0x12, s as u8, 0x57, // ldc; pop
            0xbb, (cls >> 8) as u8, cls as u8, 0x57, // new a/Base; pop
            0xb2, (fld >> 8) as u8, fld as u8, 0x57, // getstatic count; pop
            0xb1,
        ];
        child.add_method(ACC_PUBLIC | ACC_STATIC, "main", "()V", &code, 10);
        let child = child.build();

        let zip = build_zip(&[("a/Base.class", &base, true), ("a/Child.class", &child, false), ("res/x.json", b"{}", false)]);
        ClassPath::from_jar(&Jar::from_bytes(zip).unwrap()).unwrap()
    }

    #[test]
    fn loads_jar_and_indexes_classes() {
        let cp = sample();
        assert_eq!(cp.classes.len(), 2);
        assert!(cp.errors.is_empty());
        assert_eq!(cp.resources, vec!["res/x.json".to_string()]);
        assert!(cp.class("a.Child").is_some());
        assert_eq!(cp.direct_subtypes("a.Base").len(), 1);
        assert_eq!(cp.all_subtypes("java/lang/Object").len(), 2);
    }

    #[test]
    fn resolves_inherited_methods() {
        let cp = sample();
        let (ci, mi) = cp.resolve_method("a/Child", "helper", "()V").unwrap();
        assert_eq!(cp.classes[ci].name, "a/Base");
        assert_eq!(cp.classes[ci].methods[mi].name, "helper");
    }

    #[test]
    fn finds_references_by_target() {
        let cp = sample();
        let t = Target::parse("a.Child.helper", &cp);
        assert_eq!(t, Target::Member { owner: Some("a/Child".into()), name: "helper".into(), descriptor: None });
        let hits = cp.find_references(|r| t.matches(r));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.pc, 1);
        assert_eq!(hits[0].0.line, Some(10));
        assert_eq!(cp.site_name(&hits[0].0), "a.Child.main");

        let any = Target::parse("*.helper", &cp);
        assert_eq!(cp.find_references(|r| any.matches(r)).len(), 1);

        // Class target: `new a/Base` + `getstatic a/Base.count`.
        let class = Target::parse("a.Base", &cp);
        assert_eq!(class, Target::Class("a/Base".into()));
        assert_eq!(cp.find_references(|r| class.matches(r)).len(), 2);

        let strings = cp.find_references(|r| matches!(r, Reference::Str(s) if s.contains("moc3")));
        assert_eq!(strings.len(), 1);
    }

    #[test]
    fn loads_single_class_file() {
        let dir = std::env::temp_dir().join(format!("reargo-jvm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Only.class");
        std::fs::write(&path, ClassBuilder::new("Only", "java/lang/Object").build()).unwrap();
        let cp = ClassPath::load(&path).unwrap();
        assert_eq!(cp.classes[0].name, "Only");
        std::fs::remove_dir_all(&dir).ok();
    }
}
