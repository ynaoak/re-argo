//! Class-file parser (JVMS chapter 4).

use crate::{JvmError, Reader, Result};

pub const ACC_PUBLIC: u16 = 0x0001;
pub const ACC_PRIVATE: u16 = 0x0002;
pub const ACC_PROTECTED: u16 = 0x0004;
pub const ACC_STATIC: u16 = 0x0008;
pub const ACC_FINAL: u16 = 0x0010;
pub const ACC_SYNCHRONIZED: u16 = 0x0020;
pub const ACC_VOLATILE: u16 = 0x0040;
pub const ACC_BRIDGE: u16 = 0x0040;
pub const ACC_TRANSIENT: u16 = 0x0080;
pub const ACC_VARARGS: u16 = 0x0080;
pub const ACC_NATIVE: u16 = 0x0100;
pub const ACC_INTERFACE: u16 = 0x0200;
pub const ACC_ABSTRACT: u16 = 0x0400;
pub const ACC_SYNTHETIC: u16 = 0x1000;
pub const ACC_ANNOTATION: u16 = 0x2000;
pub const ACC_ENUM: u16 = 0x4000;

/// One constant-pool slot. Index 0 and the slot after a `Long` /
/// `Double` hold [`Constant::Unusable`].
#[derive(Debug, Clone, PartialEq)]
pub enum Constant {
    Unusable,
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    Class { name: u16 },
    String { utf8: u16 },
    FieldRef { class: u16, name_and_type: u16 },
    MethodRef { class: u16, name_and_type: u16 },
    InterfaceMethodRef { class: u16, name_and_type: u16 },
    NameAndType { name: u16, descriptor: u16 },
    MethodHandle { kind: u8, reference: u16 },
    MethodType { descriptor: u16 },
    Dynamic { bootstrap: u16, name_and_type: u16 },
    InvokeDynamic { bootstrap: u16, name_and_type: u16 },
    Module { name: u16 },
    Package { name: u16 },
}

/// A resolved field / method reference: owner class (internal form,
/// `a/b/C`), member name and descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemberRef {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Clone)]
pub struct ExceptionEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    /// `None` = catch-all (`finally`).
    pub catch_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Code {
    pub max_stack: u16,
    pub max_locals: u16,
    pub bytecode: Vec<u8>,
    pub exceptions: Vec<ExceptionEntry>,
    /// `(start_pc, line)` pairs from `LineNumberTable`, sorted by pc.
    pub line_numbers: Vec<(u16, u16)>,
}

impl Code {
    /// Source line covering `pc`, when the class kept line numbers.
    pub fn line_at(&self, pc: u32) -> Option<u16> {
        self.line_numbers.iter().rev().find(|(start, _)| *start as u32 <= pc).map(|&(_, line)| line)
    }
}

/// A field or a method.
#[derive(Debug, Clone)]
pub struct Member {
    pub access: u16,
    pub name: String,
    pub descriptor: String,
    /// Generic `Signature` attribute, when present.
    pub signature: Option<String>,
    /// Methods only; `None` for abstract / native methods.
    pub code: Option<Code>,
    /// Fields only: `ConstantValue` attribute index.
    pub constant_value: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct ClassFile {
    pub minor_version: u16,
    pub major_version: u16,
    pub constants: Vec<Constant>,
    pub access: u16,
    /// Internal name (`a/b/C`).
    pub name: String,
    pub super_name: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<Member>,
    pub methods: Vec<Member>,
    pub source_file: Option<String>,
    pub signature: Option<String>,
}

impl ClassFile {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let magic = r.u32()?;
        if magic != 0xCAFE_BABE {
            return Err(JvmError::BadMagic(magic));
        }
        let minor_version = r.u16()?;
        let major_version = r.u16()?;
        let constants = parse_constants(&mut r)?;
        let mut cf = ClassFile {
            minor_version,
            major_version,
            constants,
            access: 0,
            name: String::new(),
            super_name: None,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            source_file: None,
            signature: None,
        };
        cf.access = r.u16()?;
        let this_idx = r.u16()?;
        cf.name = cf.class_name(this_idx).unwrap_or("<invalid>").to_string();
        let super_idx = r.u16()?;
        cf.super_name = cf.class_name(super_idx).map(str::to_string);
        let n = r.u16()?;
        for _ in 0..n {
            let i = r.u16()?;
            cf.interfaces.push(cf.class_name(i).unwrap_or("<invalid>").to_string());
        }
        let n = r.u16()?;
        for _ in 0..n {
            let m = cf.parse_member(&mut r)?;
            cf.fields.push(m);
        }
        let n = r.u16()?;
        for _ in 0..n {
            let m = cf.parse_member(&mut r)?;
            cf.methods.push(m);
        }
        let n = r.u16()?;
        for _ in 0..n {
            let name = r.u16()?;
            let len = r.u32()? as usize;
            let body = r.bytes(len)?;
            match cf.utf8(name) {
                Some("SourceFile") if len >= 2 => {
                    cf.source_file = cf.utf8(u16::from_be_bytes([body[0], body[1]])).map(str::to_string);
                }
                Some("Signature") if len >= 2 => {
                    cf.signature = cf.utf8(u16::from_be_bytes([body[0], body[1]])).map(str::to_string);
                }
                _ => {}
            }
        }
        Ok(cf)
    }

    fn parse_member(&self, r: &mut Reader<'_>) -> Result<Member> {
        let access = r.u16()?;
        let name = self.utf8(r.u16()?).unwrap_or("<invalid>").to_string();
        let descriptor = self.utf8(r.u16()?).unwrap_or("<invalid>").to_string();
        let mut m = Member { access, name, descriptor, signature: None, code: None, constant_value: None };
        let n = r.u16()?;
        for _ in 0..n {
            let attr_name = r.u16()?;
            let len = r.u32()? as usize;
            let body = r.bytes(len)?;
            match self.utf8(attr_name) {
                Some("Code") => m.code = Some(self.parse_code(body)?),
                Some("Signature") if len >= 2 => {
                    m.signature = self.utf8(u16::from_be_bytes([body[0], body[1]])).map(str::to_string);
                }
                Some("ConstantValue") if len >= 2 => m.constant_value = Some(u16::from_be_bytes([body[0], body[1]])),
                _ => {}
            }
        }
        Ok(m)
    }

    fn parse_code(&self, body: &[u8]) -> Result<Code> {
        let mut r = Reader::new(body);
        let max_stack = r.u16()?;
        let max_locals = r.u16()?;
        let len = r.u32()? as usize;
        let bytecode = r.bytes(len)?.to_vec();
        let n = r.u16()?;
        let mut exceptions = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let start_pc = r.u16()?;
            let end_pc = r.u16()?;
            let handler_pc = r.u16()?;
            let ct = r.u16()?;
            exceptions.push(ExceptionEntry { start_pc, end_pc, handler_pc, catch_type: self.class_name(ct).map(str::to_string) });
        }
        let mut line_numbers = Vec::new();
        let n = r.u16()?;
        for _ in 0..n {
            let name = r.u16()?;
            let len = r.u32()? as usize;
            let attr = r.bytes(len)?;
            if self.utf8(name) == Some("LineNumberTable") {
                let mut lr = Reader::new(attr);
                let count = lr.u16()?;
                for _ in 0..count {
                    line_numbers.push((lr.u16()?, lr.u16()?));
                }
            }
        }
        line_numbers.sort_unstable();
        Ok(Code { max_stack, max_locals, bytecode, exceptions, line_numbers })
    }

    pub fn constant(&self, index: u16) -> Option<&Constant> {
        self.constants.get(index as usize)
    }

    pub fn utf8(&self, index: u16) -> Option<&str> {
        match self.constant(index)? {
            Constant::Utf8(s) => Some(s),
            _ => None,
        }
    }

    /// Internal name of a `Class` constant.
    pub fn class_name(&self, index: u16) -> Option<&str> {
        match self.constant(index)? {
            Constant::Class { name } => self.utf8(*name),
            _ => None,
        }
    }

    pub fn name_and_type(&self, index: u16) -> Option<(&str, &str)> {
        match self.constant(index)? {
            Constant::NameAndType { name, descriptor } => Some((self.utf8(*name)?, self.utf8(*descriptor)?)),
            _ => None,
        }
    }

    /// Resolve a `FieldRef` / `MethodRef` / `InterfaceMethodRef`.
    pub fn member_ref(&self, index: u16) -> Option<MemberRef> {
        let (class, nat) = match self.constant(index)? {
            Constant::FieldRef { class, name_and_type }
            | Constant::MethodRef { class, name_and_type }
            | Constant::InterfaceMethodRef { class, name_and_type } => (*class, *name_and_type),
            _ => return None,
        };
        let (name, descriptor) = self.name_and_type(nat)?;
        Some(MemberRef { owner: self.class_name(class)?.to_string(), name: name.to_string(), descriptor: descriptor.to_string() })
    }

    /// Value of a `String` constant.
    pub fn string(&self, index: u16) -> Option<&str> {
        match self.constant(index)? {
            Constant::String { utf8 } => self.utf8(*utf8),
            _ => None,
        }
    }

    /// Human-readable rendering of a constant, as used by `disasm`.
    pub fn display_constant(&self, index: u16) -> String {
        let Some(c) = self.constant(index) else { return format!("<bad #{index}>") };
        match c {
            Constant::Unusable => "<unusable>".into(),
            Constant::Utf8(s) => quote(s),
            Constant::Integer(v) => v.to_string(),
            Constant::Float(v) => format!("{v}f"),
            Constant::Long(v) => format!("{v}L"),
            Constant::Double(v) => format!("{v}d"),
            Constant::Class { .. } => self.class_name(index).unwrap_or("?").to_string(),
            Constant::String { .. } => quote(self.string(index).unwrap_or("?")),
            Constant::FieldRef { .. } | Constant::MethodRef { .. } | Constant::InterfaceMethodRef { .. } => match self.member_ref(index) {
                Some(m) => format!("{}.{}:{}", m.owner, m.name, m.descriptor),
                None => "?".into(),
            },
            Constant::NameAndType { .. } => match self.name_and_type(index) {
                Some((n, d)) => format!("{n}:{d}"),
                None => "?".into(),
            },
            Constant::MethodHandle { kind, reference } => format!("MethodHandle[{}] {}", kind, self.display_constant(*reference)),
            Constant::MethodType { descriptor } => format!("MethodType {}", self.utf8(*descriptor).unwrap_or("?")),
            Constant::Dynamic { bootstrap, name_and_type } | Constant::InvokeDynamic { bootstrap, name_and_type } => {
                match self.name_and_type(*name_and_type) {
                    Some((n, d)) => format!("#{bootstrap}:{n}:{d}"),
                    None => "?".into(),
                }
            }
            Constant::Module { name } | Constant::Package { name } => self.utf8(*name).unwrap_or("?").to_string(),
        }
    }

    pub fn is_interface(&self) -> bool {
        self.access & ACC_INTERFACE != 0
    }

    /// Dotted class name (`a.b.C`).
    pub fn dotted_name(&self) -> String {
        self.name.replace('/', ".")
    }

    /// Java version name for `major_version` (52 → "Java 8").
    pub fn java_version(&self) -> String {
        match self.major_version {
            45 => "Java 1.1".into(),
            46..=48 => format!("Java 1.{}", self.major_version - 44),
            v @ 49.. => format!("Java {}", v - 44),
            v => format!("major {v}"),
        }
    }
}

fn parse_constants(r: &mut Reader<'_>) -> Result<Vec<Constant>> {
    let count = r.u16()?;
    let mut pool = Vec::with_capacity(count as usize);
    pool.push(Constant::Unusable);
    let mut i = 1u16;
    while i < count {
        let tag = r.u8()?;
        let c = match tag {
            1 => {
                let len = r.u16()? as usize;
                Constant::Utf8(decode_modified_utf8(r.bytes(len)?))
            }
            3 => Constant::Integer(r.u32()? as i32),
            4 => Constant::Float(f32::from_bits(r.u32()?)),
            5 => Constant::Long(r.u64()? as i64),
            6 => Constant::Double(f64::from_bits(r.u64()?)),
            7 => Constant::Class { name: r.u16()? },
            8 => Constant::String { utf8: r.u16()? },
            9 => Constant::FieldRef { class: r.u16()?, name_and_type: r.u16()? },
            10 => Constant::MethodRef { class: r.u16()?, name_and_type: r.u16()? },
            11 => Constant::InterfaceMethodRef { class: r.u16()?, name_and_type: r.u16()? },
            12 => Constant::NameAndType { name: r.u16()?, descriptor: r.u16()? },
            15 => Constant::MethodHandle { kind: r.u8()?, reference: r.u16()? },
            16 => Constant::MethodType { descriptor: r.u16()? },
            17 => Constant::Dynamic { bootstrap: r.u16()?, name_and_type: r.u16()? },
            18 => Constant::InvokeDynamic { bootstrap: r.u16()?, name_and_type: r.u16()? },
            19 => Constant::Module { name: r.u16()? },
            20 => Constant::Package { name: r.u16()? },
            _ => return Err(JvmError::BadConstantTag { tag, index: i }),
        };
        let wide = matches!(c, Constant::Long(_) | Constant::Double(_));
        pool.push(c);
        i += 1;
        if wide {
            pool.push(Constant::Unusable);
            i += 1;
        }
    }
    Ok(pool)
}

/// Decode the JVM's "modified UTF-8" (`0xC0 0x80` for NUL, surrogate
/// pairs encoded as two 3-byte sequences). Malformed bytes become
/// U+FFFD rather than failing the whole class.
pub fn decode_modified_utf8(bytes: &[u8]) -> String {
    if bytes.is_ascii() {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            units.push(b as u16);
            i += 1;
        } else if b & 0xE0 == 0xC0 && i + 1 < bytes.len() {
            units.push((((b & 0x1F) as u16) << 6) | (bytes[i + 1] & 0x3F) as u16);
            i += 2;
        } else if b & 0xF0 == 0xE0 && i + 2 < bytes.len() {
            units.push((((b & 0x0F) as u16) << 12) | (((bytes[i + 1] & 0x3F) as u16) << 6) | (bytes[i + 2] & 0x3F) as u16);
            i += 3;
        } else {
            units.push(0xFFFD);
            i += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

/// Java-style quoted string literal with control characters escaped.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `public static final` style keyword list for class / member flags.
pub fn access_keywords(access: u16, kind: MemberKind) -> String {
    let mut words: Vec<&str> = Vec::new();
    if access & ACC_PUBLIC != 0 {
        words.push("public");
    }
    if access & ACC_PRIVATE != 0 {
        words.push("private");
    }
    if access & ACC_PROTECTED != 0 {
        words.push("protected");
    }
    if access & ACC_STATIC != 0 && kind != MemberKind::Class {
        words.push("static");
    }
    if access & ACC_FINAL != 0 {
        words.push("final");
    }
    match kind {
        MemberKind::Method => {
            if access & ACC_SYNCHRONIZED != 0 {
                words.push("synchronized");
            }
            if access & ACC_NATIVE != 0 {
                words.push("native");
            }
            if access & ACC_ABSTRACT != 0 {
                words.push("abstract");
            }
            if access & ACC_BRIDGE != 0 {
                words.push("bridge");
            }
        }
        MemberKind::Field => {
            if access & ACC_VOLATILE != 0 {
                words.push("volatile");
            }
            if access & ACC_TRANSIENT != 0 {
                words.push("transient");
            }
        }
        MemberKind::Class => {
            if access & ACC_ABSTRACT != 0 && access & ACC_INTERFACE == 0 {
                words.push("abstract");
            }
        }
    }
    if access & ACC_SYNTHETIC != 0 {
        words.push("synthetic");
    }
    words.join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    Class,
    Field,
    Method,
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Hand-assembled class files for tests.

    /// Builds a class file byte by byte. Constant indices are returned
    /// by the `add_*` helpers.
    pub struct ClassBuilder {
        pool: Vec<Vec<u8>>,
        methods: Vec<Vec<u8>>,
        fields: Vec<Vec<u8>>,
        pub name: String,
        pub super_name: String,
    }

    impl ClassBuilder {
        pub fn new(name: &str, super_name: &str) -> Self {
            Self { pool: Vec::new(), methods: Vec::new(), fields: Vec::new(), name: name.into(), super_name: super_name.into() }
        }

        fn push(&mut self, entry: Vec<u8>) -> u16 {
            if let Some(i) = self.pool.iter().position(|e| *e == entry) {
                return i as u16 + 1;
            }
            self.pool.push(entry);
            self.pool.len() as u16
        }

        pub fn utf8(&mut self, s: &str) -> u16 {
            let mut e = vec![1];
            e.extend_from_slice(&(s.len() as u16).to_be_bytes());
            e.extend_from_slice(s.as_bytes());
            self.push(e)
        }

        pub fn class(&mut self, name: &str) -> u16 {
            let n = self.utf8(name);
            let mut e = vec![7];
            e.extend_from_slice(&n.to_be_bytes());
            self.push(e)
        }

        pub fn string(&mut self, s: &str) -> u16 {
            let n = self.utf8(s);
            let mut e = vec![8];
            e.extend_from_slice(&n.to_be_bytes());
            self.push(e)
        }

        fn nat(&mut self, name: &str, desc: &str) -> u16 {
            let n = self.utf8(name);
            let d = self.utf8(desc);
            let mut e = vec![12];
            e.extend_from_slice(&n.to_be_bytes());
            e.extend_from_slice(&d.to_be_bytes());
            self.push(e)
        }

        fn member(&mut self, tag: u8, owner: &str, name: &str, desc: &str) -> u16 {
            let c = self.class(owner);
            let nt = self.nat(name, desc);
            let mut e = vec![tag];
            e.extend_from_slice(&c.to_be_bytes());
            e.extend_from_slice(&nt.to_be_bytes());
            self.push(e)
        }

        pub fn method_ref(&mut self, owner: &str, name: &str, desc: &str) -> u16 {
            self.member(10, owner, name, desc)
        }

        pub fn field_ref(&mut self, owner: &str, name: &str, desc: &str) -> u16 {
            self.member(9, owner, name, desc)
        }

        pub fn add_field(&mut self, access: u16, name: &str, desc: &str) {
            let n = self.utf8(name);
            let d = self.utf8(desc);
            let mut m = Vec::new();
            m.extend_from_slice(&access.to_be_bytes());
            m.extend_from_slice(&n.to_be_bytes());
            m.extend_from_slice(&d.to_be_bytes());
            m.extend_from_slice(&0u16.to_be_bytes());
            self.fields.push(m);
        }

        /// Adds a method with a `Code` attribute (and a one-entry
        /// `LineNumberTable` mapping pc 0 to `line`).
        pub fn add_method(&mut self, access: u16, name: &str, desc: &str, code: &[u8], line: u16) {
            let n = self.utf8(name);
            let d = self.utf8(desc);
            let code_name = self.utf8("Code");
            let lnt = self.utf8("LineNumberTable");
            let mut lnt_attr = Vec::new();
            lnt_attr.extend_from_slice(&lnt.to_be_bytes());
            lnt_attr.extend_from_slice(&6u32.to_be_bytes());
            lnt_attr.extend_from_slice(&1u16.to_be_bytes());
            lnt_attr.extend_from_slice(&0u16.to_be_bytes());
            lnt_attr.extend_from_slice(&line.to_be_bytes());
            let mut body = Vec::new();
            body.extend_from_slice(&4u16.to_be_bytes());
            body.extend_from_slice(&4u16.to_be_bytes());
            body.extend_from_slice(&(code.len() as u32).to_be_bytes());
            body.extend_from_slice(code);
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&lnt_attr);
            let mut m = Vec::new();
            m.extend_from_slice(&access.to_be_bytes());
            m.extend_from_slice(&n.to_be_bytes());
            m.extend_from_slice(&d.to_be_bytes());
            m.extend_from_slice(&1u16.to_be_bytes());
            m.extend_from_slice(&code_name.to_be_bytes());
            m.extend_from_slice(&(body.len() as u32).to_be_bytes());
            m.extend_from_slice(&body);
            self.methods.push(m);
        }

        pub fn build(mut self) -> Vec<u8> {
            let name = self.name.clone();
            let sup = self.super_name.clone();
            let this_idx = self.class(&name);
            let super_idx = self.class(&sup);
            let mut out = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
            out.extend_from_slice(&(self.pool.len() as u16 + 1).to_be_bytes());
            for e in &self.pool {
                out.extend_from_slice(e);
            }
            out.extend_from_slice(&0x0021u16.to_be_bytes());
            out.extend_from_slice(&this_idx.to_be_bytes());
            out.extend_from_slice(&super_idx.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&(self.fields.len() as u16).to_be_bytes());
            for f in &self.fields {
                out.extend_from_slice(f);
            }
            out.extend_from_slice(&(self.methods.len() as u16).to_be_bytes());
            for m in &self.methods {
                out.extend_from_slice(m);
            }
            out.extend_from_slice(&0u16.to_be_bytes());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::ClassBuilder;
    use super::*;

    #[test]
    fn parses_hand_built_class() {
        let mut b = ClassBuilder::new("com/example/Foo", "java/lang/Object");
        let s = b.string("hello");
        let m = b.method_ref("com/example/Bar", "run", "(Ljava/lang/String;)V");
        b.add_field(ACC_PRIVATE, "count", "I");
        let code = [0x12, s as u8, 0xb8, (m >> 8) as u8, m as u8, 0xb1];
        b.add_method(ACC_PUBLIC | ACC_STATIC, "go", "()V", &code, 42);
        let cf = ClassFile::parse(&b.build()).unwrap();
        assert_eq!(cf.name, "com/example/Foo");
        assert_eq!(cf.super_name.as_deref(), Some("java/lang/Object"));
        assert_eq!(cf.java_version(), "Java 8");
        assert_eq!(cf.fields[0].name, "count");
        let go = &cf.methods[0];
        assert_eq!((go.name.as_str(), go.descriptor.as_str()), ("go", "()V"));
        let code = go.code.as_ref().unwrap();
        assert_eq!(code.bytecode.len(), 6);
        assert_eq!(code.line_at(3), Some(42));
        assert_eq!(cf.string(s), Some("hello"));
        let r = cf.member_ref(m).unwrap();
        assert_eq!((r.owner.as_str(), r.name.as_str()), ("com/example/Bar", "run"));
    }

    #[test]
    fn long_constants_take_two_slots() {
        // count=4: #1 Long, #2 unusable, #3 Utf8 "x"
        let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 61, 0, 4, 5, 0, 0, 0, 0, 0, 0, 0, 7, 1, 0, 1, b'x'];
        data.extend_from_slice(&[0, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let cf = ClassFile::parse(&data).unwrap();
        assert_eq!(cf.constants[1], Constant::Long(7));
        assert_eq!(cf.constants[2], Constant::Unusable);
        assert_eq!(cf.utf8(3), Some("x"));
    }

    #[test]
    fn modified_utf8_decodes_nul_and_japanese() {
        // "a\0あ": 'a', C0 80, E3 81 82
        assert_eq!(decode_modified_utf8(&[0x61, 0xC0, 0x80, 0xE3, 0x81, 0x82]), "a\0あ");
        // U+1F600 as a surrogate pair of 3-byte sequences
        assert_eq!(decode_modified_utf8(&[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]), "😀");
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(matches!(ClassFile::parse(&[0, 1, 2, 3, 0, 0, 0, 0]), Err(JvmError::BadMagic(0x00010203))));
    }
}
