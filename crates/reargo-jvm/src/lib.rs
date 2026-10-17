//! Java bytecode support for RE-Argo.
//!
//! JVM code has no native address space, so this crate stays outside
//! the `BinaryInfo` / `Program` pipeline: it parses class files
//! ([`classfile`]), decodes their bytecode ([`bytecode`]), reads JAR
//! archives ([`jar`]) and answers cross-class questions — who calls a
//! method, who uses a string, what a method calls — over a whole
//! class path ([`index`]).

pub mod bytecode;
pub mod classfile;
pub mod descriptor;
pub mod index;
pub mod jar;

pub use bytecode::{Insn, Operand};
pub use classfile::{ClassFile, Code, Constant, Member, MemberRef};
pub use index::{ClassPath, Reference, Site};
pub use jar::Jar;

/// Errors raised while reading class files or JAR archives.
#[derive(Debug, thiserror::Error)]
pub enum JvmError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("truncated data at offset {0}")]
    Truncated(usize),
    #[error("not a class file (magic 0x{0:08x})")]
    BadMagic(u32),
    #[error("unknown constant-pool tag {tag} at index {index}")]
    BadConstantTag { tag: u8, index: u16 },
    #[error("unknown opcode 0x{opcode:02x} at pc {pc}")]
    BadOpcode { opcode: u8, pc: u32 },
    #[error("invalid ZIP archive: {0}")]
    Zip(String),
    #[error("not a class file or JAR: {0}")]
    UnknownInput(String),
    #[error("{0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, JvmError>;

/// Big-endian cursor over a byte slice.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.data.len()).ok_or(JvmError::Truncated(self.pos))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(((self.u32()? as u64) << 32) | self.u32()? as u64)
    }
}
