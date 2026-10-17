//! JVM bytecode decoder (JVMS chapter 6).

use crate::classfile::{ClassFile, quote};
use crate::{JvmError, Reader, Result};

/// Mnemonics for opcodes `0x00..=0xc9`.
const MNEMONICS: [&str; 202] = [
    // 0x00
    "nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4",
    "iconst_5", "lconst_0", "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0", "dconst_1",
    // 0x10
    "bipush", "sipush", "ldc", "ldc_w", "ldc2_w", "iload", "lload", "fload",
    "dload", "aload", "iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1",
    // 0x20
    "lload_2", "lload_3", "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1",
    "dload_2", "dload_3", "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "laload",
    // 0x30
    "faload", "daload", "aaload", "baload", "caload", "saload", "istore", "lstore",
    "fstore", "dstore", "astore", "istore_0", "istore_1", "istore_2", "istore_3", "lstore_0",
    // 0x40
    "lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1", "fstore_2", "fstore_3", "dstore_0",
    "dstore_1", "dstore_2", "dstore_3", "astore_0", "astore_1", "astore_2", "astore_3", "iastore",
    // 0x50
    "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore", "pop",
    "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap",
    // 0x60
    "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub",
    "imul", "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv",
    // 0x70
    "irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg",
    "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land",
    // 0x80
    "ior", "lor", "ixor", "lxor", "iinc", "i2l", "i2f", "i2d",
    "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l",
    // 0x90
    "d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl", "fcmpg", "dcmpl",
    "dcmpg", "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq",
    // 0xa0
    "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto",
    "jsr", "ret", "tableswitch", "lookupswitch", "ireturn", "lreturn", "freturn", "dreturn",
    // 0xb0
    "areturn", "return", "getstatic", "putstatic", "getfield", "putfield", "invokevirtual", "invokespecial",
    "invokestatic", "invokeinterface", "invokedynamic", "new", "newarray", "anewarray", "arraylength", "athrow",
    // 0xc0
    "checkcast", "instanceof", "monitorenter", "monitorexit", "wide", "multianewarray", "ifnull", "ifnonnull",
    "goto_w", "jsr_w",
];

pub const LDC: u8 = 0x12;
pub const LDC_W: u8 = 0x13;
pub const LDC2_W: u8 = 0x14;
pub const GETSTATIC: u8 = 0xb2;
pub const PUTSTATIC: u8 = 0xb3;
pub const GETFIELD: u8 = 0xb4;
pub const PUTFIELD: u8 = 0xb5;
pub const INVOKEVIRTUAL: u8 = 0xb6;
pub const INVOKESPECIAL: u8 = 0xb7;
pub const INVOKESTATIC: u8 = 0xb8;
pub const INVOKEINTERFACE: u8 = 0xb9;
pub const INVOKEDYNAMIC: u8 = 0xba;
pub const NEW: u8 = 0xbb;
pub const ANEWARRAY: u8 = 0xbd;
pub const CHECKCAST: u8 = 0xc0;
pub const INSTANCEOF: u8 = 0xc1;
pub const MULTIANEWARRAY: u8 = 0xc5;

pub fn mnemonic(opcode: u8) -> &'static str {
    MNEMONICS.get(opcode as usize).copied().unwrap_or("<unknown>")
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    None,
    /// `bipush` / `sipush` immediate.
    Int(i32),
    /// Local-variable slot (`iload`, `astore`, `ret`, …).
    Local(u16),
    /// Constant-pool index (`ldc`, field / method / class operands).
    Cp(u16),
    Iinc { index: u16, delta: i16 },
    /// Absolute branch target pc.
    Branch(u32),
    TableSwitch { default: u32, low: i32, targets: Vec<u32> },
    LookupSwitch { default: u32, pairs: Vec<(i32, u32)> },
    /// `invokeinterface` (the count byte is redundant with the descriptor).
    InvokeInterface { cp: u16, count: u8 },
    MultiANewArray { cp: u16, dims: u8 },
    /// `newarray` primitive type code.
    NewArray(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Insn {
    pub pc: u32,
    pub opcode: u8,
    /// Prefixed by `wide`.
    pub wide: bool,
    pub operand: Operand,
}

impl Insn {
    pub fn mnemonic(&self) -> &'static str {
        mnemonic(self.opcode)
    }

    /// Constant-pool index this instruction refers to, if any.
    pub fn cp_index(&self) -> Option<u16> {
        match self.operand {
            Operand::Cp(i) | Operand::InvokeInterface { cp: i, .. } | Operand::MultiANewArray { cp: i, .. } => Some(i),
            _ => None,
        }
    }

    /// Branch targets (including switch arms) for control-flow use.
    pub fn branch_targets(&self) -> Vec<u32> {
        match &self.operand {
            Operand::Branch(t) => vec![*t],
            Operand::TableSwitch { default, targets, .. } => std::iter::once(*default).chain(targets.iter().copied()).collect(),
            Operand::LookupSwitch { default, pairs } => std::iter::once(*default).chain(pairs.iter().map(|p| p.1)).collect(),
            _ => Vec::new(),
        }
    }

    /// Render operands, resolving constant-pool references against `cf`.
    pub fn operand_text(&self, cf: &ClassFile) -> String {
        match &self.operand {
            Operand::None => String::new(),
            Operand::Int(v) => v.to_string(),
            Operand::Local(i) => i.to_string(),
            Operand::Cp(i) => format!("#{i} {}", cf.display_constant(*i)),
            Operand::Iinc { index, delta } => format!("{index}, {delta}"),
            Operand::Branch(t) => t.to_string(),
            Operand::TableSwitch { default, low, targets } => {
                let arms: Vec<String> = targets.iter().enumerate().map(|(k, t)| format!("{}: {t}", *low as i64 + k as i64)).collect();
                format!("{{ {}, default: {default} }}", arms.join(", "))
            }
            Operand::LookupSwitch { default, pairs } => {
                let arms: Vec<String> = pairs.iter().map(|(k, t)| format!("{k}: {t}")).collect();
                format!("{{ {}, default: {default} }}", arms.join(", "))
            }
            Operand::InvokeInterface { cp, count } => format!("#{cp} {}, {count}", cf.display_constant(*cp)),
            Operand::MultiANewArray { cp, dims } => format!("#{cp} {}, {dims}", cf.display_constant(*cp)),
            Operand::NewArray(t) => match t {
                4 => "boolean", 5 => "char", 6 => "float", 7 => "double",
                8 => "byte", 9 => "short", 10 => "int", 11 => "long",
                _ => "?",
            }
            .to_string(),
        }
    }
}

fn target(pc: u32, offset: i32) -> u32 {
    (pc as i64 + offset as i64).max(0) as u32
}

/// Decode a whole `Code` array.
pub fn decode(code: &[u8]) -> Result<Vec<Insn>> {
    let mut r = Reader::new(code);
    let mut out = Vec::with_capacity(code.len() / 2);
    while r.pos() < code.len() {
        let pc = r.pos() as u32;
        let mut opcode = r.u8()?;
        let mut wide = false;
        if opcode == 0xc4 {
            wide = true;
            opcode = r.u8()?;
        }
        let operand = match opcode {
            0x10 => Operand::Int(r.u8()? as i8 as i32),
            0x11 => Operand::Int(r.u16()? as i16 as i32),
            LDC => Operand::Cp(r.u8()? as u16),
            LDC_W | LDC2_W => Operand::Cp(r.u16()?),
            0x15..=0x19 | 0x36..=0x3a | 0xa9 => Operand::Local(if wide { r.u16()? } else { r.u8()? as u16 }),
            0x84 => {
                if wide {
                    Operand::Iinc { index: r.u16()?, delta: r.u16()? as i16 }
                } else {
                    Operand::Iinc { index: r.u8()? as u16, delta: r.u8()? as i8 as i16 }
                }
            }
            0x99..=0xa8 | 0xc6 | 0xc7 => Operand::Branch(target(pc, r.u16()? as i16 as i32)),
            0xc8 | 0xc9 => Operand::Branch(target(pc, r.u32()? as i32)),
            0xaa | 0xab => {
                // Operands start at the next 4-byte boundary from code start.
                let pad = (4 - (r.pos() % 4)) % 4;
                r.bytes(pad)?;
                let default = target(pc, r.u32()? as i32);
                if opcode == 0xaa {
                    let low = r.u32()? as i32;
                    let high = r.u32()? as i32;
                    let n = (high as i64 - low as i64 + 1).clamp(0, 1 << 16) as usize;
                    let mut targets = Vec::with_capacity(n);
                    for _ in 0..n {
                        targets.push(target(pc, r.u32()? as i32));
                    }
                    Operand::TableSwitch { default, low, targets }
                } else {
                    let n = (r.u32()? as usize).min(1 << 16);
                    let mut pairs = Vec::with_capacity(n);
                    for _ in 0..n {
                        let key = r.u32()? as i32;
                        pairs.push((key, target(pc, r.u32()? as i32)));
                    }
                    Operand::LookupSwitch { default, pairs }
                }
            }
            GETSTATIC..=INVOKESTATIC | NEW | ANEWARRAY | CHECKCAST | INSTANCEOF => Operand::Cp(r.u16()?),
            INVOKEINTERFACE => {
                let cp = r.u16()?;
                let count = r.u8()?;
                r.u8()?;
                Operand::InvokeInterface { cp, count }
            }
            INVOKEDYNAMIC => {
                let cp = r.u16()?;
                r.u16()?;
                Operand::Cp(cp)
            }
            0xbc => Operand::NewArray(r.u8()?),
            MULTIANEWARRAY => Operand::MultiANewArray { cp: r.u16()?, dims: r.u8()? },
            0x00..=0xc9 => Operand::None,
            _ => return Err(JvmError::BadOpcode { opcode, pc }),
        };
        out.push(Insn { pc, opcode, wide, operand });
    }
    Ok(out)
}

/// One line of disassembly, `javap -c` style: `pc: mnemonic operands`.
pub fn format_insn(insn: &Insn, cf: &ClassFile) -> String {
    let ops = insn.operand_text(cf);
    let name = if insn.wide { format!("wide {}", insn.mnemonic()) } else { insn.mnemonic().to_string() };
    if ops.is_empty() { format!("{:>6}: {}", insn.pc, name) } else { format!("{:>6}: {:<16}{}", insn.pc, name, ops) }
}

/// Convenience: the string literal pushed by an `ldc*`, if any.
pub fn ldc_string<'a>(insn: &Insn, cf: &'a ClassFile) -> Option<&'a str> {
    match insn.opcode {
        LDC | LDC_W => cf.string(insn.cp_index()?),
        _ => None,
    }
}

/// Quoted form of an `ldc` string (for listings).
pub fn ldc_display(insn: &Insn, cf: &ClassFile) -> Option<String> {
    ldc_string(insn, cf).map(quote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_table_lines_up() {
        assert_eq!(mnemonic(0x00), "nop");
        assert_eq!(mnemonic(0x2a), "aload_0");
        assert_eq!(mnemonic(0x4b), "astore_0");
        assert_eq!(mnemonic(0x84), "iinc");
        assert_eq!(mnemonic(0xa7), "goto");
        assert_eq!(mnemonic(0xb1), "return");
        assert_eq!(mnemonic(0xb6), "invokevirtual");
        assert_eq!(mnemonic(0xbb), "new");
        assert_eq!(mnemonic(0xc9), "jsr_w");
        assert_eq!(mnemonic(0xca), "<unknown>");
    }

    #[test]
    fn decodes_branches_wide_and_iinc() {
        // 0: iload_0; 1: ifeq +5 -> 6; 4: iinc 1,-1; 7: wide iload 300; 11: goto -11 -> 0
        let code = [0x1a, 0x99, 0x00, 0x05, 0x84, 0x01, 0xff, 0xc4, 0x15, 0x01, 0x2c, 0xa7, 0xff, 0xf5];
        let insns = decode(&code).unwrap();
        assert_eq!(insns.len(), 5);
        assert_eq!(insns[1].operand, Operand::Branch(6));
        assert_eq!(insns[2].operand, Operand::Iinc { index: 1, delta: -1 });
        assert!(insns[3].wide);
        assert_eq!(insns[3].operand, Operand::Local(300));
        assert_eq!(insns[4].operand, Operand::Branch(0));
    }

    #[test]
    fn decodes_switch_padding() {
        // 0: iload_0; 1: tableswitch, pad 2 -> operands at 4
        let mut code = vec![0x1a, 0xaa, 0, 0];
        for v in [20i32, 0, 1, 10, 15] {
            // default=+20, low=0, high=1, targets +10, +15
            code.extend_from_slice(&v.to_be_bytes());
        }
        code.push(0xb1);
        let insns = decode(&code).unwrap();
        assert_eq!(insns[1].operand, Operand::TableSwitch { default: 21, low: 0, targets: vec![11, 16] });
        assert_eq!(insns[2].pc, 24);
        assert_eq!(insns[2].mnemonic(), "return");
    }

    #[test]
    fn rejects_unknown_opcode() {
        assert!(matches!(decode(&[0xfe]), Err(JvmError::BadOpcode { opcode: 0xfe, pc: 0 })));
    }
}
