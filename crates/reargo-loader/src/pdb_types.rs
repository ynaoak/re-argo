// PDB type record definitions (TPI stream).

#[derive(Debug, Clone)]
pub enum PdbTypeRecord {
    Pointer { pointee_type_index: u32, size: u32 },
    Modifier { modified_type: u32, is_const: bool, is_volatile: bool },
    Procedure { return_type: u32, param_count: u16, arg_list: u32 },
    ArgList { args: Vec<u32> },
    Array { element_type: u32, index_type: u32, size: u64 },
    Structure { name: String, size: u64, field_list: u32, num_fields: u16 },
    Union { name: String, size: u64, field_list: u32 },
    Enum { name: String, underlying_type: u32, field_list: u32 },
    BitField { base_type: u32, length: u8, position: u8 },
    FieldList { members: Vec<PdbFieldEntry> },
    BaseClass { base_type: u32, offset: u32 },
    Unknown { leaf_type: u16, data: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct PdbFieldEntry {
    pub name: String,
    pub type_index: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub enum PdbSymbolRecord {
    GlobalProc { name: String, offset: u32, segment: u16, type_index: u32, length: u32 },
    LocalProc { name: String, offset: u32, segment: u16, type_index: u32, length: u32 },
    GlobalData { name: String, offset: u32, segment: u16, type_index: u32 },
    LocalData { name: String, offset: u32, segment: u16, type_index: u32 },
    PublicSymbol { name: String, offset: u32, segment: u16 },
    Constant { name: String, type_index: u32, value: u64 },
    Udt { name: String, type_index: u32 },
    Unknown { record_type: u16 },
}

pub const LF_POINTER: u16 = 0x1002;
pub const LF_MODIFIER: u16 = 0x1001;
pub const LF_PROCEDURE: u16 = 0x1008;
pub const LF_ARGLIST: u16 = 0x1201;
pub const LF_ARRAY: u16 = 0x1503;
pub const LF_STRUCTURE: u16 = 0x1505;
pub const LF_UNION: u16 = 0x1506;
pub const LF_ENUM: u16 = 0x1507;
pub const LF_BITFIELD: u16 = 0x1205;
pub const LF_FIELDLIST: u16 = 0x1203;

pub const S_GPROC32: u16 = 0x1110;
pub const S_LPROC32: u16 = 0x1111;
pub const S_GDATA32: u16 = 0x110D;
pub const S_LDATA32: u16 = 0x110C;
pub const S_PUB32: u16 = 0x110E;
pub const S_CONSTANT: u16 = 0x1107;
pub const S_UDT: u16 = 0x1108;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_record_variants() {
        let ptr = PdbTypeRecord::Pointer { pointee_type_index: 0x1000, size: 8 };
        assert!(matches!(ptr, PdbTypeRecord::Pointer { .. }));

        let struc = PdbTypeRecord::Structure {
            name: "MyStruct".into(), size: 16, field_list: 0x2000, num_fields: 3
        };
        assert!(matches!(struc, PdbTypeRecord::Structure { .. }));
    }

    #[test]
    fn symbol_record_variants() {
        let proc = PdbSymbolRecord::GlobalProc {
            name: "main".into(), offset: 0x1000, segment: 1, type_index: 0x1000, length: 100
        };
        assert!(matches!(proc, PdbSymbolRecord::GlobalProc { .. }));
    }

    #[test]
    fn leaf_type_constants() {
        assert_eq!(LF_STRUCTURE, 0x1505);
        assert_eq!(S_GPROC32, 0x1110);
    }
}
