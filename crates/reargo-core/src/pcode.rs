use std::fmt;

use smallvec::SmallVec;

use crate::address::{Address, SpaceId};

/// All P-code operation codes, matching Ghidra's opcodes.hh exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum OpCode {
    Copy = 1,
    Load = 2,
    Store = 3,

    Branch = 4,
    CBranch = 5,
    BranchInd = 6,

    Call = 7,
    CallInd = 8,
    CallOther = 9,
    Return = 10,

    IntEqual = 11,
    IntNotEqual = 12,
    IntSLess = 13,
    IntSLessEqual = 14,
    IntLess = 15,
    IntLessEqual = 16,
    IntZExt = 17,
    IntSExt = 18,
    IntAdd = 19,
    IntSub = 20,
    IntCarry = 21,
    IntSCarry = 22,
    IntSBorrow = 23,
    Int2Comp = 24,
    IntNegate = 25,
    IntXor = 26,
    IntAnd = 27,
    IntOr = 28,
    IntLeft = 29,
    IntRight = 30,
    IntSRight = 31,
    IntMult = 32,
    IntDiv = 33,
    IntSDiv = 34,
    IntRem = 35,
    IntSRem = 36,

    BoolNegate = 37,
    BoolXor = 38,
    BoolAnd = 39,
    BoolOr = 40,

    FloatEqual = 41,
    FloatNotEqual = 42,
    FloatLess = 43,
    FloatLessEqual = 44,
    // 45 is unused
    FloatNan = 46,

    FloatAdd = 47,
    FloatDiv = 48,
    FloatMult = 49,
    FloatSub = 50,
    FloatNeg = 51,
    FloatAbs = 52,
    FloatSqrt = 53,

    FloatInt2Float = 54,
    FloatFloat2Float = 55,
    FloatTrunc = 56,
    FloatCeil = 57,
    FloatFloor = 58,
    FloatRound = 59,

    MultiEqual = 60,
    Indirect = 61,
    Piece = 62,
    Subpiece = 63,

    Cast = 64,
    PtrAdd = 65,
    PtrSub = 66,
    SegmentOp = 67,
    CPoolRef = 68,
    New = 69,
    Insert = 70,
    ZPull = 71,
    PopCount = 72,
    LzCount = 73,
    SPull = 74,
}

impl OpCode {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Copy),
            2 => Some(Self::Load),
            3 => Some(Self::Store),
            4 => Some(Self::Branch),
            5 => Some(Self::CBranch),
            6 => Some(Self::BranchInd),
            7 => Some(Self::Call),
            8 => Some(Self::CallInd),
            9 => Some(Self::CallOther),
            10 => Some(Self::Return),
            11 => Some(Self::IntEqual),
            12 => Some(Self::IntNotEqual),
            13 => Some(Self::IntSLess),
            14 => Some(Self::IntSLessEqual),
            15 => Some(Self::IntLess),
            16 => Some(Self::IntLessEqual),
            17 => Some(Self::IntZExt),
            18 => Some(Self::IntSExt),
            19 => Some(Self::IntAdd),
            20 => Some(Self::IntSub),
            21 => Some(Self::IntCarry),
            22 => Some(Self::IntSCarry),
            23 => Some(Self::IntSBorrow),
            24 => Some(Self::Int2Comp),
            25 => Some(Self::IntNegate),
            26 => Some(Self::IntXor),
            27 => Some(Self::IntAnd),
            28 => Some(Self::IntOr),
            29 => Some(Self::IntLeft),
            30 => Some(Self::IntRight),
            31 => Some(Self::IntSRight),
            32 => Some(Self::IntMult),
            33 => Some(Self::IntDiv),
            34 => Some(Self::IntSDiv),
            35 => Some(Self::IntRem),
            36 => Some(Self::IntSRem),
            37 => Some(Self::BoolNegate),
            38 => Some(Self::BoolXor),
            39 => Some(Self::BoolAnd),
            40 => Some(Self::BoolOr),
            41 => Some(Self::FloatEqual),
            42 => Some(Self::FloatNotEqual),
            43 => Some(Self::FloatLess),
            44 => Some(Self::FloatLessEqual),
            46 => Some(Self::FloatNan),
            47 => Some(Self::FloatAdd),
            48 => Some(Self::FloatDiv),
            49 => Some(Self::FloatMult),
            50 => Some(Self::FloatSub),
            51 => Some(Self::FloatNeg),
            52 => Some(Self::FloatAbs),
            53 => Some(Self::FloatSqrt),
            54 => Some(Self::FloatInt2Float),
            55 => Some(Self::FloatFloat2Float),
            56 => Some(Self::FloatTrunc),
            57 => Some(Self::FloatCeil),
            58 => Some(Self::FloatFloor),
            59 => Some(Self::FloatRound),
            60 => Some(Self::MultiEqual),
            61 => Some(Self::Indirect),
            62 => Some(Self::Piece),
            63 => Some(Self::Subpiece),
            64 => Some(Self::Cast),
            65 => Some(Self::PtrAdd),
            66 => Some(Self::PtrSub),
            67 => Some(Self::SegmentOp),
            68 => Some(Self::CPoolRef),
            69 => Some(Self::New),
            70 => Some(Self::Insert),
            71 => Some(Self::ZPull),
            72 => Some(Self::PopCount),
            73 => Some(Self::LzCount),
            74 => Some(Self::SPull),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Copy => "COPY",
            Self::Load => "LOAD",
            Self::Store => "STORE",
            Self::Branch => "BRANCH",
            Self::CBranch => "CBRANCH",
            Self::BranchInd => "BRANCHIND",
            Self::Call => "CALL",
            Self::CallInd => "CALLIND",
            Self::CallOther => "CALLOTHER",
            Self::Return => "RETURN",
            Self::IntEqual => "INT_EQUAL",
            Self::IntNotEqual => "INT_NOTEQUAL",
            Self::IntSLess => "INT_SLESS",
            Self::IntSLessEqual => "INT_SLESSEQUAL",
            Self::IntLess => "INT_LESS",
            Self::IntLessEqual => "INT_LESSEQUAL",
            Self::IntZExt => "INT_ZEXT",
            Self::IntSExt => "INT_SEXT",
            Self::IntAdd => "INT_ADD",
            Self::IntSub => "INT_SUB",
            Self::IntCarry => "INT_CARRY",
            Self::IntSCarry => "INT_SCARRY",
            Self::IntSBorrow => "INT_SBORROW",
            Self::Int2Comp => "INT_2COMP",
            Self::IntNegate => "INT_NEGATE",
            Self::IntXor => "INT_XOR",
            Self::IntAnd => "INT_AND",
            Self::IntOr => "INT_OR",
            Self::IntLeft => "INT_LEFT",
            Self::IntRight => "INT_RIGHT",
            Self::IntSRight => "INT_SRIGHT",
            Self::IntMult => "INT_MULT",
            Self::IntDiv => "INT_DIV",
            Self::IntSDiv => "INT_SDIV",
            Self::IntRem => "INT_REM",
            Self::IntSRem => "INT_SREM",
            Self::BoolNegate => "BOOL_NEGATE",
            Self::BoolXor => "BOOL_XOR",
            Self::BoolAnd => "BOOL_AND",
            Self::BoolOr => "BOOL_OR",
            Self::FloatEqual => "FLOAT_EQUAL",
            Self::FloatNotEqual => "FLOAT_NOTEQUAL",
            Self::FloatLess => "FLOAT_LESS",
            Self::FloatLessEqual => "FLOAT_LESSEQUAL",
            Self::FloatNan => "FLOAT_NAN",
            Self::FloatAdd => "FLOAT_ADD",
            Self::FloatDiv => "FLOAT_DIV",
            Self::FloatMult => "FLOAT_MULT",
            Self::FloatSub => "FLOAT_SUB",
            Self::FloatNeg => "FLOAT_NEG",
            Self::FloatAbs => "FLOAT_ABS",
            Self::FloatSqrt => "FLOAT_SQRT",
            Self::FloatInt2Float => "FLOAT_INT2FLOAT",
            Self::FloatFloat2Float => "FLOAT_FLOAT2FLOAT",
            Self::FloatTrunc => "FLOAT_TRUNC",
            Self::FloatCeil => "FLOAT_CEIL",
            Self::FloatFloor => "FLOAT_FLOOR",
            Self::FloatRound => "FLOAT_ROUND",
            Self::MultiEqual => "MULTIEQUAL",
            Self::Indirect => "INDIRECT",
            Self::Piece => "PIECE",
            Self::Subpiece => "SUBPIECE",
            Self::Cast => "CAST",
            Self::PtrAdd => "PTRADD",
            Self::PtrSub => "PTRSUB",
            Self::SegmentOp => "SEGMENTOP",
            Self::CPoolRef => "CPOOLREF",
            Self::New => "NEW",
            Self::Insert => "INSERT",
            Self::ZPull => "ZPULL",
            Self::PopCount => "POPCOUNT",
            Self::LzCount => "LZCOUNT",
            Self::SPull => "SPULL",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "COPY" => Some(Self::Copy),
            "LOAD" => Some(Self::Load),
            "STORE" => Some(Self::Store),
            "BRANCH" => Some(Self::Branch),
            "CBRANCH" => Some(Self::CBranch),
            "BRANCHIND" => Some(Self::BranchInd),
            "CALL" => Some(Self::Call),
            "CALLIND" => Some(Self::CallInd),
            "CALLOTHER" => Some(Self::CallOther),
            "RETURN" => Some(Self::Return),
            "INT_EQUAL" => Some(Self::IntEqual),
            "INT_NOTEQUAL" => Some(Self::IntNotEqual),
            "INT_SLESS" => Some(Self::IntSLess),
            "INT_SLESSEQUAL" => Some(Self::IntSLessEqual),
            "INT_LESS" => Some(Self::IntLess),
            "INT_LESSEQUAL" => Some(Self::IntLessEqual),
            "INT_ZEXT" => Some(Self::IntZExt),
            "INT_SEXT" => Some(Self::IntSExt),
            "INT_ADD" => Some(Self::IntAdd),
            "INT_SUB" => Some(Self::IntSub),
            "INT_CARRY" => Some(Self::IntCarry),
            "INT_SCARRY" => Some(Self::IntSCarry),
            "INT_SBORROW" => Some(Self::IntSBorrow),
            "INT_2COMP" => Some(Self::Int2Comp),
            "INT_NEGATE" => Some(Self::IntNegate),
            "INT_XOR" => Some(Self::IntXor),
            "INT_AND" => Some(Self::IntAnd),
            "INT_OR" => Some(Self::IntOr),
            "INT_LEFT" => Some(Self::IntLeft),
            "INT_RIGHT" => Some(Self::IntRight),
            "INT_SRIGHT" => Some(Self::IntSRight),
            "INT_MULT" => Some(Self::IntMult),
            "INT_DIV" => Some(Self::IntDiv),
            "INT_SDIV" => Some(Self::IntSDiv),
            "INT_REM" => Some(Self::IntRem),
            "INT_SREM" => Some(Self::IntSRem),
            "BOOL_NEGATE" => Some(Self::BoolNegate),
            "BOOL_XOR" => Some(Self::BoolXor),
            "BOOL_AND" => Some(Self::BoolAnd),
            "BOOL_OR" => Some(Self::BoolOr),
            "FLOAT_EQUAL" => Some(Self::FloatEqual),
            "FLOAT_NOTEQUAL" => Some(Self::FloatNotEqual),
            "FLOAT_LESS" => Some(Self::FloatLess),
            "FLOAT_LESSEQUAL" => Some(Self::FloatLessEqual),
            "FLOAT_NAN" => Some(Self::FloatNan),
            "FLOAT_ADD" => Some(Self::FloatAdd),
            "FLOAT_DIV" => Some(Self::FloatDiv),
            "FLOAT_MULT" => Some(Self::FloatMult),
            "FLOAT_SUB" => Some(Self::FloatSub),
            "FLOAT_NEG" => Some(Self::FloatNeg),
            "FLOAT_ABS" => Some(Self::FloatAbs),
            "FLOAT_SQRT" => Some(Self::FloatSqrt),
            "FLOAT_INT2FLOAT" => Some(Self::FloatInt2Float),
            "FLOAT_FLOAT2FLOAT" => Some(Self::FloatFloat2Float),
            "FLOAT_TRUNC" => Some(Self::FloatTrunc),
            "FLOAT_CEIL" => Some(Self::FloatCeil),
            "FLOAT_FLOOR" => Some(Self::FloatFloor),
            "FLOAT_ROUND" => Some(Self::FloatRound),
            "MULTIEQUAL" => Some(Self::MultiEqual),
            "INDIRECT" => Some(Self::Indirect),
            "PIECE" => Some(Self::Piece),
            "SUBPIECE" => Some(Self::Subpiece),
            "CAST" => Some(Self::Cast),
            "PTRADD" => Some(Self::PtrAdd),
            "PTRSUB" => Some(Self::PtrSub),
            "SEGMENTOP" => Some(Self::SegmentOp),
            "CPOOLREF" => Some(Self::CPoolRef),
            "NEW" => Some(Self::New),
            "INSERT" => Some(Self::Insert),
            "ZPULL" => Some(Self::ZPull),
            "POPCOUNT" => Some(Self::PopCount),
            "LZCOUNT" => Some(Self::LzCount),
            "SPULL" => Some(Self::SPull),
            _ => None,
        }
    }

    pub fn is_branch(&self) -> bool {
        matches!(
            self,
            Self::Branch | Self::CBranch | Self::BranchInd | Self::Call | Self::CallInd | Self::Return
        )
    }

    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call | Self::CallInd | Self::CallOther)
    }

    pub fn is_boolean_output(&self) -> bool {
        matches!(
            self,
            Self::IntEqual
                | Self::IntNotEqual
                | Self::IntSLess
                | Self::IntSLessEqual
                | Self::IntLess
                | Self::IntLessEqual
                | Self::IntCarry
                | Self::IntSCarry
                | Self::IntSBorrow
                | Self::BoolNegate
                | Self::BoolXor
                | Self::BoolAnd
                | Self::BoolOr
                | Self::FloatEqual
                | Self::FloatNotEqual
                | Self::FloatLess
                | Self::FloatLessEqual
                | Self::FloatNan
        )
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarnodeData {
    pub space: SpaceId,
    pub offset: u64,
    pub size: u32,
}

impl VarnodeData {
    pub fn new(space: SpaceId, offset: u64, size: u32) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }

    pub fn address(&self) -> Address {
        Address::new(self.space, self.offset)
    }

    pub fn contains_offset(&self, off: u64) -> bool {
        off >= self.offset && off < self.offset + self.size as u64
    }

    pub fn overlaps(&self, other: &VarnodeData) -> bool {
        if self.space != other.space {
            return false;
        }
        self.offset < other.offset + other.size as u64
            && other.offset < self.offset + self.size as u64
    }
}

impl Ord for VarnodeData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.space
            .cmp(&other.space)
            .then(self.offset.cmp(&other.offset))
            .then(self.size.cmp(&other.size))
    }
}

impl PartialOrd for VarnodeData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for VarnodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(space={}, 0x{:x}, {})", self.space.0, self.offset, self.size)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeqNum {
    pub addr: Address,
    pub order: u32,
    pub uniq: u64,
}

impl SeqNum {
    pub fn new(addr: Address, order: u32) -> Self {
        Self {
            addr,
            order,
            uniq: 0,
        }
    }

    pub fn with_uniq(addr: Address, order: u32, uniq: u64) -> Self {
        Self { addr, order, uniq }
    }
}

impl Ord for SeqNum {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.addr
            .cmp(&other.addr)
            .then(self.order.cmp(&other.order))
    }
}

impl PartialOrd for SeqNum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub struct PcodeOp {
    pub opcode: OpCode,
    pub seq: SeqNum,
    pub output: Option<VarnodeData>,
    pub inputs: SmallVec<[VarnodeData; 3]>,
}

impl PcodeOp {
    pub fn new(opcode: OpCode, seq: SeqNum) -> Self {
        Self {
            opcode,
            seq,
            output: None,
            inputs: SmallVec::new(),
        }
    }

    pub fn with_output(mut self, output: VarnodeData) -> Self {
        self.output = Some(output);
        self
    }

    pub fn with_input(mut self, input: VarnodeData) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn with_inputs(mut self, inputs: impl IntoIterator<Item = VarnodeData>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    pub fn input(&self, index: usize) -> Option<&VarnodeData> {
        self.inputs.get(index)
    }
}

impl fmt::Display for PcodeOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref out) = self.output {
            write!(f, "{} = ", out)?;
        }
        write!(f, "{}", self.opcode)?;
        for (i, inp) in self.inputs.iter().enumerate() {
            if i == 0 {
                write!(f, " {}", inp)?;
            } else {
                write!(f, ", {}", inp)?;
            }
        }
        Ok(())
    }
}

/// Named-intrinsic tags for `CallOther`. Some machine instructions are best
/// represented as an opaque-but-named operation with intact dataflow (a
/// destination that is a known function of its inputs) rather than expanded
/// into dozens of scalar ops (which hurts readability) or dropped to a
/// misleading trap. This is exactly how Ghidra/IDA surface lane-precise SIMD
/// and bit-scan ops. The lifter emits `CallOther` with `inputs[0] = const
/// <tag>` and the real operands following; the decompiler renders
/// `out = <name>(operands…)`.
///
/// Tags 0 (generic unmodeled) and 3 (int3 breakpoint) are reserved and not
/// named here. Named tags start at 0x100 to stay clear of those.
pub mod intrinsic {
    pub const BASE: u64 = 0x100;
    pub const BSR: u64 = 0x100;
    pub const BSF: u64 = 0x101;
    pub const PMOVMSKB: u64 = 0x102;
    pub const PCMPEQB: u64 = 0x103;

    /// Map an intrinsic tag to its rendered name, or None if `tag` is not a
    /// named intrinsic (e.g. 0 generic / 3 int3).
    pub fn name(tag: u64) -> Option<&'static str> {
        Some(match tag {
            BSR => "bsr",
            BSF => "bsf",
            PMOVMSKB => "pmovmskb",
            PCMPEQB => "pcmpeqb",
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_roundtrip() {
        for val in 1..=74 {
            if val == 45 {
                assert!(OpCode::from_u32(val).is_none());
                continue;
            }
            let op = OpCode::from_u32(val).unwrap();
            let name = op.name();
            let recovered = OpCode::from_name(name).unwrap();
            assert_eq!(op, recovered);
            assert_eq!(op as u32, val);
        }
    }

    #[test]
    fn opcode_max() {
        assert!(OpCode::from_u32(0).is_none());
        assert!(OpCode::from_u32(75).is_none());
        assert!(OpCode::from_u32(45).is_none());
    }

    #[test]
    fn varnode_ordering() {
        let v1 = VarnodeData::new(SpaceId(1), 0x100, 4);
        let v2 = VarnodeData::new(SpaceId(1), 0x100, 8);
        let v3 = VarnodeData::new(SpaceId(1), 0x200, 4);
        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn varnode_overlap() {
        let v1 = VarnodeData::new(SpaceId(1), 0x100, 4);
        let v2 = VarnodeData::new(SpaceId(1), 0x102, 4);
        let v3 = VarnodeData::new(SpaceId(1), 0x104, 4);
        assert!(v1.overlaps(&v2));
        assert!(!v1.overlaps(&v3));
    }

    #[test]
    fn pcode_op_builder() {
        let seq = SeqNum::new(Address::new(SpaceId(1), 0x1000), 0);
        let op = PcodeOp::new(OpCode::IntAdd, seq)
            .with_output(VarnodeData::new(SpaceId(2), 0, 8))
            .with_input(VarnodeData::new(SpaceId(2), 0, 8))
            .with_input(VarnodeData::new(SpaceId(0), 1, 8));
        assert_eq!(op.opcode, OpCode::IntAdd);
        assert!(op.output.is_some());
        assert_eq!(op.num_inputs(), 2);
    }

    #[test]
    fn opcode_classification() {
        assert!(OpCode::Branch.is_branch());
        assert!(OpCode::Call.is_branch());
        assert!(OpCode::Call.is_call());
        assert!(!OpCode::IntAdd.is_branch());
        assert!(OpCode::IntEqual.is_boolean_output());
        assert!(!OpCode::IntAdd.is_boolean_output());
    }

    #[test]
    fn seqnum_ordering() {
        let s1 = SeqNum::new(Address::new(SpaceId(1), 0x100), 0);
        let s2 = SeqNum::new(Address::new(SpaceId(1), 0x100), 1);
        let s3 = SeqNum::new(Address::new(SpaceId(1), 0x104), 0);
        assert!(s1 < s2);
        assert!(s2 < s3);
    }
}
