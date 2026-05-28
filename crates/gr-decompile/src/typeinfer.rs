use std::collections::{BTreeMap, BTreeSet};

use gr_core::address::SpaceId;
use gr_core::pcode::OpCode;

use crate::ssa::SsaFunction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    Unknown,
    Integer { size: u32, signed: bool },
    Float { size: u32 },
    Pointer { pointee_size: Option<u32> },
    /// Pointer to an array of fixed-size elements.
    Array { element_size: u32, count: Option<usize> },
    /// Pointer to a struct with the given recovered fields.
    Struct { field_count: usize },
    Bool,
    Void,
}

fn int_type_for_size(size: u32) -> String {
    match size {
        1 => "uint8_t".into(),
        2 => "uint16_t".into(),
        4 => "uint32_t".into(),
        8 => "uint64_t".into(),
        _ => format!("uint{}_t", size * 8),
    }
}

impl InferredType {
    pub fn to_c_type(&self) -> String {
        match self {
            Self::Unknown => "undefined".into(),
            Self::Void => "void".into(),
            Self::Bool => "bool".into(),
            Self::Integer { size, signed } => {
                let prefix = if *signed { "int" } else { "uint" };
                format!("{}{}_t", prefix, size * 8)
            }
            Self::Float { size } => match size {
                4 => "float".into(),
                8 => "double".into(),
                _ => format!("float{}", size * 8),
            },
            Self::Pointer { pointee_size } => match pointee_size {
                Some(1) => "char*".into(),
                Some(s) => format!("void* /* ->{}B */", s),
                None => "void*".into(),
            },
            Self::Array { element_size, count } => {
                let elem = int_type_for_size(*element_size);
                match count {
                    Some(n) => format!("{}* /* [{}] */", elem, n),
                    None => format!("{}* /* [] */", elem),
                }
            }
            Self::Struct { field_count } => {
                format!("struct {{ /* {} fields */ }}*", field_count)
            }
        }
    }
}

/// A single recovered struct field: byte offset and access width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    pub offset: u64,
    pub size: u32,
}

/// A struct layout recovered from access patterns on a base pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredStruct {
    pub fields: Vec<StructField>,
}

impl RecoveredStruct {
    /// Render a C struct definition.
    pub fn to_c_definition(&self, name: &str) -> String {
        let mut out = format!("struct {} {{\n", name);
        for (i, f) in self.fields.iter().enumerate() {
            out.push_str(&format!(
                "    {} field_{:x}; // +0x{:x}\n",
                int_type_for_size(f.size),
                f.offset,
                f.offset
            ));
            let _ = i;
        }
        out.push_str("};");
        out
    }
}

/// An array layout recovered from a scaled-index access pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredArray {
    pub element_size: u32,
}

pub struct TypeInferenceEngine {
    var_types: BTreeMap<u32, InferredType>,
    structs: BTreeMap<u32, RecoveredStruct>,
    arrays: BTreeMap<u32, RecoveredArray>,
}

impl TypeInferenceEngine {
    pub fn new() -> Self {
        Self {
            var_types: BTreeMap::new(),
            structs: BTreeMap::new(),
            arrays: BTreeMap::new(),
        }
    }

    pub fn infer(&mut self, func: &SsaFunction) {
        for op in &func.ops {
            if op.dead {
                continue;
            }
            match op.opcode {
                OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult
                | OpCode::IntDiv | OpCode::IntRem | OpCode::IntAnd
                | OpCode::IntOr | OpCode::IntXor | OpCode::IntLeft
                | OpCode::IntRight | OpCode::IntNegate | OpCode::Int2Comp => {
                    if let Some(out_id) = op.output {
                        let size = func.varnodes[out_id as usize].data.size;
                        self.set_type(out_id, InferredType::Integer { size, signed: false });
                    }
                }
                OpCode::IntSRight | OpCode::IntSDiv | OpCode::IntSRem
                | OpCode::IntSLess | OpCode::IntSLessEqual | OpCode::IntSCarry
                | OpCode::IntSBorrow | OpCode::IntSExt => {
                    if let Some(out_id) = op.output {
                        let size = func.varnodes[out_id as usize].data.size;
                        self.set_type(out_id, InferredType::Integer { size, signed: true });
                    }
                }
                OpCode::IntEqual | OpCode::IntNotEqual | OpCode::IntLess
                | OpCode::IntLessEqual | OpCode::BoolAnd | OpCode::BoolOr
                | OpCode::BoolXor | OpCode::BoolNegate => {
                    if let Some(out_id) = op.output {
                        self.set_type(out_id, InferredType::Bool);
                    }
                }
                OpCode::FloatAdd | OpCode::FloatSub | OpCode::FloatMult
                | OpCode::FloatDiv | OpCode::FloatNeg | OpCode::FloatAbs
                | OpCode::FloatSqrt | OpCode::FloatInt2Float | OpCode::FloatFloat2Float => {
                    if let Some(out_id) = op.output {
                        let size = func.varnodes[out_id as usize].data.size;
                        self.set_type(out_id, InferredType::Float { size });
                    }
                }
                OpCode::Load => {
                    if let Some(out_id) = op.output {
                        let size = func.varnodes[out_id as usize].data.size;
                        self.set_type(out_id, InferredType::Integer { size, signed: false });
                    }
                    if op.inputs.len() >= 2 {
                        let addr_id = op.inputs[1];
                        let vn = &func.varnodes[addr_id as usize];
                        if vn.data.space != SpaceId::CONST {
                            self.set_type(addr_id, InferredType::Pointer { pointee_size: Some(
                                op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(0)
                            )});
                        }
                    }
                }
                OpCode::Store
                    if op.inputs.len() >= 2 => {
                        let addr_id = op.inputs[1];
                        let vn = &func.varnodes[addr_id as usize];
                        if vn.data.space != SpaceId::CONST {
                            let store_size = if op.inputs.len() >= 3 {
                                Some(func.varnodes[op.inputs[2] as usize].data.size)
                            } else {
                                None
                            };
                            self.set_type(addr_id, InferredType::Pointer { pointee_size: store_size });
                        }
                    }
                OpCode::PtrAdd | OpCode::PtrSub => {
                    if let Some(out_id) = op.output {
                        self.set_type(out_id, InferredType::Pointer { pointee_size: None });
                    }
                }
                _ => {}
            }
        }
    }

    /// Recover struct and array layouts from memory access patterns.
    ///
    /// A base pointer dereferenced at multiple distinct constant offsets is
    /// classified as a struct; a base accessed via a scaled index
    /// (`base + index * stride`) is classified as an array of `stride`-byte
    /// elements.
    pub fn recover_aggregates(&mut self, func: &SsaFunction) {
        let def_map = build_def_map(func);

        // base-variable key (space, offset, version) -> accesses.
        // Keying by the SSA value identity (not varnode id) lets reads of the
        // same base from different sites collapse onto one aggregate.
        let mut struct_accesses: BTreeMap<VarKey, BTreeSet<(u64, u32)>> = BTreeMap::new();
        let mut array_strides: BTreeMap<VarKey, u32> = BTreeMap::new();

        for op in &func.ops {
            if op.dead || !matches!(op.opcode, OpCode::Load | OpCode::Store) {
                continue;
            }
            if op.inputs.len() < 2 {
                continue;
            }
            let addr_id = op.inputs[1];
            let access_size = match op.opcode {
                OpCode::Load => op.output.map(|id| func.varnodes[id as usize].data.size).unwrap_or(0),
                OpCode::Store => op.inputs.get(2).map(|&id| func.varnodes[id as usize].data.size).unwrap_or(0),
                _ => 0,
            };
            if access_size == 0 {
                continue;
            }

            let Some(def_idx) = resolve_def(func, &def_map, addr_id) else { continue };
            let def = &func.ops[def_idx];
            if !matches!(def.opcode, OpCode::IntAdd | OpCode::PtrAdd) || def.inputs.len() != 2 {
                continue;
            }

            let a_id = def.inputs[0];
            let b_id = def.inputs[1];
            let a = &func.varnodes[a_id as usize];
            let b = &func.varnodes[b_id as usize];

            // base + const  =>  struct field access
            if b.data.space == SpaceId::CONST && a.data.space != SpaceId::CONST {
                struct_accesses.entry(var_key(func, a_id)).or_default().insert((b.data.offset, access_size));
            } else if a.data.space == SpaceId::CONST && b.data.space != SpaceId::CONST {
                struct_accesses.entry(var_key(func, b_id)).or_default().insert((a.data.offset, access_size));
            } else {
                // base + index  =>  check for a scaled index (array)
                for (base_id, idx_id) in [(a_id, b_id), (b_id, a_id)] {
                    if let Some(stride) = scaled_index_stride(func, &def_map, idx_id) {
                        array_strides.insert(var_key(func, base_id), stride);
                    }
                }
            }
        }

        // A base with two or more distinct field offsets is a struct.
        for (key, fields) in &struct_accesses {
            if fields.len() >= 2
                && let Some(base_id) = first_var_with_key(func, key) {
                    let mut fv: Vec<StructField> = fields
                        .iter()
                        .map(|(o, s)| StructField { offset: *o, size: *s })
                        .collect();
                    fv.sort_by_key(|f| f.offset);
                    let field_count = fv.len();
                    self.structs.insert(base_id, RecoveredStruct { fields: fv });
                    self.var_types.insert(base_id, InferredType::Struct { field_count });
                }
        }

        for (key, stride) in &array_strides {
            if let Some(base_id) = first_var_with_key(func, key) {
                // Don't override a struct classification with an array.
                if self.structs.contains_key(&base_id) {
                    continue;
                }
                self.arrays.insert(base_id, RecoveredArray { element_size: *stride });
                self.var_types
                    .insert(base_id, InferredType::Array { element_size: *stride, count: None });
            }
        }
    }

    pub fn structs(&self) -> &BTreeMap<u32, RecoveredStruct> {
        &self.structs
    }

    pub fn arrays(&self) -> &BTreeMap<u32, RecoveredArray> {
        &self.arrays
    }

    fn set_type(&mut self, var_id: u32, typ: InferredType) {
        self.var_types.entry(var_id).or_insert(typ);
    }

    pub fn get_type(&self, var_id: u32) -> &InferredType {
        self.var_types.get(&var_id).unwrap_or(&InferredType::Unknown)
    }

    pub fn types(&self) -> &BTreeMap<u32, InferredType> {
        &self.var_types
    }
}

impl Default for TypeInferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Identifies an SSA value by its defining variable coordinates. The simplified
/// SSA allocates a fresh varnode per read, so reads/writes of the same value are
/// correlated by (space, offset, size, version) rather than by varnode id.
type VarKey = (u32, u64, u32, u32);

fn var_key(func: &SsaFunction, var_id: u32) -> VarKey {
    let vn = &func.varnodes[var_id as usize];
    (vn.data.space.0, vn.data.offset, vn.data.size, vn.version)
}

fn first_var_with_key(func: &SsaFunction, key: &VarKey) -> Option<u32> {
    func.varnodes
        .iter()
        .find(|vn| (vn.data.space.0, vn.data.offset, vn.data.size, vn.version) == *key)
        .map(|vn| vn.id)
}

/// Map each defined SSA value to the index of the op that produced it.
fn build_def_map(func: &SsaFunction) -> BTreeMap<VarKey, usize> {
    let mut map = BTreeMap::new();
    for op in &func.ops {
        if op.dead {
            continue;
        }
        if let Some(out_id) = op.output {
            map.insert(var_key(func, out_id), op.index);
        }
    }
    map
}

fn resolve_def(func: &SsaFunction, def_map: &BTreeMap<VarKey, usize>, var_id: u32) -> Option<usize> {
    def_map.get(&var_key(func, var_id)).copied()
}

/// If `idx_id` is defined by `index * stride` or `index << shift`, return the
/// element stride (a small power-of-two-friendly access size).
fn scaled_index_stride(
    func: &SsaFunction,
    def_map: &BTreeMap<VarKey, usize>,
    idx_id: u32,
) -> Option<u32> {
    let def_idx = resolve_def(func, def_map, idx_id)?;
    let def = &func.ops[def_idx];
    if def.inputs.len() != 2 {
        return None;
    }
    match def.opcode {
        OpCode::IntMult => {
            for k in 0..2 {
                let c = &func.varnodes[def.inputs[k] as usize];
                if c.data.space == SpaceId::CONST {
                    let stride = c.data.offset;
                    if (1..=16).contains(&stride) {
                        return Some(stride as u32);
                    }
                }
            }
            None
        }
        OpCode::IntLeft => {
            let c = &func.varnodes[def.inputs[1] as usize];
            if c.data.space == SpaceId::CONST && c.data.offset <= 4 {
                return Some(1u32 << c.data.offset);
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use gr_core::address::{Address, SpaceId as CoreSpace};
    use gr_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use gr_lift::LiftedInstruction;
    use smallvec::SmallVec;

    #[test]
    fn inferred_type_display() {
        assert_eq!(InferredType::Integer { size: 4, signed: false }.to_c_type(), "uint32_t");
        assert_eq!(InferredType::Integer { size: 8, signed: true }.to_c_type(), "int64_t");
        assert_eq!(InferredType::Float { size: 8 }.to_c_type(), "double");
        assert_eq!(InferredType::Bool.to_c_type(), "bool");
        assert_eq!(InferredType::Pointer { pointee_size: Some(1) }.to_c_type(), "char*");
        assert_eq!(InferredType::Void.to_c_type(), "void");
    }

    #[test]
    fn array_struct_display() {
        assert_eq!(
            InferredType::Array { element_size: 4, count: Some(8) }.to_c_type(),
            "uint32_t* /* [8] */"
        );
        assert_eq!(
            InferredType::Array { element_size: 8, count: None }.to_c_type(),
            "uint64_t* /* [] */"
        );
        assert!(InferredType::Struct { field_count: 3 }.to_c_type().contains("3 fields"));
    }

    #[test]
    fn struct_definition_render() {
        let s = RecoveredStruct {
            fields: vec![
                StructField { offset: 0, size: 8 },
                StructField { offset: 8, size: 4 },
            ],
        };
        let def = s.to_c_definition("Foo");
        assert!(def.contains("struct Foo"));
        assert!(def.contains("field_0"));
        assert!(def.contains("field_8"));
        assert!(def.contains("+0x8"));
    }

    fn lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction { address: addr, length: 1, mnemonic: "t".into(), ops }
    }

    // Build an SSA function from raw P-code ops and run aggregate recovery.
    fn run_recovery(ops: Vec<PcodeOp>) -> TypeInferenceEngine {
        let insns: Vec<LiftedInstruction> = ops
            .into_iter()
            .enumerate()
            .map(|(i, op)| lifted(0x1000 + i as u64, vec![op]))
            .collect();
        let cfg = ControlFlowGraph::build(&insns);
        let func = crate::ssa::SsaFunction::from_cfg("t".into(), 0x1000, cfg);
        let mut engine = TypeInferenceEngine::new();
        engine.recover_aggregates(&func);
        engine
    }

    #[test]
    fn recover_struct_from_field_accesses() {
        // reg base = rdi; load base+0; load base+8; load base+16
        let base = VarnodeData::new(CoreSpace::REGISTER, 0x38, 8); // rdi
        let seq = |a, o| SeqNum::new(Address::new(CoreSpace::RAM, a), o);
        let space = VarnodeData::new(CoreSpace::CONST, CoreSpace::RAM.0 as u64, 4);

        let mut ops = Vec::new();
        for (i, off) in [0u64, 8, 16].iter().enumerate() {
            let tmp = VarnodeData::new(CoreSpace::UNIQUE, 0x100 + i as u64 * 8, 8);
            let out = VarnodeData::new(CoreSpace::REGISTER, 0x200 + i as u64 * 8, 8);
            ops.push(PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000 + i as u64 * 2, 0),
                output: Some(tmp),
                inputs: SmallVec::from_slice(&[base, VarnodeData::new(CoreSpace::CONST, *off, 8)]),
            });
            ops.push(PcodeOp {
                opcode: OpCode::Load,
                seq: seq(0x1000 + i as u64 * 2 + 1, 0),
                output: Some(out),
                inputs: SmallVec::from_slice(&[space, tmp]),
            });
        }

        let engine = run_recovery(ops);
        assert_eq!(engine.structs().len(), 1, "expected one recovered struct");
        let s = engine.structs().values().next().unwrap();
        assert_eq!(s.fields.len(), 3);
        assert_eq!(s.fields[0].offset, 0);
        assert_eq!(s.fields[2].offset, 16);
    }

    #[test]
    fn recover_array_from_scaled_index() {
        // index_scaled = rsi * 4; addr = rdi + index_scaled; load addr
        let seq = |a, o| SeqNum::new(Address::new(CoreSpace::RAM, a), o);
        let base = VarnodeData::new(CoreSpace::REGISTER, 0x38, 8); // rdi
        let index = VarnodeData::new(CoreSpace::REGISTER, 0x30, 8); // rsi
        let scaled = VarnodeData::new(CoreSpace::UNIQUE, 0x100, 8);
        let addr = VarnodeData::new(CoreSpace::UNIQUE, 0x108, 8);
        let out = VarnodeData::new(CoreSpace::REGISTER, 0x00, 4);
        let space = VarnodeData::new(CoreSpace::CONST, CoreSpace::RAM.0 as u64, 4);

        let ops = vec![
            PcodeOp {
                opcode: OpCode::IntMult,
                seq: seq(0x1000, 0),
                output: Some(scaled),
                inputs: SmallVec::from_slice(&[index, VarnodeData::new(CoreSpace::CONST, 4, 8)]),
            },
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1001, 0),
                output: Some(addr),
                inputs: SmallVec::from_slice(&[base, scaled]),
            },
            PcodeOp {
                opcode: OpCode::Load,
                seq: seq(0x1002, 0),
                output: Some(out),
                inputs: SmallVec::from_slice(&[space, addr]),
            },
        ];

        let engine = run_recovery(ops);
        assert_eq!(engine.arrays().len(), 1, "expected one recovered array");
        let arr = engine.arrays().values().next().unwrap();
        assert_eq!(arr.element_size, 4);
    }
}
