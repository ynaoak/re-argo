use std::collections::BTreeMap;

use gr_core::address::SpaceId;
use gr_core::pcode::OpCode;

use crate::ssa::SsaFunction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    Unknown,
    Integer { size: u32, signed: bool },
    Float { size: u32 },
    Pointer { pointee_size: Option<u32> },
    Bool,
    Void,
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
        }
    }
}

pub struct TypeInferenceEngine {
    var_types: BTreeMap<u32, InferredType>,
}

impl TypeInferenceEngine {
    pub fn new() -> Self {
        Self {
            var_types: BTreeMap::new(),
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
                OpCode::Store => {
                    if op.inputs.len() >= 2 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inferred_type_display() {
        assert_eq!(InferredType::Integer { size: 4, signed: false }.to_c_type(), "uint32_t");
        assert_eq!(InferredType::Integer { size: 8, signed: true }.to_c_type(), "int64_t");
        assert_eq!(InferredType::Float { size: 8 }.to_c_type(), "double");
        assert_eq!(InferredType::Bool.to_c_type(), "bool");
        assert_eq!(InferredType::Pointer { pointee_size: Some(1) }.to_c_type(), "char*");
        assert_eq!(InferredType::Void.to_c_type(), "void");
    }
}
