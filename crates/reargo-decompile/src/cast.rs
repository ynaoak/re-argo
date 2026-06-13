// Type cast insertion for decompiled output.

use crate::ssa::SsaFunction;
use crate::typeinfer::InferredType;
use reargo_core::pcode::OpCode;

#[derive(Debug, Clone)]
pub struct CastInfo {
    pub op_index: usize,
    pub input_index: usize,
    pub from_type: InferredType,
    pub to_type: InferredType,
}

pub fn find_needed_casts(func: &SsaFunction, types: &std::collections::BTreeMap<u32, InferredType>) -> Vec<CastInfo> {
    let mut casts = Vec::new();

    for (i, op) in func.ops.iter().enumerate() {
        if op.dead { continue; }

        match op.opcode {
            OpCode::IntSExt | OpCode::IntZExt => {
                if let (Some(out_id), Some(&inp_id)) = (op.output, op.inputs.first()) {
                    let from = types.get(&inp_id).cloned().unwrap_or(InferredType::Unknown);
                    let to = types.get(&out_id).cloned().unwrap_or(InferredType::Unknown);
                    if from != to {
                        casts.push(CastInfo { op_index: i, input_index: 0, from_type: from, to_type: to });
                    }
                }
            }
            OpCode::FloatInt2Float | OpCode::FloatFloat2Float | OpCode::FloatTrunc => {
                if let Some(out_id) = op.output {
                    let to = types.get(&out_id).cloned().unwrap_or(InferredType::Unknown);
                    casts.push(CastInfo {
                        op_index: i, input_index: 0,
                        from_type: InferredType::Unknown, to_type: to,
                    });
                }
            }
            _ => {}
        }
    }
    casts
}

pub fn cast_expression(from: &InferredType, to: &InferredType, expr: &str) -> String {
    let to_str = to.to_c_type();
    if from == to || *to == InferredType::Unknown {
        return expr.to_string();
    }
    format!("({}){}", to_str, expr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cast_expression_basic() {
        let from = InferredType::Integer { size: 4, signed: true };
        let to = InferredType::Integer { size: 8, signed: true };
        assert_eq!(cast_expression(&from, &to, "x"), "(int64_t)x");
    }

    #[test]
    fn cast_same_type() {
        let t = InferredType::Integer { size: 4, signed: false };
        assert_eq!(cast_expression(&t, &t, "y"), "y");
    }

    #[test]
    fn cast_to_float() {
        let from = InferredType::Integer { size: 4, signed: true };
        let to = InferredType::Float { size: 8 };
        assert_eq!(cast_expression(&from, &to, "n"), "(double)n");
    }
}
