use gr_core::address::SpaceId;
use gr_core::pcode::{OpCode, PcodeOp};

use crate::state::EmulatorState;

#[derive(Debug, thiserror::Error)]
pub enum EmulatorError {
    #[error("no output varnode for op {0}")]
    MissingOutput(String),
    #[error("missing input {index} for op {op}")]
    MissingInput { op: String, index: usize },
    #[error("halted at 0x{0:x}")]
    Halted(u64),
    #[error("branch to 0x{0:x}")]
    Branch(u64),
    #[error("return with value 0x{0:x}")]
    Return(u64),
    #[error("call to 0x{0:x}")]
    Call(u64),
    #[error("unsupported opcode: {0}")]
    Unsupported(String),
}

pub struct Emulator {
    pub state: EmulatorState,
    pub step_count: u64,
}

impl Emulator {
    pub fn new() -> Self {
        Self {
            state: EmulatorState::new(),
            step_count: 0,
        }
    }

    pub fn with_state(state: EmulatorState) -> Self {
        Self {
            state,
            step_count: 0,
        }
    }

    pub fn execute_op(&mut self, op: &PcodeOp) -> Result<(), EmulatorError> {
        self.step_count += 1;

        match op.opcode {
            OpCode::Copy => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("COPY".into()))?;
                let src = self.read_input(op, 0)?;
                self.state.write_varnode(out, src);
            }

            OpCode::IntAdd => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_ADD".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, a.wrapping_add(b));
            }

            OpCode::IntSub => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SUB".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, a.wrapping_sub(b));
            }

            OpCode::IntMult => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_MULT".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, a.wrapping_mul(b));
            }


            OpCode::IntAnd => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_AND".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, a & b);
            }

            OpCode::IntOr => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_OR".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, a | b);
            }

            OpCode::IntXor => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_XOR".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, a ^ b);
            }

            OpCode::IntNegate => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_NEGATE".into()))?;
                let a = self.read_input(op, 0)?;
                self.state.write_varnode(out, !a);
            }

            OpCode::Int2Comp => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_2COMP".into()))?;
                let a = self.read_input(op, 0)?;
                self.state.write_varnode(out, (!a).wrapping_add(1));
            }

            OpCode::IntLeft => {
                // P-code semantics: shift by amount >= operand bitwidth gives 0
                // (Rust's wrapping_shl wraps mod 64, which would mis-shift for
                // amounts >= bitwidth on operands smaller than 64 bits, and
                // wraps for amounts >= 64 even on 64-bit operands).
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_LEFT".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8).min(8);
                let bits = (size * 8) as u64;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let result = if b >= bits { 0 } else { a.wrapping_shl(b as u32) };
                self.state.write_varnode(out, result);
            }

            OpCode::IntRight => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_RIGHT".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8).min(8);
                let bits = (size * 8) as u64;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let result = if b >= bits { 0 } else { a.wrapping_shr(b as u32) };
                self.state.write_varnode(out, result);
            }

            OpCode::IntSRight => {
                // Arithmetic shift: shift by >= bitwidth replicates the sign bit
                // (all-ones if negative at the operand width, otherwise 0).
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SRIGHT".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8).min(8);
                let bits = (size * 8) as u64;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let result = if b >= bits {
                    let sign_bit = (a >> (bits - 1)) & 1;
                    if sign_bit == 1 {
                        if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
                    } else {
                        0
                    }
                } else {
                    // Sign-extend a from `bits` to 64, then arithmetic shift.
                    let extend = 64 - bits as u32;
                    let signed_a = ((a << extend) as i64) >> extend;
                    signed_a.wrapping_shr(b as u32) as u64
                };
                self.state.write_varnode(out, result);
            }

            OpCode::IntEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_EQUAL".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, if a == b { 1 } else { 0 });
            }

            OpCode::IntNotEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_NOTEQUAL".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, if a != b { 1 } else { 0 });
            }

            OpCode::IntLess => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_LESS".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, if a < b { 1 } else { 0 });
            }

            OpCode::IntSLess => {
                // Signed compare at the operand width: read_input zero-extends
                // a sub-word value, so casting to i64 directly would treat a
                // 32-bit 0xFFFFFFFF (= -1 as i32) as positive. Sign-extend
                // from the input size first.
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SLESS".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8).min(8);
                let extend = 64 - (size * 8);
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let sa = ((a << extend) as i64) >> extend;
                let sb = ((b << extend) as i64) >> extend;
                self.state.write_varnode(out, if sa < sb { 1 } else { 0 });
            }

            OpCode::IntZExt => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_ZEXT".into()))?;
                let a = self.read_input(op, 0)?;
                self.state.write_varnode(out, a);
            }

            OpCode::IntSExt => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SEXT".into()))?;
                let in_vn = op.input(0).ok_or_else(|| EmulatorError::MissingInput { op: "INT_SEXT".into(), index: 0 })?;
                let a = self.state.read_varnode(in_vn);
                let sign_extended = match in_vn.size {
                    1 => a as u8 as i8 as i64 as u64,
                    2 => a as u16 as i16 as i64 as u64,
                    4 => a as u32 as i32 as i64 as u64,
                    _ => a,
                };
                self.state.write_varnode(out, sign_extended);
            }

            OpCode::Load => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("LOAD".into()))?;
                let _space_id = self.read_input(op, 0)?;
                let addr = self.read_input(op, 1)?;
                let val = self.state.read_memory(addr, out.size);
                self.state.write_varnode(out, val);
            }

            OpCode::Store => {
                let space_id = self.read_input(op, 0)?;
                let addr = self.read_input(op, 1)?;
                let in_vn = op.input(2).ok_or_else(|| EmulatorError::MissingInput { op: "STORE".into(), index: 2 })?;
                let val = self.state.read_varnode(in_vn);
                if space_id == 1 {
                    self.state.write_memory(addr, in_vn.size, val);
                } else {
                    self.state.write_varnode(
                        &gr_core::pcode::VarnodeData::new(SpaceId(space_id as u32), addr, in_vn.size),
                        val,
                    );
                }
            }

            OpCode::Branch => {
                let target_vn = op.input(0).ok_or_else(|| EmulatorError::MissingInput { op: "BRANCH".into(), index: 0 })?;
                return Err(EmulatorError::Branch(target_vn.offset));
            }

            OpCode::CBranch => {
                let target_vn = op.input(0).ok_or_else(|| EmulatorError::MissingInput { op: "CBRANCH".into(), index: 0 })?;
                let cond = self.read_input(op, 1)?;
                if cond != 0 {
                    return Err(EmulatorError::Branch(target_vn.offset));
                }
            }

            OpCode::Call => {
                let target_vn = op.input(0).ok_or_else(|| EmulatorError::MissingInput { op: "CALL".into(), index: 0 })?;
                return Err(EmulatorError::Call(target_vn.offset));
            }

            OpCode::Return => {
                let ret_val = self.read_input(op, 0)?;
                return Err(EmulatorError::Return(ret_val));
            }

            OpCode::CallOther => {}

            OpCode::Piece => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("PIECE".into()))?;
                let hi_vn = op.input(0).ok_or_else(|| EmulatorError::MissingInput { op: "PIECE".into(), index: 0 })?;
                let lo_vn = op.input(1).ok_or_else(|| EmulatorError::MissingInput { op: "PIECE".into(), index: 1 })?;
                let hi = self.state.read_varnode(hi_vn);
                let lo = self.state.read_varnode(lo_vn);
                // Shift by 64 would panic in debug; if lo already fills the
                // word, only lo contributes.
                let shift = lo_vn.size * 8;
                let result = if shift >= 64 { lo } else { (hi << shift) | lo };
                self.state.write_varnode(out, result);
            }

            OpCode::Subpiece => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("SUBPIECE".into()))?;
                let a = self.read_input(op, 0)?;
                let truncate = self.read_input(op, 1)?;
                let shift = truncate.saturating_mul(8);
                let result = if shift >= 64 { 0 } else { a >> shift };
                self.state.write_varnode(out, result);
            }

            OpCode::PopCount => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("POPCOUNT".into()))?;
                let a = self.read_input(op, 0)?;
                self.state.write_varnode(out, a.count_ones() as u64);
            }

            OpCode::LzCount => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("LZCOUNT".into()))?;
                let a = self.read_input(op, 0)?;
                self.state.write_varnode(out, a.leading_zeros() as u64);
            }

            OpCode::BoolNegate => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("BOOL_NEGATE".into()))?;
                let a = self.read_input(op, 0)?;
                self.state.write_varnode(out, if a == 0 { 1 } else { 0 });
            }

            OpCode::BoolAnd => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("BOOL_AND".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, if a != 0 && b != 0 { 1 } else { 0 });
            }

            OpCode::BoolOr => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("BOOL_OR".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, if a != 0 || b != 0 { 1 } else { 0 });
            }

            OpCode::BoolXor => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("BOOL_XOR".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, if (a != 0) ^ (b != 0) { 1 } else { 0 });
            }

            OpCode::FloatAdd => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_ADD".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                let b = f64::from_bits(self.read_input(op, 1)?);
                self.state.write_varnode(out, (a + b).to_bits());
            }
            OpCode::FloatSub => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_SUB".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                let b = f64::from_bits(self.read_input(op, 1)?);
                self.state.write_varnode(out, (a - b).to_bits());
            }
            OpCode::FloatMult => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_MULT".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                let b = f64::from_bits(self.read_input(op, 1)?);
                self.state.write_varnode(out, (a * b).to_bits());
            }
            OpCode::FloatDiv => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_DIV".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                let b = f64::from_bits(self.read_input(op, 1)?);
                self.state.write_varnode(out, (a / b).to_bits());
            }
            OpCode::FloatNeg => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_NEG".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, (-a).to_bits());
            }
            OpCode::FloatAbs => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_ABS".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, a.abs().to_bits());
            }
            OpCode::FloatSqrt => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_SQRT".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, a.sqrt().to_bits());
            }
            OpCode::FloatEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_EQUAL".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                let b = f64::from_bits(self.read_input(op, 1)?);
                self.state.write_varnode(out, if a == b { 1 } else { 0 });
            }
            OpCode::FloatNotEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_NOTEQUAL".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                let b = f64::from_bits(self.read_input(op, 1)?);
                self.state.write_varnode(out, if a != b { 1 } else { 0 });
            }
            OpCode::FloatLess => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_LESS".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                let b = f64::from_bits(self.read_input(op, 1)?);
                self.state.write_varnode(out, if a < b { 1 } else { 0 });
            }
            OpCode::FloatLessEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_LESSEQUAL".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                let b = f64::from_bits(self.read_input(op, 1)?);
                self.state.write_varnode(out, if a <= b { 1 } else { 0 });
            }
            OpCode::FloatNan => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_NAN".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, if a.is_nan() { 1 } else { 0 });
            }
            OpCode::FloatInt2Float => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_INT2FLOAT".into()))?;
                let a = self.read_input(op, 0)? as i64;
                self.state.write_varnode(out, (a as f64).to_bits());
            }
            OpCode::FloatFloat2Float => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_FLOAT2FLOAT".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, a.to_bits());
            }
            OpCode::FloatTrunc => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_TRUNC".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, a.trunc() as i64 as u64);
            }
            OpCode::FloatCeil => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_CEIL".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, a.ceil() as i64 as u64);
            }
            OpCode::FloatFloor => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_FLOOR".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, a.floor() as i64 as u64);
            }
            OpCode::FloatRound => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_ROUND".into()))?;
                let a = f64::from_bits(self.read_input(op, 0)?);
                self.state.write_varnode(out, a.round() as i64 as u64);
            }
            OpCode::IntCarry => {
                // Detect unsigned overflow at the operand size, not u64.
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_CARRY".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8);
                let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
                let a = self.read_input(op, 0)? & mask;
                let b = self.read_input(op, 1)? & mask;
                let sum = a.wrapping_add(b) & mask;
                self.state.write_varnode(out, if sum < a { 1 } else { 0 });
            }
            OpCode::IntSCarry => {
                // Detect signed overflow at the operand size, not i64.
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SCARRY".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8);
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let overflow = match size {
                    1 => (a as i8).checked_add(b as i8).is_none(),
                    2 => (a as i16).checked_add(b as i16).is_none(),
                    4 => (a as i32).checked_add(b as i32).is_none(),
                    _ => (a as i64).checked_add(b as i64).is_none(),
                };
                self.state.write_varnode(out, if overflow { 1 } else { 0 });
            }
            OpCode::IntSBorrow => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SBORROW".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8);
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let overflow = match size {
                    1 => (a as i8).checked_sub(b as i8).is_none(),
                    2 => (a as i16).checked_sub(b as i16).is_none(),
                    4 => (a as i32).checked_sub(b as i32).is_none(),
                    _ => (a as i64).checked_sub(b as i64).is_none(),
                };
                self.state.write_varnode(out, if overflow { 1 } else { 0 });
            }
            OpCode::IntLessEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_LESSEQUAL".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, if a <= b { 1 } else { 0 });
            }
            OpCode::IntSLessEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SLESSEQUAL".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8).min(8);
                let extend = 64 - (size * 8);
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let sa = ((a << extend) as i64) >> extend;
                let sb = ((b << extend) as i64) >> extend;
                self.state.write_varnode(out, if sa <= sb { 1 } else { 0 });
            }
            OpCode::IntDiv => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_DIV".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, a.checked_div(b).unwrap_or(0));
            }
            OpCode::IntSDiv => {
                // Signed divide at the operand width — sign-extend before
                // dividing, otherwise sdiv(-10, 2) on a 32-bit operand becomes
                // sdiv(0xFFFFFFF6, 2) = +2147483643 instead of -5.
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SDIV".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8).min(8);
                let extend = 64 - (size * 8);
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let sa = ((a << extend) as i64) >> extend;
                let sb = ((b << extend) as i64) >> extend;
                self.state.write_varnode(out, sa.checked_div(sb).unwrap_or(0) as u64);
            }
            OpCode::IntRem => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_REM".into()))?;
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                self.state.write_varnode(out, a.checked_rem(b).unwrap_or(0));
            }
            OpCode::IntSRem => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INT_SREM".into()))?;
                let size = op.inputs.first().map(|v| v.size).unwrap_or(8).min(8);
                let extend = 64 - (size * 8);
                let a = self.read_input(op, 0)?;
                let b = self.read_input(op, 1)?;
                let sa = ((a << extend) as i64) >> extend;
                let sb = ((b << extend) as i64) >> extend;
                self.state.write_varnode(out, sa.checked_rem(sb).unwrap_or(0) as u64);
            }
            OpCode::Insert => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("INSERT".into()))?;
                let base = self.read_input(op, 0)?;
                let val = self.read_input(op, 1)?;
                let pos = self.read_input(op, 2)? as u32;
                let sz = if op.inputs.len() > 3 { self.read_input(op, 3)? as u32 } else { 1 };
                let mask = ((1u64 << sz) - 1) << pos;
                self.state.write_varnode(out, (base & !mask) | ((val << pos) & mask));
            }
            OpCode::ZPull => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("ZPULL".into()))?;
                let val = self.read_input(op, 0)?;
                let pos = self.read_input(op, 1)? as u32;
                let sz = if op.inputs.len() > 2 { self.read_input(op, 2)? as u32 } else { 1 };
                self.state.write_varnode(out, (val >> pos) & ((1u64 << sz) - 1));
            }
            OpCode::SPull => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("SPULL".into()))?;
                let val = self.read_input(op, 0)? as i64;
                let pos = self.read_input(op, 1)? as u32;
                let sz = if op.inputs.len() > 2 { self.read_input(op, 2)? as u32 } else { 1 };
                let extracted = (val >> pos) & ((1i64 << sz) - 1);
                let sign_bit = 1i64 << (sz - 1);
                let sign_extended = if extracted & sign_bit != 0 {
                    extracted | !((1i64 << sz) - 1)
                } else {
                    extracted
                };
                self.state.write_varnode(out, sign_extended as u64);
            }
            OpCode::MultiEqual | OpCode::Indirect | OpCode::Cast
            | OpCode::PtrAdd | OpCode::PtrSub | OpCode::SegmentOp
            | OpCode::CPoolRef | OpCode::New => {
                if let Some(out) = &op.output {
                    let val = if !op.inputs.is_empty() { self.read_input(op, 0)? } else { 0 };
                    self.state.write_varnode(out, val);
                }
            }
            OpCode::BranchInd => {
                let target = self.read_input(op, 0)?;
                return Err(EmulatorError::Branch(target));
            }
            OpCode::CallInd => {
                let target = self.read_input(op, 0)?;
                return Err(EmulatorError::Call(target));
            }
        }

        Ok(())
    }

    pub fn execute_ops(&mut self, ops: &[PcodeOp]) -> Result<(), EmulatorError> {
        for op in ops {
            self.execute_op(op)?;
        }
        Ok(())
    }

    fn read_input(&self, op: &PcodeOp, index: usize) -> Result<u64, EmulatorError> {
        let vn = op.input(index).ok_or_else(|| EmulatorError::MissingInput {
            op: op.opcode.name().into(),
            index,
        })?;
        Ok(self.state.read_varnode(vn))
    }
}

impl Default for Emulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gr_core::address::Address;
    use gr_core::pcode::{SeqNum, VarnodeData};
    use smallvec::SmallVec;

    const REG: SpaceId = SpaceId(2);
    const CNST: SpaceId = SpaceId(0);

    fn seq() -> SeqNum {
        SeqNum::new(Address::new(SpaceId(1), 0x1000), 0)
    }

    #[test]
    fn emu_int_left_zero_for_shift_at_or_above_width() {
        // Per P-code spec, shift by amount >= operand bitwidth returns 0,
        // not the wrap-around result Rust's wrapping_shl would produce.
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0x0000_00FF);
        // 4-byte operand shifted by 65: previously the emulator's u64 wrap
        // gave (a << 1) instead of 0.
        emu.state.write_register(0x08, 4, 65);
        let op = PcodeOp {
            opcode: OpCode::IntLeft,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 4)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x08, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0);
        // Exact-width shift (32) should also be 0.
        emu.state.write_register(0x08, 4, 32);
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0);
        // In-range shift still works.
        emu.state.write_register(0x08, 4, 4);
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0xFF0);
    }

    #[test]
    fn emu_int_right_zero_for_shift_at_or_above_width() {
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0xFF00_0000);
        emu.state.write_register(0x08, 4, 64);
        let op = PcodeOp {
            opcode: OpCode::IntRight,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 4)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x08, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0);
    }

    #[test]
    fn emu_int_sright_replicates_sign_bit_above_width() {
        // ASR by >= bitwidth replicates the sign bit at the operand width.
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0xFFFF_FFFF); // -1 as i32
        emu.state.write_register(0x08, 4, 40);
        let op = PcodeOp {
            opcode: OpCode::IntSRight,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 4)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x08, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0xFFFF_FFFF);
        // Non-negative: result = 0.
        emu.state.write_register(0x00, 4, 0x7000_0000);
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0);
    }

    #[test]
    fn emu_int_sright_sign_extends_at_operand_width() {
        // ASR of a 32-bit -2 by 1 must give 32-bit -1, not 0x7FFFFFFF
        // (which would happen if the source were treated as u64 positive).
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0xFFFF_FFFE);
        emu.state.write_register(0x08, 4, 1);
        let op = PcodeOp {
            opcode: OpCode::IntSRight,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 4)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x08, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0xFFFF_FFFF);
    }

    #[test]
    fn emu_int_sless_respects_operand_size() {
        // -1 < 1 at 32-bit width must be true. Previously this used
        // (u64 as i64) directly, treating 0xFFFFFFFF (= -1 as i32) as the
        // positive i64 4294967295, so the comparison returned false and the
        // N flag was wrong throughout the ARM lifter.
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0xFFFF_FFFF); // -1 as i32
        emu.state.write_register(0x04, 4, 1);
        let op = PcodeOp {
            opcode: OpCode::IntSLess,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 1)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x04, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 1), 1);
    }

    #[test]
    fn emu_int_slessequal_respects_operand_size() {
        // -1 <= -1 at 32-bit width is true.
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0xFFFF_FFFF);
        emu.state.write_register(0x04, 4, 0xFFFF_FFFF);
        let op = PcodeOp {
            opcode: OpCode::IntSLessEqual,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 1)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x04, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 1), 1);
    }

    #[test]
    fn emu_int_sdiv_respects_operand_size() {
        // sdiv(-10, 2) at 32-bit width = -5 = 0xFFFFFFFB.
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0xFFFF_FFF6); // -10 as i32
        emu.state.write_register(0x04, 4, 2);
        let op = PcodeOp {
            opcode: OpCode::IntSDiv,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 4)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x04, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0xFFFF_FFFB);
    }

    #[test]
    fn emu_int_carry_respects_operand_size() {
        // 0xFFFFFFFF + 1 at 4-byte width should carry. Previously the
        // emulator checked u64 overflow which never triggered, breaking
        // every flag computation built on IntCarry for 32-bit ARM/SPARC.
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0xFFFF_FFFF);
        emu.state.write_register(0x04, 4, 1);
        let op = PcodeOp {
            opcode: OpCode::IntCarry,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 1)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x04, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 1), 1);

        // 0x0FFFFFFF + 1 should NOT carry at 32-bit width.
        emu.state.write_register(0x00, 4, 0x0FFF_FFFF);
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 1), 0);
    }

    #[test]
    fn emu_int_scarry_respects_operand_size() {
        // INT_MAX_32 + 1 overflows signed at 32-bit width.
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0x7FFF_FFFF);
        emu.state.write_register(0x04, 4, 1);
        let op = PcodeOp {
            opcode: OpCode::IntSCarry,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 1)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x04, 4),
            ]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x10, 1), 1);
    }

    #[test]
    fn emu_copy() {
        let mut emu = Emulator::new();
        let op = PcodeOp {
            opcode: OpCode::Copy,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x00, 8)),
            inputs: SmallVec::from_slice(&[VarnodeData::new(CNST, 42, 8)]),
        };
        emu.execute_op(&op).unwrap();
        assert_eq!(emu.state.read_register(0x00, 8), 42);
    }

    #[test]
    fn emu_add_sub() {
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 8, 100);
        emu.state.write_register(0x08, 8, 30);

        let add = PcodeOp {
            opcode: OpCode::IntAdd,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x00, 8)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 8),
                VarnodeData::new(REG, 0x08, 8),
            ]),
        };
        emu.execute_op(&add).unwrap();
        assert_eq!(emu.state.read_register(0x00, 8), 130);

        let sub = PcodeOp {
            opcode: OpCode::IntSub,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x00, 8)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 8),
                VarnodeData::new(CNST, 50, 8),
            ]),
        };
        emu.execute_op(&sub).unwrap();
        assert_eq!(emu.state.read_register(0x00, 8), 80);
    }

    #[test]
    fn emu_load_store() {
        let mut emu = Emulator::new();
        emu.state.write_register(0x20, 8, 0x8000);

        // STORE [RSP] = 0xDEAD
        let store = PcodeOp {
            opcode: OpCode::Store,
            seq: seq(),
            output: None,
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(CNST, 1, 4),
                VarnodeData::new(REG, 0x20, 8),
                VarnodeData::new(CNST, 0xDEAD, 8),
            ]),
        };
        emu.execute_op(&store).unwrap();
        assert_eq!(emu.state.read_memory(0x8000, 8), 0xDEAD);

        // RAX = LOAD [RSP]
        let load = PcodeOp {
            opcode: OpCode::Load,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x00, 8)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(CNST, 1, 4),
                VarnodeData::new(REG, 0x20, 8),
            ]),
        };
        emu.execute_op(&load).unwrap();
        assert_eq!(emu.state.read_register(0x00, 8), 0xDEAD);
    }

    #[test]
    fn emu_xor_self_zeros() {
        let mut emu = Emulator::new();
        emu.state.write_register(0x00, 4, 0x12345678);

        let xor = PcodeOp {
            opcode: OpCode::IntXor,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x00, 4)),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(REG, 0x00, 4),
                VarnodeData::new(REG, 0x00, 4),
            ]),
        };
        emu.execute_op(&xor).unwrap();
        assert_eq!(emu.state.read_register(0x00, 4), 0);
    }

    #[test]
    fn emu_comparison() {
        let mut emu = Emulator::new();
        let out = VarnodeData::new(SpaceId(3), 0, 1);

        let eq = PcodeOp {
            opcode: OpCode::IntEqual,
            seq: seq(),
            output: Some(out),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(CNST, 5, 8),
                VarnodeData::new(CNST, 5, 8),
            ]),
        };
        emu.execute_op(&eq).unwrap();
        assert_eq!(emu.state.read_varnode(&out), 1);

        let neq = PcodeOp {
            opcode: OpCode::IntEqual,
            seq: seq(),
            output: Some(out),
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(CNST, 5, 8),
                VarnodeData::new(CNST, 6, 8),
            ]),
        };
        emu.execute_op(&neq).unwrap();
        assert_eq!(emu.state.read_varnode(&out), 0);
    }

    #[test]
    fn emu_branch() {
        let mut emu = Emulator::new();
        let br = PcodeOp {
            opcode: OpCode::Branch,
            seq: seq(),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(SpaceId(1), 0x2000, 8)]),
        };
        match emu.execute_op(&br) {
            Err(EmulatorError::Branch(0x2000)) => {}
            other => panic!("expected Branch(0x2000), got {:?}", other),
        }
    }

    #[test]
    fn emu_cbranch_taken() {
        let mut emu = Emulator::new();
        let cbr = PcodeOp {
            opcode: OpCode::CBranch,
            seq: seq(),
            output: None,
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(SpaceId(1), 0x3000, 8),
                VarnodeData::new(CNST, 1, 1),
            ]),
        };
        match emu.execute_op(&cbr) {
            Err(EmulatorError::Branch(0x3000)) => {}
            other => panic!("expected Branch(0x3000), got {:?}", other),
        }
    }

    #[test]
    fn emu_cbranch_not_taken() {
        let mut emu = Emulator::new();
        let cbr = PcodeOp {
            opcode: OpCode::CBranch,
            seq: seq(),
            output: None,
            inputs: SmallVec::from_slice(&[
                VarnodeData::new(SpaceId(1), 0x3000, 8),
                VarnodeData::new(CNST, 0, 1),
            ]),
        };
        emu.execute_op(&cbr).unwrap();
    }

    #[test]
    fn emu_return() {
        let mut emu = Emulator::new();
        let ret = PcodeOp {
            opcode: OpCode::Return,
            seq: seq(),
            output: None,
            inputs: SmallVec::from_slice(&[VarnodeData::new(CNST, 0x9999, 8)]),
        };
        match emu.execute_op(&ret) {
            Err(EmulatorError::Return(0x9999)) => {}
            other => panic!("expected Return, got {:?}", other),
        }
    }
}
