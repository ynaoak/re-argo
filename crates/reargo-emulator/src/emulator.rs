use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, PcodeOp};

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
                let in_vn = op.input(0).ok_or_else(|| EmulatorError::MissingInput { op: "COPY".into(), index: 0 })?;
                if out.size > 8 {
                    let v = self.state.read_wide(in_vn);
                    self.state.write_wide(out, v);
                } else {
                    let src = self.read_input(op, 0)?;
                    self.state.write_varnode(out, src);
                }
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
                // a 128-bit product (WS86: the 64-bit `mul` / `imul` widen to 16 bytes)
                if out.size > 8 {
                    let (a, b) = (op.input(0), op.input(1));
                    let (Some(a), Some(b)) = (a, b) else { return Err(EmulatorError::MissingInput { op: "INT_MULT".into(), index: 1 }) };
                    let v = self.state.read_wide(a).wrapping_mul(self.state.read_wide(b));
                    self.state.write_wide(out, v);
                    return Ok(());
                }
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
                // (to 16 bytes: the upper half is zero)
                self.state.write_wide(out, u128::from(a));
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
                // (to 16 bytes: the upper half is the sign)
                self.state.write_wide(out, sign_extended as i64 as i128 as u128);
            }

            OpCode::Load => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("LOAD".into()))?;
                let _space_id = self.read_input(op, 0)?;
                let addr = self.read_input(op, 1)?;
                if out.size > 8 {
                    let v = self.state.read_wide(&reargo_core::pcode::VarnodeData::new(SpaceId::RAM, addr, out.size));
                    self.state.write_wide(out, v);
                } else {
                    let val = self.state.read_memory(addr, out.size);
                    self.state.write_varnode(out, val);
                }
            }

            OpCode::Store => {
                let space_id = self.read_input(op, 0)?;
                let addr = self.read_input(op, 1)?;
                let in_vn = op.input(2).ok_or_else(|| EmulatorError::MissingInput { op: "STORE".into(), index: 2 })?;
                let val = self.state.read_varnode(in_vn);
                if in_vn.size > 8 {
                    let v = self.state.read_wide(in_vn);
                    self.state.write_wide(&reargo_core::pcode::VarnodeData::new(SpaceId(space_id as u32), addr, in_vn.size), v);
                } else if space_id == 1 {
                    self.state.write_memory(addr, in_vn.size, val);
                } else {
                    self.state.write_varnode(
                        &reargo_core::pcode::VarnodeData::new(SpaceId(space_id as u32), addr, in_vn.size),
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

            // the lifter's named intrinsics with a defined value (WS84); others are opaque
            OpCode::CallOther => {
                use reargo_core::pcode::intrinsic;
                if let (Some(out), Some(tag)) = (op.output.as_ref(), op.input(0))
                    && tag.space == SpaceId::CONST
                    && let Some(v) = self.packed(tag.offset, &op.inputs[1..])
                {
                    self.state.write_wide(out, v);
                } else if let (Some(out), Some(tag), Some(src)) = (op.output.as_ref(), op.input(0), op.input(1))
                    && tag.space == SpaceId::CONST
                {
                    let bits = src.size.min(8) * 8;
                    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                    let x = self.state.read_varnode(src) & mask;
                    let value = match tag.offset {
                        // bsf / bsr leave the destination as it was for a zero source
                        intrinsic::BSF if x != 0 => Some(u64::from(x.trailing_zeros())),
                        intrinsic::BSR if x != 0 => Some(u64::from(63 - x.leading_zeros())),
                        intrinsic::TZCNT => Some(if x == 0 { u64::from(bits) } else { u64::from(x.trailing_zeros()) }),
                        intrinsic::BSWAP => Some(x.swap_bytes() >> (64 - bits)),
                        _ => None,
                    };
                    if let Some(v) = value {
                        self.state.write_varnode(out, v);
                    }
                }
            }

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
                let in_vn = op.input(0).ok_or_else(|| EmulatorError::MissingInput { op: "SUBPIECE".into(), index: 0 })?;
                let a = self.state.read_wide(in_vn);
                let truncate = self.read_input(op, 1)?;
                let shift = truncate.saturating_mul(8);
                let result = if shift >= 128 { 0 } else { a >> shift };
                self.state.write_wide(out, result);
            }

            OpCode::PopCount => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("POPCOUNT".into()))?;
                let a = self.read_input(op, 0)?;
                self.state.write_varnode(out, a.count_ones() as u64);
            }

            OpCode::LzCount => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("LZCOUNT".into()))?;
                // at the input's width, not 64 bits
                let bits = op.inputs.first().map(|v| v.size.min(8)).unwrap_or(8) * 8;
                let a = self.read_input(op, 0)?;
                let lz = if bits >= 64 { a.leading_zeros() } else { (a << (64 - bits)).leading_zeros().min(bits) };
                self.state.write_varnode(out, u64::from(lz));
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
                let a = self.read_float(op, 0)?;
                let b = self.read_float(op, 1)?;
                self.write_float(out, a + b);
            }
            OpCode::FloatSub => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_SUB".into()))?;
                let a = self.read_float(op, 0)?;
                let b = self.read_float(op, 1)?;
                self.write_float(out, a - b);
            }
            OpCode::FloatMult => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_MULT".into()))?;
                let a = self.read_float(op, 0)?;
                let b = self.read_float(op, 1)?;
                self.write_float(out, a * b);
            }
            OpCode::FloatDiv => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_DIV".into()))?;
                let a = self.read_float(op, 0)?;
                let b = self.read_float(op, 1)?;
                self.write_float(out, a / b);
            }
            OpCode::FloatNeg => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_NEG".into()))?;
                let a = self.read_float(op, 0)?;
                self.write_float(out, -a);
            }
            OpCode::FloatAbs => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_ABS".into()))?;
                let a = self.read_float(op, 0)?;
                self.write_float(out, a.abs());
            }
            OpCode::FloatSqrt => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_SQRT".into()))?;
                let a = self.read_float(op, 0)?;
                self.write_float(out, a.sqrt());
            }
            OpCode::FloatEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_EQUAL".into()))?;
                let a = self.read_float(op, 0)?;
                let b = self.read_float(op, 1)?;
                self.state.write_varnode(out, if a == b { 1 } else { 0 });
            }
            OpCode::FloatNotEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_NOTEQUAL".into()))?;
                let a = self.read_float(op, 0)?;
                let b = self.read_float(op, 1)?;
                self.state.write_varnode(out, if a != b { 1 } else { 0 });
            }
            OpCode::FloatLess => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_LESS".into()))?;
                let a = self.read_float(op, 0)?;
                let b = self.read_float(op, 1)?;
                self.state.write_varnode(out, if a < b { 1 } else { 0 });
            }
            OpCode::FloatLessEqual => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_LESSEQUAL".into()))?;
                let a = self.read_float(op, 0)?;
                let b = self.read_float(op, 1)?;
                self.state.write_varnode(out, if a <= b { 1 } else { 0 });
            }
            OpCode::FloatNan => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_NAN".into()))?;
                let a = self.read_float(op, 0)?;
                self.state.write_varnode(out, if a.is_nan() { 1 } else { 0 });
            }
            OpCode::FloatInt2Float => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_INT2FLOAT".into()))?;
                // a signed integer of the input's width
                let size = op.inputs.first().map(|v| v.size.min(8)).unwrap_or(8);
                let extend = 64 - size * 8;
                let a = ((self.read_input(op, 0)? << extend) as i64) >> extend;
                self.write_float(out, a as f64);
            }
            OpCode::FloatFloat2Float => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_FLOAT2FLOAT".into()))?;
                let a = self.read_float(op, 0)?;
                self.write_float(out, a);
            }
            OpCode::FloatTrunc => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_TRUNC".into()))?;
                let a = self.read_float(op, 0)?;
                self.state.write_varnode(out, a.trunc() as i64 as u64);
            }
            OpCode::FloatCeil => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_CEIL".into()))?;
                let a = self.read_float(op, 0)?;
                self.state.write_varnode(out, a.ceil() as i64 as u64);
            }
            OpCode::FloatFloor => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_FLOOR".into()))?;
                let a = self.read_float(op, 0)?;
                self.state.write_varnode(out, a.floor() as i64 as u64);
            }
            OpCode::FloatRound => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("FLOAT_ROUND".into()))?;
                let a = self.read_float(op, 0)?;
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
            OpCode::Select => {
                let out = op.output.as_ref().ok_or_else(|| EmulatorError::MissingOutput("SELECT".into()))?;
                let c = self.read_input(op, 0)?;
                let v = if c != 0 { self.read_input(op, 1)? } else { self.read_input(op, 2)? };
                self.state.write_varnode(out, v);
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

    /// A float input: 4 bytes are an f32, else an f64 (WS84: a 4-byte float was read as the
    /// low bits of an f64).
    fn read_float(&self, op: &PcodeOp, index: usize) -> Result<f64, EmulatorError> {
        let bits = self.read_input(op, index)?;
        Ok(match op.input(index).map(|v| v.size) {
            Some(4) => f64::from(f32::from_bits(bits as u32)),
            _ => f64::from_bits(bits),
        })
    }

    /// Write a float result at the output's width (4 bytes = f32).
    fn write_float(&mut self, out: &reargo_core::pcode::VarnodeData, v: f64) {
        let bits = if out.size == 4 { u64::from((v as f32).to_bits()) } else { v.to_bits() };
        self.state.write_varnode(out, bits);
    }

    /// The value of a lane-precise SIMD intrinsic (`pcmpeqb`, `pmovmskb`, the packed integer
    /// ops of [`reargo_core::pcode::intrinsic::PACKED`]), or None for another tag. `args` are the
    /// op's inputs after the tag; a constant last one is the immediate of a shuffle.
    fn packed(&self, tag: u64, args: &[reargo_core::pcode::VarnodeData]) -> Option<u128> {
        use reargo_core::pcode::intrinsic;
        let x = self.state.read_wide(args.first()?);
        if tag == intrinsic::PMOVMSKB {
            return Some((0..16).fold(0u128, |m, i| m | ((x >> (i * 8 + 7)) & 1) << i));
        }
        let name = if tag == intrinsic::PCMPEQB { "pcmpeqb" } else { intrinsic::name(tag).filter(|_| tag >= intrinsic::PACKED_BASE)? };
        let (imm, rest) = match args.split_last() {
            Some((last, rest)) if last.space == SpaceId::CONST && args.len() > 1 => (last.offset, rest),
            _ => (0, args),
        };
        let y = rest.get(1).map_or(0, |v| self.state.read_wide(v));
        Some(packed_op(name, x, y, imm))
    }

    fn read_input(&self, op: &PcodeOp, index: usize) -> Result<u64, EmulatorError> {
        let vn = op.input(index).ok_or_else(|| EmulatorError::MissingInput {
            op: op.opcode.name().into(),
            index,
        })?;
        Ok(self.state.read_varnode(vn))
    }
}

/// `name(x, y)` on 16-byte vectors, lane by lane as the SSE instruction does (`imm`: a
/// shuffle's immediate).
fn packed_op(name: &str, x: u128, y: u128, imm: u64) -> u128 {
    // element `i` of `n` bytes
    let el = |v: u128, n: u32, i: u32| -> u128 { (v >> (i * n * 8)) & (u128::MAX >> (128 - n * 8)) };
    let from = |n: u32, f: &dyn Fn(u32) -> u128| -> u128 { (0..16 / n).fold(0u128, |acc, i| acc | f(i) << (i * n * 8)) };
    let unpack = |n: u32, high: bool| -> u128 {
        let base = if high { 8 / n } else { 0 };
        from(n, &|i| if i % 2 == 0 { el(x, n, base + i / 2) } else { el(y, n, base + i / 2) })
    };
    let imm = imm as u32;
    match name {
        "punpcklbw" => return unpack(1, false),
        "punpcklwd" => return unpack(2, false),
        "punpckldq" | "unpcklps" => return unpack(4, false),
        "punpcklqdq" | "unpcklpd" => return unpack(8, false),
        "punpckhbw" => return unpack(1, true),
        "punpckhwd" => return unpack(2, true),
        "punpckhdq" | "unpckhps" => return unpack(4, true),
        "punpckhqdq" | "unpckhpd" => return unpack(8, true),
        "pshufb" => return from(1, &|i| if el(y, 1, i) & 0x80 != 0 { 0 } else { el(x, 1, (el(y, 1, i) & 0x0f) as u32) }),
        "movhlps" => return el(y, 8, 1) | el(x, 8, 1) << 64,
        "movlhps" => return el(x, 8, 0) | el(y, 8, 0) << 64,
        "pshufd" => return from(4, &|i| el(x, 4, (imm >> (2 * i)) & 3)),
        "pshuflw" => return from(2, &|i| if i < 4 { el(x, 2, (imm >> (2 * i)) & 3) } else { el(x, 2, i) }),
        "pshufhw" => return from(2, &|i| if i < 4 { el(x, 2, i) } else { el(x, 2, 4 + ((imm >> (2 * (i - 4))) & 3)) }),
        "shufps" => return from(4, &|i| if i < 2 { el(x, 4, (imm >> (2 * i)) & 3) } else { el(y, 4, (imm >> (2 * i)) & 3) }),
        "shufpd" => return el(x, 8, imm & 1) | el(y, 8, (imm >> 1) & 1) << 64,
        "pinsrw" => {
            let k = (imm & 7) * 16;
            return (x & !(0xffffu128 << k)) | (y & 0xffff) << k;
        }
        "pextrw" => return el(x, 2, imm & 7),
        // the count: the immediate, or the low quadword of the second register
        "psllw" | "pslld" | "psllq" | "psrlw" | "psrld" | "psrlq" | "psraw" | "psrad" => {
            let n = match name.as_bytes()[4] {
                b'w' => 2,
                b'd' => 4,
                _ => 8,
            };
            let count = if imm != 0 { u64::from(imm) } else { y as u64 };
            let bits = u64::from(n * 8);
            return from(n, &|i| {
                let v = el(x, n, i);
                let r = match &name[..4] {
                    "psll" if count < bits => v << count,
                    "psrl" if count < bits => v >> count,
                    "psra" => {
                        let k = 128 - bits as u32;
                        (((v << k) as i128) >> (k + count.min(bits - 1) as u32)) as u128
                    }
                    _ => 0,
                };
                r & (u128::MAX >> (128 - n * 8))
            });
        }
        "pslldq" => return if imm < 16 { x << (imm * 8) } else { 0 },
        "psrldq" => return if imm < 16 { x >> (imm * 8) } else { 0 },
        "pmuludq" => return from(8, &|i| el(x, 4, 2 * i) * el(y, 4, 2 * i)),
        "movhps" => return el(x, 8, 0) | el(y, 8, 0) << 64,
        _ => {}
    }
    if let Some(v) = packed_float(name, x, y, imm) {
        return v;
    }
    // lanes of `n` bytes: f(a, b) on each, the operands zero-extended
    fn lanes(x: u128, y: u128, n: u32, f: impl Fn(u64, u64) -> u64) -> u128 {
        let bits = n * 8;
        let mask = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
        (0..16 / n).fold(0u128, |acc, i| {
            let s = i * bits;
            let (a, b) = ((x >> s) as u64 & mask, (y >> s) as u64 & mask);
            acc | u128::from(f(a, b) & mask) << s
        })
    }
    let sx = |v: u64, n: u32| -> i64 {
        let k = 64 - n * 8;
        ((v << k) as i64) >> k
    };
    let all = |n: u32| if n == 8 { u64::MAX } else { (1u64 << (n * 8)) - 1 };
    let sat_s = |v: i64, n: u32| -> u64 {
        let k = n * 8 - 1;
        v.clamp(-(1i64 << k), (1i64 << k) - 1) as u64
    };
    let sat_u = |v: i64, n: u32| -> u64 { v.clamp(0, (1i64 << (n * 8)) - 1) as u64 };
    let n: u32 = match name.as_bytes()[name.len() - 1] {
        b'b' => 1,
        b'w' => 2,
        b'd' => 4,
        _ => 8,
    };
    match name {
        "paddb" | "paddw" | "paddd" | "paddq" => lanes(x, y, n, |a, b| a.wrapping_add(b)),
        "psubb" | "psubw" | "psubd" | "psubq" => lanes(x, y, n, |a, b| a.wrapping_sub(b)),
        "paddusb" | "paddusw" => lanes(x, y, n, |a, b| (a + b).min(all(n))),
        "psubusb" | "psubusw" => lanes(x, y, n, |a, b| a.saturating_sub(b)),
        "paddsb" | "paddsw" => lanes(x, y, n, |a, b| sat_s(sx(a, n) + sx(b, n), n)),
        "psubsb" | "psubsw" => lanes(x, y, n, |a, b| sat_s(sx(a, n) - sx(b, n), n)),
        "pminub" | "pminuw" | "pminud" => lanes(x, y, n, |a, b| a.min(b)),
        "pmaxub" | "pmaxuw" | "pmaxud" => lanes(x, y, n, |a, b| a.max(b)),
        "pminsb" | "pminsw" | "pminsd" => lanes(x, y, n, |a, b| if sx(a, n) < sx(b, n) { a } else { b }),
        "pmaxsb" | "pmaxsw" | "pmaxsd" => lanes(x, y, n, |a, b| if sx(a, n) > sx(b, n) { a } else { b }),
        "pcmpeqb" | "pcmpeqw" | "pcmpeqd" | "pcmpeqq" => lanes(x, y, n, |a, b| if a == b { u64::MAX } else { 0 }),
        "pcmpgtb" | "pcmpgtw" | "pcmpgtd" | "pcmpgtq" => lanes(x, y, n, |a, b| if sx(a, n) > sx(b, n) { u64::MAX } else { 0 }),
        "pavgb" | "pavgw" => lanes(x, y, n, |a, b| (a + b + 1) >> 1),
        "pmullw" | "pmulld" => lanes(x, y, n, |a, b| a.wrapping_mul(b)),
        "pmulhw" => lanes(x, y, 2, |a, b| ((sx(a, 2) * sx(b, 2)) >> 16) as u64),
        "pmulhuw" => lanes(x, y, 2, |a, b| (a * b) >> 16),
        "pmaddwd" => lanes(x, y, 4, |a, b| {
            let p = |s: u32| sx((a >> s) & 0xffff, 2) * sx((b >> s) & 0xffff, 2);
            (p(0) + p(16)) as u64
        }),
        "psadbw" => lanes(x, y, 8, |a, b| (0..8).map(|i| u64::from(((a >> (i * 8)) as u8).abs_diff((b >> (i * 8)) as u8))).sum()),
        // narrow both operands' lanes with saturation: x's into the low half, y's into the high
        "packsswb" | "packuswb" | "packssdw" | "packusdw" => {
            let (from, signed) = match name {
                "packsswb" => (2, true),
                "packuswb" => (2, false),
                "packssdw" => (4, true),
                _ => (4, false),
            };
            let to = from / 2;
            let per = 16 / from;
            let mut out = 0u128;
            for (k, v) in [x, y].into_iter().enumerate() {
                for i in 0..per {
                    let lane = sx((v >> (i * from * 8)) as u64 & all(from), from);
                    let r = if signed { sat_s(lane, to) } else { sat_u(lane, to) } & all(to);
                    out |= u128::from(r) << ((k as u32 * per + i) * to * 8);
                }
            }
            out
        }
        _ => x,
    }
}

/// The packed float ops (WS87), lane by lane as SSE computes them: a NaN operand gives the
/// first NaN operand quieted, `min`/`max` the second operand when unordered or both zero, a
/// conversion out of range (or of a NaN) the integer `0x80000000`.
fn packed_float(name: &str, x: u128, y: u128, imm: u32) -> Option<u128> {
    let el = |v: u128, n: u32, i: u32| -> u64 { ((v >> (i * n * 8)) & (u128::MAX >> (128 - n * 8))) as u64 };
    let from = |n: u32, f: &dyn Fn(u32) -> u64| -> u128 {
        let mask = if n == 8 { u64::MAX } else { (1u64 << (n * 8)) - 1 };
        (0..16 / n).fold(0u128, |acc, i| acc | u128::from(f(i) & mask) << (i * n * 8))
    };
    let s = |v: u64| f32::from_bits(v as u32);
    let d = f64::from_bits;
    // (arithmetic: the first NaN operand, quieted; else the CPU's own result)
    let arith_s = |a: f32, b: f32, op: fn(f32, f32) -> f32| -> u64 {
        u64::from(if a.is_nan() { a.to_bits() | 0x40_0000 } else if b.is_nan() { b.to_bits() | 0x40_0000 } else { op(a, b).to_bits() })
    };
    let arith_d = |a: f64, b: f64, op: fn(f64, f64) -> f64| -> u64 {
        if a.is_nan() { a.to_bits() | 1 << 51 } else if b.is_nan() { b.to_bits() | 1 << 51 } else { op(a, b).to_bits() }
    };
    let cmp = |a: f64, b: f64| -> bool {
        match imm & 7 {
            0 => a == b,
            1 => a < b,
            2 => a <= b,
            3 => a.is_nan() || b.is_nan(),
            4 => a != b,
            // (not less / not less-or-equal: true when unordered)
            5 => a >= b || a.is_nan() || b.is_nan(),
            6 => a > b || a.is_nan() || b.is_nan(),
            _ => !(a.is_nan() || b.is_nan()),
        }
    };
    let to_i32 = |v: f64, round: bool| -> u64 {
        let v = if round { v.round_ties_even() } else { v.trunc() };
        u64::from(if !(-2147483648.0..=2147483647.0).contains(&v) { 0x8000_0000 } else { v as i32 as u32 })
    };
    let quiet_s = |a: f32| if a.is_nan() { a.to_bits() | 0x40_0000 } else { a.sqrt().to_bits() };
    Some(match name {
        "addps" => from(4, &|i| arith_s(s(el(x, 4, i)), s(el(y, 4, i)), |a, b| a + b)),
        "subps" => from(4, &|i| arith_s(s(el(x, 4, i)), s(el(y, 4, i)), |a, b| a - b)),
        "mulps" => from(4, &|i| arith_s(s(el(x, 4, i)), s(el(y, 4, i)), |a, b| a * b)),
        "divps" => from(4, &|i| arith_s(s(el(x, 4, i)), s(el(y, 4, i)), |a, b| a / b)),
        "minps" => from(4, &|i| if s(el(x, 4, i)) < s(el(y, 4, i)) { el(x, 4, i) } else { el(y, 4, i) }),
        "maxps" => from(4, &|i| if s(el(x, 4, i)) > s(el(y, 4, i)) { el(x, 4, i) } else { el(y, 4, i) }),
        "addpd" => from(8, &|i| arith_d(d(el(x, 8, i)), d(el(y, 8, i)), |a, b| a + b)),
        "subpd" => from(8, &|i| arith_d(d(el(x, 8, i)), d(el(y, 8, i)), |a, b| a - b)),
        "mulpd" => from(8, &|i| arith_d(d(el(x, 8, i)), d(el(y, 8, i)), |a, b| a * b)),
        "divpd" => from(8, &|i| arith_d(d(el(x, 8, i)), d(el(y, 8, i)), |a, b| a / b)),
        "minpd" => from(8, &|i| if d(el(x, 8, i)) < d(el(y, 8, i)) { el(x, 8, i) } else { el(y, 8, i) }),
        "maxpd" => from(8, &|i| if d(el(x, 8, i)) > d(el(y, 8, i)) { el(x, 8, i) } else { el(y, 8, i) }),
        "sqrtps" => from(4, &|i| u64::from(quiet_s(s(el(x, 4, i))))),
        "sqrtpd" => from(8, &|i| {
            let a = d(el(x, 8, i));
            if a.is_nan() { a.to_bits() | 1 << 51 } else { a.sqrt().to_bits() }
        }),
        "cvtdq2ps" => from(4, &|i| u64::from((el(x, 4, i) as u32 as i32 as f32).to_bits())),
        "cvttps2dq" => from(4, &|i| to_i32(f64::from(s(el(x, 4, i))), false)),
        "cvtps2dq" => from(4, &|i| to_i32(f64::from(s(el(x, 4, i))), true)),
        "cvtps2pd" => from(8, &|i| {
            let a = s(el(x, 4, i));
            if a.is_nan() {
                // (the payload moves to the top of the wider fraction, quieted)
                let b = a.to_bits();
                (u64::from(b >> 31) << 63) | 0x7ff8_0000_0000_0000 | (u64::from(b & 0x3f_ffff) << 29)
            } else {
                f64::from(a).to_bits()
            }
        }),
        "cvtpd2ps" => from(4, &|i| {
            if i >= 2 {
                return 0;
            }
            let a = d(el(x, 8, i));
            u64::from(if a.is_nan() {
                let b = a.to_bits();
                ((b >> 63) as u32) << 31 | 0x7fc0_0000 | ((b >> 29) as u32 & 0x3f_ffff)
            } else {
                (a as f32).to_bits()
            })
        }),
        "cvttpd2dq" | "cvtpd2dq" => from(4, &|i| if i >= 2 { 0 } else { to_i32(d(el(x, 8, i)), name == "cvtpd2dq") }),
        "cvtdq2pd" => from(8, &|i| (el(x, 4, i) as u32 as i32 as f64).to_bits()),
        "cmpps" => from(4, &|i| if cmp(f64::from(s(el(x, 4, i))), f64::from(s(el(y, 4, i)))) { u64::MAX } else { 0 }),
        "cmppd" => from(8, &|i| if cmp(d(el(x, 8, i)), d(el(y, 8, i))) { u64::MAX } else { 0 }),
        _ => return None,
    })
}

impl Default for Emulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_core::address::Address;
    use reargo_core::pcode::{SeqNum, VarnodeData};
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

    /// LZCOUNT counts at the input's width (WS84: a 32-bit 1 gave 63, the 64-bit count).
    #[test]
    fn emu_lzcount_at_input_width() {
        let mut emu = Emulator::new();
        let op = |size| PcodeOp {
            opcode: OpCode::LzCount,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, 4)),
            inputs: SmallVec::from_slice(&[VarnodeData::new(REG, 0x00, size)]),
        };
        for (size, value, want) in [(4, 1, 31), (4, 0, 32), (2, 0x80, 8), (8, 1, 63), (8, 0, 64), (1, 0x10, 3)] {
            emu.state.write_register(0x00, 8, value);
            emu.execute_op(&op(size)).unwrap();
            assert_eq!(emu.state.read_register(0x10, 4), want, "lzcount size {size} of {value:#x}");
        }
    }

    /// The lifter's named intrinsics with a defined value are evaluated (WS84); bsf/bsr keep
    /// the destination for a zero source.
    #[test]
    fn emu_evaluates_bit_intrinsics() {
        use reargo_core::pcode::intrinsic;
        let call = |tag, size| PcodeOp {
            opcode: OpCode::CallOther,
            seq: seq(),
            output: Some(VarnodeData::new(REG, 0x10, size)),
            inputs: SmallVec::from_slice(&[VarnodeData::new(CNST, tag, 8), VarnodeData::new(REG, 0x00, size)]),
        };
        let mut emu = Emulator::new();
        for (tag, size, x, want) in [
            (intrinsic::BSF, 4, 0x50u64, 4u64),
            (intrinsic::BSR, 4, 0x50, 6),
            (intrinsic::BSR, 8, 1 << 40, 40),
            (intrinsic::TZCNT, 4, 0, 32),
            (intrinsic::TZCNT, 2, 0x8000, 15),
            (intrinsic::BSWAP, 4, 0x1122_3344, 0x4433_2211),
            (intrinsic::BSWAP, 8, 0x0102_0304_0506_0708, 0x0807_0605_0403_0201),
        ] {
            emu.state.write_register(0x00, 8, x);
            emu.state.write_register(0x10, 8, 0xdead);
            emu.execute_op(&call(tag, size)).unwrap();
            assert_eq!(emu.state.read_register(0x10, size), want, "tag {tag:#x} of {x:#x}");
        }
        emu.state.write_register(0x00, 8, 0);
        emu.state.write_register(0x10, 8, 0x1234);
        emu.execute_op(&call(intrinsic::BSF, 4)).unwrap();
        assert_eq!(emu.state.read_register(0x10, 4), 0x1234, "bsf of 0 keeps the destination");
    }

    /// 4-byte float ops are f32 (WS84: they were read as the low bits of an f64), and
    /// INT2FLOAT sign-extends its input's width.
    #[test]
    fn emu_float_ops_at_f32_width() {
        let mut emu = Emulator::new();
        let f = |off| VarnodeData::new(REG, off, 4);
        emu.state.write_register(0x1200, 4, u64::from(1.5f32.to_bits()));
        emu.state.write_register(0x1210, 4, u64::from(2.25f32.to_bits()));
        let bin = |opcode| PcodeOp { opcode, seq: seq(), output: Some(f(0x1220)), inputs: SmallVec::from_slice(&[f(0x1200), f(0x1210)]) };
        emu.execute_op(&bin(OpCode::FloatMult)).unwrap();
        assert_eq!(emu.state.read_register(0x1220, 4), u64::from(3.375f32.to_bits()));
        let less = PcodeOp { opcode: OpCode::FloatLess, seq: seq(), output: Some(VarnodeData::new(REG, 0x300, 1)), inputs: SmallVec::from_slice(&[f(0x1200), f(0x1210)]) };
        emu.execute_op(&less).unwrap();
        assert_eq!(emu.state.read_register(0x300, 1), 1);
        emu.state.write_register(0x00, 4, (-3i32) as u32 as u64);
        let conv = PcodeOp { opcode: OpCode::FloatInt2Float, seq: seq(), output: Some(f(0x1220)), inputs: SmallVec::from_slice(&[VarnodeData::new(REG, 0x00, 4)]) };
        emu.execute_op(&conv).unwrap();
        assert_eq!(emu.state.read_register(0x1220, 4), u64::from((-3.0f32).to_bits()));
    }
}
