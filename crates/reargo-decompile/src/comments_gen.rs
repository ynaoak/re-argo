use crate::ssa::SsaFunction;
use reargo_core::pcode::OpCode;

pub struct GeneratedComment {
    pub address: u64,
    pub text: String,
}

pub fn generate_comments(func: &SsaFunction) -> Vec<GeneratedComment> {
    let mut comments = Vec::new();

    for op in &func.ops {
        if op.dead { continue; }
        match op.opcode {
            OpCode::Call => {
                if let Some(target_vn) = op.inputs.first() {
                    let target = func.varnodes[*target_vn as usize].data.offset;
                    comments.push(GeneratedComment {
                        address: op.address,
                        text: format!("// call 0x{:x}", target),
                    });
                }
            }
            OpCode::Return => {
                comments.push(GeneratedComment {
                    address: op.address,
                    text: "// function returns here".into(),
                });
            }
            OpCode::CBranch => {
                comments.push(GeneratedComment {
                    address: op.address,
                    text: "// conditional branch".into(),
                });
            }
            _ => {}
        }
    }
    comments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_comment_type() {
        let c = GeneratedComment { address: 0x1000, text: "// test".into() };
        assert!(c.text.starts_with("//"));
    }
}
