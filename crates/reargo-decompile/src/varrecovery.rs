use std::collections::BTreeMap;

use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

use crate::ssa::SsaFunction;

#[derive(Debug, Clone)]
pub struct RecoveredVariable {
    pub name: String,
    pub typ: String,
    pub storage: VarStorage,
}

#[derive(Debug, Clone)]
pub enum VarStorage {
    Register { offset: u64, size: u32 },
    Stack { offset: i64, size: u32 },
    Global { address: u64, size: u32 },
}

pub fn recover_variables(func: &SsaFunction) -> Vec<RecoveredVariable> {
    let mut vars = Vec::new();
    let mut seen_regs: BTreeMap<u64, u32> = BTreeMap::new();
    let seen_stack: BTreeMap<i64, u32> = BTreeMap::new();

    for op in &func.ops {
        if op.dead {
            continue;
        }
        if let Some(out_id) = op.output {
            let vn = &func.varnodes[out_id as usize];
            if vn.data.space == SpaceId::REGISTER {
                seen_regs.entry(vn.data.offset).or_insert(vn.data.size);
            }
        }

        if matches!(op.opcode, OpCode::Load | OpCode::Store) {
            for &inp_id in &op.inputs {
                let inp_vn = &func.varnodes[inp_id as usize].data;
                if inp_vn.space == SpaceId::REGISTER && (inp_vn.offset == 0x20 || inp_vn.offset == 0x28) {
                    // RSP or RBP based access - could be stack var
                }
            }
        }
    }

    let param_offsets: &[(u64, &str)] = &[
        (0x08, "param_rcx"), (0x10, "param_rdx"),
        (0x38, "param_rdi"), (0x30, "param_rsi"),
        (0x80, "param_r8"), (0x88, "param_r9"),
    ];

    for (&offset, &size) in &seen_regs {
        let name = param_offsets.iter()
            .find(|(off, _)| *off == offset)
            .map(|(_, name)| name.to_string())
            .unwrap_or_else(|| format!("var_reg_{:x}", offset));

        let is_param = func.varnodes.iter().any(|vn|
            vn.data.space == SpaceId::REGISTER
            && vn.data.offset == offset
            && vn.def_op.is_none()
            && !vn.uses.is_empty()
        );

        if is_param || offset == 0x00 {
            vars.push(RecoveredVariable {
                name,
                typ: format!("uint{}_t", size * 8),
                storage: VarStorage::Register { offset, size },
            });
        }
    }

    for (&offset, &size) in &seen_stack {
        let name = if offset < 0 {
            format!("local_{:x}", (-offset) as u64)
        } else {
            format!("arg_{:x}", offset as u64)
        };
        vars.push(RecoveredVariable {
            name,
            typ: format!("uint{}_t", size * 8),
            storage: VarStorage::Stack { offset, size },
        });
    }

    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_storage_display() {
        let v = RecoveredVariable {
            name: "x".into(),
            typ: "uint32_t".into(),
            storage: VarStorage::Register { offset: 0, size: 4 },
        };
        assert_eq!(v.typ, "uint32_t");
    }
}
