use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_core::address::SpaceId;

#[derive(Debug, Clone)]
pub struct ConstructTemplate {
    pub ops: Vec<OpTemplate>,
    pub delay_slot: u32,
    pub num_labels: u32,
}

#[derive(Debug, Clone)]
pub struct OpTemplate {
    pub opcode: OpCode,
    pub output: Option<VarnodeTemplate>,
    pub inputs: Vec<VarnodeTemplate>,
}

#[derive(Debug, Clone)]
pub enum VarnodeTemplate {
    Fixed(VarnodeData),
    Dynamic { space: SpaceId, size: u32, operand_index: u32 },
    Relative { offset: i64, size: u32 },
}

impl VarnodeTemplate {
    pub fn constant(value: u64, size: u32) -> Self {
        Self::Fixed(VarnodeData::new(SpaceId::CONST, value, size))
    }

    pub fn register(offset: u64, size: u32) -> Self {
        Self::Fixed(VarnodeData::new(SpaceId::REGISTER, offset, size))
    }

    pub fn unique(offset: u64, size: u32) -> Self {
        Self::Fixed(VarnodeData::new(SpaceId::UNIQUE, offset, size))
    }

    pub fn ram(offset: u64, size: u32) -> Self {
        Self::Fixed(VarnodeData::new(SpaceId::RAM, offset, size))
    }

    pub fn operand(index: u32, size: u32) -> Self {
        Self::Dynamic {
            space: SpaceId::CONST,
            size,
            operand_index: index,
        }
    }
}

impl ConstructTemplate {
    pub fn empty() -> Self {
        Self {
            ops: Vec::new(),
            delay_slot: 0,
            num_labels: 0,
        }
    }

    pub fn op_count(&self) -> usize {
        self.ops.len()
    }

    pub fn has_delay_slot(&self) -> bool {
        self.delay_slot > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_template_basic() {
        let tmpl = ConstructTemplate {
            ops: vec![OpTemplate {
                opcode: OpCode::Copy,
                output: Some(VarnodeTemplate::register(0, 8)),
                inputs: vec![VarnodeTemplate::constant(42, 8)],
            }],
            delay_slot: 0,
            num_labels: 0,
        };
        assert_eq!(tmpl.op_count(), 1);
        assert!(!tmpl.has_delay_slot());
    }

    #[test]
    fn varnode_template_variants() {
        let c = VarnodeTemplate::constant(100, 4);
        let r = VarnodeTemplate::register(0x20, 8);
        let u = VarnodeTemplate::unique(0x100, 4);
        let o = VarnodeTemplate::operand(0, 4);
        assert!(matches!(c, VarnodeTemplate::Fixed(_)));
        assert!(matches!(r, VarnodeTemplate::Fixed(_)));
        assert!(matches!(u, VarnodeTemplate::Fixed(_)));
        assert!(matches!(o, VarnodeTemplate::Dynamic { .. }));
    }
}
