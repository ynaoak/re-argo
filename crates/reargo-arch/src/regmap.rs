use std::collections::BTreeMap;

use reargo_core::pcode::VarnodeData;
use reargo_core::address::SpaceId;

#[derive(Debug, Clone)]
pub struct RegisterOverlap {
    pub parent: String,
    pub children: Vec<(String, u64, u32)>,
}

#[derive(Debug, Default)]
pub struct RegisterOverlapMap {
    overlaps: BTreeMap<u64, Vec<(String, u32)>>,
}

impl RegisterOverlapMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: impl Into<String>, offset: u64, size: u32) {
        self.overlaps
            .entry(offset)
            .or_default()
            .push((name.into(), size));
    }

    pub fn get_parent(&self, offset: u64, size: u32) -> Option<&str> {
        for (&base_offset, regs) in &self.overlaps {
            if offset >= base_offset && offset < base_offset + regs.iter().map(|(_, s)| *s as u64).max().unwrap_or(0)
                && let Some((name, _)) = regs.iter().max_by_key(|(_, s)| *s)
                    && (offset == base_offset || size < regs.iter().map(|(_, s)| *s).max().unwrap_or(0)) {
                        return Some(name);
                    }
        }
        None
    }

    pub fn get_children(&self, offset: u64) -> Vec<(&str, u32)> {
        self.overlaps
            .get(&offset)
            .map(|regs| regs.iter().map(|(n, s)| (n.as_str(), *s)).collect())
            .unwrap_or_default()
    }

    pub fn contains_at(&self, offset: u64, size: u32) -> bool {
        self.overlaps
            .get(&offset)
            .map(|regs| regs.iter().any(|(_, s)| *s == size))
            .unwrap_or(false)
    }

    pub fn build_x86_64() -> Self {
        let mut map = Self::new();
        let gpr_names = [
            (0x00, "RAX", "EAX", "AX", "AL"),
            (0x08, "RCX", "ECX", "CX", "CL"),
            (0x10, "RDX", "EDX", "DX", "DL"),
            (0x18, "RBX", "EBX", "BX", "BL"),
            (0x20, "RSP", "ESP", "SP", "SPL"),
            (0x28, "RBP", "EBP", "BP", "BPL"),
            (0x30, "RSI", "ESI", "SI", "SIL"),
            (0x38, "RDI", "EDI", "DI", "DIL"),
        ];
        for (offset, r64, r32, r16, r8) in &gpr_names {
            map.add(*r64, *offset as u64, 8);
            map.add(*r32, *offset as u64, 4);
            map.add(*r16, *offset as u64, 2);
            map.add(*r8, *offset as u64, 1);
        }
        for i in 8..=15u64 {
            let offset = 0x80 + (i - 8) * 8;
            map.add(format!("R{}", i), offset, 8);
            map.add(format!("R{}D", i), offset, 4);
            map.add(format!("R{}W", i), offset, 2);
            map.add(format!("R{}B", i), offset, 1);
        }
        map
    }

    pub fn varnode_for(&self, name: &str) -> Option<VarnodeData> {
        for (&offset, regs) in &self.overlaps {
            for (rname, size) in regs {
                if rname.eq_ignore_ascii_case(name) {
                    return Some(VarnodeData::new(SpaceId::REGISTER, offset, *size));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_overlap_map() {
        let map = RegisterOverlapMap::build_x86_64();
        assert!(map.contains_at(0x00, 8));
        assert!(map.contains_at(0x00, 4));
        assert!(map.contains_at(0x00, 2));
        assert!(map.contains_at(0x00, 1));
        assert!(!map.contains_at(0x00, 3));
    }

    #[test]
    fn varnode_lookup() {
        let map = RegisterOverlapMap::build_x86_64();
        let rax = map.varnode_for("RAX").unwrap();
        assert_eq!(rax.size, 8);
        assert_eq!(rax.offset, 0x00);
        let eax = map.varnode_for("EAX").unwrap();
        assert_eq!(eax.size, 4);
    }

    #[test]
    fn children_at_offset() {
        let map = RegisterOverlapMap::build_x86_64();
        let children = map.get_children(0x00);
        assert!(children.len() >= 4);
    }
}
