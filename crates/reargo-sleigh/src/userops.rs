// SLEIGH user-defined operations (CALLOTHER) and pcodeop definitions.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct UserPcodeOp {
    pub name: String,
    pub index: u32,
    pub num_inputs: Option<u32>,
    pub has_output: bool,
}

#[derive(Debug, Default)]
pub struct UserOpManager {
    ops: BTreeMap<u32, UserPcodeOp>,
    name_index: BTreeMap<String, u32>,
}

impl UserOpManager {
    pub fn new() -> Self { Self::default() }

    pub fn register(&mut self, op: UserPcodeOp) {
        self.name_index.insert(op.name.clone(), op.index);
        self.ops.insert(op.index, op);
    }

    pub fn by_index(&self, index: u32) -> Option<&UserPcodeOp> {
        self.ops.get(&index)
    }

    pub fn by_name(&self, name: &str) -> Option<&UserPcodeOp> {
        self.name_index.get(name).and_then(|&idx| self.ops.get(&idx))
    }

    pub fn len(&self) -> usize { self.ops.len() }
    pub fn is_empty(&self) -> bool { self.ops.is_empty() }

    pub fn build_x86_defaults() -> Self {
        let mut mgr = Self::new();
        let defaults = [
            ("CPUID", 0), ("RDTSC", 1), ("RDMSR", 2), ("WRMSR", 3),
            ("INVD", 4), ("WBINVD", 5), ("INVLPG", 6), ("LIDT", 7),
            ("LGDT", 8), ("LLDT", 9), ("LTR", 10), ("SGDT", 11),
            ("SIDT", 12), ("SLDT", 13), ("STR", 14), ("CLFLUSH", 15),
            ("PREFETCH", 16), ("SYSCALL", 17), ("SYSRET", 18),
            ("HLT", 19), ("INT", 20), ("INTO", 21),
        ];
        for (name, idx) in &defaults {
            mgr.register(UserPcodeOp {
                name: name.to_string(),
                index: *idx,
                num_inputs: None,
                has_output: false,
            });
        }
        mgr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_op_manager() {
        let mgr = UserOpManager::build_x86_defaults();
        assert!(mgr.len() >= 22);
        assert_eq!(mgr.by_name("SYSCALL").unwrap().index, 17);
        assert_eq!(mgr.by_index(0).unwrap().name, "CPUID");
    }
}
