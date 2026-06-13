use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct SleighSpace {
    pub name: String,
    pub index: u32,
    pub address_size: u32,
    pub word_size: u32,
    pub space_type: SleighSpaceType,
    pub is_default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleighSpaceType {
    Ram,
    Register,
    Constant,
    Unique,
    Other,
}

#[derive(Debug, Default)]
pub struct SleighSpaceManager {
    spaces: Vec<SleighSpace>,
    name_index: BTreeMap<String, usize>,
    default_space: Option<usize>,
    register_space: Option<usize>,
    constant_space: Option<usize>,
    unique_space: Option<usize>,
}

impl SleighSpaceManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, space: SleighSpace) -> usize {
        let idx = self.spaces.len();
        self.name_index.insert(space.name.clone(), idx);
        match space.space_type {
            SleighSpaceType::Ram if space.is_default => self.default_space = Some(idx),
            SleighSpaceType::Register => self.register_space = Some(idx),
            SleighSpaceType::Constant => self.constant_space = Some(idx),
            SleighSpaceType::Unique => self.unique_space = Some(idx),
            _ => {}
        }
        self.spaces.push(space);
        idx
    }

    pub fn get(&self, index: usize) -> Option<&SleighSpace> {
        self.spaces.get(index)
    }

    pub fn find(&self, name: &str) -> Option<&SleighSpace> {
        self.name_index.get(name).and_then(|&idx| self.spaces.get(idx))
    }

    pub fn default_space(&self) -> Option<&SleighSpace> {
        self.default_space.and_then(|idx| self.spaces.get(idx))
    }

    pub fn register_space(&self) -> Option<&SleighSpace> {
        self.register_space.and_then(|idx| self.spaces.get(idx))
    }

    pub fn len(&self) -> usize {
        self.spaces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spaces.is_empty()
    }

    pub fn build_standard() -> Self {
        let mut mgr = Self::new();
        mgr.add(SleighSpace { name: "const".into(), index: 0, address_size: 8, word_size: 1, space_type: SleighSpaceType::Constant, is_default: false });
        mgr.add(SleighSpace { name: "ram".into(), index: 1, address_size: 8, word_size: 1, space_type: SleighSpaceType::Ram, is_default: true });
        mgr.add(SleighSpace { name: "register".into(), index: 2, address_size: 4, word_size: 1, space_type: SleighSpaceType::Register, is_default: false });
        mgr.add(SleighSpace { name: "unique".into(), index: 3, address_size: 4, word_size: 1, space_type: SleighSpaceType::Unique, is_default: false });
        mgr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_spaces() {
        let mgr = SleighSpaceManager::build_standard();
        assert_eq!(mgr.len(), 4);
        assert_eq!(mgr.default_space().unwrap().name, "ram");
        assert_eq!(mgr.register_space().unwrap().name, "register");
        assert!(mgr.find("const").is_some());
        assert!(mgr.find("unique").is_some());
    }
}
