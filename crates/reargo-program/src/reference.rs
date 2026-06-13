use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefType {
    UnconditionalCall,
    ConditionalCall,
    IndirectCall,
    UnconditionalJump,
    ConditionalJump,
    IndirectJump,
    DataRead,
    DataWrite,
    DataReadWrite,
    FallThrough,
}

impl RefType {
    pub fn is_call(&self) -> bool {
        matches!(
            self,
            Self::UnconditionalCall | Self::ConditionalCall | Self::IndirectCall
        )
    }

    pub fn is_jump(&self) -> bool {
        matches!(
            self,
            Self::UnconditionalJump | Self::ConditionalJump | Self::IndirectJump
        )
    }

    pub fn is_flow(&self) -> bool {
        self.is_call() || self.is_jump() || *self == Self::FallThrough
    }

    pub fn is_data(&self) -> bool {
        matches!(
            self,
            Self::DataRead | Self::DataWrite | Self::DataReadWrite
        )
    }
}

impl std::fmt::Display for RefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnconditionalCall => write!(f, "CALL"),
            Self::ConditionalCall => write!(f, "COND_CALL"),
            Self::IndirectCall => write!(f, "IND_CALL"),
            Self::UnconditionalJump => write!(f, "JUMP"),
            Self::ConditionalJump => write!(f, "COND_JUMP"),
            Self::IndirectJump => write!(f, "IND_JUMP"),
            Self::DataRead => write!(f, "READ"),
            Self::DataWrite => write!(f, "WRITE"),
            Self::DataReadWrite => write!(f, "RW"),
            Self::FallThrough => write!(f, "FALL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
    pub ref_type: RefType,
}

impl Reference {
    pub fn new(from: u64, to: u64, ref_type: RefType) -> Self {
        Self { from, to, ref_type }
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x} -> 0x{:x} [{}]", self.from, self.to, self.ref_type)
    }
}

#[derive(Debug, Default)]
pub struct ReferenceManager {
    refs_from: HashMap<u64, Vec<Reference>>,
    refs_to: HashMap<u64, Vec<Reference>>,
}

impl ReferenceManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, reference: Reference) {
        self.refs_from
            .entry(reference.from)
            .or_default()
            .push(reference);
        self.refs_to
            .entry(reference.to)
            .or_default()
            .push(reference);
    }

    pub fn get_refs_from(&self, address: u64) -> &[Reference] {
        self.refs_from.get(&address).map_or(&[], |v| v.as_slice())
    }

    pub fn get_refs_to(&self, address: u64) -> &[Reference] {
        self.refs_to.get(&address).map_or(&[], |v| v.as_slice())
    }

    pub fn call_refs_from(&self, address: u64) -> Vec<&Reference> {
        self.get_refs_from(address)
            .iter()
            .filter(|r| r.ref_type.is_call())
            .collect()
    }

    pub fn call_refs_to(&self, address: u64) -> Vec<&Reference> {
        self.get_refs_to(address)
            .iter()
            .filter(|r| r.ref_type.is_call())
            .collect()
    }

    pub fn all_refs(&self) -> impl Iterator<Item = &Reference> {
        self.refs_from.values().flat_map(|v| v.iter())
    }

    pub fn len(&self) -> usize {
        self.refs_from.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.refs_from.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_query_refs() {
        let mut mgr = ReferenceManager::new();
        mgr.add(Reference::new(0x1000, 0x2000, RefType::UnconditionalCall));
        mgr.add(Reference::new(0x1004, 0x3000, RefType::ConditionalJump));
        mgr.add(Reference::new(0x1008, 0x2000, RefType::UnconditionalCall));

        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.get_refs_from(0x1000).len(), 1);
        assert_eq!(mgr.get_refs_to(0x2000).len(), 2);
        assert_eq!(mgr.call_refs_to(0x2000).len(), 2);
        assert!(mgr.get_refs_from(0x1004)[0].ref_type.is_jump());
    }
}
