// Advanced memory model with regions, mapping, and protection.

use std::collections::BTreeMap;

use crate::trace::PagePermissions;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub permissions: PagePermissions,
    pub is_mapped: bool,
}

#[derive(Debug, Default)]
pub struct MemoryModel {
    regions: BTreeMap<u64, MemoryRegion>,
}

impl MemoryModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.insert(region.base, region);
    }

    pub fn region_at(&self, address: u64) -> Option<&MemoryRegion> {
        self.regions.range(..=address).next_back()
            .map(|(_, r)| r)
            .filter(|r| address < r.base + r.size)
    }

    pub fn is_executable(&self, address: u64) -> bool {
        self.region_at(address)
            .is_some_and(|r| r.permissions.contains(PagePermissions::EXECUTE))
    }

    pub fn is_writable(&self, address: u64) -> bool {
        self.region_at(address)
            .is_some_and(|r| r.permissions.contains(PagePermissions::WRITE))
    }

    pub fn is_readable(&self, address: u64) -> bool {
        self.region_at(address)
            .is_some_and(|r| r.permissions.contains(PagePermissions::READ))
    }

    pub fn regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions.values()
    }

    pub fn total_mapped_size(&self) -> u64 {
        self.regions.values().filter(|r| r.is_mapped).map(|r| r.size).sum()
    }

    pub fn build_from_sections(sections: &[(String, u64, u64, bool, bool, bool)]) -> Self {
        let mut model = Self::new();
        for (name, addr, size, r, w, x) in sections {
            let mut perms = PagePermissions::empty();
            if *r { perms |= PagePermissions::READ; }
            if *w { perms |= PagePermissions::WRITE; }
            if *x { perms |= PagePermissions::EXECUTE; }
            model.add_region(MemoryRegion {
                name: name.clone(),
                base: *addr,
                size: *size,
                permissions: perms,
                is_mapped: true,
            });
        }
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_model_basic() {
        let model = MemoryModel::build_from_sections(&[
            (".text".into(), 0x1000, 0x1000, true, false, true),
            (".data".into(), 0x2000, 0x500, true, true, false),
        ]);
        assert!(model.is_executable(0x1500));
        assert!(!model.is_writable(0x1500));
        assert!(model.is_writable(0x2100));
        assert!(!model.is_executable(0x2100));
        assert_eq!(model.total_mapped_size(), 0x1500);
    }

    #[test]
    fn unmapped_address() {
        let model = MemoryModel::new();
        assert!(!model.is_readable(0x5000));
        assert!(model.region_at(0x5000).is_none());
    }
}
