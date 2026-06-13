use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct TraceRecord {
    pub step: u64,
    pub address: u64,
    pub opcode: String,
    pub register_changes: Vec<(u64, u64, u64)>,
    pub memory_changes: Vec<(u64, u64, u64)>,
}

#[derive(Debug, Default)]
pub struct TraceLog {
    records: Vec<TraceRecord>,
    max_records: usize,
    enabled: bool,
}

impl TraceLog {
    pub fn new(max_records: usize) -> Self {
        Self {
            records: Vec::new(),
            max_records,
            enabled: true,
        }
    }

    pub fn record(&mut self, record: TraceRecord) {
        if !self.enabled {
            return;
        }
        if self.records.len() >= self.max_records && self.max_records > 0 {
            self.records.remove(0);
        }
        self.records.push(record);
    }

    pub fn records(&self) -> &[TraceRecord] {
        &self.records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn clear(&mut self) {
        self.records.clear();
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn last_n(&self, n: usize) -> &[TraceRecord] {
        let start = self.records.len().saturating_sub(n);
        &self.records[start..]
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PagePermissions: u8 {
        const READ    = 0x4;
        const WRITE   = 0x2;
        const EXECUTE = 0x1;
    }
}

#[derive(Debug, Default)]
pub struct MemoryProtection {
    pages: BTreeMap<u64, PagePermissions>,
    page_size: u64,
}

impl MemoryProtection {
    pub fn new(page_size: u64) -> Self {
        Self {
            pages: BTreeMap::new(),
            page_size,
        }
    }

    pub fn set_permissions(&mut self, address: u64, size: u64, perms: PagePermissions) {
        let start_page = address / self.page_size;
        let end_page = (address + size).div_ceil(self.page_size);
        for page in start_page..end_page {
            self.pages.insert(page, perms);
        }
    }

    pub fn check_read(&self, address: u64) -> bool {
        let page = address / self.page_size;
        self.pages
            .get(&page)
            .is_none_or(|p| p.contains(PagePermissions::READ))
    }

    pub fn check_write(&self, address: u64) -> bool {
        let page = address / self.page_size;
        self.pages
            .get(&page)
            .is_none_or(|p| p.contains(PagePermissions::WRITE))
    }

    pub fn check_execute(&self, address: u64) -> bool {
        let page = address / self.page_size;
        self.pages
            .get(&page)
            .is_none_or(|p| p.contains(PagePermissions::EXECUTE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_log_records() {
        let mut log = TraceLog::new(100);
        log.record(TraceRecord {
            step: 0,
            address: 0x1000,
            opcode: "COPY".into(),
            register_changes: Vec::new(),
            memory_changes: Vec::new(),
        });
        assert_eq!(log.len(), 1);
        assert_eq!(log.records()[0].address, 0x1000);
    }

    #[test]
    fn trace_log_max() {
        let mut log = TraceLog::new(2);
        for i in 0..5 {
            log.record(TraceRecord {
                step: i,
                address: 0x1000 + i,
                opcode: "NOP".into(),
                register_changes: Vec::new(),
                memory_changes: Vec::new(),
            });
        }
        assert_eq!(log.len(), 2);
        assert_eq!(log.records()[0].step, 3);
    }

    #[test]
    fn memory_protection() {
        let mut prot = MemoryProtection::new(0x1000);
        prot.set_permissions(0x1000, 0x1000, PagePermissions::READ | PagePermissions::EXECUTE);
        assert!(prot.check_read(0x1000));
        assert!(!prot.check_write(0x1000));
        assert!(prot.check_execute(0x1000));
    }

    #[test]
    fn memory_protection_default_allows_all() {
        let prot = MemoryProtection::new(0x1000);
        assert!(prot.check_read(0x5000));
        assert!(prot.check_write(0x5000));
        assert!(prot.check_execute(0x5000));
    }
}
