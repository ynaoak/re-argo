use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchType { Read, Write, ReadWrite }

#[derive(Debug, Clone)]
pub struct Watchpoint {
    pub id: u32,
    pub address: u64,
    pub size: u32,
    pub watch_type: WatchType,
    pub enabled: bool,
    pub hit_count: u64,
}

#[derive(Debug, Default)]
pub struct WatchpointManager {
    watchpoints: BTreeMap<u32, Watchpoint>,
    next_id: u32,
}

impl WatchpointManager {
    pub fn new() -> Self { Self::default() }

    pub fn add(&mut self, address: u64, size: u32, watch_type: WatchType) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.watchpoints.insert(id, Watchpoint { id, address, size, watch_type, enabled: true, hit_count: 0 });
        id
    }

    pub fn remove(&mut self, id: u32) -> bool { self.watchpoints.remove(&id).is_some() }

    pub fn check_read(&mut self, address: u64, size: u32) -> Option<u32> {
        for wp in self.watchpoints.values_mut() {
            if !wp.enabled { continue; }
            if !matches!(wp.watch_type, WatchType::Read | WatchType::ReadWrite) { continue; }
            if address < wp.address + wp.size as u64 && address + size as u64 > wp.address {
                wp.hit_count += 1;
                return Some(wp.id);
            }
        }
        None
    }

    pub fn check_write(&mut self, address: u64, size: u32) -> Option<u32> {
        for wp in self.watchpoints.values_mut() {
            if !wp.enabled { continue; }
            if !matches!(wp.watch_type, WatchType::Write | WatchType::ReadWrite) { continue; }
            if address < wp.address + wp.size as u64 && address + size as u64 > wp.address {
                wp.hit_count += 1;
                return Some(wp.id);
            }
        }
        None
    }

    pub fn list(&self) -> Vec<&Watchpoint> { self.watchpoints.values().collect() }
    pub fn len(&self) -> usize { self.watchpoints.len() }
    pub fn is_empty(&self) -> bool { self.watchpoints.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchpoint_write() {
        let mut mgr = WatchpointManager::new();
        mgr.add(0x1000, 4, WatchType::Write);
        assert!(mgr.check_write(0x1002, 1).is_some());
        assert!(mgr.check_write(0x2000, 1).is_none());
        assert!(mgr.check_read(0x1000, 4).is_none());
    }

    #[test]
    fn watchpoint_readwrite() {
        let mut mgr = WatchpointManager::new();
        mgr.add(0x1000, 8, WatchType::ReadWrite);
        assert!(mgr.check_read(0x1004, 4).is_some());
        assert!(mgr.check_write(0x1000, 1).is_some());
    }
}
