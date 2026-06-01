use std::collections::BTreeMap;
use std::sync::Arc;

use gr_core::address::SpaceId;
use gr_core::pcode::VarnodeData;

#[derive(Debug, Clone)]
pub struct EmulatorState {
    spaces: BTreeMap<u32, SpaceData>,
}

/// 4 KiB pages: the BTreeMap holds page-aligned addresses, each mapping
/// to a reference-counted fixed-size byte array. Reads/writes that fit
/// within a single page (the overwhelming majority of P-code accesses,
/// since varnodes are 1/2/4/8 bytes and addresses are usually
/// word-aligned) go through the fast path -- one BTreeMap lookup plus a
/// single `from_le_bytes` / `to_le_bytes` call instead of N per-byte
/// lookups.
///
/// Pages are wrapped in `Arc` so `EmulatorState::clone()` is
/// copy-on-write: a snapshot taken with `.clone()` shares every page
/// with the live state until either side actually writes, at which
/// point `Arc::make_mut` lazily forks the touched page. A naive
/// snapshot of a 64 MiB emulation used to memcpy the whole image
/// (~16k page copies); it now costs roughly the BTreeMap clone plus
/// one Arc refcount bump per page.
const PAGE_SHIFT: u32 = 12;
const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
const PAGE_MASK: u64 = (PAGE_SIZE as u64) - 1;

#[derive(Debug, Clone)]
struct SpaceData {
    pages: BTreeMap<u64, Arc<[u8; PAGE_SIZE]>>,
}

impl SpaceData {
    fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
        }
    }

    /// Read up to 8 bytes little-endian starting at `offset`. Sizes
    /// larger than 8 are clamped (P-code reads through this API are
    /// always <= 8 bytes; bigger varnodes are handled via Subpiece /
    /// Piece on the IR side).
    fn read(&self, offset: u64, size: u32) -> u64 {
        let size = (size as usize).min(8);
        let page_addr = offset & !PAGE_MASK;
        let page_off = (offset & PAGE_MASK) as usize;

        // Fast path: the access fits in one page.
        if page_off + size <= PAGE_SIZE {
            return self
                .pages
                .get(&page_addr)
                .map(|page| {
                    let mut buf = [0u8; 8];
                    buf[..size].copy_from_slice(&page[page_off..page_off + size]);
                    u64::from_le_bytes(buf)
                })
                .unwrap_or(0);
        }

        // Slow path: the read crosses a page boundary. Walk byte-by-byte
        // so the unmapped-page-as-zero semantics still hold per byte.
        let mut buf = [0u8; 8];
        for (i, slot) in buf.iter_mut().enumerate().take(size) {
            let addr = offset.wrapping_add(i as u64);
            let page_addr = addr & !PAGE_MASK;
            let page_off = (addr & PAGE_MASK) as usize;
            if let Some(page) = self.pages.get(&page_addr) {
                *slot = page[page_off];
            }
        }
        u64::from_le_bytes(buf)
    }

    /// Get a mutable reference to a page, lazily forking it (Arc::make_mut)
    /// if it's shared with another EmulatorState clone. Allocates a new
    /// zero page if none exists.
    fn page_mut(&mut self, page_addr: u64) -> &mut [u8; PAGE_SIZE] {
        let entry = self
            .pages
            .entry(page_addr)
            .or_insert_with(|| Arc::new([0u8; PAGE_SIZE]));
        Arc::make_mut(entry)
    }

    /// Write up to 8 bytes little-endian. Forks the touched page on
    /// demand if it is shared with another snapshot.
    fn write(&mut self, offset: u64, size: u32, value: u64) {
        let size = (size as usize).min(8);
        let bytes = value.to_le_bytes();
        let page_addr = offset & !PAGE_MASK;
        let page_off = (offset & PAGE_MASK) as usize;

        if page_off + size <= PAGE_SIZE {
            let page = self.page_mut(page_addr);
            page[page_off..page_off + size].copy_from_slice(&bytes[..size]);
            return;
        }

        // Slow path: the write crosses a page boundary.
        for (i, &b) in bytes.iter().enumerate().take(size) {
            let addr = offset.wrapping_add(i as u64);
            let page_addr = addr & !PAGE_MASK;
            let page_off = (addr & PAGE_MASK) as usize;
            let page = self.page_mut(page_addr);
            page[page_off] = b;
        }
    }

    /// Bulk-copy a byte slice into the space. Pages are forked on
    /// demand and the slice is split at page boundaries so each page
    /// gets one `copy_from_slice` rather than per-byte writes.
    fn write_bytes(&mut self, offset: u64, data: &[u8]) {
        let mut written = 0usize;
        while written < data.len() {
            let addr = offset.wrapping_add(written as u64);
            let page_addr = addr & !PAGE_MASK;
            let page_off = (addr & PAGE_MASK) as usize;
            let chunk = (PAGE_SIZE - page_off).min(data.len() - written);
            let page = self.page_mut(page_addr);
            page[page_off..page_off + chunk]
                .copy_from_slice(&data[written..written + chunk]);
            written += chunk;
        }
    }
}

impl EmulatorState {
    pub fn new() -> Self {
        Self {
            spaces: BTreeMap::new(),
        }
    }

    fn get_space(&self, space: SpaceId) -> Option<&SpaceData> {
        self.spaces.get(&space.0)
    }

    fn get_space_mut(&mut self, space: SpaceId) -> &mut SpaceData {
        self.spaces.entry(space.0).or_insert_with(SpaceData::new)
    }

    pub fn read_varnode(&self, vn: &VarnodeData) -> u64 {
        if vn.space == SpaceId::CONST {
            return vn.offset;
        }
        self.get_space(vn.space)
            .map(|s| s.read(vn.offset, vn.size))
            .unwrap_or(0)
    }

    pub fn write_varnode(&mut self, vn: &VarnodeData, value: u64) {
        let mask = if vn.size >= 8 {
            u64::MAX
        } else {
            (1u64 << (vn.size * 8)) - 1
        };
        self.get_space_mut(vn.space).write(vn.offset, vn.size, value & mask);
    }

    pub fn read_register(&self, offset: u64, size: u32) -> u64 {
        self.read_varnode(&VarnodeData::new(SpaceId::REGISTER, offset, size))
    }

    pub fn write_register(&mut self, offset: u64, size: u32, value: u64) {
        self.write_varnode(&VarnodeData::new(SpaceId::REGISTER, offset, size), value);
    }

    pub fn read_memory(&self, address: u64, size: u32) -> u64 {
        self.read_varnode(&VarnodeData::new(SpaceId::RAM, address, size))
    }

    pub fn write_memory(&mut self, address: u64, size: u32, value: u64) {
        self.write_varnode(&VarnodeData::new(SpaceId::RAM, address, size), value);
    }

    pub fn load_memory_bytes(&mut self, address: u64, data: &[u8]) {
        // Page-batched bulk write: pre-fix this looped one byte at a
        // time through `write_memory`, paying a BTreeMap lookup per
        // byte. Loading a 1 MiB image now allocates ~256 pages and
        // does ~256 BTreeMap lookups instead of ~1 million.
        self.get_space_mut(SpaceId::RAM).write_bytes(address, data);
    }

    pub fn dump_registers(&self) -> Vec<(String, u64)> {
        let regs = [
            ("RAX", 0x00u64), ("RCX", 0x08), ("RDX", 0x10), ("RBX", 0x18),
            ("RSP", 0x20), ("RBP", 0x28), ("RSI", 0x30), ("RDI", 0x38),
            ("R8",  0x80), ("R9",  0x88), ("R10", 0x90), ("R11", 0x98),
            ("R12", 0xA0), ("R13", 0xA8), ("R14", 0xB0), ("R15", 0xB8),
        ];
        regs.iter()
            .map(|(name, off)| (name.to_string(), self.read_register(*off, 8)))
            .collect()
    }
}

impl Default for EmulatorState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_register() {
        let mut state = EmulatorState::new();
        state.write_register(0x00, 8, 0xDEADBEEF_CAFEBABE);
        assert_eq!(state.read_register(0x00, 8), 0xDEADBEEF_CAFEBABE);
        assert_eq!(state.read_register(0x00, 4), 0xCAFEBABE);
        assert_eq!(state.read_register(0x00, 2), 0xBABE);
        assert_eq!(state.read_register(0x00, 1), 0xBE);
    }

    #[test]
    fn read_write_memory() {
        let mut state = EmulatorState::new();
        state.write_memory(0x1000, 4, 0x12345678);
        assert_eq!(state.read_memory(0x1000, 4), 0x12345678);
        assert_eq!(state.read_memory(0x1000, 2), 0x5678);
    }

    #[test]
    fn constant_varnode() {
        let state = EmulatorState::new();
        let vn = VarnodeData::new(SpaceId(0), 42, 8);
        assert_eq!(state.read_varnode(&vn), 42);
    }

    #[test]
    fn load_memory_bytes() {
        let mut state = EmulatorState::new();
        state.load_memory_bytes(0x2000, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(state.read_memory(0x2000, 4), 0x04030201);
    }

    /// A read that straddles two pages must still combine the bytes
    /// from each side in little-endian order. The fast path can't
    /// take this case, so the slow per-byte path has to be correct.
    #[test]
    fn read_spans_page_boundary() {
        let mut state = EmulatorState::new();
        // Page 0 ends at 0x1000; place 4 bytes from 0x0FFE..0x1002 so
        // the read crosses 0x1000.
        state.write_memory(0x0FFE, 4, 0xDEADBEEF);
        assert_eq!(state.read_memory(0x0FFE, 4), 0xDEADBEEF);
        // Per-byte reads from each side should also match.
        assert_eq!(state.read_memory(0x0FFE, 1), 0xEF);
        assert_eq!(state.read_memory(0x1001, 1), 0xDE);
    }

    /// Writes that straddle a page boundary must allocate both pages
    /// and split the bytes correctly between them.
    #[test]
    fn write_spans_page_boundary() {
        let mut state = EmulatorState::new();
        state.write_memory(0x0FFC, 8, 0x0123456789ABCDEF);
        assert_eq!(state.read_memory(0x0FFC, 8), 0x0123456789ABCDEF);
        // The first page holds the low half, the second page the high half.
        assert_eq!(state.read_memory(0x0FFC, 4), 0x89ABCDEF);
        assert_eq!(state.read_memory(0x1000, 4), 0x01234567);
    }

    /// Bulk load via `load_memory_bytes` must round-trip across page
    /// boundaries. Pre-fix this looped one byte at a time and was
    /// merely correct-but-slow; this test pins correctness so the
    /// page-batched fast path can't regress it.
    #[test]
    fn load_memory_bytes_across_pages() {
        let mut state = EmulatorState::new();
        let payload: Vec<u8> = (0..(PAGE_SIZE + 16) as u8).cycle().take(PAGE_SIZE + 16).collect();
        state.load_memory_bytes(0x0FF0, &payload);
        // First byte at 0x0FF0, last byte at 0x0FF0 + len - 1.
        let last = 0x0FF0 + (payload.len() as u64) - 1;
        assert_eq!(state.read_memory(0x0FF0, 1), payload[0] as u64);
        assert_eq!(state.read_memory(last, 1), payload[payload.len() - 1] as u64);
        // Middle: somewhere in the second page.
        let mid = 0x0FF0 + 100;
        assert_eq!(state.read_memory(mid, 1), payload[100] as u64);
    }

    /// Reads from an entirely unmapped page must read as zero.
    #[test]
    fn unmapped_page_reads_zero() {
        let state = EmulatorState::new();
        assert_eq!(state.read_memory(0x5_0000_0000, 8), 0);
    }

    /// A cloned state must observe the same values until either side
    /// writes. After a write the clone diverges only on the pages it
    /// actually touched.
    #[test]
    fn clone_is_copy_on_write() {
        let mut original = EmulatorState::new();
        original.write_memory(0x1000, 8, 0xAABBCCDDEEFF0011);
        original.write_memory(0x2000, 8, 0xDEADBEEFCAFEBABE);

        // Snapshot: identical contents, no allocation per page.
        let snap = original.clone();
        assert_eq!(snap.read_memory(0x1000, 8), 0xAABBCCDDEEFF0011);
        assert_eq!(snap.read_memory(0x2000, 8), 0xDEADBEEFCAFEBABE);

        // Mutate the live state: 0x1000 forks, 0x2000 stays shared.
        original.write_memory(0x1000, 8, 0x9999);
        assert_eq!(original.read_memory(0x1000, 8), 0x9999);
        // Snapshot still sees the pre-write value.
        assert_eq!(snap.read_memory(0x1000, 8), 0xAABBCCDDEEFF0011);
        assert_eq!(snap.read_memory(0x2000, 8), 0xDEADBEEFCAFEBABE);
    }

    /// Mutating the *snapshot* side must not bleed back into the
    /// original (CoW must be symmetric).
    #[test]
    fn snapshot_writes_do_not_bleed_into_original() {
        let mut original = EmulatorState::new();
        original.write_memory(0x1000, 8, 0xAAAA);

        let mut snap = original.clone();
        snap.write_memory(0x1000, 8, 0xBBBB);

        assert_eq!(original.read_memory(0x1000, 8), 0xAAAA);
        assert_eq!(snap.read_memory(0x1000, 8), 0xBBBB);
    }
}
