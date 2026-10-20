use std::sync::Arc;

use reargo_core::address::{Address, AddressRange, Endian, SpaceId};

use crate::error::LoaderError;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryFlags: u32 {
        const READ    = 0x4;
        const WRITE   = 0x2;
        const EXECUTE = 0x1;
        const VOLATILE = 0x8;
    }
}

#[derive(Debug, Clone)]
pub struct MemoryBlock {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub flags: MemoryFlags,
    pub data: Option<Arc<[u8]>>,
}

impl MemoryBlock {
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset < self.start + self.size
    }

    pub fn is_initialized(&self) -> bool {
        self.data.is_some()
    }

    pub fn read_byte(&self, offset: u64) -> Option<u8> {
        let data = self.data.as_ref()?;
        let idx = offset.checked_sub(self.start)? as usize;
        data.get(idx).copied()
    }

    pub fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<(), LoaderError> {
        let data = self.data.as_ref().ok_or(LoaderError::AddressNotFound(offset))?;
        let start_idx = offset
            .checked_sub(self.start)
            .ok_or(LoaderError::AddressNotFound(offset))? as usize;
        let end_idx = start_idx + buf.len();
        if end_idx > data.len() {
            return Err(LoaderError::AddressNotFound(offset));
        }
        buf.copy_from_slice(&data[start_idx..end_idx]);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Memory {
    /// By start address, at most one per start (a block added at the
    /// start of another replaces it). A sorted vector: a handful of
    /// blocks, looked up for every instruction decoded.
    blocks: Vec<MemoryBlock>,
    space_id: SpaceId,
    endian: Endian,
    /// The raw dynamic relocation table (ELF64 `Elf64_Rela` entries of `.rela.dyn`), kept
    /// beside the blocks rather than as one so byte scans over the image do not see it.
    /// In a PIE the pointers in `.data.rel.ro` (vtables, …) are zero in the file and live
    /// in its `R_*_RELATIVE` addends.
    dynamic_relocations: Option<Arc<[u8]>>,
}

impl Memory {
    pub fn new(space_id: SpaceId, endian: Endian) -> Self {
        Self {
            blocks: Vec::new(),
            space_id,
            endian,
            dynamic_relocations: None,
        }
    }

    /// Attach the raw `Elf64_Rela` table of the dynamic relocations (see the field).
    pub fn set_dynamic_relocations(&mut self, table: Arc<[u8]>) {
        self.dynamic_relocations = Some(table);
    }

    /// The raw `Elf64_Rela` table of the dynamic relocations, if the loader attached one.
    pub fn dynamic_relocations(&self) -> Option<&[u8]> {
        self.dynamic_relocations.as_deref()
    }

    pub fn add_block(&mut self, block: MemoryBlock) {
        match self.blocks.binary_search_by_key(&block.start, |b| b.start) {
            Ok(i) => self.blocks[i] = block,
            Err(i) => self.blocks.insert(i, block),
        }
    }

    pub fn space_id(&self) -> SpaceId {
        self.space_id
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn find_block(&self, offset: u64) -> Option<&MemoryBlock> {
        // The last block starting at or before `offset`.
        let i = self.blocks.partition_point(|b| b.start <= offset);
        let block = self.blocks.get(i.checked_sub(1)?)?;
        block.contains(offset).then_some(block)
    }

    pub fn read_byte(&self, offset: u64) -> Option<u8> {
        self.find_block(offset)?.read_byte(offset)
    }

    /// The initialized bytes of `[offset, offset + len)` as one slice, when
    /// every address in it reads from the same block — no other block starts
    /// inside the range — so a per-address [`Memory::read_byte`] /
    /// [`Memory::read_bytes`] there sees exactly these bytes. `None` otherwise.
    pub fn slice(&self, offset: u64, len: u64) -> Option<&[u8]> {
        // (`find_block`, keeping where the blocks starting after `offset` begin)
        let i = self.blocks.partition_point(|b| b.start <= offset);
        let block = self.blocks.get(i.checked_sub(1)?)?;
        if !block.contains(offset) {
            return None;
        }
        let data = block.data.as_ref()?;
        let start = usize::try_from(offset - block.start).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        if end > data.len() || end as u64 > block.size {
            return None;
        }
        // A block starting in `offset + 1 .. offset + len`: the first one starting after
        // `offset` (the blocks are sorted by start) does, if any.
        if len > 1 && self.blocks.get(i).is_some_and(|b| b.start < offset + len) {
            return None;
        }
        Some(&data[start..end])
    }

    /// The bytes [`Memory::read_bytes`] reads at `[offset, offset + len)`:
    /// borrowed when the one block it reads from holds them all, as
    /// [`Memory::slice`] gives them, else read into a copy; `None` when
    /// the read fails.
    pub fn bytes(&self, offset: u64, len: usize) -> Option<std::borrow::Cow<'_, [u8]>> {
        if let Some(bytes) = self.slice(offset, len as u64) {
            return Some(std::borrow::Cow::Borrowed(bytes));
        }
        let mut buf = vec![0u8; len];
        self.read_bytes(offset, &mut buf).ok()?;
        Some(std::borrow::Cow::Owned(buf))
    }

    pub fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<(), LoaderError> {
        let block = self
            .find_block(offset)
            .ok_or(LoaderError::AddressNotFound(offset))?;
        block.read_bytes(offset, buf)
    }

    pub fn read_u16(&self, offset: u64) -> Result<u16, LoaderError> {
        let mut buf = [0u8; 2];
        self.read_bytes(offset, &mut buf)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(buf),
            Endian::Big => u16::from_be_bytes(buf),
        })
    }

    pub fn read_u32(&self, offset: u64) -> Result<u32, LoaderError> {
        let mut buf = [0u8; 4];
        self.read_bytes(offset, &mut buf)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(buf),
            Endian::Big => u32::from_be_bytes(buf),
        })
    }

    pub fn read_u64(&self, offset: u64) -> Result<u64, LoaderError> {
        let mut buf = [0u8; 8];
        self.read_bytes(offset, &mut buf)?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(buf),
            Endian::Big => u64::from_be_bytes(buf),
        })
    }

    pub fn read_instruction_bytes(&self, address: u64, buf: &mut [u8; 15]) -> usize {
        let Some(block) = self.find_block(address) else {
            return 0;
        };
        let available = (block.start + block.size - address) as usize;
        let read_len = buf.len().min(available);
        if read_len > 0 {
            // `read_bytes` would find this same block again.
            let _ = block.read_bytes(address, &mut buf[..read_len]);
        }
        read_len
    }

    pub fn blocks(&self) -> impl Iterator<Item = &MemoryBlock> {
        self.blocks.iter()
    }

    pub fn address_range(&self) -> Option<AddressRange> {
        let first = self.blocks.first()?;
        let last = self.blocks.last()?;
        Some(AddressRange::new(
            Address::new(self.space_id, first.start),
            last.start + last.size - first.start,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_memory() -> Memory {
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: 0x1000,
            size: 4,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from([0x01, 0x02, 0x03, 0x04].as_slice())),
        });
        mem
    }

    /// Blocks kept by start: lookups pick the last block starting at or
    /// before the address, a block added at an existing start replaces
    /// it, and `slice` refuses a range another block starts inside.
    #[test]
    fn blocks_by_start() {
        let block = |start: u64, size: u64, fill: u8| MemoryBlock {
            name: format!("b{start:x}"),
            start,
            size,
            flags: MemoryFlags::READ,
            data: Some(Arc::from(vec![fill; size as usize])),
        };
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(block(0x3000, 0x10, 3));
        mem.add_block(block(0x1000, 0x10, 1));
        mem.add_block(block(0x2000, 0x10, 2));
        mem.add_block(block(0x2008, 0x10, 4));
        assert_eq!(mem.blocks().map(|b| b.start).collect::<Vec<_>>(), [0x1000, 0x2000, 0x2008, 0x3000]);
        assert!(mem.find_block(0xfff).is_none());
        assert_eq!(mem.read_byte(0x1000), Some(1));
        assert_eq!(mem.read_byte(0x100f), Some(1));
        assert!(mem.find_block(0x1010).is_none());
        assert_eq!(mem.read_byte(0x2007), Some(2));
        assert_eq!(mem.read_byte(0x2008), Some(4));
        assert_eq!(mem.read_byte(0x3000), Some(3));
        assert!(mem.slice(0x2000, 8).is_some());
        assert!(mem.slice(0x2000, 9).is_none());
        // `slice` is the bytes of `find_block(offset)` when no other block starts inside the
        // range (searched for each of its addresses here)
        for offset in 0xff0..0x3020u64 {
            for len in 0..24u64 {
                let want = mem.find_block(offset).and_then(|b| {
                    let data = b.data.as_ref()?;
                    let start = (offset - b.start) as usize;
                    let end = start + len as usize;
                    let other = (offset + 1..offset + len).any(|a| mem.blocks().any(|o| o.start == a));
                    (end <= data.len() && !other).then(|| &data[start..end])
                });
                assert_eq!(mem.slice(offset, len), want, "{offset:x} {len}");
            }
        }
        mem.add_block(block(0x2000, 0x4, 5));
        assert_eq!(mem.read_byte(0x2000), Some(5));
        assert!(mem.find_block(0x2004).is_none());
        let mut buf = [0u8; 15];
        assert_eq!(mem.read_instruction_bytes(0x300c, &mut buf), 4);
        assert_eq!(buf[..5], [3, 3, 3, 3, 0]);
        assert_eq!(mem.read_instruction_bytes(0x5000, &mut buf), 0);
        assert_eq!(mem.address_range().map(|r| (r.start.offset, r.size)), Some((0x1000, 0x2010)));
    }

    #[test]
    fn read_single_byte() {
        let mem = test_memory();
        assert_eq!(mem.read_byte(0x1000), Some(0x01));
        assert_eq!(mem.read_byte(0x1003), Some(0x04));
        assert_eq!(mem.read_byte(0x1004), None);
        assert_eq!(mem.read_byte(0x0FFF), None);
    }

    #[test]
    fn read_u16_le() {
        let mem = test_memory();
        assert_eq!(mem.read_u16(0x1000).unwrap(), 0x0201);
    }

    #[test]
    fn read_u32_le() {
        let mem = test_memory();
        assert_eq!(mem.read_u32(0x1000).unwrap(), 0x04030201);
    }

    #[test]
    fn block_flags() {
        let mem = test_memory();
        let block = mem.find_block(0x1000).unwrap();
        assert!(block.flags.contains(MemoryFlags::READ));
        assert!(block.flags.contains(MemoryFlags::EXECUTE));
        assert!(!block.flags.contains(MemoryFlags::WRITE));
    }
}
