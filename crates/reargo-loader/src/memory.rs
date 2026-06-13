use std::collections::BTreeMap;
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

#[derive(Debug)]
pub struct Memory {
    blocks: BTreeMap<u64, MemoryBlock>,
    space_id: SpaceId,
    endian: Endian,
}

impl Memory {
    pub fn new(space_id: SpaceId, endian: Endian) -> Self {
        Self {
            blocks: BTreeMap::new(),
            space_id,
            endian,
        }
    }

    pub fn add_block(&mut self, block: MemoryBlock) {
        self.blocks.insert(block.start, block);
    }

    pub fn space_id(&self) -> SpaceId {
        self.space_id
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn find_block(&self, offset: u64) -> Option<&MemoryBlock> {
        self.blocks
            .range(..=offset)
            .next_back()
            .map(|(_, block)| block)
            .filter(|block| block.contains(offset))
    }

    pub fn read_byte(&self, offset: u64) -> Option<u8> {
        self.find_block(offset)?.read_byte(offset)
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
        let available = self
            .find_block(address)
            .map(|b| (b.start + b.size - address) as usize)
            .unwrap_or(0);
        let read_len = buf.len().min(available);
        if read_len > 0 {
            let _ = self.read_bytes(address, &mut buf[..read_len]);
        }
        read_len
    }

    pub fn blocks(&self) -> impl Iterator<Item = &MemoryBlock> {
        self.blocks.values()
    }

    pub fn address_range(&self) -> Option<AddressRange> {
        let first = self.blocks.values().next()?;
        let last = self.blocks.values().next_back()?;
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
