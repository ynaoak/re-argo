use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpaceType {
    Constant,
    Processor,
    SpaceBase,
    Internal,
    FSpec,
    Iop,
    Join,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SpaceFlags: u32 {
        const BIG_ENDIAN           = 0x001;
        const HERITAGED            = 0x002;
        const DOES_DEADCODE        = 0x004;
        const PROGRAM_SPECIFIC     = 0x008;
        const REVERSE_JUSTIFY      = 0x010;
        const FORMAL_STACK         = 0x020;
        const OVERLAY              = 0x040;
        const OVERLAY_BASE         = 0x080;
        const TRUNCATED            = 0x100;
        const HAS_PHYSICAL         = 0x200;
        const IS_OTHER_SPACE       = 0x400;
        const HAS_NEAR_POINTERS    = 0x800;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpaceId(pub u32);

impl SpaceId {
    pub const CONST: SpaceId = SpaceId(0);
    pub const RAM: SpaceId = SpaceId(1);
    pub const REGISTER: SpaceId = SpaceId(2);
    pub const UNIQUE: SpaceId = SpaceId(3);
}

#[derive(Debug, Clone)]
pub struct AddressSpace {
    pub name: String,
    pub space_type: SpaceType,
    pub index: u32,
    pub address_size: u32,
    pub word_size: u32,
    pub flags: SpaceFlags,
    pub delay: u32,
    pub deadcode_delay: u32,
}

impl AddressSpace {
    pub fn highest(&self) -> u64 {
        if self.address_size >= 8 {
            u64::MAX
        } else {
            (1u64 << (self.address_size * 8)) - 1
        }
    }

    pub fn wrap_offset(&self, off: u64) -> u64 {
        off & self.highest()
    }

    pub fn is_big_endian(&self) -> bool {
        self.flags.contains(SpaceFlags::BIG_ENDIAN)
    }

    pub fn is_heritaged(&self) -> bool {
        self.flags.contains(SpaceFlags::HERITAGED)
    }

    pub fn is_overlay(&self) -> bool {
        self.flags.contains(SpaceFlags::OVERLAY)
    }
}

#[derive(Default)]
pub struct SpaceManager {
    spaces: Vec<AddressSpace>,
    default_space: Option<SpaceId>,
    constant_space: Option<SpaceId>,
    register_space: Option<SpaceId>,
    unique_space: Option<SpaceId>,
    stack_space: Option<SpaceId>,
}

impl SpaceManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_space(&mut self, space: AddressSpace) -> SpaceId {
        let idx = space.index as usize;
        let id = SpaceId(space.index);
        if idx >= self.spaces.len() {
            self.spaces.resize(idx + 1, AddressSpace {
                name: String::new(),
                space_type: SpaceType::Constant,
                index: 0,
                address_size: 0,
                word_size: 0,
                flags: SpaceFlags::empty(),
                delay: 0,
                deadcode_delay: 0,
            });
        }
        self.spaces[idx] = space;
        id
    }

    pub fn get_space(&self, id: SpaceId) -> Option<&AddressSpace> {
        self.spaces.get(id.0 as usize).filter(|s| !s.name.is_empty())
    }

    pub fn set_default_space(&mut self, id: SpaceId) {
        self.default_space = Some(id);
    }

    pub fn set_constant_space(&mut self, id: SpaceId) {
        self.constant_space = Some(id);
    }

    pub fn set_register_space(&mut self, id: SpaceId) {
        self.register_space = Some(id);
    }

    pub fn set_unique_space(&mut self, id: SpaceId) {
        self.unique_space = Some(id);
    }

    pub fn set_stack_space(&mut self, id: SpaceId) {
        self.stack_space = Some(id);
    }

    pub fn default_space(&self) -> Option<SpaceId> {
        self.default_space
    }

    pub fn constant_space(&self) -> Option<SpaceId> {
        self.constant_space
    }

    pub fn register_space(&self) -> Option<SpaceId> {
        self.register_space
    }

    pub fn unique_space(&self) -> Option<SpaceId> {
        self.unique_space
    }

    pub fn stack_space(&self) -> Option<SpaceId> {
        self.stack_space
    }

    pub fn spaces(&self) -> impl Iterator<Item = (SpaceId, &AddressSpace)> {
        self.spaces
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.name.is_empty())
            .map(|(i, s)| (SpaceId(i as u32), s))
    }

    pub fn find_space_by_name(&self, name: &str) -> Option<SpaceId> {
        self.spaces
            .iter()
            .enumerate()
            .find(|(_, s)| s.name == name)
            .map(|(i, _)| SpaceId(i as u32))
    }

    pub fn build_default_spaces(&mut self, endian: Endian) -> DefaultSpaces {
        let endian_flag = match endian {
            Endian::Big => SpaceFlags::BIG_ENDIAN,
            Endian::Little => SpaceFlags::empty(),
        };

        let const_id = self.add_space(AddressSpace {
            name: "const".into(),
            space_type: SpaceType::Constant,
            index: 0,
            address_size: 8,
            word_size: 1,
            flags: endian_flag,
            delay: 0,
            deadcode_delay: 0,
        });
        self.set_constant_space(const_id);

        let ram_id = self.add_space(AddressSpace {
            name: "ram".into(),
            space_type: SpaceType::Processor,
            index: 1,
            address_size: 8,
            word_size: 1,
            flags: endian_flag | SpaceFlags::HERITAGED | SpaceFlags::DOES_DEADCODE | SpaceFlags::HAS_PHYSICAL,
            delay: 1,
            deadcode_delay: 3,
        });
        self.set_default_space(ram_id);

        let register_id = self.add_space(AddressSpace {
            name: "register".into(),
            space_type: SpaceType::Processor,
            index: 2,
            address_size: 4,
            word_size: 1,
            flags: endian_flag | SpaceFlags::HERITAGED,
            delay: 0,
            deadcode_delay: 0,
        });
        self.set_register_space(register_id);

        let unique_id = self.add_space(AddressSpace {
            name: "unique".into(),
            space_type: SpaceType::Internal,
            index: 3,
            address_size: 4,
            word_size: 1,
            flags: endian_flag | SpaceFlags::HERITAGED,
            delay: 0,
            deadcode_delay: 0,
        });
        self.set_unique_space(unique_id);

        DefaultSpaces {
            constant: const_id,
            ram: ram_id,
            register: register_id,
            unique: unique_id,
        }
    }
}

pub struct DefaultSpaces {
    pub constant: SpaceId,
    pub ram: SpaceId,
    pub register: SpaceId,
    pub unique: SpaceId,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    pub space: SpaceId,
    pub offset: u64,
}

impl Address {
    pub fn new(space: SpaceId, offset: u64) -> Self {
        Self { space, offset }
    }

    pub fn constant(value: u64) -> Self {
        Self {
            space: SpaceId(0),
            offset: value,
        }
    }

    pub fn checked_add(&self, amount: u64) -> Option<Self> {
        self.offset.checked_add(amount).map(|offset| Self {
            space: self.space,
            offset,
        })
    }

    pub fn wrapping_add(&self, amount: u64) -> Self {
        Self {
            space: self.space,
            offset: self.offset.wrapping_add(amount),
        }
    }

    pub fn checked_sub(&self, amount: u64) -> Option<Self> {
        self.offset.checked_sub(amount).map(|offset| Self {
            space: self.space,
            offset,
        })
    }

    pub fn distance_to(&self, other: &Self) -> Option<u64> {
        if self.space != other.space {
            return None;
        }
        Some(other.offset.wrapping_sub(self.offset))
    }

    pub fn contains_in(&self, range: &AddressRange) -> bool {
        self.space == range.start.space
            && self.offset >= range.start.offset
            && self.offset < range.start.offset.saturating_add(range.size)
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.space
            .cmp(&other.space)
            .then(self.offset.cmp(&other.offset))
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(space={}, 0x{:x})", self.space.0, self.offset)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.offset)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressRange {
    pub start: Address,
    pub size: u64,
}

impl AddressRange {
    pub fn new(start: Address, size: u64) -> Self {
        Self { start, size }
    }

    pub fn end_offset(&self) -> u64 {
        self.start.offset.saturating_add(self.size)
    }

    pub fn contains(&self, addr: &Address) -> bool {
        addr.space == self.start.space
            && addr.offset >= self.start.offset
            && addr.offset < self.end_offset()
    }

    pub fn overlaps(&self, other: &AddressRange) -> bool {
        if self.start.space != other.start.space {
            return false;
        }
        self.start.offset < other.end_offset() && other.start.offset < self.end_offset()
    }
}

impl Ord for AddressRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start).then(self.size.cmp(&other.size))
    }
}

impl PartialOrd for AddressRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Default)]
pub struct AddressSet {
    ranges: BTreeSet<AddressRange>,
}

impl AddressSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, range: AddressRange) {
        self.ranges.insert(range);
    }

    pub fn contains(&self, addr: &Address) -> bool {
        let probe = AddressRange::new(*addr, u64::MAX);
        self.ranges
            .range(..=probe)
            .next_back()
            .is_some_and(|r| r.contains(addr))
    }

    pub fn ranges(&self) -> impl Iterator<Item = &AddressRange> {
        self.ranges.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SegmentedAddress {
    pub segment: u16,
    pub offset: u16,
}

impl SegmentedAddress {
    pub fn new(segment: u16, offset: u16) -> Self {
        Self { segment, offset }
    }

    pub fn to_linear(&self) -> u64 {
        (self.segment as u64) * 16 + self.offset as u64
    }

    pub fn from_linear(linear: u64) -> Self {
        Self {
            segment: ((linear >> 4) & 0xFFFF) as u16,
            offset: (linear & 0xF) as u16,
        }
    }

    pub fn to_address(&self, space: SpaceId) -> Address {
        Address::new(space, self.to_linear())
    }
}

impl fmt::Display for SegmentedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}:{:04X}", self.segment, self.offset)
    }
}

#[derive(Debug, Clone)]
pub struct OverlayAddressSpace {
    pub name: String,
    pub base_space: SpaceId,
    pub overlay_id: u32,
    pub min_offset: u64,
    pub max_offset: u64,
}

impl OverlayAddressSpace {
    pub fn new(name: impl Into<String>, base_space: SpaceId, overlay_id: u32) -> Self {
        Self {
            name: name.into(),
            base_space,
            overlay_id,
            min_offset: 0,
            max_offset: u64::MAX,
        }
    }

    pub fn translate_to_base(&self, addr: &Address) -> Address {
        Address::new(self.base_space, addr.offset)
    }
}

#[derive(Debug, Default)]
pub struct AddressMap {
    entries: Vec<AddressMapEntry>,
}

#[derive(Debug, Clone)]
struct AddressMapEntry {
    file_offset: u64,
    virtual_address: u64,
    size: u64,
}

impl AddressMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_mapping(&mut self, file_offset: u64, virtual_address: u64, size: u64) {
        self.entries.push(AddressMapEntry {
            file_offset,
            virtual_address,
            size,
        });
    }

    pub fn file_to_virtual(&self, file_offset: u64) -> Option<u64> {
        for entry in &self.entries {
            if file_offset >= entry.file_offset
                && file_offset < entry.file_offset + entry.size
            {
                return Some(
                    entry.virtual_address + (file_offset - entry.file_offset),
                );
            }
        }
        None
    }

    pub fn virtual_to_file(&self, virtual_address: u64) -> Option<u64> {
        for entry in &self.entries {
            if virtual_address >= entry.virtual_address
                && virtual_address < entry.virtual_address + entry.size
            {
                return Some(
                    entry.file_offset + (virtual_address - entry.virtual_address),
                );
            }
        }
        None
    }
}

pub fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

pub fn read_u16(data: &[u8], offset: usize, endian: Endian) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    })
}

pub fn read_u32(data: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    })
}

pub fn read_u64(data: &[u8], offset: usize, endian: Endian) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u64::from_le_bytes(bytes),
        Endian::Big => u64::from_be_bytes(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_ordering() {
        let a = Address::new(SpaceId(1), 0x100);
        let b = Address::new(SpaceId(1), 0x200);
        let c = Address::new(SpaceId(2), 0x50);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn address_arithmetic() {
        let a = Address::new(SpaceId(1), 0x100);
        assert_eq!(a.checked_add(0x50).unwrap().offset, 0x150);
        assert_eq!(a.checked_sub(0x10).unwrap().offset, 0xF0);
        assert!(a.checked_sub(0x200).is_none());
    }

    #[test]
    fn address_distance() {
        let a = Address::new(SpaceId(1), 0x100);
        let b = Address::new(SpaceId(1), 0x200);
        assert_eq!(a.distance_to(&b), Some(0x100));

        let c = Address::new(SpaceId(2), 0x100);
        assert_eq!(a.distance_to(&c), None);
    }

    #[test]
    fn range_contains() {
        let range = AddressRange::new(Address::new(SpaceId(1), 0x100), 0x100);
        assert!(range.contains(&Address::new(SpaceId(1), 0x100)));
        assert!(range.contains(&Address::new(SpaceId(1), 0x1FF)));
        assert!(!range.contains(&Address::new(SpaceId(1), 0x200)));
        assert!(!range.contains(&Address::new(SpaceId(2), 0x100)));
    }

    #[test]
    fn range_overlap() {
        let r1 = AddressRange::new(Address::new(SpaceId(1), 0x100), 0x100);
        let r2 = AddressRange::new(Address::new(SpaceId(1), 0x180), 0x100);
        let r3 = AddressRange::new(Address::new(SpaceId(1), 0x200), 0x100);
        assert!(r1.overlaps(&r2));
        assert!(!r1.overlaps(&r3));
    }

    #[test]
    fn address_set() {
        let mut set = AddressSet::new();
        set.add(AddressRange::new(Address::new(SpaceId(1), 0x100), 0x100));
        set.add(AddressRange::new(Address::new(SpaceId(1), 0x300), 0x50));
        assert!(set.contains(&Address::new(SpaceId(1), 0x150)));
        assert!(!set.contains(&Address::new(SpaceId(1), 0x250)));
        assert!(set.contains(&Address::new(SpaceId(1), 0x320)));
    }

    #[test]
    fn space_manager_default_spaces() {
        let mut mgr = SpaceManager::new();
        let defaults = mgr.build_default_spaces(Endian::Little);
        assert_eq!(mgr.get_space(defaults.ram).unwrap().name, "ram");
        assert_eq!(mgr.get_space(defaults.constant).unwrap().name, "const");
        assert_eq!(mgr.get_space(defaults.register).unwrap().name, "register");
        assert_eq!(mgr.get_space(defaults.unique).unwrap().name, "unique");
        assert!(!mgr.get_space(defaults.ram).unwrap().is_big_endian());
    }

    #[test]
    fn space_wrap_offset() {
        let space = AddressSpace {
            name: "test".into(),
            space_type: SpaceType::Processor,
            index: 0,
            address_size: 4,
            word_size: 1,
            flags: SpaceFlags::empty(),
            delay: 0,
            deadcode_delay: 0,
        };
        assert_eq!(space.wrap_offset(0x1_0000_0000), 0);
        assert_eq!(space.wrap_offset(0xFFFF_FFFF), 0xFFFF_FFFF);
    }

    #[test]
    fn endian_reads() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u16(&data, 0, Endian::Little), Some(0x0201));
        assert_eq!(read_u16(&data, 0, Endian::Big), Some(0x0102));
        assert_eq!(read_u32(&data, 0, Endian::Little), Some(0x04030201));
        assert_eq!(read_u32(&data, 0, Endian::Big), Some(0x01020304));
        assert_eq!(read_u64(&data, 0, Endian::Little), Some(0x0807060504030201));
        assert_eq!(read_u64(&data, 0, Endian::Big), Some(0x0102030405060708));
    }
}
