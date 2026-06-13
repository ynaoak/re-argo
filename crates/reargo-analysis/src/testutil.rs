#[cfg(test)]
pub(crate) mod helpers {
    use reargo_core::address::{Endian, SpaceId};
    use reargo_core::datatype::DataTypeManager;
    use reargo_loader::memory::{Memory, MemoryBlock, MemoryFlags};
    use reargo_loader::{BinaryFormat, BinaryInfo, DynamicInfo, Section, SectionFlags};
    use reargo_program::listing::Listing;
    use reargo_program::reference::ReferenceManager;
    use reargo_program::symbol::SymbolTable;
    use reargo_program::Program;
    use std::sync::Arc;

    pub fn make_x86_64_program(code: &[u8], entry: u64) -> Program {
        let mut memory = Memory::new(SpaceId(1), Endian::Little);
        memory.add_block(MemoryBlock {
            name: ".text".into(),
            start: entry,
            size: code.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(code)),
        });

        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            arch: reargo_loader::Architecture::X86_64,
            endian: Endian::Little,
            bits: 64,
            entry_point: entry,
            sections: vec![Section {
                name: ".text".into(),
                address: entry,
                size: code.len() as u64,
                flags: SectionFlags::READ | SectionFlags::EXECUTE,
            }],
            symbols: Vec::new(),
            imports: Vec::new(),
            memory,
            dwarf: reargo_loader::dwarf::DwarfInfo::default(),
            dynamic: DynamicInfo::default(),
            address_map: reargo_core::address::AddressMap::new(),
        };

        let arch = reargo_arch::arch::create_architecture(reargo_loader::Architecture::X86_64).unwrap();

        Program {
            name: "test".into(),
            arch,
            info,
            listing: Listing::new(),
            symbol_table: SymbolTable::new(),
            references: ReferenceManager::new(),
            data_types: DataTypeManager::new(),
            comments: reargo_program::comments::CommentManager::new(),
            metadata: reargo_program::metadata::ProgramMetadata::default(),
            call_renderings: std::collections::BTreeMap::new(),
            tags: reargo_program::tags::TagManager::new(),
        }
    }

    pub fn make_x86_64_program_with_data(code: &[u8], data: &[u8], code_addr: u64, data_addr: u64) -> Program {
        let mut memory = Memory::new(SpaceId(1), Endian::Little);
        memory.add_block(MemoryBlock {
            name: ".text".into(),
            start: code_addr,
            size: code.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(code)),
        });
        memory.add_block(MemoryBlock {
            name: ".rodata".into(),
            start: data_addr,
            size: data.len() as u64,
            flags: MemoryFlags::READ,
            data: Some(Arc::from(data)),
        });

        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            arch: reargo_loader::Architecture::X86_64,
            endian: Endian::Little,
            bits: 64,
            entry_point: code_addr,
            sections: vec![
                Section {
                    name: ".text".into(),
                    address: code_addr,
                    size: code.len() as u64,
                    flags: SectionFlags::READ | SectionFlags::EXECUTE,
                },
                Section {
                    name: ".rodata".into(),
                    address: data_addr,
                    size: data.len() as u64,
                    flags: SectionFlags::READ,
                },
            ],
            symbols: Vec::new(),
            imports: Vec::new(),
            memory,
            dwarf: reargo_loader::dwarf::DwarfInfo::default(),
            dynamic: DynamicInfo::default(),
            address_map: reargo_core::address::AddressMap::new(),
        };

        let arch = reargo_arch::arch::create_architecture(reargo_loader::Architecture::X86_64).unwrap();

        Program {
            name: "test".into(),
            arch,
            info,
            listing: Listing::new(),
            symbol_table: SymbolTable::new(),
            references: ReferenceManager::new(),
            data_types: DataTypeManager::new(),
            comments: reargo_program::comments::CommentManager::new(),
            metadata: reargo_program::metadata::ProgramMetadata::default(),
            call_renderings: std::collections::BTreeMap::new(),
            tags: reargo_program::tags::TagManager::new(),
        }
    }
}
