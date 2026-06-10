#[cfg(test)]
pub(crate) mod helpers {
    use gr_core::address::{Endian, SpaceId};
    use gr_core::datatype::DataTypeManager;
    use gr_loader::memory::{Memory, MemoryBlock, MemoryFlags};
    use gr_loader::{BinaryFormat, BinaryInfo, DynamicInfo, Section, SectionFlags};
    use gr_program::listing::Listing;
    use gr_program::reference::ReferenceManager;
    use gr_program::symbol::SymbolTable;
    use gr_program::Program;
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
            arch: gr_loader::Architecture::X86_64,
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
            dwarf: gr_loader::dwarf::DwarfInfo::default(),
            dynamic: DynamicInfo::default(),
            address_map: gr_core::address::AddressMap::new(),
        };

        let arch = gr_arch::arch::create_architecture(gr_loader::Architecture::X86_64).unwrap();

        Program {
            name: "test".into(),
            arch,
            info,
            listing: Listing::new(),
            symbol_table: SymbolTable::new(),
            references: ReferenceManager::new(),
            data_types: DataTypeManager::new(),
            comments: gr_program::comments::CommentManager::new(),
            metadata: gr_program::metadata::ProgramMetadata::default(),
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
            arch: gr_loader::Architecture::X86_64,
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
            dwarf: gr_loader::dwarf::DwarfInfo::default(),
            dynamic: DynamicInfo::default(),
            address_map: gr_core::address::AddressMap::new(),
        };

        let arch = gr_arch::arch::create_architecture(gr_loader::Architecture::X86_64).unwrap();

        Program {
            name: "test".into(),
            arch,
            info,
            listing: Listing::new(),
            symbol_table: SymbolTable::new(),
            references: ReferenceManager::new(),
            data_types: DataTypeManager::new(),
            comments: gr_program::comments::CommentManager::new(),
            metadata: gr_program::metadata::ProgramMetadata::default(),
        }
    }
}
