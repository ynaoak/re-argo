// Integration tests: verify crate interop and end-to-end workflows.

use reargo_core::address::{Address, AddressRange, AddressSet, SpaceId, Endian};
use reargo_core::pcode::{OpCode, PcodeOp, SeqNum, VarnodeData};

#[test]
fn address_model_complete() {
    let mut mgr = reargo_core::address::SpaceManager::new();
    let defaults = mgr.build_default_spaces(Endian::Little);
    assert_eq!(mgr.get_space(defaults.ram).unwrap().name, "ram");
    assert_eq!(mgr.get_space(defaults.constant).unwrap().name, "const");

    let addr = Address::new(defaults.ram, 0x1000);
    let range = AddressRange::new(addr, 0x100);
    assert!(range.contains(&Address::new(defaults.ram, 0x1050)));

    let mut set = AddressSet::new();
    set.add(range);
    assert!(set.contains(&Address::new(defaults.ram, 0x1050)));
}

#[test]
fn pcode_ir_complete() {
    for val in 1..=74u32 {
        if val == 45 { continue; }
        let op = OpCode::from_u32(val).unwrap();
        let name = op.name();
        assert_eq!(OpCode::from_name(name).unwrap(), op);
    }
}

#[test]
fn datatype_manager_builtins() {
    let mgr = reargo_core::datatype::DataTypeManager::new();
    assert!(mgr.type_count() >= 30);
    assert!(mgr.find_by_name("void").is_some());
    assert!(mgr.find_by_name("size_t").is_some());
    assert!(mgr.find_by_name("wchar_t").is_some());
    assert!(mgr.find_by_name("long double").is_some());
}

#[test]
fn segmented_address() {
    let seg = reargo_core::address::SegmentedAddress::new(0x0800, 0x0100);
    assert_eq!(seg.to_linear(), 0x8100);
    assert_eq!(format!("{}", seg), "0800:0100");
}

#[test]
fn address_map_roundtrip() {
    let mut map = reargo_core::address::AddressMap::new();
    map.add_mapping(0x200, 0x401000, 0x1000);
    assert_eq!(map.file_to_virtual(0x300), Some(0x401100));
    assert_eq!(map.virtual_to_file(0x401500), Some(0x700));
}

#[test]
fn memory_read_write() {
    use reargo_loader::memory::{Memory, MemoryBlock, MemoryFlags};
    use std::sync::Arc;

    let mut mem = Memory::new(SpaceId::RAM, Endian::Little);
    mem.add_block(MemoryBlock {
        name: ".text".into(),
        start: 0x1000,
        size: 4,
        flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
        data: Some(Arc::from([0xDE, 0xAD, 0xBE, 0xEF].as_slice())),
    });

    assert_eq!(mem.read_byte(0x1000), Some(0xDE));
    assert_eq!(mem.read_u32(0x1000).unwrap(), 0xEFBEADDE);

    let mut buf = [0u8; 15];
    let len = mem.read_instruction_bytes(0x1000, &mut buf);
    assert_eq!(len, 4);
}

#[test]
fn emulator_arithmetic() {
    let mut emu = reargo_emulator::Emulator::new();
    emu.state.write_register(0x00, 8, 100);
    emu.state.write_register(0x08, 8, 42);

    let seq = SeqNum::new(Address::new(SpaceId::RAM, 0x1000), 0);
    let add = PcodeOp::new(OpCode::IntAdd, seq)
        .with_output(VarnodeData::new(SpaceId::REGISTER, 0x00, 8))
        .with_input(VarnodeData::new(SpaceId::REGISTER, 0x00, 8))
        .with_input(VarnodeData::new(SpaceId::REGISTER, 0x08, 8));

    emu.execute_op(&add).unwrap();
    assert_eq!(emu.state.read_register(0x00, 8), 142);
}

#[test]
fn emulator_float_ops() {
    let mut emu = reargo_emulator::Emulator::new();
    let seq = SeqNum::new(Address::new(SpaceId::RAM, 0), 0);

    let add = PcodeOp::new(OpCode::FloatAdd, seq)
        .with_output(VarnodeData::new(SpaceId::REGISTER, 0, 8))
        .with_input(VarnodeData::new(SpaceId::CONST, 1.5f64.to_bits(), 8))
        .with_input(VarnodeData::new(SpaceId::CONST, 2.5f64.to_bits(), 8));

    emu.execute_op(&add).unwrap();
    let result = f64::from_bits(emu.state.read_register(0, 8));
    assert!((result - 4.0).abs() < 0.001);
}

#[test]
fn breakpoint_manager() {
    let mut mgr = reargo_emulator::BreakpointManager::new();
    let id1 = mgr.add(0x1000);
    let _id2 = mgr.add(0x2000);
    assert!(mgr.check(0x1000));
    assert!(mgr.check(0x2000));
    assert!(!mgr.check(0x3000));
    mgr.remove(id1);
    assert!(!mgr.check(0x1000));
}

#[test]
fn sleigh_decision_tree() {
    use reargo_sleigh::decision::{DecisionNode, PatternMatch};

    let node = DecisionNode {
        start_bit: 0,
        bit_size: 8,
        is_context: false,
        patterns: vec![
            PatternMatch { mask: 0xFF, value: 0x90, constructor_id: 1 },
            PatternMatch { mask: 0xFF, value: 0xC3, constructor_id: 2 },
            PatternMatch { mask: 0xF8, value: 0x50, constructor_id: 3 },
        ],
        children: Vec::new(),
    };

    assert_eq!(node.resolve(&[0x90], 0), Some(1));
    assert_eq!(node.resolve(&[0xC3], 0), Some(2));
    assert_eq!(node.resolve(&[0x55], 0), Some(3));
}

#[test]
fn type_inference() {
    let t = reargo_decompile::InferredType::Integer { size: 4, signed: true };
    assert_eq!(t.to_c_type(), "int32_t");

    let p = reargo_decompile::InferredType::Pointer { pointee_size: Some(1) };
    assert_eq!(p.to_c_type(), "char*");
}

#[test]
fn project_summary_roundtrip() {
    use reargo_program::project::*;

    let summary = ProjectSummary {
        name: "test".into(),
        format: "ELF".into(),
        arch: "x86_64".into(),
        bits: 64,
        entry_point: 0x1000,
        functions: vec![FunctionSummary {
            address: 0x1000, name: "main".into(),
            block_count: 3, call_count: 2, stack_size: 0x28,
        }],
        symbols: Vec::new(),
        references: Vec::new(),
        comments: Vec::new(),
        references_count: 10,
        instructions_count: 50,
        has_dwarf: false,
        dwarf_functions: 0,
        analyzers_run: vec!["test".into()],
        version: "0.1.0".into(),
        dynamic_libs: Vec::new(),
        import_count: 0,
    };

    let json = serde_json::to_string(&summary).unwrap();
    let loaded: ProjectSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(loaded.name, "test");
    assert_eq!(loaded.functions[0].name, "main");
}

#[test]
fn flirt_pattern_matching() {
    use reargo_loader::flirt::{FlirtDatabase, FlirtPattern};

    let mut db = FlirtDatabase::new();
    db.add(FlirtPattern::from_hex_pattern("554889E5", "x86_64_prologue").unwrap());
    db.add(FlirtPattern::from_hex_pattern("4883EC", "sub_rsp").unwrap());

    let code = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];
    let matches = db.scan(&code, 0x1000);
    assert!(!matches.is_empty());
    assert_eq!(matches[0].1, "x86_64_prologue");
}

#[test]
fn hash_functions() {
    use reargo_loader::hash::*;

    let h1 = fnv1a_64(b"hello");
    let h2 = fnv1a_64(b"hello");
    assert_eq!(h1, h2);
    assert_ne!(fnv1a_64(b"hello"), fnv1a_64(b"world"));

    let c = crc32(b"test");
    assert_ne!(c, 0);
    assert_eq!(c, crc32(b"test"));

    assert_eq!(hex_string(&[0xDE, 0xAD]), "dead");
}
