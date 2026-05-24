// DWARF type reconstruction: struct/union/enum/typedef from debug info.

use gr_core::datatype::*;

pub fn dwarf_type_to_datatype(name: &str, kind: &crate::dwarf::DwarfTypeKind, size: u64) -> DataType {
    match kind {
        crate::dwarf::DwarfTypeKind::Base => {
            let meta = infer_meta(name, size);
            DataType::new(name, size as usize, meta)
        }
        crate::dwarf::DwarfTypeKind::Pointer(_) => {
            DataType::new(name, size as usize, MetaType::Ptr)
        }
        crate::dwarf::DwarfTypeKind::Typedef(target) => {
            DataType::new(name, size as usize, infer_meta(target, size))
        }
        crate::dwarf::DwarfTypeKind::Enum(_) => {
            DataType::new(name, if size > 0 { size as usize } else { 4 }, MetaType::Enum)
        }
        crate::dwarf::DwarfTypeKind::Struct(_) => {
            DataType::new(name, size as usize, MetaType::Struct)
        }
        crate::dwarf::DwarfTypeKind::Array(_, count) => {
            DataType::new(format!("{}[{}]", name, count), size as usize, MetaType::Array)
        }
        crate::dwarf::DwarfTypeKind::Void => DataType::void(),
    }
}

fn infer_meta(name: &str, size: u64) -> MetaType {
    let lower = name.to_lowercase();
    if lower.contains("float") || lower == "double" || lower == "long double" {
        return MetaType::Float;
    }
    if lower.contains("bool") || lower == "_bool" {
        return MetaType::Bool;
    }
    if lower.starts_with("unsigned") || lower.starts_with("uint") || lower == "size_t" || lower == "uintptr_t" {
        return MetaType::Uint;
    }
    if lower.contains("char") && size == 1 {
        return MetaType::Int;
    }
    if lower == "wchar_t" {
        return MetaType::Utf32;
    }
    MetaType::Int
}

pub fn import_dwarf_types(dwarf: &crate::dwarf::DwarfInfo, mgr: &mut DataTypeManager) -> usize {
    let mut imported = 0;
    for dt in &dwarf.types {
        if mgr.find_by_name(&dt.name).is_none() {
            let data_type = dwarf_type_to_datatype(&dt.name, &dt.kind, dt.size);
            mgr.add(data_type);
            imported += 1;
        }
    }
    imported
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dwarf::DwarfTypeKind;

    #[test]
    fn base_type_inference() {
        let dt = dwarf_type_to_datatype("unsigned int", &DwarfTypeKind::Base, 4);
        assert_eq!(dt.meta, MetaType::Uint);
        assert_eq!(dt.size, 4);
    }

    #[test]
    fn pointer_type() {
        let dt = dwarf_type_to_datatype("int*", &DwarfTypeKind::Pointer("int".into()), 8);
        assert_eq!(dt.meta, MetaType::Ptr);
    }

    #[test]
    fn float_detection() {
        let dt = dwarf_type_to_datatype("double", &DwarfTypeKind::Base, 8);
        assert_eq!(dt.meta, MetaType::Float);
    }

    #[test]
    fn void_type() {
        let dt = dwarf_type_to_datatype("void", &DwarfTypeKind::Void, 0);
        assert!(dt.is_void());
    }
}
