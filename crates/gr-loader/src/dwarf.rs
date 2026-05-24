use std::collections::BTreeMap;

use gimli::{AttributeValue, DebuggingInformationEntry, EndianSlice, LittleEndian, UnitHeader};
use object::{Object, ObjectSection};

#[derive(Debug, Clone)]
pub struct DwarfFunctionInfo {
    pub name: String,
    pub low_pc: u64,
    pub high_pc: u64,
    pub return_type: Option<String>,
    pub parameters: Vec<DwarfParameter>,
    pub variables: Vec<DwarfVariable>,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DwarfParameter {
    pub name: String,
    pub type_name: String,
    pub location: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct DwarfVariable {
    pub name: String,
    pub type_name: String,
    pub stack_offset: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct DwarfTypeInfo {
    pub name: String,
    pub size: u64,
    pub kind: DwarfTypeKind,
}

#[derive(Debug, Clone)]
pub enum DwarfTypeKind {
    Base,
    Pointer(String),
    Struct(Vec<(String, String, u64)>),
    Array(String, u64),
    Typedef(String),
    Enum(Vec<(String, i64)>),
    Void,
}

#[derive(Debug, Clone)]
pub struct DwarfLineEntry {
    pub address: u64,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Default)]
pub struct DwarfInfo {
    pub functions: Vec<DwarfFunctionInfo>,
    pub types: Vec<DwarfTypeInfo>,
    pub compile_units: Vec<String>,
    pub line_table: Vec<DwarfLineEntry>,
}

impl DwarfInfo {
    pub fn function_at(&self, addr: u64) -> Option<&DwarfFunctionInfo> {
        self.functions
            .iter()
            .find(|f| addr >= f.low_pc && addr < f.high_pc)
    }

    pub fn line_at(&self, addr: u64) -> Option<&DwarfLineEntry> {
        self.line_table
            .iter()
            .rfind(|e| e.address <= addr)
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.types.is_empty()
    }
}

type GimliSlice<'a> = EndianSlice<'a, LittleEndian>;

pub fn parse_dwarf(data: &[u8]) -> Result<DwarfInfo, String> {
    let obj = object::File::parse(data).map_err(|e| format!("object parse: {}", e))?;

    let load_section = |id: gimli::SectionId| -> Result<GimliSlice<'_>, gimli::Error> {
        Ok(obj
            .section_by_name(id.name())
            .map(|s| s.data().unwrap_or(&[]))
            .map(|d| EndianSlice::new(d, LittleEndian))
            .unwrap_or_else(|| EndianSlice::new(&[], LittleEndian)))
    };

    let dwarf = gimli::Dwarf::load(load_section).map_err(|e| format!("dwarf load: {}", e))?;

    let mut info = DwarfInfo::default();
    let mut type_names: BTreeMap<gimli::DebugInfoOffset, String> = BTreeMap::new();

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let unit = dwarf
            .unit(header)
            .map_err(|e| format!("unit: {}", e))?;

        collect_type_names(&dwarf, &unit, &header, &mut type_names);

        let mut entries = unit.entries();
        let mut current_func: Option<DwarfFunctionInfo> = None;
        while let Ok(Some((depth, entry))) = entries.next_dfs() {
            if depth <= 1
                && let Some(func) = current_func.take() {
                    info.functions.push(func);
                }
            if entry.tag() == gimli::DW_TAG_subprogram {
                current_func = parse_subprogram(&dwarf, &unit, entry, &type_names);
            } else if entry.tag() == gimli::DW_TAG_formal_parameter {
                if let Some(ref mut func) = current_func {
                    let param_name = get_attr_string(&dwarf, &unit, entry, gimli::DW_AT_name)
                        .unwrap_or_else(|| format!("param_{}", func.parameters.len()));
                    let type_name = entry
                        .attr_value(gimli::DW_AT_type)
                        .ok()
                        .flatten()
                        .and_then(|v| resolve_type_ref(v, &type_names))
                        .unwrap_or_else(|| "unknown".into());
                    func.parameters.push(DwarfParameter {
                        name: param_name,
                        type_name,
                        location: None,
                    });
                }
            } else if entry.tag() == gimli::DW_TAG_variable && depth > 1 {
                if let Some(ref mut func) = current_func
                    && let Some(var_name) = get_attr_string(&dwarf, &unit, entry, gimli::DW_AT_name) {
                        let type_name = entry
                            .attr_value(gimli::DW_AT_type)
                            .ok()
                            .flatten()
                            .and_then(|v| resolve_type_ref(v, &type_names))
                            .unwrap_or_else(|| "unknown".into());
                        func.variables.push(DwarfVariable {
                            name: var_name,
                            type_name,
                            stack_offset: None,
                        });
                    }
            } else if entry.tag() == gimli::DW_TAG_compile_unit
                && let Some(name) = get_attr_string(&dwarf, &unit, entry, gimli::DW_AT_name) {
                    info.compile_units.push(name);
                }
        }
        if let Some(func) = current_func.take() {
            info.functions.push(func);
        }
    }

    for name in type_names.values() {
        info.types.push(DwarfTypeInfo {
            name: name.clone(),
            size: 0,
            kind: DwarfTypeKind::Base,
        });
    }

    Ok(info)
}

fn collect_type_names(
    dwarf: &gimli::Dwarf<GimliSlice<'_>>,
    unit: &gimli::Unit<GimliSlice<'_>>,
    header: &UnitHeader<GimliSlice<'_>>,
    type_names: &mut BTreeMap<gimli::DebugInfoOffset, String>,
) {
    let mut entries = unit.entries();
    while let Ok(Some((_, entry))) = entries.next_dfs() {
        let tag = entry.tag();
        if matches!(
            tag,
            gimli::DW_TAG_base_type
                | gimli::DW_TAG_typedef
                | gimli::DW_TAG_structure_type
                | gimli::DW_TAG_union_type
                | gimli::DW_TAG_enumeration_type
                | gimli::DW_TAG_pointer_type
                | gimli::DW_TAG_const_type
        ) {
            if let Some(name) = get_attr_string(dwarf, unit, entry, gimli::DW_AT_name) {
                if let Some(offset) = entry.offset().to_debug_info_offset(header) {
                    type_names.insert(offset, name);
                }
            } else if tag == gimli::DW_TAG_pointer_type
                && let Some(offset) = entry.offset().to_debug_info_offset(header) {
                    type_names.insert(offset, "void*".to_string());
                }
        }
    }
}

fn parse_subprogram(
    dwarf: &gimli::Dwarf<GimliSlice<'_>>,
    unit: &gimli::Unit<GimliSlice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, GimliSlice<'_>>,
    type_names: &BTreeMap<gimli::DebugInfoOffset, String>,
) -> Option<DwarfFunctionInfo> {
    let name = get_attr_string(dwarf, unit, entry, gimli::DW_AT_name)
        .or_else(|| get_attr_string(dwarf, unit, entry, gimli::DW_AT_linkage_name))?;

    let low_pc = entry
        .attr_value(gimli::DW_AT_low_pc)
        .ok()?
        .and_then(|v| match v {
            AttributeValue::Addr(a) => Some(a),
            _ => None,
        })?;

    let high_pc = entry
        .attr_value(gimli::DW_AT_high_pc)
        .ok()?
        .and_then(|v| match v {
            AttributeValue::Udata(len) => Some(low_pc + len),
            AttributeValue::Addr(a) => Some(a),
            _ => None,
        })
        .unwrap_or(low_pc + 1);

    let return_type = entry
        .attr_value(gimli::DW_AT_type)
        .ok()
        .flatten()
        .and_then(|v| resolve_type_ref(v, type_names));

    let (source_file, source_line) = get_source_location(dwarf, unit, entry);

    Some(DwarfFunctionInfo {
        name,
        low_pc,
        high_pc,
        return_type,
        parameters: Vec::new(),
        variables: Vec::new(),
        source_file,
        source_line,
    })
}

fn get_attr_string(
    dwarf: &gimli::Dwarf<GimliSlice<'_>>,
    _unit: &gimli::Unit<GimliSlice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, GimliSlice<'_>>,
    attr_name: gimli::DwAt,
) -> Option<String> {
    let attr = entry.attr_value(attr_name).ok()??;
    match attr {
        AttributeValue::String(s) => std::str::from_utf8(s.slice()).ok().map(|s| s.to_string()),
        AttributeValue::DebugStrRef(offset) => {
            let s = dwarf.debug_str.get_str(offset).ok()?;
            std::str::from_utf8(s.slice()).ok().map(|s| s.to_string())
        }
        AttributeValue::DebugLineStrRef(offset) => {
            let s = dwarf.debug_line_str.get_str(offset).ok()?;
            std::str::from_utf8(s.slice()).ok().map(|s| s.to_string())
        }
        _ => None,
    }
}

fn resolve_type_ref(
    val: AttributeValue<GimliSlice<'_>>,
    type_names: &BTreeMap<gimli::DebugInfoOffset, String>,
) -> Option<String> {
    match val {
        AttributeValue::UnitRef(unit_offset) => {
            let debug_offset = gimli::DebugInfoOffset(unit_offset.0);
            type_names.get(&debug_offset).cloned()
        }
        _ => None,
    }
}

fn get_source_location(
    _dwarf: &gimli::Dwarf<GimliSlice<'_>>,
    _unit: &gimli::Unit<GimliSlice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, GimliSlice<'_>>,
) -> (Option<String>, Option<u32>) {
    let line = entry
        .attr_value(gimli::DW_AT_decl_line)
        .ok()
        .flatten()
        .and_then(|v| match v {
            AttributeValue::Udata(n) => Some(n as u32),
            _ => None,
        });
    (None, line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_binary() {
        let result = parse_dwarf(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn dwarf_info_default() {
        let info = DwarfInfo::default();
        assert!(info.is_empty());
        assert!(info.function_at(0x1000).is_none());
    }
}
