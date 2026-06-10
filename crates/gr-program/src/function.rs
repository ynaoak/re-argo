use std::collections::{BTreeMap, BTreeSet};

use gr_core::address::AddressSet;

#[derive(Debug, Clone)]
pub struct StackVariable {
    pub offset: i64,
    pub size: u32,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct StackFrame {
    pub local_size: u64,
    pub variables: BTreeMap<i64, StackVariable>,
}

impl StackFrame {
    pub fn add_variable(&mut self, offset: i64, size: u32) {
        if self.variables.contains_key(&offset) {
            return;
        }
        let name = if offset < 0 {
            format!("local_{:x}", (-offset) as u64)
        } else if offset >= 8 {
            format!("param_{:x}", offset as u64)
        } else {
            format!("var_{:x}", offset as u64)
        };
        self.variables.insert(offset, StackVariable {
            offset,
            size,
            name,
        });
    }

    pub fn get_name(&self, offset: i64) -> Option<&str> {
        self.variables.get(&offset).map(|v| v.name.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub entry_point: u64,
    pub name: String,
    pub body: AddressSet,
    pub calling_convention: Option<String>,
    pub is_thunk: bool,
    pub thunk_target: Option<u64>,
    pub call_targets: BTreeSet<u64>,
    pub stack_frame: StackFrame,
    /// Return type string from signature DB / DWARF / user override
    pub return_type: Option<String>,
    /// Parameter list: (name, type) pairs from signature DB / DWARF / user override
    pub parameters: Vec<(String, String)>,
    /// True when the function is known to never return (exit, abort, throw, …)
    pub no_return: bool,
    /// Library or module the function belongs to (e.g. "libc", "win32")
    pub library: Option<String>,
}

impl Function {
    pub fn new(entry_point: u64, name: String) -> Self {
        Self {
            entry_point,
            name,
            body: AddressSet::new(),
            calling_convention: None,
            is_thunk: false,
            thunk_target: None,
            call_targets: BTreeSet::new(),
            stack_frame: StackFrame::default(),
            return_type: None,
            parameters: Vec::new(),
            no_return: false,
            library: None,
        }
    }
}

impl std::fmt::Display for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x} {}", self.entry_point, self.name)?;
        if self.is_thunk
            && let Some(target) = self.thunk_target {
                write!(f, " -> thunk(0x{:x})", target)?;
            }
        Ok(())
    }
}
