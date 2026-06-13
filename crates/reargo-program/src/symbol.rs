use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    Function,
    Label,
    Data,
    ExternalFunction,
    ExternalData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    Imported,
    Analysis,
    UserDefined,
    Default,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub symbol_type: SymbolType,
    pub source: SourceType,
}

impl Symbol {
    pub fn new(name: String, address: u64, symbol_type: SymbolType, source: SourceType) -> Self {
        Self {
            name,
            address,
            symbol_type,
            source,
        }
    }
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x} {:?} {}", self.address, self.symbol_type, self.name)
    }
}

#[derive(Debug, Default)]
pub struct SymbolTable {
    by_address: HashMap<u64, Vec<Symbol>>,
    by_name: HashMap<String, Vec<u64>>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, symbol: Symbol) {
        let addr = symbol.address;
        let name = symbol.name.clone();
        self.by_address.entry(addr).or_default().push(symbol);
        self.by_name.entry(name).or_default().push(addr);
    }

    pub fn get_at(&self, address: u64) -> &[Symbol] {
        self.by_address.get(&address).map_or(&[], |v| v.as_slice())
    }

    /// Force `address`'s primary (first) symbol to `name`, as a
    /// `UserDefined` symbol. Inserts a new symbol at the front if
    /// none exists. Used by the user-override layer so a manual
    /// rename wins over every analysis-supplied name and propagates
    /// through `primary_at` / `function_name_at` everywhere.
    pub fn set_primary(&mut self, address: u64, name: impl Into<String>, ty: SymbolType) {
        let name = name.into();
        self.by_name.entry(name.clone()).or_default().push(address);
        let sym = Symbol::new(name, address, ty, SourceType::UserDefined);
        let entry = self.by_address.entry(address).or_default();
        // Front-insert so `primary_at` (which returns `.first()`)
        // returns the user override.
        entry.insert(0, sym);
    }

    /// Remove every symbol at `address`. Returns how many were
    /// removed. Used to purge symbols for a function the user has
    /// marked as not-a-function.
    pub fn remove_at(&mut self, address: u64) -> usize {
        if let Some(syms) = self.by_address.remove(&address) {
            for s in &syms {
                if let Some(addrs) = self.by_name.get_mut(&s.name) {
                    addrs.retain(|&a| a != address);
                }
            }
            syms.len()
        } else {
            0
        }
    }

    pub fn get_by_name(&self, name: &str) -> Option<&[u64]> {
        self.by_name.get(name).map(|v| v.as_slice())
    }

    pub fn primary_at(&self, address: u64) -> Option<&Symbol> {
        self.by_address.get(&address).and_then(|syms| syms.first())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Symbol> {
        self.by_address.values().flat_map(|v| v.iter())
    }

    pub fn len(&self) -> usize {
        self.by_address.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    pub fn function_symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.iter()
            .filter(|s| matches!(s.symbol_type, SymbolType::Function | SymbolType::ExternalFunction))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_table_add_and_lookup() {
        let mut table = SymbolTable::new();
        table.add(Symbol::new(
            "main".into(),
            0x1000,
            SymbolType::Function,
            SourceType::Imported,
        ));
        table.add(Symbol::new(
            "printf".into(),
            0x2000,
            SymbolType::ExternalFunction,
            SourceType::Imported,
        ));

        assert_eq!(table.len(), 2);
        assert_eq!(table.primary_at(0x1000).unwrap().name, "main");
        assert_eq!(table.get_by_name("printf").unwrap(), &[0x2000]);
        assert_eq!(table.function_symbols().count(), 2);
    }
}
