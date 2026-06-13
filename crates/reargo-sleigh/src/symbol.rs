use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum SleighSymbol {
    Space { name: String, index: u32 },
    Token { name: String, size: u32 },
    Value { name: String },
    Context { name: String },
    Varnode { name: String, space: u32, offset: u64, size: u32 },
    Subtable { name: String, constructors: Vec<usize> },
    UserOp { name: String, index: u32 },
    Start,
    End,
    Next,
    Operand { name: String },
    Epsilon,
}

impl SleighSymbol {
    pub fn name(&self) -> &str {
        match self {
            Self::Space { name, .. } => name,
            Self::Token { name, .. } => name,
            Self::Value { name, .. } => name,
            Self::Context { name, .. } => name,
            Self::Varnode { name, .. } => name,
            Self::Subtable { name, .. } => name,
            Self::UserOp { name, .. } => name,
            Self::Operand { name, .. } => name,
            Self::Start => "inst_start",
            Self::End => "inst_end",
            Self::Next => "inst_next",
            Self::Epsilon => "epsilon",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Constructor {
    pub id: u32,
    pub parent_id: u32,
    pub minimum_length: u32,
    pub num_operands: u32,
    pub print_pieces: Vec<String>,
    pub context_changes: Vec<ContextChange>,
}

#[derive(Debug, Clone)]
pub struct ContextChange {
    pub space: u32,
    pub offset: u64,
    pub value: u64,
}

#[derive(Debug, Default)]
pub struct SymbolTable {
    symbols: Vec<SleighSymbol>,
    name_index: BTreeMap<String, usize>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, symbol: SleighSymbol) -> usize {
        let idx = self.symbols.len();
        self.name_index.insert(symbol.name().to_string(), idx);
        self.symbols.push(symbol);
        idx
    }

    pub fn get(&self, index: usize) -> Option<&SleighSymbol> {
        self.symbols.get(index)
    }

    pub fn find_by_name(&self, name: &str) -> Option<usize> {
        self.name_index.get(name).copied()
    }

    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub fn varnodes(&self) -> impl Iterator<Item = (usize, &SleighSymbol)> {
        self.symbols.iter().enumerate().filter(|(_, s)| matches!(s, SleighSymbol::Varnode { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_table_basic() {
        let mut table = SymbolTable::new();
        table.add(SleighSymbol::Space { name: "ram".into(), index: 0 });
        table.add(SleighSymbol::Varnode { name: "RAX".into(), space: 1, offset: 0, size: 8 });
        assert_eq!(table.len(), 2);
        assert_eq!(table.find_by_name("RAX"), Some(1));
        assert!(table.find_by_name("RBX").is_none());
    }
}
