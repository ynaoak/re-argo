use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ContextField {
    pub name: String,
    pub start_bit: u32,
    pub end_bit: u32,
    pub signed: bool,
    pub default_value: u64,
}

impl ContextField {
    pub fn bit_size(&self) -> u32 {
        self.end_bit - self.start_bit + 1
    }

    pub fn mask(&self) -> u64 {
        ((1u64 << self.bit_size()) - 1) << self.start_bit
    }

    pub fn extract(&self, context: u64) -> u64 {
        (context >> self.start_bit) & ((1u64 << self.bit_size()) - 1)
    }

    pub fn inject(&self, context: u64, value: u64) -> u64 {
        let mask = self.mask();
        (context & !mask) | ((value << self.start_bit) & mask)
    }
}

#[derive(Debug, Default)]
pub struct ContextDatabase {
    fields: Vec<ContextField>,
    field_index: BTreeMap<String, usize>,
    address_context: BTreeMap<u64, u64>,
    default_context: u64,
}

impl ContextDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_field(&mut self, field: ContextField) {
        let idx = self.fields.len();
        self.default_context = field.inject(self.default_context, field.default_value);
        self.field_index.insert(field.name.clone(), idx);
        self.fields.push(field);
    }

    pub fn get_field(&self, name: &str) -> Option<&ContextField> {
        self.field_index.get(name).and_then(|&idx| self.fields.get(idx))
    }

    pub fn get_context(&self, address: u64) -> u64 {
        self.address_context.get(&address).copied().unwrap_or(self.default_context)
    }

    pub fn set_context(&mut self, address: u64, context: u64) {
        self.address_context.insert(address, context);
    }

    pub fn set_field_at(&mut self, address: u64, field_name: &str, value: u64) {
        if let Some(&idx) = self.field_index.get(field_name) {
            let field = &self.fields[idx];
            let current = self.get_context(address);
            let updated = field.inject(current, value);
            self.address_context.insert(address, updated);
        }
    }

    pub fn get_field_at(&self, address: u64, field_name: &str) -> Option<u64> {
        let &idx = self.field_index.get(field_name)?;
        let field = &self.fields[idx];
        Some(field.extract(self.get_context(address)))
    }

    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    pub fn fields(&self) -> &[ContextField] {
        &self.fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_field_extract_inject() {
        let field = ContextField {
            name: "mode".into(),
            start_bit: 0,
            end_bit: 1,
            signed: false,
            default_value: 0,
        };
        assert_eq!(field.bit_size(), 2);
        assert_eq!(field.extract(0b1010), 0b10);
        assert_eq!(field.inject(0, 0b11), 0b11);
    }

    #[test]
    fn context_database_basic() {
        let mut db = ContextDatabase::new();
        db.add_field(ContextField {
            name: "addrsize".into(),
            start_bit: 0,
            end_bit: 0,
            signed: false,
            default_value: 1,
        });
        db.add_field(ContextField {
            name: "opsize".into(),
            start_bit: 1,
            end_bit: 1,
            signed: false,
            default_value: 1,
        });
        assert_eq!(db.field_count(), 2);
        assert_eq!(db.get_field_at(0x1000, "addrsize"), Some(1));
        db.set_field_at(0x1000, "addrsize", 0);
        assert_eq!(db.get_field_at(0x1000, "addrsize"), Some(0));
        assert_eq!(db.get_field_at(0x2000, "addrsize"), Some(1));
    }
}
