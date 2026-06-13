// Variable scope tracking for decompiler output.


#[derive(Debug, Clone)]
pub struct VarScope {
    pub name: String,
    pub var_type: String,
    pub start_addr: u64,
    pub end_addr: u64,
    pub storage: ScopeStorage,
}

#[derive(Debug, Clone)]
pub enum ScopeStorage {
    Register(u64, u32),
    Stack(i64, u32),
    Global(u64, u32),
}

#[derive(Debug, Default)]
pub struct ScopeManager {
    scopes: Vec<VarScope>,
    block_nesting: Vec<u64>,
}

impl ScopeManager {
    pub fn new() -> Self { Self::default() }

    pub fn add_scope(&mut self, scope: VarScope) {
        self.scopes.push(scope);
    }

    pub fn vars_at(&self, address: u64) -> Vec<&VarScope> {
        self.scopes.iter()
            .filter(|s| address >= s.start_addr && address < s.end_addr)
            .collect()
    }

    pub fn all_vars(&self) -> &[VarScope] {
        &self.scopes
    }

    pub fn enter_block(&mut self, addr: u64) {
        self.block_nesting.push(addr);
    }

    pub fn exit_block(&mut self) -> Option<u64> {
        self.block_nesting.pop()
    }

    pub fn nesting_depth(&self) -> usize {
        self.block_nesting.len()
    }

    pub fn generate_declarations(&self, address: u64) -> Vec<String> {
        self.vars_at(address).iter()
            .filter(|v| v.start_addr == address)
            .map(|v| format!("{} {};", v.var_type, v.name))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_tracking() {
        let mut mgr = ScopeManager::new();
        mgr.add_scope(VarScope {
            name: "x".into(), var_type: "int".into(),
            start_addr: 0x1000, end_addr: 0x1100,
            storage: ScopeStorage::Stack(-8, 4),
        });
        mgr.add_scope(VarScope {
            name: "y".into(), var_type: "int".into(),
            start_addr: 0x1020, end_addr: 0x1080,
            storage: ScopeStorage::Stack(-12, 4),
        });
        assert_eq!(mgr.vars_at(0x1050).len(), 2);
        assert_eq!(mgr.vars_at(0x1090).len(), 1);
        assert_eq!(mgr.vars_at(0x1200).len(), 0);
    }

    #[test]
    fn declarations() {
        let mut mgr = ScopeManager::new();
        mgr.add_scope(VarScope {
            name: "count".into(), var_type: "uint32_t".into(),
            start_addr: 0x1000, end_addr: 0x2000,
            storage: ScopeStorage::Register(0, 4),
        });
        let decls = mgr.generate_declarations(0x1000);
        assert_eq!(decls, vec!["uint32_t count;"]);
    }

    #[test]
    fn block_nesting() {
        let mut mgr = ScopeManager::new();
        mgr.enter_block(0x1000);
        mgr.enter_block(0x1020);
        assert_eq!(mgr.nesting_depth(), 2);
        mgr.exit_block();
        assert_eq!(mgr.nesting_depth(), 1);
    }
}
