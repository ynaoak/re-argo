// Program diff: compare two analysis results.

use crate::project::ProjectSummary;

#[derive(Debug)]
pub struct ProgramDiff {
    pub added_functions: Vec<u64>,
    pub removed_functions: Vec<u64>,
    pub modified_functions: Vec<(u64, String)>,
    pub added_symbols: usize,
    pub removed_symbols: usize,
    pub reference_delta: i64,
}

impl ProgramDiff {
    pub fn compare(old: &ProjectSummary, new: &ProjectSummary) -> Self {
        let old_funcs: std::collections::BTreeSet<u64> = old.functions.iter().map(|f| f.address).collect();
        let new_funcs: std::collections::BTreeSet<u64> = new.functions.iter().map(|f| f.address).collect();

        let added_functions: Vec<u64> = new_funcs.difference(&old_funcs).copied().collect();
        let removed_functions: Vec<u64> = old_funcs.difference(&new_funcs).copied().collect();

        let old_map: std::collections::HashMap<u64, &crate::project::FunctionSummary> =
            old.functions.iter().map(|f| (f.address, f)).collect();
        let new_map: std::collections::HashMap<u64, &crate::project::FunctionSummary> =
            new.functions.iter().map(|f| (f.address, f)).collect();

        let mut modified_functions = Vec::new();
        for addr in old_funcs.intersection(&new_funcs) {
            if let (Some(o), Some(n)) = (old_map.get(addr), new_map.get(addr))
                && (o.name != n.name || o.block_count != n.block_count) {
                    modified_functions.push((*addr, format!("{} -> {}", o.name, n.name)));
                }
        }

        let old_sym_count = old.symbols.len();
        let new_sym_count = new.symbols.len();

        Self {
            added_functions,
            removed_functions,
            modified_functions,
            added_symbols: new_sym_count.saturating_sub(old_sym_count),
            removed_symbols: old_sym_count.saturating_sub(new_sym_count),
            reference_delta: new.references_count as i64 - old.references_count as i64,
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.added_functions.is_empty()
            || !self.removed_functions.is_empty()
            || !self.modified_functions.is_empty()
            || self.added_symbols > 0
            || self.removed_symbols > 0
    }

    pub fn summary(&self) -> String {
        format!(
            "+{} -{} ~{} functions, +{} -{} symbols, {} refs",
            self.added_functions.len(),
            self.removed_functions.len(),
            self.modified_functions.len(),
            self.added_symbols,
            self.removed_symbols,
            if self.reference_delta >= 0 { format!("+{}", self.reference_delta) } else { format!("{}", self.reference_delta) },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::{FunctionSummary, ProjectSummary};

    fn make_summary(funcs: Vec<(u64, &str)>) -> ProjectSummary {
        ProjectSummary {
            name: "test".into(),
            format: "ELF".into(),
            arch: "x86_64".into(),
            bits: 64,
            entry_point: 0x1000,
            functions: funcs.iter().map(|(a, n)| FunctionSummary {
                address: *a, name: n.to_string(), block_count: 1, call_count: 0, stack_size: 0,
            }).collect(),
            symbols: Vec::new(),
            references: Vec::new(),
            references_count: 0,
            instructions_count: 0,
            has_dwarf: false,
            dwarf_functions: 0,
            analyzers_run: Vec::new(),
            version: "0.1.0".into(),
            dynamic_libs: Vec::new(),
            import_count: 0,
        }
    }

    #[test]
    fn diff_added_functions() {
        let old = make_summary(vec![(0x1000, "main")]);
        let new = make_summary(vec![(0x1000, "main"), (0x2000, "helper")]);
        let diff = ProgramDiff::compare(&old, &new);
        assert_eq!(diff.added_functions, vec![0x2000]);
        assert!(diff.has_changes());
    }

    #[test]
    fn diff_no_changes() {
        let a = make_summary(vec![(0x1000, "main")]);
        let b = make_summary(vec![(0x1000, "main")]);
        let diff = ProgramDiff::compare(&a, &b);
        assert!(!diff.has_changes());
    }
}
