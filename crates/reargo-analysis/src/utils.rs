// Shared utility functions for analyzers.

pub fn is_valid_address(val: u64, ranges: &[(u64, u64)]) -> bool {
    if val < 0x1000 {
        return false;
    }
    ranges.iter().any(|&(start, end)| val >= start && val < end)
}

pub fn collect_code_ranges(sections: &[reargo_loader::Section]) -> Vec<(u64, u64)> {
    sections
        .iter()
        .filter(|s| s.flags.contains(reargo_loader::SectionFlags::EXECUTE))
        .map(|s| (s.address, s.address + s.size))
        .collect()
}

pub fn collect_valid_ranges(sections: &[reargo_loader::Section]) -> Vec<(u64, u64)> {
    sections
        .iter()
        .filter(|s| s.address != 0 && s.size > 0)
        .map(|s| (s.address, s.address + s.size))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_address_check() {
        let ranges = vec![(0x400000, 0x500000), (0x600000, 0x700000)];
        assert!(is_valid_address(0x400100, &ranges));
        assert!(!is_valid_address(0x100, &ranges));
        assert!(!is_valid_address(0x550000, &ranges));
    }
}
