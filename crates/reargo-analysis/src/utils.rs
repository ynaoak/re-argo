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

/// The opcode byte of the x86-64 instruction `bytes`: its first byte
/// that is no legacy prefix (operand / address size, lock, rep, segment)
/// or REX prefix. An instruction a decoder reads as, say, `imul r, r/m,
/// imm` has `0x69` / `0x6b` there, an SSE / AVX one `0x0f` (or a VEX /
/// EVEX `0xc4` / `0xc5` / `0x62`), so a scan for such instructions can
/// skip the others without decoding them.
pub fn x86_64_opcode_byte(bytes: &[u8]) -> Option<u8> {
    bytes
        .iter()
        .copied()
        .find(|b| !matches!(b, 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x40..=0x4f))
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
