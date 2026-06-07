// Binary hash computation for identification and matching.

pub fn md5_simple(data: &[u8]) -> [u8; 16] {
    let mut hash = [0u8; 16];
    let mut state: u64 = 0x0123456789ABCDEF;
    for (i, &byte) in data.iter().enumerate() {
        state = state.wrapping_mul(0x100000001B3).wrapping_add(byte as u64);
        hash[i % 16] ^= (state >> ((i % 8) * 8)) as u8;
    }
    hash
}

pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

pub fn function_hash(bytes: &[u8], max_bytes: usize) -> u64 {
    let len = bytes.len().min(max_bytes);
    fnv1a_64(&bytes[..len])
}

pub fn hex_string(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_deterministic() {
        assert_eq!(fnv1a_64(b"hello"), fnv1a_64(b"hello"));
        assert_ne!(fnv1a_64(b"hello"), fnv1a_64(b"world"));
    }

    #[test]
    fn crc32_known() {
        assert_eq!(crc32(b""), 0);
        assert_ne!(crc32(b"test"), 0);
        assert_eq!(crc32(b"test"), crc32(b"test"));
    }

    #[test]
    fn function_hash_truncate() {
        let data = vec![0u8; 1000];
        let h1 = function_hash(&data, 64);
        let h2 = function_hash(&data, 128);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hex_output() {
        assert_eq!(hex_string(&[0xDE, 0xAD]), "dead");
    }
}
