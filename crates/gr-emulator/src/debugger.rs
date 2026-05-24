/// GDB Remote Serial Protocol (RSP) client foundation.
/// Provides the protocol layer for connecting to GDB stubs,
/// QEMU, OpenOCD, and other RSP-compatible debug servers.

#[derive(Debug, Clone)]
pub struct GdbCommand {
    pub data: String,
}

impl GdbCommand {
    pub fn new(data: impl Into<String>) -> Self {
        Self { data: data.into() }
    }

    pub fn halt() -> Self { Self::new("?") }
    pub fn continue_exec() -> Self { Self::new("c") }
    pub fn step() -> Self { Self::new("s") }
    pub fn read_registers() -> Self { Self::new("g") }
    pub fn write_registers(hex_data: &str) -> Self { Self::new(format!("G{}", hex_data)) }

    pub fn read_memory(addr: u64, length: u64) -> Self {
        Self::new(format!("m{:x},{:x}", addr, length))
    }

    pub fn write_memory(addr: u64, hex_data: &str) -> Self {
        Self::new(format!("M{:x},{:x}:{}", addr, hex_data.len() / 2, hex_data))
    }

    pub fn set_breakpoint(addr: u64) -> Self {
        Self::new(format!("Z0,{:x},1", addr))
    }

    pub fn remove_breakpoint(addr: u64) -> Self {
        Self::new(format!("z0,{:x},1", addr))
    }

    pub fn set_watchpoint(addr: u64, length: u64, kind: WatchKind) -> Self {
        let type_code = match kind {
            WatchKind::Write => 2,
            WatchKind::Read => 3,
            WatchKind::Access => 4,
        };
        Self::new(format!("Z{},{:x},{:x}", type_code, addr, length))
    }

    pub fn kill() -> Self { Self::new("k") }
    pub fn detach() -> Self { Self::new("D") }

    pub fn encode(&self) -> Vec<u8> {
        let checksum: u8 = self.data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        format!("${}#{:02x}", self.data, checksum).into_bytes()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WatchKind {
    Write,
    Read,
    Access,
}

#[derive(Debug, Clone)]
pub enum GdbResponse {
    Ok,
    Error(u8),
    Data(String),
    Signal(u8),
    Exited(u8),
    Unknown(String),
}

impl GdbResponse {
    pub fn parse(data: &str) -> Self {
        if data == "OK" {
            return Self::Ok;
        }
        if let Some(rest) = data.strip_prefix('E')
            && let Ok(code) = u8::from_str_radix(rest, 16) {
                return Self::Error(code);
            }
        if let Some(rest) = data.strip_prefix('S')
            && let Ok(sig) = u8::from_str_radix(rest, 16) {
                return Self::Signal(sig);
            }
        if let Some(rest) = data.strip_prefix('W')
            && let Ok(code) = u8::from_str_radix(rest, 16) {
                return Self::Exited(code);
            }
        if let Some(rest) = data.strip_prefix('T')
            && rest.len() >= 2
                && let Ok(sig) = u8::from_str_radix(&rest[..2], 16) {
                    return Self::Signal(sig);
                }
        Self::Data(data.to_string())
    }
}

pub fn decode_packet(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?;
    let start = s.find('$')? + 1;
    let end = s.find('#')?;
    Some(s[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_command() {
        let cmd = GdbCommand::halt();
        let encoded = cmd.encode();
        let s = String::from_utf8(encoded).unwrap();
        assert!(s.starts_with('$'));
        assert!(s.contains('#'));
    }

    #[test]
    fn encode_memory_read() {
        let cmd = GdbCommand::read_memory(0x1000, 16);
        assert_eq!(cmd.data, "m1000,10");
    }

    #[test]
    fn parse_response() {
        assert!(matches!(GdbResponse::parse("OK"), GdbResponse::Ok));
        assert!(matches!(GdbResponse::parse("E01"), GdbResponse::Error(1)));
        assert!(matches!(GdbResponse::parse("S05"), GdbResponse::Signal(5)));
        assert!(matches!(GdbResponse::parse("W00"), GdbResponse::Exited(0)));
    }

    #[test]
    fn decode_packet_basic() {
        let raw = b"$OK#9a";
        assert_eq!(decode_packet(raw), Some("OK".into()));
    }

    #[test]
    fn breakpoint_commands() {
        let set = GdbCommand::set_breakpoint(0x401000);
        assert!(set.data.starts_with("Z0,"));
        let remove = GdbCommand::remove_breakpoint(0x401000);
        assert!(remove.data.starts_with("z0,"));
    }
}
