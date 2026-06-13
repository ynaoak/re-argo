//! GDB Remote Serial Protocol (RSP) *server*.
//!
//! While `debugger.rs` provides the client side (building commands to send to an
//! external stub), this module implements the server side: it lets a real GDB
//! (or LLDB) connect to our emulator and drive execution remotely.
//!
//! The protocol handling is split from I/O so it can be unit-tested:
//!   * [`GdbStub`] owns a [`DebugTarget`] and turns decoded packets into
//!     responses via [`GdbStub::handle_packet`].
//!   * [`serve`] runs the blocking TCP accept/read loop on top of a stub.
//!
//! The amd64 register block layout used by GDB (no target.xml) is provided by
//! [`amd64_read_registers`] / [`amd64_write_registers`] so a concrete target
//! built on [`crate::EmulatorState`] can map our register offsets to GDB order.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, ToSocketAddrs};

use crate::state::EmulatorState;

/// Why execution stopped, reported back to GDB as a stop-reply packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Single-step or breakpoint trap (SIGTRAP / signal 5).
    Trap,
    /// Program exited with the given status code.
    Exited(u8),
    /// Stopped due to an arbitrary signal.
    Signal(u8),
}

/// A target that the GDB stub can inspect and control.
///
/// Implementors expose registers and memory in GDB's expected encoding and
/// advance execution one step (or until a breakpoint / exit) at a time.
pub trait DebugTarget {
    /// Raw register block in GDB order (little-endian per register).
    fn read_registers(&self) -> Vec<u8>;
    /// Write back a full register block in GDB order.
    fn write_registers(&mut self, data: &[u8]);
    /// Read `len` bytes of memory starting at `addr`.
    fn read_memory(&self, addr: u64, len: usize) -> Vec<u8>;
    /// Write `data` to memory starting at `addr`.
    fn write_memory(&mut self, addr: u64, data: &[u8]);
    /// Resume execution; `step` requests a single instruction.
    fn resume(&mut self, step: bool) -> StopReason;
    /// Register a software breakpoint at `addr`.
    fn add_breakpoint(&mut self, addr: u64);
    /// Remove a software breakpoint at `addr`.
    fn remove_breakpoint(&mut self, addr: u64);
}

// ---------------------------------------------------------------------------
// amd64 register block (GDB's default layout when no target.xml is sent)
//
// Order: rax rbx rcx rdx rsi rdi rbp rsp r8..r15 rip eflags cs ss ds es fs gs
// Widths: 16 GPRs + rip = 8 bytes; eflags + 6 segment regs = 4 bytes.
// Total = 17*8 + 7*4 = 164 bytes.
// ---------------------------------------------------------------------------

/// (our REGISTER-space offset, GDB index) for the 16 GPRs + rip, in GDB order.
/// rip uses a synthetic offset that the emulator target also uses for the PC.
pub const AMD64_PC_OFFSET: u64 = 0x288;

const AMD64_GPR_LAYOUT: [u64; 17] = [
    0x00, // rax
    0x18, // rbx
    0x08, // rcx
    0x10, // rdx
    0x30, // rsi
    0x38, // rdi
    0x28, // rbp
    0x20, // rsp
    0x80, // r8
    0x88, // r9
    0x90, // r10
    0x98, // r11
    0xA0, // r12
    0xA8, // r13
    0xB0, // r14
    0xB8, // r15
    AMD64_PC_OFFSET, // rip
];

const AMD64_REG_BLOCK_LEN: usize = 17 * 8 + 7 * 4;

/// Build the amd64 register block from emulator state in GDB order.
pub fn amd64_read_registers(state: &EmulatorState) -> Vec<u8> {
    let mut out = Vec::with_capacity(AMD64_REG_BLOCK_LEN);
    for off in AMD64_GPR_LAYOUT {
        let val = state.read_register(off, 8);
        out.extend_from_slice(&val.to_le_bytes());
    }
    // eflags + cs/ss/ds/es/fs/gs: not modelled, report zero.
    out.extend_from_slice(&[0u8; 7 * 4]);
    out
}

/// Write an amd64 register block (GDB order) back into emulator state.
pub fn amd64_write_registers(state: &mut EmulatorState, data: &[u8]) {
    for (i, off) in AMD64_GPR_LAYOUT.iter().enumerate() {
        let start = i * 8;
        if start + 8 <= data.len() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[start..start + 8]);
            state.write_register(*off, 8, u64::from_le_bytes(buf));
        }
    }
}

// ---------------------------------------------------------------------------
// Packet framing
// ---------------------------------------------------------------------------

fn checksum(payload: &str) -> u8 {
    payload.bytes().fold(0u8, |acc, b| acc.wrapping_add(b))
}

/// Encode a payload into a full RSP packet: `$<payload>#<checksum>`.
pub fn encode_packet(payload: &str) -> Vec<u8> {
    format!("${}#{:02x}", payload, checksum(payload)).into_bytes()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// GdbStub
// ---------------------------------------------------------------------------

/// Protocol state machine over a [`DebugTarget`].
pub struct GdbStub<T: DebugTarget> {
    target: T,
}

impl<T: DebugTarget> GdbStub<T> {
    pub fn new(target: T) -> Self {
        Self { target }
    }

    pub fn target(&self) -> &T {
        &self.target
    }

    pub fn target_mut(&mut self) -> &mut T {
        &mut self.target
    }

    /// Translate a [`StopReason`] into a GDB stop-reply payload.
    fn stop_reply(reason: StopReason) -> String {
        match reason {
            StopReason::Trap => "S05".into(),
            StopReason::Signal(s) => format!("S{:02x}", s),
            StopReason::Exited(code) => format!("W{:02x}", code),
        }
    }

    /// Handle one decoded packet payload, returning the response payload.
    ///
    /// Returns `None` for packets that need no reply (the caller should not send
    /// anything). An empty string means "send an empty packet" (unsupported).
    pub fn handle_packet(&mut self, packet: &str) -> Option<String> {
        let first = packet.chars().next()?;
        match first {
            // Halt reason
            '?' => Some("S05".into()),

            // Read all registers
            'g' => Some(hex_encode(&self.target.read_registers())),

            // Write all registers
            'G' => {
                if let Some(bytes) = hex_decode(&packet[1..]) {
                    self.target.write_registers(&bytes);
                    Some("OK".into())
                } else {
                    Some("E01".into())
                }
            }

            // Read memory: m<addr>,<len>
            'm' => Some(self.handle_read_memory(&packet[1..])),

            // Write memory: M<addr>,<len>:<hex>
            'M' => Some(self.handle_write_memory(&packet[1..])),

            // Continue (optionally c<addr> — addr resume not supported)
            'c' => Some(Self::stop_reply(self.target.resume(false))),

            // Single step
            's' => Some(Self::stop_reply(self.target.resume(true))),

            // Set breakpoint: Z<type>,<addr>,<kind>
            'Z' => Some(self.handle_breakpoint(&packet[1..], true)),

            // Remove breakpoint: z<type>,<addr>,<kind>
            'z' => Some(self.handle_breakpoint(&packet[1..], false)),

            // Queries
            'q' => Some(self.handle_query(packet)),

            // Thread select: always OK (single thread)
            'H' => Some("OK".into()),

            // vCont and other v-packets
            'v' => Some(self.handle_v_packet(packet)),

            // Kill / detach: acknowledge, connection will close
            'k' => None,
            'D' => Some("OK".into()),

            // Anything else: unsupported (empty reply)
            _ => Some(String::new()),
        }
    }

    fn handle_read_memory(&self, args: &str) -> String {
        let (addr, len) = match parse_addr_len(args) {
            Some(v) => v,
            None => return "E01".into(),
        };
        let bytes = self.target.read_memory(addr, len as usize);
        hex_encode(&bytes)
    }

    fn handle_write_memory(&mut self, args: &str) -> String {
        let (head, hex) = match args.split_once(':') {
            Some(v) => v,
            None => return "E01".into(),
        };
        let (addr, _len) = match parse_addr_len(head) {
            Some(v) => v,
            None => return "E01".into(),
        };
        match hex_decode(hex) {
            Some(bytes) => {
                self.target.write_memory(addr, &bytes);
                "OK".into()
            }
            None => "E01".into(),
        }
    }

    fn handle_breakpoint(&mut self, args: &str, set: bool) -> String {
        // <type>,<addr>,<kind>
        let parts: Vec<&str> = args.split(',').collect();
        if parts.len() < 2 {
            return "E01".into();
        }
        let addr = match u64::from_str_radix(parts[1], 16) {
            Ok(a) => a,
            Err(_) => return "E01".into(),
        };
        if set {
            self.target.add_breakpoint(addr);
        } else {
            self.target.remove_breakpoint(addr);
        }
        "OK".into()
    }

    fn handle_query(&self, packet: &str) -> String {
        if packet.starts_with("qSupported") {
            return "PacketSize=4000;qXfer:features:read-".into();
        }
        if packet.starts_with("qAttached") {
            return "1".into();
        }
        if packet == "qC" {
            return "QC0".into();
        }
        if packet == "qfThreadInfo" {
            return "m0".into();
        }
        if packet == "qsThreadInfo" {
            return "l".into();
        }
        if packet.starts_with("qTStatus") {
            return String::new();
        }
        String::new()
    }

    fn handle_v_packet(&mut self, packet: &str) -> String {
        if packet == "vCont?" {
            return "vCont;c;s".into();
        }
        if let Some(rest) = packet.strip_prefix("vCont;") {
            // Take the first action; ';' separates per-thread actions.
            let action = rest.split(';').next().unwrap_or("");
            let step = action.starts_with('s');
            return Self::stop_reply(self.target.resume(step));
        }
        String::new()
    }
}

fn parse_addr_len(s: &str) -> Option<(u64, u64)> {
    let (a, l) = s.split_once(',')?;
    let addr = u64::from_str_radix(a, 16).ok()?;
    let len = u64::from_str_radix(l, 16).ok()?;
    Some((addr, len))
}

// ---------------------------------------------------------------------------
// TCP serve loop
// ---------------------------------------------------------------------------

/// Read one RSP packet payload from a reader, sending an ack (`+`) on success.
///
/// Returns `Ok(None)` on clean EOF. Interrupt (`0x03`) is surfaced as the
/// synthetic payload `"\x03"`.
fn read_packet<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> std::io::Result<Option<String>> {
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return Ok(None);
        }
        match byte[0] {
            b'$' => break,
            0x03 => return Ok(Some("\x03".into())),
            // Ignore acks ('+'/'-') and stray bytes between packets.
            _ => continue,
        }
    }

    let mut payload = Vec::new();
    let mut csum = [0u8; 2];
    // Read until '#'.
    loop {
        let mut byte = [0u8; 1];
        if reader.read(&mut byte)? == 0 {
            return Ok(None);
        }
        if byte[0] == b'#' {
            break;
        }
        payload.push(byte[0]);
    }
    reader.read_exact(&mut csum)?;

    // Acknowledge receipt.
    writer.write_all(b"+")?;
    writer.flush()?;

    Ok(Some(String::from_utf8_lossy(&payload).into_owned()))
}

/// Serve a single GDB connection on `addr` until the client detaches or exits.
///
/// Blocks accepting one connection, then runs the packet loop. Returns after the
/// connection closes.
pub fn serve<A: ToSocketAddrs, T: DebugTarget>(
    addr: A,
    target: T,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let (stream, _peer) = listener.accept()?;
    serve_stream(stream.try_clone()?, stream, target)
}

/// Run the RSP loop over an already-connected reader/writer pair.
pub fn serve_stream<R: Read, W: Write, T: DebugTarget>(
    read_half: R,
    mut write_half: W,
    target: T,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(read_half);
    let mut stub = GdbStub::new(target);

    while let Some(packet) = read_packet(&mut reader, &mut write_half)? {
        if packet == "\x03" {
            // Interrupt: report a trap.
            write_half.write_all(&encode_packet("S05"))?;
            write_half.flush()?;
            continue;
        }
        let is_kill = packet.starts_with('k');
        match stub.handle_packet(&packet) {
            Some(response) => {
                write_half.write_all(&encode_packet(&response))?;
                write_half.flush()?;
            }
            None => {
                if is_kill {
                    break;
                }
            }
        }
        if packet.starts_with('D') {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory target for protocol tests.
    struct MockTarget {
        regs: Vec<u8>,
        mem: std::collections::BTreeMap<u64, u8>,
        breakpoints: Vec<u64>,
        steps: usize,
    }

    impl MockTarget {
        fn new() -> Self {
            Self {
                regs: vec![0u8; 164],
                mem: std::collections::BTreeMap::new(),
                breakpoints: Vec::new(),
                steps: 0,
            }
        }
    }

    impl DebugTarget for MockTarget {
        fn read_registers(&self) -> Vec<u8> {
            self.regs.clone()
        }
        fn write_registers(&mut self, data: &[u8]) {
            self.regs = data.to_vec();
        }
        fn read_memory(&self, addr: u64, len: usize) -> Vec<u8> {
            (0..len as u64)
                .map(|i| *self.mem.get(&(addr + i)).unwrap_or(&0))
                .collect()
        }
        fn write_memory(&mut self, addr: u64, data: &[u8]) {
            for (i, b) in data.iter().enumerate() {
                self.mem.insert(addr + i as u64, *b);
            }
        }
        fn resume(&mut self, _step: bool) -> StopReason {
            self.steps += 1;
            StopReason::Trap
        }
        fn add_breakpoint(&mut self, addr: u64) {
            self.breakpoints.push(addr);
        }
        fn remove_breakpoint(&mut self, addr: u64) {
            self.breakpoints.retain(|&a| a != addr);
        }
    }

    #[test]
    fn checksum_and_encode() {
        let pkt = encode_packet("OK");
        let s = String::from_utf8(pkt).unwrap();
        assert_eq!(s, "$OK#9a");
    }

    #[test]
    fn halt_reason() {
        let mut stub = GdbStub::new(MockTarget::new());
        assert_eq!(stub.handle_packet("?"), Some("S05".into()));
    }

    #[test]
    fn read_registers_hex() {
        let mut target = MockTarget::new();
        target.regs[0] = 0xAB;
        let mut stub = GdbStub::new(target);
        let resp = stub.handle_packet("g").unwrap();
        assert!(resp.starts_with("ab"));
        assert_eq!(resp.len(), 164 * 2);
    }

    #[test]
    fn write_registers_roundtrip() {
        let mut stub = GdbStub::new(MockTarget::new());
        let data = "ff".repeat(164);
        assert_eq!(stub.handle_packet(&format!("G{}", data)), Some("OK".into()));
        assert_eq!(stub.handle_packet("g"), Some(data));
    }

    #[test]
    fn memory_read_write() {
        let mut stub = GdbStub::new(MockTarget::new());
        // Write 0xDEADBEEF at 0x1000.
        assert_eq!(stub.handle_packet("M1000,4:deadbeef"), Some("OK".into()));
        assert_eq!(stub.handle_packet("m1000,4"), Some("deadbeef".into()));
    }

    #[test]
    fn breakpoint_set_remove() {
        let mut stub = GdbStub::new(MockTarget::new());
        assert_eq!(stub.handle_packet("Z0,401000,1"), Some("OK".into()));
        assert_eq!(stub.target().breakpoints, vec![0x401000]);
        assert_eq!(stub.handle_packet("z0,401000,1"), Some("OK".into()));
        assert!(stub.target().breakpoints.is_empty());
    }

    #[test]
    fn step_and_continue() {
        let mut stub = GdbStub::new(MockTarget::new());
        assert_eq!(stub.handle_packet("s"), Some("S05".into()));
        assert_eq!(stub.handle_packet("c"), Some("S05".into()));
        assert_eq!(stub.target().steps, 2);
    }

    #[test]
    fn supported_query() {
        let mut stub = GdbStub::new(MockTarget::new());
        let resp = stub.handle_packet("qSupported:multiprocess+").unwrap();
        assert!(resp.contains("PacketSize"));
    }

    #[test]
    fn vcont_query_and_step() {
        let mut stub = GdbStub::new(MockTarget::new());
        assert_eq!(stub.handle_packet("vCont?"), Some("vCont;c;s".into()));
        assert_eq!(stub.handle_packet("vCont;s:1"), Some("S05".into()));
    }

    #[test]
    fn unsupported_packet_empty() {
        let mut stub = GdbStub::new(MockTarget::new());
        assert_eq!(stub.handle_packet("X"), Some(String::new()));
    }

    #[test]
    fn amd64_register_block_roundtrip() {
        let mut state = EmulatorState::new();
        state.write_register(0x00, 8, 0x1122334455667788); // rax
        state.write_register(AMD64_PC_OFFSET, 8, 0x401000); // rip
        let block = amd64_read_registers(&state);
        assert_eq!(block.len(), 164);
        // rax is first, little-endian.
        assert_eq!(&block[0..8], &0x1122334455667788u64.to_le_bytes());
        // rip is the 17th register (index 16).
        assert_eq!(&block[16 * 8..17 * 8], &0x401000u64.to_le_bytes());

        let mut state2 = EmulatorState::new();
        amd64_write_registers(&mut state2, &block);
        assert_eq!(state2.read_register(0x00, 8), 0x1122334455667788);
        assert_eq!(state2.read_register(AMD64_PC_OFFSET, 8), 0x401000);
    }

    #[test]
    fn read_packet_parses_and_acks() {
        let input = b"$g#67";
        let mut reader = std::io::BufReader::new(&input[..]);
        let mut ack = Vec::new();
        let pkt = read_packet(&mut reader, &mut ack).unwrap();
        assert_eq!(pkt, Some("g".into()));
        assert_eq!(ack, b"+");
    }

    #[test]
    fn serve_stream_handles_session() {
        // Simulate a GDB session: query registers, then detach.
        let input = b"$?#3f$D#aa";
        let output: Vec<u8> = Vec::new();
        let mut sink = std::io::Cursor::new(output);
        serve_stream(&input[..], &mut sink, MockTarget::new()).unwrap();
        let written = String::from_utf8(sink.into_inner()).unwrap();
        // Should contain acks and the stop reply.
        assert!(written.contains("S05"));
        assert!(written.contains("OK"));
    }
}
