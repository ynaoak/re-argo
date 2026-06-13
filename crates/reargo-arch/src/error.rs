#[derive(Debug, thiserror::Error)]
pub enum DisasmError {
    #[error("failed to decode instruction at 0x{address:x}: {reason}")]
    DecodeError { address: u64, reason: String },
    #[error("address 0x{0:x} not readable")]
    UnreadableAddress(u64),
    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),
    #[error("disassembler engine error: {0}")]
    EngineError(String),
}
