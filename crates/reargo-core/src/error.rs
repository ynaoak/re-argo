#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown space id: {0}")]
    UnknownSpace(u32),
    #[error("address out of bounds: offset 0x{offset:x} in space {space_name}")]
    AddressOutOfBounds { offset: u64, space_name: String },
    #[error("unknown opcode: {0}")]
    UnknownOpCode(u32),
    #[error("{0}")]
    Other(String),
}
