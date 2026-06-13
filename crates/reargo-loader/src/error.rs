#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported binary format")]
    UnsupportedFormat,
    #[error("parse error: {0}")]
    Parse(String),
    #[error("address {0:#x} not found in memory")]
    AddressNotFound(u64),
}
