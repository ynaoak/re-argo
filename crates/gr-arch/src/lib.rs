pub mod arch;
pub mod assembler;
pub mod cspec;
pub mod error;
pub mod pspec;

#[cfg(feature = "arm")]
pub mod arm;
#[cfg(feature = "arm")]
pub mod mips;
#[cfg(feature = "arm")]
pub mod ppc;
#[cfg(feature = "arm")]
pub mod riscv;
#[cfg(feature = "arm")]
pub mod sparc;
#[cfg(feature = "x86")]
pub mod x86;

pub use arch::{
    Architecture, CallingConvention, DecodedInstruction, FlowType, ParamLocation, RegisterInfo,
};
pub use cspec::CompilerSpec;
pub use error::DisasmError;
