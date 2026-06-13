use crate::error::DisasmError;

pub trait Assembler: Send + Sync {
    fn assemble(&self, instruction: &str, address: u64) -> Result<Vec<u8>, DisasmError>;
    fn assemble_multiple(&self, instructions: &[&str], address: u64) -> Result<Vec<u8>, DisasmError> {
        let mut result = Vec::new();
        let mut addr = address;
        for insn in instructions {
            let bytes = self.assemble(insn, addr)?;
            addr += bytes.len() as u64;
            result.extend_from_slice(&bytes);
        }
        Ok(result)
    }
}

#[cfg(feature = "x86")]
pub mod x86_asm {
    use super::*;

    pub struct X86Assembler {
        bitness: u32,
    }

    impl X86Assembler {
        pub fn new_64() -> Self {
            Self { bitness: 64 }
        }

        pub fn new_32() -> Self {
            Self { bitness: 32 }
        }
    }

    impl Assembler for X86Assembler {
        fn assemble(&self, instruction: &str, address: u64) -> Result<Vec<u8>, DisasmError> {
            use iced_x86::code_asm::*;

            let _ = self.bitness;
            let _ = address;

            let mnemonic = instruction.trim().to_lowercase();
            let mut asm = CodeAssembler::new(self.bitness)
                .map_err(|e| DisasmError::EngineError(e.to_string()))?;

            if mnemonic == "nop" {
                asm.nop().map_err(|e| DisasmError::EngineError(e.to_string()))?;
            } else if mnemonic == "ret" {
                asm.ret().map_err(|e| DisasmError::EngineError(e.to_string()))?;
            } else if mnemonic == "int3" {
                asm.int3().map_err(|e| DisasmError::EngineError(e.to_string()))?;
            } else {
                return Err(DisasmError::EngineError(format!(
                    "assembler: instruction '{}' not yet supported in simplified assembler",
                    instruction
                )));
            }

            asm.assemble(address)
                .map_err(|e| DisasmError::EngineError(e.to_string()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn assemble_nop() {
            let asm = X86Assembler::new_64();
            let bytes = asm.assemble("nop", 0x1000).unwrap();
            assert_eq!(bytes, vec![0x90]);
        }

        #[test]
        fn assemble_ret() {
            let asm = X86Assembler::new_64();
            let bytes = asm.assemble("ret", 0x1000).unwrap();
            assert_eq!(bytes, vec![0xc3]);
        }

        #[test]
        fn assemble_int3() {
            let asm = X86Assembler::new_64();
            let bytes = asm.assemble("int3", 0x1000).unwrap();
            assert_eq!(bytes, vec![0xcc]);
        }
    }
}
