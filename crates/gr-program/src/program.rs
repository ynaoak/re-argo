use gr_core::datatype::DataTypeManager;
use gr_loader::{BinaryInfo, BinaryLoader};
use gr_arch::arch::create_architecture;
use gr_arch::Architecture;

use crate::listing::Listing;
use crate::reference::ReferenceManager;
use crate::symbol::{SourceType, Symbol, SymbolTable, SymbolType};

#[derive(Debug, thiserror::Error)]
pub enum ProgramError {
    #[error("loader error: {0}")]
    Loader(#[from] gr_loader::LoaderError),
    #[error("architecture error: {0}")]
    Architecture(String),
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("{0}")]
    Other(String),
}

impl From<gr_arch::DisasmError> for ProgramError {
    fn from(e: gr_arch::DisasmError) -> Self {
        Self::Architecture(e.to_string())
    }
}

pub struct Program {
    pub name: String,
    pub arch: Box<dyn Architecture>,
    pub info: BinaryInfo,
    pub listing: Listing,
    pub symbol_table: SymbolTable,
    pub references: ReferenceManager,
    pub data_types: DataTypeManager,
}

impl Program {
    pub fn from_binary(path: &std::path::Path) -> Result<Self, ProgramError> {
        let info = BinaryLoader::load(path)?;
        let arch = create_architecture(info.arch)?;

        let mut symbol_table = SymbolTable::new();
        for sym in &info.symbols {
            let sym_type = match sym.kind {
                gr_loader::SymbolKind::Function => SymbolType::Function,
                gr_loader::SymbolKind::Import => SymbolType::ExternalFunction,
                gr_loader::SymbolKind::Export => SymbolType::Function,
                gr_loader::SymbolKind::Data => SymbolType::Data,
                _ => SymbolType::Label,
            };
            symbol_table.add(Symbol::new(
                sym.name.clone(),
                sym.address,
                sym_type,
                SourceType::Imported,
            ));
        }

        Ok(Self {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            arch,
            info,
            listing: Listing::new(),
            symbol_table,
            references: ReferenceManager::new(),
            data_types: DataTypeManager::new(),
        })
    }

    pub fn entry_point(&self) -> u64 {
        self.info.entry_point
    }

    pub fn resolve_symbol_name(&self, address: u64) -> Option<&str> {
        self.symbol_table
            .primary_at(address)
            .map(|s| s.name.as_str())
    }

    pub fn function_name_at(&self, address: u64) -> String {
        self.resolve_symbol_name(address)
            .map(|s| s.to_string())
            .or_else(|| {
                self.listing
                    .get_function(address)
                    .map(|f| f.name.clone())
            })
            .unwrap_or_else(|| format!("FUN_{:x}", address))
    }
}
