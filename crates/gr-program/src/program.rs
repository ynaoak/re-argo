use gr_core::datatype::DataTypeManager;
use gr_loader::{BinaryInfo, BinaryLoader};
use gr_arch::arch::create_architecture;
use gr_arch::Architecture;

use crate::comments::CommentManager;
use crate::listing::Listing;
use crate::metadata::ProgramMetadata;
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
    /// Persistent comments (plate / EOL / etc.). Populated by the
    /// user-override layer and any analyzer that annotates addresses.
    pub comments: CommentManager,
    /// Compiler / language / build metadata, surfaced via `info` and
    /// `export`. Populated by the compiler-fingerprint analyzer.
    pub metadata: ProgramMetadata,
    /// Per-call-site rendering: address of the Call instruction →
    /// the C-style expression the decompiler should emit *in place*
    /// of the synthetic `<callee>@plt()` stub. Populated by
    /// `CallSiteAnnotator` once it has resolved arg values + a
    /// matching `SignatureDatabase` signature; the decompiler
    /// emitters check this map before falling back to their
    /// untyped form. Format: full expression *without* a trailing
    /// semicolon — `printf("hi %d", 42)`.
    pub call_renderings: std::collections::BTreeMap<u64, String>,
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

        for dwarf_func in &info.dwarf.functions {
            if dwarf_func.low_pc == 0 {
                continue;
            }
            if symbol_table.primary_at(dwarf_func.low_pc).is_none() {
                symbol_table.add(Symbol::new(
                    dwarf_func.name.clone(),
                    dwarf_func.low_pc,
                    SymbolType::Function,
                    SourceType::Imported,
                ));
            }
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
            comments: CommentManager::new(),
            metadata: ProgramMetadata::default(),
            call_renderings: std::collections::BTreeMap::new(),
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
            .or_else(|| {
                self.info
                    .dwarf
                    .function_at(address)
                    .map(|f| f.name.clone())
            })
            .unwrap_or_else(|| format!("FUN_{:x}", address))
    }

    pub fn has_dwarf(&self) -> bool {
        !self.info.dwarf.is_empty()
    }

    pub fn dwarf_function_count(&self) -> usize {
        self.info.dwarf.functions.len()
    }
}
