use reargo_core::datatype::DataTypeManager;
use reargo_loader::{BinaryInfo, BinaryLoader};
use reargo_arch::arch::create_architecture;
use reargo_arch::Architecture;

use crate::comments::CommentManager;
use crate::listing::Listing;
use crate::metadata::ProgramMetadata;
use crate::reference::ReferenceManager;
use crate::symbol::{SourceType, Symbol, SymbolTable, SymbolType};

#[derive(Debug, thiserror::Error)]
pub enum ProgramError {
    #[error("loader error: {0}")]
    Loader(#[from] reargo_loader::LoaderError),
    #[error("architecture error: {0}")]
    Architecture(String),
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("{0}")]
    Other(String),
}

impl From<reargo_arch::DisasmError> for ProgramError {
    fn from(e: reargo_arch::DisasmError) -> Self {
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
    /// Categorised analyzer findings (Binary-Ninja-style tags).
    /// Distinct from `comments` — comments annotate byte ranges in
    /// the listing; tags drive filterable reports (`tags --filter
    /// crypto`, `summary`, JSON export). Populated by `TagAnalyzer`
    /// which re-categorises the existing analyzer output stream.
    pub tags: crate::tags::TagManager,
    /// In-memory results analyzers share with later analyzers (see
    /// [`crate::analysis_cache`]). Not exported.
    pub analysis_cache: crate::analysis_cache::AnalysisCache,
}

impl Program {
    pub fn from_binary(path: &std::path::Path) -> Result<Self, ProgramError> {
        let info = BinaryLoader::load(path)?;
        let arch = create_architecture(info.arch)?;

        let mut symbol_table = SymbolTable::new();
        for sym in &info.symbols {
            let sym_type = match sym.kind {
                reargo_loader::SymbolKind::Function => SymbolType::Function,
                reargo_loader::SymbolKind::Import => SymbolType::ExternalFunction,
                reargo_loader::SymbolKind::Export => SymbolType::Function,
                reargo_loader::SymbolKind::Data => SymbolType::Data,
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
            tags: crate::tags::TagManager::new(),
            analysis_cache: crate::analysis_cache::AnalysisCache::new(),
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

/// Everything the analysis pipeline adds to a [`Program`], borrowed for
/// serialisation (the on-disk analysis cache of `re-argo`). The loader
/// side — `info`, `arch`, `name` — is not part of it: it is rebuilt by
/// loading the binary again, which is cheap. Read back as
/// [`AnalysisState`]; the two structs must list the same fields in the
/// same order (a positional binary format reads them in that order).
#[derive(serde::Serialize)]
pub struct AnalysisStateRef<'a> {
    pub listing: &'a Listing,
    pub symbol_table: &'a SymbolTable,
    pub references: &'a ReferenceManager,
    pub comments: &'a CommentManager,
    pub metadata: &'a ProgramMetadata,
    pub call_renderings: &'a std::collections::BTreeMap<u64, String>,
    pub tags: &'a crate::tags::TagManager,
}

/// Owned form of [`AnalysisStateRef`], read back from the cache.
#[derive(serde::Deserialize)]
pub struct AnalysisState {
    pub listing: Listing,
    pub symbol_table: SymbolTable,
    pub references: ReferenceManager,
    pub comments: CommentManager,
    pub metadata: ProgramMetadata,
    pub call_renderings: std::collections::BTreeMap<u64, String>,
    pub tags: crate::tags::TagManager,
}

impl Program {
    /// The analysis results of this program, for the on-disk cache.
    pub fn analysis_state(&self) -> AnalysisStateRef<'_> {
        // Exhaustive on purpose: a field added to `Program` stops the
        // build here until it is either stored in the cache or listed as
        // rebuilt on load (`restore_analysis_state`) — a cached program
        // must never silently lack something the pipeline produces.
        let Program {
            name: _,
            arch: _,
            info: _,
            listing,
            symbol_table,
            references,
            data_types: _,
            comments,
            metadata,
            call_renderings,
            tags,
            analysis_cache: _,
        } = self;
        AnalysisStateRef { listing, symbol_table, references, comments, metadata, call_renderings, tags }
    }

    /// Put analysis results read back from the cache into a freshly
    /// loaded program (`Program::from_binary` of the same binary), so it
    /// is the program the analysis pipeline would have produced.
    ///
    /// Not stored but rebuilt here: `data_types`, which the pipeline
    /// fills only from the binary's DWARF types (the Type Recovery
    /// analyzer), and `analysis_cache`, scratch space analyzers hand
    /// each other while the pipeline runs (nothing reads it after).
    pub fn restore_analysis_state(&mut self, state: AnalysisState) {
        let AnalysisState { listing, symbol_table, references, comments, metadata, call_renderings, tags } = state;
        self.listing = listing;
        self.symbol_table = symbol_table;
        self.references = references;
        self.comments = comments;
        self.metadata = metadata;
        self.call_renderings = call_renderings;
        self.tags = tags;
        self.data_types = DataTypeManager::new();
        reargo_loader::dwarf_types::import_dwarf_types(&self.info.dwarf, &mut self.data_types);
        self.analysis_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comments::CommentType;
    use crate::reference::{RefType, Reference};
    use crate::tags::{TagKind, TagManager};
    use crate::Function;
    use bincode::Options;
    use reargo_arch::{DecodedInstruction, FlowType};
    use reargo_core::address::{Address, AddressRange, SpaceId};

    /// Everything [`AnalysisStateRef`] holds survives the cache's
    /// encoding exactly (same `Debug` dump, same lookups).
    #[test]
    fn analysis_state_round_trips() {
        let mut listing = Listing::new();
        listing.add_instruction(DecodedInstruction::new(
            0x1000,
            5,
            "call".into(),
            "0x2000".into(),
            smallvec_bytes(&[0xe8, 0xfb, 0x0f, 0, 0]),
            FlowType::Call,
            Some(0x2000),
        ));
        let mut f = Function::new(0x1000, "main".into());
        f.body.add(AddressRange::new(Address::new(SpaceId::RAM, 0x1000), 5));
        f.call_targets.insert(0x2000);
        f.stack_frame.add_variable(-0x18, 8);
        f.parameters.push(("argc".into(), "int".into()));
        f.no_return = true;
        listing.add_function(f);

        let mut symbols = SymbolTable::new();
        symbols.add(Symbol::new("main".into(), 0x1000, SymbolType::Function, SourceType::Imported));
        symbols.set_primary(0x1000, "renamed", SymbolType::Function);
        symbols.add(Symbol::new("gone".into(), 0x3000, SymbolType::Data, SourceType::Analysis));
        symbols.remove_at(0x3000);

        let mut refs = ReferenceManager::new();
        refs.add(Reference::new(0x1000, 0x2000, RefType::UnconditionalCall));
        refs.add(Reference::new(0x1005, 0x1000, RefType::ConditionalJump));
        let mut comments = CommentManager::new();
        comments.set(0x1000, CommentType::Plate, "entry");
        comments.set(0x1000, CommentType::Eol, "call");
        let mut metadata = ProgramMetadata::default();
        metadata.set_property("imphash", "abc");
        let mut renderings = std::collections::BTreeMap::new();
        renderings.insert(0x1000u64, "f(1)".to_string());
        let mut tags = TagManager::new();
        tags.add_address(0x1000, TagKind::Crypto, "aes", true);
        tags.add_function(0x1000, TagKind::Custom("ioc".into()), "x", false);

        let state = AnalysisStateRef {
            listing: &listing,
            symbol_table: &symbols,
            references: &refs,
            comments: &comments,
            metadata: &metadata,
            call_renderings: &renderings,
            tags: &tags,
        };
        let codec = bincode::DefaultOptions::new().with_varint_encoding();
        let bytes = codec.serialize(&state).unwrap();
        let back: AnalysisState = codec.deserialize(&bytes).unwrap();

        assert_eq!(format!("{:?}", back.listing), format!("{listing:?}"));
        assert_eq!(format!("{:?}", back.comments), format!("{comments:?}"));
        assert_eq!(format!("{:?}", back.metadata), format!("{metadata:?}"));
        assert_eq!(back.call_renderings, renderings);
        assert_eq!(format!("{:?}", back.tags), format!("{tags:?}"));
        let syms = |t: &SymbolTable| t.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>();
        assert_eq!(syms(&back.symbol_table), syms(&symbols));
        assert_eq!(back.symbol_table.get_by_name("renamed"), symbols.get_by_name("renamed"));
        assert_eq!(back.symbol_table.get_by_name("gone"), symbols.get_by_name("gone"));
        let all = |r: &ReferenceManager| r.all_refs().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(all(&back.references), all(&refs));
        assert_eq!(back.references.get_refs_to(0x1000), refs.get_refs_to(0x1000));
        assert_eq!(back.references.get_refs_from(0x1005), refs.get_refs_from(0x1005));
        // A restored manager is a new one: marks of the old never apply.
        assert_ne!(back.references.jump_mark(), refs.jump_mark());
    }

    /// An x86 instruction whose text is formatted lazily is stored
    /// without it and formats the same text after the round trip, whether
    /// or not the text had been read before it was stored.
    #[test]
    fn lazy_x86_text_round_trips() {
        use reargo_arch::Architecture;
        use reargo_core::address::Endian;
        use reargo_loader::{Memory, MemoryBlock, MemoryFlags};
        let code = [0x48u8, 0x8b, 0x44, 0x24, 0x10, 0xe8, 0x10, 0, 0, 0];
        let mut mem = Memory::new(SpaceId(1), Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: 0x1000,
            size: code.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(std::sync::Arc::from(&code[..])),
        });
        let arch = reargo_arch::x86::X86Arch::new_64();
        let codec = bincode::DefaultOptions::new().with_varint_encoding();
        for (addr, read_first) in [(0x1000u64, false), (0x1005, true), (0x1000, true)] {
            let insn = arch.decode_instruction(&mem, addr).unwrap();
            if read_first {
                let _ = insn.mnemonic();
            }
            let bytes = codec.serialize(&insn).unwrap();
            let back: DecodedInstruction = codec.deserialize(&bytes).unwrap();
            let fresh = arch.decode_instruction(&mem, addr).unwrap();
            assert_eq!(back.mnemonic(), fresh.mnemonic());
            assert_eq!(back.operands(), fresh.operands());
            assert_eq!(format!("{back}"), format!("{fresh}"));
            assert!(!back.mnemonic().is_empty());
        }
    }

    fn smallvec_bytes(b: &[u8]) -> smallvec::SmallVec<[u8; 16]> {
        smallvec::SmallVec::from_slice(b)
    }
}
