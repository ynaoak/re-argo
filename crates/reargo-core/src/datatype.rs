use std::fmt;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetaType {
    Void,
    Unknown,
    Int,
    Uint,
    Bool,
    Code,
    Float,
    Ptr,
    Array,
    Struct,
    Union,
    Enum,
    FuncProto,
    Utf8,
    Utf16,
    Utf32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataType {
    pub name: String,
    pub size: usize,
    pub meta: MetaType,
    pub description: String,
}

impl DataType {
    pub fn new(name: impl Into<String>, size: usize, meta: MetaType) -> Self {
        Self {
            name: name.into(),
            size,
            meta,
            description: String::new(),
        }
    }

    pub fn void() -> Self {
        Self::new("void", 0, MetaType::Void)
    }

    pub fn bool_type() -> Self {
        Self::new("bool", 1, MetaType::Bool)
    }

    pub fn u8() -> Self {
        Self::new("uint8_t", 1, MetaType::Uint)
    }

    pub fn i8() -> Self {
        Self::new("int8_t", 1, MetaType::Int)
    }

    pub fn u16() -> Self {
        Self::new("uint16_t", 2, MetaType::Uint)
    }

    pub fn i16() -> Self {
        Self::new("int16_t", 2, MetaType::Int)
    }

    pub fn u32() -> Self {
        Self::new("uint32_t", 4, MetaType::Uint)
    }

    pub fn i32() -> Self {
        Self::new("int32_t", 4, MetaType::Int)
    }

    pub fn u64() -> Self {
        Self::new("uint64_t", 8, MetaType::Uint)
    }

    pub fn i64() -> Self {
        Self::new("int64_t", 8, MetaType::Int)
    }

    pub fn f32() -> Self {
        Self::new("float", 4, MetaType::Float)
    }

    pub fn f64() -> Self {
        Self::new("double", 8, MetaType::Float)
    }

    pub fn pointer(pointee: Arc<DataType>, ptr_size: usize) -> Self {
        Self::new(format!("{}*", pointee.name), ptr_size, MetaType::Ptr)
    }

    pub fn array(element: Arc<DataType>, count: usize) -> Self {
        Self::new(
            format!("{}[{}]", element.name, count),
            element.size * count,
            MetaType::Array,
        )
    }

    pub fn unknown(size: usize) -> Self {
        Self::new(format!("undefined{}", size), size, MetaType::Unknown)
    }

    pub fn is_integer(&self) -> bool {
        matches!(self.meta, MetaType::Int | MetaType::Uint)
    }

    pub fn is_float(&self) -> bool {
        self.meta == MetaType::Float
    }

    pub fn is_void(&self) -> bool {
        self.meta == MetaType::Void
    }

    pub fn is_pointer(&self) -> bool {
        self.meta == MetaType::Ptr
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub offset: usize,
    pub data_type: Arc<DataType>,
}

#[derive(Debug, Clone)]
pub struct StructType {
    pub base: DataType,
    pub fields: Vec<StructField>,
}

impl StructType {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            base: DataType::new(name, 0, MetaType::Struct),
            fields: Vec::new(),
        }
    }

    pub fn add_field(&mut self, name: impl Into<String>, data_type: Arc<DataType>) {
        let offset = self.base.size;
        self.fields.push(StructField {
            name: name.into(),
            offset,
            data_type: data_type.clone(),
        });
        self.base.size += data_type.size;
    }
}

#[derive(Debug, Clone)]
pub struct EnumMember {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone)]
pub struct EnumType {
    pub base: DataType,
    pub members: Vec<EnumMember>,
}

impl EnumType {
    pub fn new(name: impl Into<String>, size: usize) -> Self {
        Self {
            base: DataType::new(name, size, MetaType::Enum),
            members: Vec::new(),
        }
    }

    pub fn add_member(&mut self, name: impl Into<String>, value: i64) {
        self.members.push(EnumMember {
            name: name.into(),
            value,
        });
    }
}

#[derive(Debug, Clone)]
pub struct UnionType {
    pub base: DataType,
    pub fields: Vec<StructField>,
}

impl UnionType {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            base: DataType::new(name, 0, MetaType::Union),
            fields: Vec::new(),
        }
    }

    pub fn add_field(&mut self, name: impl Into<String>, data_type: Arc<DataType>) {
        let dt_size = data_type.size;
        self.fields.push(StructField {
            name: name.into(),
            offset: 0,
            data_type,
        });
        if dt_size > self.base.size {
            self.base.size = dt_size;
        }
    }
}

#[derive(Debug, Clone)]
pub struct PointerType {
    pub base: DataType,
    pub pointee: Arc<DataType>,
}

impl PointerType {
    pub fn new(pointee: Arc<DataType>, ptr_size: usize) -> Self {
        Self {
            base: DataType::new(format!("{}*", pointee.name), ptr_size, MetaType::Ptr),
            pointee,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArrayType {
    pub base: DataType,
    pub element: Arc<DataType>,
    pub count: usize,
}

impl ArrayType {
    pub fn new(element: Arc<DataType>, count: usize) -> Self {
        Self {
            base: DataType::new(
                format!("{}[{}]", element.name, count),
                element.size * count,
                MetaType::Array,
            ),
            element,
            count,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TypedefType {
    pub base: DataType,
    pub target: Arc<DataType>,
}

impl TypedefType {
    pub fn new(name: impl Into<String>, target: Arc<DataType>) -> Self {
        let target_size = target.size;
        Self {
            base: DataType::new(name, target_size, target.meta),
            target,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionPrototype {
    pub name: String,
    pub return_type: Arc<DataType>,
    pub parameters: Vec<(String, Arc<DataType>)>,
    pub is_variadic: bool,
}

impl FunctionPrototype {
    pub fn new(name: impl Into<String>, return_type: Arc<DataType>) -> Self {
        Self {
            name: name.into(),
            return_type,
            parameters: Vec::new(),
            is_variadic: false,
        }
    }

    pub fn add_param(&mut self, name: impl Into<String>, typ: Arc<DataType>) {
        self.parameters.push((name.into(), typ));
    }

    pub fn to_c_signature(&self) -> String {
        let params = if self.parameters.is_empty() {
            "void".to_string()
        } else {
            let mut parts: Vec<String> = self
                .parameters
                .iter()
                .map(|(name, ty)| format!("{} {}", ty.name, name))
                .collect();
            if self.is_variadic {
                parts.push("...".to_string());
            }
            parts.join(", ")
        };
        format!("{} {}({})", self.return_type.name, self.name, params)
    }
}

#[derive(Debug, Clone)]
pub struct BitFieldDataType {
    pub base: DataType,
    pub bit_offset: u32,
    pub bit_size: u32,
    pub base_type: Arc<DataType>,
}

impl BitFieldDataType {
    pub fn new(base_type: Arc<DataType>, bit_offset: u32, bit_size: u32) -> Self {
        Self {
            base: DataType::new(
                format!("{}:{}", base_type.name, bit_size),
                base_type.size,
                base_type.meta,
            ),
            bit_offset,
            bit_size,
            base_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CategoryPath {
    pub path: Vec<String>,
}

impl CategoryPath {
    pub fn root() -> Self {
        Self { path: Vec::new() }
    }

    pub fn new(path: impl Into<String>) -> Self {
        let s: String = path.into();
        Self {
            path: s.split('/').filter(|p| !p.is_empty()).map(|p| p.to_string()).collect(),
        }
    }

    pub fn child(&self, name: impl Into<String>) -> Self {
        let mut p = self.path.clone();
        p.push(name.into());
        Self { path: p }
    }

    pub fn parent(&self) -> Option<Self> {
        if self.path.is_empty() {
            None
        } else {
            let mut p = self.path.clone();
            p.pop();
            Some(Self { path: p })
        }
    }

    pub fn name(&self) -> &str {
        self.path.last().map(|s| s.as_str()).unwrap_or("/")
    }
}

impl fmt::Display for CategoryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.path.join("/"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    ReplaceExisting,
    KeepExisting,
    RenamNew,
}

#[derive(Debug, Default)]
pub struct DataTypeManager {
    types: Vec<Arc<DataType>>,
    categories: std::collections::BTreeSet<String>,
}

impl DataTypeManager {
    pub fn new() -> Self {
        let mut mgr = Self::default();
        mgr.register_builtins();
        mgr
    }

    fn register_builtins(&mut self) {
        self.add(DataType::void());
        self.add(DataType::bool_type());
        self.add(DataType::u8());
        self.add(DataType::i8());
        self.add(DataType::u16());
        self.add(DataType::i16());
        self.add(DataType::u32());
        self.add(DataType::i32());
        self.add(DataType::u64());
        self.add(DataType::i64());
        self.add(DataType::f32());
        self.add(DataType::f64());
        self.add(DataType::new("char", 1, MetaType::Int));
        self.add(DataType::new("unsigned char", 1, MetaType::Uint));
        self.add(DataType::new("short", 2, MetaType::Int));
        self.add(DataType::new("unsigned short", 2, MetaType::Uint));
        self.add(DataType::new("int", 4, MetaType::Int));
        self.add(DataType::new("unsigned int", 4, MetaType::Uint));
        self.add(DataType::new("long", 8, MetaType::Int));
        self.add(DataType::new("unsigned long", 8, MetaType::Uint));
        self.add(DataType::new("long long", 8, MetaType::Int));
        self.add(DataType::new("unsigned long long", 8, MetaType::Uint));
        self.add(DataType::new("size_t", 8, MetaType::Uint));
        self.add(DataType::new("ssize_t", 8, MetaType::Int));
        self.add(DataType::new("ptrdiff_t", 8, MetaType::Int));
        self.add(DataType::new("intptr_t", 8, MetaType::Int));
        self.add(DataType::new("uintptr_t", 8, MetaType::Uint));
        self.add(DataType::new("wchar_t", 4, MetaType::Utf32));
        self.add(DataType::new("char16_t", 2, MetaType::Utf16));
        self.add(DataType::new("char32_t", 4, MetaType::Utf32));
        self.add(DataType::new("long double", 16, MetaType::Float));
    }

    pub fn add(&mut self, dt: DataType) -> Arc<DataType> {
        let arc = Arc::new(dt);
        self.types.push(arc.clone());
        arc
    }

    pub fn add_with_category(&mut self, dt: DataType, category: &CategoryPath) -> Arc<DataType> {
        self.categories.insert(category.to_string());
        self.add(dt)
    }

    pub fn resolve(&mut self, dt: DataType, strategy: ConflictResolution) -> Arc<DataType> {
        if let Some(existing) = self.find_by_name(&dt.name) {
            match strategy {
                ConflictResolution::KeepExisting => existing,
                ConflictResolution::ReplaceExisting => {
                    self.types.retain(|t| t.name != dt.name);
                    self.add(dt)
                }
                ConflictResolution::RenamNew => {
                    let renamed = DataType::new(
                        format!("{}.conflict", dt.name),
                        dt.size,
                        dt.meta,
                    );
                    self.add(renamed)
                }
            }
        } else {
            self.add(dt)
        }
    }

    pub fn find_by_name(&self, name: &str) -> Option<Arc<DataType>> {
        self.types.iter().find(|t| t.name == name).cloned()
    }

    pub fn find_by_size_and_meta(&self, size: usize, meta: MetaType) -> Option<Arc<DataType>> {
        self.types
            .iter()
            .find(|t| t.size == size && t.meta == meta)
            .cloned()
    }

    pub fn types(&self) -> &[Arc<DataType>] {
        &self.types
    }

    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    pub fn categories(&self) -> &std::collections::BTreeSet<String> {
        &self.categories
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_types() {
        let mgr = DataTypeManager::new();
        let void = mgr.find_by_name("void").unwrap();
        assert!(void.is_void());
        assert_eq!(void.size, 0);

        let u32_type = mgr.find_by_name("uint32_t").unwrap();
        assert!(u32_type.is_integer());
        assert_eq!(u32_type.size, 4);

        let f64_type = mgr.find_by_name("double").unwrap();
        assert!(f64_type.is_float());
        assert_eq!(f64_type.size, 8);
    }

    #[test]
    fn pointer_type() {
        let base = Arc::new(DataType::i32());
        let ptr = DataType::pointer(base, 8);
        assert!(ptr.is_pointer());
        assert_eq!(ptr.size, 8);
        assert_eq!(ptr.name, "int32_t*");
    }

    #[test]
    fn struct_type() {
        let mut s = StructType::new("my_struct");
        s.add_field("x", Arc::new(DataType::i32()));
        s.add_field("y", Arc::new(DataType::i32()));
        assert_eq!(s.base.size, 8);
        assert_eq!(s.fields.len(), 2);
        assert_eq!(s.fields[1].offset, 4);
    }

    #[test]
    fn enum_type() {
        let mut e = EnumType::new("color", 4);
        e.add_member("RED", 0);
        e.add_member("GREEN", 1);
        e.add_member("BLUE", 2);
        assert_eq!(e.members.len(), 3);
        assert_eq!(e.base.size, 4);
    }

    #[test]
    fn find_by_size_and_meta() {
        let mgr = DataTypeManager::new();
        let result = mgr.find_by_size_and_meta(4, MetaType::Uint);
        assert_eq!(result.unwrap().name, "uint32_t");
    }
}
