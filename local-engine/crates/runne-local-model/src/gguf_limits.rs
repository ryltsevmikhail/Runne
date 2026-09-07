//! Bounded GGUF admission parser limits (Plan Task 4 Step 2, OQ-LE-002):
//! every untrusted count/length is checked against these before any
//! allocation or read.

/// Admitted GGUF format revision (v3).
pub const GGUF_VERSION: u32 = 3;
pub const GGUF_MAGIC: [u8; 4] = *b"GGUF";

/// Upper bound on metadata key/value entries.
pub const MAX_KV_COUNT: u64 = 1024;
/// Upper bound on tensor infos.
pub const MAX_TENSOR_COUNT: u64 = 4096;
/// Upper bound for a single metadata/tensor string in bytes.
pub const MAX_STRING_BYTES: u64 = 128 * 1024;

/// Cap for an embedded chat template captured for the builder; larger
/// embedded templates are refused (bounded intake policy).
pub const MAX_TEMPLATE_BYTES: u64 = 64 * 1024;

/// Cap for captured identifier strings (architecture, tokenizer family).
pub const MAX_ID_STRING_BYTES: u64 = 256;
/// Upper bound for a single metadata array length.
pub const MAX_ARRAY_LEN: u64 = 65_536;
/// Upper bound for array nesting (arrays of arrays).
pub const MAX_ARRAY_DEPTH: usize = 2;
/// Upper bound on total bytes consumed by the metadata section.
pub const MAX_METADATA_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum tensor dimensions.
pub const MAX_TENSOR_DIMS: u32 = 8;
/// Default and maximum tensor alignment (must be a power of two).
pub const DEFAULT_ALIGNMENT: u64 = 32;
pub const MAX_ALIGNMENT: u64 = 4096;

/// GGUF metadata value types (v3 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GgufValueType {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    F32,
    Bool,
    String,
    Array,
    U64,
    I64,
    F64,
}

pub fn value_type(raw: u32) -> Option<GgufValueType> {
    Some(match raw {
        0 => GgufValueType::U8,
        1 => GgufValueType::I8,
        2 => GgufValueType::U16,
        3 => GgufValueType::I16,
        4 => GgufValueType::U32,
        5 => GgufValueType::I32,
        6 => GgufValueType::F32,
        7 => GgufValueType::Bool,
        8 => GgufValueType::String,
        9 => GgufValueType::Array,
        10 => GgufValueType::U64,
        11 => GgufValueType::I64,
        12 => GgufValueType::F64,
        _ => return None,
    })
}

/// Fixed byte width of scalar value types (arrays/strings handled
/// separately).
pub fn scalar_width(ty: GgufValueType) -> Option<u64> {
    Some(match ty {
        GgufValueType::U8 | GgufValueType::I8 | GgufValueType::Bool => 1,
        GgufValueType::U16 | GgufValueType::I16 => 2,
        GgufValueType::U32 | GgufValueType::I32 | GgufValueType::F32 => 4,
        GgufValueType::U64 | GgufValueType::I64 | GgufValueType::F64 => 8,
        GgufValueType::String | GgufValueType::Array => return None,
    })
}

/// Tensor element size by GGUF quant/type id (subset Phase 1 admits:
/// F32=0, F16=1, Q4_K=14, Q6_K=16, Q8_0=8 — sizes in bytes per block of 32
/// or per element for float types).
pub fn tensor_type_block(type_id: u32) -> Option<(u64, u64)> {
    // (bytes_per_block, elements_per_block)
    Some(match type_id {
        0 => (4, 1),      // F32
        1 => (2, 1),      // F16
        8 => (34, 32),    // Q8_0
        14 => (144, 256), // Q4_K
        16 => (210, 256), // Q6_K
        _ => return None,
    })
}
