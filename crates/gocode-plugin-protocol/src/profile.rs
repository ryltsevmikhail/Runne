//! Protocol profile constants and decode limits.

/// Decoding safety limits — cap wire sizes, nesting, and cardinalities.
///
/// Every CBOR decode operation is bounded by these limits.
/// Defaults are generous but safe for plugin protocol handshake
/// and bootstrap frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum unsigned integer value accepted during decode.
    pub max_unsigned: u64,
    /// Maximum signed integer value accepted during decode.
    pub max_signed: i64,
    /// Minimum signed integer value accepted during decode.
    pub min_signed: i64,
    /// Maximum byte length for byte strings and text strings.
    pub max_string_bytes: usize,
    /// Maximum number of items in an array.
    pub max_array_items: u32,
    /// Maximum number of pairs in a map.
    pub max_map_items: u32,
    /// Maximum nesting depth for composite CBOR items.
    pub max_nesting_depth: u32,
    /// Maximum frame size in bytes.
    pub max_frame_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_unsigned: u64::MAX,
            max_signed: i64::MAX,
            min_signed: i64::MIN,
            max_string_bytes: 64 * 1024,      // 64 KiB
            max_array_items: 1024,
            max_map_items: 256,
            max_nesting_depth: 16,
            max_frame_bytes: 1024 * 1024,     // 1 MiB
        }
    }
}
