//! Deterministic CBOR codec — RFC 8949 Core Deterministic Encoding subset.
//!
//! Supported: unsigned int, negative int, byte string, text string, array, map,
//! simple values (false, true, null).
//!
//! Rejected: floats (major 7 values 25-27), tags (major 6), indefinite-length,
//! other simple values, non-canonical integer encodings.

include!("cbor/types.rs");
include!("cbor/encoder.rs");
include!("cbor/decoder/types.rs");
include!("cbor/decoder/headers.rs");
include!("cbor/decoder/values.rs");
include!("cbor/codec.rs");
include!("cbor/tests.rs");
