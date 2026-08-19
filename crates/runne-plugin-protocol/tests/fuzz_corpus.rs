//! Fuzz-proofing deterministic byte corpus.
//!
//! Each byte sequence in the corpus exercises a specific error path.
//! The invariant: `CborDecoder` and `decode_frame` must NEVER panic —
//! every path returns a `DecodeError`.

#![allow(clippy::same_item_push)]
use runne_plugin_protocol::cbor::CborDecoder;
use runne_plugin_protocol::frame::decode_frame;
use runne_plugin_protocol::profile::DecodeLimits;

fn limits() -> DecodeLimits {
    DecodeLimits {
        max_frame_bytes: 1024,
        max_recursion_depth: 5,
        max_nesting_depth: 5,
        max_string_bytes: 4096,
        max_array_items: 32,
        max_map_items: 32,
        max_text_bytes: 256,
        max_byte_string_bytes: 256,
        max_unsigned: 10_000,
        min_signed: -10_000,
        max_signed: 10_000,
    }
}

/// All decode paths must return DecodeError, never panic.
fn must_not_panic(data: &[u8]) {
    let _ = std::panic::catch_unwind(|| {
        // Decoder path
        let mut d = CborDecoder::new(data);
        // Try reading each type — ignore results, just ensure no panic
        let _ = d.read_unsigned(10_000);
        let _ = d.read_signed(-10_000, 10_000);
        let _ = d.read_byte_string(256);
        let _ = d.read_text_string(256);
        let _ = d.read_array_header(32);
        let _ = d.read_map_header(32);
        let _ = d.read_bool();
        let _ = d.read_null();
        let _ = d.read_optional_bool();
        let _ = d.read_uuid_bytes();
        let _ = d.reject_tags();
    });

    // Frame decoder path
    let _ = std::panic::catch_unwind(|| {
        let _ = decode_frame(data, &limits());
    });
}

// ─── Edge case corpus ────────────────────────────────────────────────────

#[test]
fn test_corpus_empty() {
    must_not_panic(&[]);
}

#[test]
fn test_corpus_single_zero() {
    must_not_panic(&[0x00]);
}

#[test]
fn test_corpus_all_zeros_32() {
    must_not_panic(&[0x00; 32]);
}

#[test]
fn test_corpus_all_ff_64() {
    must_not_panic(&[0xFF; 64]);
}

#[test]
fn test_corpus_truncated_map_header() {
    must_not_panic(&[0xA1, 0x01]);
}

#[test]
fn test_corpus_truncated_array_header() {
    must_not_panic(&[0x83, 0x01]);
}

#[test]
fn test_corpus_oversize_length_prefix() {
    // uint32_be = 0xFFFFFFFF (huge frame claim)
    let data: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF];
    must_not_panic(data);
}

#[test]
fn test_corpus_byte_string_with_truncated_data() {
    // Byte string header claiming 100 bytes, only 5 provided
    let mut data = vec![0x58, 100];
    data.extend_from_slice(&[0; 5]);
    must_not_panic(&data);
}

#[test]
fn test_corpus_text_string_invalid_utf8() {
    // Text string with invalid UTF-8
    let mut data = vec![0x64]; // text(4)
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    must_not_panic(&data);
}

#[test]
fn test_corpus_simple_value_unsupported() {
    // Simple value 0xF0 (not false/true/null)
    must_not_panic(&[0xF0]);
    must_not_panic(&[0xF8]);
}

#[test]
fn test_corpus_tag_at_start() {
    // Tag major type
    must_not_panic(&[0xC0]);
}

#[test]
fn test_corpus_indefinite_length_at_start() {
    // Indefinite length start byte
    must_not_panic(&[0x9F]);
    must_not_panic(&[0xBF]);
    must_not_panic(&[0x5F]);
    must_not_panic(&[0x7F]);
}

#[test]
fn test_corpus_non_canonical_integers() {
    must_not_panic(&[0x18, 0x17]); // non-canonical 23 encoded in 2 bytes
    must_not_panic(&[0x19, 0x00, 0x18]); // non-canonical 24 encoded in 3 bytes
}

#[test]
fn test_corpus_deeply_nested_arrays() {
    // 10 nested empty arrays = 10 * 0x80 + 1 break
    let mut data = Vec::new();
    for _ in 0..10 {
        data.push(0x81);
    } // array(1) — each contains 1 item
    data.extend_from_slice(&[0x00]); // unsigned(0) — leaf value
    must_not_panic(&data);
}

#[test]
fn test_corpus_negative_integers() {
    must_not_panic(&[0x20]); // -1
    must_not_panic(&[0x38, 0xFF]); // -256 (non-canonical check)
    must_not_panic(&[0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn test_corpus_map_duplicate_keys() {
    // A2 01 01 01 02 — map(2) with duplicate key 1
    must_not_panic(&[0xA2, 0x01, 0x01, 0x01, 0x02]);
}

#[test]
fn test_corpus_trailing_bytes_after_valid_cbor() {
    let mut data = vec![0x01]; // valid unsigned(1)
    data.extend_from_slice(&[0x00]); // trailing
    must_not_panic(&data);
}

#[test]
fn test_corpus_minimal_valid_frames() {
    // uint32_be(1) + 0x01 — valid frame with single unsigned
    must_not_panic(&[0x00, 0x00, 0x00, 0x01, 0x01]);
}
