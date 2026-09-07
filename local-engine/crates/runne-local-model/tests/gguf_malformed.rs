//! Malformed GGUF corpus (checked-in generator + rejection matrix):
//! every malformed vector must be rejected with a typed error, without
//! panic and without unbounded allocation. See
//! docs/golden/local-engine/gguf-malformed/README.md.

use runne_local_model::gguf::inspect;

fn base_valid() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GGUF");
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes()); // tensors
    out.extend_from_slice(&1u64.to_le_bytes()); // kvs
    let key = b"general.architecture";
    out.extend_from_slice(&(key.len() as u64).to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&8u32.to_le_bytes());
    let val = b"llama";
    out.extend_from_slice(&(val.len() as u64).to_le_bytes());
    out.extend_from_slice(val);
    let name = b"t0";
    out.extend_from_slice(&(name.len() as u64).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&8u64.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    let data_start = out.len() as u64;
    let _ = data_start;
    out.extend_from_slice(&[0u8; 32]); // tensor data (8 F32 elements)
    out
}

fn expect_reject(bytes: &[u8]) {
    if let Ok(inspection) = inspect(bytes) {
        panic!("malformed input accepted: {inspection:?}");
    }
}

#[test]
fn bad_magic_rejected() {
    let mut image = base_valid();
    image[0] = b'X';
    expect_reject(&image);
}

#[test]
fn unsupported_version_rejected() {
    let mut image = base_valid();
    image[4..8].copy_from_slice(&2u32.to_le_bytes());
    expect_reject(&image);
}

#[test]
fn kv_count_bomb_rejected_without_allocation() {
    let mut image = base_valid();
    image[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    expect_reject(&image);
}

#[test]
fn tensor_count_bomb_rejected() {
    let mut image = base_valid();
    image[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    expect_reject(&image);
}

#[test]
fn duplicate_metadata_key_rejected() {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes()); // 0 tensors
    image.extend_from_slice(&2u64.to_le_bytes()); // 2 kvs (same key twice)
    for _ in 0..2 {
        let key = b"general.architecture";
        image.extend_from_slice(&(key.len() as u64).to_le_bytes());
        image.extend_from_slice(key);
        image.extend_from_slice(&8u32.to_le_bytes());
        let val = b"llama";
        image.extend_from_slice(&(val.len() as u64).to_le_bytes());
        image.extend_from_slice(val);
    }
    expect_reject(&image);
}

#[test]
fn unsupported_metadata_value_type_rejected() {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&1u64.to_le_bytes());
    let key = b"general.k";
    image.extend_from_slice(&(key.len() as u64).to_le_bytes());
    image.extend_from_slice(key);
    image.extend_from_slice(&99u32.to_le_bytes()); // unknown type
    expect_reject(&image);
}

#[test]
fn oversized_metadata_string_rejected() {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&1u64.to_le_bytes());
    let key = b"general.k";
    image.extend_from_slice(&(key.len() as u64).to_le_bytes());
    image.extend_from_slice(key);
    image.extend_from_slice(&8u32.to_le_bytes()); // STRING
    image.extend_from_slice(&u64::MAX.to_le_bytes()); // declared length
    expect_reject(&image);
}

#[test]
fn tensor_data_truncated_rejected() {
    let mut image = base_valid();
    image.truncate(image.len() - 8); // cut into tensor data
    expect_reject(&image);
}

#[test]
fn tensor_data_overlong_rejected() {
    let mut image = base_valid();
    image.extend_from_slice(&[0u8; 8]); // trailing structural inconsistency
    expect_reject(&image);
}

#[test]
fn duplicate_tensor_name_rejected() {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&2u64.to_le_bytes()); // 2 tensors, same name
    image.extend_from_slice(&0u64.to_le_bytes()); // 0 kvs
    for offset in [0u64, 32] {
        let name = b"t0";
        image.extend_from_slice(&(name.len() as u64).to_le_bytes());
        image.extend_from_slice(name);
        image.extend_from_slice(&1u32.to_le_bytes());
        image.extend_from_slice(&8u64.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&offset.to_le_bytes());
    }
    image.resize(image.len() + 64, 0);
    expect_reject(&image);
}

#[test]
fn overlapping_tensor_range_rejected() {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&2u64.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    for offset in [0u64, 0] {
        let name = b"t0";
        image.extend_from_slice(&(name.len() as u64).to_le_bytes());
        image.extend_from_slice(name);
        image.extend_from_slice(&1u32.to_le_bytes());
        image.extend_from_slice(&8u64.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&offset.to_le_bytes());
    }
    image.resize(image.len() + 32, 0);
    expect_reject(&image);
}

#[test]
fn unsupported_tensor_type_rejected() {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&1u64.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    let name = b"t0";
    image.extend_from_slice(&(name.len() as u64).to_le_bytes());
    image.extend_from_slice(name);
    image.extend_from_slice(&1u32.to_le_bytes());
    image.extend_from_slice(&8u64.to_le_bytes());
    image.extend_from_slice(&77u32.to_le_bytes()); // unsupported type
    image.extend_from_slice(&0u64.to_le_bytes());
    image.resize(image.len() + 32, 0);
    expect_reject(&image);
}

#[test]
fn bad_alignment_kv_rejected() {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&1u64.to_le_bytes());
    let key = b"general.alignment";
    image.extend_from_slice(&(key.len() as u64).to_le_bytes());
    image.extend_from_slice(key);
    image.extend_from_slice(&4u32.to_le_bytes()); // U32
    image.extend_from_slice(&33u32.to_le_bytes()); // not power of two
    expect_reject(&image);
}

#[test]
fn malformed_corpus_is_frozen_in_docs() {
    // The corpus generator lives in this test; the frozen documentation
    // points here (single source of truth).
    let readme = include_str!("../../../docs/golden/local-engine/gguf-malformed/README.md");
    assert!(readme.contains("gguf-malformed"));
}
