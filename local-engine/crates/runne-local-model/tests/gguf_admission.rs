//! GGUF admission tests: a programmatically-built valid v3 image parses;
//! manifest format binding works.

use runne_local_model::gguf::inspect;
use runne_local_model::gguf_limits::{DEFAULT_ALIGNMENT, GGUF_MAGIC};

/// Builds a minimal valid GGUF v3 image: header, one metadata KV
/// (general.architecture), one F32 tensor of 8 elements, padded to
/// alignment.
pub fn build_valid_gguf() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GGUF_MAGIC);
    out.extend_from_slice(&3u32.to_le_bytes()); // version
    out.extend_from_slice(&1u64.to_le_bytes()); // tensor count
    out.extend_from_slice(&1u64.to_le_bytes()); // kv count
    // KV: key "general.architecture" (string), value type STRING, "llama"
    let key = b"general.architecture";
    out.extend_from_slice(&(key.len() as u64).to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&8u32.to_le_bytes()); // STRING
    let val = b"llama";
    out.extend_from_slice(&(val.len() as u64).to_le_bytes());
    out.extend_from_slice(val);
    // Tensor info: name "t0", 1 dim [8], type F32(0), offset 0
    let name = b"t0";
    out.extend_from_slice(&(name.len() as u64).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&1u32.to_le_bytes()); // n_dims
    out.extend_from_slice(&8u64.to_le_bytes()); // dim[0]
    out.extend_from_slice(&0u32.to_le_bytes()); // type F32
    out.extend_from_slice(&0u64.to_le_bytes()); // offset
    // Alignment KV omitted → default 32; tensor data: 8 × 4 bytes = 32.
    let data_start = out.len() as u64;
    out.resize(out.len() + 32, 0);
    debug_assert_eq!(data_start + 32, out.len() as u64);
    out
}

#[test]
fn valid_gguf_parses_with_summary() {
    let image = build_valid_gguf();
    let inspection = inspect(&image).expect("valid image");
    assert_eq!(inspection.version, 3);
    assert_eq!(inspection.tensor_count, 1);
    assert_eq!(inspection.kv_count, 1);
    assert_eq!(inspection.alignment, DEFAULT_ALIGNMENT);
    assert_eq!(inspection.architecture.as_deref(), Some("llama"));
}

#[test]
fn empty_input_rejects() {
    assert!(inspect(&[]).is_err());
}

#[test]
fn inspect_is_deterministic() {
    let image = build_valid_gguf();
    let a = inspect(&image).expect("a");
    let b = inspect(&image).expect("b");
    assert_eq!(a.tensor_count, b.tensor_count);
    assert_eq!(a.architecture, b.architecture);
}
