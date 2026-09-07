//! Shared builder-test fixture: a deterministic zero-tensor GGUF with
//! the metadata the builder derives from. Each test binary compiles
//! this module separately, so unused helpers are expected.
#![allow(dead_code)]

use runne_local_model::UserSupplied;

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn put_kv_string(out: &mut Vec<u8>, key: &str, value: &str) {
    put_str(out, key);
    out.extend_from_slice(&8u32.to_le_bytes());
    put_str(out, value);
}

fn put_kv_u32(out: &mut Vec<u8>, key: &str, value: u32) {
    put_str(out, key);
    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&value.to_le_bytes());
}

pub const TEMPLATE: &str = "{{ .Prompt }}";

/// Zero-tensor GGUF v3 with the four builder-relevant keys.
pub fn gguf_with_metadata() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GGUF");
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // tensor count
    out.extend_from_slice(&4u64.to_le_bytes()); // kv count
    put_kv_string(&mut out, "general.architecture", "llama");
    put_kv_u32(&mut out, "llama.context_length", 4096);
    put_kv_string(&mut out, "tokenizer.ggml.model", "bpe");
    put_kv_string(&mut out, "tokenizer.chat_template", TEMPLATE);
    out
}

/// Zero-tensor GGUF v3 with the builder-relevant keys except the
/// embedded template.
pub fn gguf_without_template() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GGUF");
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&3u64.to_le_bytes());
    put_kv_string(&mut out, "general.architecture", "llama");
    put_kv_u32(&mut out, "llama.context_length", 4096);
    put_kv_string(&mut out, "tokenizer.ggml.model", "bpe");
    out
}

/// A GGUF without any builder-relevant metadata.
pub fn gguf_without_metadata() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GGUF");
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

/// Complete user-supplied fields (tests strip pieces to trigger
/// refusals).
pub fn full_user() -> UserSupplied {
    UserSupplied {
        model_id: "test-model".into(),
        model_revision: "r1".into(),
        license: Some("Apache-2.0".into()),
        provenance_source_uri: Some("https://example.test/model".into()),
        provenance_publisher: Some("tester".into()),
        provenance_acquired_at: Some("2026-09-05T00:00:00Z".into()),
        chat_template: None,
        min_compatible_runtime: None,
    }
}
