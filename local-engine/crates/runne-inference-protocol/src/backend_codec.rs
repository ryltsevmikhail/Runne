//! Worker-catalog body codec: `WorkerFrameV1` ↔ canonical CBOR body
//! map. Strict: unknown fields, unknown types and unknown error codes
//! are rejected (closed catalog per PROTOCOL.md).

use crate::backend::{WorkerBackendConfig, WorkerFrameV1, WorkerLoad};
use crate::cbor::Cbor;

pub use crate::backend_decode::decode_worker_body;

fn map() -> std::collections::BTreeMap<Vec<u8>, Cbor> {
    std::collections::BTreeMap::new()
}

fn put_bytes(m: &mut std::collections::BTreeMap<Vec<u8>, Cbor>, k: &str, v: &[u8]) {
    m.insert(k.as_bytes().to_vec(), Cbor::Bytes(v.to_vec()));
}

fn put_text(m: &mut std::collections::BTreeMap<Vec<u8>, Cbor>, k: &str, v: &str) {
    m.insert(k.as_bytes().to_vec(), Cbor::Text(v.to_string()));
}

fn put_u64(m: &mut std::collections::BTreeMap<Vec<u8>, Cbor>, k: &str, v: u64) {
    m.insert(k.as_bytes().to_vec(), Cbor::Unsigned(v));
}

/// Shared generation triple present in every worker body.
fn put_triple(
    m: &mut std::collections::BTreeMap<Vec<u8>, Cbor>,
    worker_generation: &[u8; 16],
    host_generation: &[u8; 16],
    backend_profile: &str,
) {
    put_bytes(m, "wg", worker_generation);
    put_bytes(m, "hg", host_generation);
    put_text(m, "profile", backend_profile);
}

fn encode_config(m: &mut std::collections::BTreeMap<Vec<u8>, Cbor>, c: &WorkerBackendConfig) {
    put_u64(m, "ctx", c.context_max_tokens as u64);
    put_u64(m, "out", c.output_max_tokens as u64);
    put_u64(m, "gpu", c.gpu_layers as u64);
    put_u64(m, "thr", c.threads as u64);
    put_u64(m, "seed", c.seed as u64);
}

pub fn encode_worker_body(frame: &WorkerFrameV1) -> Cbor {
    let mut m = map();
    match frame {
        WorkerFrameV1::BackendLoad {
            worker_generation,
            host_generation,
            backend_profile,
            load:
                WorkerLoad {
                    model_identity,
                    load_id,
                    artifact_digest,
                    byte_length,
                    load_fence,
                },
            config,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
            put_text(&mut m, "model_identity", model_identity);
            put_bytes(&mut m, "load_id", load_id);
            put_text(&mut m, "digest", artifact_digest);
            put_u64(&mut m, "len", *byte_length);
            put_bytes(&mut m, "fence", load_fence);
            encode_config(&mut m, config);
        }
        WorkerFrameV1::BackendLoaded {
            worker_generation,
            host_generation,
            backend_profile,
            load_id,
            model_identity,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
            put_bytes(&mut m, "load_id", load_id);
            put_text(&mut m, "model_identity", model_identity);
        }
        WorkerFrameV1::BackendInfer {
            worker_generation,
            host_generation,
            backend_profile,
            generation_id,
            attempt_id,
            stream_id,
            prompt,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
            put_bytes(&mut m, "generation_id", generation_id);
            put_bytes(&mut m, "attempt_id", attempt_id);
            put_bytes(&mut m, "stream_id", stream_id);
            put_text(&mut m, "prompt", prompt);
        }
        WorkerFrameV1::BackendItem {
            worker_generation,
            host_generation,
            backend_profile,
            stream_id,
            stream_sequence,
            kind,
            payload,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
            put_bytes(&mut m, "stream_id", stream_id);
            put_u64(&mut m, "seq", *stream_sequence);
            put_text(&mut m, "kind", kind);
            put_bytes(&mut m, "payload", payload);
        }
        WorkerFrameV1::BackendCancel {
            worker_generation,
            host_generation,
            backend_profile,
            cancel_id,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
            put_bytes(&mut m, "cancel_id", cancel_id);
        }
        WorkerFrameV1::BackendUnload {
            worker_generation,
            host_generation,
            backend_profile,
            load_id,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
            put_bytes(&mut m, "load_id", load_id);
        }
        WorkerFrameV1::BackendHealth {
            worker_generation,
            host_generation,
            backend_profile,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
        }
        WorkerFrameV1::BackendTerminal {
            worker_generation,
            host_generation,
            backend_profile,
            stream_id,
            reason,
            prompt_tokens,
            output_tokens,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
            put_bytes(&mut m, "stream_id", stream_id);
            put_text(&mut m, "reason", reason);
            put_u64(&mut m, "prompt_tokens", *prompt_tokens);
            put_u64(&mut m, "output_tokens", *output_tokens);
        }
        WorkerFrameV1::BackendError {
            worker_generation,
            host_generation,
            backend_profile,
            code,
            detail,
        } => {
            put_triple(&mut m, worker_generation, host_generation, backend_profile);
            put_text(&mut m, "code", code.as_str());
            put_text(&mut m, "detail", detail);
        }
    }
    Cbor::Map(m)
}
