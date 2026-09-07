//! `WorkerBackend` tests: the host client runs against a real worker
//! session loop (`runne-llama-worker::serve`) with the deterministic
//! `FakeEngine` over a socketpair. Covers happy load+generate, binding
//! mismatch, digest mismatch fencing, mid-stream crash fencing,
//! forced-OOM mapping and unload.

use runne_inference_host::backend::{BackendConfig, BackendPort, GenerationCtx, LoadRequest};
use runne_inference_host::error::HostError;
use runne_inference_host::worker_backend::{WorkerBackend, WorkerBinding};
use runne_inference_protocol::{
    ContextMaterial, Direction, LaunchSecret, Session, SessionKeys, UnixWorkerWire, WORKER_PURPOSE,
    WorkerFrameV1,
};
use runne_llama_worker::engine::FakeEngine;
use runne_llama_worker::{WorkerIdentity, serve};
use std::fs::File;
use std::io::Write as _;
use std::os::unix::net::UnixStream;

const WORKER_GEN: [u8; 16] = [0xAA; 16];
const HOST_GEN: [u8; 16] = [0xBB; 16];
const PROFILE: &str = "llama-cpp-cpu-macos-arm64-v1";

fn keys(channel: [u8; 16]) -> SessionKeys {
    SessionKeys::derive(
        &LaunchSecret::from_bytes(&[0x5E; 32]),
        b"worker-hello",
        b"worker-welcome",
        &ContextMaterial {
            channel,
            epoch: [3; 8],
            tag: [0, 0, 0],
        },
        WORKER_PURPOSE.as_bytes(),
    )
    .expect("keys")
}

/// Spawns the worker session loop on one end of a socketpair and
/// returns the host-side `WorkerBackend` on the other.
fn spawn_worker(engine: FakeEngine) -> WorkerBackend<UnixWorkerWire> {
    let (host_end, worker_end) = UnixStream::pair().expect("pair");
    let channel = [0x11; 16];
    let host_session: Session<WorkerFrameV1> =
        Session::new(keys(channel), channel, 7, Direction::C2h, 64 * 1024);
    std::thread::spawn(move || {
        let mut worker_session: Session<WorkerFrameV1> =
            Session::new(keys(channel), channel, 7, Direction::H2c, 64 * 1024);
        let mut wire = UnixWorkerWire::new(worker_end);
        let identity = WorkerIdentity {
            worker_generation: WORKER_GEN,
            host_generation: HOST_GEN,
            backend_profile: PROFILE.into(),
        };
        let mut engine = engine;
        let _ = serve(&mut wire, &mut worker_session, identity, &mut engine);
    });
    let binding = WorkerBinding {
        worker_generation: WORKER_GEN,
        host_generation: HOST_GEN,
        backend_profile: PROFILE.into(),
    };
    WorkerBackend::new(UnixWorkerWire::new(host_end), host_session, binding)
}

/// 24-byte zero-tensor GGUF image written to a temp file; returns the
/// file plus its exact digest and length.
fn gguf_fixture() -> (File, String, u64, tempfile::TempDir) {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("m.gguf");
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(&image))
        .expect("write");
    use sha2::Digest as _;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&image)));
    let file = std::fs::File::open(&path).expect("open");
    (file, digest, image.len() as u64, dir)
}

fn load_request(file: File, digest: &str, len: u64) -> LoadRequest {
    LoadRequest {
        model_identity: "local:m1:r1".into(),
        load_id: [7; 16],
        artifact: file,
        artifact_digest: digest.to_string(),
        byte_length: len,
        config: BackendConfig::default(),
    }
}

fn gen_ctx() -> GenerationCtx {
    GenerationCtx {
        generation_id: [1; 16],
        attempt_id: [2; 16],
        stream_id: [3; 16],
        prompt: "hello".into(),
        artifact_path_hint: None,
    }
}

#[test]
fn load_and_generate_happy_path() {
    let mut backend = spawn_worker(FakeEngine::new(vec!["answer".into()]));
    let (_f, digest, len, dir) = gguf_fixture();
    let file = std::fs::File::open(dir.path().join("m.gguf")).expect("reopen");
    backend
        .load(&load_request(file, &digest, len))
        .expect("load");
    let items = backend.generate(&gen_ctx()).expect("generate");
    let texts: Vec<&str> = items
        .iter()
        .filter_map(|m| match m {
            runne_inference_protocol::MessageV1::StreamItem {
                kind,
                stream_sequence,
                payload,
                ..
            } if kind == "text" => {
                assert_eq!(*stream_sequence, 0);
                Some(std::str::from_utf8(payload).expect("utf8"))
            }
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["answer"]);
    assert!(items
        .iter()
        .any(|m| matches!(m, runne_inference_protocol::MessageV1::StreamItem { kind, .. } if kind == "usage")));
    assert!(items
        .iter()
        .any(|m| matches!(m, runne_inference_protocol::MessageV1::StreamItem { kind, .. } if kind == "finish")));
}

#[test]
fn digest_mismatch_rejected_then_recovers() {
    let mut backend = spawn_worker(FakeEngine::new(vec!["answer".into()]));
    let (_f, _digest, len, dir) = gguf_fixture();
    let file = std::fs::File::open(dir.path().join("m.gguf")).expect("reopen");
    let err = backend
        .load(&load_request(file, "sha256:deadbeef", len))
        .expect_err("digest mismatch");
    assert!(matches!(err, HostError::ShaMismatch));
    // Load-level failures are attempt-level: an explicit correct retry
    // is possible (no silent auto-retry happens inside the backend).
    let (file, digest, len, _dir) = gguf_fixture();
    backend
        .load(&load_request(file, &digest, len))
        .expect("correct load after failure");
}

#[test]
fn worker_crash_midstream_fences_backend() {
    let mut backend = spawn_worker(FakeEngine::new(vec!["a".into(), "b".into()]).crash_after(1));
    let (_f, digest, len, dir) = gguf_fixture();
    let file = std::fs::File::open(dir.path().join("m.gguf")).expect("reopen");
    backend
        .load(&load_request(file, &digest, len))
        .expect("load");
    let err = backend.generate(&gen_ctx()).expect_err("crash");
    assert!(matches!(err, HostError::IntegrityViolation));
    let err = backend.generate(&gen_ctx()).expect_err("fenced");
    assert!(matches!(err, HostError::IntegrityViolation));
}

#[test]
fn forced_oom_maps_to_worker_error() {
    let mut backend = spawn_worker(FakeEngine::new(vec!["a".into()]).oom_after(0));
    let (_f, digest, len, dir) = gguf_fixture();
    let file = std::fs::File::open(dir.path().join("m.gguf")).expect("reopen");
    backend
        .load(&load_request(file, &digest, len))
        .expect("load");
    let err = backend.generate(&gen_ctx()).expect_err("oom");
    match err {
        HostError::Worker { code, .. } => {
            assert_eq!(code.as_str(), "memory");
        }
        other => panic!("expected worker error, got {other:?}"),
    }
}

#[test]
fn unload_releases_model() {
    let mut backend = spawn_worker(FakeEngine::new(vec!["answer".into()]));
    let (_f, digest, len, dir) = gguf_fixture();
    let file = std::fs::File::open(dir.path().join("m.gguf")).expect("reopen");
    backend
        .load(&load_request(file, &digest, len))
        .expect("load");
    backend.unload().expect("unload");
    // The host state went idle on unload; generation is refused
    // locally before any frame reaches the worker.
    let err = backend.generate(&gen_ctx()).expect_err("unloaded");
    assert!(matches!(err, HostError::ModelNotLoaded));
}

#[test]
fn length_mismatch_rejected() {
    let mut backend = spawn_worker(FakeEngine::new(vec!["answer".into()]));
    let (_f, digest, len, dir) = gguf_fixture();
    let file = std::fs::File::open(dir.path().join("m.gguf")).expect("reopen");
    let err = backend
        .load(&load_request(file, &digest, len + 1))
        .expect_err("length");
    assert!(matches!(err, HostError::CorruptModel));
}
