//! Deterministic fake-session tests: session-level state gates, drain
//! and bounded shutdown over the fake backend.

use runne_inference_host::backend::{BackendConfig, BackendPort, LoadRequest};
use runne_inference_host::{FakeBackend, HostSession, HostState};
use runne_inference_protocol::{Direction, SESSION_PURPOSE, Session, SessionKeys};
fn host_session() -> HostSession<FakeBackend> {
    let keys = SessionKeys::derive(
        &runne_inference_protocol::LaunchSecret::from_bytes(&[0x42; 32]),
        b"hello",
        b"welcome",
        &runne_inference_protocol::ContextMaterial {
            channel: [3; 16],
            epoch: 7u64.to_be_bytes(),
            tag: [0, 0, 0],
        },
        SESSION_PURPOSE.as_bytes(),
    )
    .expect("keys");
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().expect("pair");
    let transport = Session::new(keys, [3; 16], 7, Direction::H2c, 64 * 1024);
    HostSession::new(transport, stream, FakeBackend::default())
}

#[test]
fn state_machine_starts_ready() {
    let host = host_session();
    assert_eq!(host.state(), HostState::Ready);
}

#[test]
fn generate_before_load_is_rejected() {
    let mut host = host_session();
    let err =
        runne_inference_host::generate::stream_generation(&mut host, [1; 16], [2; 16], [3; 16], "")
            .expect_err("generate before load");
    assert!(matches!(
        err,
        runne_inference_host::HostError::ModelNotLoaded
    ));
}

#[test]
fn drain_then_bounded_shutdown() {
    let mut host = host_session();
    host.drain(100).expect("drain");
    assert_eq!(host.state(), HostState::Draining);
    host.shutdown(100).expect("shutdown");
    assert_eq!(host.state(), HostState::Stopped);
    // Post-stop operations are invalid.
    assert!(host.drain(100).is_err());
}

#[test]
fn shutdown_after_stop_is_invalid() {
    let mut host = host_session();
    host.shutdown(50).expect("first");
    assert!(host.shutdown(50).is_err());
}

#[test]
fn load_via_backend_sets_loaded_identity() {
    let mut host = host_session();
    let tmp = tempfile::NamedTempFile::new().expect("tmp");
    use std::io::Write as _;
    let mut image = Vec::new();
    image.extend_from_slice(&runne_local_model::gguf_limits::GGUF_MAGIC);
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    tmp.as_file().write_all(&image).expect("write");
    let file = tmp.reopen().expect("reopen");
    let req = LoadRequest {
        model_identity: "local:m:r:d".into(),
        load_id: [9; 16],
        artifact: file,
        artifact_digest: String::new(),
        byte_length: 0,
        config: BackendConfig::default(),
    };
    let loaded = host.backend_mut().load(&req).expect("load");
    assert_eq!(loaded.model_identity, "local:m:r:d");
    // Backend-level load only; session state flips via the host load handler.
}
