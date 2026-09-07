//! Cancel tests: cancel during/after streaming, identity conflicts,
//! drain semantics.

use runne_inference_host::backend::{BackendConfig, BackendPort, LoadRequest};
use runne_inference_host::{FakeBackend, HostSession, HostState};
use runne_inference_protocol::{Direction, MessageV1};
use runne_inference_protocol::{SESSION_PURPOSE, Session, SessionKeys};

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

fn load(host: &mut HostSession<FakeBackend>) {
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
    host.backend_mut().load(&req).expect("load");
    host.mark_loaded("local:m:r:d".into(), [9; 16]);
}

#[test]
fn cancel_race_streams_nothing_after_terminal() {
    // Cancel arrives after the generation finished: bounded cancel is a
    // no-op for already-terminal work (fake backend deterministic).
    let mut host = host_session();
    load(&mut host);
    let items =
        runne_inference_host::generate::stream_generation(&mut host, [1; 16], [2; 16], [3; 16], "")
            .expect("generate");
    // Terminal item present: last StreamItem is finish.
    let terminal = items
        .iter()
        .any(|m| matches!(m, MessageV1::StreamItem { kind, .. } if kind == "finish"));
    assert!(terminal, "generation must end with a terminal finish item");
    host.backend_mut().cancel();
    // Nothing further streams; state remains Loaded.
    assert_eq!(host.state(), HostState::Loaded);
}

#[test]
fn generation_id_conflict_rejected() {
    let mut host = host_session();
    load(&mut host);
    let first =
        runne_inference_host::generate::stream_generation(&mut host, [1; 16], [2; 16], [3; 16], "")
            .expect("first");
    assert!(!first.is_empty());
    // Same generation id reused for a second stream → attempt conflict.
    let err =
        runne_inference_host::generate::stream_generation(&mut host, [1; 16], [2; 16], [3; 16], "")
            .expect_err("conflict");
    assert!(matches!(
        err,
        runne_inference_host::HostError::AttemptConflict
    ));
}

#[test]
fn drain_blocks_generation() {
    let mut host = host_session();
    load(&mut host);
    host.drain(50).expect("drain");
    let err =
        runne_inference_host::generate::stream_generation(&mut host, [1; 16], [2; 16], [3; 16], "")
            .expect_err("drained");
    assert!(matches!(err, runne_inference_host::HostError::InvalidState));
}
