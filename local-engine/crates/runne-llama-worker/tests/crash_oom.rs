//! Crash/OOM containment on the worker session: a crash closes the
//! wire with NO protocol frame (the host experiences process death);
//! forced OOM reports the typed `memory` code and keeps the exchange
//! balanced; unload/health idle-ack round-trips.

use runne_inference_protocol::{
    ContextMaterial, Direction, LaunchSecret, ProtocolError, Session, SessionKeys, WORKER_PURPOSE,
    WorkerBackendConfig, WorkerErrorCode, WorkerFrameV1, WorkerLoad, WorkerWire,
};
use runne_llama_worker::WorkerIdentity;
use runne_llama_worker::engine::FakeEngine;
use runne_llama_worker::session::serve;
use std::os::fd::OwnedFd;
use std::sync::mpsc::{Receiver, Sender, channel};

const WORKER_GEN: [u8; 16] = [0xAA; 16];
const HOST_GEN: [u8; 16] = [0xBB; 16];
const PROFILE: &str = "llama-cpp-cpu-macos-arm64-v1";
const CHANNEL: [u8; 16] = [0x21; 16];

fn keys() -> SessionKeys {
    SessionKeys::derive(
        &LaunchSecret::from_bytes(&[0x5E; 32]),
        b"worker-hello",
        b"worker-welcome",
        &ContextMaterial {
            channel: CHANNEL,
            epoch: [3; 8],
            tag: [0, 0, 0],
        },
        WORKER_PURPOSE.as_bytes(),
    )
    .expect("keys")
}

/// In-memory wire: both ends in one process; `dead` simulates the
/// abrupt EOF of a dead worker process.
struct QueueWire {
    inbound: Receiver<Vec<u8>>,
    outbound: Sender<Vec<u8>>,
    inbound_fds: Receiver<OwnedFd>,
    outbound_fds: Sender<OwnedFd>,
    dead: bool,
}

fn wire_pair() -> (QueueWire, QueueWire) {
    let (a_tx, a_rx) = channel();
    let (b_tx, b_rx) = channel();
    let (afd_tx, afd_rx) = channel();
    let (bfd_tx, bfd_rx) = channel();
    let mk = |inbound, outbound, inbound_fds, outbound_fds| QueueWire {
        inbound,
        outbound,
        inbound_fds,
        outbound_fds,
        dead: false,
    };
    (
        mk(a_rx, b_tx, afd_rx, bfd_tx),
        mk(b_rx, a_tx, bfd_rx, afd_tx),
    )
}

impl QueueWire {
    fn push_fd(&self, fd: OwnedFd) {
        let _ = self.outbound_fds.send(fd);
    }
}

impl WorkerWire for QueueWire {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), ProtocolError> {
        self.outbound
            .send(frame.to_vec())
            .map_err(|_| ProtocolError::Malformed)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, ProtocolError> {
        if self.dead {
            return Err(ProtocolError::Malformed);
        }
        self.inbound.recv().map_err(|_| ProtocolError::Malformed)
    }

    fn send_fd(&mut self, _fd: std::os::fd::BorrowedFd<'_>) -> Result<(), ProtocolError> {
        Err(ProtocolError::Malformed)
    }

    fn recv_fd(&mut self) -> Result<OwnedFd, ProtocolError> {
        self.inbound_fds
            .recv()
            .map_err(|_| ProtocolError::Malformed)
    }
}

/// 24-byte zero-tensor GGUF with its exact digest/length.
fn gguf_fixture() -> (OwnedFd, String, u64, tempfile::TempDir) {
    let mut image = Vec::new();
    image.extend_from_slice(b"GGUF");
    image.extend_from_slice(&3u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("m.gguf");
    std::fs::write(&path, &image).expect("write");
    use sha2::Digest as _;
    let digest = format!(
        "sha256:{}",
        sha2::Sha256::digest(&image)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let file = std::fs::File::open(&path).expect("open");
    let fd: OwnedFd = file.into();
    (fd, digest, image.len() as u64, dir)
}

fn identity() -> WorkerIdentity {
    WorkerIdentity {
        worker_generation: WORKER_GEN,
        host_generation: HOST_GEN,
        backend_profile: PROFILE.into(),
    }
}

fn load_frame(digest: &str, len: u64) -> WorkerFrameV1 {
    WorkerFrameV1::BackendLoad {
        worker_generation: WORKER_GEN,
        host_generation: HOST_GEN,
        backend_profile: PROFILE.into(),
        load: WorkerLoad {
            model_identity: "local:m1:r1".into(),
            load_id: [7; 16],
            artifact_digest: digest.into(),
            byte_length: len,
            load_fence: [7; 16],
        },
        config: WorkerBackendConfig {
            context_max_tokens: 512,
            output_max_tokens: 32,
            gpu_layers: 0,
            threads: 2,
            seed: 42,
        },
    }
}

fn infer_frame() -> WorkerFrameV1 {
    WorkerFrameV1::BackendInfer {
        worker_generation: WORKER_GEN,
        host_generation: HOST_GEN,
        backend_profile: PROFILE.into(),
        generation_id: [1; 16],
        attempt_id: [2; 16],
        stream_id: [3; 16],
        prompt: "hello".into(),
    }
}

/// Runs the worker loop in a thread; returns the host-side handle.
fn start_worker(engine: FakeEngine) -> QueueWire {
    let (host_wire, worker_wire) = wire_pair();
    std::thread::spawn(move || {
        let mut worker_session: Session<WorkerFrameV1> =
            Session::new(keys(), CHANNEL, 7, Direction::H2c, 64 * 1024);
        let mut wire = worker_wire;
        let mut engine = engine;
        let _ = serve(&mut wire, &mut worker_session, identity(), &mut engine);
    });
    host_wire
}

fn host_session() -> Session<WorkerFrameV1> {
    Session::new(keys(), CHANNEL, 7, Direction::C2h, 64 * 1024)
}

/// Crash: no error frame ever arrives — the wire just dies mid-step,
/// exactly as when a real worker process dies during inference.
#[test]
fn crash_closes_wire_without_error_frame() {
    let mut wire = start_worker(FakeEngine::new(vec!["a".into(), "b".into()]).crash_after(1));
    let (fd, digest, len, _dir) = gguf_fixture();
    let mut session = host_session();
    let load = load_frame(&digest, len);
    wire.push_fd(fd);
    wire.send_frame(&session.encode(&load).expect("enc"))
        .expect("send");
    let ack = session
        .decode(&wire.recv_frame().expect("recv"))
        .expect("dec");
    assert!(matches!(ack, WorkerFrameV1::BackendLoaded { .. }));
    wire.send_frame(&session.encode(&infer_frame()).expect("enc"))
        .expect("send");
    // The engine dies before completing the step: no items, no error.
    let err = wire.recv_frame().expect_err("wire dead");
    assert!(matches!(err, ProtocolError::Malformed));
}

/// Forced OOM: the typed `memory` code arrives as a balanced frame.
#[test]
fn forced_oom_reports_memory_code() {
    let mut wire = start_worker(FakeEngine::new(vec!["a".into()]).oom_after(0));
    let (fd, digest, len, _dir) = gguf_fixture();
    let mut session = host_session();
    wire.push_fd(fd);
    wire.send_frame(&session.encode(&load_frame(&digest, len)).expect("enc"))
        .expect("send");
    let ack = session
        .decode(&wire.recv_frame().expect("recv"))
        .expect("dec");
    assert!(matches!(ack, WorkerFrameV1::BackendLoaded { .. }));
    wire.send_frame(&session.encode(&infer_frame()).expect("enc"))
        .expect("send");
    let err = session
        .decode(&wire.recv_frame().expect("recv"))
        .expect("dec");
    match err {
        WorkerFrameV1::BackendError { code, .. } => assert_eq!(code, WorkerErrorCode::Memory),
        other => panic!("expected backend error, got {other:?}"),
    }
}

/// Unload and health round-trip the documented idle ack.
#[test]
fn unload_and_health_idle_ack() {
    let mut wire = start_worker(FakeEngine::new(vec!["answer".into()]));
    let (fd, digest, len, _dir) = gguf_fixture();
    let mut session = host_session();
    wire.push_fd(fd);
    wire.send_frame(&session.encode(&load_frame(&digest, len)).expect("enc"))
        .expect("send");
    let ack = session
        .decode(&wire.recv_frame().expect("recv"))
        .expect("dec");
    assert!(matches!(ack, WorkerFrameV1::BackendLoaded { .. }));
    let unload = WorkerFrameV1::BackendUnload {
        worker_generation: WORKER_GEN,
        host_generation: HOST_GEN,
        backend_profile: PROFILE.into(),
        load_id: [7; 16],
    };
    wire.send_frame(&session.encode(&unload).expect("enc"))
        .expect("send");
    let ack = session
        .decode(&wire.recv_frame().expect("recv"))
        .expect("dec");
    assert!(matches!(ack, WorkerFrameV1::BackendHealth { .. }));
    let health = WorkerFrameV1::BackendHealth {
        worker_generation: WORKER_GEN,
        host_generation: HOST_GEN,
        backend_profile: PROFILE.into(),
    };
    wire.send_frame(&session.encode(&health).expect("enc"))
        .expect("send");
    let ack = session
        .decode(&wire.recv_frame().expect("recv"))
        .expect("dec");
    assert!(matches!(ack, WorkerFrameV1::BackendHealth { .. }));
}
