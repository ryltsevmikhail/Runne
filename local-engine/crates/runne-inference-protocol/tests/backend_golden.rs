//! Worker-catalog golden tests (Plan Task 9): closed `backend_*` catalog
//! round-trips canonically; engine keys/catalog never open worker
//! frames; strict sequence and bounded fields hold on the worker
//! channel (PROTOCOL.md §Phase 1 backend worker profile).

use runne_inference_protocol::{
    ContextMaterial, Direction, LaunchSecret, ProtocolError, Session, SessionKeys, WORKER_PURPOSE,
    WorkerBackendConfig, WorkerErrorCode, WorkerFrameV1, WorkerLoad,
};

fn worker_keys(channel: [u8; 16], purpose: &[u8]) -> SessionKeys {
    SessionKeys::derive(
        &LaunchSecret::from_bytes(&[0x77; 32]),
        b"worker-hello",
        b"worker-welcome",
        &ContextMaterial {
            channel,
            epoch: [1; 8],
            tag: [0, 0, 0],
        },
        purpose,
    )
    .expect("keys")
}

fn host_session(channel: [u8; 16], purpose: &[u8]) -> Session<WorkerFrameV1> {
    Session::new(
        worker_keys(channel, purpose),
        channel,
        7,
        Direction::C2h,
        64 * 1024,
    )
}

fn worker_session(channel: [u8; 16], purpose: &[u8]) -> Session<WorkerFrameV1> {
    Session::new(
        worker_keys(channel, purpose),
        channel,
        7,
        Direction::H2c,
        64 * 1024,
    )
}

fn sample_load() -> WorkerLoad {
    WorkerLoad {
        model_identity: "local:m1:r1".into(),
        load_id: [10; 16],
        artifact_digest: "sha256:abcd".into(),
        byte_length: 24,
        load_fence: [11; 16],
    }
}

/// One frame of every catalog entry, host→worker and worker→host.
fn catalog() -> Vec<WorkerFrameV1> {
    let wg = [1; 16];
    let hg = [2; 16];
    let profile = "llama-cpp-cpu-macos-arm64-v1".to_string();
    let cfg = WorkerBackendConfig {
        context_max_tokens: 4096,
        output_max_tokens: 1024,
        gpu_layers: 0,
        threads: 4,
        seed: 42,
    };
    vec![
        WorkerFrameV1::BackendLoad {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile.clone(),
            load: sample_load(),
            config: cfg,
        },
        WorkerFrameV1::BackendLoaded {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile.clone(),
            load_id: [10; 16],
            model_identity: "local:m1:r1".into(),
        },
        WorkerFrameV1::BackendInfer {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile.clone(),
            generation_id: [3; 16],
            attempt_id: [4; 16],
            stream_id: [5; 16],
            prompt: "hello".into(),
        },
        WorkerFrameV1::BackendItem {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile.clone(),
            stream_id: [5; 16],
            stream_sequence: 0,
            kind: "text".into(),
            payload: b"answer".to_vec(),
        },
        WorkerFrameV1::BackendCancel {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile.clone(),
            cancel_id: [6; 16],
        },
        WorkerFrameV1::BackendUnload {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile.clone(),
            load_id: [10; 16],
        },
        WorkerFrameV1::BackendHealth {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile.clone(),
        },
        WorkerFrameV1::BackendTerminal {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile.clone(),
            stream_id: [5; 16],
            reason: "stop".into(),
            prompt_tokens: 9,
            output_tokens: 4,
        },
        WorkerFrameV1::BackendError {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile,
            code: WorkerErrorCode::Memory,
            detail: "allocator returned null".into(),
        },
    ]
}

#[test]
fn worker_catalog_roundtrips_canonically() {
    let channel = [9; 16];
    let mut host = host_session(channel, WORKER_PURPOSE.as_bytes());
    let mut worker = worker_session(channel, WORKER_PURPOSE.as_bytes());
    for frame in catalog() {
        let wire = host.encode(&frame).expect("encode");
        let back = worker.decode(&wire).expect("decode");
        assert_eq!(back, frame, "canonical roundtrip for {}", frame.type_name());
    }
}

#[test]
fn engine_purpose_keys_reject_worker_frames() {
    let channel = [8; 16];
    let mut host = host_session(channel, WORKER_PURPOSE.as_bytes());
    let mut eavesdropper = worker_session(
        channel,
        runne_inference_protocol::SESSION_PURPOSE.as_bytes(),
    );
    let wire = host
        .encode(&catalog().into_iter().next().expect("frame"))
        .expect("encode");
    let err = eavesdropper.decode(&wire).expect_err("foreign keys");
    assert!(matches!(err, ProtocolError::MacMismatch));
}

#[test]
fn engine_catalog_rejected_on_worker_channel() {
    // Same keys/session ids as the worker channel, but the engine
    // catalog: MAC validates, the unknown type must not decode.
    let channel = [7; 16];
    let purpose = WORKER_PURPOSE.as_bytes();
    let mut engine_session: Session<runne_inference_protocol::MessageV1> = Session::new(
        worker_keys(channel, purpose),
        channel,
        7,
        Direction::C2h,
        64 * 1024,
    );
    let wire = engine_session
        .encode(&runne_inference_protocol::MessageV1::Health)
        .expect("encode engine frame");
    let mut worker = worker_session(channel, purpose);
    let err = worker.decode(&wire).expect_err("engine type");
    assert!(matches!(err, ProtocolError::UnknownType));
}

#[test]
fn worker_sequence_gap_closes() {
    let channel = [6; 16];
    let purpose = WORKER_PURPOSE.as_bytes();
    let mut host = host_session(channel, purpose);
    let mut worker = worker_session(channel, purpose);
    let frames = catalog();
    let first = host.encode(&frames[0]).expect("encode 1");
    let _second = host.encode(&frames[1]).expect("encode 2");
    worker.decode(&first).expect("first ok");
    // Replayed or gap frames close the session (SequenceGap), never replay.
    let err = worker.decode(&first).expect_err("replay");
    assert!(matches!(err, ProtocolError::SequenceGap));
}

#[test]
fn worker_error_codes_are_closed() {
    let all = [
        WorkerErrorCode::LoadFailed,
        WorkerErrorCode::DigestMismatch,
        WorkerErrorCode::LengthMismatch,
        WorkerErrorCode::ContextExceeded,
        WorkerErrorCode::Memory,
        WorkerErrorCode::Cancelled,
        WorkerErrorCode::Unsupported,
        WorkerErrorCode::Internal,
    ];
    for code in all {
        assert_eq!(code.as_str().parse::<WorkerErrorCode>(), Ok(code));
    }
    assert_eq!("bogus".parse::<WorkerErrorCode>(), Err(()));
}

#[test]
fn worker_item_kinds_and_terminal_reasons_are_closed() {
    assert_eq!(
        runne_inference_protocol::backend::WORKER_ITEM_KINDS,
        ["text", "usage", "finish"]
    );
    assert_eq!(
        runne_inference_protocol::backend::WORKER_TERMINAL_REASONS,
        ["stop", "cancelled", "error"]
    );
}
