//! Golden tests: deterministic handshake + every catalog message type
//! round-trips through paired sessions; canonical re-encode equality;
//! RFC 5869 expand vector.

use runne_inference_protocol::{
    Direction, LaunchSecret, MessageV1, ProtocolError, SESSION_PURPOSE, Session, SessionKeys,
    handshake, hmac,
};

fn secret() -> LaunchSecret {
    LaunchSecret::from_bytes(&[0x42u8; 32])
}

fn establish() -> (Session, Session) {
    let sec = secret();
    let (hello_bytes, state) = handshake::client_hello(
        &sec,
        &[1u8; 16],
        "runne-runtime/1",
        "provider-local/1",
        "llama-cpp-cpu-macos-arm64-v1",
        "local:qwen3-4b:r1:sha256:deadbeef",
    )
    .expect("hello");
    let (welcome_bytes, mut host_session) = handshake::host_accept(
        &sec,
        &hello_bytes,
        &[2u8; 16],
        &[3u8; 16],
        7,
        "runne-host/1",
        64 * 1024,
    )
    .expect("welcome");
    let (ready_bytes, client_session) =
        handshake::client_finalize(&sec, state, &welcome_bytes).expect("ready");
    // Host must accept `ready` as its first inbound frame.
    let res = host_session.decode(&ready_bytes);
    if let Err(e) = &res {
        eprintln!("READY DECODE ERR: {e:?}");
        eprintln!(
            "READY BYTES: {}",
            ready_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
    res.expect("host consumes ready");
    (client_session, host_session)
}

#[test]
fn handshake_roundtrip_produces_paired_sessions() {
    let (mut client, mut host) = establish();
    let msg = MessageV1::LoadModel {
        model_identity: "local:qwen3-4b:r1:sha256:deadbeef".into(),
        load_id: [9u8; 16],
        artifact_digest: "sha256:feedface".into(),
        byte_length: 1024,
    };
    let bytes = client.encode(&msg).expect("encode");
    let decoded = host.decode(&bytes).expect("decode");
    assert_eq!(decoded, msg);
}

#[test]
fn every_catalog_message_roundtrips() {
    let cases: Vec<MessageV1> = vec![
        MessageV1::LoadModel {
            model_identity: "local:m:r:d".into(),
            load_id: [1; 16],
            artifact_digest: "sha256:aa".into(),
            byte_length: 5,
        },
        MessageV1::GenerationRequest {
            generation_id: [2; 16],
            attempt_id: [3; 16],
            prepared_request_ref: "prep-1".into(),
        },
        MessageV1::GenerationStarted {
            generation_id: [2; 16],
            attempt_id: [3; 16],
            stream_id: [4; 16],
        },
        MessageV1::StreamItem {
            generation_id: [2; 16],
            attempt_id: [3; 16],
            stream_id: [4; 16],
            stream_sequence: 0,
            kind: "text".into(),
            payload: b"hello".to_vec(),
        },
        MessageV1::StreamAck {
            stream_id: [4; 16],
            highest_sequence: 0,
        },
        MessageV1::Cancel {
            generation_id: [2; 16],
            attempt_id: [3; 16],
            cancel_id: [5; 16],
        },
        MessageV1::CancelAck {
            cancel_id: [5; 16],
            disposition: "terminal".into(),
        },
        MessageV1::Health,
        MessageV1::HealthResult {
            state: "ready".into(),
        },
        MessageV1::Drain { deadline_ms: 1000 },
        MessageV1::DrainAck,
        MessageV1::Shutdown { deadline_ms: 500 },
        MessageV1::ShutdownAck,
        MessageV1::Reconcile {
            attempt_id: [3; 16],
            generation_id: [2; 16],
        },
        MessageV1::ReconcileResult {
            result: "uncertain".into(),
        },
        MessageV1::Error {
            code: "HostUnavailable".into(),
            detail: "sanitized".into(),
        },
    ];
    for case in cases {
        let (mut client, mut host) = establish();
        let bytes = client.encode(&case).expect("encode");
        let decoded = host.decode(&bytes).expect("decode");
        assert_eq!(
            decoded,
            case,
            "roundtrip for {}",
            runne_inference_protocol::request::type_name(&case)
        );
    }
}

#[test]
fn encode_is_deterministic_and_canonical() {
    let (mut client, _host) = establish();
    let msg = MessageV1::Health;
    let a = client.encode(&msg).expect("a");
    // Rebuild a fresh identical session to encode the same logical frame:
    // sequence differs, so instead assert re-encode equality via decode.
    let (_value, canonical) =
        runne_inference_protocol::decode_frame(&a, 64 * 1024).expect("decode");
    assert!(canonical);
}

#[test]
fn rfc5869_expand_vector_matches() {
    // RFC 5869 Appendix A, Test Case 1 (SHA-256): PRK and first OKM block.
    let ikm = [0x0b_u8; 22];
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let prk = hmac(&salt, &[&ikm]);
    let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    assert_eq!(hex(&prk), expected_prk);
    // expand: T1 = HMAC(PRK, info || 0x01)
    let t1 = hmac(&prk, &[&info, &[1u8]]);
    let expected_t1 = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf";
    assert_eq!(hex(&t1), expected_t1);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn directional_keys_differ_and_depends_on_transcript() {
    let sec = secret();
    let keys_a = SessionKeys::derive(
        &sec,
        b"hello-a",
        b"welcome",
        &runne_inference_protocol::ContextMaterial {
            channel: [1; 16],
            epoch: [0; 8],
            tag: [0, 0, 0],
        },
        SESSION_PURPOSE.as_bytes(),
    )
    .expect("keys");
    let keys_b = SessionKeys::derive(
        &sec,
        b"hello-b",
        b"welcome",
        &runne_inference_protocol::ContextMaterial {
            channel: [1; 16],
            epoch: [0; 8],
            tag: [0, 0, 0],
        },
        SESSION_PURPOSE.as_bytes(),
    )
    .expect("keys");
    assert_ne!(keys_a.key(Direction::C2h), keys_a.key(Direction::H2c));
    assert_ne!(keys_a.key(Direction::C2h), keys_b.key(Direction::C2h));
}

#[test]
fn wrong_secret_fails_handshake() {
    let sec = secret();
    let (hello_bytes, _state) =
        handshake::client_hello(&sec, &[1u8; 16], "r", "a", "p", "m").expect("hello");
    let other = LaunchSecret::from_bytes(&[0x99u8; 32]);
    match handshake::host_accept(&other, &hello_bytes, &[2u8; 16], &[3u8; 16], 7, "h", 1024) {
        Err(ProtocolError::AuthenticationFailed) => {}
        Err(other_err) => panic!("unexpected error: {other_err:?}"),
        Ok(_) => panic!("wrong secret must not authenticate"),
    }
}
