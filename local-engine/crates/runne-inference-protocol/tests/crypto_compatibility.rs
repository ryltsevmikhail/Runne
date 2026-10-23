//! Fixed public nonsecret protocol fixtures; source and error assertions shared by both lanes.
use runne_inference_protocol::{
    ContextMaterial, Direction, LaunchSecret, MessageV1, ProtocolError, SESSION_PURPOSE, Session,
    SessionKeys, WORKER_PURPOSE,
    cbor::{self, Cbor},
    frame, handshake,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn secret() -> LaunchSecret {
    LaunchSecret::from_bytes(&[0x42; 32])
}
fn keys(channel: u8, epoch: u64, purpose: &str, hello: &[u8]) -> SessionKeys {
    SessionKeys::derive(
        &secret(),
        hello,
        b"welcome",
        &ContextMaterial {
            channel: [channel; 16],
            epoch: epoch.to_be_bytes(),
            tag: [0; 3],
        },
        purpose.as_bytes(),
    )
    .unwrap()
}
fn pair(epoch: u64) -> (Session, Session) {
    (
        Session::new(
            keys(3, epoch, SESSION_PURPOSE, b"hello"),
            [3; 16],
            epoch,
            Direction::C2h,
            65536,
        ),
        Session::new(
            keys(3, epoch, SESSION_PURPOSE, b"hello"),
            [3; 16],
            epoch,
            Direction::H2c,
            65536,
        ),
    )
}
fn change(bytes: &[u8], field: &[u8], value: Cbor) -> Vec<u8> {
    let (Cbor::Map(mut map), true) = frame::decode_frame(bytes, 65536).unwrap() else {
        panic!()
    };
    map.insert(field.to_vec(), value);
    frame::pack_outer(Cbor::Map(map), 65536).unwrap()
}
fn record(records: &mut Vec<String>, name: &str, bytes: &[u8]) {
    records.push(format!("{name}={}", hex(bytes)));
}

#[test]
fn deterministic_handshake_stream_and_derivation_bytes() {
    let mut records = Vec::new();
    for epoch in [0, 1, u64::MAX] {
        let (hello, state) = handshake::client_hello(
            &secret(),
            &[1; 16],
            "runtime-A",
            "adapter-A",
            "profile-A",
            "local:model-A:r1:sha256:fixture",
        )
        .unwrap();
        let (welcome, mut host) = handshake::host_accept(
            &secret(),
            &hello,
            &[2; 16],
            &[3; 16],
            epoch,
            "host-A",
            65536,
        )
        .unwrap();
        let (ready, mut client) = handshake::client_finalize(&secret(), state, &welcome).unwrap();
        host.decode(&ready).unwrap();
        for (label, bytes) in [("hello", hello), ("welcome", welcome), ("ready", ready)] {
            record(&mut records, &format!("{label}-{epoch}"), &bytes);
        }
        let messages = [
            MessageV1::StreamItem {
                generation_id: [4; 16],
                attempt_id: [5; 16],
                stream_id: [6; 16],
                stream_sequence: 0,
                kind: "text".into(),
                payload: b"fixture".to_vec(),
            },
            MessageV1::Cancel {
                generation_id: [4; 16],
                attempt_id: [5; 16],
                cancel_id: [7; 16],
            },
            MessageV1::ReconcileResult {
                result: "uncertain".into(),
            },
        ];
        for (i, message) in messages.into_iter().enumerate() {
            let bytes = client.encode(&message).unwrap();
            assert_eq!(host.decode(&bytes).unwrap(), message);
            record(&mut records, &format!("message-{epoch}-{i}"), &bytes);
        }
        for purpose in [SESSION_PURPOSE, WORKER_PURPOSE] {
            let k = keys(3, epoch, purpose, b"hello");
            for direction in [Direction::C2h, Direction::H2c] {
                record(
                    &mut records,
                    &format!("key-{epoch}-{purpose}-{}", direction.as_str()),
                    k.key(direction),
                );
            }
            assert_ne!(k.key(Direction::C2h), k.key(Direction::H2c));
            for alternate in [
                keys(4, epoch, purpose, b"hello"),
                keys(3, epoch, purpose, b"hello!"),
                keys(3, epoch ^ 1, purpose, b"hello"),
            ] {
                assert_ne!(k.key(Direction::C2h), alternate.key(Direction::C2h));
            }
        }
        assert_ne!(
            keys(3, epoch, SESSION_PURPOSE, b"hello").key(Direction::C2h),
            keys(3, epoch, WORKER_PURPOSE, b"hello").key(Direction::C2h)
        );
    }
    let output = records.join("\n") + "\n";
    println!("WIRE-FIXTURE-BEGIN\n{output}WIRE-FIXTURE-END");
    // Frozen from pristine-M implementation before the migrated lane executes.
    let frozen = include_str!("fixtures/crypto-wire-v1.txt");
    assert_eq!(output, frozen);
    println!(
        "CRYPTO wire-fixtures-sha256={}",
        hex(&Sha256::digest(output.as_bytes()))
    );
}

#[test]
fn exact_tag_tamper_replay_epoch_and_direction_errors() {
    let (mut client, _) = pair(1);
    let authentic = client.encode(&MessageV1::Health).unwrap();
    let (Cbor::Map(map), true) = frame::decode_frame(&authentic, 65536).unwrap() else {
        panic!()
    };
    let Some(Cbor::Bytes(tag)) = map.get(b"mac".as_slice()) else {
        panic!()
    };
    let mut corrupt = tag.clone();
    corrupt[0] ^= 1;
    let cases = [
        (
            "empty-tag",
            change(&authentic, b"mac", Cbor::Bytes(vec![])),
            ProtocolError::MacMismatch,
        ),
        (
            "short-tag",
            change(&authentic, b"mac", Cbor::Bytes(vec![0; 31])),
            ProtocolError::MacMismatch,
        ),
        (
            "long-tag",
            change(&authentic, b"mac", Cbor::Bytes(vec![0; 33])),
            ProtocolError::MacMismatch,
        ),
        (
            "bitflip-tag",
            change(&authentic, b"mac", Cbor::Bytes(corrupt)),
            ProtocolError::MacMismatch,
        ),
        (
            "wrong-epoch",
            change(&authentic, b"gen", Cbor::Unsigned(2)),
            ProtocolError::IdentityMismatch,
        ),
        (
            "wrong-channel",
            change(&authentic, b"sid", Cbor::Bytes(vec![4; 16])),
            ProtocolError::IdentityMismatch,
        ),
        (
            "reflection",
            change(&authentic, b"dir", Cbor::Text("h2c".into())),
            ProtocolError::Reflection,
        ),
        (
            "gap",
            change(&authentic, b"seq", Cbor::Unsigned(1)),
            ProtocolError::SequenceGap,
        ),
    ];
    for (name, bytes, error) in cases {
        let (_, mut host) = pair(1);
        assert_eq!(host.decode(&bytes).unwrap_err(), error, "{name}");
        // Rejection cannot advance the receive sequence.
        assert_eq!(host.decode(&authentic).unwrap(), MessageV1::Health);
        assert_eq!(
            host.decode(&authentic).unwrap_err(),
            ProtocolError::SequenceGap
        );
        println!("CRYPTO error-{name}={error:?}");
    }
    let mut wrong_key_host: Session = Session::new(
        keys(3, 1, WORKER_PURPOSE, b"hello"),
        [3; 16],
        1,
        Direction::H2c,
        65536,
    );
    assert_eq!(
        wrong_key_host.decode(&authentic).unwrap_err(),
        ProtocolError::MacMismatch
    );
    let (_, mut host) = pair(1);
    assert_eq!(
        host.decode(&[0, 0, 0, 1, 0xff]).unwrap_err(),
        ProtocolError::Malformed
    );
    let mut raw = Vec::new();
    cbor::encode(&Cbor::Null, &mut raw);
    assert_eq!(raw, vec![0xf6]);
}
