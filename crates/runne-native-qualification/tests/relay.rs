use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_api::{
    LaunchSecret, QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
};
use runne_native_qualification::{
    MAX_FAULT_TICKET_BYTES, PendingQualificationFault, QualificationFaultRelayCodecV1,
};
use serde::Serialize;

#[derive(Serialize)]
struct TicketFixture {
    schema_version: &'static str,
    ticket_id: String,
    selector: &'static str,
    process_role: &'static str,
    candidate_sha256: String,
    release_tuple_v3_sha256: String,
    source_revision: String,
    workflow_run_id: &'static str,
    namespace_sha256: String,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
    signature: SignatureFixture,
}

#[derive(Serialize)]
struct SignatureFixture {
    algorithm: &'static str,
    key_id: String,
    value: String,
}

const fn session(byte: u8) -> [u8; 16] {
    [
        0x71, byte, byte, byte, byte, byte, 0x71, byte, 0x81, byte, byte, byte, byte, byte, byte,
        byte,
    ]
}

fn binding(
    session_byte: u8,
    release_byte: u8,
    generation: u64,
    direction: QualificationFaultRelayDirectionV1,
    sequence: u64,
) -> QualificationFaultRelayBindingV1 {
    QualificationFaultRelayBindingV1::new(
        session(session_byte),
        [release_byte; 32],
        generation,
        direction,
        sequence,
    )
    .expect("valid relay binding")
}

fn codec(secret: u8) -> QualificationFaultRelayCodecV1 {
    let keys = LaunchSecret::from_bytes([secret; 32])
        .expect("nonzero launch secret")
        .derive_keys();
    QualificationFaultRelayCodecV1::from_protected_activation(&keys)
}

fn ticket(ticket_byte: u8) -> Vec<u8> {
    serde_json::to_vec(&TicketFixture {
        schema_version: "runne/macos-xpc-dpk-fault-ticket/v1",
        ticket_id: format!("{ticket_byte:02x}").repeat(32),
        selector: "kill_before_native_effect",
        process_role: "service",
        candidate_sha256: "aa".repeat(32),
        release_tuple_v3_sha256: "bb".repeat(32),
        source_revision: "cc".repeat(20),
        workflow_run_id: "run-42",
        namespace_sha256: "dd".repeat(32),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_600,
        nonce: URL_SAFE_NO_PAD.encode([ticket_byte; 32]),
        signature: SignatureFixture {
            algorithm: "ed25519",
            key_id: "ee".repeat(32),
            value: URL_SAFE_NO_PAD.encode([0x55; 64]),
        },
    })
    .expect("canonical ticket fixture")
}

fn pending(ticket_byte: u8) -> PendingQualificationFault {
    PendingQualificationFault::from_admitted_frame(ticket(ticket_byte))
        .expect("valid admitted ticket fixture")
}

#[test]
fn canonical_none_and_some_frames_round_trip_exactly() {
    let codec = codec(7);
    let none_binding = binding(
        1,
        2,
        3,
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        1,
    );
    let none = codec.encode_none(&none_binding).expect("none frame");
    assert!(
        codec
            .decode(&none, &none_binding)
            .expect("valid none")
            .is_none()
    );
    assert_eq!(codec.encode_none(&none_binding).unwrap(), none);

    let some_binding = binding(
        1,
        2,
        3,
        QualificationFaultRelayDirectionV1::RuntimeToService,
        2,
    );
    let some = pending(0x11)
        .encode_relay(&codec, &some_binding)
        .expect("some frame");
    let decoded = codec
        .decode(&some, &some_binding)
        .expect("valid some")
        .expect("present ticket");
    assert_eq!(decoded.encode_relay(&codec, &some_binding).unwrap(), some);
}

#[test]
fn authentication_binds_authority_and_every_relay_context_field() {
    let relay = codec(7);
    let exact = binding(
        1,
        2,
        3,
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        4,
    );
    let frame = pending(0x11).encode_relay(&relay, &exact).unwrap();
    assert!(
        codec(8).decode(&frame, &exact).is_err(),
        "wrong MAC authority"
    );
    for (label, other) in [
        (
            "session",
            binding(
                9,
                2,
                3,
                QualificationFaultRelayDirectionV1::DesktopToRuntime,
                4,
            ),
        ),
        (
            "release tuple",
            binding(
                1,
                9,
                3,
                QualificationFaultRelayDirectionV1::DesktopToRuntime,
                4,
            ),
        ),
        (
            "generation",
            binding(
                1,
                2,
                9,
                QualificationFaultRelayDirectionV1::DesktopToRuntime,
                4,
            ),
        ),
        (
            "direction",
            binding(
                1,
                2,
                3,
                QualificationFaultRelayDirectionV1::RuntimeToWriter,
                4,
            ),
        ),
        (
            "sequence",
            binding(
                1,
                2,
                3,
                QualificationFaultRelayDirectionV1::DesktopToRuntime,
                9,
            ),
        ),
    ] {
        assert!(
            relay.decode(&frame, &other).is_err(),
            "accepted wrong {label}"
        );
    }
}

#[test]
fn malformed_recognized_frames_fail_closed() {
    let codec = codec(7);
    let exact = binding(
        1,
        2,
        3,
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        4,
    );
    let frame = pending(0x11).encode_relay(&codec, &exact).unwrap();
    let ticket_len = ticket(0x11).len();
    let mut cases = Vec::new();
    cases.push(("truncated", frame[..frame.len() - 1].to_vec()));
    let mut trailing = frame.clone();
    trailing.push(0);
    cases.push(("trailing", trailing));
    let mut wrong_mac = frame.clone();
    *wrong_mac.last_mut().unwrap() ^= 1;
    cases.push(("MAC", wrong_mac));
    for (label, offset, value) in [
        ("version", 8, 2_u8),
        ("direction", 9, 0xff),
        ("presence tag", 74, 0xff),
    ] {
        let mut altered = frame.clone();
        altered[offset] = value;
        cases.push((label, altered));
    }
    let mut empty_some = frame.clone();
    empty_some[75..79].copy_from_slice(&0_u32.to_be_bytes());
    empty_some.drain(79..79 + ticket_len);
    cases.push(("empty some", empty_some));
    let mut oversized = frame;
    oversized[75..79]
        .copy_from_slice(&(u32::try_from(MAX_FAULT_TICKET_BYTES + 1).unwrap()).to_be_bytes());
    oversized.splice(79..79 + ticket_len, vec![b'x'; MAX_FAULT_TICKET_BYTES + 1]);
    cases.push(("oversized ticket", oversized));
    for (label, altered) in cases {
        assert!(codec.decode(&altered, &exact).is_err(), "accepted {label}");
    }
}

#[test]
fn unknown_magic_and_ticket_byte_changes_cannot_reuse_authentication() {
    let codec = codec(7);
    let exact = binding(
        1,
        2,
        3,
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        4,
    );
    let first = pending(0x11).encode_relay(&codec, &exact).unwrap();
    let second = pending(0x22).encode_relay(&codec, &exact).unwrap();
    assert_ne!(&first[first.len() - 32..], &second[second.len() - 32..]);

    let mut unknown = first;
    unknown[..8].copy_from_slice(b"UNKNOWN!");
    assert!(codec.decode(&unknown, &exact).is_err());
}

#[test]
fn outer_channel_recognition_is_exact_and_never_authentication() {
    let relay = codec(7);
    let exact = binding(
        1,
        2,
        3,
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        1,
    );
    let payload = pending(0x11).encode_relay(&relay, &exact).unwrap();
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    assert!(QualificationFaultRelayCodecV1::recognizes_frame(&frame));

    let mut wrong_magic = frame.clone();
    wrong_magic[4] ^= 1;
    assert!(!QualificationFaultRelayCodecV1::recognizes_frame(
        &wrong_magic
    ));
    assert!(!QualificationFaultRelayCodecV1::recognizes_frame(&payload));
}
