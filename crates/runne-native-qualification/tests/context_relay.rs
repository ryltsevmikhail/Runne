#[path = "support/context_relay_fixture.rs"]
mod fixture;

use runne_api::{
    LaunchSecret, QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationRunContextRelayAuthenticator, QualificationRunContextRelayBindingV1,
    QualificationRunContextRelayContentBindingV1, QualificationRunContextRelayDirectionV1,
};
use runne_native_qualification::{
    MAX_RUN_CONTEXT_BYTES, PendingQualificationAdmission, QualificationFaultRelayCodecV1,
    QualificationRunContextRelayCodecV1,
};
use sha2::{Digest as _, Sha256};

const PREFIX_BYTES: usize = 78;
const MAC_BYTES: usize = 32;

const fn session(byte: u8) -> [u8; 16] {
    [
        0x71, byte, byte, byte, byte, byte, 0x71, byte, 0x81, byte, byte, byte, byte, byte, byte,
        byte,
    ]
}

fn context_binding(
    session_byte: u8,
    release_byte: u8,
    generation: u64,
    sequence: u64,
) -> QualificationRunContextRelayBindingV1 {
    QualificationRunContextRelayBindingV1::new(
        session(session_byte),
        [release_byte; 32],
        generation,
        QualificationRunContextRelayDirectionV1::DesktopToRuntime,
        sequence,
    )
    .expect("valid context binding")
}

fn fault_binding(sequence: u64) -> QualificationFaultRelayBindingV1 {
    QualificationFaultRelayBindingV1::new(
        session(1),
        [2; 32],
        3,
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        sequence,
    )
    .expect("valid fault binding")
}

fn keys(secret: u8) -> runne_api::ProtectedActivationKeys {
    LaunchSecret::from_bytes([secret; 32])
        .unwrap()
        .derive_keys()
}

fn frames(secret: u8, context_id: u8, context_sequence: u64, fault_sequence: u64) -> [Vec<u8>; 2] {
    let ticket = fixture::ticket(0x11);
    let context = fixture::context(&ticket, context_id);
    let admission = PendingQualificationAdmission::from_admitted_bundle(fixture::admission_bundle(
        &context, &ticket,
    ))
    .expect("valid pair");
    let keys = keys(secret);
    admission
        .encode_relays(
            &QualificationRunContextRelayCodecV1::from_protected_activation(&keys),
            &context_binding(1, 2, 3, context_sequence),
            &QualificationFaultRelayCodecV1::from_protected_activation(&keys),
            &fault_binding(fault_sequence),
        )
        .expect("encoded ordered pair")
        .into_ordered_frames()
}

#[test]
fn canonical_context_frame_round_trips_deterministically_before_unchanged_fault_frame() {
    let exact = context_binding(1, 2, 3, 4);
    let pair = frames(7, 0x33, 4, 9);
    assert!(pair[0].starts_with(b"RNQCTX1\0\x01\x01"));
    assert!(pair[1].starts_with(b"RNQFRLY1\x01\x01"));
    let codec = QualificationRunContextRelayCodecV1::from_protected_activation(&keys(7));
    codec
        .decode(&pair[0], &exact)
        .expect("authenticated canonical context");
    assert_eq!(frames(7, 0x33, 4, 9), pair);

    let ticket = fixture::ticket(0x11);
    let expected_fault =
        runne_native_qualification::PendingQualificationFault::from_admitted_frame(ticket)
            .unwrap()
            .encode_relay(
                &QualificationFaultRelayCodecV1::from_protected_activation(&keys(7)),
                &fault_binding(9),
            )
            .unwrap();
    assert_eq!(pair[1], expected_fault, "RNQFRLY1 must remain unchanged");
}

#[test]
fn authentication_rejects_wrong_secret_and_every_expected_binding_field() {
    let frame = frames(7, 0x33, 4, 9).into_iter().next().unwrap();
    let exact = context_binding(1, 2, 3, 4);
    assert!(
        QualificationRunContextRelayCodecV1::from_protected_activation(&keys(8))
            .decode(&frame, &exact)
            .is_err()
    );
    let codec = QualificationRunContextRelayCodecV1::from_protected_activation(&keys(7));
    for other in [
        context_binding(9, 2, 3, 4),
        context_binding(1, 9, 3, 4),
        context_binding(1, 2, 9, 4),
        context_binding(1, 2, 3, 9),
    ] {
        assert!(codec.decode(&frame, &other).is_err());
    }
    let mut wrong_direction = frame;
    wrong_direction[9] = 2;
    assert!(codec.decode(&wrong_direction, &exact).is_err());
}

#[test]
fn malformed_authenticated_or_recognized_context_frames_fail_closed() {
    let exact = context_binding(1, 2, 3, 4);
    let codec = QualificationRunContextRelayCodecV1::from_protected_activation(&keys(7));
    let frame = frames(7, 0x33, 4, 9).into_iter().next().unwrap();
    let context_len = frame.len() - PREFIX_BYTES - MAC_BYTES;
    let mut cases = vec![frame[..frame.len() - 1].to_vec()];
    let mut trailing = frame.clone();
    trailing.push(0);
    cases.push(trailing);
    for (offset, value) in [(0, b'X'), (8, 2), (9, 2)] {
        let mut changed = frame.clone();
        changed[offset] = value;
        cases.push(changed);
    }
    let mut empty = frame.clone();
    empty[74..78].copy_from_slice(&0_u32.to_be_bytes());
    empty.drain(PREFIX_BYTES..PREFIX_BYTES + context_len);
    cases.push(empty);
    let mut oversized = frame.clone();
    oversized[74..78].copy_from_slice(
        &u32::try_from(MAX_RUN_CONTEXT_BYTES + 1)
            .unwrap()
            .to_be_bytes(),
    );
    oversized.splice(
        PREFIX_BYTES..PREFIX_BYTES + context_len,
        vec![b'x'; MAX_RUN_CONTEXT_BYTES + 1],
    );
    cases.push(oversized);
    let mut altered_context = frame.clone();
    altered_context[PREFIX_BYTES] ^= 1;
    cases.push(altered_context);
    let mut altered_mac = frame;
    *altered_mac.last_mut().unwrap() ^= 1;
    cases.push(altered_mac);
    for changed in cases {
        assert!(codec.decode(&changed, &exact).is_err());
    }
}

#[test]
fn valid_mac_does_not_bypass_canonical_context_shape_admission() {
    let binding = context_binding(1, 2, 3, 4);
    let keys = keys(7);
    let auth = QualificationRunContextRelayAuthenticator::from_protected_activation(&keys);
    let invalid = b"{}";
    let content = QualificationRunContextRelayContentBindingV1::new(
        u32::try_from(invalid.len()).unwrap(),
        Sha256::digest(invalid).into(),
    )
    .unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(b"RNQCTX1");
    frame.push(1);
    frame.push(1);
    frame.extend_from_slice(&binding.protected_session_id());
    frame.extend_from_slice(&binding.release_tuple_v3_sha256());
    frame.extend_from_slice(&binding.launch_generation().to_be_bytes());
    frame.extend_from_slice(&binding.sequence().to_be_bytes());
    frame.extend_from_slice(&u32::try_from(invalid.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(invalid);
    frame.extend_from_slice(&auth.authenticate(&binding, &content));
    assert!(
        QualificationRunContextRelayCodecV1::from_protected_activation(&keys)
            .decode(&frame, &binding)
            .is_err()
    );
}

#[test]
fn context_digest_changes_authentication_and_outer_recognition_is_only_a_hint() {
    let first = frames(7, 0x33, 4, 9).into_iter().next().unwrap();
    let second = frames(7, 0x44, 4, 9).into_iter().next().unwrap();
    assert_ne!(
        &first[first.len() - MAC_BYTES..],
        &second[second.len() - MAC_BYTES..]
    );
    let mut outer = Vec::new();
    outer.extend_from_slice(&u32::try_from(first.len()).unwrap().to_be_bytes());
    outer.extend_from_slice(&first);
    assert!(QualificationRunContextRelayCodecV1::recognizes_frame(
        &outer
    ));
    outer[4] ^= 1;
    assert!(!QualificationRunContextRelayCodecV1::recognizes_frame(
        &outer
    ));
    assert!(!QualificationRunContextRelayCodecV1::recognizes_frame(
        &first
    ));
}

#[test]
fn ordered_members_cannot_authenticate_or_route_as_each_other() {
    let pair = frames(7, 0x33, 4, 9);
    let keys = keys(7);
    let context_codec = QualificationRunContextRelayCodecV1::from_protected_activation(&keys);
    let fault_codec = QualificationFaultRelayCodecV1::from_protected_activation(&keys);
    assert!(
        context_codec
            .decode(&pair[1], &context_binding(1, 2, 3, 4))
            .is_err()
    );
    assert!(fault_codec.decode(&pair[0], &fault_binding(9)).is_err());

    let mut context_outer = Vec::new();
    context_outer.extend_from_slice(&u32::try_from(pair[0].len()).unwrap().to_be_bytes());
    context_outer.extend_from_slice(&pair[0]);
    let mut fault_outer = Vec::new();
    fault_outer.extend_from_slice(&u32::try_from(pair[1].len()).unwrap().to_be_bytes());
    fault_outer.extend_from_slice(&pair[1]);
    assert!(QualificationRunContextRelayCodecV1::recognizes_frame(
        &context_outer
    ));
    assert!(!QualificationFaultRelayCodecV1::recognizes_frame(
        &context_outer
    ));
    assert!(QualificationFaultRelayCodecV1::recognizes_frame(
        &fault_outer
    ));
    assert!(!QualificationRunContextRelayCodecV1::recognizes_frame(
        &fault_outer
    ));
}
