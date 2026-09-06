use std::io::Write as _;
use std::os::unix::net::UnixStream;

use runne_api::{QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1};
use runne_native_qualification::{PendingQualificationFault, QualificationFaultRelayCodecV1};

use super::super::super::ProtectedActivationChannel;
use super::read_initial_request;

const TICKET: &[u8] = br#"{"schema_version":"runne/macos-xpc-dpk-fault-ticket/v1","ticket_id":"1111111111111111111111111111111111111111111111111111111111111111","selector":"kill_desktop_process","process_role":"desktop","candidate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_tuple_v3_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","source_revision":"cccccccccccccccccccccccccccccccccccccccc","workflow_run_id":"run-42","namespace_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","issued_at":1800000000,"expires_at":1800000600,"nonce":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","signature":{"algorithm":"ed25519","key_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","value":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw"}}"#;

fn outer(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn relay(
    binding: QualificationFaultRelayBindingV1,
    keys: &runne_api::ProtectedActivationKeys,
) -> Vec<u8> {
    let codec = QualificationFaultRelayCodecV1::from_protected_activation(keys);
    outer(
        &PendingQualificationFault::from_admitted_frame(TICKET.to_vec())
            .unwrap()
            .encode_relay(&codec, &binding)
            .unwrap(),
    )
}

fn exact_binding(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> QualificationFaultRelayBindingV1 {
    QualificationFaultRelayBindingV1::new(
        *owned.session_id(),
        *owned.enrollment_binding().release_tuple_digest(),
        owned.launch_generation(),
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        1,
    )
    .unwrap()
}

#[test]
fn authenticated_present_relay_fails_before_request_admission() {
    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let (mut peer, daemon) = UnixStream::pair().unwrap();
    peer.write_all(&relay(exact_binding(&owned), &keys))
        .unwrap();
    let mut channel = ProtectedActivationChannel::new(daemon).unwrap();
    assert!(read_initial_request(&mut channel, &keys, &owned).is_err());
}

#[test]
fn ordinary_first_request_is_returned_byte_for_byte() {
    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let request = outer(b"GCPCECTLprevious-request");
    let (mut peer, daemon) = UnixStream::pair().unwrap();
    peer.write_all(&request).unwrap();
    let mut channel = ProtectedActivationChannel::new(daemon).unwrap();
    assert_eq!(
        &*read_initial_request(&mut channel, &keys, &owned).unwrap(),
        &request
    );
}

#[test]
fn malformed_mac_and_every_wrong_binding_fail_closed() {
    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let mut bad_mac = relay(exact_binding(&owned), &keys);
    *bad_mac.last_mut().unwrap() ^= 1;
    let mut cases = vec![bad_mac];
    for binding in [
        QualificationFaultRelayBindingV1::new(
            [0x71, 9, 9, 9, 9, 9, 0x71, 9, 0x89, 9, 9, 9, 9, 9, 9, 9],
            *owned.enrollment_binding().release_tuple_digest(),
            owned.launch_generation(),
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            1,
        )
        .unwrap(),
        QualificationFaultRelayBindingV1::new(
            *owned.session_id(),
            [9; 32],
            owned.launch_generation(),
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            1,
        )
        .unwrap(),
        QualificationFaultRelayBindingV1::new(
            *owned.session_id(),
            *owned.enrollment_binding().release_tuple_digest(),
            owned.launch_generation() + 1,
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            1,
        )
        .unwrap(),
        QualificationFaultRelayBindingV1::new(
            *owned.session_id(),
            *owned.enrollment_binding().release_tuple_digest(),
            owned.launch_generation(),
            QualificationFaultRelayDirectionV1::RuntimeToWriter,
            1,
        )
        .unwrap(),
        QualificationFaultRelayBindingV1::new(
            *owned.session_id(),
            *owned.enrollment_binding().release_tuple_digest(),
            owned.launch_generation(),
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            2,
        )
        .unwrap(),
    ] {
        cases.push(relay(binding, &keys));
    }
    for frame in cases {
        let (mut peer, daemon) = UnixStream::pair().unwrap();
        peer.write_all(&frame).unwrap();
        let mut channel = ProtectedActivationChannel::new(daemon).unwrap();
        assert!(read_initial_request(&mut channel, &keys, &owned).is_err());
    }
}

#[test]
fn duplicate_relay_and_dead_channel_never_become_an_initial_request() {
    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let frame = relay(exact_binding(&owned), &keys);
    let (mut peer, daemon) = UnixStream::pair().unwrap();
    peer.write_all(&frame).unwrap();
    peer.write_all(&frame).unwrap();
    let mut channel = ProtectedActivationChannel::new(daemon).unwrap();
    assert!(read_initial_request(&mut channel, &keys, &owned).is_err());
    assert!(read_initial_request(&mut channel, &keys, &owned).is_err());

    let (peer, daemon) = UnixStream::pair().unwrap();
    let mut channel = ProtectedActivationChannel::new(daemon).unwrap();
    drop(peer);
    assert!(read_initial_request(&mut channel, &keys, &owned).is_err());
}
