use super::*;
use crate::LaunchSecret;
mod bootstrap_tests;
mod request_tests;
mod terminal_tests;

fn context() -> ProtectedCredentialRecoveryContext {
    ProtectedCredentialRecoveryContext::new(
        [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], 7, 8,
    )
    .unwrap()
}

fn offer() -> ProtectedCredentialRecoveryOffer {
    ProtectedCredentialRecoveryOffer::new(context(), [9; 16], [10; 32], 1, 2, 3, 100, 130).unwrap()
}

fn codec() -> ProtectedCredentialRecoveryCodec {
    ProtectedCredentialRecoveryCodec::new(
        &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
        context(),
    )
}

#[test]
fn recovery_exchange_roundtrip_binds_exact_offer_and_rejects_replay() {
    let (mut daemon, mut desktop) = (codec(), codec());
    let expected = offer();
    let frame = daemon.encode_daemon_offer(&expected, 100).unwrap();
    let received = desktop.decode_daemon_offer(&frame, 100).unwrap();
    assert!(received == expected);
    assert!(desktop.decode_daemon_offer(&frame, 100).is_err());
    let ack = desktop.encode_desktop_accept(&received, 101).unwrap();
    daemon.decode_desktop_accept(&ack, &expected, 101).unwrap();
    assert!(daemon.decode_desktop_accept(&ack, &expected, 101).is_err());
}

#[test]
fn recovery_exchange_rejects_invalid_bindings_and_unbounded_lifetime() {
    for position in 0..8 {
        let mut digests = [[1; 32]; 6];
        let mut generations = [1, 1];
        if position < 6 {
            digests[position] = [0; 32];
        } else {
            generations[position - 6] = 0;
        }
        assert!(
            ProtectedCredentialRecoveryContext::new(
                digests[0],
                digests[1],
                digests[2],
                digests[3],
                digests[4],
                digests[5],
                generations[0],
                generations[1]
            )
            .is_err()
        );
    }
    for (operation, proof, attempt, lifecycle, fence, issued, expires) in [
        ([0; 16], [10; 32], 1, 2, 3, 100, 130),
        ([9; 16], [0; 32], 1, 2, 3, 100, 130),
        ([9; 16], [10; 32], 0, 2, 3, 100, 130),
        ([9; 16], [10; 32], 1, 0, 3, 100, 130),
        ([9; 16], [10; 32], 1, 2, 0, 100, 130),
        ([9; 16], [10; 32], 1, 2, 3, 130, 130),
        ([9; 16], [10; 32], 1, 2, 3, 100, 401),
    ] {
        assert!(
            ProtectedCredentialRecoveryOffer::new(
                context(),
                operation,
                proof,
                attempt,
                lifecycle,
                fence,
                issued,
                expires
            )
            .is_err()
        );
    }
}

#[test]
fn recovery_exchange_rejects_other_host_session_release_and_generations() {
    let frame = codec().encode_daemon_offer(&offer(), 100).unwrap();
    for position in 0..8 {
        let mut c = context();
        match position {
            0 => c.installation = [99; 32],
            1 => c.release = [99; 32],
            2 => c.session = [99; 32],
            3 => c.daemon = [99; 32],
            4 => c.peer = [99; 32],
            5 => c.broker = [99; 32],
            6 => c.database = 99,
            _ => c.supervisor = 99,
        }
        let mut other = ProtectedCredentialRecoveryCodec::new(
            &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
            c,
        );
        assert!(other.decode_daemon_offer(&frame, 100).is_err());
    }
    let mut other_key = ProtectedCredentialRecoveryCodec::new(
        &LaunchSecret::from_bytes([42; 32]).unwrap().derive_keys(),
        context(),
    );
    assert!(other_key.decode_daemon_offer(&frame, 100).is_err());
}

#[test]
fn recovery_exchange_accept_cannot_substitute_operation_attempt_or_lease() {
    let expected = offer();
    let ack = codec().encode_desktop_accept(&expected, 100).unwrap();
    for position in 0..7 {
        let mut substituted = expected.clone();
        match position {
            0 => substituted.operation = [99; 16],
            1 => substituted.continuation = [99; 32],
            2 => substituted.attempt = 99,
            3 => substituted.lifecycle = 99,
            4 => substituted.fence = 99,
            5 => substituted.issued = 99,
            _ => substituted.expires = 129,
        }
        let mut daemon = codec();
        assert!(
            daemon
                .decode_desktop_accept(&ack, &substituted, 100)
                .is_err()
        );
        daemon.decode_desktop_accept(&ack, &expected, 100).unwrap();
    }
}

#[test]
fn recovery_exchange_rejects_wrong_version_direction_lengths_and_tampering() {
    let mut sender = codec();
    let original = sender.encode_daemon_offer(&offer(), 100).unwrap();
    for index in [4, 12, 13] {
        let mut modified = original.clone();
        modified[index] ^= 64;
        // A valid MAC must not authorize another version/direction/magic.
        let end = modified.len() - 32;
        let proof = authenticated_mac(&sender.key, DOMAIN, &modified[4..end]);
        modified[end..].copy_from_slice(&proof);
        assert!(codec().decode_daemon_offer(&modified, 100).is_err());
    }
    for length in 0..original.len() {
        assert!(
            codec()
                .decode_daemon_offer(&original[..length], 100)
                .is_err()
        );
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(codec().decode_daemon_offer(&trailing, 100).is_err());
    for index in 0..original.len() {
        let mut modified = original.clone();
        modified[index] ^= 1;
        assert!(codec().decode_daemon_offer(&modified, 100).is_err());
    }
    assert!(
        codec()
            .decode_desktop_accept(&original, &offer(), 100)
            .is_err()
    );
    let lifecycle = crate::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(
        &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
    );
    assert!(lifecycle.decode_desktop_begin(&original, 0).is_err());
}

#[test]
fn recovery_exchange_expiry_and_sequence_failures_do_not_consume_next_frame() {
    let (mut sender, mut receiver) = (codec(), codec());
    let first = sender.encode_daemon_offer(&offer(), 100).unwrap();
    let second = sender.encode_daemon_offer(&offer(), 100).unwrap();
    assert!(receiver.decode_daemon_offer(&second, 100).is_err());
    assert!(receiver.decode_daemon_offer(&first, 99).is_err());
    assert!(receiver.decode_daemon_offer(&first, 130).is_err());
    receiver.decode_daemon_offer(&first, 100).unwrap();
    receiver.decode_daemon_offer(&second, 100).unwrap();
    assert!(codec().encode_daemon_offer(&offer(), 130).is_err());
    assert!(codec().encode_desktop_accept(&offer(), 99).is_err());
    let ack = codec().encode_desktop_accept(&offer(), 100).unwrap();
    assert!(codec().decode_desktop_accept(&ack, &offer(), 130).is_err());
    sender.sent = u64::MAX;
    assert!(sender.encode_daemon_offer(&offer(), 100).is_err());
    receiver.received = u64::MAX;
    assert!(receiver.decode_daemon_offer(&first, 100).is_err());
}

#[test]
fn recovery_exchange_authenticated_payload_still_requires_valid_operation_and_lease() {
    for (offset, bytes) in [
        (208, vec![0; 16]),
        (224, vec![0; 32]),
        (256, vec![0; 8]),
        (288, 401_u64.to_be_bytes().to_vec()),
    ] {
        let mut sender = codec();
        let mut payload = offer().payload();
        payload[offset..offset + bytes.len()].copy_from_slice(&bytes);
        let signed_invalid = sender.encode(OFFER, &payload).unwrap();
        assert!(codec().decode_daemon_offer(&signed_invalid, 100).is_err());
    }
}
