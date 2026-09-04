use super::*;

#[test]
fn recovery_request_offer_accept_roundtrip_has_independent_direction_sequences() {
    let (mut desktop, mut daemon) = (codec(), codec());
    let request = desktop.encode_desktop_request([9; 16]).unwrap();
    assert_eq!(daemon.decode_desktop_request(&request).unwrap(), [9; 16]);
    assert!(daemon.decode_desktop_request(&request).is_err());
    let frame = daemon.encode_daemon_offer(&offer(), 100).unwrap();
    let received = desktop.decode_daemon_offer(&frame, 100).unwrap();
    let accept = desktop.encode_desktop_accept(&received, 101).unwrap();
    daemon
        .decode_desktop_accept(&accept, &offer(), 101)
        .unwrap();
    assert!(
        daemon
            .decode_desktop_accept(&accept, &offer(), 101)
            .is_err()
    );
    assert!(desktop.encode_desktop_request([10; 16]).is_err());
}

#[test]
fn recovery_request_rejects_offer_for_another_operation_without_consuming_sequence() {
    let (mut desktop, mut daemon) = (codec(), codec());
    let request = desktop.encode_desktop_request([9; 16]).unwrap();
    daemon.decode_desktop_request(&request).unwrap();
    let mut other = offer();
    other.operation = [99; 16];
    assert!(daemon.encode_daemon_offer(&other, 100).is_err());
    let malicious = codec().encode_daemon_offer(&other, 100).unwrap();
    assert!(desktop.decode_daemon_offer(&malicious, 100).is_err());
    let valid = daemon.encode_daemon_offer(&offer(), 100).unwrap();
    assert!(desktop.decode_daemon_offer(&valid, 100).is_ok());
}

#[test]
fn recovery_request_is_bound_to_desktop_known_launch_fields_and_key() {
    let request = codec().encode_desktop_request([9; 16]).unwrap();
    for field in [0, 1, 2, 4, 5, 7] {
        let mut c = context();
        match field {
            0 => c.installation = [99; 32],
            1 => c.release = [99; 32],
            2 => c.session = [99; 32],
            3 => c.daemon = [99; 32],
            4 => c.peer = [99; 32],
            5 => c.broker = [99; 32],
            6 => c.database = 99,
            _ => c.supervisor = 99,
        }
        let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
        let mut receiver = ProtectedCredentialRecoveryCodec::new(&keys, c);
        assert!(
            receiver.decode_desktop_request(&request).is_err(),
            "field {field}"
        );
    }
    let keys = LaunchSecret::from_bytes([42; 32]).unwrap().derive_keys();
    assert!(
        ProtectedCredentialRecoveryCodec::new(&keys, context())
            .decode_desktop_request(&request)
            .is_err()
    );
}

#[test]
fn recovery_request_rejects_tampering_truncation_trailing_bytes_and_other_kinds() {
    let mut sender = codec();
    let frame = sender.encode_desktop_request([9; 16]).unwrap();
    for index in 0..frame.len() {
        let mut altered = frame.clone();
        altered[index] ^= 1;
        assert!(codec().decode_desktop_request(&altered).is_err());
    }
    for length in 0..frame.len() {
        assert!(codec().decode_desktop_request(&frame[..length]).is_err());
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(codec().decode_desktop_request(&trailing).is_err());
    for index in [12, 13] {
        let mut altered = frame.clone();
        altered[index] = 99;
        let end = altered.len() - 32;
        let mac = authenticated_mac(&sender.key, DOMAIN, &altered[4..end]);
        altered[end..].copy_from_slice(&mac);
        assert!(codec().decode_desktop_request(&altered).is_err());
    }
    assert!(codec().decode_daemon_offer(&frame, 100).is_err());
    assert!(
        codec()
            .decode_desktop_accept(&frame, &offer(), 100)
            .is_err()
    );
    let lifecycle = crate::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(
        &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
    );
    assert!(lifecycle.decode_desktop_begin(&frame, 0).is_err());
}

#[test]
fn recovery_request_zero_selector_and_late_request_fail_without_poisoning_state() {
    let mut desktop = codec();
    assert!(desktop.encode_desktop_request([0; 16]).is_err());
    let valid = desktop.encode_desktop_request([9; 16]).unwrap();
    let mut invalid = valid.clone();
    invalid[4 + HEADER + 32..4 + HEADER + 48].fill(0);
    let end = invalid.len() - 32;
    let mac = authenticated_mac(&desktop.key, DOMAIN, &invalid[4..end]);
    invalid[end..].copy_from_slice(&mac);
    let mut daemon = codec();
    assert!(daemon.decode_desktop_request(&invalid).is_err());
    assert_eq!(daemon.decode_desktop_request(&valid).unwrap(), [9; 16]);
    let mut late = codec();
    late.encode_daemon_offer(&offer(), 100).unwrap();
    assert!(late.decode_desktop_request(&valid).is_err());
    assert!(late.encode_desktop_request([9; 16]).is_err());
}
