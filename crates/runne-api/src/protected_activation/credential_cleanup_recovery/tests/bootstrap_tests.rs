use super::*;

#[test]
fn desktop_bootstrap_from_owned_launch_needs_no_database_measurement() {
    let (_, ready, keys) = crate::protected_activation::enrollment_launch_v3_tests::fixture();
    let owned = ready.owned_launch();
    let known = ProtectedCredentialRecoveryBootstrap::from_owned_launch(&owned, [21; 32], [22; 32])
        .unwrap();
    let mut desktop = ProtectedCredentialRecoveryCodec::for_desktop(&keys, known).unwrap();
    // Golden for this fixture's launch authority/session/daemon/generation.
    let session = [
        38, 210, 173, 112, 66, 126, 129, 53, 141, 241, 84, 92, 63, 72, 145, 13, 51, 120, 189, 159,
        207, 120, 213, 214, 23, 125, 211, 44, 110, 105, 134, 224,
    ];
    let context = ProtectedCredentialRecoveryContext::new(
        [6; 32],
        [7; 32],
        session,
        [31; 32],
        [9; 32],
        crate::protected_credential_broker_evidence_binding([7; 32], [21; 32], [22; 32]),
        77,
        1,
    )
    .unwrap();
    let mut daemon = ProtectedCredentialRecoveryCodec::new(&keys, context.clone());
    let request = desktop.encode_desktop_request([9; 16]).unwrap();
    assert_eq!(daemon.decode_desktop_request(&request).unwrap(), [9; 16]);
    let offer =
        ProtectedCredentialRecoveryOffer::new(context, [9; 16], [10; 32], 1, 2, 3, 100, 130)
            .unwrap();
    let frame = daemon.encode_daemon_offer(&offer, 100).unwrap();
    let received = desktop.decode_daemon_offer(&frame, 100).unwrap();
    let ack = desktop.encode_desktop_accept(&received, 101).unwrap();
    daemon.decode_desktop_accept(&ack, &offer, 101).unwrap();
    for (channel, key) in [([0; 32], [22; 32]), ([21; 32], [0; 32])] {
        assert!(
            ProtectedCredentialRecoveryBootstrap::from_owned_launch(&owned, channel, key).is_err()
        );
    }
}

fn desktop() -> ProtectedCredentialRecoveryCodec {
    let known =
        ProtectedCredentialRecoveryBootstrap::new([1; 32], [2; 32], [3; 32], [5; 32], [6; 32], 8)
            .unwrap();
    ProtectedCredentialRecoveryCodec::for_desktop(
        &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
        known,
    )
    .unwrap()
}

#[test]
fn desktop_bootstrap_learns_daemon_context_only_from_authenticated_offer() {
    let mut desktop = desktop();
    let mut daemon = codec();
    assert!(desktop.encode_desktop_accept(&offer(), 101).is_err());
    assert!(desktop.encode_daemon_offer(&offer(), 101).is_err());
    let request = desktop.encode_desktop_request([9; 16]).unwrap();
    assert_eq!(daemon.decode_desktop_request(&request).unwrap(), [9; 16]);
    let frame = daemon.encode_daemon_offer(&offer(), 100).unwrap();
    let received = desktop.decode_daemon_offer(&frame, 100).unwrap();
    assert!(received == offer());
    let ack = desktop.encode_desktop_accept(&received, 101).unwrap();
    daemon.decode_desktop_accept(&ack, &offer(), 101).unwrap();
    let mut altered = received.clone();
    altered.context.database = 99;
    assert!(desktop.encode_desktop_accept(&altered, 101).is_err());
}

#[test]
fn desktop_bootstrap_rejects_wrong_known_facts_and_keeps_valid_offer_available() {
    for field in 0..6 {
        let mut desktop = desktop();
        desktop.encode_desktop_request([9; 16]).unwrap();
        let mut bad = offer();
        match field {
            0 => bad.context.installation = [99; 32],
            1 => bad.context.release = [99; 32],
            2 => bad.context.session = [99; 32],
            3 => bad.context.peer = [99; 32],
            4 => bad.context.broker = [99; 32],
            _ => bad.context.supervisor = 99,
        }
        let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
        let frame = ProtectedCredentialRecoveryCodec::new(&keys, bad.context.clone())
            .encode_daemon_offer(&bad, 100)
            .unwrap();
        assert!(desktop.decode_daemon_offer(&frame, 100).is_err());
        assert!(
            desktop
                .decode_daemon_offer(&codec().encode_daemon_offer(&offer(), 100).unwrap(), 100)
                .is_ok()
        );
    }
}

#[test]
fn desktop_bootstrap_does_not_pin_unauthenticated_expired_or_unsolicited_offer() {
    let valid = codec().encode_daemon_offer(&offer(), 100).unwrap();
    let mut client = desktop();
    assert!(client.decode_daemon_offer(&valid, 100).is_err());
    client.encode_desktop_request([9; 16]).unwrap();
    let mut tampered = valid.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(client.decode_daemon_offer(&tampered, 100).is_err());
    assert!(client.decode_daemon_offer(&valid, 130).is_err());
    let mut wrong = offer();
    wrong.operation = [99; 16];
    let wrong = codec().encode_daemon_offer(&wrong, 100).unwrap();
    assert!(client.decode_daemon_offer(&wrong, 100).is_err());
    let pinned = client.decode_daemon_offer(&valid, 100).unwrap();
    for field in 0..2 {
        let mut changed = pinned.clone();
        if field == 0 {
            changed.context.database = 99;
        } else {
            changed.context.daemon = [99; 32];
        }
        assert!(client.encode_desktop_accept(&changed, 101).is_err());
    }
    assert!(client.encode_desktop_accept(&pinned, 101).is_ok());
}
