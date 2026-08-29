use super::*;

fn fixture() -> (
    ProtectedCredentialEnrollmentPrepareV2,
    ProtectedCredentialEnrollmentPreludeV2,
    ProtectedOwnedLaunchV2,
    ProtectedActivationKeys,
) {
    let (launch, ready, keys) = enrollment_launch_v3_tests::fixture();
    let owned_v1 = ProtectedOwnedLaunchV1::new(
        launch.launch_authority_id(),
        launch.desktop_host_instance_id(),
        ready.executable().clone(),
        ready.profile().clone(),
        ready.stable().clone(),
        *ready.daemon_instance_id(),
        ready.launch_generation(),
        *ready.session_id(),
    )
    .unwrap();
    let owned = ProtectedOwnedLaunchV2::new(owned_v1, launch.provider_binding().clone()).unwrap();
    let mut request = ProtectedCredentialEnrollmentPrepareV2::new(
        owned.clone(),
        1,
        [21; 32],
        [23; 32],
        [24; 32],
        [25; 32],
        1,
    )
    .unwrap();
    request.sign(&keys);
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        *owned.launch_authority_id(),
        *owned.desktop_host_instance_id(),
        [26; 32],
        [27; 32],
        [28; 32],
        [22; 32],
        [25; 32],
        1,
        10,
        20,
    )
    .unwrap();
    let mut response =
        ProtectedCredentialEnrollmentPreludeV2::new(&request, [29; 32], prelude).unwrap();
    response.sign(&keys);
    (request, response, owned, keys)
}

#[test]
fn enrollment_transition_v2_prepare_has_no_desktop_anchor_claim() {
    let (_, _, owned, _) = fixture();
    let request = ProtectedCredentialEnrollmentPrepareV2::new(
        owned, 2, [51; 32], [52; 32], [53; 32], [54; 32], 2,
    )
    .unwrap();
    assert_eq!(request.release_tuple_digest(), &[52; 32]);
}

#[test]
fn enrollment_transition_v2_roundtrips_deterministically_and_exactly() {
    let (request, response, owned, keys) = fixture();
    assert_eq!(
        request.encode_frame().unwrap(),
        request.encode_frame().unwrap()
    );
    assert_eq!(
        response.encode_frame().unwrap(),
        response.encode_frame().unwrap()
    );
    let request =
        ProtectedCredentialEnrollmentPrepareV2::decode_frame(&request.encode_frame().unwrap())
            .unwrap();
    let response =
        ProtectedCredentialEnrollmentPreludeV2::decode_frame(&response.encode_frame().unwrap())
            .unwrap();
    request.verify_exact(&owned, 0, &keys).unwrap();
    response
        .verify_exact_at(&request, &owned, 0, 10, &keys)
        .unwrap();
}

#[test]
fn enrollment_transition_v2_request_rejects_owner_sequence_keys_and_claim_mutation() {
    let (request, _, owned, keys) = fixture();
    let mut wrong_owner = owned.clone();
    wrong_owner.compatibility_owned_launch.session_id = enrollment_launch_v3_tests::id(45);
    assert!(request.verify_exact(&wrong_owner, 0, &keys).is_err());
    assert!(request.verify_exact(&owned, 1, &keys).is_err());
    let other_keys = LaunchSecret::from_bytes([46; 32]).unwrap().derive_keys();
    assert!(request.verify_exact(&owned, 0, &other_keys).is_err());
    for changed in [
        {
            let mut value = request.clone();
            value.owned_launch.compatibility_owned_launch.session_id =
                enrollment_launch_v3_tests::id(44);
            value
        },
        {
            let mut value = request.clone();
            value.nonce[0] ^= 1;
            value
        },
        {
            let mut value = request.clone();
            value.release_tuple_digest[0] ^= 1;
            value
        },
        {
            let mut value = request.clone();
            value.qualification_binding_digest[0] ^= 1;
            value
        },
        {
            let mut value = request.clone();
            value.desktop_peer_binding_digest[0] ^= 1;
            value
        },
        {
            let mut value = request.clone();
            value.desktop_supervisor_generation += 1;
            value
        },
        {
            let mut value = request.clone();
            value.proof[0] ^= 1;
            value
        },
    ] {
        assert!(changed.verify_exact(&owned, 0, &keys).is_err());
    }
    assert!(
        ProtectedCredentialEnrollmentPrepareV2::new(
            owned, 0, [1; 32], [1; 32], [1; 32], [1; 32], 1,
        )
        .is_err()
    );
}

#[test]
fn enrollment_transition_v2_response_rejects_transcript_prelude_and_proof_substitution() {
    let (request, response, owned, keys) = fixture();
    let mut different = request.clone();
    different.release_tuple_digest[0] ^= 1;
    different.sign(&keys);
    assert!(
        response
            .verify_exact_at(&different, &owned, 0, 10, &keys)
            .is_err()
    );
    for changed in [
        {
            let mut value = response.clone();
            value.nonce[0] ^= 1;
            value
        },
        {
            let mut value = response.clone();
            value.sequence += 1;
            value
        },
        {
            let mut value = response.clone();
            value.request_digest[0] ^= 1;
            value
        },
        {
            let mut value = response.clone();
            value.prelude.channel_binding[0] ^= 1;
            value
        },
        {
            let mut value = response.clone();
            value.proof[0] ^= 1;
            value
        },
    ] {
        assert!(
            changed
                .verify_exact_at(&request, &owned, 0, 10, &keys)
                .is_err()
        );
    }
    let foreign = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        enrollment_launch_v3_tests::id(47),
        *owned.desktop_host_instance_id(),
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        [5; 32],
        1,
        10,
        20,
    )
    .unwrap();
    assert!(ProtectedCredentialEnrollmentPreludeV2::new(&request, [1; 32], foreign).is_err());
}

#[test]
fn enrollment_transition_v2_keeps_anchor_daemon_owned_and_rejects_tampering() {
    let (request, response, owned, keys) = fixture();
    assert_eq!(response.prelude().installation_identity_digest(), &[22; 32]);
    for prelude in [
        DaemonEnrollmentLaunchPreludeV1::macos_arm64(
            *owned.launch_authority_id(),
            *owned.desktop_host_instance_id(),
            [35; 32],
            [36; 32],
            [37; 32],
            [34; 32],
            [38; 32],
            request.desktop_supervisor_generation(),
            10,
            20,
        )
        .unwrap(),
        DaemonEnrollmentLaunchPreludeV1::macos_arm64(
            *owned.launch_authority_id(),
            *owned.desktop_host_instance_id(),
            [39; 32],
            [40; 32],
            [41; 32],
            [35; 32],
            *request.desktop_peer_binding_digest(),
            request.desktop_supervisor_generation() + 1,
            10,
            20,
        )
        .unwrap(),
    ] {
        assert!(
            ProtectedCredentialEnrollmentPreludeV2::new(&request, [42; 32], prelude.clone())
                .is_err()
        );
        let mut signed = response.clone();
        signed.prelude = prelude;
        signed.sign(&keys);
        assert!(
            signed
                .verify_exact_at(&request, &owned, 0, 10, &keys)
                .is_err()
        );
    }
    let mut anchor_mutation = response.clone();
    anchor_mutation.prelude.installation_identity_digest[0] ^= 1;
    assert!(
        anchor_mutation
            .verify_exact_at(&request, &owned, 0, 10, &keys)
            .is_err()
    );
    assert!(
        response
            .verify_exact_at(&request, &owned, 0, 21, &keys)
            .is_err()
    );
}

#[test]
fn enrollment_transition_v2_cross_rejects_versions_and_redacts_debug() {
    let (request, response, _, _) = fixture();
    let request_frame = request.encode_frame().unwrap();
    let response_frame = response.encode_frame().unwrap();
    assert!(ProtectedRenewRequestV2::decode_frame(&request_frame).is_err());
    assert!(ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(&request_frame).is_err());
    assert!(ProtectedRenewTicketV2::decode_frame(&response_frame).is_err());
    assert!(ProtectedCredentialEnrollmentReadyV3::decode_frame(&response_frame).is_err());
    let request_debug = format!("{request:?}");
    let response_debug = format!("{response:?}");
    assert!(!request_debug.contains("22") && !response_debug.contains("26"));
    assert!(request_debug.contains("<redacted>") && response_debug.contains("<redacted>"));
}
