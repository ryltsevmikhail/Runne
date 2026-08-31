use super::*;

fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

#[test]
fn enrollment_launch_prelude_round_trips_and_stabilizes_commitment() {
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        id(1),
        id(2),
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        1,
        10,
        20,
    )
    .unwrap();
    let decoded =
        DaemonEnrollmentLaunchPreludeV1::decode_frame(&prelude.encode_frame().unwrap()).unwrap();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys(),
    );
    assert_eq!(prelude, decoded);
    assert_eq!(
        authenticator.enrollment_launch_commitment(&prelude),
        authenticator.enrollment_launch_commitment(&decoded)
    );
}

#[test]
fn enrollment_launch_prelude_commitment_covers_every_security_field() {
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        id(1),
        id(2),
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        1,
        10,
        20,
    )
    .unwrap();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys(),
    );
    let commitment = authenticator.enrollment_launch_commitment(&prelude);
    for changed in [
        {
            let mut value = prelude.clone();
            value.launch_authority_id = id(9);
            value
        },
        {
            let mut value = prelude.clone();
            value.desktop_host_instance_id = id(9);
            value
        },
        {
            let mut value = prelude.clone();
            value.nonce[0] ^= 1;
            value
        },
        {
            let mut value = prelude.clone();
            value.channel_binding[0] ^= 1;
            value
        },
        {
            let mut value = prelude.clone();
            value.publication_key[0] ^= 1;
            value
        },
        {
            let mut value = prelude.clone();
            value.installation_identity_digest[0] ^= 1;
            value
        },
        {
            let mut value = prelude.clone();
            value.desktop_peer_binding_digest[0] ^= 1;
            value
        },
        {
            let mut value = prelude.clone();
            value.supervisor_generation += 1;
            value
        },
        {
            let mut value = prelude.clone();
            value.issued_at_unix_millis += 1;
            value
        },
        {
            let mut value = prelude.clone();
            value.expires_at_unix_millis += 1;
            value
        },
    ] {
        assert_ne!(
            commitment,
            authenticator.enrollment_launch_commitment(&changed)
        );
    }
}

#[test]
fn enrollment_launch_prelude_rejects_invalid_shapes_and_redacts_debug() {
    assert!(
        DaemonEnrollmentLaunchPreludeV1::macos_arm64(
            [0; 16],
            id(2),
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            1,
            10,
            20,
        )
        .is_err()
    );
    assert!(
        DaemonEnrollmentLaunchPreludeV1::macos_arm64(
            id(1),
            id(2),
            [0; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            0,
            10,
            40_011,
        )
        .is_err()
    );
    let value = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        id(1),
        id(2),
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        1,
        10,
        20,
    )
    .unwrap();
    let mut malformed = value.encode_frame().unwrap();
    malformed.push(0);
    assert!(DaemonEnrollmentLaunchPreludeV1::decode_frame(&malformed).is_err());
    let debug = format!("{value:?}");
    assert!(!debug.contains("030303") && !debug.contains("040404"));
}

#[test]
fn enrollment_launch_prelude_freshness_is_closed_at_both_deadline_sides() {
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        id(1),
        id(2),
        [3; 32],
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        1,
        10,
        20,
    )
    .unwrap();
    assert_eq!(
        prelude.validate_freshness(9),
        Err(LaunchAuthorityError::StaleLaunchAuthority)
    );
    assert_eq!(prelude.validate_freshness(10), Ok(()));
    assert_eq!(prelude.validate_freshness(20), Ok(()));
    assert_eq!(
        prelude.validate_freshness(21),
        Err(LaunchAuthorityError::StaleLaunchAuthority)
    );
    assert!(
        DaemonEnrollmentLaunchPreludeV1::macos_arm64(
            id(1),
            id(2),
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            1,
            10,
            40_011,
        )
        .is_err()
    );
}
