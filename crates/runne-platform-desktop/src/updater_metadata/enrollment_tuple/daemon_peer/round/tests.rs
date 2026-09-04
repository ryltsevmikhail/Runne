use super::*;
use runne_api::{
    ExecutableIdentityV1, PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
    ProtectedCredentialEnrollmentLaunchBindingV1, ProtectedCredentialEnrollmentReadyV3,
    ProtectedReadyV1, ProtectedRuntimeProfileV1, ProviderActivationBindingV1,
    ProviderActivationReadinessV1, StableRuntimeBindingV1,
};

fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70;
    value[8] = 0x80;
    value
}

fn owned(
    admission: &NativeEnrollmentTupleAdmission,
    peer: &MacOsLocalPeerProcessIdentity,
    case: u8,
) -> ProtectedCredentialEnrollmentOwnedLaunchV3 {
    let release = admission.release_tuple_sha256;
    let qualification = admission
        .qualification
        .retained_qualification_binding_digest()
        .unwrap();
    let binding = desktop_peer_digest(
        release,
        admission.desktop_sha256,
        peer.process_start_digest(),
        peer.euid(),
        id(1),
        id(2),
        1,
    );
    let profile = ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "fixture",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let ready = ProtectedReadyV1::new(
        id(if case == 4 { 91 } else { 1 }),
        id(if case == 5 { 92 } else { 2 }),
        ExecutableIdentityV1::new(
            if case == 6 {
                [99; 32]
            } else {
                admission.daemon_sha256
            },
            [5; 32],
            1,
        )
        .unwrap(),
        profile,
        StableRuntimeBindingV1::new(id(10), "local-owner", id(11), "fixture", [1; 32], [2; 32])
            .unwrap(),
        id(12),
        1,
        id(13),
        "https://127.0.0.1",
        [14; 32],
        vec![15],
        vec!["provider.enroll".into()],
    )
    .unwrap();
    let keys = runne_api::LaunchSecret::from_bytes([3; 32])
        .unwrap()
        .derive_keys();
    let prelude = runne_api::DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        id(1),
        id(2),
        [10; 32],
        [11; 32],
        [12; 32],
        [21; 32],
        binding,
        1,
        10,
        20,
    )
    .unwrap();
    let commitment =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
            .enrollment_launch_commitment(&prelude);
    let enrollment = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [21; 32],
        if case == 1 { [99; 32] } else { release },
        if case == 2 { [99; 32] } else { qualification },
        if case == 3 { [99; 32] } else { binding },
        if case == 7 { 2 } else { 1 },
        commitment,
    )
    .unwrap();
    ProtectedCredentialEnrollmentReadyV3::new(
        ready,
        ProviderActivationBindingV1::openai_responses_text_v1(),
        enrollment,
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .unwrap()
    .owned_launch()
}

#[test]
fn v3_round_requires_exact_native_claims_and_unexpired_qualification() {
    let fixture =
        crate::updater_metadata::enrollment_daemon_installed::tests::signed_fixture_admission();
    let (stream, _other) = UnixStream::pair().unwrap();
    let peer = MacOsLocalPeerProcessIdentity::capture(&stream).unwrap();
    let valid = owned(&fixture.admission, &peer, 0);
    assert!(round_claims_match(
        &fixture.admission,
        &peer,
        &valid,
        fixture.expires_at - 1
    ));
    assert!(!round_claims_match(
        &fixture.admission,
        &peer,
        &valid,
        fixture.expires_at
    ));
    for case in 1..=7 {
        let wrong = owned(&fixture.admission, &peer, case);
        assert!(
            !round_claims_match(&fixture.admission, &peer, &wrong, fixture.expires_at - 1),
            "case {case}"
        );
    }
}
