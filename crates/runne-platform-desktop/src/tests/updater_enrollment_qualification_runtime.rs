use runne_api::{
    DaemonEnrollmentLaunchPreludeV1, ExecutableIdentityV1, LaunchSecret,
    PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, ProtectedCredentialEnrollmentLaunchBindingV1,
    ProtectedCredentialEnrollmentReadyV3, ProtectedReadyV1, ProtectedRuntimeProfileV1,
    ProviderActivationBindingV1, ProviderActivationReadinessV1, StableRuntimeBindingV1,
};

use super::super::{
    NativeEnrollmentQualificationRowV1, VerifiedInstalledEnrollmentMeasurementFacts,
};

fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70;
    value[8] = 0x80;
    value
}

fn owned(
    release: [u8; 32],
    qualification: [u8; 32],
) -> runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3 {
    let profile = ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "fixture",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        ExecutableIdentityV1::new([3; 32], [4; 32], 1).unwrap(),
        profile,
        StableRuntimeBindingV1::new(id(10), "owner", id(11), "fixture", [1; 32], [2; 32])
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
    let keys = LaunchSecret::from_bytes([3; 32]).unwrap().derive_keys();
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        id(1), id(2), [10; 32], [11; 32], [12; 32], [21; 32], [22; 32], 1, 10, 20,
    )
    .unwrap();
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [21; 32],
        release,
        qualification,
        [22; 32],
        1,
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
            .enrollment_launch_commitment(&prelude),
    )
    .unwrap();
    ProtectedCredentialEnrollmentReadyV3::new(
        ready,
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding,
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .unwrap()
    .owned_launch()
}

#[test]
fn exact_v3_revalidated_facts_mint_only_for_the_current_owned_session() {
    let mut target = super::updater_enrollment_macos_identity::target();
    target.native_enrollment_tuple = None;
    let measured = super::updater_enrollment_v3_fixture::macos_tuple_v3(&target, '4');
    let row = NativeEnrollmentQualificationRowV1::new_v3(
        &target,
        &measured,
        "9".repeat(64),
        99,
        200,
    )
    .unwrap();
    target.native_enrollment_tuple_v3 = Some(
        measured
            .clone()
            .with_qualification(&target, row)
            .unwrap(),
    );
    let verified = super::updater_enrollment_macos_identity::verify_target(&target).unwrap();
    let admission = verified.admit_native_enrollment_v3(&measured).unwrap();
    let facts = VerifiedInstalledEnrollmentMeasurementFacts::for_qualification_expectation_test(
        &admission,
    )
    .unwrap();
    let (release, qualification) = facts.qualification_session_binding_for_test();

    assert!(
        facts
            .qualification_runtime_installed_expectation(&owned(release, qualification))
            .is_some()
    );
    assert!(
        facts
            .qualification_runtime_installed_expectation(&owned([31; 32], qualification))
            .is_none()
    );
    assert!(
        facts
            .qualification_runtime_installed_expectation(&owned(release, [32; 32]))
            .is_none()
    );
}

#[test]
fn qualified_v2_facts_cannot_mint_a_runtime_installed_expectation() {
    let target = super::updater_enrollment_qualification::qualified_target(200);
    let verified = super::updater_enrollment_macos_identity::verify_target(&target).unwrap();
    let admission = verified
        .admit_native_enrollment(&super::updater_enrollment_qualification::artifacts(&target))
        .unwrap();
    let facts = VerifiedInstalledEnrollmentMeasurementFacts::for_qualification_expectation_test(
        &admission,
    )
    .unwrap();
    let (release, qualification) = facts.qualification_session_binding_for_test();

    assert!(
        facts
            .qualification_runtime_installed_expectation(&owned(release, qualification))
            .is_none()
    );
}
