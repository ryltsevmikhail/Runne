use runne_api::{
    ActivationDispositionV1, CredentialBrokerTransferAuthenticator,
    DaemonEnrollmentLaunchPreludeV1, ExecutableIdentityV1, LaunchSecret,
    ProtectedCredentialEnrollmentLaunchBindingV1, ProtectedRuntimeProfileV1,
    ProviderActivationReadinessV1, StableRuntimeBindingV1,
};

#[test]
fn v3_ready_profile_retains_exact_enrollment_control_state() {
    let (launch, ready, keys) = v3_fixture(false, 6);
    let profile = ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 1_000, &keys)
        .expect("exact V3 readiness");

    assert_eq!(
        profile.enrollment_owned_launch().expect("V3 control state"),
        &ready.owned_launch()
    );
    assert!(matches!(
        ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 999, &keys),
        Err(runne_api::LaunchAuthorityError::StaleLaunchAuthority)
    ));
}

#[test]
fn v3_renewal_enforces_macos_continuous_time_boundaries_and_advances_owned_state() {
    let (launch, ready, keys) = v3_fixture(false, 6);
    let profile = ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 1_000, &keys)
        .expect("exact V3 readiness");
    drop(profile);
    let (renewal, ticket) = v3_renewal(&ready, &keys);

    assert_eq!(
        ProtectedBundledRuntimeProfile::from_renewal_v3(
            &ready,
            &launch,
            &ready.owned_launch(),
            &renewal,
            &ticket,
            1_999,
            0,
            &keys,
        )
        .expect_err("before the continuous-time issued boundary"),
        runne_api::LaunchAuthorityError::RenewalReplay
    );
    assert_eq!(
        ProtectedBundledRuntimeProfile::from_renewal_v3(
            &ready,
            &launch,
            &ready.owned_launch(),
            &renewal,
            &ticket,
            3_001,
            0,
            &keys,
        )
        .expect_err("after the continuous-time expiry boundary"),
        runne_api::LaunchAuthorityError::RenewalReplay
    );
    assert_eq!(
        ProtectedBundledRuntimeProfile::from_renewal_v3(
            &ready,
            &launch,
            &ready.owned_launch(),
            &renewal,
            &ticket,
            2_000,
            1,
            &keys,
        )
        .expect_err("replayed renewal sequence"),
        runne_api::LaunchAuthorityError::RenewalReplay
    );
    let next = ProtectedBundledRuntimeProfile::from_renewal_v3(
        &ready,
        &launch,
        &ready.owned_launch(),
        &renewal,
        &ticket,
        2_000,
        0,
        &keys,
    )
    .expect("fresh exact ticket after the original profile is consumed");
    assert_eq!(
        next.enrollment_owned_launch()
            .expect("next V3 control state")
            .session_id(),
        ticket.next_session_id()
    );
}

#[test]
fn v3_renewal_rejects_a_substituted_owned_binding() {
    let (launch, ready, keys) = v3_fixture(false, 6);
    let (_, substituted_ready, _) = v3_fixture(false, 22);
    let (renewal, ticket) = v3_renewal(&substituted_ready, &keys);

    assert_eq!(
        ProtectedBundledRuntimeProfile::from_renewal_v3(
            &ready,
            &launch,
            &substituted_ready.owned_launch(),
            &renewal,
            &ticket,
            2_000,
            0,
            &keys,
        )
        .expect_err("substituted enrollment binding"),
        runne_api::LaunchAuthorityError::OwnershipMismatch
    );
}

#[test]
fn v3_ready_profile_rejects_a_signed_certificate_digest_substitution() {
    let (launch, ready, keys) = v3_fixture(true, 6);
    assert!(matches!(
        ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 1_000, &keys),
        Err(runne_api::LaunchAuthorityError::ReadinessProofMismatch)
    ));
}

fn v3_fixture(
    substitute_certificate_digest: bool,
    binding_marker: u8,
) -> (
    ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentReadyV3,
    runne_api::ProtectedActivationKeys,
) {
    let capabilities = crate::PROTECTED_RUNTIME_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect::<Vec<_>>();
    v3_fixture_with_capabilities(substitute_certificate_digest, binding_marker, capabilities)
}

fn v3_fixture_with_capabilities(
    substitute_certificate_digest: bool,
    binding_marker: u8,
    capabilities: Vec<String>,
) -> (
    ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentReadyV3,
    runne_api::ProtectedActivationKeys,
) {
    let profile_hash: [u8; 32] = hex::decode(crate::GOLDEN_BUNDLE_HASH)
        .expect("schema hash")
        .try_into()
        .expect("32 byte schema hash");
    let capability_digest = ordered_capability_digest(&capabilities);
    let profile = ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        crate::EXPECTED_BUNDLE_ID,
        profile_hash,
        capability_digest,
    )
    .expect("protected profile");
    let request = ProtectedLaunchRequestV1::new(
        v3_id(1),
        v3_id(2),
        LaunchSecret::from_bytes([3; 32]).expect("launch secret"),
        1_000,
        31_000,
        "local-owner",
        profile.clone(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 4_096).expect("executable"),
        protected_runtime_root(),
        ActivationDispositionV1::FirstActivation,
    )
    .expect("launch");
    let keys = request.derive_keys();
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        request.launch_authority_id(), request.desktop_host_instance_id(), [10; 32], [11; 32],
        [12; 32], [binding_marker; 32], [binding_marker.wrapping_add(3); 32], 1, 1_000, 31_000,
    )
    .expect("enrollment prelude");
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [binding_marker; 32],
        [binding_marker.wrapping_add(1); 32],
        [binding_marker.wrapping_add(2); 32],
        [binding_marker.wrapping_add(3); 32],
        1,
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
            .enrollment_launch_commitment(&prelude),
    )
    .expect("enrollment binding");
    let launch = ProtectedCredentialEnrollmentLaunchRequestV3::new(
        request.clone(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding.clone(),
    )
    .expect("V3 launch");
    let certificate_der = vec![10, 11, 12, 13];
    let certificate_sha256 = if substitute_certificate_digest {
        [14; 32]
    } else {
        Sha256::digest(&certificate_der).into()
    };
    let ready_v1 = ProtectedReadyV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        request.executable().clone(),
        profile.clone(),
        StableRuntimeBindingV1::new(
            v3_id(15),
            request.principal_id(),
            v3_id(16),
            profile.profile_id(),
            *profile.profile_hash(),
            *profile.capability_digest(),
        )
        .expect("stable binding"),
        v3_id(17),
        7,
        v3_id(18),
        "https://127.0.0.1:43123",
        certificate_sha256,
        certificate_der,
        capabilities,
    )
    .expect("V1 ready");
    let mut ready = ProtectedCredentialEnrollmentReadyV3::new(
        ready_v1,
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding,
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .expect("V3 ready");
    ready.sign(&launch, &keys).expect("V3 ready proof");
    (launch, ready, keys)
}

fn v3_renewal(
    ready: &ProtectedCredentialEnrollmentReadyV3,
    keys: &runne_api::ProtectedActivationKeys,
) -> (
    ProtectedCredentialEnrollmentRenewRequestV3,
    ProtectedCredentialEnrollmentRenewTicketV3,
) {
    let mut renewal =
        ProtectedCredentialEnrollmentRenewRequestV3::new(ready.owned_launch(), 1, [19; 32])
            .expect("renewal");
    renewal.sign(keys);
    let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
        &renewal,
        v3_id(20),
        [21; 32],
        2_000,
        3_000,
    )
    .expect("renewal ticket");
    ticket.sign(keys);
    (renewal, ticket)
}

fn protected_runtime_root() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/private/tmp/runne-protected-runtime")
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(r"C:\runne-protected-runtime")
    }
}

const fn v3_id(last: u8) -> [u8; 16] {
    let mut value = [last; 16];
    value[6] = 0x70 | (last & 0x0f);
    value[8] = 0x80 | (last & 0x3f);
    value
}
