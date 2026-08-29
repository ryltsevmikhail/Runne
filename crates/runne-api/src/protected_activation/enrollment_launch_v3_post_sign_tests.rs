use super::*;

fn rejects_ready_mutation(
    ready: ProtectedCredentialEnrollmentReadyV3,
    launch: &ProtectedCredentialEnrollmentLaunchRequestV3,
    keys: &ProtectedActivationKeys,
) {
    assert!(ready.verify_exact(launch, keys).is_err());
}

#[test]
fn enrollment_v3_ready_proof_covers_each_ready_only_field_after_signing() {
    let (launch, ready, keys) = enrollment_launch_v3_tests::fixture();
    let mut request_digest = ready.clone();
    request_digest.request_digest[0] ^= 1;
    rejects_ready_mutation(request_digest, &launch, &keys);
    let mut readiness = ready.clone();
    readiness.readiness = ProviderActivationReadinessV1::Ready;
    rejects_ready_mutation(readiness, &launch, &keys);
    let mut endpoint = ready.clone();
    endpoint.endpoint.push_str("/substituted");
    rejects_ready_mutation(endpoint, &launch, &keys);
    let mut certificate_sha256 = ready.clone();
    certificate_sha256.certificate_sha256[0] ^= 1;
    rejects_ready_mutation(certificate_sha256, &launch, &keys);
    let mut certificate_der = ready.clone();
    certificate_der.certificate_der[0] ^= 1;
    rejects_ready_mutation(certificate_der, &launch, &keys);
    let mut capabilities = ready.clone();
    capabilities.capabilities[0].push_str(".substituted");
    rejects_ready_mutation(capabilities, &launch, &keys);
    let mut authority = ready.clone();
    authority.core.authority_id = enrollment_launch_v3_tests::id(40);
    rejects_ready_mutation(authority, &launch, &keys);
    let mut desktop = ready.clone();
    desktop.core.desktop_id = enrollment_launch_v3_tests::id(41);
    rejects_ready_mutation(desktop, &launch, &keys);
    let mut executable = ready.clone();
    executable.core.executable = ExecutableIdentityV1::new(
        [0x65; 32],
        *executable.core.executable.canonical_path_sha256(),
        executable.core.executable.byte_length(),
    )
    .unwrap();
    rejects_ready_mutation(executable, &launch, &keys);
    let mut profile = ready.clone();
    profile.core.profile = ProtectedRuntimeProfileV1::new(
        profile.core.profile.transport_profile_id(),
        profile.core.profile.runtime_profile_schema_version(),
        profile.core.profile.profile_id(),
        [0x66; 32],
        *profile.core.profile.capability_digest(),
    )
    .unwrap();
    rejects_ready_mutation(profile, &launch, &keys);
    let mut stable = ready.clone();
    stable.core.stable = StableRuntimeBindingV1::new(
        *stable.core.stable.authority_id(),
        stable.core.stable.principal_id(),
        *stable.core.stable.lineage_id(),
        stable.core.stable.profile_id(),
        [0x67; 32],
        *stable.core.stable.capability_digest(),
    )
    .unwrap();
    rejects_ready_mutation(stable, &launch, &keys);
    let mut daemon = ready.clone();
    daemon.core.daemon_id = enrollment_launch_v3_tests::id(42);
    rejects_ready_mutation(daemon, &launch, &keys);
    let mut generation = ready.clone();
    generation.core.generation += 1;
    rejects_ready_mutation(generation, &launch, &keys);
    let mut session = ready.clone();
    session.core.session_id = enrollment_launch_v3_tests::id(43);
    rejects_ready_mutation(session, &launch, &keys);
    let mut provider = ready.clone();
    provider.provider = ProviderActivationBindingV1::deepseek_responses_text_v1();
    rejects_ready_mutation(provider, &launch, &keys);
    let mut enrollment = ready;
    enrollment.enrollment.desktop_peer_binding_digest[0] ^= 1;
    rejects_ready_mutation(enrollment, &launch, &keys);
}

#[test]
fn enrollment_v3_decoders_reject_deterministic_provider_in_every_phase() {
    let (mut launch, mut ready, _) = enrollment_launch_v3_tests::fixture();
    launch.provider = ProviderActivationBindingV1::deterministic_v1();
    assert!(
        ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(&launch.encode_frame().unwrap())
            .is_err()
    );
    ready.provider = ProviderActivationBindingV1::deterministic_v1();
    assert!(
        ProtectedCredentialEnrollmentReadyV3::decode_frame(&ready.encode_frame().unwrap()).is_err()
    );

    let (_, ready, keys, mut renew, mut ticket, owned) = lifecycle_with_ticket();
    renew.owned.provider = ProviderActivationBindingV1::deterministic_v1();
    assert!(
        ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&renew.encode_frame().unwrap())
            .is_err()
    );
    ticket.owned.provider = ProviderActivationBindingV1::deterministic_v1();
    assert!(
        ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(&ticket.encode_frame().unwrap())
            .is_err()
    );
    let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(owned.clone());
    shutdown.sign(&keys);
    shutdown.owned.provider = ProviderActivationBindingV1::deterministic_v1();
    assert!(
        ProtectedCredentialEnrollmentShutdownV3::decode_frame(&shutdown.encode_frame().unwrap())
            .is_err()
    );
    let mut ack = ProtectedCredentialEnrollmentShutdownAckV3::new(ready.owned_launch(), true);
    ack.sign(&keys);
    ack.owned.provider = ProviderActivationBindingV1::deterministic_v1();
    assert!(
        ProtectedCredentialEnrollmentShutdownAckV3::decode_frame(&ack.encode_frame().unwrap())
            .is_err()
    );
}

#[test]
fn enrollment_v3_launch_and_ready_constructors_reject_deterministic_provider() {
    let request = ProtectedLaunchRequestV1::new(
        enrollment_launch_v3_tests::id(45),
        enrollment_launch_v3_tests::id(46),
        LaunchSecret::from_bytes([0x72; 32]).unwrap(),
        10,
        20,
        "principal",
        ProtectedRuntimeProfileV1::new(
            PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
            1,
            "gocode-test/1",
            [1; 32],
            [2; 32],
        )
        .unwrap(),
        ExecutableIdentityV1::new([3; 32], [4; 32], 1).unwrap(),
        PathBuf::from("/tmp/runtime"),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let keys = request.derive_keys();
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [5; 32],
        [6; 32],
        [7; 32],
        [8; 32],
        1,
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
            .enrollment_launch_commitment(request.launch_authority_id()),
    )
    .unwrap();
    assert!(
        ProtectedCredentialEnrollmentLaunchRequestV3::new(
            request.clone(),
            ProviderActivationBindingV1::deterministic_v1(),
            binding.clone(),
        )
        .is_err()
    );
    let stable = StableRuntimeBindingV1::new(
        request.launch_authority_id(),
        "principal",
        enrollment_launch_v3_tests::id(47),
        request.profile().profile_id(),
        *request.profile().profile_hash(),
        *request.profile().capability_digest(),
    )
    .unwrap();
    let ready = ProtectedReadyV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        request.executable().clone(),
        request.profile().clone(),
        stable,
        enrollment_launch_v3_tests::id(48),
        1,
        enrollment_launch_v3_tests::id(49),
        "https://127.0.0.1",
        [9; 32],
        vec![10; 32],
        vec!["provider.enroll".to_owned()],
    )
    .unwrap();
    assert!(
        ProtectedCredentialEnrollmentReadyV3::new(
            ready,
            ProviderActivationBindingV1::deterministic_v1(),
            binding,
            ProviderActivationReadinessV1::CredentialMissing,
        )
        .is_err()
    );
}

fn lifecycle_with_ticket() -> (
    ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentReadyV3,
    ProtectedActivationKeys,
    ProtectedCredentialEnrollmentRenewRequestV3,
    ProtectedCredentialEnrollmentRenewTicketV3,
    ProtectedCredentialEnrollmentOwnedLaunchV3,
) {
    let (launch, ready, keys) = enrollment_launch_v3_tests::fixture();
    let owned = ready.owned_launch();
    let mut renew =
        ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), 1, [0x70; 32]).unwrap();
    renew.sign(&keys);
    let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
        &renew,
        enrollment_launch_v3_tests::id(44),
        [0x71; 32],
        100,
        200,
    )
    .unwrap();
    ticket.sign(&keys);
    (launch, ready, keys, renew, ticket, owned)
}
