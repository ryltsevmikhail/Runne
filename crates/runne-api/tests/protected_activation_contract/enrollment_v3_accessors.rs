#[test]
fn enrollment_v3_exposes_only_semantic_cross_crate_accessors() {
    let request = launch(LaunchSecret::from_bytes([0x41; 32]).unwrap());
    let keys = request.derive_keys();
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        AUTHORITY_ID, HOST_ID, [9; 32], [10; 32], [11; 32], [1; 32], [4; 32], 1, 10, 20,
    )
    .unwrap();
    let commitment = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
        .enrollment_launch_commitment(&prelude);
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        1,
        commitment,
    )
    .unwrap();
    let launch = ProtectedCredentialEnrollmentLaunchRequestV3::new(
        request,
        openai_binding(),
        binding.clone(),
    )
    .unwrap();
    let binding = launch.enrollment_binding();
    let _ = (
        binding.platform(),
        binding.architecture(),
        binding.installation_identity_digest(),
        binding.release_tuple_digest(),
        binding.qualification_binding_digest(),
        binding.desktop_peer_binding_digest(),
        binding.desktop_supervisor_generation(),
        binding.broker_transfer_commitment(),
    );
    let _ = (
        launch.launch_authority_id(),
        launch.desktop_host_instance_id(),
        launch.expires_at_unix_millis(),
        launch.principal_id(),
        launch.profile(),
        launch.executable(),
        launch.runtime_root(),
        launch.activation_disposition(),
        launch.provider_binding(),
        launch.enrollment_binding(),
    );
    let base = ProtectedReadyV1::new(
        AUTHORITY_ID,
        HOST_ID,
        executable(),
        profile(),
        stable(),
        INSTANCE_ID,
        1,
        SESSION_ID,
        "https://127.0.0.1",
        [5; 32],
        vec![6; 32],
        vec!["provider.enroll".to_owned()],
    )
    .unwrap();
    let mut ready = ProtectedCredentialEnrollmentReadyV3::new(
        base,
        openai_binding(),
        binding.clone(),
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .unwrap();
    ready.sign(&launch, &keys).unwrap();
    let _ = (
        ready.provider_binding(),
        ready.enrollment_binding(),
        ready.stable(),
        ready.profile(),
        ready.executable(),
        ready.daemon_instance_id(),
        ready.launch_generation(),
        ready.session_id(),
        ready.endpoint(),
        ready.certificate_sha256(),
        ready.certificate_der(),
        ready.capabilities(),
        ready.provider_readiness(),
    );
    let owned = ready.owned_launch();
    let _ = (
        owned.launch_authority_id(),
        owned.desktop_host_instance_id(),
        owned.daemon_instance_id(),
        owned.launch_generation(),
        owned.executable(),
        owned.profile(),
        owned.stable(),
        owned.provider_binding(),
        owned.enrollment_binding(),
        owned.session_id(),
    );
    let mut renew = ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), 1, [7; 32])
        .unwrap();
    renew.sign(&keys);
    let _ = (renew.owned_launch(), renew.sequence(), renew.nonce());
    let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
        &renew,
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x17,
        ],
        [8; 32],
        100,
        200,
    )
    .unwrap();
    ticket.sign(&keys);
    let verified_ticket = ticket.verify_exact_at(&renew, 100, &keys).unwrap();
    let _ = (
        verified_ticket.next_session_id(),
        verified_ticket.bootstrap_ticket(),
        ticket.issued_at_monotonic_millis(),
        ticket.expires_at_monotonic_millis(),
        verified_ticket.next_owned_launch(),
    );
    let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(owned.clone());
    shutdown.sign(&keys);
    let _ = shutdown.owned_launch();
    let mut ack = ProtectedCredentialEnrollmentShutdownAckV3::new(owned, true);
    ack.sign(&keys);
    let _ = (ack.owned_launch(), ack.graceful());
}
