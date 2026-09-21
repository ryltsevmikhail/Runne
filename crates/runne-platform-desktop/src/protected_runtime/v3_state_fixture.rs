const fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

fn v3_fixture() -> (
    runne_api::ProtectedCredentialEnrollmentLaunchRequestV3,
    runne_api::ProtectedCredentialEnrollmentReadyV3,
    ProtectedReadyV1,
    ProtectedActivationKeys,
) {
    v3_fixture_with_peer_digest(9)
}

fn v3_fixture_with_peer_digest(
    peer_digest_byte: u8,
) -> (
    runne_api::ProtectedCredentialEnrollmentLaunchRequestV3,
    runne_api::ProtectedCredentialEnrollmentReadyV3,
    ProtectedReadyV1,
    ProtectedActivationKeys,
) {
    let profile = expected_profile().expect("expected protected profile");
    let request = ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        LaunchSecret::from_bytes([3; 32]).expect("launch secret"),
        10,
        20,
        "principal",
        profile.clone(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).expect("executable"),
        std::env::temp_dir().join("runtime"),
        ActivationDispositionV1::FirstActivation,
    )
    .expect("V1 request");
    let keys = request.derive_keys();
    let broker = runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let prelude = runne_api::DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        request.launch_authority_id(), request.desktop_host_instance_id(), [10; 32], [11; 32],
        [12; 32], [6; 32], [peer_digest_byte; 32], 1, 10, 20,
    )
    .expect("enrollment prelude");
    let binding = runne_api::ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [6; 32],
        [7; 32],
        [8; 32],
        [peer_digest_byte; 32],
        1,
        broker.enrollment_launch_commitment(&prelude),
    )
    .expect("enrollment binding");
    let launch = runne_api::ProtectedCredentialEnrollmentLaunchRequestV3::new(
        request.clone(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding.clone(),
    )
    .expect("V3 launch");
    let stable = StableRuntimeBindingV1::new(
        id(10),
        "principal",
        id(11),
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )
    .expect("stable binding");
    let mut v1_ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        request.executable().clone(),
        profile,
        stable,
        id(12),
        1,
        id(13),
        "https://127.0.0.1:43123",
        Sha256::digest([15; 32]).into(),
        vec![15; 32],
        PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
    )
    .expect("V1 ready");
    v1_ready.sign(&keys);
    let mut v3_ready = runne_api::ProtectedCredentialEnrollmentReadyV3::new(
        v1_ready.clone(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding,
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .expect("V3 ready");
    v3_ready.sign(&launch, &keys).expect("sign V3 ready");
    (launch, v3_ready, v1_ready, keys)
}

fn v2_ready(ready: ProtectedReadyV1, keys: &ProtectedActivationKeys) -> ProtectedReadyV2 {
    let mut ready = ProtectedReadyV2::new(
        ready,
        ProviderActivationBindingV1::openai_responses_text_v1(),
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .expect("V2 ready");
    ready.sign(keys);
    ready
}

fn v3_activation() -> (
    ProtectedProcessActivation,
    ProtectedActivationKeys,
    ProtectedReadyV1,
    runne_api::ProtectedCredentialEnrollmentReadyV3,
) {
    let (launch, ready, v1_ready, keys) = v3_fixture();
    let request = DesktopLaunchRequest::V3(launch);
    let decoded = request
        .decode_ready(&ready.encode_frame().expect("V3 ready frame"), &keys)
        .expect("V3 ready");
    let activation = decoded
        .into_process_activation(request)
        .expect("V3 activation");
    (activation, keys, v1_ready, ready)
}

fn v3_activation_with_tickets() -> (
    ProtectedProcessActivation,
    ProtectedActivationKeys,
    ProtectedRenewTicketV1,
    ProtectedRenewTicketV2,
    runne_api::ProtectedCredentialEnrollmentRenewRequestV3,
    runne_api::ProtectedCredentialEnrollmentRenewTicketV3,
) {
    let (activation, keys, v1_ready, v3_ready) = v3_activation();
    let v2_ready = v2_ready(v1_ready.clone(), &keys);
    let mut v1_request =
        ProtectedRenewRequestV1::new(v1_ready.owned_launch(), 1, [16; 32]).expect("V1 renewal");
    v1_request.sign(&keys);
    let mut v1_ticket =
        ProtectedRenewTicketV1::new(&v1_request, id(17), [18; 32], 100, 200).expect("V1 ticket");
    v1_ticket.sign(&keys);
    let mut v2_request =
        ProtectedRenewRequestV2::new(v2_ready.owned_launch(), 1, [19; 32]).expect("V2 renewal");
    v2_request.sign(&keys);
    let mut v2_ticket =
        ProtectedRenewTicketV2::new(&v2_request, id(20), [21; 32], 100, 200).expect("V2 ticket");
    v2_ticket.sign(&keys);
    let owned = v3_ready.owned_launch();
    let mut v3_request =
        runne_api::ProtectedCredentialEnrollmentRenewRequestV3::new(owned, 1, [22; 32])
            .expect("V3 renewal");
    v3_request.sign(&keys);
    let mut v3_ticket = runne_api::ProtectedCredentialEnrollmentRenewTicketV3::new(
        &v3_request,
        id(23),
        [24; 32],
        100,
        200,
    )
    .expect("V3 ticket");
    v3_ticket.sign(&keys);
    (
        activation, keys, v1_ticket, v2_ticket, v3_request, v3_ticket,
    )
}

fn signed_v1_ack(
    owned: ProtectedOwnedLaunchV1,
    keys: &ProtectedActivationKeys,
) -> ProtectedShutdownAckV1 {
    let mut acknowledgement = ProtectedShutdownAckV1::new(owned, true);
    acknowledgement.sign(keys);
    acknowledgement
}

fn signed_v2_ack(
    owned: ProtectedOwnedLaunchV2,
    keys: &ProtectedActivationKeys,
) -> ProtectedShutdownAckV2 {
    let mut acknowledgement = ProtectedShutdownAckV2::new(owned, true);
    acknowledgement.sign(keys);
    acknowledgement
}

fn signed_v3_ack(
    owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    keys: &ProtectedActivationKeys,
) -> runne_api::ProtectedCredentialEnrollmentShutdownAckV3 {
    let mut acknowledgement =
        runne_api::ProtectedCredentialEnrollmentShutdownAckV3::new(owned, true);
    acknowledgement.sign(keys);
    acknowledgement
}

fn substituted_owned() -> runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3 {
    let (_, other_ready, _, _) = v3_fixture_with_peer_digest(25);
    other_ready.owned_launch()
}
