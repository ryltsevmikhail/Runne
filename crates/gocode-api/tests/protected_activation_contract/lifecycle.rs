
#[test]
fn v2_readiness_renewal_and_shutdown_bind_provider_to_owned_session() {
    let secret = LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret");
    let keys = secret.derive_keys();
    let request = launch_v2(secret);
    let base_ready = ProtectedReadyV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        executable(),
        profile(),
        stable(),
        INSTANCE_ID,
        7,
        SESSION_ID,
        "https://127.0.0.1:43123",
        [0x31; 32],
        vec![1, 2, 3, 4],
        vec!["conversation-replay-v2".to_owned()],
    )
    .unwrap();
    let mut ready = ProtectedReadyV2::new(base_ready, openai_binding()).unwrap();
    ready.sign(&keys);
    ready
        .verify_exact(&request, &keys)
        .expect("exact V2 readiness");
    assert_eq!(
        ProtectedReadyV2::decode_frame(&ready.encode_frame().unwrap()).unwrap(),
        ready
    );

    let changed_ready_base = ProtectedReadyV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        executable(),
        profile(),
        stable(),
        INSTANCE_ID,
        7,
        SESSION_ID,
        "https://127.0.0.1:43123",
        [0x31; 32],
        vec![1, 2, 3, 4],
        vec!["conversation-replay-v2".to_owned()],
    )
    .unwrap();
    let mut changed_ready =
        ProtectedReadyV2::new(changed_ready_base, deterministic_binding()).unwrap();
    changed_ready.sign(&keys);
    assert_eq!(
        changed_ready.verify_exact(&request, &keys).unwrap_err(),
        LaunchAuthorityError::ProviderModeMismatch
    );

    let owned = ready.owned_launch();
    let mut renewal = ProtectedRenewRequestV2::new(owned.clone(), 1, [0x71; 32]).unwrap();
    renewal.sign(&keys);
    renewal.verify_exact(&owned, 0, &keys).unwrap();
    let mut maximum_renewal =
        ProtectedRenewRequestV2::new(owned.clone(), u64::MAX, [0x73; 32]).unwrap();
    maximum_renewal.sign(&keys);
    maximum_renewal
        .verify_exact(&owned, u64::MAX - 1, &keys)
        .expect("maximum V2 sequence is accepted exactly once");
    assert_eq!(
        maximum_renewal
            .verify_exact(&owned, u64::MAX, &keys)
            .unwrap_err(),
        LaunchAuthorityError::RenewalReplay
    );
    assert_eq!(
        ProtectedRenewRequestV2::decode_frame(&renewal.encode_frame().unwrap()).unwrap(),
        renewal
    );
    let changed_owned = ProtectedOwnedLaunchV2::new(
        owned.compatibility_owned_launch().clone(),
        deterministic_binding(),
    )
    .unwrap();
    assert_eq!(
        renewal.verify_exact(&changed_owned, 0, &keys).unwrap_err(),
        LaunchAuthorityError::ProviderModeMismatch
    );

    let next_session = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 6,
    ];
    let mut ticket =
        ProtectedRenewTicketV2::new(&renewal, next_session, [0x72; 32], 1_000, 31_000).unwrap();
    ticket.sign(&keys);
    ticket.verify_exact(&renewal, &keys).unwrap();
    assert_eq!(
        ProtectedRenewTicketV2::decode_frame(&ticket.encode_frame().unwrap()).unwrap(),
        ticket
    );
    assert_eq!(
        ticket.next_owned_launch().provider_binding(),
        &openai_binding()
    );

    let mut shutdown = ProtectedShutdownV2::new(owned.clone());
    shutdown.sign(&keys);
    shutdown.verify_exact(&owned, &keys).unwrap();
    assert_eq!(
        shutdown.verify_exact(&changed_owned, &keys).unwrap_err(),
        LaunchAuthorityError::ProviderModeMismatch
    );
    assert_eq!(
        ProtectedShutdownV2::decode_frame(&shutdown.encode_frame().unwrap()).unwrap(),
        shutdown
    );
    let mut acknowledgement = ProtectedShutdownAckV2::new(owned, true);
    acknowledgement.sign(&keys);
    acknowledgement
        .verify_exact(shutdown.owned_launch(), &keys)
        .unwrap();
    assert_eq!(
        ProtectedShutdownAckV2::decode_frame(&acknowledgement.encode_frame().unwrap()).unwrap(),
        acknowledgement
    );
}

#[test]
fn v2_codec_rejects_unknown_duplicate_and_truncated_provider_fields() {
    let request = launch_v2(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    let frame = request.encode_frame().unwrap();

    let binding_prefix = [0x03, 0xa3, 0x01, 0x02, 0x02];
    let binding_offset = frame
        .windows(binding_prefix.len())
        .rposition(|window| window == binding_prefix)
        .expect("outer provider binding key");

    let mut duplicate = frame.clone();
    duplicate[binding_offset] = 0x02;
    assert!(ProtectedLaunchRequestV2::decode_frame(&duplicate).is_err());

    let mut unknown_mode = frame.clone();
    unknown_mode[binding_offset + 4] = 0x03;
    assert!(ProtectedLaunchRequestV2::decode_frame(&unknown_mode).is_err());

    let mut truncated = frame;
    truncated.truncate(truncated.len() - 1);
    assert!(ProtectedLaunchRequestV2::decode_frame(&truncated).is_err());
}

#[test]
fn protected_activation_v1_and_v2_digest_goldens_are_stable_and_cross_rejected() {
    let v1 = launch(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"))
        .encode_frame()
        .unwrap();
    let v2 = launch_v2(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"))
        .encode_frame()
        .unwrap();
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/golden/protected-bundled-activation-v1.json"
    ))
    .unwrap();
    let golden_v2: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/golden/protected-bundled-activation-v2.json"
    ))
    .unwrap();

    let v1_digest = hex_digest(Sha256::digest(&v1));
    let v2_digest = hex_digest(Sha256::digest(&v2));
    assert_eq!(golden["frame_length"], v1.len());
    assert_eq!(golden["frame_sha256"], v1_digest);
    assert_eq!(golden_v2["frame_length"], v2.len());
    assert_eq!(golden_v2["frame_sha256"], v2_digest);
    assert!(ProtectedLaunchRequestV1::decode_frame(&v2).is_err());
    assert!(ProtectedLaunchRequestV2::decode_frame(&v1).is_err());
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
