#[test]
fn executable_identity_detects_byte_replacement_without_exposing_the_path() {
    use std::io::Write as _;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runned");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"first executable").unwrap();
    file.sync_all().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let first = ExecutableIdentityV1::measure(&path).expect("first identity");
    std::fs::write(&path, b"replacement executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let replacement = ExecutableIdentityV1::measure(&path).expect("replacement identity");

    assert_ne!(first, replacement);
    assert!(!format!("{first:?}").contains(directory.path().to_str().unwrap()));
}

#[test]
fn first_activation_prepare_and_commit_are_exact_authenticated_frames() {
    let secret = LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret");
    let keys = secret.derive_keys();
    let request = launch_with_disposition(secret, ActivationDispositionV1::FirstActivation);
    let pending = PendingFirstActivationV1::new(
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 7,
        ],
        [0x41; 32],
        stable(),
        executable(),
        profile(),
    )
    .expect("pending");
    let mut prepared = ProtectedFirstActivationPreparedV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        pending.clone(),
    );
    prepared.sign(&keys);
    prepared
        .verify_exact(&request, &keys)
        .expect("prepared proof");
    let prepared_frame = prepared.encode_frame().expect("prepared frame");
    assert_eq!(
        ProtectedFirstActivationPreparedV1::decode_frame(&prepared_frame).unwrap(),
        prepared
    );

    let mut commit = ProtectedFirstActivationCommitV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        pending.clone(),
    );
    commit.sign(&keys);
    commit
        .verify_exact(&request, &pending, &keys)
        .expect("commit proof");
    let commit_frame = commit.encode_frame().expect("commit frame");
    assert_eq!(
        ProtectedFirstActivationCommitV1::decode_frame(&commit_frame).unwrap(),
        commit
    );

    let different = PendingFirstActivationV1::new(
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 8,
        ],
        [0x42; 32],
        stable(),
        executable(),
        profile(),
    )
    .unwrap();
    assert_eq!(
        commit
            .verify_exact(&request, &different, &keys)
            .unwrap_err(),
        LaunchAuthorityError::FirstActivationPreparationMismatch
    );
}

#[test]
fn renewal_and_shutdown_are_bound_to_the_current_owned_launch() {
    let secret = LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret");
    let keys = secret.derive_keys();
    let request = launch(secret);
    let mut ready = ProtectedReadyV1::new(
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
    ready.sign(&keys);
    let owned = ready.owned_launch();

    let mut renewal = ProtectedRenewRequestV1::new(owned.clone(), 1, [0x71; 32]).unwrap();
    renewal.sign(&keys);
    renewal
        .verify_exact(&owned, 0, &keys)
        .expect("first renewal");
    assert_eq!(
        renewal.verify_exact(&owned, 1, &keys).unwrap_err(),
        LaunchAuthorityError::RenewalReplay
    );
    let mut maximum_renewal =
        ProtectedRenewRequestV1::new(owned.clone(), u64::MAX, [0x73; 32]).unwrap();
    maximum_renewal.sign(&keys);
    maximum_renewal
        .verify_exact(&owned, u64::MAX - 1, &keys)
        .expect("maximum sequence is accepted exactly once");
    assert_eq!(
        maximum_renewal
            .verify_exact(&owned, u64::MAX, &keys)
            .unwrap_err(),
        LaunchAuthorityError::RenewalReplay
    );
    assert_eq!(
        ProtectedRenewRequestV1::decode_frame(&renewal.encode_frame().unwrap()).unwrap(),
        renewal
    );

    let next_session = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 6,
    ];
    let mut ticket =
        ProtectedRenewTicketV1::new(&renewal, next_session, [0x72; 32], 1_000, 31_000).unwrap();
    ticket.sign(&keys);
    ticket
        .verify_exact(&renewal, &keys)
        .expect("renewal ticket");
    assert_eq!(
        ProtectedRenewTicketV1::decode_frame(&ticket.encode_frame().unwrap()).unwrap(),
        ticket
    );

    let mut shutdown = ProtectedShutdownV1::new(owned.clone());
    shutdown.sign(&keys);
    shutdown
        .verify_exact(&owned, &keys)
        .expect("owned shutdown");
    assert_eq!(
        ProtectedShutdownV1::decode_frame(&shutdown.encode_frame().unwrap()).unwrap(),
        shutdown
    );
    let mut acknowledgement = ProtectedShutdownAckV1::new(owned, true);
    acknowledgement.sign(&keys);
    acknowledgement
        .verify_exact(shutdown.owned_launch(), &keys)
        .expect("owned shutdown ack");
    assert_eq!(
        ProtectedShutdownAckV1::decode_frame(&acknowledgement.encode_frame().unwrap()).unwrap(),
        acknowledgement
    );
}

#[test]
fn v1_is_deterministic_only_and_openai_requires_v2_binding() {
    let request = launch(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));

    request
        .validate_provider_mode(ProviderActivationModeV1::DeterministicV1)
        .expect("V1 deterministic compatibility");
    assert_eq!(
        request
            .validate_provider_mode(ProviderActivationModeV1::OpenAiResponsesTextV1)
            .unwrap_err(),
        LaunchAuthorityError::MissingProviderBinding
    );
}

#[test]
fn v2_launch_round_trips_exact_provider_binding_and_rejects_mismatch() {
    let request = launch_v2(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    let frame = request.encode_frame().expect("V2 frame");
    assert_eq!(
        ProtectedLaunchRequestV2::decode_frame(&frame).expect("V2 round trip"),
        request
    );
    request
        .validate(
            1_001,
            &LaunchAuthorityValidationV1 {
                principal_id: "local-owner",
                profile: &profile(),
                executable: &executable(),
            },
            &openai_binding(),
        )
        .expect("exact V2 launch binding");

    assert_eq!(
        ProviderActivationBindingV1::new(
            ProviderActivationModeV1::OpenAiResponsesTextV1,
            "runne-openai-responses-text/1",
            runne_api::OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
        )
        .unwrap_err(),
        LaunchAuthorityError::ProviderProfileMismatch
    );
    assert_eq!(
        request
            .validate(
                1_001,
                &LaunchAuthorityValidationV1 {
                    principal_id: "local-owner",
                    profile: &profile(),
                    executable: &executable(),
                },
                &deterministic_binding(),
            )
            .unwrap_err(),
        LaunchAuthorityError::ProviderModeMismatch
    );

    let mut trailing = frame;
    trailing.push(0);
    assert!(ProtectedLaunchRequestV2::decode_frame(&trailing).is_err());
}

#[test]
fn historical_provider_bindings_retain_their_released_gocode_literals() {
    for (mode, profile_id, profile_digest, runne_alias) in [
        (
            ProviderActivationModeV1::DeterministicV1,
            "gocode-deterministic-text/1",
            [
                0xb7, 0x9e, 0xfd, 0x52, 0xcd, 0x0d, 0xe3, 0x29, 0x17, 0x0e, 0xfa, 0xae, 0xd2, 0xa1,
                0x8e, 0x6d, 0x9f, 0xb0, 0xb9, 0xd7, 0x3d, 0x8b, 0x47, 0x40, 0x65, 0x14, 0x45, 0xb4,
                0xe9, 0x0a, 0x95, 0x17,
            ],
            "runne-deterministic-text/1",
        ),
        (
            ProviderActivationModeV1::OpenAiResponsesTextV1,
            "gocode-openai-responses-text/1",
            [
                0xd3, 0xe2, 0x09, 0x34, 0x77, 0x5d, 0x9d, 0x97, 0x03, 0x50, 0xd1, 0x6b, 0x78, 0xa1,
                0x73, 0x98, 0x85, 0xc0, 0x8d, 0xd5, 0xd3, 0xe4, 0x7b, 0x93, 0x07, 0x23, 0x3d, 0x4d,
                0xd0, 0xfb, 0xed, 0x80,
            ],
            "runne-openai-responses-text/1",
        ),
        (
            ProviderActivationModeV1::DeepSeekResponsesTextV1,
            "gocode-deepseek-responses-text/1",
            [
                0x01, 0x12, 0xc4, 0xb6, 0xce, 0x64, 0x73, 0x98, 0x10, 0xbb, 0x79, 0x80, 0x2e, 0xbb, 0x5a, 0xe6, 0xfd, 0x8a, 0xc5, 0x63, 0xd1, 0xd1, 0x39, 0x7a, 0xc5, 0x1f, 0x07, 0xa1, 0x90, 0x53, 0x81, 0x95,
            ],
            "runne-deepseek-responses-text/1",
        ),
    ] {
        let binding = ProviderActivationBindingV1::new(mode, profile_id, profile_digest)
            .expect("source-pinned canonical GOCODE binding");
        assert_eq!(
            (binding.profile_id(), binding.profile_digest()),
            (profile_id, &profile_digest)
        );
        assert_eq!(
            ProviderActivationBindingV1::new(mode, runne_alias, profile_digest).unwrap_err(),
            LaunchAuthorityError::ProviderProfileMismatch
        );
    }
}

#[test]
fn superseded_deepseek_profile_revision_one_digest_fails_closed() {
    let superseded_revision_one_digest = [
        0x25, 0x67, 0x0f, 0xfe, 0x78, 0xdb, 0xc7, 0xef, 0x4d, 0xb8, 0x91, 0x13, 0x56, 0xd9, 0xeb,
        0x4e, 0x27, 0x41, 0x67, 0xff, 0x9e, 0xed, 0x0a, 0x7c, 0xc9, 0xb5, 0xe6, 0x6e, 0x40, 0x85,
        0xd8, 0x53,
    ];
    assert_eq!(
        ProviderActivationBindingV1::new(
            ProviderActivationModeV1::DeepSeekResponsesTextV1,
            "gocode-deepseek-responses-text/1",
            superseded_revision_one_digest,
        )
        .unwrap_err(),
        LaunchAuthorityError::ProviderProfileMismatch
    );
}
