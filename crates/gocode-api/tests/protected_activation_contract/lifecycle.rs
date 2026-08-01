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
