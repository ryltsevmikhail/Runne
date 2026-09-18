// Enrollment-transition rotation tests: the only primitive that raises the
// authorization epoch, and the revocation guarantees it must keep.

#[test]
fn enrollment_epoch_rotation_raises_epoch_by_exactly_one_and_revokes_prior_authorities() {
    let (mut service, current) = rotation_service();
    let challenge = service.issue_challenge([2; 32], [1; 32], Duration::ZERO).unwrap();
    let transcript = bootstrap_proof_transcript(&current, [1; 32], [2; 32]);
    let mut mac = HmacSha256::new_from_slice(&[0x22; 32]).unwrap();
    mac.update(&transcript);
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            [0x44; 32],
            Duration::ZERO,
        )
        .unwrap();

    let next = rotation_binding(5, [9; 16], 8, Sensitivity::Internal, [6; 32]);
    service
        .rotate_protected_enrollment_epoch(
            &current,
            next.clone(),
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .unwrap();

    assert_eq!(service.current_binding(), &next);
    let replay = service
        .current_replay_authorization("rotation-owner", 5)
        .unwrap();
    assert_eq!(replay.authorization_epoch, 8);
}

#[test]
fn enrollment_epoch_rotation_rejects_epoch_rewrite_and_epoch_skip() {
    let (mut service, current) = rotation_service();
    // Rewriting the same epoch is the generation-only rotation's job.
    let same_epoch = rotation_binding(5, [9; 16], 7, Sensitivity::Internal, [6; 32]);
    assert!(matches!(
        service.rotate_protected_enrollment_epoch(
            &current,
            same_epoch,
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    // Skipping an epoch (7 → 9) is not an enrollment rotation either.
    let skipped = rotation_binding(5, [9; 16], 9, Sensitivity::Internal, [6; 32]);
    assert!(matches!(
        service.rotate_protected_enrollment_epoch(
            &current,
            skipped,
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn enrollment_epoch_rotation_rejects_substituted_current_binding() {
    let (mut service, _current) = rotation_service();
    let stranger = rotation_binding_with(
        ROTATION_AUTHORITY,
        ROTATION_DAEMON,
        5,
        [9; 16],
        8,
        Sensitivity::Internal,
        [6; 32],
    );
    let next = rotation_binding(5, [9; 16], 8, Sensitivity::Internal, [6; 32]);
    assert!(matches!(
        service.rotate_protected_enrollment_epoch(
            &stranger,
            next,
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn enrollment_epoch_rotation_fail_closed_when_the_store_rejects_the_reservation() {
    let (mut service, current) = rotation_service_with(Err(
        EnrollmentLaunchGenerationConsumeError::Rejected,
    ));
    let next = rotation_binding(5, [9; 16], 8, Sensitivity::Internal, [6; 32]);
    assert!(matches!(
        service.rotate_protected_enrollment_epoch(
            &current,
            next,
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    // A rejected rotation must not leave the raised epoch behind.
    assert_eq!(
        service.current_binding().ephemeral().authorization_epoch(),
        7
    );
}
