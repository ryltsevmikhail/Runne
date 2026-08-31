#[test]
fn protected_enrollment_generation_rotation_clears_pending_old_challenge() {
    let (mut service, current) = rotation_service();
    let challenge = service.issue_challenge([2; 32], [1; 32], Duration::ZERO).unwrap();
    let next = rotation_binding(5, [9; 16], 7, Sensitivity::Internal, [6; 32]);
    service
        .rotate_protected_enrollment_generation(
            &current,
            next.clone(),
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .unwrap();
    let transcript = bootstrap_proof_transcript(&next, [1; 32], [2; 32]);
    let mut mac = HmacSha256::new_from_slice(&[0x33; 32]).unwrap();
    mac.update(&transcript);
    assert!(matches!(
        service.authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            [0x44; 32],
            Duration::from_secs(1),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn protected_enrollment_generation_rejects_local_policy_before_store_consumption() {
    let current = rotation_binding(4, [5; 16], 7, Sensitivity::Internal, [6; 32]);
    let next = rotation_binding(5, [9; 16], 7, Sensitivity::Internal, [6; 32]);
    let mut external = LocalSessionService::with_reservation_store(
        current.clone(),
        [1; 16],
        [2; 32],
        [0x22; 32],
        Arc::new(UnavailableBootstrapReservationStore),
    );
    assert_local_rotation_rejected(&mut external, &current, next.clone(), [0x33; 32], 30);

    for (secret, expiry) in [([0; 32], 30), ([0x33; 32], 1), ([0x33; 32], 32)] {
        let mut protected = LocalSessionService::new_protected_with_stores(
            current.clone(),
            [1; 16],
            [2; 32],
            [0x22; 32],
            Arc::new(UnavailableBootstrapReservationStore),
            Arc::new(FixedGenerationStore::Panic),
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap();
        assert_local_rotation_rejected(&mut protected, &current, next.clone(), secret, expiry);
    }
}

fn assert_local_rotation_rejected(
    service: &mut LocalSessionService,
    current: &RuntimeSessionBinding,
    next: RuntimeSessionBinding,
    secret: [u8; 32],
    expires_at_seconds: u64,
) {
    assert!(matches!(
        service.rotate_protected_enrollment_generation(
            current,
            next,
            secret,
            Duration::from_secs(1),
            Duration::from_secs(expires_at_seconds),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    assert_eq!(service.current_binding(), current);
}
