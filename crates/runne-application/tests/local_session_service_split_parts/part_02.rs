#[test]
fn protected_bootstrap_is_consumed_after_one_successful_authentication() {
    let binding = runtime_binding(7, 3);
    let mut service = LocalSessionService::new_protected(
        binding.clone(),
        SECRET,
        Duration::ZERO,
        Duration::from_secs(30),
    )
    .unwrap();
    let challenge = service
        .issue_challenge([2; 32], [1; 32], Duration::ZERO)
        .unwrap();
    service
        .authenticate(
            challenge.id,
            proof(&binding, [1; 32], [2; 32]),
            [3; 32],
            Duration::ZERO,
        )
        .unwrap();

    assert!(matches!(
        service.issue_challenge([5; 32], [4; 32], Duration::ZERO),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn protected_rotation_revokes_old_authority_and_requires_exact_launch_tuple() {
    let binding = runtime_binding(7, 3);
    let mut service = LocalSessionService::new_protected(
        binding.clone(),
        SECRET,
        Duration::ZERO,
        Duration::from_secs(30),
    )
    .unwrap();
    let initial = service
        .issue_challenge([2; 32], [1; 32], Duration::ZERO)
        .unwrap();
    service
        .authenticate(
            initial.id,
            proof(&binding, [1; 32], [2; 32]),
            [3; 32],
            Duration::ZERO,
        )
        .unwrap();
    let next_secret = [0x66; 32];
    let rotated = runtime_binding_with_session(
        7,
        3,
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 6,
        ],
    );
    service
        .rotate_protected_bootstrap(
            rotated.clone(),
            next_secret,
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .expect("same stable launch with new session");
    assert!(matches!(
        service.authorize_wire(&[3; 32], Duration::ZERO),
        Err(LocalSessionError::Unauthorized)
    ));

    let renewal = service
        .issue_challenge([5; 32], [4; 32], Duration::ZERO)
        .unwrap();
    let issued = service
        .authenticate(
            renewal.id,
            proof_with_secret(&rotated, [4; 32], [5; 32], &next_secret),
            [7; 32],
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(issued.binding, rotated);

    assert!(matches!(
        service.rotate_protected_bootstrap(
            runtime_binding(8, 3),
            [8; 32],
            Duration::ZERO,
            Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn protected_bootstrap_deadline_rejects_held_initial_and_renewal_tickets() {
    let binding = runtime_binding(7, 3);
    let mut service = LocalSessionService::new_protected(
        binding.clone(),
        SECRET,
        Duration::from_secs(4),
        Duration::from_secs(34),
    )
    .unwrap();
    assert!(matches!(
        service.issue_challenge([2; 32], [1; 32], Duration::from_secs(35)),
        Err(LocalSessionError::Unauthorized)
    ));

    let mut service = LocalSessionService::new_protected(
        binding,
        SECRET,
        Duration::ZERO,
        Duration::from_secs(30),
    )
    .unwrap();
    let rotated = runtime_binding_with_session(
        7,
        3,
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 6,
        ],
    );
    service
        .rotate_protected_bootstrap(
            rotated,
            [0x66; 32],
            Duration::from_secs(100),
            Duration::from_secs(130),
        )
        .unwrap();
    assert!(matches!(
        service.issue_challenge([4; 32], [3; 32], Duration::from_secs(131)),
        Err(LocalSessionError::Unauthorized)
    ));
}
