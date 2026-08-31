const ROTATION_AUTHORITY: [u8; 16] = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 11];
const ROTATION_DAEMON: [u8; 16] = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 12];

fn rotation_binding(
    generation: u64,
    session_id: [u8; 16],
    epoch: u64,
    sensitivity: Sensitivity,
    certificate: [u8; 32],
) -> RuntimeSessionBinding {
    rotation_binding_with(
        ROTATION_AUTHORITY,
        ROTATION_DAEMON,
        generation,
        session_id,
        epoch,
        sensitivity,
        certificate,
    )
}

fn rotation_binding_with(
    authority: [u8; 16],
    daemon: [u8; 16],
    generation: u64,
    session_id: [u8; 16],
    epoch: u64,
    sensitivity: Sensitivity,
    certificate: [u8; 32],
) -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            authority,
            ApiPrincipalId::new("rotation-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000013"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "profile",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(daemon),
        generation,
        session_id,
        epoch,
        sensitivity,
        certificate,
    )
    .unwrap()
}

fn rotation_service() -> (LocalSessionService, RuntimeSessionBinding) {
    rotation_service_with(Ok(()))
}

fn rotation_service_with(
    result: Result<(), EnrollmentLaunchGenerationConsumeError>,
) -> (LocalSessionService, RuntimeSessionBinding) {
    let current = rotation_binding(4, [5; 16], 7, Sensitivity::Internal, [6; 32]);
    (
        LocalSessionService::new_protected_with_stores(
            current.clone(),
            [1; 16],
            [2; 32],
            [0x22; 32],
            Arc::new(UnavailableBootstrapReservationStore),
            Arc::new(FixedGenerationStore::Result(result)),
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap(),
        current,
    )
}

#[test]
fn protected_enrollment_generation_rotation_installs_exact_next_binding_once() {
    let (mut service, current) = rotation_service();
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
    assert_eq!(service.current_binding(), &next);

    let challenge = service
        .issue_challenge([2; 32], [1; 32], Duration::from_secs(1))
        .unwrap();
    let transcript = bootstrap_proof_transcript(&next, [1; 32], [2; 32]);
    let mut mac = HmacSha256::new_from_slice(&[0x33; 32]).unwrap();
    mac.update(&transcript);
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            [0x44; 32],
            Duration::from_secs(1),
        )
        .unwrap();
    assert!(matches!(
        service.issue_challenge([4; 32], [3; 32], Duration::from_secs(1)),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn protected_enrollment_generation_rotation_rejects_substitution_and_preserves_authority() {
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
    let (_, issuer) = service
        .authorize_wire_with_replay_issuer(&[0x44; 32], Duration::ZERO)
        .unwrap();
    let next = rotation_binding(6, [9; 16], 7, Sensitivity::Internal, [6; 32]);
    assert!(matches!(
        service.rotate_protected_enrollment_generation(
            &current,
            next,
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    assert_eq!(service.current_binding(), &current);
    assert!(service.authorize_wire(&[0x44; 32], Duration::from_secs(1)).is_ok());
    assert!(issuer.issue(scope(), candidate(), Duration::from_secs(1), 1_000, 2_000).is_ok());
}

#[test]
fn protected_enrollment_generation_rotation_revokes_prior_authority_and_issuer() {
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
    let (_, issuer) = service
        .authorize_wire_with_replay_issuer(&[0x44; 32], Duration::ZERO)
        .unwrap();
    service
        .rotate_protected_enrollment_generation(
            &current,
            rotation_binding(5, [9; 16], 7, Sensitivity::Internal, [6; 32]),
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .unwrap();
    assert!(matches!(
        service.authorize_wire(&[0x44; 32], Duration::from_secs(1)),
        Err(LocalSessionError::Unauthorized)
    ));
    assert!(matches!(
        issuer.issue(scope(), candidate(), Duration::from_secs(1), 1_000, 2_000),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn protected_enrollment_generation_rotation_rejects_all_generation_and_identity_substitutions() {
    let other_authority = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 21];
    let other_daemon = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 22];
    let cases = [
        rotation_binding(4, [9; 16], 7, Sensitivity::Internal, [6; 32]),
        rotation_binding(3, [9; 16], 7, Sensitivity::Internal, [6; 32]),
        rotation_binding(6, [9; 16], 7, Sensitivity::Internal, [6; 32]),
        rotation_binding_with(other_authority, ROTATION_DAEMON, 5, [9; 16], 7, Sensitivity::Internal, [6; 32]),
        rotation_binding_with(ROTATION_AUTHORITY, other_daemon, 5, [9; 16], 7, Sensitivity::Internal, [6; 32]),
        rotation_binding(5, [9; 16], 8, Sensitivity::Internal, [6; 32]),
        rotation_binding(5, [9; 16], 7, Sensitivity::Public, [6; 32]),
        rotation_binding(5, [9; 16], 7, Sensitivity::Internal, [7; 32]),
        rotation_binding(5, [5; 16], 7, Sensitivity::Internal, [6; 32]),
    ];
    for next in cases {
        let (mut service, current) = rotation_service();
        assert!(matches!(
            service.rotate_protected_enrollment_generation(
                &current,
                next,
                [0x33; 32],
                Duration::from_secs(1),
                Duration::from_secs(30),
            ),
            Err(LocalSessionError::Unauthorized)
        ));
        assert_eq!(service.current_binding(), &current);
    }

    let (mut service, current) = rotation_service();
    assert!(matches!(
        service.rotate_protected_enrollment_generation(
            &rotation_binding(4, [8; 16], 7, Sensitivity::Internal, [6; 32]),
            rotation_binding(5, [9; 16], 7, Sensitivity::Internal, [6; 32]),
            [0x33; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    assert_eq!(service.current_binding(), &current);

    let current = rotation_binding(u64::MAX, [5; 16], 7, Sensitivity::Internal, [6; 32]);
    let mut service = LocalSessionService::new_protected_with_stores(
        current.clone(), [1; 16], [2; 32], [0x22; 32],
        Arc::new(UnavailableBootstrapReservationStore), Arc::new(FixedGenerationStore::Result(Ok(()))),
        Duration::ZERO, Duration::from_secs(30),
    ).unwrap();
    assert!(matches!(
        service.rotate_protected_enrollment_generation(
            &current, current.clone(), [0x33; 32], Duration::from_secs(1), Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    assert_eq!(service.current_binding(), &current);
}

#[test]
fn protected_enrollment_generation_consume_failure_preserves_pending_challenge() {
    let (mut service, current) = rotation_service_with(Err(EnrollmentLaunchGenerationConsumeError::Rejected));
    let challenge = service.issue_challenge([2; 32], [1; 32], Duration::ZERO).unwrap();
    assert!(matches!(
        service.rotate_protected_enrollment_generation(
            &current, rotation_binding(5, [9; 16], 7, Sensitivity::Internal, [6; 32]),
            [0x33; 32], Duration::from_secs(1), Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    let transcript = bootstrap_proof_transcript(&current, [1; 32], [2; 32]);
    let mut mac = HmacSha256::new_from_slice(&[0x22; 32]).unwrap();
    mac.update(&transcript);
    assert!(service.authenticate(challenge.id, BootstrapProof::new(mac.finalize().into_bytes().into()), [0x44; 32], Duration::from_secs(1)).is_ok());

    let (mut unavailable, current) = rotation_service_with(Err(EnrollmentLaunchGenerationConsumeError::Unavailable));
    assert!(matches!(
        unavailable.rotate_protected_enrollment_generation(
            &current, rotation_binding(5, [9; 16], 7, Sensitivity::Internal, [6; 32]),
            [0x33; 32], Duration::from_secs(1), Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unavailable)
    ));
}

#[test]
fn protected_enrollment_generation_rejects_locally_without_consuming() {
    let current = rotation_binding(4, [5; 16], 7, Sensitivity::Internal, [6; 32]);
    let mut service = LocalSessionService::new_protected_with_stores(
        current.clone(), [1; 16], [2; 32], [0x22; 32], Arc::new(UnavailableBootstrapReservationStore),
        Arc::new(FixedGenerationStore::Panic), Duration::ZERO, Duration::from_secs(30),
    ).unwrap();
    assert!(matches!(
        service.rotate_protected_enrollment_generation(
            &current, rotation_binding(4, [9; 16], 7, Sensitivity::Internal, [6; 32]),
            [0x33; 32], Duration::from_secs(1), Duration::from_secs(30),
        ),
        Err(LocalSessionError::Unauthorized)
    ));
}
