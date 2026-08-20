pub(crate) fn candidate_v2() -> crate::replay_service::ReplayRetentionBaselineCandidateV2 {
    let task = TaskRunId::from_bytes(TEST_ID);
    let draft = DomainEventDraft::new(
        AggregateId::TaskRun(task),
        AggregateId::TaskRun(task),
        1,
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
    );
    let event = EventEnvelope::from_parts(
        EventId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 4]),
        draft.aggregate_id().clone(),
        draft.correlation_id().clone(),
        None,
        CommandId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 5]),
        IdempotencyKey::new("baseline-issuer-v2").unwrap(),
        1,
        Actor::new("test").unwrap(),
        Sensitivity::Public,
        draft.payload().clone(),
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([7; 32]),
    );
    let bytes = runne_api::ReplayPromotionProjectionV1::encode_task_run(
        &TaskRun::replay(&[event]).unwrap().snapshot_v1(),
    )
    .unwrap();
    crate::replay_service::ReplayRetentionBaselineCandidateV2::from_storage(
        crate::replay_service::ReplayRetentionBaselineCandidateV2Parts {
            promotion_projection_bytes: bytes,
            sequence: 1,
            version: 1,
            baseline_global_position: 5,
            head_event_id: [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 4],
            head_integrity_digest: [7; 32],
            retained_floor: 5,
            captured_high_water: 6,
            retention_generation: 1,
            retention_manifest_digest: [9; 32],
        },
    )
    .unwrap()
}

#[test]
fn replay_issuer_v2_binds_semantic_claims_and_returns_closed_resume_claims() {
    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    let wire = issuer
        .issue_v2(
            scope(),
            candidate_v2(),
            Duration::from_secs(1),
            1_000,
            50_000,
        )
        .unwrap();
    let fields = wire.to_unauthenticated_fields();
    assert_eq!(
        fields.runtime_session_binding_digest,
        binding.canonical_digest()
    );
    assert_eq!(fields.replay_scope_digest, scope().canonical_digest());
    assert_eq!(fields.expires_at_unix_ms, 31_000);
    assert_eq!(
        fields.head_event_id,
        [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 4]
    );
    assert_eq!(fields.retention_manifest_digest, [9; 32]);

    let claims = issuer
        .verify_v2_for_resume(&scope(), &wire, Duration::from_secs(1), 1_500)
        .unwrap();
    assert_eq!(claims.aggregate_id(), TEST_ID);
    assert_eq!(
        claims.aggregate_kind(),
        runne_api::ApiReplayAggregateKind::TaskRun
    );
    assert_eq!(claims.sequence(), 1);
    assert_eq!(claims.version(), 1);
    assert_eq!(claims.baseline_global_position(), 5);
    assert_eq!(claims.head_event_id(), fields.head_event_id);
    assert_eq!(claims.head_integrity_digest(), [7; 32]);
    assert_eq!(claims.retained_floor(), 5);
    assert_eq!(claims.captured_high_water(), 6);
    assert_eq!(claims.retention_generation(), 1);
    assert_eq!(claims.retention_manifest_digest(), [9; 32]);
    assert_eq!(
        claims.promotion_projection_bytes(),
        fields.promotion_projection_bytes
    );
}

#[test]
fn replay_issuer_v2_rejects_wrong_session_scope_or_signing_key() {
    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    let wire = issuer
        .issue_v2(
            scope(),
            candidate_v2(),
            Duration::from_secs(1),
            1_000,
            2_000,
        )
        .unwrap();
    let wrong_scope = ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: [9; 16],
    };
    assert!(matches!(
        issuer.verify_v2_for_resume(&wrong_scope, &wire, Duration::from_secs(1), 1_500),
        Err(LocalSessionError::Unauthorized)
    ));

    let other_binding = test_binding([9; 16]);
    let mut other_service = LocalSessionService::new(other_binding.clone(), TEST_SECRET);
    let other_issuer = authenticate_issuer(&mut other_service, &other_binding);
    assert!(matches!(
        other_issuer.verify_v2_for_resume(&scope(), &wire, Duration::from_secs(1), 1_500),
        Err(LocalSessionError::Unauthorized)
    ));

    let same_binding = test_binding([5; 16]);
    let mut other_service = LocalSessionService::new(same_binding.clone(), TEST_SECRET);
    let challenge = other_service
        .issue_challenge([2; 32], [1; 32], Duration::ZERO)
        .unwrap();
    let transcript = bootstrap_proof_transcript(&same_binding, [1; 32], [2; 32]);
    let mut proof = HmacSha256::new_from_slice(&TEST_SECRET).unwrap();
    proof.update(&transcript);
    let other_authority = [0x99; 32];
    other_service
        .authenticate(
            challenge.id,
            BootstrapProof::new(proof.finalize().into_bytes().into()),
            other_authority,
            Duration::ZERO,
        )
        .unwrap();
    let other_issuer = other_service
        .authorize_wire_with_replay_issuer(&other_authority, Duration::ZERO)
        .unwrap()
        .1;
    assert!(matches!(
        other_issuer.verify_v2_for_resume(&scope(), &wire, Duration::from_secs(1), 1_500),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn replay_issuer_v2_rejects_expiry_revocation_and_sensitivity_downgrade() {
    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    let wire = issuer
        .issue_v2(
            scope(),
            candidate_v2(),
            Duration::from_secs(1),
            1_000,
            2_000,
        )
        .unwrap();
    assert!(matches!(
        issuer.verify_v2_for_resume(&scope(), &wire, Duration::from_secs(1), 2_000),
        Err(LocalSessionError::Unauthorized)
    ));
    assert!(matches!(
        issuer.verify_v2_for_resume(&scope(), &wire, Duration::from_secs(600), 1_500),
        Err(LocalSessionError::Unauthorized)
    ));
    service.set_authorization_epoch(8);
    assert!(matches!(
        issuer.verify_v2_for_resume(&scope(), &wire, Duration::from_secs(1), 1_500),
        Err(LocalSessionError::Unauthorized)
    ));

    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    let wire = issuer
        .issue_v2(
            scope(),
            candidate_v2(),
            Duration::from_secs(1),
            1_000,
            2_000,
        )
        .unwrap();
    service.set_sensitivity_ceiling(Sensitivity::Public);
    assert!(matches!(
        issuer.verify_v2_for_resume(&scope(), &wire, Duration::from_secs(1), 1_500),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn replay_issuer_v2_uses_a_stable_independent_mac_domain() {
    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    let first = issuer
        .issue_v2(
            scope(),
            candidate_v2(),
            Duration::from_secs(1),
            1_000,
            2_000,
        )
        .unwrap();
    let second = issuer
        .issue_v2(
            scope(),
            candidate_v2(),
            Duration::from_secs(1),
            1_000,
            2_000,
        )
        .unwrap();
    let v1 = issuer
        .issue(scope(), candidate(), Duration::from_secs(1), 1_000, 2_000)
        .unwrap();
    assert_eq!(
        first.to_unauthenticated_fields().witness_mac,
        second.to_unauthenticated_fields().witness_mac
    );
    assert_eq!(
        first.to_unauthenticated_fields().witness_mac,
        [
            110, 45, 36, 70, 31, 46, 172, 79, 248, 251, 168, 191, 152, 83, 18, 234, 240, 248, 216,
            43, 122, 223, 104, 139, 220, 26, 170, 31, 104, 56, 240, 29,
        ],
        "independent V2 MAC test vector"
    );
    assert_ne!(
        first.to_unauthenticated_fields().witness_mac,
        v1.to_unauthenticated_fields().witness_mac
    );
    assert_ne!(
        runne_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V1,
        runne_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2
    );
}

#[test]
fn v2_resume_context_has_no_caller_supplied_clock_constructor() {
    let source = include_str!("replay_baseline_v2.rs");
    assert!(source.contains("pub(crate) fn issue_v2"));
    assert!(!source.contains("pub fn issue_v2"));
    assert!(!source.contains("pub fn resume_context"));
    assert!(source.contains("pub fn replay_resume_context_v2"));
}
