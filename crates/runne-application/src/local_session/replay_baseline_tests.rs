use runne_api::{ApiPrincipalId, DaemonInstanceId, StableRuntimeBinding};
use runne_domain::{
    event::{Actor, DomainEventDraft, EventEnvelope},
    id::{
        AggregateId, CommandId, EventId, EventLogLineageId, IdempotencyKey, IntegrityDigest,
        TaskRunId,
    },
    replay::ReplayScope,
    task_run::{TaskRun, TaskRunEvent},
    timestamp::Timestamp,
};

const TEST_ID: [u8; 16] = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1];
const TEST_DAEMON: [u8; 16] = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2];
const TEST_SECRET: [u8; 32] = [0x22; 32];
const TEST_AUTHORITY: [u8; 32] = [0x88; 32];

fn test_binding(session_id: [u8; 16]) -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            TEST_ID,
            ApiPrincipalId::new("baseline-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "profile",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(TEST_DAEMON),
        1,
        session_id,
        7,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}

fn scope() -> ReplayScope {
    ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: TEST_ID,
    }
}

fn candidate() -> crate::replay_service::ReplayRetentionBaselineCandidateV1 {
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
        IdempotencyKey::new("baseline-issuer").unwrap(),
        1,
        Actor::new("test").unwrap(),
        Sensitivity::Public,
        draft.payload().clone(),
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([7; 32]),
    );
    let projection =
        runne_api::ReplayAggregateProjectionV1::from_task_run(&TaskRun::replay(&[event]).unwrap())
            .unwrap();
    let projection = runne_api::UnauthenticatedReplayProjectionV1::decode_task_run_bytes(
        projection.encoded_bytes(),
    )
    .unwrap();
    crate::replay_service::ReplayRetentionBaselineCandidateV1 {
        projection,
        sequence: 1,
        version: 1,
        baseline_global_position: 5,
        retained_floor: 6,
        captured_high_water: 6,
        retention_generation: 1,
        retention_witness: [8; 32],
    }
}

fn authenticate_issuer(
    service: &mut LocalSessionService,
    binding: &RuntimeSessionBinding,
) -> AuthenticatedReplayBaselineIssuer {
    let challenge = service
        .issue_challenge([2; 32], [1; 32], Duration::ZERO)
        .unwrap();
    let transcript = bootstrap_proof_transcript(binding, [1; 32], [2; 32]);
    let mut mac = HmacSha256::new_from_slice(&TEST_SECRET).unwrap();
    mac.update(&transcript);
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            TEST_AUTHORITY,
            Duration::ZERO,
        )
        .unwrap();
    service
        .authorize_wire_with_replay_issuer(&TEST_AUTHORITY, Duration::ZERO)
        .unwrap()
        .1
}

#[test]
fn replay_issuer_issues_exact_claims_clamps_ttl_and_rejects_wrong_candidate_or_scope() {
    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    let clone = issuer.clone();
    let wire = issuer
        .issue(scope(), candidate(), Duration::from_secs(1), 1_000, 50_000)
        .unwrap();
    let fields = wire.to_unauthenticated_fields();
    assert_eq!(fields.authority_id, TEST_ID);
    assert_eq!(
        fields.runtime_session_binding_digest,
        binding.canonical_digest()
    );
    assert_eq!(fields.replay_scope_digest, scope().canonical_digest());
    assert_eq!(fields.expires_at_unix_ms, 31_000);
    assert!(
        clone
            .issue(scope(), candidate(), Duration::from_secs(2), 1_000, 2_000)
            .is_ok()
    );
    assert!(matches!(
        clone.issue(
            ReplayScope::Aggregate {
                aggregate_type: 1,
                aggregate_id: [9; 16]
            },
            candidate(),
            Duration::from_secs(2),
            1_000,
            2_000,
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    assert!(matches!(
        clone.issue(
            ReplayScope::Aggregate {
                aggregate_type: 2,
                aggregate_id: TEST_ID
            },
            candidate(),
            Duration::from_secs(2),
            1_000,
            2_000,
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    let mut invalid = candidate();
    invalid.sequence = 0;
    assert!(matches!(
        clone.issue(scope(), invalid, Duration::from_secs(2), 1_000, 2_000),
        Err(LocalSessionError::Unauthorized)
    ));
    let clamped = clone
        .issue(
            scope(),
            candidate(),
            Duration::from_secs(599),
            1_000,
            50_000,
        )
        .unwrap();
    assert_eq!(
        clamped.to_unauthenticated_fields().expires_at_unix_ms,
        2_000
    );
}

#[test]
fn replay_issuer_clone_is_revoked_by_prune_and_epoch_change() {
    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    let saved_issuer = issuer.clone();
    service.prune(Duration::from_secs(600));
    assert!(matches!(
        saved_issuer.issue(scope(), candidate(), Duration::from_secs(600), 1_000, 2_000),
        Err(LocalSessionError::Unauthorized)
    ));

    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    let saved_issuer = issuer.clone();
    service.set_authorization_epoch(8);
    assert!(matches!(
        saved_issuer.issue(scope(), candidate(), Duration::from_secs(1), 1_000, 2_000),
        Err(LocalSessionError::Unauthorized)
    ));

    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    service.set_sensitivity_ceiling(Sensitivity::Public);
    assert!(matches!(
        issuer.issue(scope(), candidate(), Duration::from_secs(1), 1_000, 2_000),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn protected_rotation_revokes_saved_replay_issuer() {
    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new_protected(
        binding.clone(),
        TEST_SECRET,
        Duration::ZERO,
        Duration::from_secs(30),
    )
    .unwrap();
    let issuer = authenticate_issuer(&mut service, &binding);
    let saved_issuer = issuer.clone();
    service
        .rotate_protected_bootstrap(
            test_binding([6; 16]),
            [0x66; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .unwrap();
    assert!(matches!(
        saved_issuer.issue(scope(), candidate(), Duration::from_secs(1), 1_000, 2_000),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn replay_issuer_has_no_public_signing_or_serialization_surface() {
    let source = include_str!("replay_baseline.rs");
    let issuer = include_str!("../local_session.rs");
    assert!(source.contains("pub(crate) fn issue"));
    assert!(!source.contains("pub fn issue"));
    assert!(!source.contains("pub fn replay_baseline_mac"));
    assert!(!issuer.contains("pub authority"));
    assert!(!issuer.contains("Serialize"));
    assert!(!issuer.contains("Deserialize"));
    assert!(!issuer.contains("Debug for AuthenticatedReplayBaselineIssuer"));
}
