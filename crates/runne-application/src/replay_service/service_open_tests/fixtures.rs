fn gap_candidate() -> ReplayRetentionBaselineCandidateV1 {
    let taskrun_id =
        TaskRunId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1]);
    let draft = DomainEventDraft::new(
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        1,
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
    );
    let event = EventEnvelope::from_parts(
        EventId::from_bytes([1; 16]),
        draft.aggregate_id().clone(),
        draft.correlation_id().clone(),
        None,
        CommandId::from_bytes([2; 16]),
        IdempotencyKey::new("gap-test").unwrap(),
        1,
        Actor::new("test").unwrap(),
        Sensitivity::Public,
        draft.payload().clone(),
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([3; 32]),
    );
    let taskrun = TaskRun::replay(&[event]).unwrap();
    let projection = runne_api::ReplayAggregateProjectionV1::from_task_run(&taskrun).unwrap();
    let projection = runne_api::UnauthenticatedReplayProjectionV1::decode_task_run_bytes(
        projection.encoded_bytes(),
    )
    .unwrap();
    ReplayRetentionBaselineCandidateV1 {
        projection,
        sequence: 1,
        version: 1,
        baseline_global_position: 1,
        retained_floor: 2,
        captured_high_water: 2,
        retention_generation: 1,
        retention_witness: [8; 32],
    }
}

fn baseline_issuer() -> (
    crate::local_session::LocalSessionService,
    crate::local_session::AuthenticatedReplayBaselineIssuer,
) {
    let id = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2];
    let binding = RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            id,
            ApiPrincipalId::new("owner").unwrap(),
            EventLogLineageId::from_bytes([
                1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 3,
            ]),
            "profile",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 4]),
        1,
        [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 5],
        0,
        Sensitivity::Sensitive,
        [7; 32],
    )
    .unwrap();
    let mut sessions = crate::local_session::LocalSessionService::new(binding.clone(), [9; 32]);
    let challenge = sessions
        .issue_challenge([10; 32], [11; 32], std::time::Duration::ZERO)
        .unwrap();
    let mut mac = HmacSha256::new_from_slice(&[9; 32]).unwrap();
    mac.update(&crate::local_session::bootstrap_proof_transcript(
        &binding, [11; 32], [10; 32],
    ));
    sessions
        .authenticate(
            challenge.id,
            crate::local_session::BootstrapProof::new(mac.finalize().into_bytes().into()),
            [12; 32],
            std::time::Duration::ZERO,
        )
        .unwrap();
    let issuer = sessions
        .authorize_wire_with_replay_issuer(&[12; 32], std::time::Duration::ZERO)
        .unwrap()
        .1;
    (sessions, issuer)
}

fn invalid_v2_wire() -> ReplayRetentionBaselineWireV2 {
    ReplayRetentionBaselineWireV2::from_unauthenticated_fields(
        UnauthenticatedReplayRetentionBaselineFieldsV2 {
            schema_version: 2,
            authority_id: [0; 16],
            principal_id: "owner".to_owned(),
            lineage_id: [0; 16],
            runtime_session_binding_digest: [0; 32],
            replay_scope_digest: [0; 32],
            aggregate_kind: runne_api::ApiReplayAggregateKind::TaskRun,
            aggregate_id: [0; 16],
            sequence: 1,
            version: 1,
            baseline_global_position: 1,
            head_event_id: [0; 16],
            head_integrity_digest: [1; 32],
            promotion_codec: 1,
            promotion_projection_bytes: vec![0],
            promotion_projection_digest: [0; 32],
            retained_floor: 1,
            captured_high_water: 1,
            retention_generation: 1,
            retention_manifest_digest: [1; 32],
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 2,
            witness_mac: [0; 32],
        },
    )
}

fn scope() -> ReplayScope {
    ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: [0; 16],
    }
}

fn v2_scope() -> ReplayScope {
    ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
    }
}
