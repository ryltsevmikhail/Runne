
#[test]
fn nonce_reuse_keeps_poll_marker_and_recovery_freezes_before_repoll() {
    let fixture = fixture();
    arm_poll(&fixture, 0).unwrap();
    fixture
        .execution
        .append_encrypted_event(&event(&fixture, 0, 20, false))
        .unwrap();
    arm_poll(&fixture, 1).unwrap();
    assert_eq!(
        fixture
            .execution
            .append_encrypted_event(&event(&fixture, 1, 20, false)),
        Err(ProviderExecutionError::NonceReuse)
    );
    assert_eq!(
        arm_poll(&fixture, 1),
        Err(ProviderExecutionError::AttemptUncertain)
    );
    let connection = fixture.database.connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        6
    );
}

#[test]
fn terminal_commit_atomically_settles_accounting_releases_reservations_and_creates_outbox() {
    let fixture = fixture();
    arm_poll(&fixture, 0).unwrap();
    fixture
        .execution
        .append_encrypted_event(&event(&fixture, 0, 20, false))
        .unwrap();
    arm_poll(&fixture, 1).unwrap();
    fixture
        .execution
        .append_encrypted_event(&event(&fixture, 1, 21, true))
        .unwrap();
    let request = ProviderTerminalCommitRequest::forge_for_tests(
        [30; 16],
        fixture.attempt_id,
        fixture.fencing_token,
        1,
        runne_provider::ProviderCallDigestVersion::V2,
        fixture.key,
        encrypted(31, 71),
        11,
        [2; 32],
        ProviderUsage::new(500, 900, 0, 0).unwrap(),
        40_000,
        "USD".to_owned(),
        [32; 32],
        "conversation-complete-provider-terminal-1".to_owned(),
    );

    assert_eq!(
        fixture.execution.commit_terminal(&request).unwrap(),
        ProviderTerminalCommitOutcome::Committed
    );
    assert_eq!(
        fixture.execution.commit_terminal(&request).unwrap(),
        ProviderTerminalCommitOutcome::Replayed
    );
    let pending = fixture.execution.pending_terminal_outbox().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].outbox_id, [30; 16]);
    assert_eq!(
        pending[0].encrypted_output,
        *request
            .encrypted_output()
            .expect("completed terminal payload"),
    );

    let connection = fixture.database.connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        4
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_budget_reservations WHERE state = 2",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT token_budget_reserved + cost_budget_reserved_micros
                 FROM provider_runtime_authority_state WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT token_budget_settled, cost_budget_settled_micros
                 FROM provider_runtime_authority_state WHERE id = 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap(),
        (1_400, 40_000)
    );

    fixture
        .execution
        .acknowledge_terminal_outbox([30; 16], [33; 32])
        .unwrap();
    assert!(
        fixture
            .execution
            .pending_terminal_outbox()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .dispatch
            .get_dispatch(fixture.attempt_id)
            .unwrap()
            .unwrap()
            .state,
        runne_store::provider::ProviderDispatchState::Settled
    );
}

#[test]
fn terminal_settlement_over_reservation_rolls_back_every_edge() {
    let fixture = fixture();
    arm_poll(&fixture, 0).unwrap();
    fixture
        .execution
        .append_encrypted_event(&event(&fixture, 0, 20, true))
        .unwrap();
    let request = ProviderTerminalCommitRequest::forge_for_tests(
        [30; 16],
        fixture.attempt_id,
        fixture.fencing_token,
        0,
        runne_provider::ProviderCallDigestVersion::V2,
        fixture.key,
        encrypted(31, 71),
        11,
        [2; 32],
        ProviderUsage::new(1_000, 1_000, 0, 0).unwrap(),
        50_001,
        "USD".to_owned(),
        [32; 32],
        "conversation-complete-provider-terminal-1".to_owned(),
    );

    assert_eq!(
        fixture.execution.commit_terminal(&request),
        Err(ProviderExecutionError::ReservationMismatch)
    );
    let connection = fixture.database.connection();
    for table in [
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_budget_reservations WHERE state = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
}

#[test]
fn settled_usage_remains_consumed_for_later_admission() {
    let fixture = fixture();
    arm_poll(&fixture, 0).unwrap();
    fixture
        .execution
        .append_encrypted_event(&event(&fixture, 0, 20, true))
        .unwrap();
    assert_eq!(
        fixture
            .execution
            .commit_terminal(&terminal_request(&fixture))
            .unwrap(),
        ProviderTerminalCommitOutcome::Committed
    );

    let call = ProviderCall::new(
        ProviderCallId::from_bytes([44; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-31",
        )
        .unwrap(),
        [45; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [2; 32],
    };
    fixture.dispatch.persist_prepared(&record).unwrap();

    assert_eq!(
        fixture.execution.issue(&ProviderAuthorityIssueRequest {
            principal_id: "principal-1".to_owned(),
            conversation_id: ConversationId::from_bytes([46; 16]),
            taskrun_id: TaskRunId::from_bytes([47; 16]),
            execution_attempt_id: AttemptId::from_bytes([48; 16]),
            prepared: ContractPreparedProviderRecord {
                call_id: record.call_id,
                call_digest_version: record.call_digest_version,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
            },
            pricing_revision_digest: [3; 32],
            requested_input_tokens: 512,
            requested_output_tokens: 1_024,
            max_cost_micros: 50_000,
            currency: "USD".to_owned(),
            provider_idempotency_key: "provider-terminal-2".to_owned(),
        }),
        Err(ProviderAdmissionError::TokenBudgetDenied)
    );
    assert_eq!(fixture.execution.admitted_count().unwrap(), 1);
}

#[test]
fn stale_runtime_lease_cannot_append_settle_or_mutate_attempt_state() {
    let fixture = fixture();
    fixture.execution.advance_worker_lease(12, 14).unwrap();

    assert_eq!(
        fixture
            .execution
            .append_encrypted_event(&event(&fixture, 0, 20, true)),
        Err(ProviderExecutionError::StaleGeneration)
    );
    assert_eq!(
        fixture
            .execution
            .commit_terminal(&terminal_request(&fixture)),
        Err(ProviderExecutionError::StaleGeneration)
    );
    assert_eq!(
        fixture
            .execution
            .mark_execution_uncertain(fixture.attempt_id, fixture.fencing_token),
        Err(ProviderExecutionError::StaleGeneration)
    );

    let connection = fixture.database.connection();
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        6
    );
}
