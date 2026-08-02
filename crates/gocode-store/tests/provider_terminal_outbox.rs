use gocode_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderEncryptedPayload,
    ProviderExecutionError, ProviderExecutionStore, ProviderJournalAppendOutcome,
    ProviderJournalAppendRequest, ProviderJournalKeyBinding, ProviderPollRequest,
    ProviderTerminalCommitOutcome,
};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderId, ProviderStreamId, ProviderUsage,
};
use gocode_runtime::provider_execution::{
    ProviderTerminalCommitRequest, ProviderTerminalPersistence,
};
use gocode_store::provider::{
    MarkProviderStreaming, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
    ProviderRuntimeAuthorityConfig, SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
use rusqlite::Connection;
struct Fixture {
    execution: SqliteProviderExecutionStore,
    dispatch: SqliteProviderDispatchStore,
    attempt_id: gocode_provider::DispatchAttemptId,
    fencing_token: u64,
    key: ProviderJournalKeyBinding,
    path: std::path::PathBuf,
}
fn fixture() -> Fixture {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.keep().join("provider-terminal.sqlite");
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-31",
        )
        .unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let prepared_record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [2; 32],
    };
    let dispatch = SqliteProviderDispatchStore::open(&path).unwrap();
    dispatch.persist_prepared(&prepared_record).unwrap();
    let execution = SqliteProviderExecutionStore::open(&path).unwrap();
    execution
        .install_runtime_authority(&ProviderRuntimeAuthorityConfig {
            runtime_authority_id: [1; 16],
            database_generation: 7,
            principal_id: "principal-1".to_owned(),
            owner_id: "runtime-owner-1".to_owned(),
            scope: "provider.dispatch".to_owned(),
            generation: 11,
            fencing_token: 13,
            capability_grant_id: "grant-provider-network-1".to_owned(),
            capability_revision: 2,
            capability_allowed: true,
            capability_revocation_epoch: 1,
            approval_id: "approval-provider-network-1".to_owned(),
            approval_revision: 3,
            approval_allowed: true,
            approval_revocation_epoch: 1,
            profile_digest: [2; 32],
            pricing_revision_digest: [3; 32],
            activation_binding_kind:
                gocode_application::provider::ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 2_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    let ProviderAuthorityIssueOutcome::Winner(admitted) = execution
        .issue(&ProviderAuthorityIssueRequest {
            principal_id: "principal-1".to_owned(),
            conversation_id: ConversationId::from_bytes([6; 16]),
            taskrun_id: TaskRunId::from_bytes([7; 16]),
            execution_attempt_id: AttemptId::from_bytes([8; 16]),
            prepared: ContractPreparedProviderRecord {
                call_id: prepared_record.call_id,
                call_digest_version: prepared_record.call_digest_version,
                prepared_digest: prepared_record.prepared_digest,
                render_digest: prepared_record.render_digest,
                profile_digest: prepared_record.profile_digest,
            },
            pricing_revision_digest: [3; 32],
            requested_input_tokens: 512,
            requested_output_tokens: 1_024,
            max_cost_micros: 50_000,
            currency: "USD".to_owned(),
            provider_idempotency_key: "provider-terminal-1".to_owned(),
        })
        .unwrap()
    else {
        panic!("first issue must win")
    };
    dispatch
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: admitted.claim().attempt_id,
            fencing_token: admitted.claim().fencing_token,
            stream_id: ProviderStreamId::from_bytes([9; 16]),
        })
        .unwrap();
    let key = ProviderJournalKeyBinding::new([10; 16], 1, [1; 16], 7).unwrap();
    execution.activate_journal_key(key).unwrap();
    Fixture {
        execution,
        dispatch,
        attempt_id: admitted.claim().attempt_id,
        fencing_token: admitted.claim().fencing_token,
        key,
        path,
    }
}
fn encrypted(nonce_byte: u8, plaintext_byte: u8) -> ProviderEncryptedPayload {
    ProviderEncryptedPayload::new(
        [nonce_byte; 12],
        vec![plaintext_byte; 32],
        16,
        [plaintext_byte; 32],
    )
    .unwrap()
}
fn event(
    fixture: &Fixture,
    sequence: u64,
    nonce: u8,
    terminal: bool,
) -> ProviderJournalAppendRequest {
    ProviderJournalAppendRequest {
        attempt_id: fixture.attempt_id,
        fencing_token: fixture.fencing_token,
        sequence,
        event_kind: if terminal { 5 } else { 2 },
        terminal,
        call_digest_version: gocode_provider::ProviderCallDigestVersion::V2,
        profile_digest: [2; 32],
        runtime_generation: 11,
        key: fixture.key,
        encrypted: encrypted(nonce, nonce.wrapping_add(40)),
    }
}

fn arm_poll(fixture: &Fixture, cursor: u64) -> Result<(), ProviderExecutionError> {
    fixture.execution.begin_provider_poll(&ProviderPollRequest {
        attempt_id: fixture.attempt_id,
        fencing_token: fixture.fencing_token,
        cursor,
        profile_digest: [2; 32],
        runtime_generation: 11,
    })
}

fn terminal_request(fixture: &Fixture) -> ProviderTerminalCommitRequest {
    ProviderTerminalCommitRequest::forge_for_tests(
        [30; 16],
        fixture.attempt_id,
        fixture.fencing_token,
        0,
        gocode_provider::ProviderCallDigestVersion::V2,
        fixture.key,
        encrypted(31, 71),
        11,
        [2; 32],
        ProviderUsage::new(500, 900, 0, 0).unwrap(),
        40_000,
        "USD".to_owned(),
        [32; 32],
        "conversation-complete-provider-terminal-1".to_owned(),
    )
}

#[derive(Debug, PartialEq, Eq)]
struct TerminalStateSnapshot {
    terminal_nonces: i64,
    accounting: i64,
    outbox: i64,
    live_reservations: i64,
    reserved_tokens: i64,
    settled_tokens: i64,
    reserved_cost_micros: i64,
    settled_cost_micros: i64,
    attempt_state: i64,
    settlement_digest: Option<Vec<u8>>,
}

fn terminal_state_snapshot(fixture: &Fixture) -> TerminalStateSnapshot {
    let connection = Connection::open(&fixture.path).unwrap();
    let (reserved_tokens, settled_tokens, reserved_cost_micros, settled_cost_micros) = connection
        .query_row(
            "SELECT token_budget_reserved, token_budget_settled,
                    cost_budget_reserved_micros, cost_budget_settled_micros
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let (attempt_state, settlement_digest) = connection
        .query_row(
            "SELECT state, settlement_digest FROM provider_dispatch_attempts
             WHERE attempt_id = ?1",
            [fixture.attempt_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    TerminalStateSnapshot {
        terminal_nonces: connection
            .query_row(
                "SELECT COUNT(*) FROM provider_encryption_nonces WHERE purpose = 2",
                [],
                |row| row.get(0),
            )
            .unwrap(),
        accounting: connection
            .query_row(
                "SELECT COUNT(*) FROM provider_accounting_settlements",
                [],
                |row| row.get(0),
            )
            .unwrap(),
        outbox: connection
            .query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |row| {
                row.get(0)
            })
            .unwrap(),
        live_reservations: connection
            .query_row(
                "SELECT COUNT(*) FROM provider_budget_reservations WHERE state = 1",
                [],
                |row| row.get(0),
            )
            .unwrap(),
        reserved_tokens,
        settled_tokens,
        reserved_cost_micros,
        settled_cost_micros,
        attempt_state,
        settlement_digest,
    }
}

#[test]
fn encrypted_journal_is_contiguous_idempotent_and_nonce_unique() {
    let fixture = fixture();
    let first = event(&fixture, 0, 20, false);
    arm_poll(&fixture, 0).unwrap();
    assert_eq!(
        fixture.execution.append_encrypted_event(&first).unwrap(),
        ProviderJournalAppendOutcome::Inserted
    );
    assert_eq!(
        fixture.execution.append_encrypted_event(&first).unwrap(),
        ProviderJournalAppendOutcome::Replayed
    );
    assert_eq!(
        arm_poll(&fixture, 2),
        Err(ProviderExecutionError::SequenceMismatch)
    );
    arm_poll(&fixture, 1).unwrap();
    assert_eq!(
        fixture
            .execution
            .append_encrypted_event(&event(&fixture, 1, 21, true))
            .unwrap(),
        ProviderJournalAppendOutcome::Inserted
    );
    assert_eq!(
        fixture
            .execution
            .load_encrypted_events(fixture.attempt_id)
            .unwrap(),
        vec![first, event(&fixture, 1, 21, true)]
    );
}

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
    let connection = Connection::open(&fixture.path).unwrap();
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
        gocode_provider::ProviderCallDigestVersion::V2,
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

    let connection = Connection::open(&fixture.path).unwrap();
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
        gocode_store::provider::ProviderDispatchState::Settled
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
        gocode_provider::ProviderCallDigestVersion::V2,
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
    let connection = Connection::open(&fixture.path).unwrap();
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

    let connection = Connection::open(&fixture.path).unwrap();
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
fn every_terminal_transaction_write_edge_rolls_back_to_the_streaming_snapshot() {
    let failure_edges = [
        (
            "terminal_nonce",
            "BEFORE INSERT ON provider_encryption_nonces
             WHEN NEW.purpose = 2",
        ),
        (
            "accounting",
            "BEFORE INSERT ON provider_accounting_settlements",
        ),
        ("outbox", "BEFORE INSERT ON provider_terminal_outbox"),
        (
            "reservation_release",
            "BEFORE UPDATE ON provider_budget_reservations
             WHEN OLD.state = 1 AND NEW.state = 2",
        ),
        (
            "authority_budget_release",
            "BEFORE UPDATE ON provider_runtime_authority_state
             WHEN NEW.token_budget_reserved < OLD.token_budget_reserved",
        ),
        (
            "attempt_terminal",
            "BEFORE UPDATE ON provider_dispatch_attempts
             WHEN OLD.state = 3 AND NEW.state = 4",
        ),
    ];

    for (name, trigger_edge) in failure_edges {
        let fixture = fixture();
        arm_poll(&fixture, 0).unwrap();
        fixture
            .execution
            .append_encrypted_event(&event(&fixture, 0, 20, true))
            .unwrap();
        let before = terminal_state_snapshot(&fixture);
        assert_eq!(before.attempt_state, 3);
        assert_eq!(before.live_reservations, 2);

        let connection = Connection::open(&fixture.path).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TRIGGER fail_{name}
                 {trigger_edge}
                 BEGIN SELECT RAISE(ABORT, 'injected terminal failure'); END;"
            ))
            .unwrap();
        drop(connection);

        assert!(
            fixture
                .execution
                .commit_terminal(&terminal_request(&fixture))
                .is_err(),
            "{name} failure must fail closed"
        );
        assert_eq!(
            terminal_state_snapshot(&fixture),
            before,
            "{name} failure left a partial terminal transaction"
        );
    }
}

#[test]
fn retired_key_cannot_be_removed_while_journal_or_outbox_references_it() {
    let fixture = fixture();
    arm_poll(&fixture, 0).unwrap();
    fixture
        .execution
        .append_encrypted_event(&event(&fixture, 0, 20, false))
        .unwrap();
    let replacement = ProviderJournalKeyBinding::new([11; 16], 2, [1; 16], 7).unwrap();
    fixture.execution.activate_journal_key(replacement).unwrap();

    assert_eq!(
        fixture
            .execution
            .journal_key_reference_count(fixture.key)
            .unwrap(),
        1
    );
    assert_eq!(
        fixture.execution.remove_retired_journal_key(fixture.key),
        Err(ProviderExecutionError::JournalKeyUnavailable)
    );
    assert_eq!(
        fixture.execution.remove_retired_journal_key(replacement),
        Err(ProviderExecutionError::JournalKeyUnavailable)
    );
}
