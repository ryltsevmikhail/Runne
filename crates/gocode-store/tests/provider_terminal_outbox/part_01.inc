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
