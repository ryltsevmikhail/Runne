use std::sync::{Arc, Barrier};

use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{
    DispatchAttemptId, ProviderCallDigestVersion, ProviderCallId, ProviderDispatchRepository,
    ProviderId, ProviderPreEffectRejection, ProviderStreamId,
};
use runne_store::provider::{
    MarkProviderStreaming, PersistPreparedOutcome, PreparedProviderRecord,
    ProviderAuthorityIssueOutcome, ProviderDispatchClaim, ProviderDispatchState,
    ProviderStoreError, SettleProviderDispatch,
};
fn prepared(call_byte: u8) -> PreparedProviderRecord {
    PreparedProviderRecord {
        call_id: ProviderCallId::from_bytes([call_byte; 16]),
        call_digest_version: ProviderCallDigestVersion::V2,
        prepared_digest: [2; 32],
        render_digest: [3; 32],
        profile_digest: [4; 32],
    }
}
fn legacy_claim(call_byte: u8) -> ProviderDispatchClaim {
    ProviderDispatchClaim {
        call_id: ProviderCallId::from_bytes([call_byte; 16]),
        attempt_id: DispatchAttemptId::from_bytes([5; 16]),
        permit_id: [6; 16],
        prepared_digest: [2; 32],
        render_digest: [3; 32],
        profile_digest: [4; 32],
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        fencing_token: 9,
        provider_idempotency_key: "provider-attempt-5".to_owned(),
    }
}
fn issue_dispatch(
    database: &validated_reopen::ProviderTestDatabase,
    call_byte: u8,
) -> runne_provider::ProviderDispatchClaim {
    let record = prepared(call_byte);
    let execution = database.execution();
    let launch = execution
        .activate_runtime_launch(&fixture::config())
        .unwrap();
    crate::online_proof::arm(&execution, 1);
    let ProviderAuthorityIssueOutcome::Winner(admitted) = execution
        .issue(&launch, &ProviderAuthorityIssueRequest {
            provider_id: ProviderId::new("fixture-provider").unwrap(),
            principal_id: "provider-dispatch-test-principal".to_owned(),
            conversation_id: ConversationId::from_bytes([call_byte.wrapping_add(30); 16]),
            taskrun_id: TaskRunId::from_bytes([call_byte.wrapping_add(40); 16]),
            execution_attempt_id: AttemptId::from_bytes([call_byte.wrapping_add(50); 16]),
            prepared: runne_provider::PreparedProviderRecord {
                call_id: record.call_id,
                call_digest_version: record.call_digest_version,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
            },
            pricing_revision_digest: [22; 32],
            requested_input_tokens: 1,
            requested_output_tokens: 1,
            max_cost_micros: 1,
            currency: "USD".to_owned(),
            provider_idempotency_key: format!("provider-dispatch-test-{call_byte}"),
        })
        .unwrap()
    else {
        panic!("fresh runtime issuance must win")
    };
    (*admitted).into_claim()
}

#[test]
fn persist_prepared_exact_replay_is_idempotent_and_changed_digest_conflicts() {
    let (_database, store, launch) = fresh_store("persist-replay");
    let record = prepared(1);

    assert_eq!(
        store.persist_prepared(&launch, &record).unwrap(),
        PersistPreparedOutcome::Inserted
    );
    assert_eq!(
        store.persist_prepared(&launch, &record).unwrap(),
        PersistPreparedOutcome::Replayed
    );

    let mut changed = record;
    changed.render_digest = [99; 32];
    assert_eq!(
        store.persist_prepared(&launch, &changed),
        Err(ProviderStoreError::PreparedConflict)
    );
    assert_eq!(store.get_prepared(record.call_id).unwrap(), Some(record));
}

#[test]
fn prepared_outer_digest_domains_are_versioned_and_mismatch_fails_closed() {
    let (database, store, launch) = fresh_store("prepared-domains");
    let mut v1 = prepared(1);
    v1.call_digest_version = ProviderCallDigestVersion::V1;
    let v2 = prepared(2);
    store.persist_prepared(&launch, &v1).unwrap();
    store.persist_prepared(&launch, &v2).unwrap();

    let connection = database.connection();
    for (call_id, expected_hex) in [
        (
            [1_u8; 16],
            "046077617ad82d9417faaa8f6d25a876417bf9845fb8edb73f531f257d533263",
        ),
        (
            [2_u8; 16],
            "4edd716486d16988d0326fe7930c3d2977123a6a00ce02a41a56fff128e296b2",
        ),
    ] {
        let digest: Vec<u8> = connection
            .query_row(
                "SELECT record_digest FROM provider_prepared_requests WHERE call_id = ?1",
                [call_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let actual_hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual_hex, expected_hex);
    }

    connection
        .execute(
            "UPDATE provider_prepared_requests
             SET call_digest_version = 1 WHERE call_id = ?1",
            [[2_u8; 16].as_slice()],
        )
        .unwrap();
    assert_eq!(
        store.get_prepared(v2.call_id),
        Err(ProviderStoreError::CorruptData)
    );
}

#[test]
fn impossible_dispatch_state_shape_is_corrupt_not_recoverable() {
    let (database, store, launch) = fresh_store("corrupt-state-shape");
    store.persist_prepared(&launch, &prepared(1)).unwrap();
    let dispatch_claim = issue_dispatch(&database, 1);

    let connection = database.connection();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_dispatch_attempts SET stream_id = ?1 WHERE attempt_id = ?2",
            rusqlite::params![
                [10_u8; 16].as_slice(),
                dispatch_claim.attempt_id.as_bytes().as_slice(),
            ],
        )
        .unwrap();

    assert_eq!(
        store.get_dispatch(dispatch_claim.attempt_id),
        Err(ProviderStoreError::CorruptData)
    );
}

#[test]
fn v2_dispatch_cannot_downgrade_to_legacy_settlement_without_stream_evidence() {
    let (database, store, launch) = fresh_store("legacy-settlement-downgrade");
    store.persist_prepared(&launch, &prepared(1)).unwrap();
    let dispatch_claim = issue_dispatch(&database, 1);

    let connection = database.connection();
    connection
        .execute(
            "UPDATE provider_dispatch_attempts
             SET state = 5, settlement_digest = ?1
             WHERE attempt_id = ?2",
            rusqlite::params![
                [11_u8; 32].as_slice(),
                dispatch_claim.attempt_id.as_bytes().as_slice(),
            ],
        )
        .unwrap();
    assert_eq!(
        store.get_dispatch(dispatch_claim.attempt_id),
        Err(ProviderStoreError::CorruptData)
    );

    connection
        .execute(
            "UPDATE provider_prepared_requests
             SET call_digest_version = 1 WHERE call_id = ?1",
            [dispatch_claim.call_id.as_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(
        store.get_dispatch(dispatch_claim.attempt_id),
        Err(ProviderStoreError::CorruptData)
    );
}

#[test]
fn legacy_caller_selected_claim_is_typed_and_leaves_no_effect_rows() {
    let (database, store, launch) = fresh_store("claim-disabled");
    store.persist_prepared(&launch, &prepared(1)).unwrap();

    assert_eq!(
        store.claim(&legacy_claim(1)),
        Err(ProviderStoreError::LegacyClaimDisabled)
    );
    let connection = database.connection();
    for table in [
        "provider_dispatch_attempts",
        "provider_effect_authorities",
        "provider_execution_admissions",
        "provider_budget_reservations",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "legacy claim mutated {table}"
        );
    }
}

#[test]
fn dispatch_lifecycle_replays_exactly_and_reopens_incomplete_as_uncertain() {
    let (database, store, _launch) = fresh_store("lifecycle");
    let dispatch_claim = stream_dispatch(&database, 1);

    let streaming = MarkProviderStreaming {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        stream_id: ProviderStreamId::from_bytes([10; 16]),
    };
    // Exact coordinator replay is asserted by stream_dispatch; clockless publication is denied.
    assert_eq!(store.mark_streaming(&streaming), Err(ProviderStoreError::StaleFencingToken));
    assert_eq!(store.get_dispatch(dispatch_claim.attempt_id).unwrap().unwrap().state, ProviderDispatchState::Streaming);
    drop(store);

    let reopened = database.dispatch();
    let incomplete = reopened.reopen_incomplete().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].state, ProviderDispatchState::Uncertain);
}
