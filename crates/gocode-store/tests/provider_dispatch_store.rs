use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use gocode_provider::{
    DispatchAttemptId, ProviderCallDigestVersion, ProviderCallId, ProviderDispatchRepository,
    ProviderPreEffectRejection, ProviderStreamId,
};
use gocode_store::provider::{
    MarkProviderStreaming, PersistPreparedOutcome, PreparedProviderRecord, ProviderClaimOutcome,
    ProviderDispatchClaim, ProviderDispatchState, ProviderStoreError, SettleProviderDispatch,
    SqliteProviderDispatchStore,
};

fn database_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gocode-provider-dispatch-{name}-{}-{:?}.sqlite",
        std::process::id(),
        std::thread::current().id()
    ))
}

fn fresh_store(name: &str) -> (PathBuf, SqliteProviderDispatchStore) {
    let path = database_path(name);
    let _ = std::fs::remove_file(&path);
    let store = SqliteProviderDispatchStore::open(&path).unwrap();
    (path, store)
}

fn prepared(call_byte: u8) -> PreparedProviderRecord {
    PreparedProviderRecord {
        call_id: ProviderCallId::from_bytes([call_byte; 16]),
        call_digest_version: ProviderCallDigestVersion::V2,
        prepared_digest: [2; 32],
        render_digest: [3; 32],
        profile_digest: [4; 32],
    }
}

fn claim(call_byte: u8) -> ProviderDispatchClaim {
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

#[test]
fn persist_prepared_exact_replay_is_idempotent_and_changed_digest_conflicts() {
    let (_path, store) = fresh_store("persist-replay");
    let record = prepared(1);

    assert_eq!(
        store.persist_prepared(&record).unwrap(),
        PersistPreparedOutcome::Inserted
    );
    assert_eq!(
        store.persist_prepared(&record).unwrap(),
        PersistPreparedOutcome::Replayed
    );

    let mut changed = record;
    changed.render_digest = [99; 32];
    assert_eq!(
        store.persist_prepared(&changed),
        Err(ProviderStoreError::PreparedConflict)
    );
    assert_eq!(store.get_prepared(record.call_id).unwrap(), Some(record));
}

#[test]
fn prepared_outer_digest_domains_are_versioned_and_mismatch_fails_closed() {
    let (path, store) = fresh_store("prepared-domains");
    let mut v1 = prepared(1);
    v1.call_digest_version = ProviderCallDigestVersion::V1;
    let v2 = prepared(2);
    store.persist_prepared(&v1).unwrap();
    store.persist_prepared(&v2).unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
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
    let (path, store) = fresh_store("corrupt-state-shape");
    store.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    store.claim(&dispatch_claim).unwrap();

    let connection = rusqlite::Connection::open(path).unwrap();
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
    let (path, store) = fresh_store("legacy-settlement-downgrade");
    store.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    store.claim(&dispatch_claim).unwrap();

    let connection = rusqlite::Connection::open(path).unwrap();
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
fn concurrent_exact_claim_has_one_permit_winner_and_one_existing_observer() {
    let (path, first) = fresh_store("claim-race");
    first.persist_prepared(&prepared(1)).unwrap();
    let second = SqliteProviderDispatchStore::open(&path).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let first_barrier = barrier.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first.claim(&claim(1))
    });
    let second_barrier = barrier.clone();
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second.claim(&claim(1))
    });

    let outcomes = [
        first_thread.join().unwrap().unwrap(),
        second_thread.join().unwrap().unwrap(),
    ];

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ProviderClaimOutcome::Winner { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                ProviderClaimOutcome::Existing {
                    state: ProviderDispatchState::Dispatching,
                    ..
                }
            ))
            .count(),
        1
    );
}

#[test]
fn claim_mismatch_or_stale_fence_changes_nothing() {
    let (_path, store) = fresh_store("claim-validation");
    store.persist_prepared(&prepared(1)).unwrap();
    let mut mismatched = claim(1);
    mismatched.render_digest = [42; 32];

    assert_eq!(
        store.claim(&mismatched),
        Err(ProviderStoreError::PreparedMismatch)
    );

    let mut stale = claim(1);
    stale.fencing_token = 0;
    assert_eq!(
        store.claim(&stale),
        Err(ProviderStoreError::StaleFencingToken)
    );
    assert!(store.get_dispatch(stale.attempt_id).unwrap().is_none());
}

#[test]
fn dispatch_lifecycle_replays_exactly_and_reopens_incomplete_as_uncertain() {
    let (path, store) = fresh_store("lifecycle");
    store.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    let winner = store.claim(&dispatch_claim).unwrap();
    assert!(matches!(winner, ProviderClaimOutcome::Winner { .. }));

    let streaming = MarkProviderStreaming {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        stream_id: ProviderStreamId::from_bytes([10; 16]),
    };
    assert_eq!(
        store.mark_streaming(&streaming).unwrap(),
        ProviderDispatchState::Streaming
    );
    assert_eq!(
        store.mark_streaming(&streaming).unwrap(),
        ProviderDispatchState::Streaming
    );
    drop(store);

    let reopened = SqliteProviderDispatchStore::open(&path).unwrap();
    let incomplete = reopened.reopen_incomplete().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].state, ProviderDispatchState::Uncertain);
}

#[test]
fn settlement_is_idempotent_and_conflicting_settlement_preserves_original() {
    let (_path, store) = fresh_store("settlement");
    store.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    store.claim(&dispatch_claim).unwrap();
    store
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: dispatch_claim.attempt_id,
            fencing_token: dispatch_claim.fencing_token,
            stream_id: ProviderStreamId::from_bytes([10; 16]),
        })
        .unwrap();
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };

    ProviderDispatchRepository::mark_terminal_pending(
        &store,
        settlement.attempt_id,
        settlement.fencing_token,
        settlement.settlement_digest,
    )
    .unwrap();
    assert!(
        ProviderDispatchRepository::mark_terminal_pending(
            &store,
            settlement.attempt_id,
            settlement.fencing_token,
            [12; 32],
        )
        .is_err()
    );
    ProviderDispatchRepository::mark_terminal_pending(
        &store,
        settlement.attempt_id,
        settlement.fencing_token,
        settlement.settlement_digest,
    )
    .unwrap();
    assert_eq!(
        store
            .get_dispatch(settlement.attempt_id)
            .unwrap()
            .unwrap()
            .state,
        ProviderDispatchState::TerminalPendingCommit
    );
    assert_eq!(
        store.settle(&settlement).unwrap(),
        ProviderDispatchState::Settled
    );
    assert_eq!(
        store.settle(&settlement).unwrap(),
        ProviderDispatchState::Settled
    );

    let mut conflicting = settlement;
    conflicting.settlement_digest = [12; 32];
    assert_eq!(
        store.settle(&conflicting),
        Err(ProviderStoreError::SettlementConflict)
    );
    assert_eq!(
        store
            .get_dispatch(conflicting.attempt_id)
            .unwrap()
            .unwrap()
            .settlement_digest,
        Some([11; 32])
    );
}

#[test]
fn terminal_settlement_and_uncertainty_race_has_one_authoritative_winner() {
    let (path, first) = fresh_store("terminal-race");
    first.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    first.claim(&dispatch_claim).unwrap();
    first
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: dispatch_claim.attempt_id,
            fencing_token: dispatch_claim.fencing_token,
            stream_id: ProviderStreamId::from_bytes([10; 16]),
        })
        .unwrap();
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };
    first.mark_terminal_pending(&settlement).unwrap();

    let second = SqliteProviderDispatchStore::open(&path).unwrap();
    let attempt_id = dispatch_claim.attempt_id;
    let fencing_token = dispatch_claim.fencing_token;
    let barrier = Arc::new(Barrier::new(2));
    let settle_barrier = barrier.clone();
    let settle_thread = std::thread::spawn(move || {
        settle_barrier.wait();
        first.settle(&settlement)
    });
    let uncertain_barrier = barrier.clone();
    let uncertain_thread = std::thread::spawn(move || {
        uncertain_barrier.wait();
        second.mark_uncertain(attempt_id, fencing_token)
    });

    let outcomes = [
        settle_thread.join().unwrap(),
        uncertain_thread.join().unwrap(),
    ];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);

    let final_record = SqliteProviderDispatchStore::open(&path)
        .unwrap()
        .get_dispatch(attempt_id)
        .unwrap()
        .unwrap();
    let winning_state = outcomes.iter().find_map(|outcome| outcome.as_ref().ok());
    assert_eq!(winning_state, Some(&final_record.state));
    assert!(matches!(
        final_record.state,
        ProviderDispatchState::Settled | ProviderDispatchState::Uncertain
    ));
}

#[test]
fn repository_port_commits_terminal_settlement_after_stream_binding() {
    let (_path, store) = fresh_store("settlement-port");
    store.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    store.claim(&dispatch_claim).unwrap();
    store
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: dispatch_claim.attempt_id,
            fencing_token: dispatch_claim.fencing_token,
            stream_id: ProviderStreamId::from_bytes([10; 16]),
        })
        .unwrap();

    ProviderDispatchRepository::mark_terminal_pending(
        &store,
        dispatch_claim.attempt_id,
        dispatch_claim.fencing_token,
        [11; 32],
    )
    .unwrap();
    ProviderDispatchRepository::settle(
        &store,
        dispatch_claim.attempt_id,
        dispatch_claim.fencing_token,
        [11; 32],
    )
    .unwrap();

    let record = store
        .get_dispatch(dispatch_claim.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ProviderDispatchState::Settled);
    assert_eq!(record.settlement_digest, Some([11; 32]));
}

#[test]
fn settlement_before_stream_binding_fails_without_terminal_mutation() {
    let (_path, store) = fresh_store("settlement-before-stream");
    store.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    store.claim(&dispatch_claim).unwrap();
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };

    assert!(store.settle(&settlement).is_err());
    let record = store
        .get_dispatch(dispatch_claim.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ProviderDispatchState::Dispatching);
    assert_eq!(record.settlement_digest, None);
}

#[test]
fn settlement_before_terminal_evidence_preserves_streaming_state() {
    let (_path, store) = fresh_store("settlement-before-terminal");
    store.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    store.claim(&dispatch_claim).unwrap();
    store
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: dispatch_claim.attempt_id,
            fencing_token: dispatch_claim.fencing_token,
            stream_id: ProviderStreamId::from_bytes([10; 16]),
        })
        .unwrap();
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };

    assert_eq!(
        store.settle(&settlement),
        Err(ProviderStoreError::SettlementBeforeTerminal)
    );
    let record = store
        .get_dispatch(dispatch_claim.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ProviderDispatchState::Streaming);
    assert_eq!(record.settlement_digest, None);
}

#[test]
fn pre_effect_rejection_is_terminal_exact_and_never_becomes_streaming() {
    let (_path, store) = fresh_store("pre-effect-rejection");
    store.persist_prepared(&prepared(1)).unwrap();
    let dispatch_claim = claim(1);
    store.claim(&dispatch_claim).unwrap();

    ProviderDispatchRepository::mark_rejected_before_effect(
        &store,
        dispatch_claim.attempt_id,
        dispatch_claim.fencing_token,
        ProviderPreEffectRejection::CredentialUnavailable,
    )
    .unwrap();
    ProviderDispatchRepository::mark_rejected_before_effect(
        &store,
        dispatch_claim.attempt_id,
        dispatch_claim.fencing_token,
        ProviderPreEffectRejection::CredentialUnavailable,
    )
    .unwrap();

    let record = store
        .get_dispatch(dispatch_claim.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ProviderDispatchState::RejectedBeforeEffect);
    assert_eq!(
        record.pre_effect_rejection,
        Some(ProviderPreEffectRejection::CredentialUnavailable)
    );
    assert!(
        ProviderDispatchRepository::mark_rejected_before_effect(
            &store,
            dispatch_claim.attempt_id,
            dispatch_claim.fencing_token,
            ProviderPreEffectRejection::CredentialAccessDenied,
        )
        .is_err()
    );
    assert!(
        store
            .mark_streaming(&MarkProviderStreaming {
                attempt_id: dispatch_claim.attempt_id,
                fencing_token: dispatch_claim.fencing_token,
                stream_id: ProviderStreamId::from_bytes([10; 16]),
            })
            .is_err()
    );
}
