use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use gocode_provider::{DispatchAttemptId, ProviderCallId, ProviderStreamId};
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
    let settlement = SettleProviderDispatch {
        attempt_id: dispatch_claim.attempt_id,
        fencing_token: dispatch_claim.fencing_token,
        settlement_digest: [11; 32],
    };

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
