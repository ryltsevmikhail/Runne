use Outcome::*;
use State::*;
use runne_provider::{
    DispatchAttemptId as Attempt, ProviderCallDigestVersion, ProviderCallId as Call,
    ProviderStreamId as Stream,
};
use runne_store::provider::{
    MarkProviderStreaming as MarkStreaming, PreparedProviderRecord as Prepared,
    ProviderClaimOutcome, ProviderDispatchClaim as Claim, ProviderDispatchState as State,
    ProviderStoreError as Error, RecoveryCasOutcome as Outcome,
    SettleProviderDispatch as Settlement, SqliteProviderDispatchStore as Store,
};
use rusqlite::Connection;

#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/provider_credential_fixture.rs"]
mod provider_credential_fixture;
#[path = "support/recovery/mod.rs"]
mod recovery_support;
#[path = "support/runtime_launch.rs"]
mod runtime_launch;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

use recovery_support::claim_dispatch_row;
use validated_reopen::ProviderTestDatabase;

type Setup = (ProviderTestDatabase, Store, Claim);

fn setup(name: &str) -> Setup {
    let (d, store, claim) = prepared_setup(name);
    assert!(matches!(
        claim_dispatch_row(d.as_path(), &claim),
        ProviderClaimOutcome::Winner { .. }
    ));
    (d, store, claim)
}

fn prepared_setup(name: &str) -> Setup {
    let d = ProviderTestDatabase::new(name);
    let store = d.dispatch();
    let execution = d.execution();
    let launch = runtime_launch::activate(&execution);
    store
        .persist_prepared(
            &launch,
            &Prepared {
                call_id: Call::from_bytes([1; 16]),
                call_digest_version: ProviderCallDigestVersion::V2,
                prepared_digest: [2; 32],
                render_digest: [3; 32],
                profile_digest: [4; 32],
            },
        )
        .unwrap();
    let claim = Claim {
        call_id: Call::from_bytes([1; 16]),
        attempt_id: Attempt::from_bytes([5; 16]),
        permit_id: [6; 16],
        prepared_digest: [2; 32],
        render_digest: [3; 32],
        profile_digest: [4; 32],
        token_reservation_id: [7; 16],
        cost_reservation_id: [8; 16],
        fencing_token: 9,
        provider_idempotency_key: "k".to_owned(),
    };
    (d, store, claim)
}

fn snapshot(store: &Store, id: Attempt) -> runne_store::provider::ProviderDispatchRecord {
    store.get_dispatch(id).unwrap().unwrap()
}

fn ignore_lifecycle_update(d: &ProviderTestDatabase, state: i64) {
    let connection = Connection::open(d.as_path()).unwrap();
    connection
        .execute_batch(&format!(
            "CREATE TRIGGER ignore_lifecycle_update
             BEFORE UPDATE OF state ON provider_dispatch_attempts
             WHEN NEW.state = {state}
             BEGIN SELECT RAISE(IGNORE); END;"
        ))
        .unwrap();
}

fn readonly(
    store: &Store,
    claim: &Claim,
    fence: u64,
    state: State,
    expected: Result<Outcome, Error>,
) {
    let before = snapshot(store, claim.attempt_id);
    assert_eq!(
        store.recover_attempt(claim.attempt_id, fence, state),
        expected
    );
    assert_eq!(snapshot(store, claim.attempt_id), before);
}

#[test]
fn recover_rejects_settled_or_uncertain_expected_state_without_mutation() {
    let (_d, store, claim) = setup("a");
    readonly(&store, &claim, 9, Settled, Err(Error::RecoveryConflict));
    readonly(&store, &claim, 9, Uncertain, Err(Error::RecoveryConflict));
}

#[test]
fn recover_missing_attempt_is_not_found() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(&d.path().join("s")).unwrap();
    let attempt_id = Attempt::from_bytes([99; 16]);
    assert_eq!(store.get_dispatch(attempt_id).unwrap(), None);
    assert_eq!(
        store.recover_attempt(attempt_id, 9, Dispatching),
        Err(Error::NotFound)
    );
    assert_eq!(store.get_dispatch(attempt_id).unwrap(), None);
}

#[test]
fn recover_stale_fence_is_rejected() {
    let (_d, store, claim) = setup("b");
    readonly(
        &store,
        &claim,
        claim.fencing_token + 1,
        Dispatching,
        Err(Error::StaleFencingToken),
    );
    readonly(
        &store,
        &claim,
        0,
        Dispatching,
        Err(Error::StaleFencingToken),
    );
}

#[test]
fn recover_dispatching_transitions_to_uncertain() {
    let (_d, store, claim) = setup("c");
    let mut after = snapshot(&store, claim.attempt_id);
    after.state = Uncertain;
    assert_eq!(
        store.recover_attempt(claim.attempt_id, 9, Dispatching),
        Ok(TransitionedToUncertain)
    );
    assert_eq!(snapshot(&store, claim.attempt_id), after);
}

#[test]
fn recover_streaming_transitions_to_uncertain() {
    let (_d, store, claim) = setup("d");
    store
        .mark_streaming(&MarkStreaming {
            attempt_id: claim.attempt_id,
            fencing_token: 9,
            stream_id: Stream::from_bytes([10; 16]),
        })
        .unwrap();
    let mut after = snapshot(&store, claim.attempt_id);
    after.state = Uncertain;
    assert_eq!(
        store.recover_attempt(claim.attempt_id, 9, Streaming),
        Ok(TransitionedToUncertain)
    );
    assert_eq!(snapshot(&store, claim.attempt_id), after);
}

#[test]
fn recover_uncertain_is_idempotent() {
    let (_d, store, claim) = setup("e");
    store.mark_uncertain(claim.attempt_id, 9).unwrap();
    readonly(&store, &claim, 9, Dispatching, Ok(AlreadyUncertain));
}

#[test]
fn recover_settled_is_read_only() {
    let (_d, store, claim) = setup("f");
    store
        .mark_streaming(&MarkStreaming {
            attempt_id: claim.attempt_id,
            fencing_token: 9,
            stream_id: Stream::from_bytes([10; 16]),
        })
        .unwrap();
    store
        .mark_terminal_pending(&Settlement {
            attempt_id: claim.attempt_id,
            fencing_token: 9,
            settlement_digest: [11; 32],
        })
        .unwrap();
    store
        .settle(&Settlement {
            attempt_id: claim.attempt_id,
            fencing_token: 9,
            settlement_digest: [11; 32],
        })
        .unwrap();
    readonly(&store, &claim, 9, Dispatching, Ok(AlreadySettled));
}

#[test]
fn recover_conflicting_incomplete_state_is_recovery_conflict() {
    let (_d, store, claim) = setup("g");
    store
        .mark_streaming(&MarkStreaming {
            attempt_id: claim.attempt_id,
            fencing_token: 9,
            stream_id: Stream::from_bytes([10; 16]),
        })
        .unwrap();
    readonly(&store, &claim, 9, Dispatching, Err(Error::RecoveryConflict));
}

#[test]
fn mark_streaming_zero_affected_rows_is_not_false_success() {
    let (d, store, claim) = setup("streaming-zero-row");
    ignore_lifecycle_update(&d, 3);
    let before = snapshot(&store, claim.attempt_id);
    let result = store.mark_streaming(&MarkStreaming {
        attempt_id: claim.attempt_id,
        fencing_token: claim.fencing_token,
        stream_id: Stream::from_bytes([10; 16]),
    });

    assert_eq!(snapshot(&store, claim.attempt_id), before);
    assert_eq!(result, Err(Error::CorruptData));
}

#[test]
fn settle_zero_affected_rows_is_not_false_success() {
    let (d, store, claim) = setup("settlement-zero-row");
    store
        .mark_streaming(&MarkStreaming {
            attempt_id: claim.attempt_id,
            fencing_token: claim.fencing_token,
            stream_id: Stream::from_bytes([10; 16]),
        })
        .unwrap();
    store
        .mark_terminal_pending(&Settlement {
            attempt_id: claim.attempt_id,
            fencing_token: claim.fencing_token,
            settlement_digest: [11; 32],
        })
        .unwrap();
    ignore_lifecycle_update(&d, 5);
    let before = snapshot(&store, claim.attempt_id);
    let result = store.settle(&Settlement {
        attempt_id: claim.attempt_id,
        fencing_token: claim.fencing_token,
        settlement_digest: [11; 32],
    });

    assert_eq!(snapshot(&store, claim.attempt_id), before);
    assert_eq!(result, Err(Error::CorruptData));
}

include!("provider_dispatch_recovery_parts/task3.rs");
include!("provider_dispatch_recovery_parts/task4.rs");
include!("provider_dispatch_recovery_parts/task4_faults.rs");
include!("provider_dispatch_recovery_parts/task5.rs");

#[test]
fn task4_test_support_is_available_only_to_integration_tests() {
    use recovery_support::{
        CountingProvider, DispatchSnapshot, RecoveryFaultDecorator, RecoveryFaultPoint,
    };

    let _ = (
        RecoveryFaultPoint::BeforeClaim,
        RecoveryFaultDecorator::new,
        CountingProvider::new,
        DispatchSnapshot::load,
    );
}
