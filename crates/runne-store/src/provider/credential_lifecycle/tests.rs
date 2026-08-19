use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use runne_provider::{
    CredentialAuthorityPair, CredentialLease, CredentialVersionRef, PrepareCredentialVersion,
    ProviderCredentialVersionStore, ProviderId,
};
use rusqlite::Connection;

use super::SqliteProviderCredentialLifecycleStore;

struct Clock {
    now: AtomicI64,
    reads: AtomicUsize,
}

impl Clock {
    fn read(&self) -> i64 {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.now.load(Ordering::SeqCst)
    }
}

#[test]
fn activation_samples_expiry_only_after_waiting_for_the_write_lock() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("activation-lock-expiry.sqlite");
    let clock = Arc::new(Clock {
        now: AtomicI64::new(100),
        reads: AtomicUsize::new(0),
    });
    let captured = Arc::clone(&clock);
    let store = SqliteProviderCredentialLifecycleStore::open_with_now(
        &path,
        Arc::new(move || captured.read()),
    )
    .unwrap();
    let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 1).unwrap();
    store
        .create_prepared(PrepareCredentialVersion::new(reference.clone()))
        .unwrap();
    let lease = CredentialLease::new(reference.clone(), [0xA1; 16], 101, 1).unwrap();
    let reads_before = clock.reads.load(Ordering::SeqCst);
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    let result = std::thread::scope(|scope| {
        let pending = scope.spawn(|| store.activate(lease));
        for _ in 0..100 {
            if clock.reads.load(Ordering::SeqCst) > reads_before {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        clock.now.store(101, Ordering::SeqCst);
        blocker.execute_batch("COMMIT").unwrap();
        pending.join().unwrap()
    });

    assert_eq!(
        result.unwrap_err(),
        runne_provider::CredentialLifecycleError::StaleLease
    );
    assert_eq!(
        store.version_state(&reference).unwrap(),
        runne_provider::CredentialVersionState::Prepared
    );
}

#[test]
fn completed_provision_replays_the_exact_operation_and_version() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("completed-provision-replay.sqlite");
    let store = SqliteProviderCredentialLifecycleStore::open_at(&path, 100).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let operation_id = [0xD1; 16];
    let source = store.provision_source([0xD3; 16]).unwrap();
    let prepared = store
        .begin_provision(&provider, operation_id, &source)
        .unwrap();
    let native_created = store.mark_native_created(&prepared).unwrap();
    store
        .activate(
            CredentialLease::new(native_created.version_ref().clone(), [0xD2; 16], 200, 1).unwrap(),
        )
        .unwrap();
    store.complete_provision(&native_created).unwrap();

    let replay = store
        .begin_provision(&provider, operation_id, &source)
        .unwrap();
    assert_eq!(replay.version_ref(), prepared.version_ref());
    store.mark_native_created(&replay).unwrap();
    store.complete_provision(&replay).unwrap();
}

#[test]
fn provision_replay_rejects_changed_source_before_native_create() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provision-source-conflict.sqlite");
    let store = SqliteProviderCredentialLifecycleStore::open_at(&path, 100).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let first = store.provision_source([0xE1; 16]).unwrap();
    let changed = store.provision_source([0xE2; 16]).unwrap();
    assert_eq!(
        store.provision_source([0; 16]).unwrap_err(),
        runne_provider::CredentialLifecycleError::InvalidInput
    );
    let operation = [0xE3; 16];

    let prepared = store.begin_provision(&provider, operation, &first).unwrap();
    assert_eq!(
        store
            .begin_provision(&provider, operation, &changed)
            .unwrap_err(),
        runne_provider::CredentialLifecycleError::Conflict
    );
    assert!(!prepared.native_created());
    assert_eq!(
        store.version_state(prepared.version_ref()).unwrap(),
        runne_provider::CredentialVersionState::Prepared
    );
    let (foreign, _) = CredentialAuthorityPair::new().split();
    let foreign_source = foreign.issue_provision_source([0xE4; 16]).unwrap();
    assert_eq!(
        store
            .begin_provision(&provider, [0xE5; 16], &foreign_source)
            .unwrap_err(),
        runne_provider::CredentialLifecycleError::StaleLease
    );
}
