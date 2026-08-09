use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use gocode_provider::{
    CredentialLease, CredentialVersionRef, PrepareCredentialVersion,
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
        gocode_provider::CredentialLifecycleError::StaleLease
    );
    assert_eq!(
        store.version_state(&reference).unwrap(),
        gocode_provider::CredentialVersionState::Prepared
    );
}

#[test]
fn completed_provision_replays_the_exact_operation_and_version() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("completed-provision-replay.sqlite");
    let store = SqliteProviderCredentialLifecycleStore::open_at(&path, 100).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let operation_id = [0xD1; 16];
    let prepared = store.begin_provision(&provider, operation_id).unwrap();
    let native_created = store.mark_native_created(&prepared).unwrap();
    store
        .activate(
            CredentialLease::new(native_created.version_ref().clone(), [0xD2; 16], 200, 1).unwrap(),
        )
        .unwrap();
    store.complete_provision(&native_created).unwrap();

    let replay = store.begin_provision(&provider, operation_id).unwrap();
    assert_eq!(replay.version_ref(), prepared.version_ref());
    store.mark_native_created(&replay).unwrap();
    store.complete_provision(&replay).unwrap();
}
