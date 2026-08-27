use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::executor::block_on;
use runne_provider::ProviderPreEffectRejection;
use rusqlite::Connection;

use super::SqliteProviderExecutionStore;
use super::authority_test_support::{config, configured_connection};
use super::dispatch_coordinator_online_tests::{
    Effect, Guard, coordinator_request, secure_directory,
};
use crate::provider::credential_lifecycle::online_claim_test_support::open_test_store;
use crate::provider::credential_lifecycle::online_test_support::complete_pair;
use crate::provider::{
    CredentialDispatchAuthority, ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore,
};

#[test]
fn coordinator_never_dispatches_after_lease_expires_during_stage_effect() {
    let (directory, path, lifecycle) = setup(99, "stage-expiry");
    let text = path.to_str().unwrap();
    let dispatch =
        SqliteProviderDispatchStore::open_with_connection(text, configured_connection(&path))
            .unwrap();
    let execution = SqliteProviderExecutionStore::open_with_connection_and_now(
        text,
        configured_connection(&path),
        Arc::new(|| 100),
    )
    .unwrap();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&execution);
    let effect = Effect::default();
    let (reached, release) = effect.pause_after_stage();
    let coordinator = coordinator(&dispatch, &execution, &lifecycle, &launch, &effect);
    std::thread::scope(|scope| {
        let worker =
            scope.spawn(|| block_on(coordinator.dispatch(coordinator_request(99, "stage-expiry"))));
        reached.wait();
        expire_mirror(&path, 100);
        release.wait();
        assert_eq!(
            worker.join().unwrap().unwrap(),
            ProviderCoordinatorOutcome::RejectedBeforeEffect {
                reason: ProviderPreEffectRejection::AdapterRejected
            }
        );
    });
    assert_eq!(effect.dispatched_count(), 0);
    assert_eq!(counts(&path), (0, 0, 0));
    drop(directory);
}

#[test]
fn coordinator_freezes_without_dispatch_when_readback_is_expired() {
    let phase = Arc::new(AtomicUsize::new(0));
    let clock = Arc::clone(&phase);
    let (directory, path, lifecycle) = setup(100, "readback-expiry");
    let text = path.to_str().unwrap();
    let dispatch =
        SqliteProviderDispatchStore::open_with_connection(text, configured_connection(&path))
            .unwrap();
    let execution = SqliteProviderExecutionStore::open_with_connection_and_now(
        text,
        configured_connection(&path),
        Arc::new(move || match clock.load(Ordering::SeqCst) {
            0 => 100,
            1 => {
                clock.store(2, Ordering::SeqCst);
                100
            }
            _ => 220,
        }),
    )
    .unwrap();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&execution);
    let effect = Effect::default();
    let (reached, release) = effect.pause_after_stage();
    let coordinator = coordinator(&dispatch, &execution, &lifecycle, &launch, &effect);
    std::thread::scope(|scope| {
        let worker = scope
            .spawn(|| block_on(coordinator.dispatch(coordinator_request(100, "readback-expiry"))));
        reached.wait();
        phase.store(1, Ordering::SeqCst);
        release.wait();
        assert_eq!(
            worker.join().unwrap().unwrap(),
            ProviderCoordinatorOutcome::Uncertain
        );
    });
    assert_eq!(effect.dispatched_count(), 0);
    assert_eq!(counts(&path), (1, 1, 1));
    drop(directory);
}

fn setup(
    id: u8,
    key: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    crate::provider::SqliteProviderCredentialLifecycleStore,
) {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    secure_directory(directory.path());
    secure_directory(&daemon);
    let path = daemon.join(format!("coordinator-expiry-{id}.sqlite"));
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, id, key);
    (directory, path, lifecycle)
}

fn coordinator<'a>(
    dispatch: &'a SqliteProviderDispatchStore,
    execution: &'a SqliteProviderExecutionStore,
    lifecycle: &'a crate::provider::SqliteProviderCredentialLifecycleStore,
    launch: &'a crate::provider::ProviderRuntimeLaunchCapability,
    effect: &'a Effect,
) -> SqliteProviderDispatchCoordinator<'a, Effect, Effect> {
    SqliteProviderDispatchCoordinator::new(
        dispatch,
        execution,
        CredentialDispatchAuthority::new(lifecycle, launch),
        effect,
        effect,
        &Guard,
    )
}

fn expire_mirror(path: &std::path::Path, expiry: i64) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_credential_identity_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_credential_versions SET lease_expires_at=?1
         WHERE provider_id='openai' AND credential_version=1",
            [expiry],
        )
        .unwrap();
}

fn counts(path: &std::path::Path) -> (i64, i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_effect_starts),
                (SELECT COUNT(*) FROM provider_online_credential_effect_bindings),
                (SELECT COUNT(*) FROM security_audit_pre_effect)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}
