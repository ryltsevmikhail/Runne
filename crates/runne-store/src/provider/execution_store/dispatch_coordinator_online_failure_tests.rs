use std::sync::atomic::Ordering;

use futures::executor::block_on;
use rusqlite::Connection;

use super::SqliteProviderExecutionStore;
use super::authority_test_support::{config, configured_connection};
use super::dispatch_coordinator_online_tests::{
    Effect, Guard, coordinator_request, secure_directory,
};
use crate::provider::credential_lifecycle::online_claim_test_support::open_test_store;
use crate::provider::{
    CredentialDispatchAuthority, ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore,
};

#[test]
fn repository_failure_after_issue_freezes_the_live_dispatch_claim() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    secure_directory(directory.path());
    secure_directory(&daemon);
    let path = daemon.join("repository-failure-online.sqlite");
    let lifecycle = open_test_store(&path, 100);
    let text = path.to_str().unwrap();
    let dispatch =
        SqliteProviderDispatchStore::open_with_connection(text, configured_connection(&path))
            .unwrap();
    let execution =
        SqliteProviderExecutionStore::open_with_connection(text, configured_connection(&path))
            .unwrap();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&execution);
    Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE provider_credential_authority_heads")
        .unwrap();
    let effect = Effect::default();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        CredentialDispatchAuthority::new(&lifecycle, &launch),
        &effect,
        &effect,
        &Guard,
    );

    assert_eq!(
        block_on(coordinator.dispatch(coordinator_request(95, "repository-online"))).unwrap(),
        ProviderCoordinatorOutcome::Uncertain
    );
    assert_eq!(effect.materialized.load(Ordering::SeqCst), 0);
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row("SELECT state FROM provider_dispatch_attempts", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        6
    );
}
