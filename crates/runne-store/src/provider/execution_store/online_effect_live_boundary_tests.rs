use std::sync::Arc;

use runne_application::provider::ProviderAdmissionError;
use rusqlite::Connection;

use super::authority_test_support::{config, prepare_request_for_provider};
use super::{ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore};
use crate::provider::credential_lifecycle::online_claim_test_support::{
    open_test_store, reopen_test_store,
};
use crate::provider::credential_lifecycle::online_test_support::{complete_pair, provider};

#[test]
fn online_effect_cas_rejects_mirror_lease_at_or_after_observed_time() {
    for (id, expiry) in [(96, 100), (97, 99)] {
        let (directory, path) = setup(id);
        let store = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 100)).unwrap();
        let launch = store.activate_runtime_launch(&config()).unwrap();
        super::online_proof_test_support::arm(&store);
        let admission = issue(&store, &launch, &path, id);
        let binding = reopen_test_store(&path, 100)
            .authorize_online_dispatch(&launch, admission.claim(), 100)
            .unwrap();
        let (_, effect_binding) = binding.split();
        expire_mirror(&path, expiry);

        assert!(matches!(
            store.start_online_effect(&launch, admission.claim(), &effect_binding),
            Err(ProviderAdmissionError::AuthorityDenied)
        ));
        assert_eq!(counts(&path), (0, 0, 0), "expiry={expiry}");
        drop(directory);
    }
}

#[test]
fn v26_trigger_rejects_an_expired_mirror_at_durable_effect_time() {
    let (_directory, path) = setup(98);
    let store = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 100)).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    let admission = issue(&store, &launch, &path, 98);
    expire_mirror(&path, 100);
    let connection = Connection::open(&path).unwrap();
    insert_effect_start(&connection, &admission);
    let error = insert_effect_binding(&connection, &admission).unwrap_err();
    assert_eq!(
        sqlite_message(error),
        "online credential effect binding is stale or fenced"
    );
    assert_eq!(counts(&path), (1, 0, 0));
}

#[test]
fn v26_trigger_accepts_a_live_mirror_at_durable_effect_time() {
    let (_directory, path) = setup(99);
    let store = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 100)).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    let admission = issue(&store, &launch, &path, 99);
    let connection = Connection::open(&path).unwrap();
    insert_effect_start(&connection, &admission);

    assert_eq!(insert_effect_binding(&connection, &admission).unwrap(), 1);
    assert_eq!(counts(&path), (1, 1, 0));
}

fn insert_effect_start(connection: &Connection, admission: &super::DurableProviderAdmission) {
    connection
        .execute(
            "INSERT INTO provider_effect_starts
             (dispatch_attempt_id, provider_idempotency_key, permit_id, effect_started_at, effect_expires_at, state)
             SELECT dispatch_attempt_id, provider_idempotency_key, permit_id, 100, 220, 1
               FROM provider_execution_admissions WHERE dispatch_attempt_id=?1",
            [admission.claim().attempt_id.as_bytes().as_slice()],
        )
        .unwrap();
}

fn insert_effect_binding(
    connection: &Connection,
    admission: &super::DurableProviderAdmission,
) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO provider_online_credential_effect_bindings
         (dispatch_attempt_id, provider_id, launch_generation, lifecycle_revision, credential_fence, active_credential_version, active_ref_digest, effect_mac)
         SELECT effect.dispatch_attempt_id, head.provider_id, admission.generation,
                head.lifecycle_revision, head.credential_fence, head.active_credential_version,
                head.active_ref_digest, zeroblob(32)
           FROM provider_effect_starts effect
           JOIN provider_execution_admissions admission ON admission.dispatch_attempt_id=effect.dispatch_attempt_id
           JOIN provider_credential_authority_heads head ON head.provider_id='openai'
          WHERE effect.dispatch_attempt_id=?1",
        [admission.claim().attempt_id.as_bytes().as_slice()],
    )
}

fn setup(id: u8) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join(format!("online-lease-{id}.sqlite"));
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, id, "online-live-boundary");
    drop(lifecycle);
    (directory, path)
}

fn issue(
    store: &SqliteProviderExecutionStore,
    launch: &crate::provider::ProviderRuntimeLaunchCapability,
    path: &std::path::Path,
    id: u8,
) -> Box<super::DurableProviderAdmission> {
    match store
        .issue(
            launch,
            &prepare_request_for_provider(launch, path, id, provider().as_str()),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    }
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

fn sqlite_message(error: rusqlite::Error) -> String {
    match error {
        rusqlite::Error::SqliteFailure(_, Some(message)) => message,
        other => panic!("expected SQLite failure message, got {other:?}"),
    }
}
