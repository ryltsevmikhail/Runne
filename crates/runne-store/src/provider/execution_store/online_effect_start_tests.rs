use runne_application::provider::ProviderAdmissionError;
use runne_provider::{CredentialFence, HardFenceProvider, ProviderCredentialEnrollmentStore};
use rusqlite::Connection;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use super::authority_test_support::config;
use super::{ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore};
use crate::provider::credential_lifecycle::online_claim_test_support::{
    open_test_store, reopen_test_store,
};
use crate::provider::credential_lifecycle::online_test_support::{complete_pair, provider};

mod final_send_tests;
mod online_materialization_fence_tests;
mod online_revoke_fence_tests;

#[test]
fn cross_provider_claim_is_denied_before_online_effect_cas() {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "online-effect.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 81, "online-effect");
    drop(lifecycle);
    let store = SqliteProviderExecutionStore::open(&path).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::authority_test_support::prepare_request(&launch, &path, 81),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let lifecycle = reopen_test_store(&path, 100);
    assert!(
        lifecycle
            .authorize_online_dispatch(&launch, admission.claim(), 100)
            .is_err()
    );
    assert_eq!(counts(&path), (0, 0, 0));
}

#[test]
fn online_receipt_reads_exact_committed_tuple() {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "online-receipt.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 84, "online-receipt");
    drop(lifecycle);
    let store = SqliteProviderExecutionStore::open(&path).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::authority_test_support::prepare_request_for_provider(
                &launch, &path, 84, "openai",
            ),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let lifecycle = reopen_test_store(&path, 100);
    let binding = lifecycle
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    let receipt = store
        .start_online_effect(&launch, admission.claim(), &effect_binding)
        .unwrap();
    assert_eq!(receipt.launch_generation(), 11);
    assert_eq!(receipt.lifecycle_revision(), 2);
    assert_eq!(receipt.credential_fence(), 2);
    assert_eq!(receipt.credential_version(), 1);
    let durable: (Vec<u8>, String, i64, i64, i64, i64, Vec<u8>) = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT dispatch_attempt_id, provider_id, launch_generation, lifecycle_revision,
                    credential_fence, active_credential_version, active_ref_digest
               FROM provider_online_credential_effect_bindings",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(receipt.attempt_id(), durable.0.as_slice());
    assert_eq!(receipt.provider(), durable.1);
    assert_eq!(
        receipt.launch_generation(),
        u64::try_from(durable.2).unwrap()
    );
    assert_eq!(
        receipt.lifecycle_revision(),
        u64::try_from(durable.3).unwrap()
    );
    assert_eq!(
        receipt.credential_fence(),
        u64::try_from(durable.4).unwrap()
    );
    assert_eq!(
        receipt.credential_version(),
        u64::try_from(durable.5).unwrap()
    );
    assert_eq!(receipt.ref_digest(), durable.6.as_slice());
    assert_eq!(counts(&path), (1, 1, 1));
}

#[test]
fn fence_between_materialization_and_effect_start_leaves_no_rows() {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "online-fence.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 82, "online-fence");
    drop(lifecycle);
    let store = Arc::new(SqliteProviderExecutionStore::open(&path).unwrap());
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::authority_test_support::prepare_request_for_provider(
                &launch, &path, 82, "openai",
            ),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let lifecycle = reopen_test_store(&path, 100);
    let binding = lifecycle
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    drop(lifecycle);
    let materialized = Arc::new(AtomicUsize::new(0));
    let materialized_gate = Arc::new(Barrier::new(2));
    let resume_effect_cas = Arc::new(Barrier::new(2));
    let worker_store = Arc::clone(&store);
    let worker_claim = admission.claim().clone();
    let worker_materialized = Arc::clone(&materialized);
    let worker_gate = Arc::clone(&materialized_gate);
    let worker_resume = Arc::clone(&resume_effect_cas);
    let worker = thread::spawn(move || {
        worker_materialized.fetch_add(1, Ordering::SeqCst);
        worker_gate.wait();
        worker_resume.wait();
        worker_store.start_online_effect(&launch, &worker_claim, &effect_binding)
    });
    materialized_gate.wait();
    let fencing_connection = reopen_test_store(&path, 100);
    ProviderCredentialEnrollmentStore::hard_fence_provider(
        &fencing_connection,
        HardFenceProvider::new(
            provider(),
            CredentialFence::new(2).unwrap(),
            CredentialFence::new(3).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    drop(fencing_connection);
    resume_effect_cas.wait();
    assert!(matches!(
        worker.join().unwrap(),
        Err(ProviderAdmissionError::AuthorityDenied)
    ));
    assert_eq!(materialized.load(Ordering::SeqCst), 1);
    assert_eq!(counts(&path), (0, 0, 0));
}

#[test]
fn effect_start_commit_ambiguity_never_issues_online_receipt() {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "online-uncertain.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 83, "online-uncertain");
    drop(lifecycle);
    let store = SqliteProviderExecutionStore::open(&path).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::authority_test_support::prepare_request_for_provider(
                &launch, &path, 83, "openai",
            ),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let lifecycle = reopen_test_store(&path, 100);
    let binding = lifecycle
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    drop(lifecycle);
    store.fail_next_effect_readback();
    assert!(matches!(
        store.start_online_effect(&launch, admission.claim(), &effect_binding),
        Err(ProviderAdmissionError::PostClaimUncertain)
    ));
    assert_eq!(counts(&path), (1, 1, 1));
}

#[test]
fn online_effect_start_maps_unknown_sqlite_failure_to_repository_failure() {
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let path = managed_path(directory.path(), "online-repository-failure.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 85, "online-repository-failure");
    drop(lifecycle);
    let store = SqliteProviderExecutionStore::open(&path).unwrap();
    let launch = store.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&store);
    let admission = match store
        .issue(
            &launch,
            &super::authority_test_support::prepare_request_for_provider(
                &launch, &path, 85, "openai",
            ),
        )
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let lifecycle = reopen_test_store(&path, 100);
    let binding = lifecycle
        .authorize_online_dispatch(&launch, admission.claim(), 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    drop(lifecycle);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER injected_online_effect_failure
             BEFORE INSERT ON provider_effect_starts
             BEGIN SELECT RAISE(ABORT, 'injected repository failure'); END;",
        )
        .unwrap();

    assert!(matches!(
        store.start_online_effect(&launch, admission.claim(), &effect_binding),
        Err(ProviderAdmissionError::RepositoryFailure)
    ));
    assert_eq!(counts(&path), (0, 0, 0));
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

#[cfg_attr(not(unix), allow(unused_variables))]
fn secure_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn managed_path(root: &std::path::Path, name: &str) -> std::path::PathBuf {
    let daemon = root.join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    secure_directory(&daemon);
    daemon.join(name)
}
