use std::sync::Arc;

use gocode_domain::security::Generation;
use gocode_security::atomic::{
    AtomicPreEffectTransaction, AtomicTransactionError, AuthorizationDecision,
    PreEffectTransactionOutcome,
};
#[cfg(not(target_os = "windows"))]
use gocode_security::broker::fs::CanonicalPath;
use gocode_security::broker::fs::{
    FilesystemBroker, FsBrokerError, SymlinkPolicy, WorkspacePolicy, WorkspaceRoot,
};
use gocode_security::broker::network::{
    EgressPolicy, NetworkBroker, NetworkDestination, NetworkError,
};
use gocode_security::broker::secret::{SecretBroker, SecretError};
use gocode_security::cleanup::{CleanupError, CleanupPool, CleanupState};
use gocode_store::atomic_pre_effect::SqliteAtomicPreEffectStore;
use tempfile::TempDir;
use tokio::sync::Barrier;

type CommitResult = Result<PreEffectTransactionOutcome, AtomicTransactionError>;

fn shared_sqlite_stores() -> (
    TempDir,
    Arc<SqliteAtomicPreEffectStore>,
    Arc<SqliteAtomicPreEffectStore>,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("security-races.sqlite");
    let first = Arc::new(SqliteAtomicPreEffectStore::open(&path).unwrap());
    let second = Arc::new(SqliteAtomicPreEffectStore::open(&path).unwrap());
    (directory, first, second)
}

async fn concurrent_commits(
    first_store: Arc<SqliteAtomicPreEffectStore>,
    first_transaction: AtomicPreEffectTransaction,
    second_store: Arc<SqliteAtomicPreEffectStore>,
    second_transaction: AtomicPreEffectTransaction,
) -> (CommitResult, CommitResult) {
    // Barrier запускает обе попытки до блокирующих SQLite-коммитов.
    let barrier = Arc::new(Barrier::new(2));
    let first_barrier = barrier.clone();
    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        tokio::task::spawn_blocking(move || first_store.commit_pre_effect(&first_transaction))
            .await
            .unwrap()
    });
    let second_barrier = barrier.clone();
    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        tokio::task::spawn_blocking(move || second_store.commit_pre_effect(&second_transaction))
            .await
            .unwrap()
    });

    (first.await.unwrap(), second.await.unwrap())
}

#[tokio::test]
async fn race_dual_dispatch_same_permit_idempotent() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let transaction = valid_tx("intent-a", "permit-a");

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        transaction.clone(),
        second_store,
        transaction,
    )
    .await;

    assert_eq!(first_result, second_result);
    assert!(matches!(
        first_result,
        Ok(PreEffectTransactionOutcome::Committed { ref intent_id }) if intent_id == "intent-a"
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_same_permit_with_different_intents_rejects_one_without_mutation() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        valid_tx("intent-a", "permit-shared"),
        second_store,
        valid_tx("intent-b", "permit-shared"),
    )
    .await;
    let outcomes = [first_result, second_result];

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| {
                matches!(result, Err(AtomicTransactionError::PermitIntentConflict))
            })
            .count(),
        1
    );
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

fn valid_tx(intent: &str, permit_id: &str) -> AtomicPreEffectTransaction {
    AtomicPreEffectTransaction {
        authorization_decision: AuthorizationDecision {
            grant_id: "grant-1".into(),
            allowed: true,
            reason: "authorized".into(),
        },
        budget_reservation_id: format!("reservation-{intent}"),
        budget_amount: 1,
        side_effect_started: true,
        dispatch_intent: intent.into(),
        permit_id: permit_id.into(),
    }
}

#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn race_toc_tou_replacement_is_rejected_by_production_broker() {
    let test_root =
        std::env::temp_dir().join(format!("gocode-security-race-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&test_root).unwrap();
    let broker = Arc::new(FilesystemBroker::new(vec![WorkspaceRoot {
        root_id: "race-root".into(),
        canonical_path: std::fs::canonicalize(&test_root).unwrap(),
        policy: WorkspacePolicy {
            read_allowed: true,
            write_allowed: true,
            create_allowed: true,
            delete_allowed: true,
            symlink_policy: SymlinkPolicy::NoFollow,
        },
    }]));
    let root = broker.open_root("race-root").unwrap();
    let path = CanonicalPath::new("target.txt").unwrap();
    std::fs::write(test_root.join("target.txt"), b"original").unwrap();
    let (_, identity_before) = broker.resolve_and_identity(&root, &path).unwrap();
    let writer_done = Arc::new(Barrier::new(2));
    let writer_barrier = writer_done.clone();
    let writer_root = test_root.clone();
    let writer = async move {
        let replacement = writer_root.join("replacement.tmp");
        std::fs::write(&replacement, b"replacement").unwrap();
        std::fs::rename(replacement, writer_root.join("target.txt")).unwrap();
        writer_barrier.wait().await;
    };
    let checker_barrier = writer_done.clone();
    let checker_broker = broker.clone();
    let checker = async move {
        checker_barrier.wait().await;
        checker_broker.write_with_revalidation(&root, &path, b"mutated", &identity_before)
    };

    let (_, result) = tokio::join!(writer, checker);

    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
    assert_eq!(
        std::fs::read(test_root.join("target.txt")).unwrap(),
        b"replacement"
    );
    std::fs::remove_dir_all(test_root).unwrap();
}

#[tokio::test]
#[cfg(target_os = "windows")]
async fn race_toc_tou_production_broker_fails_closed_before_setup() {
    let test_root =
        std::env::temp_dir().join(format!("gocode-security-race-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&test_root).unwrap();
    let target = test_root.join("target.txt");
    std::fs::write(&target, b"original").unwrap();
    let broker = FilesystemBroker::new(vec![WorkspaceRoot {
        root_id: "race-root".into(),
        canonical_path: std::fs::canonicalize(&test_root).unwrap(),
        policy: WorkspacePolicy {
            read_allowed: true,
            write_allowed: true,
            create_allowed: true,
            delete_allowed: true,
            symlink_policy: SymlinkPolicy::NoFollow,
        },
    }]);

    assert!(matches!(
        broker.open_root("race-root"),
        Err(FsBrokerError::BackendUnavailable)
    ));
    assert_eq!(std::fs::read(&target).unwrap(), b"original");

    std::fs::remove_dir_all(test_root).unwrap();
}

#[tokio::test]
async fn race_dns_redirect_to_private_address_is_rejected() {
    use std::net::{IpAddr, Ipv4Addr};

    let broker = NetworkBroker::new(EgressPolicy {
        allowed_hosts: vec!["example.com".into(), "redirect.example.com".into()],
        deny_private: true,
        deny_loopback: true,
        deny_metadata: true,
        max_redirects: 3,
    });
    let initial = broker
        .resolve_destination(
            NetworkDestination {
                scheme: "https".into(),
                host: "example.com".into(),
                port: 443,
            },
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .unwrap();
    let connection = broker.connect(initial).unwrap();
    let redirect_ready = Arc::new(Barrier::new(2));
    let resolved_addresses = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let dns_barrier = redirect_ready.clone();
    let dns_addresses = resolved_addresses.clone();
    let dns_update = async move {
        *dns_addresses.lock().await = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        dns_barrier.wait().await;
    };
    let redirect_barrier = redirect_ready.clone();
    let redirect_addresses = resolved_addresses.clone();
    let redirect = async move {
        redirect_barrier.wait().await;
        let addresses = redirect_addresses.lock().await.clone();
        broker.follow_redirect(
            &connection,
            NetworkDestination {
                scheme: "https".into(),
                host: "redirect.example.com".into(),
                port: 443,
            },
            addresses,
        )
    };

    let (_, result) = tokio::join!(dns_update, redirect);

    assert!(matches!(
        result,
        Err(NetworkError::RedirectedToPrivateAddress)
    ));
}

#[tokio::test]
async fn race_revocation_wins_over_dispatch() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let dispatch = valid_tx("dispatch-before-revocation", "permit-revoked-grant");
    first_store.commit_pre_effect(&dispatch).unwrap();
    let mut revoked_grant = dispatch.clone();
    revoked_grant.authorization_decision.grant_id = "grant-revoked".into();

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        revoked_grant.clone(),
        second_store,
        revoked_grant,
    )
    .await;

    assert!(matches!(
        first_result,
        Err(AtomicTransactionError::ReplayConflict)
    ));
    assert!(matches!(
        second_result,
        Err(AtomicTransactionError::ReplayConflict)
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_dispatch_commit_wins_before_revocation_and_remains_committed() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let dispatch = valid_tx("intent-before-revoke", "permit-before-revoke");
    first_store.commit_pre_effect(&dispatch).unwrap();

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        dispatch.clone(),
        second_store,
        dispatch,
    )
    .await;

    assert!(first_result.is_ok());
    assert!(second_result.is_ok());
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_cancel_fences_new_dispatch() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let cancelled_run = valid_tx("cancel-run-cancel-first", "run-cancel-first");
    first_store.commit_pre_effect(&cancelled_run).unwrap();

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        valid_tx("dispatch-after-cancel-a", "run-cancel-first"),
        second_store,
        valid_tx("dispatch-after-cancel-b", "run-cancel-first"),
    )
    .await;

    assert!(matches!(
        first_result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert!(matches!(
        second_result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_dispatch_claim_wins_before_cancel_and_new_dispatch_is_fenced() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    first_store
        .commit_pre_effect(&valid_tx("dispatch-first", "run-dispatch-first"))
        .unwrap();

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        valid_tx("cancel-after-dispatch-a", "run-dispatch-first"),
        second_store,
        valid_tx("cancel-after-dispatch-b", "run-dispatch-first"),
    )
    .await;

    assert!(matches!(
        first_result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert!(matches!(
        second_result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_dual_approval_idempotent() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let approval = valid_tx("approval-approval-a", "approval-a");

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        approval.clone(),
        second_store,
        approval,
    )
    .await;

    assert_eq!(first_result, second_result);
    assert!(matches!(
        first_result,
        Ok(PreEffectTransactionOutcome::Committed { ref intent_id }) if intent_id == "approval-approval-a"
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_concurrent_grants_different_ids() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let mut first_grant = valid_tx("grant-a", "permit-grant-a");
    first_grant.authorization_decision.grant_id = "grant-a".into();
    let mut second_grant = valid_tx("grant-b", "permit-grant-b");
    second_grant.authorization_decision.grant_id = "grant-b".into();

    let (first_result, second_result) =
        concurrent_commits(first_store.clone(), first_grant, second_store, second_grant).await;

    assert!(first_result.is_ok());
    assert!(second_result.is_ok());
    assert_eq!(first_store.committed_count().unwrap(), 2);
}

#[tokio::test]
async fn race_concurrent_replay_with_changed_payload_is_rejected() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let original = valid_tx("intent-changed-replay", "permit-changed-replay");
    let mut changed = original.clone();
    changed.authorization_decision.reason = "changed authorization".into();

    let (first_result, second_result) =
        concurrent_commits(first_store.clone(), original, second_store, changed).await;
    let outcomes = [first_result, second_result];

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(AtomicTransactionError::ReplayConflict)))
            .count(),
        1
    );
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_cleanup_before_restart() {
    let pool = Arc::new(tokio::sync::Mutex::new(CleanupPool::new(1)));
    pool.lock()
        .await
        .allocate_for_generation("cleanup-1".into(), Generation::INITIAL)
        .unwrap();
    pool.lock()
        .await
        .release_for_generation("cleanup-1", Generation::INITIAL)
        .unwrap();

    assert_eq!(
        pool.lock().await.reservation("cleanup-1").unwrap().state,
        CleanupState::Released
    );
    assert_eq!(pool.lock().await.available(), 1);
}

#[tokio::test]
async fn race_restart_before_cleanup() {
    let mut pool = CleanupPool::new(1);
    pool.allocate_for_generation("cleanup-2".into(), Generation::INITIAL)
        .unwrap();

    let result = pool.release_for_generation("cleanup-2", Generation::INITIAL.next());

    assert!(matches!(result, Err(CleanupError::StaleGeneration)));
    assert_eq!(pool.available(), 0);
    assert_eq!(
        pool.reservation("cleanup-2").unwrap().state,
        CleanupState::Allocated
    );
}

#[tokio::test]
async fn race_secret_resolve_before_revoke() {
    let mut broker = SecretBroker::new();
    let secret_ref = broker.register("race-secret-1", b"secret-value".to_vec());
    let handle = broker.resolve(&secret_ref, true).unwrap();

    broker.revoke(&secret_ref).unwrap();

    assert_eq!(handle.value().unwrap(), b"secret-value");
    assert!(matches!(
        broker.resolve(&secret_ref, true),
        Err(SecretError::ReferenceRevoked)
    ));
}

#[tokio::test]
async fn race_secret_revoke_before_resolve() {
    let mut broker = SecretBroker::new();
    let secret_ref = broker.register("race-secret-2", b"secret-value".to_vec());

    broker.revoke(&secret_ref).unwrap();
    let result = broker.resolve(&secret_ref, true);

    assert!(matches!(result, Err(SecretError::ReferenceRevoked)));
}
