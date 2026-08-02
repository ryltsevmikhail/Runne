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
