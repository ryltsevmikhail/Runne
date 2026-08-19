use std::sync::Arc;

use runne_domain::security::Generation;
use runne_security::atomic::{
    AtomicPreEffectTransaction, AtomicTransactionError, AuthorizationDecision,
    PreEffectTransactionOutcome,
};
#[cfg(not(target_os = "windows"))]
use runne_security::broker::fs::CanonicalPath;
use runne_security::broker::fs::{
    FilesystemBroker, FsBrokerError, SymlinkPolicy, WorkspacePolicy, WorkspaceRoot,
};
use runne_security::broker::network::{
    EgressPolicy, NetworkBroker, NetworkDestination, NetworkError,
};
use runne_security::broker::secret::{SecretBroker, SecretError};
use runne_security::cleanup::{CleanupError, CleanupPool, CleanupState};
use runne_store::atomic_pre_effect::SqliteAtomicPreEffectStore;
use tokio::sync::Barrier;

type CommitResult = Result<PreEffectTransactionOutcome, AtomicTransactionError>;

fn shared_sqlite_stores() -> (
    validated_reopen::ValidatedTestDatabase,
    Arc<SqliteAtomicPreEffectStore>,
    Arc<SqliteAtomicPreEffectStore>,
) {
    let database = validated_reopen::ValidatedTestDatabase::new("security-races");
    let identity = validated_reopen::initialize_database_identity(database.path()).unwrap();
    let first = Arc::new(
        SqliteAtomicPreEffectStore::open(std::path::Path::new(database.path())).unwrap(),
    );
    assert!(SqliteAtomicPreEffectStore::open(std::path::Path::new(database.path())).is_err());
    let connection =
        validated_reopen::open_validated_connection(database.path(), identity).unwrap();
    let second = Arc::new(
        SqliteAtomicPreEffectStore::open_with_connection(database.path(), connection).unwrap(),
    );
    (database, first, second)
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
