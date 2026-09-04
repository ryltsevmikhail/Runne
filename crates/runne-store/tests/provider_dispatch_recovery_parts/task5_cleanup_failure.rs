use super::task5_fixture::Task5ProductionFixture;
use super::task5_support::*;
use runne_provider::StreamCursor;
use runne_runtime::provider_execution::{RuntimeProviderExecution, RuntimeProviderExecutionError};
use runne_runtime::provider_redaction::ProviderEventRedactionBoundary;
use runne_store::provider::SqliteProviderRecoveryStore;

#[tokio::test]
async fn revoked_before_poll_is_durably_frozen_without_provider_read() {
    revoked_before_poll(false).await;
}

#[tokio::test]
async fn failed_pre_poll_freeze_still_cancels_without_claiming_durability() {
    revoked_before_poll(true).await;
}

async fn revoked_before_poll(fail_freeze: bool) {
    let keyring = MemoryKeyring::default();
    let fixture = Task5ProductionFixture::new(&keyring);
    let recovery = SqliteProviderRecoveryStore::open(fixture.path(), [1; 16]).unwrap();
    let tails = SecretTailStore::default();
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &SecretMatcher);
    let runtime = RuntimeProviderExecution::new(&keyring, fixture.execution(), &FixedPricing, &AllowingGuard, &redaction);
    runtime.use_existing_active_key(fixture.journal_key()).unwrap();
    fixture.revoke();
    let connection = rusqlite::Connection::open(fixture.path()).unwrap();
    if fail_freeze {
        connection.execute_batch("CREATE TRIGGER fail_freeze BEFORE UPDATE OF state ON provider_dispatch_attempts WHEN NEW.state=6 BEGIN SELECT RAISE(ABORT, 'injected freeze failure'); END;").unwrap();
    }
    let provider = SecretProvider::default();
    let expected = if fail_freeze { RuntimeProviderExecutionError::JournalCommitLost } else { RuntimeProviderExecutionError::RecoveryFrozen };
    assert_eq!(runtime.next_and_commit(&provider, fixture.stream(), StreamCursor::new(0), fixture.context()).await, Err(expected));
    assert_eq!(provider.polls(), 0);
    assert_eq!(*provider.cancelled.lock().unwrap(), vec![*fixture.stream()]);
    let (state, flights): (i64, i64) = connection.query_row("SELECT state, (SELECT COUNT(*) FROM provider_poll_flights) FROM provider_dispatch_attempts", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!((state, flights), (if fail_freeze { 3 } else { 6 }, 0));
}

#[tokio::test]
async fn failed_poll_admission_freezes_attempt_before_retry() {
    let keyring = MemoryKeyring::default();
    let fixture = Task5ProductionFixture::new(&keyring);
    let recovery = SqliteProviderRecoveryStore::open(fixture.path(), [1; 16]).unwrap();
    let tails = SecretTailStore::default();
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &SecretMatcher);
    let runtime = RuntimeProviderExecution::new(&keyring, fixture.execution(), &FixedPricing, &AllowingGuard, &redaction);
    runtime.use_existing_active_key(fixture.journal_key()).unwrap();
    let connection = rusqlite::Connection::open(fixture.path()).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_poll BEFORE INSERT ON provider_poll_flights BEGIN SELECT RAISE(ABORT, 'injected poll failure'); END;").unwrap();
    let provider = SecretProvider::default();
    assert_eq!(runtime.next_and_commit(&provider, fixture.stream(), StreamCursor::new(0), fixture.context()).await, Err(RuntimeProviderExecutionError::PersistenceUnavailable));
    connection.execute_batch("DROP TRIGGER fail_poll;").unwrap();
    drop(runtime);
    let reopened = fixture.reopened_execution();
    let runtime = RuntimeProviderExecution::new(&keyring, &reopened, &FixedPricing, &AllowingGuard, &redaction);
    runtime.use_existing_active_key(fixture.journal_key()).unwrap();
    assert_eq!(runtime.next_and_commit(&provider, fixture.stream(), StreamCursor::new(0), fixture.context()).await, Err(RuntimeProviderExecutionError::RecoveryFrozen));
    assert_eq!(provider.polls(), 0);
    assert_eq!(*provider.cancelled.lock().unwrap(), vec![*fixture.stream(); 2]);
    let state: i64 = connection.query_row("SELECT state FROM provider_dispatch_attempts", [], |row| row.get(0)).unwrap();
    assert_eq!(state, 6);
}

#[tokio::test]
async fn frozen_attempt_cancels_stream_without_polling() {
    use runne_application::provider::ProviderExecutionStore;
    let keyring = MemoryKeyring::default();
    let fixture = Task5ProductionFixture::new(&keyring);
    let recovery = SqliteProviderRecoveryStore::open(fixture.path(), [1; 16]).unwrap();
    let tails = SecretTailStore::default();
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &SecretMatcher);
    let runtime = RuntimeProviderExecution::new(&keyring, fixture.execution(), &FixedPricing, &AllowingGuard, &redaction);
    runtime.use_existing_active_key(fixture.journal_key()).unwrap();
    fixture.execution().mark_execution_uncertain(fixture.attempt(), fixture.context().fencing_token).unwrap();
    let provider = SecretProvider::default();
    assert_eq!(runtime.next_and_commit(&provider, fixture.stream(), StreamCursor::new(0), fixture.context()).await,
        Err(RuntimeProviderExecutionError::RecoveryFrozen));
    assert_eq!(provider.polls(), 0);
    assert_eq!(*provider.cancelled.lock().unwrap(), vec![*fixture.stream()]);
    assert!(fixture.execution().load_encrypted_events(fixture.attempt()).unwrap().is_empty());
}

#[tokio::test]
async fn adapter_error_cancels_stream_even_if_uncertain_write_fails() {
    for fail_write in [false, true] {
        let keyring = MemoryKeyring::default();
        let fixture = Task5ProductionFixture::new(&keyring);
        let recovery = SqliteProviderRecoveryStore::open(fixture.path(), [1; 16]).unwrap();
        let tails = SecretTailStore::default();
        let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &SecretMatcher);
        let runtime = RuntimeProviderExecution::new(&keyring, fixture.execution(), &FixedPricing, &AllowingGuard, &redaction);
        runtime.use_existing_active_key(fixture.journal_key()).unwrap();
        let connection = rusqlite::Connection::open(fixture.path()).unwrap();
        if fail_write {
            connection.execute_batch(
                "CREATE TRIGGER fail_uncertain_write BEFORE UPDATE OF state ON provider_dispatch_attempts
                 WHEN NEW.state=6 BEGIN SELECT RAISE(ABORT, 'injected uncertain failure'); END;"
            ).unwrap();
        }
        let provider = SecretProvider::failing_stream();
        let expected = if fail_write {
            RuntimeProviderExecutionError::JournalCommitLost
        } else {
            RuntimeProviderExecutionError::AdapterStreamUnavailable
        };
        assert_eq!(runtime.next_and_commit(&provider, fixture.stream(), StreamCursor::new(0), fixture.context()).await, Err(expected));
        assert_eq!(*provider.cancelled.lock().unwrap(), vec![*fixture.stream()]);
        assert_eq!(provider.polls(), 1);
        let (state, journal): (i64, i64) = connection.query_row(
            "SELECT state, (SELECT COUNT(*) FROM provider_stream_journal) FROM provider_dispatch_attempts",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(state, if fail_write { 3 } else { 6 });
        assert_eq!(journal, 0);
    }
}

#[tokio::test]
async fn failed_uncertain_write_still_cancels_uncommitted_stream() {
    let keyring = MemoryKeyring::default();
    let fixture = Task5ProductionFixture::new(&keyring);
    let recovery = SqliteProviderRecoveryStore::open(fixture.path(), [1; 16]).unwrap();
    let tails = SecretTailStore::default();
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &SecretMatcher);
    let runtime = RuntimeProviderExecution::new(&keyring, fixture.execution(), &FixedPricing, &AllowingGuard, &redaction);
    runtime.use_existing_active_key(fixture.journal_key()).unwrap();
    let connection = rusqlite::Connection::open(fixture.path()).unwrap();
    connection.execute_batch(
        "CREATE TRIGGER fail_event_append BEFORE INSERT ON provider_stream_journal
         BEGIN SELECT RAISE(ABORT, 'injected journal failure'); END;
         CREATE TRIGGER fail_uncertain_write BEFORE UPDATE OF state ON provider_dispatch_attempts
         WHEN NEW.state=6 BEGIN SELECT RAISE(ABORT, 'injected uncertain failure'); END;"
    ).unwrap();
    let provider = SecretProvider::default();
    assert_eq!(runtime.next_and_commit(&provider, fixture.stream(), StreamCursor::new(0), fixture.context()).await,
        Err(RuntimeProviderExecutionError::JournalCommitLost));
    assert_eq!(*provider.cancelled.lock().unwrap(), vec![*fixture.stream()]);
    assert_eq!(provider.polls(), 1);
    let journal: i64 = connection.query_row("SELECT COUNT(*) FROM provider_stream_journal", [], |row| row.get(0)).unwrap();
    assert_eq!(journal, 0);
}
