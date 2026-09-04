use super::task5_fixture::Task5ProductionFixture;
use super::task5_support::*;
use runne_application::provider::ProviderExecutionStore;
use runne_provider::*;
use runne_runtime::provider_execution::{RuntimeProviderExecution, RuntimeProviderExecutionError};
use runne_runtime::provider_redaction::ProviderEventRedactionBoundary;
use runne_store::provider::SqliteProviderRecoveryStore;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn poll_revalidation_preserves_exact_flight_and_rejects_unarmed_cursor() {
    use runne_application::provider::{ProviderExecutionError, ProviderPollRequest};
    let keyring = MemoryKeyring::default();
    let fixture = Task5ProductionFixture::new(&keyring);
    let context = fixture.context();
    let request = ProviderPollRequest {
        attempt_id: fixture.attempt(), fencing_token: context.fencing_token,
        cursor: 0, profile_digest: context.profile_digest, runtime_generation: context.runtime_generation,
    };
    assert_eq!(fixture.execution().revalidate_provider_poll(&request), Err(ProviderExecutionError::PollNotArmed));
    fixture.execution().begin_provider_poll(&request).unwrap();
    let connection = rusqlite::Connection::open(fixture.path()).unwrap();
    let before: i64 = connection.query_row("PRAGMA data_version", [], |row| row.get(0)).unwrap();
    for _ in 0..3 { fixture.execution().revalidate_provider_poll(&request).unwrap(); }
    let wrong_cursor = ProviderPollRequest { cursor: 1, ..request };
    assert_eq!(fixture.execution().revalidate_provider_poll(&wrong_cursor), Err(ProviderExecutionError::SequenceMismatch));
    let after: i64 = connection.query_row("PRAGMA data_version", [], |row| row.get(0)).unwrap();
    assert_eq!(before, after, "revalidation must not commit any database change");
    let (state, flights): (i64, i64) = connection.query_row(
        "SELECT state, (SELECT COUNT(*) FROM provider_poll_flights) FROM provider_dispatch_attempts",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!((state, flights), (3, 1));
}

#[derive(Default)]
struct PendingProvider {
    transport: SecretProvider,
    entered: tokio::sync::Notify,
    dropped: AtomicBool,
}
struct DropWitness<'a>(&'a AtomicBool);
impl Drop for DropWitness<'_> {
    fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
}
impl ProviderPort for PendingProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        self.transport.prepare(call)
    }
    fn prepare_for_digest_version(&self, call: &ProviderCall, version: ProviderCallDigestVersion) -> Result<PreparedRequest, PrepareError> {
        self.transport.prepare_for_digest_version(call, version)
    }
    fn dispatch(&self, request: DispatchRequest) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        self.transport.dispatch(request)
    }
    fn next<'a>(&'a self, stream: &'a ProviderStreamId, cursor: StreamCursor) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async move {
            assert_eq!(*stream, ProviderStreamId::from_bytes([9; 16]));
            assert_eq!(cursor.sequence(), 0);
            let _drop = DropWitness(&self.dropped);
            self.entered.notify_one();
            std::future::pending().await
        })
    }
    fn cancel(&self, request: CancelRequest) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        assert!(self.dropped.load(Ordering::SeqCst), "drop pending read before cancel");
        self.transport.cancel(request)
    }
    fn reconcile(&self, request: ReconcileRequest) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        self.transport.reconcile(request)
    }
}

#[tokio::test]
async fn frozen_pending_poll_is_dropped_and_cancelled_without_event() {
    interrupted_pending_poll(false).await;
}

#[tokio::test]
async fn revoked_credential_interrupts_pending_poll_before_native_delete() {
    interrupted_pending_poll(true).await;
}

async fn interrupted_pending_poll(revoke: bool) {
    let keyring = MemoryKeyring::default();
    let fixture = Task5ProductionFixture::new(&keyring);
    let recovery = SqliteProviderRecoveryStore::open(fixture.path(), [1; 16]).unwrap();
    let tails = SecretTailStore::default();
    let redaction = ProviderEventRedactionBoundary::new(&tails, &recovery, &SecretMatcher);
    let runtime = RuntimeProviderExecution::new(&keyring, fixture.execution(), &FixedPricing, &AllowingGuard, &redaction);
    runtime.use_existing_active_key(fixture.journal_key()).unwrap();
    let provider = PendingProvider::default();
    let freeze = async {
        provider.entered.notified().await;
        if revoke {
            fixture.revoke();
        } else {
            fixture.execution().mark_execution_uncertain(fixture.attempt(), fixture.context().fencing_token).unwrap();
        }
    };
    let observe = async {
        runtime.next_and_commit(&provider, fixture.stream(), StreamCursor::new(0), fixture.context()).await
    };
    let (_, result) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(freeze, observe)
    }).await.expect("frozen pending poll must stop without provider response");
    assert_eq!(result, Err(RuntimeProviderExecutionError::RecoveryFrozen));
    assert!(provider.dropped.load(Ordering::SeqCst));
    assert_eq!(*provider.transport.cancelled.lock().unwrap(), vec![*fixture.stream()]);
    assert!(fixture.execution().load_encrypted_events(fixture.attempt()).unwrap().is_empty());
}
