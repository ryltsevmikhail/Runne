use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use futures::executor::block_on;
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::provider::ProviderCoordinatorRequest;
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{
    CancelDisposition, CancelRequest, CredentialFence, DispatchError, DispatchRequest,
    HardFenceProvider, ModelRef, PrepareError, PreparedRequest, ProviderCall, ProviderCallId,
    ProviderCredentialEnrollmentStore, ProviderFuture, ProviderPort, ProviderStreamId,
    ProviderStreamItem, ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};
use rusqlite::Connection;

use super::SqliteProviderExecutionStore;
use super::authority_test_support::{config, configured_connection};
use crate::provider::credential_lifecycle::online_claim_test_support::{
    open_test_store, reopen_test_store,
};
use crate::provider::credential_lifecycle::online_test_support::{complete_pair, provider};
use crate::provider::{
    CredentialDispatchAuthority, CredentialDispatchBinding, ProviderEffectPort,
    ProviderEffectStartReceipt, ProviderReadyEffect, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore,
};

mod forged_evidence;
mod runtime_launch_capability;

struct Ready;
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

#[derive(Default)]
pub(super) struct Effect {
    pub(super) materialized: AtomicUsize,
    dispatched: AtomicUsize,
    pause: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
}

impl Effect {
    pub(super) fn pause_after_stage(&self) -> (Arc<Barrier>, Arc<Barrier>) {
        let reached = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        *self.pause.lock().unwrap() = Some((Arc::clone(&reached), Arc::clone(&release)));
        (reached, release)
    }

    pub(super) fn dispatched_count(&self) -> usize {
        self.dispatched.load(Ordering::SeqCst)
    }
}

impl ProviderPort for Effect {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: runne_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { unreachable!() })
    }
    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
}

impl ProviderEffectPort for Effect {
    fn stage_effect(
        &self,
        _: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        self.materialized.fetch_add(1, Ordering::SeqCst);
        if let Some((reached, release)) = self.pause.lock().unwrap().take() {
            reached.wait();
            release.wait();
        }
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        self.dispatched.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(ProviderStreamId::from_bytes([9; 16])) })
    }
}

pub(super) struct Guard;
impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

#[test]
fn stale_dispatch_fails_before_network_effect() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    secure_directory(directory.path());
    secure_directory(&daemon);
    let path = daemon.join("online-coordinator.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 93, "coordinator-fence");
    let text = path.to_str().unwrap();
    let dispatch =
        SqliteProviderDispatchStore::open_with_connection(text, configured_connection(&path))
            .unwrap();
    let execution =
        SqliteProviderExecutionStore::open_with_connection(text, configured_connection(&path))
            .unwrap();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    super::online_proof_test_support::arm(&execution);
    let effect = Effect::default();
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *effect.pause.lock().unwrap() = Some((Arc::clone(&reached), Arc::clone(&release)));
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        CredentialDispatchAuthority::new(&lifecycle, &launch),
        &effect,
        &effect,
        &Guard,
    );
    let request = ProviderCoordinatorRequest {
        call: ProviderCall::new(
            ProviderCallId::from_bytes([93; 16]),
            ModelRef::new(provider(), "model", "v1").unwrap(),
            [5; 32],
            64,
            serde_json::Value::Null,
        )
        .unwrap(),
        principal_id: "principal-1".into(),
        conversation_id: ConversationId::from_bytes([6; 16]),
        taskrun_id: TaskRunId::from_bytes([7; 16]),
        execution_attempt_id: AttemptId::from_bytes([8; 16]),
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 32,
        requested_output_tokens: 64,
        max_cost_micros: 10_000,
        currency: "USD".into(),
        provider_idempotency_key: "coordinator-fence".into(),
    };
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| block_on(coordinator.dispatch(request)));
        reached.wait();
        let fencing = reopen_test_store(&path, 100);
        ProviderCredentialEnrollmentStore::hard_fence_provider(
            &fencing,
            HardFenceProvider::new(
                provider(),
                CredentialFence::new(2).unwrap(),
                CredentialFence::new(3).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        release.wait();
        assert!(worker.join().unwrap().is_ok());
    });
    assert_eq!(effect.materialized.load(Ordering::SeqCst), 1);
    assert_eq!(effect.dispatched.load(Ordering::SeqCst), 0);
    assert_eq!(online_counts(&path), (0, 0, 0));
}

#[test]
fn stale_dispatch_fails_before_materialization() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    secure_directory(directory.path());
    secure_directory(&daemon);
    let path = daemon.join("stale-online.sqlite");
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
    let effect = Effect::default();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        CredentialDispatchAuthority::new(&lifecycle, &launch),
        &effect,
        &effect,
        &Guard,
    );
    let request = coordinator_request(94, "stale-online");

    assert_eq!(
        block_on(coordinator.dispatch(request)).unwrap(),
        crate::provider::ProviderCoordinatorOutcome::RejectedBeforeEffect {
            reason: runne_provider::ProviderPreEffectRejection::AdapterRejected,
        }
    );
    assert_eq!(effect.materialized.load(Ordering::SeqCst), 0);
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row("SELECT state FROM provider_dispatch_attempts", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        2
    );
}

pub(super) fn coordinator_request(call: u8, key: &str) -> ProviderCoordinatorRequest {
    ProviderCoordinatorRequest {
        call: ProviderCall::new(
            ProviderCallId::from_bytes([call; 16]),
            ModelRef::new(provider(), "model", "v1").unwrap(),
            [5; 32],
            64,
            serde_json::Value::Null,
        )
        .unwrap(),
        principal_id: "principal-1".into(),
        conversation_id: ConversationId::from_bytes([6; 16]),
        taskrun_id: TaskRunId::from_bytes([7; 16]),
        execution_attempt_id: AttemptId::from_bytes([8; 16]),
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 32,
        requested_output_tokens: 64,
        max_cost_micros: 10_000,
        currency: "USD".into(),
        provider_idempotency_key: key.into(),
    }
}

pub(super) fn secure_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn online_counts(path: &std::path::Path) -> (i64, i64, i64) {
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
