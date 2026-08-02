use std::sync::Mutex;

use futures::executor::block_on;
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::provider::ProviderCoordinatorRequest;
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchError, DispatchRequest, ModelRef, PrepareError, PreparedRequest, ProviderCall,
    ProviderCallId, ProviderFuture, ProviderId, ProviderPort, ProviderPreEffectRejection,
    ProviderStreamId,
};
use gocode_store::provider::{
    ProviderCoordinatorOutcome, ProviderEffectPort, ProviderEffectStartReceipt,
    ProviderReadyEffect, ProviderRuntimeAuthorityConfig, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
use rusqlite::Connection;

const MARKER: &str = "provider-boundary-marker";

struct Ready(DispatchRequest);
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

#[derive(Clone, Copy)]
enum ProviderMode {
    Streaming,
    Rejected,
    Timeout,
}

struct RecordingProvider {
    mode: ProviderMode,
    prepared: Mutex<usize>,
    dispatched: Mutex<usize>,
}

impl RecordingProvider {
    fn new(mode: ProviderMode) -> Self {
        Self {
            mode,
            prepared: Mutex::new(0),
            dispatched: Mutex::new(0),
        }
    }

    fn dispatched(&self) -> usize {
        *self.dispatched.lock().unwrap()
    }
}

impl ProviderPort for RecordingProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        *self.prepared.lock().unwrap() += 1;
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: gocode_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        *self.prepared.lock().unwrap() += 1;
        PreparedRequest::from_call_for_digest_version(call, version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        *self.dispatched.lock().unwrap() += 1;
        let outcome = match self.mode {
            ProviderMode::Streaming => Ok(ProviderStreamId::from_bytes([12; 16])),
            ProviderMode::Rejected => Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::AdapterRejected,
            )),
            ProviderMode::Timeout => Err(DispatchError::MaybeDispatched),
        };
        Box::pin(async move { outcome })
    }

    fn next<'a>(
        &'a self,
        _stream_id: &'a ProviderStreamId,
        _cursor: gocode_provider::StreamCursor,
    ) -> ProviderFuture<'a, Result<gocode_provider::ProviderStreamItem, gocode_provider::StreamError>>
    {
        Box::pin(async { unreachable!("dispatch coordinator does not poll") })
    }

    fn cancel(
        &self,
        _request: gocode_provider::CancelRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch coordinator does not cancel") })
    }

    fn reconcile(
        &self,
        _request: gocode_provider::ReconcileRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch coordinator does not reconcile") })
    }
}

impl ProviderEffectPort for RecordingProvider {
    fn stage_effect(
        &self,
        request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move { Ok(Box::new(Ready(request)) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        let ready = ready.into_any().downcast::<Ready>().unwrap();
        self.dispatch(ready.0)
    }
}

struct Guard(bool);

impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        if self.0 {
            Ok(ContentDisposition::Allowed { policy_epoch: 1 })
        } else {
            Ok(ContentDisposition::Prohibited { policy_epoch: 1 })
        }
    }
}

fn fixture() -> (
    tempfile::TempDir,
    SqliteProviderDispatchStore,
    SqliteProviderExecutionStore,
    ProviderCoordinatorRequest,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite");
    let dispatch = SqliteProviderDispatchStore::open(&path).unwrap();
    let execution = SqliteProviderExecutionStore::open(&path).unwrap();
    execution
        .install_runtime_authority(&ProviderRuntimeAuthorityConfig {
            runtime_authority_id: [1; 16],
            database_generation: 1,
            principal_id: "principal".into(),
            owner_id: "owner".into(),
            scope: "provider.dispatch".into(),
            generation: 1,
            fencing_token: 1,
            capability_grant_id: "grant".into(),
            capability_revision: 1,
            capability_allowed: true,
            capability_revocation_epoch: 1,
            approval_id: "approval".into(),
            approval_revision: 1,
            approval_allowed: true,
            approval_revocation_epoch: 1,
            profile_digest: [2; 32],
            pricing_revision_digest: [3; 32],
            activation_binding_kind:
                gocode_application::provider::ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(ProviderId::new("fixture").unwrap(), "model", "2026-08-01").unwrap(),
        [5; 32],
        64,
        serde_json::json!({"marker": MARKER}),
    )
    .unwrap();
    (
        directory,
        dispatch,
        execution,
        ProviderCoordinatorRequest {
            call,
            principal_id: "principal".into(),
            conversation_id: ConversationId::from_bytes([6; 16]),
            taskrun_id: TaskRunId::from_bytes([7; 16]),
            execution_attempt_id: AttemptId::from_bytes([8; 16]),
            profile_digest: [2; 32],
            pricing_revision_digest: [3; 32],
            requested_input_tokens: 32,
            requested_output_tokens: 64,
            max_cost_micros: 10_000,
            currency: "USD".into(),
            provider_idempotency_key: "provider-coordinator".into(),
        },
    )
}

#[test]
fn prohibited_content_stops_prepare_admission_and_dispatch() {
    let (_directory, dispatch, execution, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Streaming);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        &provider,
        &provider,
        &Guard(false),
    );

    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Err(gocode_application::provider::ProviderAdmissionError::PolicyDenied)
    ));
    assert_eq!(*provider.prepared.lock().unwrap(), 0);
    assert_eq!(provider.dispatched(), 0);
    assert_eq!(execution.admitted_count().unwrap(), 0);
}

#[test]
fn sqlite_admission_dispatches_once_and_exact_replay_never_redispaches() {
    let (_directory, dispatch, execution, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Streaming);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        &provider,
        &provider,
        &Guard(true),
    );

    assert!(matches!(
        block_on(coordinator.dispatch(request.clone())),
        Ok(ProviderCoordinatorOutcome::Streaming { .. })
    ));
    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Ok(ProviderCoordinatorOutcome::Existing { .. })
    ));
    assert_eq!(provider.dispatched(), 1);
}

#[test]
fn adapter_rejection_after_effect_cas_is_durably_uncertain() {
    let (_directory, dispatch, execution, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Rejected);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        &provider,
        &provider,
        &Guard(true),
    );

    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Ok(ProviderCoordinatorOutcome::Uncertain)
    ));
    assert_eq!(provider.dispatched(), 1);
}

#[test]
fn timeout_after_effect_cas_is_uncertain_and_exact_replay_does_not_retry() {
    let (_directory, dispatch, execution, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Timeout);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        &provider,
        &provider,
        &Guard(true),
    );
    assert!(matches!(
        block_on(coordinator.dispatch(request.clone())),
        Ok(ProviderCoordinatorOutcome::Uncertain)
    ));
    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Ok(ProviderCoordinatorOutcome::Existing { .. })
    ));
    assert_eq!(provider.dispatched(), 1);
}

#[path = "support/provider_dispatch_coordinator_persistence_tests.rs"]
mod provider_dispatch_coordinator_persistence_tests;
