#![allow(dead_code)]

use std::sync::Mutex;

use futures::executor::block_on;
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::provider::ProviderCoordinatorRequest;
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{
    DispatchError, DispatchRequest, ModelRef, PrepareError, PreparedRequest, ProviderCall,
    ProviderCallId, ProviderFuture, ProviderId, ProviderPort, ProviderPreEffectRejection,
    ProviderStreamId,
};
use runne_store::provider::{
    CredentialDispatchBinding, ProviderCoordinatorOutcome, ProviderEffectPort,
    ProviderEffectStartReceipt, ProviderReadyEffect, ProviderRuntimeAuthorityConfig,
    SqliteProviderCredentialLifecycleStore, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

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
        version: runne_provider::ProviderCallDigestVersion,
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
        _cursor: runne_provider::StreamCursor,
    ) -> ProviderFuture<'a, Result<runne_provider::ProviderStreamItem, runne_provider::StreamError>>
    {
        Box::pin(async { unreachable!("dispatch coordinator does not poll") })
    }

    fn cancel(
        &self,
        _request: runne_provider::CancelRequest,
    ) -> ProviderFuture<'_, Result<runne_provider::CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch coordinator does not cancel") })
    }

    fn reconcile(
        &self,
        _request: runne_provider::ReconcileRequest,
    ) -> ProviderFuture<'_, Result<runne_provider::ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch coordinator does not reconcile") })
    }
}

impl ProviderEffectPort for RecordingProvider {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _credential: CredentialDispatchBinding,
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
    validated_reopen::ProviderTestDatabase,
    SqliteProviderDispatchStore,
    SqliteProviderExecutionStore,
    SqliteProviderCredentialLifecycleStore,
    runne_store::provider::ProviderRuntimeLaunchCapability,
    ProviderCoordinatorRequest,
) {
    let database = validated_reopen::ProviderTestDatabase::new("provider-dispatch-coordinator");
    let dispatch = database.dispatch();
    let execution = database.execution();
    let credential = online_credential_fixture::credential(&database, "fixture", 4);
    let launch = execution
        .activate_runtime_launch(&ProviderRuntimeAuthorityConfig {
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
                runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    online_proof::arm(&execution, 1);
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(ProviderId::new("fixture").unwrap(), "model", "2026-08-01").unwrap(),
        [5; 32],
        64,
        serde_json::json!({"marker": MARKER}),
    )
    .unwrap();
    (
        database,
        dispatch,
        execution,
        credential,
        launch,
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
fn adapter_rejection_after_effect_cas_is_durably_uncertain() {
    let (_directory, dispatch, execution, credential, launch, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Rejected);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
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
    let (_directory, dispatch, execution, credential, launch, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Timeout);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
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

#[path = "support/provider_credential_dispatch_tests.rs"]
mod provider_credential_dispatch_tests;
#[path = "support/provider_dispatch_coordinator_persistence_tests.rs"]
mod provider_dispatch_coordinator_persistence_tests;
