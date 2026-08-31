#![allow(dead_code)]

use std::sync::Mutex;

use futures::executor::block_on;
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::provider::{ProviderAdmissionError, ProviderCoordinatorRequest};
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{
    DispatchError, DispatchRequest, ModelRef, PrepareError, PreparedRequest, ProviderCall,
    ProviderCallDigestVersion, ProviderCallId, ProviderFuture, ProviderId, ProviderPort,
    ProviderStreamId,
};
use runne_store::provider::{
    CredentialDispatchBinding, PreparedProviderRecord, ProviderCoordinatorOutcome,
    ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
    ProviderRuntimeAuthorityConfig, SqliteProviderCredentialLifecycleStore,
    SqliteProviderDispatchCoordinator, SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};

#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

const MARKER: &str = "serialized-provider-marker";
struct Ready(DispatchRequest);
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

#[derive(Clone, Copy)]
enum Response {
    Stream,
    MaybeDispatched,
}

struct Provider {
    response: Response,
    prepared: Mutex<Vec<ProviderCallDigestVersion>>,
    dispatched: Mutex<usize>,
}

impl Provider {
    fn new(response: Response) -> Self {
        Self {
            response,
            prepared: Mutex::new(Vec::new()),
            dispatched: Mutex::new(0),
        }
    }
}

impl ProviderPort for Provider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        self.prepared
            .lock()
            .unwrap()
            .push(ProviderCallDigestVersion::V2);
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        self.prepared.lock().unwrap().push(version);
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        *self.dispatched.lock().unwrap() += 1;
        let result = match self.response {
            Response::Stream => Ok(ProviderStreamId::from_bytes([9; 16])),
            Response::MaybeDispatched => Err(DispatchError::MaybeDispatched),
        };
        Box::pin(async move { result })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: runne_provider::StreamCursor,
    ) -> ProviderFuture<'a, Result<runne_provider::ProviderStreamItem, runne_provider::StreamError>>
    {
        Box::pin(async { unreachable!("dispatch tests do not poll") })
    }
    fn cancel(
        &self,
        _: runne_provider::CancelRequest,
    ) -> ProviderFuture<'_, Result<runne_provider::CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch tests do not cancel") })
    }
    fn reconcile(
        &self,
        _: runne_provider::ReconcileRequest,
    ) -> ProviderFuture<'_, Result<runne_provider::ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch tests do not reconcile") })
    }
}

impl ProviderEffectPort for Provider {
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

#[derive(Clone, Copy)]
enum GuardMode {
    Allowed,
    Prohibited,
    Unavailable,
}

struct Guard {
    mode: GuardMode,
    saw_marker: Mutex<bool>,
}

impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        assert_eq!(boundary, CanonicalContentBoundary::OutboundDelivery);
        *self.saw_marker.lock().unwrap() = bytes
            .windows(MARKER.len())
            .any(|part| part == MARKER.as_bytes());
        match self.mode {
            GuardMode::Allowed => Ok(ContentDisposition::Allowed { policy_epoch: 1 }),
            GuardMode::Prohibited => Ok(ContentDisposition::Prohibited { policy_epoch: 1 }),
            GuardMode::Unavailable => Err(ContentGuardError::Unavailable),
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
    let database = validated_reopen::ProviderTestDatabase::new("provider-concrete-regressions");
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
            provider_idempotency_key: "concrete-regression".into(),
        },
    )
}

#[test]
fn released_v1_prepared_replay_uses_stored_domain_without_redispatch() {
    let (_directory, dispatch, execution, credential, launch, request) = fixture();
    let v1 =
        PreparedRequest::from_call_for_digest_version(&request.call, ProviderCallDigestVersion::V1)
            .unwrap();
    dispatch
        .persist_prepared(
            &launch,
            &PreparedProviderRecord {
                call_id: request.call.call_id(),
                call_digest_version: ProviderCallDigestVersion::V1,
                prepared_digest: *v1.request_ref().as_bytes(),
                render_digest: *v1.render_digest(),
                profile_digest: [2; 32],
            },
        )
        .unwrap();
    let provider = Provider::new(Response::Stream);
    let guard = Guard {
        mode: GuardMode::Allowed,
        saw_marker: Mutex::new(false),
    };
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
        &provider,
        &provider,
        &guard,
    );
    assert!(matches!(
        block_on(coordinator.dispatch(request.clone())),
        Ok(ProviderCoordinatorOutcome::Streaming { .. })
    ));
    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Ok(ProviderCoordinatorOutcome::Existing { .. })
    ));
    assert_eq!(
        *provider.prepared.lock().unwrap(),
        vec![ProviderCallDigestVersion::V1, ProviderCallDigestVersion::V1]
    );
    assert_eq!(*provider.dispatched.lock().unwrap(), 1);
}

include!("provider_concrete_regressions_parts/maybe_dispatched.rs");

#[path = "support/provider_concrete_regressions_policy_tests.rs"]
mod provider_concrete_regressions_policy_tests;
