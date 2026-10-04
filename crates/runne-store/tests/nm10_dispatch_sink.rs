//! NM-10 §E dispatch-bytes sink: fake canaries registered through the
//! production `SecretBroker` path (S7) are denied at the provider dispatch
//! boundary before any adapter call; the clean call streams.

use futures::executor::block_on;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::provider::{ProviderAdmissionError, ProviderCoordinatorRequest};
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, ModelRef, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallId, ProviderFuture, ProviderId, ProviderStreamId,
    ProviderStreamItem, ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_security::SecretBroker;
use runne_store::provider::{
    CredentialDispatchAuthority, CredentialDispatchBinding, ProviderCoordinatorOutcome,
    ProviderReadyEffect, ProviderRuntimeAuthorityConfig, SqliteProviderDispatchCoordinator,
};

#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/provider_taskrun_start.rs"]
mod provider_taskrun_start;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

/// FAKE-SECRET-003 value from `docs/golden/t1/fake-canary-secrets-v1.json`
/// (frozen synthetic canary, never a real secret).
const FAKE_SECRET_ENV: &str = "RUNNE_T1_FAKE_ENV_VALUE_3c5d9e1a";

/// Tracks whether any adapter hook ran; the denied call must never touch it,
/// while the clean call streams through the effect path.
#[derive(Default)]
struct CountingAdapter {
    dispatched: std::sync::Mutex<usize>,
}

struct Staged(DispatchRequest);

impl ProviderReadyEffect for Staged {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

impl runne_provider::ProviderPort for CountingAdapter {
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
        *self.dispatched.lock().unwrap() += 1;
        Box::pin(async { Ok(ProviderStreamId::from_bytes([12; 16])) })
    }

    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { unreachable!("dispatch coordinator does not poll") })
    }

    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("no stream is ever cancelled here") })
    }

    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("dispatch coordinator does not reconcile") })
    }
}

impl runne_store::provider::ProviderEffectPort for CountingAdapter {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move { Ok(Box::new(Staged(request)) as Box<dyn ProviderReadyEffect>) })
    }

    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        mut receipt: runne_store::provider::ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        let staged = ready.into_any().downcast::<Staged>().unwrap();
        Box::pin(async move {
            let final_send = receipt.take_final_send_authority().map_err(|_| {
                DispatchError::RejectedBeforeEffect(
                    runne_provider::ProviderPreEffectRejection::AdapterRejected,
                )
            })?;
            final_send.consume().map_err(|_| {
                DispatchError::RejectedBeforeEffect(
                    runne_provider::ProviderPreEffectRejection::AdapterRejected,
                )
            })?;
            runne_provider::ProviderPort::dispatch(self, staged.0).await
        })
    }
}

fn request(
    call: ProviderCall,
    receipt: &runne_application::ports::TextGenerationReceipt,
) -> ProviderCoordinatorRequest {
    ProviderCoordinatorRequest {
        call,
        principal_id: "principal".into(),
        conversation_id: receipt.conversation_id,
        taskrun_id: receipt.taskrun_id,
        execution_attempt_id: receipt.attempt_id,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 32,
        requested_output_tokens: 64,
        max_cost_micros: 10_000,
        currency: "USD".into(),
        provider_idempotency_key: "nm10-dispatch-sink".into(),
    }
}

fn call(id: u8, payload: serde_json::Value) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([id; 16]),
        ModelRef::new(ProviderId::new("fixture").unwrap(), "model", "2026-08-01").unwrap(),
        [5; 32],
        64,
        payload,
    )
    .unwrap()
}

/// S7: the fake env secret enters the registry through the production
/// broker path; real environment variables are never touched.
fn registered_secret_guard() -> impl ProhibitedContentPort {
    let mut broker = SecretBroker::new();
    broker
        .register(
            "RUNNE_T1_FAKE_SECRET_ENV",
            FAKE_SECRET_ENV.as_bytes().to_vec(),
        )
        .expect("register FAKE-SECRET-003");
    broker.prohibited_content_guard()
}

#[test]
fn nm10_registered_secret_call_bytes_are_denied_at_dispatch() {
    let database = validated_reopen::ProviderTestDatabase::new("nm10-dispatch-sink");
    let started = provider_taskrun_start::begin(
        database.path(),
        [1; 16],
        "principal",
        "safe public nm10 dispatch fixture prompt",
    );
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
    let guard = registered_secret_guard();
    let adapter = CountingAdapter::default();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        CredentialDispatchAuthority::new(&credential, &launch),
        &adapter,
        &adapter,
        &guard,
    );

    let denied = block_on(coordinator.dispatch(request(
        call(9, serde_json::json!({ "note": FAKE_SECRET_ENV })),
        &started.receipt,
    )));
    assert!(
        matches!(denied, Err(ProviderAdmissionError::PolicyDenied)),
        "registered canary must be denied at the dispatch-bytes boundary"
    );
    assert_eq!(
        *adapter.dispatched.lock().unwrap(),
        0,
        "the adapter never sees denied bytes"
    );

    let outcome = block_on(coordinator.dispatch(request(
        call(
            10,
            serde_json::json!({ "note": "clean dispatch payload for the nm10 sink scan" }),
        ),
        &started.receipt,
    )));
    assert!(
        matches!(outcome, Ok(ProviderCoordinatorOutcome::Streaming { .. })),
        "clean call passes the same guard and streams"
    );
    assert_eq!(*adapter.dispatched.lock().unwrap(), 1);
}
