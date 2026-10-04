use super::fixture::*;
pub(in crate::canonical_provider::composition::tests) mod setup;

use runne_application::provider::{ProviderRemoteRecoveryStore, ProviderSecondaryProfileGrantSpec};
use runne_provider::ProviderRecoveryDispatchContextProvider;
use runne_provider::TextProviderProfile;
use runne_provider::*;
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[path = "part_08/capability_metadata.rs"]
mod capability_metadata;

struct Ready;
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

#[derive(Default)]
struct RecoveryEffect {
    execution: Mutex<Option<Arc<runne_store::provider::SqliteProviderExecutionStore>>>,
    creates: AtomicUsize,
    checks: AtomicUsize,
    local_cancels: AtomicUsize,
    remote_cancels: AtomicUsize,
    seen_ids: Mutex<Vec<RemoteResponseId>>,
}

impl ProviderPort for RecoveryEffect {
    fn recovery_capabilities(&self) -> ProviderRecoveryCapabilities {
        ProviderRecoveryCapabilities {
            status_check: true,
            stream_resume: false,
            remote_cancel: false,
        }
    }
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { panic!("saved-ID recovery must not create") })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { panic!("saved-ID recovery must not resume a stream") })
    }
    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        self.local_cancels.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { panic!("no local stream cancellation expected") })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { panic!("no generic reconciliation expected") })
    }
    fn check_remote_status(
        &self,
        request: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        self.seen_ids
            .lock()
            .unwrap()
            .push(request.response_id().clone());
        let execution = self.execution.lock().unwrap().as_ref().unwrap().clone();
        Box::pin(async move {
            let Some((intent, response)) = execution
                .load_remote_identity(request.binding().provider_attempt_id())
                .map_err(|_| ProviderRecoveryError::Unavailable)?
            else {
                return Err(ProviderRecoveryError::InvalidIdentity);
            };
            if response.is_none() {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let proof = execution
                .issue_remote_operation_proof(
                    &intent.binding,
                    request.response_id(),
                    ProviderRecoveryOperation::StatusCheck,
                )
                .map_err(|_| ProviderRecoveryError::Unavailable)?;
            ProviderRemoteCheck::new_authorized(
                request.binding(),
                request.response_id().clone(),
                ProviderRemoteResponseStatus::Pending,
                None,
                ProviderRecoveryOperation::StatusCheck,
                proof,
            )
        })
    }

    fn cancel_remote(
        &self,
        _: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        self.remote_cancels.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(ProviderRecoveryError::Unsupported) })
    }
}

impl ProviderEffectPort for RecoveryEffect {
    fn stage_effect(
        &self,
        _: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { panic!("observer must not dispatch") })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn composed_secondary_observer_routes_saved_id_with_primary_missing() {
    let harness = Harness::new().await;
    let effect = Arc::new(RecoveryEffect::default());
    let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../../docs/profiles/openai-responses-background-text-v1.json"
    ))
    .unwrap();
    let provider = ProviderId::new(profile.provider_id()).unwrap();
    let spec = ProviderSecondaryProfileGrantSpec::new(
        &provider,
        profile.profile_id(),
        profile.provider_id(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        16_384,
        50_000,
    )
    .unwrap();
    let service = harness
        .try_compose_with_mock_secondary(harness.catalog_for_test(spec), effect.clone(), false)
        .await
        .unwrap();
    assert_eq!(
        service.credential_status,
        runne_secure_store::ProviderCredentialStatus::Missing
    );
    let route = service.secondary_profile.as_ref().unwrap();
    assert!(
        route.grant.is_some(),
        "only an active store-issued grant is dispatchable"
    );
    assert_eq!(
        route.credential_status,
        runne_secure_store::ProviderCredentialStatus::Configured
    );
    assert_eq!(
        service.current_provider_readiness(),
        runne_api::ProviderActivationReadinessV1::CredentialMissing
    );
    assert_eq!(
        service.current_secondary_provider_readiness(),
        Some(runne_api::ProviderActivationReadinessV1::Ready)
    );
    *effect.execution.lock().unwrap() = Some(Arc::clone(&service.execution_store));

    let saved = setup::prepare(&harness, &service, route);
    let context_provider =
        runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter::new(
            Arc::clone(&service.keyring),
            Arc::clone(&service.execution_store),
        );
    let context = futures::executor::block_on(context_provider.for_new_dispatch(
        &saved.claim,
        &provider,
        &provider,
        route.profile.profile_id(),
    ))
    .unwrap();
    futures::executor::block_on(context.persist_request(&saved.rendered_request)).unwrap();
    let response_id = RemoteResponseId::new("resp_composed_background_fixture").unwrap();
    futures::executor::block_on(context.commit_response_id(&response_id)).unwrap();

    let page = service.scan_saved_remote_candidates(None, 16).unwrap();
    assert_eq!(page.candidates.len(), 1);
    let outcome = service
        .observe_saved_remote_attempt(saved.taskrun_id, saved.attempt_id)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        super::super::super::super::saved_remote_observe::SavedRemoteObservationOutcome::Pending
    );
    assert_eq!(effect.checks.load(Ordering::SeqCst), 1);
    assert_eq!(effect.creates.load(Ordering::SeqCst), 0);
    assert_eq!(*effect.seen_ids.lock().unwrap(), vec![response_id]);
}
