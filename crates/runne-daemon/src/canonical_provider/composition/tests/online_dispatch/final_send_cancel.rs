use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use runne_application::provider::ProviderSecondaryProfileGrantSpec;
use runne_domain::task_run::SelectedProviderProfile;
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderFuture, ProviderPort,
    ProviderPreEffectRejection, ProviderRecoveryCapabilities, ProviderRecoveryError,
    ProviderRecoveryRequest, ProviderRemoteCheck, ProviderStreamId, ProviderStreamItem,
    ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
};

use self::claimed_fixture::claimed_job;
use super::super::recovery_audit::Harness;

mod assert_cancel;
mod claimed_fixture;
mod positive_control;
mod support;
use assert_cancel::assert_cancellation_denies_before_send;
use support::{compose_paused_openai, test_context};

struct Ready;

impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

struct PausedEffect {
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    sends: AtomicUsize,
    consumes: AtomicUsize,
    stages: AtomicUsize,
    attempt: Mutex<Option<runne_provider::DispatchAttemptId>>,
}

impl Default for PausedEffect {
    fn default() -> Self {
        Self {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
            sends: AtomicUsize::new(0),
            consumes: AtomicUsize::new(0),
            stages: AtomicUsize::new(0),
            attempt: Mutex::new(None),
        }
    }
}

impl ProviderPort for PausedEffect {
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
        digest_version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, digest_version)
    }

    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { Err(DispatchError::MaybeDispatched) })
    }

    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { Err(StreamError::NotFound) })
    }

    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { Ok(CancelDisposition::Requested) })
    }

    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }

    fn check_remote_status(
        &self,
        _: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        Box::pin(async { Err(ProviderRecoveryError::Unavailable) })
    }
}

impl ProviderEffectPort for PausedEffect {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        self.stages.fetch_add(1, Ordering::SeqCst);
        *self.attempt.lock().unwrap() = Some(request.attempt_id());
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }

    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        mut receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            let final_send = receipt.take_final_send_authority().map_err(|_| {
                DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
            })?;
            self.entered.notify_one();
            let permit = self
                .release
                .acquire()
                .await
                .map_err(|_| DispatchError::MaybeDispatched)?;
            drop(permit);
            self.consumes.fetch_add(1, Ordering::SeqCst);
            final_send.consume().map_err(|_| {
                DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
            })?;
            self.sends.fetch_add(1, Ordering::SeqCst);
            Err(DispatchError::MaybeDispatched)
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn direct_route_cancellation_before_final_send_consumption_sends_zero() {
    let effect = Arc::new(PausedEffect::default());
    let (harness, service) = compose_paused_openai(effect.clone()).await;
    let (job, _) = claimed_job(&harness, &service, None, 0xA0);
    assert_cancellation_denies_before_send(&harness, &service, job, None, None, effect).await;
}

#[tokio::test(flavor = "current_thread")]
async fn claimed_route_cancellation_before_final_send_consumption_sends_zero() {
    let effect = Arc::new(PausedEffect::default());
    let (harness, service) = compose_paused_openai(effect.clone()).await;
    let (job, assignment) = claimed_job(&harness, &service, None, 0xA1);
    assert_cancellation_denies_before_send(&harness, &service, job, Some(assignment), None, effect)
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn secondary_route_cancellation_before_final_send_consumption_sends_zero() {
    let harness = Harness::new().await;
    let effect = Arc::new(PausedEffect::default());
    let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../../docs/profiles/openai-responses-background-text-v1.json"
    ))
    .unwrap();
    let provider = runne_provider::ProviderId::new(profile.provider_id()).unwrap();
    let spec = ProviderSecondaryProfileGrantSpec::new(
        &provider,
        profile.profile_id(),
        profile.provider_id(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        u64::try_from(profile.max_input_bytes()).unwrap() + u64::from(profile.max_output_tokens()),
        profile
            .price_usage_micros(
                runne_provider::ProviderUsage::new(
                    u64::try_from(profile.max_input_bytes()).unwrap(),
                    u64::from(profile.max_output_tokens()),
                    0,
                    0,
                )
                .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let service = harness
        .try_compose_with_mock_secondary(harness.catalog_for_test(spec), effect.clone(), false)
        .await
        .unwrap();
    let selected =
        SelectedProviderProfile::new(profile.profile_id().to_owned(), profile.profile_digest())
            .unwrap();
    let (job, assignment) = claimed_job(&harness, &service, Some(selected.clone()), 0xA2);
    assert_cancellation_denies_before_send(
        &harness,
        &service,
        job,
        Some(assignment),
        Some(selected),
        effect,
    )
    .await;
}
