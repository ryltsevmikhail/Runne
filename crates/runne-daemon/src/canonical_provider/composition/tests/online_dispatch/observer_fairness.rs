use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use runne_application::ports::EventStore;
use runne_application::provider::{ProviderRemoteRecoveryStore, ProviderSecondaryProfileGrantSpec};
use runne_application::service::TaskRunService;
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderFuture, ProviderPort,
    ProviderRecoveryCapabilities, ProviderRecoveryError, ProviderRecoveryOperation,
    ProviderRecoveryRequest, ProviderRemoteCheck, ProviderRemoteResponseStatus, ProviderStreamId,
    ProviderStreamItem, ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunService;
use runne_store::provider::{
    ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
    SqliteProviderExecutionStore,
};

use super::super::command_context;
use super::super::recovery_audit::{Harness, part_08};
mod persist;

struct Ready;

impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

#[derive(Default)]
struct FairObserverEffect {
    execution: Mutex<Option<Arc<SqliteProviderExecutionStore>>>,
    cancel_calls: AtomicUsize,
    status_calls: AtomicUsize,
    first_status_finished: AtomicUsize,
    completed_status_checks: AtomicUsize,
    healthy_candidate_checks: AtomicUsize,
    observed_identities: Mutex<Vec<(String, String)>>,
}

impl ProviderPort for FairObserverEffect {
    fn recovery_capabilities(&self) -> ProviderRecoveryCapabilities {
        ProviderRecoveryCapabilities {
            status_check: true,
            stream_resume: false,
            remote_cancel: true,
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
        Box::pin(async { panic!("observer must never dispatch") })
    }

    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { panic!("observer must never stream") })
    }

    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { panic!("observer must never cancel a local stream") })
    }

    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { panic!("observer must never use generic reconciliation") })
    }

    fn check_remote_status(
        &self,
        request: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        let call = self.status_calls.fetch_add(1, Ordering::SeqCst);
        self.observed_identities.lock().unwrap().push((
            format!("{:?}", request.binding().provider_attempt_id()),
            request.response_id().as_str().to_owned(),
        ));
        let execution = Arc::clone(self.execution.lock().unwrap().as_ref().unwrap());
        let first_status_finished = &self.first_status_finished;
        Box::pin(async move {
            if call == 0 {
                tokio::time::sleep(Duration::from_millis(400)).await;
                first_status_finished.fetch_add(1, Ordering::SeqCst);
                return Err(ProviderRecoveryError::Unavailable);
            }
            let provider_attempt_id = request.binding().provider_attempt_id();
            let Some((intent, response)) = execution
                .load_remote_identity(provider_attempt_id)
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
            let check = ProviderRemoteCheck::new_authorized(
                request.binding(),
                request.response_id().clone(),
                ProviderRemoteResponseStatus::Pending,
                None,
                ProviderRecoveryOperation::StatusCheck,
                proof,
            )
            .map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
            self.completed_status_checks.fetch_add(1, Ordering::SeqCst);
            self.healthy_candidate_checks.fetch_add(1, Ordering::SeqCst);
            Ok(check)
        })
    }

    fn cancel_remote(
        &self,
        _: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        let call = self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if call == 0 {
                tokio::time::sleep(Duration::from_millis(2_750)).await;
                Err(ProviderRecoveryError::Unavailable)
            } else {
                Err(ProviderRecoveryError::Unsupported)
            }
        })
    }
}

impl ProviderEffectPort for FairObserverEffect {
    fn stage_effect(
        &self,
        _: DispatchRequest,
        _: runne_store::provider::CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }

    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { panic!("observer must never dispatch an effect") })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_observer_page_checks_second_saved_attempt_after_slow_first_budget() {
    let harness = Harness::new().await;
    let effect = Arc::new(FairObserverEffect::default());
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
        16_384,
        100_000,
    )
    .unwrap();
    let service = harness
        .try_compose_with_mock_secondary(harness.catalog_for_test(spec), effect.clone(), false)
        .await
        .unwrap();
    let route = service.secondary_profile.as_ref().unwrap();
    *effect.execution.lock().unwrap() = Some(Arc::clone(&service.execution_store));
    let slow = part_08::setup::prepare_with_instance(&harness, &service, route, 0);
    let healthy = part_08::setup::prepare_with_instance(&harness, &service, route, 1);
    persist::persist_saved_identity(&service, route, &slow, "resp_slow_first").await;
    persist::persist_saved_identity(&service, route, &healthy, "resp_healthy_second").await;
    for (index, taskrun_id) in [slow.taskrun_id, healthy.taskrun_id]
        .into_iter()
        .enumerate()
    {
        let version = harness
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version;
        TaskRunService::new(
            harness.store.clone(),
            harness.store.clone(),
            harness.store.clone(),
            harness.authority(),
        )
        .cancel_task_run(
            &command_context(
                &format!("018f2e3a-7000-7000-8000-0000000009{:02x}", index),
                &format!("observer-cancel-{index}"),
            ),
            runne_application::commands::CancelTaskRunInput {
                taskrun_id,
                expected_version: version,
            },
        )
        .unwrap();
    }

    let worker = crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns::new(
        harness.store.clone(),
        Arc::new(TaskRunService::new(
            harness.store.clone(),
            harness.store.clone(),
            harness.store.clone(),
            harness.authority(),
        )),
        harness.text_service(),
        Some(Arc::clone(&service)),
        runne_application::ports::ExecutionNodeId(
            uuid::Uuid::from_bytes(service.runtime_authority_id).to_string(),
        ),
        harness.generation(),
        Arc::new(std::sync::atomic::AtomicU64::new(harness.generation())),
    );
    let started_at = Instant::now();
    let progress = worker
        .observe_saved_remote_page(None, 4)
        .await
        .expect("one bounded observer page");
    assert!(progress.reached_end);
    assert_eq!(progress.unavailable_candidates, 0);
    assert!(progress.next_after.is_some());
    assert_eq!(effect.cancel_calls.load(Ordering::SeqCst), 2);
    assert_eq!(effect.status_calls.load(Ordering::SeqCst), 2);
    assert_eq!(effect.first_status_finished.load(Ordering::SeqCst), 0);
    assert_eq!(effect.completed_status_checks.load(Ordering::SeqCst), 1);
    assert_eq!(effect.healthy_candidate_checks.load(Ordering::SeqCst), 1);
    let observed = effect.observed_identities.lock().unwrap();
    assert_eq!(observed.len(), 2);
    assert_ne!(observed[0].0, observed[1].0);
    assert_ne!(observed[0].1, observed[1].1);
    assert_eq!(
        observed
            .iter()
            .map(|(_, response)| response.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        ["resp_healthy_second", "resp_slow_first"]
            .into_iter()
            .collect()
    );
    drop(observed);
    assert!(started_at.elapsed() < Duration::from_secs(5));
}
