use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender};

use runne_application::ports::{EventStoreError, LoadedStream, TaskRunEffectsReadSnapshot};
use runne_application::provider::{
    ProviderRemoteAccountingProjection, ProviderRemoteCredentialProjection,
    ProviderRemoteEffectsSnapshot, ProviderRemoteGrantProjection, ProviderRemoteLocalDisposition,
    ProviderRemoteObservationProjection,
};
use runne_runtime::TaskRunEffectsEnricher;

#[derive(Clone)]
struct CompositeEffectsStore {
    inner: StoreTransaction,
    calls: Arc<AtomicUsize>,
    provider_revision: Arc<AtomicUsize>,
    wrong_attempt: bool,
    wrong_taskrun: bool,
    local_projection: bool,
    entered: Arc<Mutex<Option<Sender<()>>>>,
    release: Arc<Mutex<Option<Receiver<()>>>>,
}

impl EventStore for CompositeEffectsStore {
    fn load_task_run(
        &self,
        _: runne_domain::id::TaskRunId,
    ) -> Result<LoadedStream, EventStoreError> {
        panic!("effects query must not split out a TaskRun stream read")
    }

    fn load_task_run_effects(
        &self,
        _: runne_domain::id::TaskRunId,
    ) -> Result<runne_api::TaskRunEffectsV1, EventStoreError> {
        panic!("effects query must use the composite read")
    }

    fn load_task_run_effects_with_remote_authenticator(
        &self,
        id: runne_domain::id::TaskRunId,
        _: Option<&dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
        _: Option<&dyn runne_application::provider::HistoricalProviderModelResolver>,
    ) -> Result<TaskRunEffectsReadSnapshot, EventStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut effects = self.inner.load_task_run_effects(id)?;
        let captured_revision = self.provider_revision.load(Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        if let Some(release) = self.release.lock().unwrap().take() {
            release.recv().unwrap();
        }
        effects.remote.outcome = if captured_revision == 0 {
            runne_api::RemoteEffectOutcomeV1::Unknown
        } else {
            runne_api::RemoteEffectOutcomeV1::Completed
        };
        if self.local_projection {
            effects.local_command = Some(runne_api::LocalCommandEffectV1 {
                outcome: runne_api::LocalCommandOutcomeV1::NotStarted,
                stop: runne_api::LocalCommandStopV1::Unconfirmed,
                exit_code: None,
            });
        }
        let attempt = effects.attempt_id.ok_or(EventStoreError::CorruptData)?;
        let remote = ProviderRemoteEffectsSnapshot {
            binding: binding(
                if self.wrong_taskrun {
                    runne_domain::id::TaskRunId::from_bytes([0xf0; 16])
                } else {
                    id
                },
                if self.wrong_attempt {
                    runne_domain::id::AttemptId::from_bytes([0xf1; 16])
                } else {
                    attempt
                },
            ),
            fact: None,
            observation: ProviderRemoteObservationProjection::NotObserved,
            local_disposition: ProviderRemoteLocalDisposition::Pending,
            accounting: ProviderRemoteAccountingProjection::Unknown,
            secondary_grant: ProviderRemoteGrantProjection::NotSecondary,
            credential: ProviderRemoteCredentialProjection::Ready,
            successor_eligibility: runne_api::SuccessorEligibilityV1::Blocked,
        };
        Ok(TaskRunEffectsReadSnapshot {
            effects,
            remote: Some(remote),
            source1: None,
        })
    }
}

fn binding(
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
) -> runne_application::provider::ProviderRemoteAttemptBinding {
    runne_application::provider::ProviderRemoteAttemptBinding {
        taskrun_id,
        taskrun_attempt_id: attempt_id,
        dispatch_attempt_id: runne_provider::DispatchAttemptId::from_bytes([0xf2; 16]),
        provider_id: "pinned-provider".to_owned(),
        credential_realm: "pinned-provider".to_owned(),
        profile_id: "pinned-profile".to_owned(),
        profile_digest: [0xf3; 32],
        pricing_digest: [0xf4; 32],
        semantic_digest: [0xf5; 32],
        prepared_digest: [0xf6; 32],
        request_digest: [0xf7; 32],
        runtime_authority_id: [0xf8; 16],
        database_generation: 1,
        runtime_generation: 1,
        fencing_token: 1,
    }
}

struct ClosedMetadata(Arc<AtomicUsize>);

impl TaskRunEffectsEnricher for ClosedMetadata {
    fn runtime_metadata(
        &self,
        _: &TaskRunEffectsReadSnapshot,
    ) -> Result<
        Option<(
            runne_api::RemoteEffectAvailabilityV1,
            runne_api::RemoteEffectCapabilitiesV1,
        )>,
        runne_api::TaskRunHostError,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Some((
            runne_api::RemoteEffectAvailabilityV1::Unavailable,
            runne_api::RemoteEffectCapabilitiesV1 {
                status_check: true,
                stream_resume: false,
                remote_cancel: true,
            },
        )))
    }
}

fn composite_store(inner: StoreTransaction) -> CompositeEffectsStore {
    CompositeEffectsStore {
        inner,
        calls: Arc::new(AtomicUsize::new(0)),
        provider_revision: Arc::new(AtomicUsize::new(0)),
        wrong_attempt: false,
        wrong_taskrun: false,
        local_projection: false,
        entered: Arc::new(Mutex::new(None)),
        release: Arc::new(Mutex::new(None)),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn one_composite_read_keeps_same_version_provider_mutations_out_of_its_snapshot() {
    let mut runtime = TestRuntime::start();
    let taskrun_id = create_running_taskrun(&runtime, 40).await;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let mut store = composite_store(runtime.store.clone());
    store.entered = Arc::new(Mutex::new(Some(entered_tx)));
    store.release = Arc::new(Mutex::new(Some(release_rx)));
    let calls = Arc::clone(&store.calls);
    let revision = Arc::clone(&store.provider_revision);
    let metadata_calls = Arc::new(AtomicUsize::new(0));
    let host = RuntimeTaskRunHost::new(runtime.handle.clone(), store)
        .with_effects_enricher(Arc::new(ClosedMetadata(Arc::clone(&metadata_calls))));
    let next_query = host.clone();
    let pending = tokio::spawn(async move { host.get_task_run_effects(taskrun_id).await });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
    revision.store(1, Ordering::SeqCst);
    release_tx.send(()).unwrap();

    let effects = pending.await.unwrap().unwrap();
    assert_eq!(effects.stream_version, 4);
    assert_eq!(
        effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Unknown
    );
    assert_eq!(
        effects.remote.availability,
        runne_api::RemoteEffectAvailabilityV1::Unavailable
    );
    assert!(effects.remote.capabilities.status_check);
    let next = next_query.get_task_run_effects(taskrun_id).await.unwrap();
    assert_eq!(next.stream_version, 4);
    assert_eq!(
        next.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(metadata_calls.load(Ordering::SeqCst), 2);
    runtime.shutdown().await;
}

async fn create_running_taskrun(
    runtime: &TestRuntime,
    sequence: u8,
) -> runne_domain::id::TaskRunId {
    let taskrun_id = runtime
        .host
        .create_task_run(
            command_context(sequence, "effects-create"),
            create_command(),
        )
        .await
        .unwrap()
        .taskrun_id;
    for (offset, operation) in [(1, "queue"), (2, "admit")] {
        let command = ExistingTaskRunCommand {
            taskrun_id,
            expected_version: u64::from(offset),
        };
        if operation == "queue" {
            runtime
                .host
                .queue_task_run(command_context(sequence + offset, operation), command)
                .await
                .unwrap();
        } else {
            runtime
                .host
                .admit_task_run(command_context(sequence + offset, operation), command)
                .await
                .unwrap();
        }
    }
    runtime
        .host
        .start_attempt(
            command_context(sequence + 3, "effects-start"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 3,
            },
        )
        .await
        .unwrap();
    taskrun_id
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_composite_taskrun_or_attempt_is_rejected() {
    let mut runtime = TestRuntime::start();
    let taskrun_id = create_running_taskrun(&runtime, 50).await;
    let metadata_calls = Arc::new(AtomicUsize::new(0));
    for wrong_attempt in [true, false] {
        let mut store = composite_store(runtime.store.clone());
        store.wrong_attempt = wrong_attempt;
        store.wrong_taskrun = !wrong_attempt;
        let calls = Arc::clone(&store.calls);
        let host = RuntimeTaskRunHost::new(runtime.handle.clone(), store)
            .with_effects_enricher(Arc::new(ClosedMetadata(Arc::clone(&metadata_calls))));
        assert_eq!(
            host.get_task_run_effects(taskrun_id).await,
            Err(runne_api::TaskRunHostError::Unavailable)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    assert_eq!(metadata_calls.load(Ordering::SeqCst), 0);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn local_projection_does_not_receive_remote_metadata_overlay() {
    let mut runtime = TestRuntime::start();
    let taskrun_id = create_running_taskrun(&runtime, 60).await;
    let mut store = composite_store(runtime.store.clone());
    store.local_projection = true;
    let metadata_calls = Arc::new(AtomicUsize::new(0));
    let host = RuntimeTaskRunHost::new(runtime.handle.clone(), store)
        .with_effects_enricher(Arc::new(ClosedMetadata(Arc::clone(&metadata_calls))));

    let effects = host.get_task_run_effects(taskrun_id).await.unwrap();
    assert_eq!(
        effects.local_command,
        Some(runne_api::LocalCommandEffectV1 {
            outcome: runne_api::LocalCommandOutcomeV1::NotStarted,
            stop: runne_api::LocalCommandStopV1::Unconfirmed,
            exit_code: None,
        })
    );
    assert_eq!(
        effects.remote.availability,
        runne_api::RemoteEffectAvailabilityV1::Unknown
    );
    assert_eq!(metadata_calls.load(Ordering::SeqCst), 0);
    runtime.shutdown().await;
}
