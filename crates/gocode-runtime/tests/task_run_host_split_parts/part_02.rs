#[tokio::test(flavor = "current_thread")]
async fn maps_idempotency_and_expected_version_conflicts_without_mutation() {
    let mut runtime = TestRuntime::start();
    let created = runtime
        .host
        .create_task_run(command_context(10, "create-conflict"), create_command())
        .await
        .unwrap();
    let taskrun_id = created.taskrun_id;

    runtime
        .host
        .queue_task_run(
            command_context(11, "shared-queue-key"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();

    let idempotency_conflict = runtime
        .host
        .queue_task_run(
            command_context(12, "shared-queue-key"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 3,
            },
        )
        .await;
    assert_eq!(idempotency_conflict, Err(TaskRunHostError::Conflict));

    let stale_version = runtime
        .host
        .admit_task_run(
            command_context(13, "stale-admit"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await;
    assert_eq!(stale_version, Err(TaskRunHostError::Conflict));

    let snapshot = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.state, CanonicalTaskRunState::Queued);
    assert_eq!(snapshot.stream_version, 2);

    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn maps_missing_queries_and_reconstructs_after_store_reopen() {
    let mut runtime = TestRuntime::start();
    let missing = MISSING_TASKRUN_ID.parse::<TaskRunId>().unwrap();
    assert_eq!(
        runtime.host.get_task_run(missing).await,
        Err(TaskRunHostError::NotFound)
    );

    let created = runtime
        .host
        .create_task_run(command_context(20, "create-reopen"), create_command())
        .await
        .unwrap();
    let taskrun_id = created.taskrun_id;
    runtime
        .host
        .queue_task_run(
            command_context(21, "queue-reopen"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();

    runtime.shutdown().await;
    drop(runtime.host);
    drop(runtime.store);

    let (reopened_store, reopened_host, mut reopened_controller) =
        start_runtime(&runtime.database_path, runtime.authority.clone());
    let snapshot = reopened_host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.state, CanonicalTaskRunState::Queued);
    assert_eq!(snapshot.stream_version, 2);
    assert_eq!(snapshot.active_attempt_id, None);
    assert_eq!(snapshot.terminal_result, None);

    let outcome = reopened_controller
        .shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_secs(5),
        })
        .await;
    assert_eq!(outcome, ShutdownOutcome::Quiesced);
    drop(reopened_host);
    drop(reopened_store);
}

const PROVIDER_MARKER: &str = "registered-provider-output";

struct MarkerGuard;

impl ProhibitedContentPort for MarkerGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(
            if bytes
                .windows(PROVIDER_MARKER.len())
                .any(|window| window == PROVIDER_MARKER.as_bytes())
            {
                ContentDisposition::Prohibited { policy_epoch: 1 }
            } else {
                ContentDisposition::Allowed { policy_epoch: 1 }
            },
        )
    }
}

struct ProviderInputRejectingGuard;

impl ProhibitedContentPort for ProviderInputRejectingGuard {
    fn inspect(
        &self,
        boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(match boundary {
            CanonicalContentBoundary::CanonicalMutation => {
                ContentDisposition::Allowed { policy_epoch: 1 }
            }
            CanonicalContentBoundary::OutboundDelivery => {
                ContentDisposition::Prohibited { policy_epoch: 2 }
            }
        })
    }
}

struct CountingConversationTextService {
    inner: ConversationTextService<StoreTransaction, StoreTransaction>,
    finish_calls: Arc<AtomicUsize>,
}

impl ConversationTextCommandService for CountingConversationTextService {
    fn begin_text(
        &self,
        context: &ApplicationCommandContext,
        input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.inner.begin_text(context, input)
    }

    fn finish_text(
        &self,
        context: &ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.finish_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.finish_text(context, input)
    }
}

#[derive(Clone)]
struct MarkerProvider {
    calls: Arc<AtomicUsize>,
}

impl LocalTextProvider for MarkerProvider {
    fn generate(&self, _input: &MessageText) -> Result<MessageText, LocalTextProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        MessageText::new(PROVIDER_MARKER).map_err(|_| LocalTextProviderError::InvalidOutput)
    }
}

fn conversation_context(sequence: u8, key: &str) -> ConversationCommandContext {
    ConversationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000001{sequence:02x}")
            .parse()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("gocode-cli").unwrap(),
    }
}
