use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use gocode_api::{
    ApiActor, ApiPrincipalId, CanonicalMessageText, CanonicalTaskRunState, CanonicalTerminalResult,
    CompleteTaskRunCommand, ConversationCommandContext, ConversationCommandHostPort,
    ConversationHostError, ConversationQueryHostPort, CreateCanonicalConversationCommand,
    CreateTaskRunCommand, ExistingTaskRunCommand, GenerateConversationTextCommand,
    TaskRunCommandAckKind, TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError,
    TaskRunQueryHostPort,
};
use gocode_application::commands::{BeginConversationTextInput, FinishConversationTextInput};
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService, ConversationTextServiceError,
};
use gocode_application::ports::{
    ApplicationCommandContext, ConversationRepository, EventStore, RuntimeAuthorityId,
    TextGenerationReceipt,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::service::TaskRunService;
use gocode_domain::conversation::Conversation;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use gocode_domain::message::MessageText;
use gocode_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use gocode_runtime::{
    LocalTextProvider, LocalTextProviderError, Runtime, RuntimeCanonicalConversationHost,
    RuntimeTaskRunHost,
};
use gocode_store::store::StoreTransaction;
use tempfile::TempDir;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-00000000000a";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-00000000000b";
const MISSING_TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-0000000000ff";

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

struct TestRuntime {
    _directory: TempDir,
    database_path: String,
    authority: RuntimeAuthorityId,
    store: StoreTransaction,
    host: RuntimeTaskRunHost<StoreTransaction>,
    controller: RuntimeController,
}

impl TestRuntime {
    fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory
            .path()
            .join("runtime.sqlite")
            .to_str()
            .unwrap()
            .to_owned();
        let authority = RuntimeAuthorityId("canonical-taskrun-test".to_owned());
        let (store, host, controller) = start_runtime(&database_path, authority.clone());
        Self {
            _directory: directory,
            database_path,
            authority,
            store,
            host,
            controller,
        }
    }

    async fn shutdown(&mut self) {
        let outcome = self
            .controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await;
        assert_eq!(outcome, ShutdownOutcome::Quiesced);
    }
}

fn start_runtime(
    database_path: &str,
    authority: RuntimeAuthorityId,
) -> (
    StoreTransaction,
    RuntimeTaskRunHost<StoreTransaction>,
    RuntimeController,
) {
    let store = StoreTransaction::open(database_path, authority.clone()).unwrap();
    let service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority,
    ));
    let (handle, controller) = Runtime::start_borrowed(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        service,
        RuntimeConfig::default(),
    )
    .unwrap();
    let host = RuntimeTaskRunHost::new(handle, store.clone());
    (store, host, controller)
}

fn command_context(sequence: u8, key: impl Into<String>) -> TaskRunCommandContext {
    TaskRunCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000000{sequence:02x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("gocode-cli").unwrap(),
    }
}

fn create_command() -> CreateTaskRunCommand {
    CreateTaskRunCommand {
        conversation_id: CONVERSATION_ID.parse::<ConversationId>().unwrap(),
        workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn dispatches_and_reconstructs_the_complete_durable_lifecycle() {
    let mut runtime = TestRuntime::start();

    let create_context = command_context(1, "create-1");
    let created = runtime
        .host
        .create_task_run(create_context.clone(), create_command())
        .await
        .unwrap();
    assert_eq!(created.new_version, 1);
    assert_eq!(created.kind, TaskRunCommandAckKind::Created);

    let duplicate = runtime
        .host
        .create_task_run(create_context, create_command())
        .await
        .unwrap();
    assert_eq!(duplicate, created);

    let taskrun_id = created.taskrun_id;
    let queued = runtime
        .host
        .queue_task_run(
            command_context(2, "queue-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(queued.new_version, 2);
    assert_eq!(queued.kind, TaskRunCommandAckKind::Queued);

    let admitted = runtime
        .host
        .admit_task_run(
            command_context(3, "admit-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(admitted.new_version, 3);
    assert_eq!(admitted.kind, TaskRunCommandAckKind::Admitted);

    let started = runtime
        .host
        .start_attempt(
            command_context(4, "attempt-1"),
            ExistingTaskRunCommand {
                taskrun_id,
                expected_version: 3,
            },
        )
        .await
        .unwrap();
    let attempt_id = match started.kind {
        TaskRunCommandAckKind::AttemptStarted { attempt_id } => attempt_id,
        other => panic!("expected attempt acknowledgement, got {other:?}"),
    };
    assert_eq!(started.new_version, 4);
    let running = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(running.state, CanonicalTaskRunState::Running);
    assert_eq!(running.active_attempt_id, Some(attempt_id));

    let completed = runtime
        .host
        .complete_task_run(
            command_context(5, "complete-1"),
            CompleteTaskRunCommand {
                taskrun_id,
                expected_version: 4,
                result: CanonicalTerminalResult::Success,
            },
        )
        .await
        .unwrap();
    assert_eq!(completed.new_version, 5);
    assert_eq!(
        completed.kind,
        TaskRunCommandAckKind::Completed {
            result: CanonicalTerminalResult::Success,
        }
    );

    let snapshot = runtime.host.get_task_run(taskrun_id).await.unwrap();
    assert_eq!(snapshot.taskrun_id, taskrun_id);
    assert_eq!(snapshot.state, CanonicalTaskRunState::Succeeded);
    assert_eq!(snapshot.stream_version, 5);
    assert_eq!(snapshot.active_attempt_id, None);
    assert_eq!(
        snapshot.terminal_result,
        Some(CanonicalTerminalResult::Success)
    );

    let stream = runtime.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(stream.events.len(), 5);
    assert!(
        stream
            .events
            .iter()
            .all(|event| event.actor().as_str() == "gocode-cli")
    );

    runtime.shutdown().await;
}

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

#[tokio::test(flavor = "current_thread")]
async fn prohibited_provider_output_is_rejected_durably_without_an_assistant_message() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory
        .path()
        .join("provider-output-rejection.sqlite")
        .to_str()
        .unwrap()
        .to_owned();
    let authority = RuntimeAuthorityId("provider-output-rejection-test".into());
    let store = StoreTransaction::open(&database_path, authority.clone()).unwrap();
    let taskrun_service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    ));
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(MarkerGuard);
    let text_service: Arc<dyn ConversationTextCommandService> =
        Arc::new(ConversationTextService::new(
            store.clone(),
            store.clone(),
            authority.clone(),
            Arc::clone(&guard),
        ));
    let (handle, mut controller) = Runtime::start_borrowed_with_conversations(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        taskrun_service,
        text_service,
        RuntimeConfig::default(),
    )
    .unwrap();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let host = RuntimeCanonicalConversationHost::new(
        handle,
        Arc::new(ConversationService::new(
            store.clone(),
            store.clone(),
            authority,
        )),
        store.clone(),
        MarkerProvider {
            calls: Arc::clone(&provider_calls),
        },
        guard,
    );
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    let workspace_id: WorkspaceId = WORKSPACE_ID.parse().unwrap();
    host.create_conversation(
        conversation_context(1, "create-provider-rejection"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id,
        },
    )
    .await
    .unwrap();
    let generation_context = conversation_context(2, "generate-provider-rejection");
    let command = GenerateConversationTextCommand {
        conversation_id,
        expected_version: 1,
        text: CanonicalMessageText::new("ordinary user input").unwrap(),
    };

    let first = host
        .generate_text(generation_context.clone(), command.clone())
        .await;
    let duplicate = host.generate_text(generation_context, command).await;

    assert_eq!(first, Err(ConversationHostError::ProviderOutputRejected));
    assert_eq!(
        duplicate,
        Err(ConversationHostError::ProviderOutputRejected)
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert!(!format!("{first:?}").contains(PROVIDER_MARKER));

    let snapshot = host.list_messages(conversation_id).await.unwrap();
    assert_eq!(snapshot.stream_version, 3);
    assert_eq!(snapshot.messages.len(), 1);
    let conversation =
        Conversation::replay(&store.load_conversation(conversation_id).unwrap().events).unwrap();
    assert_eq!(conversation.active_generation(), None);

    let taskrun_id = snapshot.messages[0].taskrun_id;
    let taskrun_stream = store.load_task_run(taskrun_id).unwrap();
    assert!(matches!(
        taskrun_stream.events.last().unwrap().payload(),
        TaskRunEvent::TaskRunFailed { reason } if reason == "provider_output_rejected"
    ));
    assert_eq!(
        TaskRun::replay(&taskrun_stream.events).unwrap().state(),
        TaskRunState::Failed
    );

    assert_eq!(
        controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await,
        ShutdownOutcome::Quiesced
    );
}

#[tokio::test(flavor = "current_thread")]
async fn newly_prohibited_provider_input_is_rejected_before_provider_invocation() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory
        .path()
        .join("provider-input-rejection.sqlite")
        .to_str()
        .unwrap()
        .to_owned();
    let authority = RuntimeAuthorityId("provider-input-rejection-test".into());
    let store = StoreTransaction::open(&database_path, authority.clone()).unwrap();
    let taskrun_service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    ));
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(ProviderInputRejectingGuard);
    let finish_calls = Arc::new(AtomicUsize::new(0));
    let text_service: Arc<dyn ConversationTextCommandService> =
        Arc::new(CountingConversationTextService {
            inner: ConversationTextService::new(
                store.clone(),
                store.clone(),
                authority.clone(),
                Arc::clone(&guard),
            ),
            finish_calls: Arc::clone(&finish_calls),
        });
    let (handle, mut controller) = Runtime::start_borrowed_with_conversations(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        taskrun_service,
        text_service,
        RuntimeConfig::default(),
    )
    .unwrap();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let host = RuntimeCanonicalConversationHost::new(
        handle,
        Arc::new(ConversationService::new(
            store.clone(),
            store.clone(),
            authority,
        )),
        store.clone(),
        MarkerProvider {
            calls: Arc::clone(&provider_calls),
        },
        guard,
    );
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    host.create_conversation(
        conversation_context(3, "create-provider-input-rejection"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse().unwrap(),
        },
    )
    .await
    .unwrap();

    let generation_context = conversation_context(4, "generate-provider-input-rejection");
    let command = GenerateConversationTextCommand {
        conversation_id,
        expected_version: 1,
        text: CanonicalMessageText::new("accepted before policy change").unwrap(),
    };
    let first = host
        .generate_text(generation_context.clone(), command.clone())
        .await;
    let snapshot_after_first = host.list_messages(conversation_id).await.unwrap();
    let duplicate = host.generate_text(generation_context, command).await;

    assert_eq!(first, Err(ConversationHostError::ProhibitedSecretMaterial));
    assert_eq!(
        duplicate,
        Err(ConversationHostError::ProhibitedSecretMaterial)
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(finish_calls.load(Ordering::SeqCst), 1);
    let snapshot = host.list_messages(conversation_id).await.unwrap();
    assert_eq!(snapshot, snapshot_after_first);
    assert_eq!(snapshot.messages.len(), 1);
    assert_eq!(snapshot.stream_version, 3);
    assert_eq!(
        TaskRun::replay(
            &store
                .load_task_run(snapshot.messages[0].taskrun_id)
                .unwrap()
                .events
        )
        .unwrap()
        .state(),
        TaskRunState::Failed
    );

    assert_eq!(
        controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await,
        ShutdownOutcome::Quiesced
    );
}
