use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use gocode_application::commands::{BeginConversationTextInput, FinishConversationTextInput};
use gocode_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextServiceError,
};
use gocode_application::ports::{
    ApplicationCommandContext, PrincipalId, RuntimeAuthorityId, TextGenerationPhase,
    TextGenerationReceipt,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::service::TaskRunService;
use gocode_domain::event::Actor;
use gocode_domain::id::{
    AttemptId, ConversationId, IdempotencyKey, MessageId, TaskRunId, WorkspaceId,
};
use gocode_domain::message::MessageText;
use gocode_provider::ProviderFuture;
use gocode_runtime::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
    CanonicalProviderExecutionService,
};
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{ShutdownMode, ShutdownOutcome};
use gocode_runtime::{Runtime, TokioRuntimeContext};
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;
use tokio::sync::Notify;

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

struct UnusedConversationService;

impl ConversationTextCommandService for UnusedConversationService {
    fn begin_text(
        &self,
        _context: &ApplicationCommandContext,
        _input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        unreachable!("provider job test does not call begin")
    }

    fn finish_text(
        &self,
        _context: &ApplicationCommandContext,
        _input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        unreachable!("provider job test does not call finish")
    }
}

struct ControlledProviderService {
    started: Notify,
    release: Notify,
    calls: AtomicUsize,
    completed: AtomicUsize,
}

impl CanonicalProviderExecutionService for ControlledProviderService {
    fn execute(
        &self,
        mut job: CanonicalProviderExecutionJob,
    ) -> ProviderFuture<'_, Result<TextGenerationReceipt, CanonicalProviderExecutionError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            self.release.notified().await;
            job.started.phase = TextGenerationPhase::Completed;
            job.started.conversation_version += 1;
            job.started.taskrun_version += 1;
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(job.started)
        })
    }
}

fn job(seed: u8) -> CanonicalProviderExecutionJob {
    CanonicalProviderExecutionJob {
        context: ApplicationCommandContext {
            command_id: format!("018f2e3a-7000-7000-8000-0000000000{seed:02x}")
                .parse()
                .unwrap(),
            idempotency_key: IdempotencyKey::new(format!("provider-job-{seed}")).unwrap(),
            principal_id: PrincipalId("local-owner".into()),
            actor: Actor::new("test").unwrap(),
        },
        original: BeginConversationTextInput {
            conversation_id: ConversationId::from_bytes([seed; 16]),
            expected_version: 1,
            text: MessageText::new("hello").unwrap(),
        },
        started: TextGenerationReceipt {
            phase: TextGenerationPhase::Started,
            conversation_id: ConversationId::from_bytes([seed; 16]),
            workspace_id: WorkspaceId::from_bytes([seed.wrapping_add(1); 16]),
            taskrun_id: TaskRunId::from_bytes([seed.wrapping_add(2); 16]),
            attempt_id: AttemptId::from_bytes([seed.wrapping_add(3); 16]),
            user_message_id: MessageId::from_bytes([seed.wrapping_add(4); 16]),
            assistant_message_id: MessageId::from_bytes([seed.wrapping_add(5); 16]),
            conversation_version: 2,
            taskrun_version: 4,
        },
    }
}

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn test_database_path(directory: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
    let runtime = directory.path().join("runtime");
    let daemon = runtime.join("gocode-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    daemon.join(name)
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_owns_provider_job_after_local_waiter_is_cancelled_and_drains_on_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let database = test_database_path(&directory, "canonical-provider.sqlite");
    let authority = RuntimeAuthorityId("canonical-provider-test".into());
    let store = StoreTransaction::open(
        database.to_str().unwrap(),
        authority.clone(),
        available_guard(),
    )
    .unwrap();
    let task_service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store,
        authority,
    ));
    let provider = Arc::new(ControlledProviderService {
        started: Notify::new(),
        release: Notify::new(),
        calls: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
    });
    let (handle, mut controller) = Runtime::start_borrowed_with_provider_conversations(
        TokioRuntimeContext::new_for_test(),
        task_service,
        Arc::new(UnusedConversationService),
        provider.clone(),
        RuntimeConfig::default(),
    )
    .unwrap();

    let waiter_handle = handle.clone();
    let waiter =
        tokio::spawn(async move { waiter_handle.execute_canonical_provider(job(11)).await });
    provider.started.notified().await;
    waiter.abort();
    provider.release.notify_one();

    assert_eq!(
        controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await,
        ShutdownOutcome::Quiesced
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.completed.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn global_in_flight_limit_is_held_until_provider_job_replies() {
    let directory = tempfile::tempdir().unwrap();
    let database = test_database_path(&directory, "canonical-provider-limit.sqlite");
    let authority = RuntimeAuthorityId("canonical-provider-limit-test".into());
    let store = StoreTransaction::open(
        database.to_str().unwrap(),
        authority.clone(),
        available_guard(),
    )
    .unwrap();
    let task_service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store,
        authority,
    ));
    let provider = Arc::new(ControlledProviderService {
        started: Notify::new(),
        release: Notify::new(),
        calls: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
    });
    let config = RuntimeConfig {
        max_in_flight_requests: 1,
        ..RuntimeConfig::default()
    };
    let (handle, mut controller) = Runtime::start_borrowed_with_provider_conversations(
        TokioRuntimeContext::new_for_test(),
        task_service,
        Arc::new(UnusedConversationService),
        provider.clone(),
        config,
    )
    .unwrap();

    let first_handle = handle.clone();
    let first = tokio::spawn(async move { first_handle.execute_canonical_provider(job(21)).await });
    provider.started.notified().await;
    let second_handle = handle.clone();
    let second =
        tokio::spawn(async move { second_handle.execute_canonical_provider(job(22)).await });
    tokio::task::yield_now().await;
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

    provider.release.notify_one();
    first.await.unwrap().unwrap();
    provider.started.notified().await;
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    provider.release.notify_one();
    second.await.unwrap().unwrap();

    assert_eq!(
        controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await,
        ShutdownOutcome::Quiesced
    );
}
