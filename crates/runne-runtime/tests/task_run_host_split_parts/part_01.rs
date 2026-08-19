use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use runne_api::{
    ApiActor, ApiPrincipalId, CanonicalMessageText, CanonicalTaskRunState, CanonicalTerminalResult,
    CompleteTaskRunCommand, ConversationCommandContext, ConversationCommandHostPort,
    ConversationHostError, ConversationQueryHostPort, CreateCanonicalConversationCommand,
    CreateTaskRunCommand, ExistingTaskRunCommand, GenerateConversationTextCommand,
    TaskRunCommandAckKind, TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError,
    TaskRunQueryHostPort,
};
use runne_application::commands::{BeginConversationTextInput, FinishConversationTextInput};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService, ConversationTextServiceError,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, EventStore, RuntimeAuthorityId,
    TextGenerationReceipt,
};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::service::TaskRunService;
use runne_domain::conversation::Conversation;
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use runne_domain::message::MessageText;
use runne_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use runne_provider::ProviderFuture;
use runne_runtime::config::RuntimeConfig;
use runne_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use runne_runtime::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
    CanonicalProviderExecutionService, DeterministicTextProvider, LocalTextProvider,
    LocalTextProviderError, Runtime, RuntimeCanonicalConversationHost, RuntimeTaskRunHost,
};
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-00000000000a";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-00000000000b";
const MISSING_TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-0000000000ff";

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

struct TestRuntime {
    _database: validated_reopen::ValidatedTestDatabase,
    database_path: String,
    authority: RuntimeAuthorityId,
    identity: validated_reopen::MainDatabaseIdentity,
    store: StoreTransaction,
    host: RuntimeTaskRunHost<StoreTransaction>,
    controller: RuntimeController,
}

impl TestRuntime {
    fn start() -> Self {
        let database = validated_reopen::ValidatedTestDatabase::new("task-run-host");
        let database_path = database.path().to_owned();
        let authority = RuntimeAuthorityId("canonical-taskrun-test".to_owned());
        let (store, identity) = validated_reopen::initialize_store(
            &database_path,
            authority.clone(),
            available_guard(),
        )
        .unwrap();
        validated_reopen::seed_canonical_workspace(
            &store,
            "local-owner",
            WORKSPACE_ID.parse().unwrap(),
        );
        let (host, controller) = start_runtime(store.clone(), authority.clone());
        Self {
            _database: database,
            database_path,
            authority,
            identity,
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
        assert_eq!(
            self.controller.wait_terminated().await,
            ShutdownOutcome::Quiesced
        );
    }
}

fn start_runtime(
    store: StoreTransaction,
    authority: RuntimeAuthorityId,
) -> (
    RuntimeTaskRunHost<StoreTransaction>,
    RuntimeController,
) {
    let service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority,
    ));
    let (handle, controller) = Runtime::start_borrowed(
        runne_runtime::TokioRuntimeContext::new_for_test(),
        service,
        RuntimeConfig::default(),
    )
    .unwrap();
    let host = RuntimeTaskRunHost::new(handle, store.clone());
    (host, controller)
}

fn command_context(sequence: u8, key: impl Into<String>) -> TaskRunCommandContext {
    TaskRunCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000000{sequence:02x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("runne-cli").unwrap(),
    }
}

fn create_command() -> CreateTaskRunCommand {
    CreateTaskRunCommand {
        conversation_id: CONVERSATION_ID.parse::<ConversationId>().unwrap(),
        workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
    }
}
