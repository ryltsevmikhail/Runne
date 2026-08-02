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
use gocode_provider::ProviderFuture;
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use gocode_runtime::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
    CanonicalProviderExecutionService, DeterministicTextProvider, LocalTextProvider,
    LocalTextProviderError, Runtime, RuntimeCanonicalConversationHost, RuntimeTaskRunHost,
};
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;
use tempfile::TempDir;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-00000000000a";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-00000000000b";
const MISSING_TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-0000000000ff";

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

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
    let store =
        StoreTransaction::open(database_path, authority.clone(), available_guard()).unwrap();
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
