//! Shared fixture for the D1.3 append identity readback contract tests.

use std::sync::Arc;

use runne_api::CreateConversationInput;
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextService, ConversationTextServiceError,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, ProjectWorkspaceRepository,
    RuntimeAuthorityId, TextGenerationReceipt,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, IdempotencyKey, MessageId};
use runne_domain::message::MessageText;
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_security::SecretBroker;
use runne_store::ProjectWorkspaceStore;
use runne_store::store::StoreTransaction;

use super::validated_reopen;

pub const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8001-0000000000a1";
pub const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8002-0000000000a2";
pub const PROJECT_ID: &str = "018f2e3a-7000-7000-8002-0000000000a3";
pub const GENERATE_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-0000000000a4";
#[cfg(unix)]
pub const KILL_TEST_NAME: &str =
    "real_sigkill_between_commit_and_ack_preserves_exactly_once_append";

pub fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

pub fn authority() -> RuntimeAuthorityId {
    RuntimeAuthorityId("d13-append-readback".into())
}

pub fn command_context(id: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: id.parse::<CommandId>().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("d13-append-readback").unwrap(),
    }
}

pub fn generate_context() -> ApplicationCommandContext {
    command_context(GENERATE_COMMAND_ID, "d13-append-readback")
}

pub fn database_directory(tag: &str) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join(tag).with_extension("sqlite");
    (directory, path.to_str().unwrap().to_owned())
}

pub fn initialized(
    database_path: &str,
) -> (StoreTransaction, validated_reopen::MainDatabaseIdentity) {
    validated_reopen::initialize_store(database_path, authority(), available_guard()).unwrap()
}

pub fn reopened_store(
    database_path: &str,
    identity: validated_reopen::MainDatabaseIdentity,
) -> StoreTransaction {
    validated_reopen::reopen_store(database_path, identity, authority(), available_guard()).unwrap()
}

pub fn text_service(
    store: &StoreTransaction,
) -> ConversationTextService<StoreTransaction, StoreTransaction> {
    ConversationTextService::new(store.clone(), store.clone(), authority(), available_guard())
}

pub fn seed_conversation(store: &StoreTransaction) {
    let projects = ProjectWorkspaceStore::from_store(store.clone());
    let display = |text: &str| ProjectWorkspaceDisplayName::new(text.into()).unwrap();
    let key = |text: &str| IdempotencyKey::new(text).unwrap();
    let project_command: CommandId = "018f2e3a-7000-7000-8002-0000000000a5".parse().unwrap();
    let workspace_command: CommandId = "018f2e3a-7000-7000-8002-0000000000a6".parse().unwrap();
    let project = Project::create(PROJECT_ID.parse().unwrap(), display("Project"));
    let workspace = Workspace::create(
        WORKSPACE_ID.parse().unwrap(),
        PROJECT_ID.parse().unwrap(),
        display("Workspace"),
    );
    projects
        .create_project(
            "local-owner",
            project_command,
            &key("create-project"),
            project,
        )
        .unwrap();
    projects
        .create_workspace(
            "local-owner",
            workspace_command,
            &key("create-workspace"),
            workspace,
        )
        .unwrap();
    let create_context = command_context(
        "018f2e3a-7000-7000-8000-0000000000a7",
        "create-conversation",
    );
    ConversationService::new(store.clone(), store.clone(), authority())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id: CONVERSATION_ID.parse().unwrap(),
                workspace_id: WORKSPACE_ID.parse().unwrap(),
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
}

pub fn original_input(text: &str) -> BeginConversationTextInput {
    BeginConversationTextInput {
        conversation_id: CONVERSATION_ID.parse().unwrap(),
        expected_version: 1,
        text: MessageText::new(text).unwrap(),
    }
}

pub fn finish_input(text: &str, started: &TextGenerationReceipt) -> FinishConversationTextInput {
    FinishConversationTextInput {
        original: original_input(text),
        started: started.clone(),
        completion: ConversationTextCompletion::AssistantText(
            MessageText::new("assistant answer").unwrap(),
        ),
    }
}

pub fn finish_completed(
    store: &StoreTransaction,
    started: &TextGenerationReceipt,
) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
    text_service(store).finish(&generate_context(), finish_input("hello", started))
}

/// Returns (conversation version, assistant message ids, user message ids).
pub fn conversation_evidence(store: &StoreTransaction) -> (u64, Vec<MessageId>, Vec<MessageId>) {
    let stream = store
        .load_conversation(CONVERSATION_ID.parse().unwrap())
        .unwrap();
    let (mut assistants, mut users) = (Vec::new(), Vec::new());
    for event in &stream.events {
        match event.payload() {
            ConversationEvent::AssistantMessageAppended { message_id, .. } => {
                assistants.push(*message_id);
            }
            ConversationEvent::UserMessageAppended { message_id, .. } => users.push(*message_id),
            _ => {}
        }
    }
    (stream.current_version, assistants, users)
}

pub fn append_counts(store: &StoreTransaction) -> (u64, usize, usize) {
    let (version, assistants, users) = conversation_evidence(store);
    (version, assistants.len(), users.len())
}

pub fn readback(store: &StoreTransaction) -> TextGenerationReceipt {
    let context = generate_context();
    store
        .load_text_generation_receipt_by_command(context.command_id, &context.idempotency_key)
        .unwrap()
}

pub fn receipt_count(database_path: &str) -> i64 {
    rusqlite::Connection::open(database_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM command_receipts", [], |row| {
            row.get(0)
        })
        .unwrap()
}
