use runne_api::{ConversationContextScope, CreateConversationInput};
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, RuntimeAuthorityId,
    TextGenerationPhase,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::Actor;
use runne_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
use runne_domain::message::MessageText;
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;
use rusqlite::Connection;
use std::sync::Arc;

#[path = "support/validated_reopen.rs"]
mod validated_reopen;

fn guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn context(suffix: u64, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-{suffix:012}")
            .parse()
            .expect("canonical command ID"),
        idempotency_key: IdempotencyKey::new(key).expect("idempotency key"),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("text-only-integration").expect("actor"),
    }
}

fn ids(suffix: u64) -> (ConversationId, WorkspaceId) {
    (
        format!("018f2e3a-7000-7000-8001-{suffix:012}")
            .parse()
            .expect("canonical conversation ID"),
        format!("018f2e3a-7000-7000-8002-{suffix:012}")
            .parse()
            .expect("canonical workspace ID"),
    )
}

fn database() -> (
    validated_reopen::ValidatedTestDatabase,
    validated_reopen::MainDatabaseIdentity,
    StoreTransaction,
) {
    let file = validated_reopen::ValidatedTestDatabase::new("text-only-generation");
    let (store, identity) = validated_reopen::initialize_store(
        file.path(),
        RuntimeAuthorityId("text-only-generation-integration".into()),
        guard(),
    )
    .expect("initialize store");
    (file, identity, store)
}

fn reopen(
    file: &validated_reopen::ValidatedTestDatabase,
    identity: validated_reopen::MainDatabaseIdentity,
) -> StoreTransaction {
    validated_reopen::reopen_store(
        file.path(),
        identity,
        RuntimeAuthorityId("text-only-generation-integration".into()),
        guard(),
    )
    .expect("reopen validated store")
}

#[test]
fn text_only_generation_survives_duplicate_begin_reopen_and_finish() {
    let (file, identity, store) = database();
    let (conversation_id, workspace_id) = ids(501);
    let authority = RuntimeAuthorityId("text-only-generation-integration".into());
    let create_context = context(502, "create-text-only-generation");
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
                scope: ConversationContextScope::TextOnly,
            },
        )
        .expect("create TextOnly conversation without a workspace row");
    let workspace_exists: bool = Connection::open(file.path())
        .expect("open read connection")
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM workspaces WHERE workspace_id=?1)",
            [workspace_id.as_bytes()],
            |row| row.get(0),
        )
        .expect("check workspace absence");
    assert!(!workspace_exists);

    let generation_context = context(503, "generate-text-only-once");
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("A short test prompt").expect("valid prompt"),
    };
    let started = {
        let service =
            ConversationTextService::new(store.clone(), store.clone(), authority.clone(), guard());
        let started = service
            .begin_text(&generation_context, original.clone())
            .expect("TextOnly begin should commit its user and task-run events");
        assert_eq!(started.phase, TextGenerationPhase::Started);
        assert_eq!(started.conversation_version, 2);
        assert_eq!(started.taskrun_version, 4);
        assert_eq!(
            service
                .begin_text(&generation_context, original.clone())
                .expect("duplicate begin returns the durable receipt"),
            started
        );
        let connection = Connection::open(file.path()).expect("open lineage check connection");
        let text_only_lineage: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM text_only_taskrun_lineage",
                [],
                |row| row.get(0),
            )
            .expect("count TextOnly task-run lineage");
        let workspace_lineage: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM task_run_workspace_lineage",
                [],
                |row| row.get(0),
            )
            .expect("count workspace task-run lineage");
        assert_eq!((text_only_lineage, workspace_lineage), (1, 0));
        started
    };
    drop(store);

    let store = reopen(&file, identity);
    let service =
        ConversationTextService::new(store.clone(), store.clone(), authority.clone(), guard());
    assert_eq!(
        service
            .begin_text(&generation_context, original.clone())
            .expect("reopened duplicate begin returns its durable receipt"),
        started
    );
    let finish_input = FinishConversationTextInput {
        original: original.clone(),
        started: started.clone(),
        completion: ConversationTextCompletion::AssistantText(
            MessageText::new("A short test reply").expect("valid reply"),
        ),
    };
    let finished = service
        .finish_text(&generation_context, finish_input.clone())
        .expect("finish TextOnly generation");
    assert_eq!(finished.phase, TextGenerationPhase::Completed);
    assert_eq!(
        service
            .finish_text(&generation_context, finish_input)
            .expect("duplicate finish returns the durable receipt"),
        finished
    );
    drop(service);
    drop(store);

    let store = reopen(&file, identity);
    let conversation = store
        .load_conversation(conversation_id)
        .expect("reopen completed conversation");
    assert_eq!(conversation.current_version, 3);
    assert_eq!(
        conversation
            .events
            .iter()
            .filter(|event| matches!(
                event.payload(),
                ConversationEvent::AssistantMessageAppended { .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        ConversationTextService::new(store.clone(), store.clone(), authority, guard(),)
            .begin_text(&generation_context, original)
            .expect("completed duplicate remains reconcilable after reopen"),
        finished
    );
}

#[test]
fn workspace_generation_still_rejects_an_unregistered_workspace() {
    let (file, _identity, store) = database();
    let (conversation_id, workspace_id) = ids(601);
    let authority = RuntimeAuthorityId("text-only-generation-integration".into());
    let create_context = context(602, "create-unregistered-workspace-conversation");
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
                scope: ConversationContextScope::Workspace,
            },
        )
        .expect("create canonical conversation stream");

    let generation_context = context(603, "generate-unregistered-workspace");
    let service = ConversationTextService::new(store.clone(), store.clone(), authority, guard());
    assert!(
        service
            .begin_text(
                &generation_context,
                BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("must remain blocked").expect("valid prompt"),
                },
            )
            .is_err()
    );
    let taskrun_streams: i64 = Connection::open(file.path())
        .expect("open read connection")
        .query_row(
            "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type=1",
            [],
            |row| row.get(0),
        )
        .expect("count task-run streams");
    assert_eq!(taskrun_streams, 0);
}
