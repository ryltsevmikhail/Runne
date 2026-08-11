use std::sync::Arc;

use gocode_api::CreateConversationInput;
use gocode_application::commands::BeginConversationTextInput;
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use gocode_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::provider::{
    ProviderEncryptedPayload, ProviderJournalKeyBinding, ProviderTerminalOutboxRecord,
};
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::Actor;
use gocode_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
use gocode_domain::message::MessageText;
use gocode_provider::{DispatchAttemptId, ProviderCallDigestVersion};
use gocode_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderTerminalConversationResolver,
    ProviderTerminalOutboxApplication,
};
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;

#[path = "support/validated_reopen.rs"]
mod validated_reopen;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("test").unwrap(),
    }
}

#[test]
fn production_terminal_application_reconstructs_started_command_and_finishes_once() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory
        .path()
        .join("provider-conversation-terminal.sqlite");
    let authority = RuntimeAuthorityId("provider-conversation-terminal".into());
    let store = StoreTransaction::open(
        database.to_str().unwrap(),
        authority.clone(),
        available_guard(),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000081".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000082".parse().unwrap();
    validated_reopen::seed_canonical_workspace(&store, "local-owner", workspace_id);
    let create_context = context(
        "018f2e3a-7000-7000-8000-000000000083",
        "create-provider-conversation",
    );
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
            },
        )
        .unwrap();
    let generate_context = context(
        "018f2e3a-7000-7000-8000-000000000084",
        "generate-provider-conversation",
    );
    let service: Arc<dyn ConversationTextCommandService> = Arc::new(ConversationTextService::new(
        store.clone(),
        store.clone(),
        authority,
        available_guard(),
    ));
    let started = service
        .begin_text(
            &generate_context,
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("hello provider").unwrap(),
            },
        )
        .unwrap();
    let record = ProviderTerminalOutboxRecord {
        outbox_id: [31; 16],
        attempt_id: DispatchAttemptId::from_bytes([32; 16]),
        fencing_token: 1,
        principal_id: "local-owner".into(),
        conversation_id,
        taskrun_id: started.taskrun_id,
        execution_attempt_id: started.attempt_id,
        terminal_sequence: 3,
        call_digest_version: ProviderCallDigestVersion::V2,
        key: ProviderJournalKeyBinding::new([33; 16], 1, [34; 16], 1).unwrap(),
        encrypted_output: ProviderEncryptedPayload::new([35; 12], vec![36; 17], 1, [37; 32])
            .unwrap(),
        runtime_generation: 1,
        profile_digest: [38; 32],
        settlement_digest: [39; 32],
        application_idempotency_key: "provider-terminal-attempt-1".into(),
    };
    let recovered = store
        .resolve_provider_terminal_conversation(&record)
        .unwrap();
    assert_eq!(recovered.original.expected_version, 1);
    assert_eq!(recovered.original.text.as_str(), "hello provider");
    assert_eq!(recovered.started, started);

    let application = ConversationProviderTerminalApplication::new(store.clone(), service);
    let first = application
        .complete_provider_terminal(&record, b"provider answer")
        .unwrap();
    let replay = application
        .complete_provider_terminal(&record, b"provider answer")
        .unwrap();
    assert_ne!(first, [0; 32]);
    assert_eq!(replay, first);

    let stream = store.load_conversation(conversation_id).unwrap();
    assert_eq!(stream.current_version, 3);
    assert_eq!(
        stream
            .events
            .iter()
            .filter(|event| matches!(
                event.payload(),
                ConversationEvent::AssistantMessageAppended { .. }
            ))
            .count(),
        1
    );
}
