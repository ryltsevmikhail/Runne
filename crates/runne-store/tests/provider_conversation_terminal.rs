use runne_api::CreateConversationInput;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, RuntimeAuthorityId,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::provider::{
    ProviderEncryptedPayload, ProviderJournalKeyBinding, ProviderTerminalOutboxRecord,
};
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::Actor;
use runne_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
use runne_domain::message::MessageText;
use runne_provider::{DispatchAttemptId, ProviderCallDigestVersion};
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderTerminalConversationResolver,
    ProviderTerminalOutboxApplication,
};
use runne_security::SecretBroker;
use runne_store::schema::{apply_migrations, apply_migrations_through_v18_for_test};
use runne_store::store::StoreTransaction;
use std::sync::Arc;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;
#[path = "support/x2_historical_schema_fixture/mod.rs"]
mod x2_historical_schema_fixture;
fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn assert_reopen_rejected(database: &std::path::Path) {
    assert!(
        StoreTransaction::open(
            database.to_str().unwrap(),
            RuntimeAuthorityId("provider-conversation-terminal".into()),
            available_guard(),
        )
        .is_err()
    );
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("test").unwrap(),
    }
}

#[path = "support/provider_conversation_terminal_case.rs"]
mod terminal_case;
#[path = "support/provider_conversation_terminal_integrity.rs"]
mod terminal_integrity;
