use std::sync::Arc;

use runne_api::CreateConversationInput;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, PrincipalId, RuntimeAuthorityId, TextGenerationReceipt,
};
use runne_domain::event::Actor;
use runne_domain::id::IdempotencyKey;
use runne_domain::message::MessageText;
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;

#[allow(
    dead_code,
    reason = "Some integration harnesses need only the started receipt"
)]
pub(crate) struct StartedProviderTaskRun {
    pub(crate) _store: StoreTransaction,
    pub(crate) receipt: TextGenerationReceipt,
}

/// Issues a canonical running text TaskRun through the same application entrypoints as the UI.
#[allow(
    dead_code,
    reason = "Shared fixture entrypoint varies by integration harness"
)]
pub(crate) fn begin(
    database_path: &str,
    runtime_authority: [u8; 16],
    principal: &str,
    text: &str,
) -> StartedProviderTaskRun {
    begin_with_discriminator(database_path, runtime_authority, principal, text, 0x81)
}

/// Issues a distinct canonical running text TaskRun for fixtures that admit
/// several independent provider attempts in one database.
#[allow(
    dead_code,
    reason = "Only online stream fixtures need explicit TaskRun identities"
)]
pub(crate) fn begin_with_discriminator(
    database_path: &str,
    runtime_authority: [u8; 16],
    principal: &str,
    text: &str,
    discriminator: u8,
) -> StartedProviderTaskRun {
    let runtime_authority = RuntimeAuthorityId(compact_hex(&runtime_authority));
    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let (store, _) = super::validated_reopen::initialize_store(
        database_path,
        runtime_authority.clone(),
        guard.clone(),
    )
    .expect("initialize canonical provider TaskRun store");
    let receipt = begin_in_store(
        &store,
        runtime_authority,
        guard,
        principal,
        text,
        discriminator,
    );
    StartedProviderTaskRun {
        _store: store,
        receipt,
    }
}

/// Creates several independent requests on one already-open public store.
/// This avoids reopening a writer after the managed database identity is held.
#[allow(dead_code)]
pub(crate) fn begin_many(
    database_path: &str,
    runtime_authority: [u8; 16],
    principal: &str,
    text: &str,
    discriminators: &[u8],
) -> Vec<TextGenerationReceipt> {
    let runtime_authority = RuntimeAuthorityId(compact_hex(&runtime_authority));
    let guard = Arc::new(SecretBroker::new().prohibited_content_guard());
    let (store, _) = super::validated_reopen::initialize_store(
        database_path,
        runtime_authority.clone(),
        guard.clone(),
    )
    .expect("initialize canonical provider TaskRun store");
    discriminators
        .iter()
        .map(|discriminator| {
            begin_in_store(
                &store,
                runtime_authority.clone(),
                guard.clone(),
                principal,
                text,
                *discriminator,
            )
        })
        .collect()
}

fn begin_in_store(
    store: &StoreTransaction,
    runtime_authority: RuntimeAuthorityId,
    guard: Arc<dyn runne_application::prohibited_content::ProhibitedContentPort>,
    principal: &str,
    text: &str,
    discriminator: u8,
) -> TextGenerationReceipt {
    let conversation_id = id(0x81, discriminator);
    let workspace_id = id(0x82, discriminator);
    super::validated_reopen::seed_canonical_workspace(store, principal, workspace_id);

    let create = command_context(
        principal,
        &id_text(0x83, discriminator),
        &format!("provider-create-{discriminator}"),
    );
    ConversationService::new(store.clone(), store.clone(), runtime_authority.clone())
        .create_from_application(
            &create,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create.command_id,
                idempotency_key: create.idempotency_key.clone(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .expect("create provider test conversation");

    let begin = command_context(
        principal,
        &id_text(0x84, discriminator),
        &format!("provider-begin-{discriminator}"),
    );
    ConversationTextService::new(store.clone(), store.clone(), runtime_authority, guard)
        .begin_text(
            &begin,
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new(text).expect("valid provider test prompt"),
            },
        )
        .expect("begin canonical provider TaskRun")
}

fn id<T>(role: u8, discriminator: u8) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    id_text(role, discriminator).parse().unwrap()
}

fn id_text(role: u8, discriminator: u8) -> String {
    let suffix = (u64::from(role) << 40) | (u64::from(discriminator) << 32) | 1;
    format!("018f2e3a-7000-7000-8000-{suffix:012x}")
}

fn command_context(principal: &str, command_id: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command_id.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId(principal.to_owned()),
        actor: Actor::new("provider-effect-fixture").unwrap(),
    }
}

fn compact_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
