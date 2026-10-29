use runne_api::{ConversationContextScope, CreateConversationInput};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, RuntimeAuthorityId,
};
use runne_domain::{
    event::Actor,
    id::{ConversationId, IdempotencyKey, WorkspaceId},
};
use runne_security::SecretBroker;
use std::sync::Arc;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

#[test]
fn empty_sessions_survive_reopen_with_principal_workspace_paging() {
    let file = validated_reopen::ValidatedTestDatabase::new("conversation-list");
    let authority = RuntimeAuthorityId("conversation-list-tests".into());
    let guard = || {
        Arc::new(SecretBroker::new().prohibited_content_guard())
            as Arc<dyn runne_application::prohibited_content::ProhibitedContentPort>
    };
    let (store, identity) =
        validated_reopen::initialize_store(file.path(), authority.clone(), guard()).unwrap();
    let workspace: WorkspaceId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
    let other: WorkspaceId = "018f2e3a-7000-7000-8000-000000000002".parse().unwrap();
    for (suffix, principal, workspace_id) in [
        (11, "alice", workspace),
        (12, "alice", workspace),
        (13, "bob", workspace),
        (14, "alice", other),
    ] {
        let conversation_id: ConversationId = format!("018f2e3a-7000-7000-8001-{suffix:012}")
            .parse()
            .unwrap();
        let context = ApplicationCommandContext {
            command_id: format!("018f2e3a-7000-7000-8002-{suffix:012}")
                .parse()
                .unwrap(),
            idempotency_key: IdempotencyKey::new(format!("create-{suffix}")).unwrap(),
            principal_id: PrincipalId(principal.into()),
            actor: Actor::new("list-test").unwrap(),
        };
        ConversationService::new(store.clone(), store.clone(), authority.clone())
            .create_from_application(
                &context,
                CreateConversationInput {
                    conversation_id,
                    workspace_id,
                    command_id: context.command_id,
                    idempotency_key: context.idempotency_key.clone(),
                    scope: ConversationContextScope::TextOnly,
                },
            )
            .unwrap();
    }
    drop(store);
    let store = validated_reopen::reopen_store(file.path(), identity, authority, guard()).unwrap();
    let first = store
        .list_conversations(&PrincipalId("alice".into()), workspace, 1, None)
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].1.current_version, 1);
    let second = store
        .list_conversations(&PrincipalId("alice".into()), workspace, 1, Some(first[0].0))
        .unwrap();
    assert_eq!(second.len(), 1);
    assert!(second[0].0 > first[0].0);
    assert!(
        store
            .list_conversations(
                &PrincipalId("alice".into()),
                workspace,
                1,
                Some(second[0].0)
            )
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .list_conversations(&PrincipalId("unknown".into()), workspace, 100, None)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .list_conversations(&PrincipalId("alice".into()), workspace, 102, None)
            .is_err()
    );
}
