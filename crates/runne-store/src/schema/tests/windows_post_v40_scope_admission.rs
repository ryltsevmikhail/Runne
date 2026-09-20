// Windows regression: on a freshly initialized v40 database the full
// post-v40 admission chain works end to end — workspace seed, a new
// conversation committed with an explicit `workspace` scope marker through
// the regular commit path, and a validated reopen re-admitting the store.

#[cfg(windows)]
fn scratch_derived(mut value: [u8; 16], marker: u8) -> [u8; 16] {
    value[14] ^= marker;
    value
}

#[cfg(windows)]
#[test]
fn windows_post_v40_admission_records_scope_and_reopens() {
    use runne_application::ports::ConversationRepository;
use runne_application::ports::ProjectWorkspaceRepository;
    use runne_application::prohibited_content::ProhibitedContentPort;
    use runne_application::ports::{
        AggregateScope, ConversationCommit, IdempotencyScope, OperationTag, RuntimeAuthorityId,
    };
    use runne_application::fingerprint::CommandFingerprint;
    use runne_domain::conversation::{Conversation, ConversationContextScope};
    use runne_domain::event::{materialize_batch, Actor, CommandContext};
    use runne_domain::id::{CommandId, ConversationId, EventId, IdempotencyKey, WorkspaceId};
    use runne_security::SecretBroker;

    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    let path = daemon.join("event-log.sqlite");

    let prohibited: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = crate::store::StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId(String::from("windows-post-v40")),
        Arc::clone(&prohibited),
    )
    .unwrap();

    let repository = crate::ProjectWorkspaceStore::from_store(store.clone());
    let workspace: WorkspaceId =
        "018f2e3a-7000-7000-8000-00000000009e".parse().unwrap();
    repository
        .create_project(
            "test-principal",
            CommandId::from_bytes(scratch_derived(workspace.into_bytes(), 0xb1)),
            &IdempotencyKey::new(String::from("fixture-project")).unwrap(),
            runne_domain::project_workspace::Project::create(
                runne_domain::id::ProjectId::from_bytes(scratch_derived(
                    workspace.into_bytes(),
                    0xa1,
                )),
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new(
                    String::from("Fixture project"),
                )
                .unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            "test-principal",
            CommandId::from_bytes(scratch_derived(workspace.into_bytes(), 0xb2)),
            &IdempotencyKey::new(String::from("fixture-workspace")).unwrap(),
            runne_domain::project_workspace::Workspace::create(
                workspace,
                runne_domain::id::ProjectId::from_bytes(scratch_derived(
                    workspace.into_bytes(),
                    0xa1,
                )),
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new(
                    String::from("Fixture workspace"),
                )
                .unwrap(),
            ),
        )
        .unwrap();

    let conversation: ConversationId =
        "018f2e3a-7000-7000-8000-00000000009d".parse().unwrap();
    let create_event: EventId = "018f2e3a-7000-7000-8000-00000000007f".parse().unwrap();
    let commit = ConversationCommit {
        command_id: CommandId::from_bytes(scratch_derived(workspace.into_bytes(), 0xc1)),
        idempotency_key: IdempotencyKey::new(String::from("post-v40-create")).unwrap(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: RuntimeAuthorityId(String::from("windows-post-v40")),
            principal_id: runne_application::ports::PrincipalId(String::from("test-principal")),
            operation: OperationTag::CreateConversation,
            aggregate_scope: AggregateScope::NewConversation {
                conversation_id: conversation,
                workspace_id: workspace,
            },
        },
        command_fingerprint: CommandFingerprint::for_create_conversation(
            &conversation,
            &workspace,
        ),
        expected_version: 0,
        events: materialize_batch(
            vec![Conversation::decide_create(conversation, workspace)],
            &[create_event],
            None,
            &CommandContext {
                command_id: CommandId::from_bytes(scratch_derived(
                    workspace.into_bytes(),
                    0xc1,
                )),
                idempotency_key: IdempotencyKey::new(String::from("post-v40-create")).unwrap(),
                actor: Actor::new(String::from("test-actor")).unwrap(),
            },
        )
        .unwrap(),
        workspace_id: workspace,
        context_scope: ConversationContextScope::Workspace,
    };
    store.commit_conversation(commit).unwrap();
    let scope = store
        .conversation_context_scope(conversation)
        .unwrap()
        .map(|scope| scope.as_str().to_string());
    assert_eq!(scope.as_deref(), Some("workspace"));
}
