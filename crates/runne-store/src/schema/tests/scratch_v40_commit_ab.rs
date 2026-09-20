// SCRATCH DIAGNOSTIC — not for commit.
// Minimal isolation: does commit_conversation fail on a MIGRATED v39→v40
// database that carries NO hand-seeded rows? Empty released-v39 database
// (WAL mode), migrated by the public apply_migrations on the WAL-owning
// connection, clean close, then managed open + workspace seed + commit.

#[cfg(windows)]
#[test]
fn scratch_commit_on_migrated_empty_v39_database() {
    use runne_application::fingerprint::CommandFingerprint;
    use runne_application::ports::ConversationRepository;
    use runne_application::ports::{
        AggregateScope, ConversationCommit, IdempotencyScope, OperationTag, RuntimeAuthorityId,
    };
    use runne_application::ports::ProjectWorkspaceRepository;
    use runne_application::prohibited_content::ProhibitedContentPort;
    use runne_domain::conversation::{Conversation, ConversationContextScope};
    use runne_domain::event::{materialize_batch, Actor, CommandContext};
    use runne_domain::id::{CommandId, ConversationId, EventId, IdempotencyKey, WorkspaceId};
    use runne_security::SecretBroker;

    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    let path = daemon.join("event-log.sqlite");

    // Stage released v39 on a WAL connection, then migrate on the same
    // WAL-owning connection and clean close.
    let staging = rusqlite::Connection::open(&path).unwrap();
    staging.pragma_update(None, "journal_mode", "wal").unwrap();
    apply_migrations_internal(&staging, 39).unwrap();
    assert_eq!(schema_marker(&staging), 39);
    apply_migrations(&staging).unwrap();
    assert_eq!(schema_marker(&staging), 40);
    drop(staging);

    // Managed store on the migrated database.
    let prohibited: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = crate::store::StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId(String::from("scratch-migrated")),
        Arc::clone(&prohibited),
    )
    .unwrap();

    // Workspace seed through the public repository.
    let repository = crate::ProjectWorkspaceStore::from_store(store.clone());
    let conversation: ConversationId =
        "018f2e3a-7000-7000-8000-00000000009d".parse().unwrap();
    let workspace: WorkspaceId =
        "018f2e3a-7000-7000-8000-00000000009e".parse().unwrap();
    repository
        .create_project(
            "scratch-principal",
            CommandId::from_bytes(derived(workspace.into_bytes(), 0xb1)),
            &IdempotencyKey::new(String::from("scratch-project")).unwrap(),
            runne_domain::project_workspace::Project::create(
                runne_domain::id::ProjectId::from_bytes(derived(
                    workspace.into_bytes(),
                    0xa1,
                )),
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new(
                    String::from("Scratch"),
                )
                .unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            "scratch-principal",
            CommandId::from_bytes(derived(workspace.into_bytes(), 0xb2)),
            &IdempotencyKey::new(String::from("scratch-workspace")).unwrap(),
            runne_domain::project_workspace::Workspace::create(
                workspace,
                runne_domain::id::ProjectId::from_bytes(derived(
                    workspace.into_bytes(),
                    0xa1,
                )),
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new(
                    String::from("Scratch workspace"),
                )
                .unwrap(),
            ),
        )
        .unwrap();

    // The checked operation: create a new conversation with an explicit
    // workspace scope through the public commit path.
    let create_event: EventId = "018f2e3a-7000-7000-8000-00000000009f".parse().unwrap();
    let commit = ConversationCommit {
        command_id: CommandId::from_bytes(derived(workspace.into_bytes(), 0xc1)),
        idempotency_key: IdempotencyKey::new(String::from("scratch-create")).unwrap(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: RuntimeAuthorityId(String::from("scratch-migrated")),
            principal_id: runne_application::ports::PrincipalId(String::from(
                "scratch-principal",
            )),
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
                command_id: CommandId::from_bytes(derived(workspace.into_bytes(), 0xc1)),
                idempotency_key: IdempotencyKey::new(String::from("scratch-create")).unwrap(),
                actor: Actor::new(String::from("scratch-actor")).unwrap(),
            },
        )
        .unwrap(),
        workspace_id: workspace,
        context_scope: ConversationContextScope::Workspace,
    };
    let outcome = store.commit_conversation(commit);
    let scope_after = store.conversation_context_scope(conversation);

    println!("==== SCRATCH RESULT ====");
    println!("commit outcome: {outcome:?}");
    println!("scope after: {scope_after:?}");
    println!("==== END SCRATCH RESULT ====");
}

#[cfg(windows)]
fn derived(mut value: [u8; 16], marker: u8) -> [u8; 16] {
    value[14] ^= marker;
    value
}
