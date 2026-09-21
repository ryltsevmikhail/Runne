// Post-migration phase of the single-database scenario: this fragment is
// include!'d from windows_v39_v40_live_wal.rs (a block expression, because
// include! splices exactly one expression) to respect the 300-line physical
// file limit. It seeds a workspace through the public store API, commits a
// NEW conversation with an explicit `workspace` scope, then closes the store
// cleanly, validated-reopens it, and reads both streams back.
{
// A new conversation is created through the regular commit path with an
    // explicit `workspace` scope; its events continue the global sequence
    // (no UNIQUE conflicts with the historical stream).
    let new_workspace: WorkspaceId =
        "018f2e3a-7000-7000-8000-00000000009e".parse().unwrap();
    let new_conversation: ConversationId =
        "018f2e3a-7000-7000-8000-00000000009d".parse().unwrap();
    let repository = crate::ProjectWorkspaceStore::from_store(store.clone());
    repository
        .create_project(
            "test-principal",
            CommandId::from_bytes(derived_bytes(new_workspace.into_bytes(), 0xb1)),
            &IdempotencyKey::new(String::from("fixture-project")).unwrap(),
            runne_domain::project_workspace::Project::create(
                runne_domain::id::ProjectId::from_bytes(derived_bytes(
                    new_workspace.into_bytes(),
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
            CommandId::from_bytes(derived_bytes(new_workspace.into_bytes(), 0xb2)),
            &IdempotencyKey::new(String::from("fixture-workspace")).unwrap(),
            runne_domain::project_workspace::Workspace::create(
                new_workspace,
                runne_domain::id::ProjectId::from_bytes(derived_bytes(
                    new_workspace.into_bytes(),
                    0xa1,
                )),
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new(
                    String::from("Fixture workspace"),
                )
                .unwrap(),
            ),
        )
        .unwrap();
    let create_event: EventId = "018f2e3a-7000-7000-8000-00000000007f".parse().unwrap();
    let commit = ConversationCommit {
        command_id: CommandId::from_bytes(derived_bytes(new_workspace.into_bytes(), 0xc1)),
        idempotency_key: IdempotencyKey::new(String::from("post-v40-create")).unwrap(),
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: RuntimeAuthorityId(String::from("integration-v39-v40")),
            principal_id: runne_application::ports::PrincipalId(String::from("test-principal")),
            operation: OperationTag::CreateConversation,
            aggregate_scope: AggregateScope::NewConversation {
                conversation_id: new_conversation,
                workspace_id: new_workspace,
            },
        },
        command_fingerprint: CommandFingerprint::for_create_conversation(
            &new_conversation,
            &new_workspace,
        ),
        expected_version: 0,
        events: materialize_batch(
            vec![Conversation::decide_create(new_conversation, new_workspace)],
            &[create_event],
            None,
            &CommandContext {
                command_id: CommandId::from_bytes(derived_bytes(
                    new_workspace.into_bytes(),
                    0xc1,
                )),
                idempotency_key: IdempotencyKey::new(String::from("post-v40-create")).unwrap(),
                actor: Actor::new(String::from("test-actor")).unwrap(),
            },
        )
        .unwrap(),
        workspace_id: new_workspace,
        context_scope: ConversationContextScope::Workspace,
    };
    store.commit_conversation(commit).unwrap();
    let new_scope = store
        .conversation_context_scope(new_conversation)
        .unwrap()
        .map(|scope| scope.as_str().to_string());
    assert_eq!(new_scope.as_deref(), Some("workspace"));

    // The single-writer lifecycle: the repository holds an Arc clone of the
    // store, so it must be released first — only then does `drop(store)`
    // perform the clean close that checkpoints and removes the sidecars —
    // and the guarded
    // validated reopen re-admits the database with both streams preserved.
    drop(repository);
    drop(store);
    let reopened = reopen_managed_connection_validated(
        &path,
        ConnectionMode::ValidatedReopen,
        |_| Ok(()),
    )
    .expect("validated reopen must succeed");
    // Global positions continue without gaps or conflicts: the historical
    // event holds position 1 and the new conversation continues at exactly 2.
    let (max_position, conversations): (i64, i64) = reopened
        .query_row(
            "SELECT COALESCE(MAX(global_position), 0), COUNT(DISTINCT aggregate_id)
             FROM events WHERE aggregate_type = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(max_position, 2, "global positions must continue without gaps");
    assert_eq!(conversations, 2);
    drop(reopened);

    let store = crate::store::StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId(String::from("integration-v39-v40")),
        Arc::clone(&prohibited),
    )
    .unwrap();
    let historical = store.load_conversation(conversation_id).unwrap();
    assert_eq!(historical.events.len(), 1, "old stream must be preserved");
    assert_eq!(
        store.conversation_context_scope(conversation_id).unwrap(),
        None,
        "old conversations stay unclassified"
    );
    let created = store.load_conversation(new_conversation).unwrap();
    assert_eq!(created.events.len(), 1, "new stream must be preserved");
    let new_scope_after = store
        .conversation_context_scope(new_conversation)
        .unwrap()
        .map(|scope| scope.as_str().to_string());
    assert_eq!(new_scope_after.as_deref(), Some("workspace"));
}
