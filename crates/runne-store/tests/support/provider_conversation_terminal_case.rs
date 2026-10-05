use super::*;
use rusqlite::Connection;

#[path = "provider_conversation_terminal_case/migration.rs"]
mod migration;

#[test]
fn production_terminal_application_reconstructs_started_command_and_finishes_once() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database = daemon.join("provider-conversation-terminal.sqlite");
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
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let old_projection: (Vec<u8>, Vec<u8>, Vec<u8>) = Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT projection_bytes, projection_digest, snapshot_integrity_digest
             FROM aggregate_state_snapshots WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
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
        application_kind:
            runne_application::provider::ProviderTerminalApplicationKind::TextGeneration,
        outbox_id: [31; 16],
        attempt_id: DispatchAttemptId::from_bytes([32; 16]),
        source: runne_application::provider::ProviderTerminalOutboxSource::StreamJournal,
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
    drop(store);
    migration::verify_v18_migration_integrity(
        &daemon,
        &database,
        conversation_id,
        started.taskrun_id.as_bytes(),
        &old_projection,
    );
}
