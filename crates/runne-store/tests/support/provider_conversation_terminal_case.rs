use super::*;
use rusqlite::Connection;

struct RepairedSnapshot {
    aggregate_type: i64,
    aggregate_id: Vec<u8>,
    codec_version: i64,
    aggregate_version: i64,
    event_sequence: i64,
    head_event_id: Vec<u8>,
    head_integrity_digest: Vec<u8>,
    projection_bytes: Vec<u8>,
    projection_digest: Vec<u8>,
    promotion_codec_version: i64,
    promotion_projection_bytes: Vec<u8>,
    promotion_projection_digest: Vec<u8>,
    head_global_position: i64,
    snapshot_integrity_digest: Vec<u8>,
}

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
    let source_database = database;
    let database = daemon.join("provider-conversation-terminal-v18.sqlite");
    let connection = Connection::open(&database).unwrap();
    apply_migrations_through_v18_for_test(&connection).unwrap();
    x2_historical_schema_fixture::copy_conversation_and_taskrun_history(
        &connection,
        &source_database,
        conversation_id.as_bytes(),
        started.taskrun_id.as_bytes(),
    )
    .unwrap();
    let v50_objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name IN (
                'provider_terminal_dispositions',
                'provider_terminal_dispositions_immutable',
                'provider_terminal_dispositions_no_delete')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(v50_objects, 0, "v18 fixture must not retain v50 objects");
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let connection = Connection::open(&database).unwrap();
    apply_migrations(&connection).unwrap();
    let backfilled: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM aggregate_state_snapshots",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(backfilled, 2);
    let repair_snapshot: RepairedSnapshot = connection
        .query_row(
            "SELECT aggregate_type, aggregate_id, codec_version, aggregate_version,
                    event_sequence, head_event_id, head_integrity_digest, projection_bytes,
                    projection_digest, promotion_codec_version, promotion_projection_bytes,
                    promotion_projection_digest, head_global_position, snapshot_integrity_digest
             FROM aggregate_state_snapshots WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| {
                Ok(RepairedSnapshot {
                    aggregate_type: row.get(0)?,
                    aggregate_id: row.get(1)?,
                    codec_version: row.get(2)?,
                    aggregate_version: row.get(3)?,
                    event_sequence: row.get(4)?,
                    head_event_id: row.get(5)?,
                    head_integrity_digest: row.get(6)?,
                    projection_bytes: row.get(7)?,
                    projection_digest: row.get(8)?,
                    promotion_codec_version: row.get(9)?,
                    promotion_projection_bytes: row.get(10)?,
                    promotion_projection_digest: row.get(11)?,
                    head_global_position: row.get(12)?,
                    snapshot_integrity_digest: row.get(13)?,
                })
            },
        )
        .unwrap();
    let projection_bytes: Vec<u8> = connection
        .query_row(
            "SELECT projection_bytes FROM aggregate_state_snapshots
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let migrated = StoreTransaction::open(
        database.to_str().unwrap(),
        RuntimeAuthorityId("provider-conversation-terminal".into()),
        available_guard(),
    )
    .expect("a valid V18 history backfills to an openable snapshot schema");
    assert_eq!(
        migrated
            .load_conversation(conversation_id)
            .unwrap()
            .current_version,
        3
    );
    drop(migrated);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET projection_bytes = x'00'
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert_reopen_rejected(&database);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET projection_bytes = ?1
             WHERE aggregate_type = 2 AND aggregate_id = ?2",
            rusqlite::params![projection_bytes, conversation_id.as_bytes()],
        )
        .unwrap();
    let snapshot_integrity_digest: Vec<u8> = connection
        .query_row(
            "SELECT snapshot_integrity_digest FROM aggregate_state_snapshots
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET projection_bytes = ?1, projection_digest = ?2,
             snapshot_integrity_digest = ?3 WHERE aggregate_type = 2 AND aggregate_id = ?4",
            rusqlite::params![
                old_projection.0,
                old_projection.1,
                old_projection.2,
                conversation_id.as_bytes()
            ],
        )
        .unwrap();
    drop(connection);
    assert_reopen_rejected(&database);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET snapshot_integrity_digest = zeroblob(32)
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert_reopen_rejected(&database);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET snapshot_integrity_digest = ?1
             WHERE aggregate_type = 2 AND aggregate_id = ?2",
            rusqlite::params![snapshot_integrity_digest, conversation_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM aggregate_state_snapshots WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert_reopen_rejected(&database);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_state_snapshots
             (aggregate_type, aggregate_id, codec_version, aggregate_version, event_sequence,
              head_event_id, head_integrity_digest, projection_bytes, projection_digest,
              promotion_codec_version, promotion_projection_bytes, promotion_projection_digest,
              head_global_position, snapshot_integrity_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            rusqlite::params![
                repair_snapshot.aggregate_type,
                repair_snapshot.aggregate_id,
                repair_snapshot.codec_version,
                repair_snapshot.aggregate_version,
                repair_snapshot.event_sequence,
                repair_snapshot.head_event_id,
                repair_snapshot.head_integrity_digest,
                repair_snapshot.projection_bytes,
                repair_snapshot.projection_digest,
                repair_snapshot.promotion_codec_version,
                repair_snapshot.promotion_projection_bytes,
                repair_snapshot.promotion_projection_digest,
                repair_snapshot.head_global_position,
                repair_snapshot.snapshot_integrity_digest,
            ],
        )
        .unwrap();
    drop(connection);
    let repaired = StoreTransaction::open(
        database.to_str().unwrap(),
        RuntimeAuthorityId("provider-conversation-terminal".into()),
        available_guard(),
    )
    .expect("restoring the valid backfilled snapshot permits reopening");
    let repaired_stream = repaired.load_conversation(conversation_id).unwrap();
    assert_eq!(repaired_stream.current_version, 3);
    assert_eq!(
        repaired_stream
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
