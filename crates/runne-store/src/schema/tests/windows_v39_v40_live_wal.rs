// Windows regression: the released v39 → v40 migration under a live WAL,
// followed by guarded managed access (owner-private hot reader and validated
// reopen), with a REAL pre-v40 conversation stream built through the
// historical codec (`Conversation::decide_create` → `materialize_batch` →
// `ConversationEventCodec` → the store's own profile-2 digest function),
// all on ONE database.
//
// Lifecycle fidelity: the v39 schema is staged on a plain connection in WAL
// mode; the upgrade runs through the public `apply_migrations` on the
// WAL-owning connection (its own Exclusive transaction and trailing
// `wal_checkpoint(FULL)`); the hot reader is admitted while the sidecars
// are still live; the sidecar reaches its documented end of life by the
// clean close; a second concurrent writer is refused with the exact typed
// `SidecarPresent` diagnostic while the sidecars are live.
//
// Contract: pre-v40 conversations keep their durable events but gain NO
// context-scope marker — unknown provenance stays denied, nothing is
// backfilled into `text_only`.

#[cfg(windows)]
fn derived_bytes(mut value: [u8; 16], marker: u8) -> [u8; 16] {
    value[14] ^= marker;
    value
}

#[cfg(windows)]
#[test]
fn windows_v39_to_v40_migration_preserves_live_wal_conversations_without_scope_backfill() {
    use runne_application::fingerprint::CommandFingerprint;
    use crate::codec::StoreCodec;
    use runne_application::ports::ConversationRepository;
    use runne_application::ports::ProjectWorkspaceRepository;
    use runne_application::ports::RuntimeAuthorityId;
    use runne_application::ports::{
        AggregateScope, ConversationCommit, IdempotencyScope, OperationTag,
    };
    use runne_application::prohibited_content::ProhibitedContentPort;
    use runne_domain::conversation::{Conversation, ConversationContextScope, ConversationEvent};
    use runne_domain::event::{materialize_batch, Actor, CommandContext};
    use runne_domain::id::{
        AggregateId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest,
        WorkspaceId,
    };
    use runne_domain::timestamp::Timestamp;
    use runne_security::SecretBroker;

    const CORRELATION_TYPE_CONVERSATION: i64 = 2;
    const INTEGRITY_PROFILE_V2: i64 = 2;

    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    let path = daemon.join("event-log.sqlite");

    // Stage the released v39 schema on a raw connection in WAL mode and seed
    // a real pre-v40 conversation stream through the historical codec.
    let staging = Connection::open(&path).unwrap();
    staging.pragma_update(None, "journal_mode", "wal").unwrap();
    apply_migrations_internal(&staging, 39).unwrap();
    assert_eq!(schema_marker(&staging), 39);
    let conversation_id: ConversationId =
        "018f2e3a-7000-7000-8000-00000000007a".parse().unwrap();
    let workspace_id: WorkspaceId =
        "018f2e3a-7000-7000-8000-00000000007b".parse().unwrap();
    let event_id: EventId = "018f2e3a-7000-7000-8000-00000000007c".parse().unwrap();
    let events = materialize_batch(
        vec![Conversation::decide_create(conversation_id, workspace_id)],
        &[event_id],
        None,
        &CommandContext {
            command_id: CommandId::from_bytes(derived_bytes(workspace_id.into_bytes(), 0x10)),
            idempotency_key: IdempotencyKey::new(String::from("v39-historical-create")).unwrap(),
            actor: Actor::new(String::from("v39-historical")).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(events.len(), 1);
    let global_position: i64 = staging
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let now: i64 = 1_700_000_000_000;
    for (index, event) in events.iter().enumerate() {
        let global = global_position + index as i64;
        let payload = crate::codec::ConversationEventCodec
            .encode(event.payload())
            .unwrap();
        let envelope = runne_domain::event::EventEnvelope::from_parts(
            *event.event_id(),
            AggregateId::Conversation(conversation_id),
            AggregateId::Conversation(conversation_id),
            event.causation_id().copied(),
            *event.command_id(),
            event.idempotency_key().clone(),
            event.schema_version(),
            event.actor().clone(),
            *event.sensitivity(),
            event.payload().clone(),
            index as u64 + 1,
            Timestamp::from_unix_micros(now),
            IntegrityDigest::from_bytes([0; 32]),
        );
        let digest = crate::integrity::compute_integrity_digest_v2_with_global_position(
            &envelope, global, &payload,
        )
        .unwrap();
        staging
            .execute(
                "INSERT INTO aggregate_streams
                 (aggregate_type, aggregate_id, current_version, last_event_id,
                  last_timestamp, created_at)
                 VALUES (2, ?1, 1, ?2, ?3, ?3)",
                params![conversation_id.as_bytes(), event.event_id().as_bytes(), now],
            )
            .unwrap();
        staging
            .execute(
                "INSERT INTO events
                 (event_id, aggregate_type, aggregate_id, sequence, global_position,
                  timestamp, sensitivity, schema_version, causation_id, command_id,
                  idempotency_key, actor, payload, integrity_digest, correlation_id,
                  correlation_type, integrity_profile)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?3, ?2, ?13)",
                params![
                    event.event_id().as_bytes(),
                    CORRELATION_TYPE_CONVERSATION,
                    conversation_id.as_bytes(),
                    global,
                    now,
                    event.schema_version() as i64,
                    event.causation_id().map(EventId::as_bytes),
                    event.command_id().as_bytes(),
                    event.idempotency_key().as_str().as_bytes(),
                    event.actor().as_str().as_bytes(),
                    payload,
                    digest.as_bytes(),
                    INTEGRITY_PROFILE_V2,
                ],
            )
            .unwrap();
    }
    // The seeded events consumed global positions; move the log state
    // forward exactly as the production writer would have.
    staging
        .execute(
            "UPDATE event_log_state SET next_global_position = ?1 WHERE singleton = 1",
            params![global_position + events.len() as i64],
        )
        .unwrap();
    // The startup gate requires a replay snapshot for every aggregate stream;
    // refresh it through the store's own replay builder so the fixture is
    // exactly what production would have written.
    let snapshot_tx = staging.unchecked_transaction().unwrap();
    crate::store::snapshot::refresh_aggregate_snapshot(
        &snapshot_tx,
        CORRELATION_TYPE_CONVERSATION,
        conversation_id.as_bytes(),
    )
    .unwrap();
    snapshot_tx.commit().unwrap();

    // v39 probe: the context-scope table does not exist at this version —
    // pin the exact SQLite failure, not just any error.
    let probe = staging.execute(
        "INSERT INTO conversation_context_scope
         (conversation_id, context_scope, recorded_at) VALUES (?1, 'workspace', 1)",
        params![conversation_id.as_bytes()],
    );
    match probe {
        Err(rusqlite::Error::SqliteFailure(_, message)) => assert!(message
            .as_deref()
            .is_some_and(|m| m.contains("no such table: conversation_context_scope"))),
        other => panic!("v39 probe must fail on the missing scope table, got {other:?}"),
    }

    // Live-WAL pin: the staging connection holds the sidecars open.
    assert!(sidecar_path(&path, "-wal").exists());
    assert!(sidecar_path(&path, "-shm").exists());

    // A second concurrent writer is refused while the sidecars are live —
    // with the exact typed diagnostic, not just any error.
    let second_writer = open_managed_connection(&path, ConnectionMode::Writer);
    let typed_refusal = matches!(
        &second_writer,
        Err(rusqlite::Error::ToSqlConversionFailure(payload))
            if payload.downcast_ref::<SchemaOpenDiagnostic>().copied()
                == Some(SchemaOpenDiagnostic::SidecarPresent)
    );
    assert!(typed_refusal);

    // The upgrade runs on the WAL-owning connection through the public API;
    // its trailing checkpoint may shrink the WAL but the sidecar stays
    // present until the clean close.
    apply_migrations(&staging).unwrap();
    assert_eq!(schema_marker(&staging), 40);
    assert!(sidecar_path(&path, "-wal").exists());
    let preserved: i64 = staging
        .query_row(
            "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(preserved, 1, "the pre-v40 conversation was lost");
    let scope_rows: i64 = staging
        .query_row(
            "SELECT COUNT(*) FROM conversation_context_scope",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(scope_rows, 0, "migration must not backfill scope markers");

    // Hot-reader stage on the still-live WAL: the sidecars are explicitly
    // present and the guarded owner-private Reader profile is admitted
    // alongside the WAL-owning writer, observing the migrated state.
    assert!(sidecar_path(&path, "-wal").exists());
    assert!(sidecar_path(&path, "-shm").exists());
    let reader = open_managed_connection(&path, ConnectionMode::Reader).unwrap();
    let version: i64 = reader
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 40);
    let conversations: i64 = reader
        .query_row(
            "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(conversations, 1);
    let historical_events: i64 = reader
        .query_row(
            "SELECT COUNT(*) FROM events WHERE aggregate_id = ?1",
            params![conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(historical_events, 1);
    let old_scope: Option<String> = reader
        .query_row(
            "SELECT context_scope FROM conversation_context_scope
             WHERE conversation_id = ?1",
            params![conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(old_scope, None);
    drop(reader);

    // Documented WAL end of life: the staging connection's clean close
    // checkpoints and removes the sidecars.
    drop(staging);
    assert!(!sidecar_path(&path, "-wal").exists());
    assert!(!sidecar_path(&path, "-shm").exists());

    // Managed access through the store API: the migrated conversation loads
    // with its full event stream and stays without a scope marker.
    let prohibited: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = crate::store::StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId(String::from("integration-v39-v40")),
        Arc::clone(&prohibited),
    )
    .unwrap();
    let loaded = store.load_conversation(conversation_id).unwrap();
    assert_eq!(loaded.events.len(), 1, "event stream must be preserved");
    let expected_workspace = workspace_id;
    assert!(matches!(
        loaded.events[0].payload(),
        ConversationEvent::ConversationCreated { workspace_id }
            if *workspace_id == expected_workspace
    ));
    assert_eq!(
        store.conversation_context_scope(conversation_id).unwrap(),
        None,
        "pre-v40 conversations must stay unclassified"
    );

    include!("windows_v39_v40_phase2.rs");
}
