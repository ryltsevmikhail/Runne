// ── Round 5: delivery-context scope in create-conversation idempotency ────
//
// The scope is part of the create-conversation semantic fingerprint. The
// same command/key/IDs with a flipped scope must conflict before any write,
// while exact replays — including receipts stored by older builds in the
// legacy scope-less fingerprint format — stay idempotent. A missing
// context-scope marker (pre-V40 receipt) never contradicts a replay and
// never derives a scope from absence.

const ROUND5_TEXT_ONLY_SCOPE: &str = "text_only";
const ROUND5_EMPTY_MARKER: &str = "";

fn round5_create_input(
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    key: &str,
    scope: runne_api::ConversationContextScope,
) -> CreateConversationInput {
    CreateConversationInput {
        conversation_id,
        workspace_id,
        command_id,
        idempotency_key: IdempotencyKey::new(key.to_owned()).unwrap(),
        scope,
    }
}

fn round5_open_service(
    db_path: &str,
) -> (
    StoreTransaction,
    ConversationService<StoreTransaction, StoreTransaction>,
) {
    let store = StoreTransaction::open(
        db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let service =
        ConversationService::new(store.clone(), store.clone(), store.runtime_authority_id().clone());
    (store, service)
}

/// `(conversation events, receipts of the command, marker rows, marker scope)`
fn round5_counts(db_path: &str, command_id: &CommandId) -> (i64, i64, i64, String) {
    let conn = runne_store::schema::reopen_managed_connection_validated(
        std::path::Path::new(db_path),
        runne_store::schema::ConnectionMode::Reader,
        |connection| {
            let version: i64 = connection.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )?;
            if version == runne_store::schema::CURRENT_SCHEMA_VERSION {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    )
    .unwrap();
    runne_store::schema::readiness_from_managed(&conn).unwrap();
    conn.query_row(
        "SELECT (SELECT COUNT(*) FROM events WHERE aggregate_type = 2),
                (SELECT COUNT(*) FROM command_receipts WHERE command_id = ?1),
                (SELECT COUNT(*) FROM conversation_context_scope),
                (SELECT COALESCE((SELECT context_scope FROM conversation_context_scope LIMIT 1), ''))",
        [command_id.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .unwrap()
}

#[test]
fn conversation_scope_flip_conflicts_without_new_writes() {
    for (name, initial, flipped) in [
        (
            "workspace-to-text",
            runne_api::ConversationContextScope::Workspace,
            runne_api::ConversationContextScope::TextOnly,
        ),
        (
            "text-to-workspace",
            runne_api::ConversationContextScope::TextOnly,
            runne_api::ConversationContextScope::Workspace,
        ),
    ] {
        let db_path = temp_db_path(&format!("round5-scope-flip-{name}"));
        cleanup_db(&db_path);
        let (store, service) = round5_open_service(&db_path);
        let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000001a1".parse().unwrap();
        let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000001a2".parse().unwrap();
        let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000001a3".parse().unwrap();
        let input = round5_create_input(
            conversation_id,
            workspace_id,
            command_id,
            "round5-flip",
            initial,
        );
        let first = service.create(&api_context(), input.clone()).unwrap();
        let replay = service.create(&api_context(), input.clone()).unwrap();
        assert_eq!(replay.committed_at, first.committed_at);

        let flipped_input = CreateConversationInput { scope: flipped, ..input };
        assert!(matches!(
            service.create(&api_context(), flipped_input),
            Err(ConversationServiceError::Commit(
                CommitError::IdempotencyConflict { .. }
            ))
        ));
        assert_eq!(
            store.conversation_context_scope(conversation_id).unwrap(),
            Some(initial)
        );
        assert_eq!(store.load_conversation(conversation_id).unwrap().events.len(), 1);
        assert_eq!(
            round5_counts(&db_path, &command_id),
            (1, 1, 1, initial.as_str().to_owned())
        );
        drop(store);
        cleanup_db(&db_path);
    }
}

#[test]
fn conversation_exact_replay_stays_idempotent_after_reopen() {
    let database = validated_reopen::ValidatedTestDatabase::new("round5-restart-replay");
    let db_path = database.path().to_owned();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000001b1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000001b2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000001b3".parse().unwrap();
    let input = round5_create_input(
        conversation_id,
        workspace_id,
        command_id,
        "round5-restart",
        runne_api::ConversationContextScope::TextOnly,
    );
    let first = {
        let (store, identity) = validated_reopen::initialize_store(
            &db_path,
            RuntimeAuthorityId("test-host".into()),
            available_guard(),
        )
        .unwrap();
        let service = ConversationService::new(
            store.clone(),
            store.clone(),
            store.runtime_authority_id().clone(),
        );
        (service.create(&api_context(), input.clone()).unwrap(), identity)
    };
    let reopened = validated_reopen::reopen_store(
        &db_path,
        first.1,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let reopened_service = ConversationService::new(
        reopened.clone(),
        reopened.clone(),
        reopened.runtime_authority_id().clone(),
    );
    let replay = reopened_service.create(&api_context(), input.clone()).unwrap();
    assert_eq!(replay.committed_at, first.0.committed_at);
    let flipped = CreateConversationInput {
        scope: runne_api::ConversationContextScope::Workspace,
        ..input
    };
    assert!(matches!(
        reopened_service.create(&api_context(), flipped),
        Err(ConversationServiceError::Commit(
            CommitError::IdempotencyConflict { .. }
        ))
    ));
    assert_eq!(
        reopened
            .conversation_context_scope(conversation_id)
            .unwrap(),
        Some(runne_api::ConversationContextScope::TextOnly)
    );
    assert_eq!(reopened.load_conversation(conversation_id).unwrap().events.len(), 1);
    assert_eq!(
        round5_counts(&db_path, &command_id),
        (1, 1, 1, ROUND5_TEXT_ONLY_SCOPE.to_owned())
    );
}
