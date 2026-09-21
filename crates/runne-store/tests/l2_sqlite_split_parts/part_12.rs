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

// ── Round 6: only an explicitly supported encoding (v2 tag 21 of the passed
// IDs+scope, or legacy tag 6 of the same IDs) yields a duplicate; arbitrary
// digests conflict in BOTH paths; legacy vs v2-stored stays fail-closed.
#[test]
fn round6_unsupported_attempted_digest_conflicts_in_both_duplicate_paths() {
    let database = validated_reopen::ValidatedTestDatabase::new("round6-unsupported-attempted");
    let db_path = database.path().to_owned();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000001e1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000001e2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000001e3".parse().unwrap();
    let other_conversation_id: ConversationId =
        "018f2e3a-7000-7000-8000-0000000001e4".parse().unwrap();
    let key = IdempotencyKey::new("round6-unsupported").unwrap();
    let (store, identity) = validated_reopen::initialize_store(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    store
        .commit_conversation(direct_conversation_commit(
            &store,
            conversation_id,
            workspace_id,
            command_id,
            key.clone(),
        ))
        .unwrap();
    drop(store);
    let store = validated_reopen::reopen_store(
        &db_path,
        identity,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let scope = IdempotencyScope {
        runtime_authority_id: store.runtime_authority_id().clone(),
        principal_id: PrincipalId("test-principal".into()),
        operation: OperationTag::CreateConversation,
        aggregate_scope: AggregateScope::NewConversation {
            conversation_id,
            workspace_id,
        },
    };
    let v2 =
        |scope| CommandFingerprint::for_create_conversation(&conversation_id, &workspace_id, scope);
    let foreign_ids = CommandFingerprint::for_create_conversation(
        &other_conversation_id,
        &workspace_id,
        runne_api::ConversationContextScope::Workspace,
    );
    let legacy = CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id);
    for (attempted, attempted_scope) in [
        // Arbitrary digest; foreign IDs; other scope; legacy vs v2-stored (fail-closed).
        (CommandFingerprint::from_bytes([0x5a; 32]), runne_api::ConversationContextScope::Workspace),
        (foreign_ids, runne_api::ConversationContextScope::Workspace),
        (
            v2(runne_api::ConversationContextScope::TextOnly),
            runne_api::ConversationContextScope::TextOnly,
        ),
        (legacy, runne_api::ConversationContextScope::Workspace),
    ] {
        assert!(matches!(
            store.lookup_conversation_receipt(command_id, &key, &scope, &attempted, attempted_scope,),
            Err(CommitError::IdempotencyConflict { .. })
        ));
        let mut payload = direct_conversation_commit(
            &store,
            conversation_id,
            workspace_id,
            command_id,
            key.clone(),
        );
        payload.command_fingerprint = attempted;
        payload.context_scope = attempted_scope;
        assert!(matches!(
            store.commit_conversation(payload),
            Err(CommitError::IdempotencyConflict { .. })
        ));
    }
    // Correct v2 replay stays a duplicate in both paths.
    let exact = v2(runne_api::ConversationContextScope::Workspace);
    assert!(matches!(
        store
            .lookup_conversation_receipt(
                command_id,
                &key,
                &scope,
                &exact,
                runne_api::ConversationContextScope::Workspace,
            )
            .unwrap(),
        runne_application::ports::ConversationReceiptLookup::Duplicate { .. }
    ));
    let payload =
        direct_conversation_commit(&store, conversation_id, workspace_id, command_id, key);
    assert!(matches!(
        store.commit_conversation(payload),
        Ok(runne_application::ports::ConversationCommitResult::Duplicate { .. })
    ));
    assert_eq!(
        round5_counts(&db_path, &command_id),
        (1, 1, 1, "workspace".to_owned())
    );
}
