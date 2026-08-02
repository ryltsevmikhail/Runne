
#[test]
fn conversation_create_is_durable_idempotent_and_replayable_after_reopen() {
    let db_path = temp_db_path("conversation-create");
    cleanup_db(&db_path);
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000000c1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000000c2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000000c3".parse().unwrap();
    let input = CreateConversationInput {
        conversation_id,
        workspace_id,
        command_id,
        idempotency_key: IdempotencyKey::new("conversation-create").unwrap(),
    };

    let first = {
        let store = StoreTransaction::open(
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
        let first = service.create(&api_context(), input.clone()).unwrap();
        let duplicate = service.create(&api_context(), input.clone()).unwrap();
        assert_eq!(first.conversation_id, duplicate.conversation_id);
        assert_eq!(first.workspace_id, duplicate.workspace_id);
        assert_eq!(first.committed_at, duplicate.committed_at);
        assert_eq!(first.stream_version, 1);

        let stream = store.load_conversation(conversation_id).unwrap();
        assert_eq!(stream.current_version, 1);
        assert_eq!(stream.events.len(), 1);
        let aggregate = Conversation::replay(&stream.events).unwrap();
        assert_eq!(aggregate.id, conversation_id);
        assert_eq!(aggregate.workspace_id, workspace_id);
        assert_eq!(aggregate.state, ConversationState::Active);
        first
    };

    let reopened = StoreTransaction::open(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let reopened_service = ConversationService::new(
        reopened.clone(),
        reopened.clone(),
        reopened.runtime_authority_id().clone(),
    );
    let duplicate = reopened_service
        .create(&api_context(), input.clone())
        .unwrap();
    assert_eq!(duplicate.committed_at, first.committed_at);
    assert_eq!(
        reopened
            .load_conversation(conversation_id)
            .unwrap()
            .events
            .len(),
        1
    );

    let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();
    let counts: (i64, i64, i64) = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 2),
                (SELECT COUNT(*) FROM events WHERE aggregate_type = 2),
                (SELECT COUNT(*) FROM command_receipts WHERE command_id = ?1)",
            rusqlite::params![command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1, 1));

    cleanup_db(&db_path);
}

#[test]
fn conversation_commit_rejects_non_public_event_without_mutation() {
    let db_path = temp_db_path("conversation-non-public");
    cleanup_db(&db_path);
    let store = StoreTransaction::open(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000000d1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000000d2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000000d3".parse().unwrap();
    let mut commit = direct_conversation_commit(
        &store,
        conversation_id,
        workspace_id,
        command_id,
        IdempotencyKey::new("conversation-non-public").unwrap(),
    );
    let original = commit.events.pop().unwrap();
    commit.events.push(replace_conversation_event_metadata(
        &original,
        command_id,
        commit.idempotency_key.clone(),
        1,
        Sensitivity::Sensitive,
    ));

    assert_eq!(
        store.commit_conversation(commit),
        Err(CommitError::StorageFailure(
            StorageFailureKind::IntegrityViolation
        ))
    );
    drop(store);
    assert_no_conversation_commit_rows(&db_path);
    cleanup_db(&db_path);
}

#[test]
fn conversation_commit_rejects_mismatched_event_command_without_mutation() {
    let db_path = temp_db_path("conversation-command-mismatch");
    cleanup_db(&db_path);
    let store = StoreTransaction::open(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000000e1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000000e2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000000e3".parse().unwrap();
    let other_command_id: CommandId = "018f2e3a-7000-7000-8000-0000000000e4".parse().unwrap();
    let mut commit = direct_conversation_commit(
        &store,
        conversation_id,
        workspace_id,
        command_id,
        IdempotencyKey::new("conversation-command-mismatch").unwrap(),
    );
    let original = commit.events.pop().unwrap();
    commit.events.push(replace_conversation_event_metadata(
        &original,
        other_command_id,
        commit.idempotency_key.clone(),
        1,
        Sensitivity::Public,
    ));

    assert_eq!(
        store.commit_conversation(commit),
        Err(CommitError::StorageFailure(
            StorageFailureKind::IntegrityViolation
        ))
    );
    drop(store);
    assert_no_conversation_commit_rows(&db_path);
    cleanup_db(&db_path);
}

#[test]
fn conversation_commit_rejects_noncanonical_scope_fingerprint_key_and_schema() {
    enum Mismatch {
        Scope,
        Fingerprint,
        Key,
        Schema,
    }

    for (name, mismatch) in [
        ("scope", Mismatch::Scope),
        ("fingerprint", Mismatch::Fingerprint),
        ("key", Mismatch::Key),
        ("schema", Mismatch::Schema),
    ] {
        let db_path = temp_db_path(&format!("conversation-{name}-mismatch"));
        cleanup_db(&db_path);
        let store = StoreTransaction::open(
            &db_path,
            RuntimeAuthorityId("test-host".into()),
            available_guard(),
        )
        .unwrap();
        let conversation_id: ConversationId =
            "018f2e3a-7000-7000-8000-0000000000f1".parse().unwrap();
        let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000000f2".parse().unwrap();
        let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000000f3".parse().unwrap();
        let mut commit = direct_conversation_commit(
            &store,
            conversation_id,
            workspace_id,
            command_id,
            IdempotencyKey::new(format!("conversation-{name}-mismatch")).unwrap(),
        );

        match mismatch {
            Mismatch::Scope => {
                commit.idempotency_scope.operation = OperationTag::CreateTaskRun;
            }
            Mismatch::Fingerprint => {
                commit.command_fingerprint = CommandFingerprint::from_bytes([0x5a; 32]);
            }
            Mismatch::Key => {
                commit.idempotency_key = IdempotencyKey::new("different-key").unwrap();
            }
            Mismatch::Schema => {
                let original = commit.events.pop().unwrap();
                commit.events.push(replace_conversation_event_metadata(
                    &original,
                    command_id,
                    commit.idempotency_key.clone(),
                    2,
                    Sensitivity::Public,
                ));
            }
        }

        assert_eq!(
            store.commit_conversation(commit),
            Err(CommitError::StorageFailure(
                StorageFailureKind::IntegrityViolation
            )),
            "{name} mismatch must fail closed"
        );
        drop(store);
        assert_no_conversation_commit_rows(&db_path);
        cleanup_db(&db_path);
    }
}
