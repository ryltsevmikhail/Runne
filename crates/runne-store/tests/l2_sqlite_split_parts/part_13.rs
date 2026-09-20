// ── Round 5: store duplicate-path arbitration for create receipts ─────────
//
// Store-level duplicate resolution: the receipt fingerprint (current format
// or legacy scope-less format of the same conversation/workspace) plus the
// durable context-scope marker decide replay versus conflict before any
// write. A missing marker (pre-V40 receipt) keeps the exact replay a
// duplicate without deriving a scope from absence.

fn round5_legacy_direction(
    name: &str,
    initial: runne_api::ConversationContextScope,
    flipped: runne_api::ConversationContextScope,
) {
    let database = validated_reopen::ValidatedTestDatabase::new(name);
    let db_path = database.path().to_owned();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000001c1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000001c2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000001c3".parse().unwrap();
    let key = IdempotencyKey::new("round5-duplicate").unwrap();
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
    service
        .create(
            &api_context(),
            round5_create_input(conversation_id, workspace_id, command_id, "round5-duplicate", initial),
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
    // Rewrite the receipt into the legacy scope-less fingerprint format, as
    // an older build would have stored it.
    let legacy = CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id);
    drop(service);
    drop(store);
    let writer = validated_reopen_store::open_validated_writer(&db_path, identity).unwrap();
    writer
        .execute(
            "UPDATE command_receipts SET fingerprint = ?1 WHERE command_id = ?2",
            rusqlite::params![legacy.as_bytes(), command_id.as_bytes()],
        )
        .unwrap();
    drop(writer);
    let store = validated_reopen::reopen_store(
        &db_path,
        identity,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    // Exact replay (current fingerprint, same scope) stays a duplicate.
    assert!(matches!(
        store
            .lookup_conversation_receipt(
                command_id,
                &key,
                &scope,
                &CommandFingerprint::for_create_conversation(&conversation_id, &workspace_id, initial,),
                initial,
            )
            .unwrap(),
        runne_application::ports::ConversationReceiptLookup::Duplicate { .. }
    ));
    // Flipped scope: the durable marker contradicts it — conflict.
    assert!(matches!(
        store.lookup_conversation_receipt(
            command_id,
            &key,
            &scope,
            &CommandFingerprint::for_create_conversation(&conversation_id, &workspace_id, flipped,),
            flipped,
        ),
        Err(CommitError::IdempotencyConflict { .. })
    ));
    // Commit path: the flipped payload is rejected before any write.
    let mut payload =
        direct_conversation_commit(&store, conversation_id, workspace_id, command_id, key.clone());
    payload.command_fingerprint = CommandFingerprint::for_create_conversation(
        &conversation_id,
        &workspace_id,
        flipped,
    );
    payload.context_scope = flipped;
    assert!(matches!(
        store.commit_conversation(payload),
        Err(CommitError::IdempotencyConflict { .. })
    ));
    assert_eq!(
        round5_counts(&db_path, &command_id),
        (1, 1, 1, initial.as_str().to_owned())
    );
}

#[test]
fn store_duplicate_path_arbitrates_scope_before_writes() {
    round5_legacy_direction(
        "round5-duplicate-workspace",
        runne_api::ConversationContextScope::Workspace,
        runne_api::ConversationContextScope::TextOnly,
    );
    round5_legacy_direction(
        "round5-duplicate-text",
        runne_api::ConversationContextScope::TextOnly,
        runne_api::ConversationContextScope::Workspace,
    );
}

#[test]
fn pre_v40_receipt_without_marker_keeps_exact_replay_duplicate() {
    let database = validated_reopen::ValidatedTestDatabase::new("round5-pre-v40");
    let db_path = database.path().to_owned();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000001d1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000001d2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000001d3".parse().unwrap();
    let key = IdempotencyKey::new("round5-pre-v40").unwrap();
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
    service
        .create(
            &api_context(),
            round5_create_input(
                conversation_id,
                workspace_id,
                command_id,
                "round5-pre-v40",
                runne_api::ConversationContextScope::Workspace,
            ),
        )
        .unwrap();
    let legacy = CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id);
    drop(service);
    drop(store);
    let writer = validated_reopen_store::open_validated_writer(&db_path, identity).unwrap();
    writer
        .execute(
            "UPDATE command_receipts SET fingerprint = ?1 WHERE command_id = ?2",
            rusqlite::params![legacy.as_bytes(), command_id.as_bytes()],
        )
        .unwrap();
    // Simulate the pre-V40 state: no durable marker row at all.
    writer
        .execute(
            "DELETE FROM conversation_context_scope WHERE conversation_id = ?1",
            [conversation_id.as_bytes()],
        )
        .unwrap();
    drop(writer);
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
    // Exact replay of the legacy receipt: idempotent duplicate. Absence of
    // the marker derives no scope (Decision, round 5): delivery stays
    // fail-closed, and a flipped attempted scope cannot be contradicted.
    assert!(matches!(
        store
            .lookup_conversation_receipt(command_id, &key, &scope, &legacy, runne_api::ConversationContextScope::Workspace,)
            .unwrap(),
        runne_application::ports::ConversationReceiptLookup::Duplicate { .. }
    ));
    assert!(matches!(
        store
            .lookup_conversation_receipt(
                command_id,
                &key,
                &scope,
                &CommandFingerprint::for_create_conversation(&conversation_id, &workspace_id, runne_api::ConversationContextScope::TextOnly,),
                runne_api::ConversationContextScope::TextOnly,
            )
            .unwrap(),
        runne_application::ports::ConversationReceiptLookup::Duplicate { .. }
    ));
    // Commit-path replay of the legacy payload duplicates without writes.
    let mut payload =
        direct_conversation_commit(&store, conversation_id, workspace_id, command_id, key);
    payload.command_fingerprint = legacy;
    assert!(matches!(
        store.commit_conversation(payload),
        Ok(runne_application::ports::ConversationCommitResult::Duplicate { .. })
    ));
    assert_eq!(
        round5_counts(&db_path, &command_id),
        (1, 1, 0, ROUND5_EMPTY_MARKER.to_owned())
    );
}
