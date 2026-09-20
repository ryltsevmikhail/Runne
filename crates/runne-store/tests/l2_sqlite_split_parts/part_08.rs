#[test]
fn taskrun_command_id_rejects_changed_idempotency_key() {
    let db_path = temp_db_path("taskrun-command-key-conflict");
    cleanup_db(&db_path);
    let (_store, service) = open_service(&db_path);
    let original = make_context(301);
    service
        .create_task_run(
            &original,
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let mut changed = original;
    changed.idempotency_key = IdempotencyKey::new("changed-taskrun-key").unwrap();
    assert!(matches!(
        service.create_task_run(
            &changed,
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        ),
        Err(ApplicationError::IdempotencyConflict { .. })
    ));
    cleanup_db(&db_path);
}

#[test]
fn conversation_command_id_rejects_changed_idempotency_key() {
    let db_path = temp_db_path("conversation-command-key-conflict");
    cleanup_db(&db_path);
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
    let command_id = "018f2e3a-7000-7000-8000-000000000071".parse().unwrap();
    let conversation_id = make_conv_id();
    let workspace_id = make_ws_id();
    validated_reopen::seed_canonical_workspace(&store, "test-principal", workspace_id);
    let original = CreateConversationInput {
        conversation_id,
        workspace_id,
        command_id,
        idempotency_key: IdempotencyKey::new("original-conversation-key").unwrap(),
        scope: runne_api::ConversationContextScope::Workspace,
    };
    service.create(&api_context(), original.clone()).unwrap();
    let changed = CreateConversationInput {
        conversation_id,
        workspace_id,
        command_id,
        idempotency_key: IdempotencyKey::new("changed-conversation-key").unwrap(),
        scope: runne_api::ConversationContextScope::Workspace,
    };
    assert!(matches!(
        service.create(&api_context(), changed),
        Err(ConversationServiceError::Commit(
            CommitError::IdempotencyConflict { .. }
        ))
    ));
    let scope = IdempotencyScope {
        runtime_authority_id: store.runtime_authority_id().clone(),
        principal_id: PrincipalId("test-principal".into()),
        operation: OperationTag::CreateConversation,
        aggregate_scope: AggregateScope::NewConversation {
            conversation_id,
            workspace_id,
        },
    };
    assert!(matches!(
        store.lookup_conversation_receipt(
            command_id,
            &original.idempotency_key,
            &scope,
            &CommandFingerprint::from_bytes([0x70; 32]),
            runne_api::ConversationContextScope::Workspace,
        ),
        Err(CommitError::IdempotencyConflict { .. })
    ));
    let mut changed_fingerprint = direct_conversation_commit(
        &store,
        conversation_id,
        workspace_id,
        command_id,
        original.idempotency_key,
    );
    changed_fingerprint.command_fingerprint = CommandFingerprint::from_bytes([0x70; 32]);
    assert!(matches!(
        store.commit_conversation(changed_fingerprint),
        Err(CommitError::IdempotencyConflict { .. })
    ));
    cleanup_db(&db_path);
}

#[test]
fn receipt_lookup_rejects_changed_fingerprint_and_corrupt_identity() {
    let database = validated_reopen::ValidatedTestDatabase::new("receipt-identity-corrupt");
    let db_path = database.path().to_owned();
    let (store, identity) = validated_reopen::initialize_store(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    validated_reopen::seed_canonical_workspace(&store, "test-principal", make_ws_id());
    let payload = direct_taskrun_commit(
        &store,
        "018f2e3a-7000-7000-8000-000000000074".parse().unwrap(),
        "018f2e3a-7000-7000-8000-000000000075".parse().unwrap(),
        IdempotencyKey::new("receipt-identity").unwrap(),
        0x76,
    );
    assert!(matches!(store.commit(payload.clone()), Ok(CommitResult::Committed { .. })));
    assert!(matches!(
        store.lookup_receipt(
            payload.command_id,
            &payload.idempotency_key,
            &payload.idempotency_scope,
            &CommandFingerprint::from_bytes([0x77; 32]),
        ),
        Err(CommitError::IdempotencyConflict { .. })
    ));
    drop(store);
    let connection = validated_reopen_store::open_validated_writer(&db_path, identity).unwrap();
    connection
        .execute(
            "UPDATE command_receipts SET fingerprint = x'01' WHERE command_id = ?1",
            [payload.command_id.as_bytes()],
        )
        .unwrap();
    drop(connection);
    let reopened = validated_reopen::reopen_store(
        &db_path,
        identity,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    assert_eq!(
        reopened.lookup_receipt(
            payload.command_id,
            &payload.idempotency_key,
            &payload.idempotency_scope,
            &payload.command_fingerprint,
        ),
        Err(CommitError::StorageFailure(StorageFailureKind::CorruptData))
    );
    cleanup_db(&db_path);
}

#[test]
fn concurrent_exact_create_double_miss_replays_winner_identity() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let database = validated_reopen::ValidatedTestDatabase::new("command-double-miss");
    let db_path = database.path().to_owned();
    let (seed, identity) = validated_reopen::initialize_store(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    validated_reopen::seed_canonical_workspace(&seed, "test-principal", make_ws_id());
    drop(seed);
    let command_id = "018f2e3a-7000-7000-8000-000000000081".parse().unwrap();
    let taskrun_ids = [
        "018f2e3a-7000-7000-8000-000000000082".parse().unwrap(),
        "018f2e3a-7000-7000-8000-000000000083".parse().unwrap(),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for variant in 0..2_u8 {
        let path = db_path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = validated_reopen::reopen_store(
                &path,
                identity,
                RuntimeAuthorityId("test-host".into()),
                available_guard(),
            )
            .unwrap();
            let payload = direct_taskrun_commit(
                &store,
                taskrun_ids[variant as usize],
                command_id,
                IdempotencyKey::new("racing-exact-key").unwrap(),
                0x84 + variant,
            );
            assert_eq!(
                store
                    .lookup_receipt(
                        command_id,
                        &payload.idempotency_key,
                        &payload.idempotency_scope,
                        &payload.command_fingerprint,
                    )
                    .unwrap(),
                ReceiptLookup::Miss
            );
            barrier.wait();
            store.commit(payload)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(CommitResult::Committed { .. })))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(CommitResult::Duplicate { .. })))
            .count(),
        1,
        "exact loser must replay the winner: {results:?}"
    );
    let winner_index = results
        .iter()
        .position(|result| matches!(result, Ok(CommitResult::Committed { .. })))
        .unwrap();
    let winner_taskrun_id = taskrun_ids[winner_index];
    let duplicate = results
        .iter()
        .find_map(|result| match result {
            Ok(CommitResult::Duplicate {
                stored_result: CommandOutcome::TaskRunCreated { taskrun_id, .. },
            }) => Some(*taskrun_id),
            _ => None,
        })
        .unwrap();
    assert_eq!(duplicate, winner_taskrun_id);
    let connection = validated_reopen_store::open_validated_reader(&db_path, identity).unwrap();
    let durable: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM command_receipts WHERE command_id = ?1),
                    (SELECT COUNT(*) FROM events WHERE command_id = ?1),
                    (SELECT COUNT(*) FROM task_run_workspace_lineage WHERE origin_command_id = ?1),
                    (SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 1)",
            [command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(durable, (1, 1, 1, 1));
    let durable_taskrun: Vec<u8> = connection
        .query_row(
            "SELECT aggregate_id FROM events WHERE command_id = ?1",
            [command_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(durable_taskrun, winner_taskrun_id.as_bytes());
    cleanup_db(&db_path);
}
