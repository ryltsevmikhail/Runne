use super::event_guard::*;
use super::*;
use runne_application::ports::ProjectWorkspaceRepository;
use runne_domain::id::{CommandId, IdempotencyKey, MessageId, ProjectId};
use runne_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName};
use runne_security::SecretBroker;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn temp_db_path(name: &str) -> String {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    let runtime_root = std::env::temp_dir().join(format!("runne-store-{name}-{unique}"));
    let daemon = runtime_root.join("runne-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    daemon
        .join("event-log.sqlite")
        .to_string_lossy()
        .into_owned()
}

fn cleanup_db(db_path: &str) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{db_path}{suffix}"));
    }
    if let Some(daemon) = Path::new(db_path).parent() {
        let _ = std::fs::remove_dir(daemon);
        if let Some(runtime_root) = daemon.parent() {
            let _ = std::fs::remove_dir(runtime_root);
        }
    }
}

#[test]
fn public_store_open_rejects_memory_database() {
    let result = StoreTransaction::open(
        ":memory:",
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    );

    assert!(matches!(
        result,
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    ));
}

#[test]
fn public_store_reopens_after_last_clone_drops_and_reads_committed_project() {
    let db_path = temp_db_path("drop-order-reopen");
    let authority = RuntimeAuthorityId("drop-order-host".into());
    let store = StoreTransaction::open(&db_path, authority.clone(), available_guard()).unwrap();
    let clone = store.clone();
    let repository = crate::ProjectWorkspaceStore::from_store(store.clone());
    let project_id = ProjectId::from_bytes(uuid::Uuid::now_v7().into_bytes());
    let command_id = CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes());
    let created = repository
        .create_project(
            "drop-order-owner",
            command_id,
            &IdempotencyKey::new("drop-order-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Durable after reopen".into()).unwrap(),
            ),
        )
        .unwrap();

    drop(repository);
    drop(clone);
    drop(store);

    let reopened = StoreTransaction::open(&db_path, authority, available_guard()).unwrap();
    let reopened_repository = crate::ProjectWorkspaceStore::from_store(reopened.clone());
    assert_eq!(
        reopened_repository
            .get_project("drop-order-owner", project_id)
            .unwrap(),
        created
    );

    drop(reopened_repository);
    drop(reopened);
    cleanup_db(&db_path);
}

#[test]
fn append_guard_rejects_json_escape_expanded_canonical_event() {
    let conversation_id = ConversationId::from_bytes([0x11; 16]);
    let event = UncommittedEvent::from_parts(
        EventId::from_bytes([0x22; 16]),
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        None,
        CommandId::from_bytes([0x33; 16]),
        IdempotencyKey::new("oversized-replay-event").unwrap(),
        1,
        Actor::new("test-actor").unwrap(),
        Sensitivity::Sensitive,
        ConversationEvent::UserMessageAppended {
            message_id: MessageId::from_bytes([0x44; 16]),
            taskrun_id: TaskRunId::from_bytes([0x55; 16]),
            attempt_id: AttemptId::from_bytes([0x66; 16]),
            text: MessageText::new("\0".repeat(MAX_MESSAGE_TEXT_BYTES)).unwrap(),
        },
    );
    let guard = available_guard();

    let error = guard_conversation_event(guard.as_ref(), &event, 1, 1, 0).unwrap_err();

    assert_eq!(
        error,
        CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)
    );
}

#[test]
fn failed_stream_query_is_not_reported_as_missing() {
    let db_path = temp_db_path("reader-query-failure");
    let store = StoreTransaction::open(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    store
        .inner
        .writer
        .lock()
        .unwrap()
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
                 DROP TABLE events;
                 DROP TABLE aggregate_streams;",
        )
        .unwrap();

    let result = store.load_task_run(TaskRunId::from_bytes([1; 16]));

    assert_eq!(result.unwrap_err(), EventStoreError::CorruptData);
    drop(store);
    cleanup_db(&db_path);
}

#[test]
fn failed_receipt_query_is_not_reported_as_a_miss() {
    let db_path = temp_db_path("receipt-query-failure");
    let store = StoreTransaction::open(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    store
        .inner
        .writer
        .lock()
        .unwrap()
        .execute_batch("DROP TABLE command_receipts;")
        .unwrap();
    let taskrun_id = TaskRunId::from_bytes([1; 16]);
    let scope = IdempotencyScope {
        runtime_authority_id: RuntimeAuthorityId("test-host".into()),
        principal_id: runne_application::ports::PrincipalId("test-principal".into()),
        operation: OperationTag::StartAttempt,
        aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id },
    };

    let result = store.lookup_receipt(
        CommandId::from_bytes([2; 16]),
        &IdempotencyKey::new("test-key").unwrap(),
        &scope,
        &CommandFingerprint::from_bytes([3; 32]),
    );

    assert_eq!(
        result.unwrap_err(),
        CommitError::StorageFailure(StorageFailureKind::CorruptData)
    );
    drop(store);
    cleanup_db(&db_path);
}
