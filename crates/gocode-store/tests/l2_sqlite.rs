//! L2-I: SQLite integration tests for gocode-store.
//!
//! Uses a real temporary SQLite file and `StoreTransaction` for full
//! persistence tests. Tests the complete lifecycle through the service
//! layer, dedup, conflicts, reopen, concurrent writes, clock regression,
//! and fail-closed behavior on schema corruption.

use gocode_api::{
    ApiActor, ApiCommandContext, ApiPrincipalId, CreateConversationInput, ResponseSeed,
};
use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::conversation_service::ConversationService;
use gocode_application::errors::ApplicationError;
use gocode_application::fingerprint::CommandFingerprint;
use gocode_application::ports::{
    AggregateScope, ApplicationCommandContext, CommitError, ConversationCommit,
    ConversationRepository, EventStore, EventStoreError, IdempotencyScope, LoadedStream,
    OperationTag, PrincipalId, RuntimeAuthorityId, StorageFailureKind,
};
use gocode_application::service::TaskRunService;
use gocode_domain::command::TerminalResult;
use gocode_domain::conversation::{Conversation, ConversationEvent, ConversationState};
use gocode_domain::event::{
    Actor, CommandContext, Sensitivity, UncommittedEvent, materialize_batch,
};
use gocode_domain::id::{
    CommandId, ConversationId, EventId, IdempotencyKey, TaskRunId, WorkspaceId,
};
use gocode_domain::task_run::TaskRun;
use gocode_store::store::StoreTransaction;

// ── Helpers ──────────────────────────────────────────────────────────────

fn temp_db_path(name: &str) -> String {
    let mut dir = std::env::temp_dir();
    dir.push(format!("gocode-test-l2i-{}.sqlite", name));
    dir.to_str().unwrap().to_string()
}

fn cleanup_db(db_path: &str) {
    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(format!("{}-wal", db_path));
    let _ = std::fs::remove_file(format!("{}-shm", db_path));
}

/// Build a unique `ApplicationCommandContext` per test invocation.
fn make_context(counter: u16) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: CommandId::from_bytes([
            0x01,
            0x8f,
            0x2e,
            0x3a,
            0x70,
            0x00,
            0x70,
            0x00,
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            (counter >> 8) as u8,
            counter as u8,
        ]),
        idempotency_key: IdempotencyKey::new(format!("test-key-{}", counter)).unwrap(),
        principal_id: PrincipalId("test-principal".into()),
        actor: Actor::new(format!("test-actor-{}", counter)).unwrap(),
    }
}

const CONV_ID: &str = "018f2e3a-7000-7000-8000-00000000000a";
const WS_ID: &str = "018f2e3a-7000-7000-8000-00000000000b";

fn make_conv_id() -> ConversationId {
    CONV_ID.parse().unwrap()
}

fn make_ws_id() -> WorkspaceId {
    WS_ID.parse().unwrap()
}

fn open_service(
    db_path: &str,
) -> (
    StoreTransaction,
    TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>,
) {
    let store = StoreTransaction::open(db_path, RuntimeAuthorityId("test-host".into())).unwrap();
    let ra_id = store.runtime_authority_id().clone();
    let svc = TaskRunService::new(store.clone(), store.clone(), store.clone(), ra_id);
    (store, svc)
}

fn api_context() -> ApiCommandContext {
    ApiCommandContext {
        principal: ApiPrincipalId::new("test-principal").unwrap(),
        actor: ApiActor::new("test-actor").unwrap(),
        response_seed: ResponseSeed {
            project_id: "project".into(),
            directory: "/workspace".into(),
            path: None,
            version: "test".into(),
            workspace_id: None,
        },
    }
}

fn direct_conversation_commit(
    store: &StoreTransaction,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
) -> ConversationCommit {
    let event_id: EventId = "018f2e3a-7000-7000-8000-0000000000d4".parse().unwrap();
    let events = materialize_batch(
        vec![Conversation::decide_create(conversation_id, workspace_id)],
        &[event_id],
        None,
        &CommandContext {
            command_id,
            idempotency_key: idempotency_key.clone(),
            actor: Actor::new("direct-test").unwrap(),
        },
    )
    .unwrap();
    ConversationCommit {
        command_id,
        idempotency_key,
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: store.runtime_authority_id().clone(),
            principal_id: PrincipalId("test-principal".into()),
            operation: OperationTag::CreateConversation,
            aggregate_scope: AggregateScope::NewConversation {
                conversation_id,
                workspace_id,
            },
        },
        command_fingerprint: CommandFingerprint::for_create_conversation(
            &conversation_id,
            &workspace_id,
        ),
        expected_version: 0,
        events,
        workspace_id,
    }
}

fn replace_conversation_event_metadata(
    event: &UncommittedEvent<ConversationEvent>,
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
    schema_version: u32,
    sensitivity: Sensitivity,
) -> UncommittedEvent<ConversationEvent> {
    UncommittedEvent::from_parts(
        *event.event_id(),
        event.aggregate_id().clone(),
        event.correlation_id().clone(),
        event.causation_id().copied(),
        command_id,
        idempotency_key,
        schema_version,
        event.actor().clone(),
        sensitivity,
        event.payload().clone(),
    )
}

fn assert_no_conversation_commit_rows(db_path: &str) {
    let conn = gocode_store::schema::open_with_pragmas(db_path).unwrap();
    let counts: (i64, i64, i64) = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 2),
                (SELECT COUNT(*) FROM events WHERE aggregate_type = 2),
                (SELECT COUNT(*) FROM command_receipts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0, 0));
}

// ── Test 1: PRAGMA profile ───────────────────────────────────────────────

#[test]
fn test_pragma_profile() {
    let db_path = temp_db_path("pragma");
    cleanup_db(&db_path);

    let (_store, _svc) = open_service(&db_path);

    // Verify PRAGMAs via direct rusqlite connection
    let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();

    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode, "wal", "expected WAL journal mode");

    let synchronous: i32 = conn
        .query_row("PRAGMA synchronous;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(synchronous, 2, "expected FULL synchronous (2)");

    let fk: i32 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(fk, 1, "expected foreign_keys = ON");

    // fullfsync is macOS-only
    #[cfg(target_os = "macos")]
    {
        let fullfsync: i32 = conn
            .query_row("PRAGMA fullfsync;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fullfsync, 1, "expected fullfsync = 1 on macOS");
    }

    cleanup_db(&db_path);
}

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
        let store =
            StoreTransaction::open(&db_path, RuntimeAuthorityId("test-host".into())).unwrap();
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

    let reopened =
        StoreTransaction::open(&db_path, RuntimeAuthorityId("test-host".into())).unwrap();
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
    let store = StoreTransaction::open(&db_path, RuntimeAuthorityId("test-host".into())).unwrap();
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
    let store = StoreTransaction::open(&db_path, RuntimeAuthorityId("test-host".into())).unwrap();
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
        let store =
            StoreTransaction::open(&db_path, RuntimeAuthorityId("test-host".into())).unwrap();
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

// ── Test 2: Full lifecycle ───────────────────────────────────────────────

#[test]
fn test_full_lifecycle() {
    let db_path = temp_db_path("full-lifecycle");
    cleanup_db(&db_path);

    let (_store, svc) = open_service(&db_path);

    // Create
    let outcome = svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let tr_id = match outcome {
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(new_version, 1);
            taskrun_id
        }
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Queue
    let outcome = svc
        .queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunQueued { new_version: 2, .. }
    ));

    // Admit
    let outcome = svc
        .admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunAdmitted { new_version: 3, .. }
    ));

    // Start attempt
    let outcome = svc
        .start_attempt(
            &make_context(4),
            StartAttemptInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::AttemptStarted { new_version: 4, .. }
    ));

    // Complete
    let outcome = svc
        .complete_task_run(
            &make_context(5),
            CompleteTaskRunInput {
                taskrun_id: tr_id,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunCompleted { new_version: 5, .. }
    ));

    cleanup_db(&db_path);
}

// ── Test 3: Replay after reopen ──────────────────────────────────────────

#[test]
fn test_replay_after_reopen() {
    let db_path = temp_db_path("replay-reopen");
    cleanup_db(&db_path);

    let tr_id: TaskRunId = {
        let (_store, svc) = open_service(&db_path);

        let outcome = svc
            .create_task_run(
                &make_context(1),
                CreateTaskRunInput {
                    conversation_id: make_conv_id(),
                    workspace_id: make_ws_id(),
                },
            )
            .unwrap();
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        };

        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();

        svc.admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();

        svc.start_attempt(
            &make_context(4),
            StartAttemptInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap();

        tr_id
    }; // store dropped — connections closed

    // Reopen
    let (store, _svc) = open_service(&db_path);

    // Load stream
    let stream: LoadedStream = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 4, "expected 4 events");
    assert_eq!(stream.events.len(), 4);
    assert!(stream.last_event_id.is_some());

    // Verify sequences are consecutive
    for (i, env) in stream.events.iter().enumerate() {
        assert_eq!(
            env.sequence(),
            (i + 1) as u64,
            "sequence mismatch at index {}",
            i
        );
    }

    // Replay aggregate
    let agg = TaskRun::replay(&stream.events).unwrap();
    assert!(
        !agg.state().is_terminal(),
        "aggregate should not be terminal after create+queue+admit+start"
    );

    cleanup_db(&db_path);
}

#[test]
fn test_correlation_metadata_is_persisted_and_corruption_fails_closed() {
    let db_path = temp_db_path("correlation-metadata");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);
    let outcome = svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let taskrun_id = match outcome {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();
    let (correlation_id, correlation_type, integrity_profile): (Vec<u8>, i64, i64) = conn
        .query_row(
            "SELECT correlation_id, correlation_type, integrity_profile
             FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1",
            rusqlite::params![taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(correlation_id, taskrun_id.as_bytes());
    assert_eq!(correlation_type, 1);
    assert_eq!(integrity_profile, 1);

    conn.execute(
        "UPDATE events SET correlation_type = 2
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
        rusqlite::params![taskrun_id.as_bytes()],
    )
    .unwrap();
    assert!(matches!(
        store.load_task_run(taskrun_id),
        Err(EventStoreError::CorruptData)
    ));

    conn.execute(
        "UPDATE events SET correlation_type = 1, integrity_profile = 2
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
        rusqlite::params![taskrun_id.as_bytes()],
    )
    .unwrap();
    assert!(matches!(
        store.load_task_run(taskrun_id),
        Err(EventStoreError::CorruptData)
    ));

    conn.execute(
        "UPDATE events SET integrity_profile = 1
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
        rusqlite::params![taskrun_id.as_bytes()],
    )
    .unwrap();
    assert!(
        conn.execute(
            "UPDATE events SET correlation_id = x'00'
             WHERE aggregate_type = 1 AND aggregate_id = ?1",
            rusqlite::params![taskrun_id.as_bytes()],
        )
        .is_err()
    );
    assert!(store.load_task_run(taskrun_id).is_ok());

    conn.execute(
        "UPDATE events SET correlation_id = zeroblob(16)
         WHERE aggregate_type = 1 AND aggregate_id = ?1",
        rusqlite::params![taskrun_id.as_bytes()],
    )
    .unwrap();
    assert!(matches!(
        store.load_task_run(taskrun_id),
        Err(EventStoreError::CorruptData)
    ));

    cleanup_db(&db_path);
}

// ── Test 4: Dedup — repeat command returns original result ────────────────

#[test]
fn test_dedup_repeat_command() {
    let db_path = temp_db_path("dedup");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);

    let ctx = make_context(1);
    let input = CreateTaskRunInput {
        conversation_id: make_conv_id(),
        workspace_id: make_ws_id(),
    };

    // First call
    let first = svc.create_task_run(&ctx, input.clone()).unwrap();
    let tr_id = match first {
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(new_version, 1);
            taskrun_id
        }
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Repeat with same context → dedup, same result
    let second = svc.create_task_run(&ctx, input).unwrap();
    match second {
        CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        } => {
            assert_eq!(taskrun_id, tr_id, "dedup should return same taskrun_id");
            assert_eq!(new_version, 1, "dedup should return same version");
        }
        other => panic!("expected TaskRunCreated (dedup), got {:?}", other),
    }

    // Verify events NOT duplicated: version should still be 1
    let stream = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 1, "events should not be duplicated");
    assert_eq!(stream.events.len(), 1);

    // Queue dedup
    let ctx_q = make_context(2);
    svc.queue_task_run(
        &ctx_q,
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap(); // version now 2

    // Repeat queue with same context → dedup
    let retry = svc
        .queue_task_run(
            &ctx_q,
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
    assert!(matches!(
        retry,
        CommandOutcome::TaskRunQueued { new_version: 2, .. }
    ));

    // Check stream: should still have 2 events, not 3
    let stream2 = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream2.current_version, 2);
    assert_eq!(stream2.events.len(), 2);

    cleanup_db(&db_path);
}

// ── Test 5: VersionConflict — stale expected_version ─────────────────────

#[test]
fn test_version_conflict() {
    let db_path = temp_db_path("version-conflict");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);

    // Create (version 1)
    let outcome = svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let tr_id = match outcome {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Queue at version 1 → success (version becomes 2)
    svc.queue_task_run(
        &make_context(2),
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap();

    // Queue again at version 1 (stale) → VersionConflict
    let err = svc
        .queue_task_run(
            &make_context(3),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap_err();

    assert!(
        matches!(
            err,
            ApplicationError::VersionConflict {
                expected: 1,
                actual: 2
            }
        ),
        "expected VersionConflict, got {:?}",
        err,
    );

    // Verify stream was NOT modified (still version 2)
    let stream = store.load_task_run(tr_id).unwrap();
    assert_eq!(
        stream.current_version, 2,
        "stream should be unchanged after conflict"
    );
    assert_eq!(stream.events.len(), 2);

    cleanup_db(&db_path);
}

// ── Test 6: IdempotencyConflict — same scope+key, different fingerprint ──

#[test]
fn test_idempotency_conflict_different_fingerprint() {
    let db_path = temp_db_path("idem-conflict");
    cleanup_db(&db_path);

    let (_store, svc) = open_service(&db_path);

    // Create
    let outcome = svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap();
    let tr_id = match outcome {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {:?}", other),
    };

    // Queue at version 1 with idempotency key from context(2)
    svc.queue_task_run(
        &make_context(2),
        QueueTaskRunInput {
            taskrun_id: tr_id,
            expected_version: 1,
        },
    )
    .unwrap();

    // Same idempotency_key ("test-key-2"), different CommandId and expected_version
    // → different fingerprint. Scope+key matches → IdempotencyConflict.
    let conflict_ctx = ApplicationCommandContext {
        command_id: CommandId::from_bytes([
            0x02, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x99,
        ]),
        idempotency_key: IdempotencyKey::new("test-key-2").unwrap(),
        principal_id: PrincipalId("test-principal".into()),
        actor: Actor::new("test-actor-99").unwrap(),
    };
    let err = svc
        .queue_task_run(
            &conflict_ctx,
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap_err();

    assert!(
        matches!(err, ApplicationError::IdempotencyConflict { .. }),
        "expected IdempotencyConflict, got {:?}",
        err,
    );

    cleanup_db(&db_path);
}

// ── Test 7: ClockRegression — reject timestamps going backwards ──────────

#[test]
fn test_clock_regression() {
    let db_path = temp_db_path("clock-regression");
    cleanup_db(&db_path);

    let tr_id: TaskRunId = {
        let (_store, svc) = open_service(&db_path);

        let outcome = svc
            .create_task_run(
                &make_context(1),
                CreateTaskRunInput {
                    conversation_id: make_conv_id(),
                    workspace_id: make_ws_id(),
                },
            )
            .unwrap();
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        };

        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();

        tr_id
    }; // store dropped — connections closed, WAL checkpointed

    // Open DB directly and set last_timestamp to a far-future value
    {
        let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute(
            "UPDATE aggregate_streams SET last_timestamp = ?1",
            rusqlite::params![i64::MAX],
        )
        .unwrap();
    }

    // Reopen store and try to commit — should detect clock regression.
    // The service maps ClockRegression to StorageFailed(IntegrityViolation).
    let (_store, svc) = open_service(&db_path);

    let err = svc
        .admit_task_run(
            &make_context(5),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap_err();

    assert!(
        matches!(
            err,
            ApplicationError::StorageFailed(StorageFailureKind::IntegrityViolation)
        ),
        "expected StorageFailed(IntegrityViolation) from ClockRegression, got {:?}",
        err,
    );

    cleanup_db(&db_path);
}

// ── Test 8: Two competing writers ────────────────────────────────────────

#[test]
fn test_two_competing_writers() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let db_path = temp_db_path("competing");
    cleanup_db(&db_path);

    let tr_id: TaskRunId = {
        let (_store, svc) = open_service(&db_path);
        let outcome = svc
            .create_task_run(
                &make_context(1),
                CreateTaskRunInput {
                    conversation_id: make_conv_id(),
                    workspace_id: make_ws_id(),
                },
            )
            .unwrap();
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("{other:?}"),
        };
        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();
        tr_id
    };

    let barrier = Arc::new(Barrier::new(2));
    let db = Arc::new(db_path.clone());
    let tr = Arc::new(tr_id);
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = vec![];
    for i in 0..2 {
        let db = Arc::clone(&db);
        let tr = Arc::clone(&tr);
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);
        let ctx = make_context(10 + i);
        handles.push(thread::spawn(move || {
            let store =
                StoreTransaction::open(&db, RuntimeAuthorityId("test-host".into())).unwrap();
            let ra = store.runtime_authority_id().clone();
            let svc = TaskRunService::new(store.clone(), store.clone(), store.clone(), ra);
            barrier.wait();
            let r = svc.admit_task_run(
                &ctx,
                AdmitTaskRunInput {
                    taskrun_id: *tr,
                    expected_version: 2,
                },
            );
            results.lock().unwrap().push(r);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let res = results.lock().unwrap();
    let committed = res.iter().filter(|r| r.is_ok()).count();
    assert_eq!(committed, 1, "exactly one writer must commit, got {res:?}");

    let (_store, _svc) = open_service(&db_path);
    let stream = _store.load_task_run(*tr).unwrap();
    assert_eq!(
        stream.current_version, 3,
        "stream must have exactly 3 events"
    );
    cleanup_db(&db_path);
}

#[test]
fn taskrun_crash_mid_lifecycle_preserves_all_committed_events() {
    let db_path = temp_db_path("taskrun-crash-mid-lifecycle");
    cleanup_db(&db_path);

    let (store, svc) = open_service(&db_path);
    let taskrun_id = match svc
        .create_task_run(
            &make_context(1),
            CreateTaskRunInput {
                conversation_id: make_conv_id(),
                workspace_id: make_ws_id(),
            },
        )
        .unwrap()
    {
        CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
        other => panic!("expected TaskRunCreated, got {other:?}"),
    };
    svc.queue_task_run(
        &make_context(2),
        QueueTaskRunInput {
            taskrun_id,
            expected_version: 1,
        },
    )
    .unwrap();
    svc.admit_task_run(
        &make_context(3),
        AdmitTaskRunInput {
            taskrun_id,
            expected_version: 2,
        },
    )
    .unwrap();
    svc.start_attempt(
        &make_context(4),
        StartAttemptInput {
            taskrun_id,
            expected_version: 3,
        },
    )
    .unwrap();

    std::mem::forget(svc);
    std::mem::forget(store);

    let (reopened_store, reopened_service) = open_service(&db_path);
    let stream = reopened_store.load_task_run(taskrun_id).unwrap();
    assert_eq!(stream.current_version, 4);
    assert_eq!(stream.events.len(), 4);
    assert!(
        !TaskRun::replay(&stream.events)
            .unwrap()
            .state()
            .is_terminal()
    );

    reopened_service
        .complete_task_run(
            &make_context(5),
            CompleteTaskRunInput {
                taskrun_id,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
        .unwrap();
    assert_eq!(
        reopened_store
            .load_task_run(taskrun_id)
            .unwrap()
            .events
            .len(),
        5
    );

    cleanup_db(&db_path);
}

#[test]
fn two_writers_racing_on_start_and_complete_have_exactly_one_winner_each() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let db_path = temp_db_path("start-complete-race");
    cleanup_db(&db_path);
    let taskrun_id = {
        let (_store, svc) = open_service(&db_path);
        let taskrun_id = match svc
            .create_task_run(
                &make_context(1),
                CreateTaskRunInput {
                    conversation_id: make_conv_id(),
                    workspace_id: make_ws_id(),
                },
            )
            .unwrap()
        {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {other:?}"),
        };
        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id,
                expected_version: 1,
            },
        )
        .unwrap();
        svc.admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
        taskrun_id
    };

    type RaceOperation = fn(
        &TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>,
        &ApplicationCommandContext,
        TaskRunId,
    ) -> Result<CommandOutcome, ApplicationError>;
    let race = |counter: u16, operation: RaceOperation| {
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for offset in 0..2 {
            let barrier = Arc::clone(&barrier);
            let path = db_path.clone();
            handles.push(thread::spawn(move || {
                let (store, service) = open_service(&path);
                barrier.wait();
                let result = operation(&service, &make_context(counter + offset), taskrun_id);
                drop(store);
                result
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    };

    let start = race(10, |service, context, taskrun_id| {
        service.start_attempt(
            context,
            StartAttemptInput {
                taskrun_id,
                expected_version: 3,
            },
        )
    });
    assert_eq!(
        start.iter().filter(|result| result.is_ok()).count(),
        1,
        "unexpected start race outcomes: {start:?}"
    );
    assert_eq!(
        start
            .iter()
            .filter(|result| matches!(
                result,
                Err(ApplicationError::VersionConflict {
                    expected: 3,
                    actual: 4
                })
            ))
            .count(),
        1,
        "unexpected start race outcomes: {start:?}"
    );

    let complete = race(20, |service, context, taskrun_id| {
        service.complete_task_run(
            context,
            CompleteTaskRunInput {
                taskrun_id,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
    });
    assert_eq!(
        complete.iter().filter(|result| result.is_ok()).count(),
        1,
        "unexpected completion race outcomes: {complete:?}"
    );
    assert_eq!(
        complete
            .iter()
            .filter(|result| matches!(
                result,
                Err(ApplicationError::VersionConflict {
                    expected: 4,
                    actual: 5
                })
            ))
            .count(),
        1,
        "unexpected completion race outcomes: {complete:?}"
    );
    assert_eq!(
        open_service(&db_path)
            .0
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        5
    );

    cleanup_db(&db_path);
}

// ── Test 9: WAL reopen — data survives close/reopen ──────────────────────

#[test]
fn test_wal_reopen_data_intact() {
    let db_path = temp_db_path("wal-reopen");
    cleanup_db(&db_path);

    // Phase 1: create + queue + admit
    let tr_id: TaskRunId = {
        let (_store, svc) = open_service(&db_path);

        let outcome = svc
            .create_task_run(
                &make_context(1),
                CreateTaskRunInput {
                    conversation_id: make_conv_id(),
                    workspace_id: make_ws_id(),
                },
            )
            .unwrap();
        let tr_id = match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        };

        svc.queue_task_run(
            &make_context(2),
            QueueTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 1,
            },
        )
        .unwrap();

        svc.admit_task_run(
            &make_context(3),
            AdmitTaskRunInput {
                taskrun_id: tr_id,
                expected_version: 2,
            },
        )
        .unwrap();

        tr_id
    }; // store dropped

    // Phase 2: reopen and verify data intact (WAL mode verified via PRAGMA in Test 1) and continue from version 3
    let (store, svc) = open_service(&db_path);

    // Load stream — should have 3 events
    let stream = store.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 3);
    assert_eq!(stream.events.len(), 3);

    // Verify replay works
    let agg = TaskRun::replay(&stream.events).unwrap();
    assert!(!agg.state().is_terminal());

    // Continue: start attempt (version 3 → 4)
    let outcome = svc
        .start_attempt(
            &make_context(4),
            StartAttemptInput {
                taskrun_id: tr_id,
                expected_version: 3,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::AttemptStarted { new_version: 4, .. }
    ));

    // Complete (version 4 → 5)
    let outcome = svc
        .complete_task_run(
            &make_context(5),
            CompleteTaskRunInput {
                taskrun_id: tr_id,
                result: TerminalResult::Success,
                expected_version: 4,
            },
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CommandOutcome::TaskRunCompleted { new_version: 5, .. }
    ));

    // Final check via a fresh open: 5 events total
    let (store3, _svc3) = open_service(&db_path);
    let stream = store3.load_task_run(tr_id).unwrap();
    assert_eq!(stream.current_version, 5);
    assert_eq!(stream.events.len(), 5);

    cleanup_db(&db_path);
}

// ── Test 10: Schema mismatch — verify fail-closed behavior ────────────────

#[test]
fn test_schema_mismatch_fail_closed() {
    let db_path = temp_db_path("schema-mismatch");
    cleanup_db(&db_path);

    // Phase 1: create a valid store with data
    let tr_id: TaskRunId = {
        let (_store, svc) = open_service(&db_path);

        let outcome = svc
            .create_task_run(
                &make_context(1),
                CreateTaskRunInput {
                    conversation_id: make_conv_id(),
                    workspace_id: make_ws_id(),
                },
            )
            .unwrap();
        match outcome {
            CommandOutcome::TaskRunCreated { taskrun_id, .. } => taskrun_id,
            other => panic!("expected TaskRunCreated, got {:?}", other),
        }
    }; // store dropped

    // Phase 2: corrupt the DB by dropping the events table
    {
        let conn = gocode_store::schema::open_with_pragmas(&db_path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        // Drop the events table — integrity_check checks internal b-tree
        // integrity, not application table presence, so reopen won't fail.
        conn.execute_batch("DROP TABLE events;").unwrap();
    }

    // Phase 3: reopen — should succeed (PRAGMA integrity_check passes)
    let (store, _svc) = open_service(&db_path);

    // Phase 4: try to load the stream — should fail because events table is missing
    let result = store.load_task_run(tr_id);
    assert!(
        result.is_err(),
        "loading with missing tables should fail — fail-closed"
    );
    match result {
        Err(EventStoreError::CorruptData) => {
            // Expected: fail-closed on corrupted schema
        }
        other => panic!("expected CorruptData, got {:?}", other),
    }

    cleanup_db(&db_path);
}
