// L2-I: SQLite integration tests for gocode-store.
//
// Uses a real temporary SQLite file and `StoreTransaction` for full
// persistence tests. Tests the complete lifecycle through the service
// layer, dedup, conflicts, reopen, concurrent writes, clock regression,
// and fail-closed behavior on schema corruption.

use std::sync::Arc;

use gocode_api::{
    ApiActor, ApiCommandContext, ApiPrincipalId, CreateConversationInput, ResponseSeed,
};
use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::conversation_service::{ConversationService, ConversationServiceError};
use gocode_application::errors::ApplicationError;
use gocode_application::fingerprint::CommandFingerprint;
use gocode_application::ports::{
    AggregateScope, ApplicationCommandContext, CommandCommit, CommitError, CommitResult,
    ConversationCommit, ConversationRepository, EventStore, EventStoreError, IdempotencyScope,
    LoadedStream, OperationTag, PrincipalId, ReceiptLookup, RuntimeAuthorityId,
    StorageFailureKind, UnitOfWork,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::service::TaskRunService;
use gocode_domain::command::{CreateTaskRun, TerminalResult};
use gocode_domain::conversation::{Conversation, ConversationEvent, ConversationState};
use gocode_domain::event::{
    Actor, CommandContext, Sensitivity, UncommittedEvent, materialize_batch,
};
use gocode_domain::id::{
    CommandId, ConversationId, EventId, IdempotencyKey, TaskRunId, WorkspaceId,
};
use gocode_domain::task_run::TaskRun;
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;

// ── Helpers ──────────────────────────────────────────────────────────────

fn temp_db_path(name: &str) -> String {
    let runtime_root = std::env::temp_dir().join(format!("gocode-test-l2i-{name}"));
    let daemon = runtime_root.join("gocode-daemon");
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

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn open_service(
    db_path: &str,
) -> (
    StoreTransaction,
    TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>,
) {
    let store = StoreTransaction::open(
        db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();
    validated_reopen::seed_canonical_workspace(&store, "test-principal", make_ws_id());
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

fn direct_taskrun_commit(
    store: &StoreTransaction,
    taskrun_id: TaskRunId,
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
    event_byte: u8,
) -> CommandCommit {
    let conversation_id = make_conv_id();
    let workspace_id = make_ws_id();
    let events = materialize_batch(
        vec![TaskRun::decide_create(CreateTaskRun {
            taskrun_id,
            conversation_id,
            workspace_id,
        })
        .unwrap()],
        &[
            format!("018f2e3a-7000-7000-8000-0000000000{event_byte:02x}")
                .parse()
                .unwrap(),
        ],
        None,
        &CommandContext {
            command_id,
            idempotency_key: idempotency_key.clone(),
            actor: Actor::new("direct-taskrun-test").unwrap(),
        },
    )
    .unwrap();
    CommandCommit {
        command_id,
        idempotency_key,
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: store.runtime_authority_id().clone(),
            principal_id: PrincipalId("test-principal".into()),
            operation: OperationTag::CreateTaskRun,
            aggregate_scope: AggregateScope::NewTaskRun {
                conversation_id,
                workspace_id,
            },
        },
        command_fingerprint: CommandFingerprint::for_create(&conversation_id, &workspace_id),
        expected_version: 0,
        events,
        command_result: CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version: 1,
        },
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
    let conn = gocode_store::schema::reopen_managed_connection_validated(
        std::path::Path::new(db_path),
        gocode_store::schema::ConnectionMode::Reader,
        |connection| {
            let version: i64 = connection.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )?;
            if version == gocode_store::schema::CURRENT_SCHEMA_VERSION {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    )
    .unwrap();
    gocode_store::schema::readiness_from_managed(&conn).unwrap();
    gocode_store::schema::publication_from_managed(&conn).unwrap();
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
    let database = validated_reopen::ValidatedTestDatabase::new("pragma");
    let db_path = database.path().to_owned();
    cleanup_db(&db_path);

    let (_store, identity) = validated_reopen::initialize_store(
        &db_path,
        RuntimeAuthorityId("test-host".into()),
        available_guard(),
    )
    .unwrap();

    // Verify PRAGMAs via direct rusqlite connection
    let conn = validated_reopen_store::open_validated_reader(&db_path, identity).unwrap();

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
