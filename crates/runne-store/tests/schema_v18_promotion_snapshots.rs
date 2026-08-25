use runne_store::schema::{
    CURRENT_SCHEMA_VERSION, apply_migrations, apply_migrations_through_v15_for_test,
    apply_migrations_through_v19_for_test,
};
use std::sync::Arc;

use runne_api::CreateConversationInput;
use runne_api::ReplayPromotionProjectionViewV1;
use runne_api::UnauthenticatedReplayPromotionProjectionV1;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{ApplicationCommandContext, PrincipalId, RuntimeAuthorityId};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::Actor;
use runne_domain::event::{EventEnvelope, Sensitivity};
use runne_domain::id::{
    AggregateId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
    WorkspaceId,
};
use runne_domain::message::MessageText;
use runne_domain::task_run::TaskRunEvent;
use runne_domain::timestamp::Timestamp;
use runne_security::SecretBroker;
use runne_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
use runne_store::integrity::{
    compute_integrity_digest_v2_with_global_position, compute_integrity_digest_with_global_position,
};
use runne_store::store::StoreTransaction;
use rusqlite::{Connection, params};

#[path = "support/validated_reopen.rs"]
mod validated_reopen;

fn guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("v18-promotion").unwrap(),
    }
}

#[test]
fn current_schema_requires_bound_promotion_projection_columns() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();

    assert_eq!(CURRENT_SCHEMA_VERSION, 23);
    for column in [
        "promotion_codec_version",
        "promotion_projection_bytes",
        "promotion_projection_digest",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('aggregate_state_snapshots')
                 WHERE name = ?1)",
                [column],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing {column}");
    }
}

#[test]
fn writes_promotions_with_exact_times_taskrun_view_and_tamper_rejection() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database = daemon.join("promotion.sqlite");
    let authority = RuntimeAuthorityId("v18-promotion".into());
    let store =
        StoreTransaction::open(database.to_str().unwrap(), authority.clone(), guard()).unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000000e1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000000e2".parse().unwrap();
    validated_reopen::seed_canonical_workspace(&store, "local-owner", workspace_id);
    let create = context("018f2e3a-7000-7000-8000-0000000000e3", "promotion-create");
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create.command_id,
                idempotency_key: create.idempotency_key.clone(),
            },
        )
        .unwrap();
    let begun = ConversationTextService::new(store.clone(), store.clone(), authority, guard())
        .begin(
            &context("018f2e3a-7000-7000-8000-0000000000e4", "promotion-begin"),
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("exact timestamp").unwrap(),
            },
        )
        .unwrap();
    let connection = Connection::open(&database).unwrap();
    let user_timestamp: i64 = connection.query_row(
        "SELECT timestamp FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 2",
        [conversation_id.as_bytes()], |row| row.get(0),
    ).unwrap();
    let conversation_bytes: Vec<u8> = connection.query_row(
        "SELECT promotion_projection_bytes FROM aggregate_state_snapshots WHERE aggregate_type = 2 AND aggregate_id = ?1",
        [conversation_id.as_bytes()], |row| row.get(0),
    ).unwrap();
    let taskrun_bytes: Vec<u8> = connection.query_row(
        "SELECT promotion_projection_bytes FROM aggregate_state_snapshots WHERE aggregate_type = 1 AND aggregate_id = ?1",
        [begun.taskrun_id.as_bytes()], |row| row.get(0),
    ).unwrap();
    let conversation =
        UnauthenticatedReplayPromotionProjectionV1::decode(&conversation_bytes).unwrap();
    let ReplayPromotionProjectionViewV1::Conversation(view) = conversation.view() else {
        panic!("conversation promotion")
    };
    assert_eq!(view.aggregate_id(), *conversation_id.as_bytes());
    assert_eq!(view.messages().len(), 1);
    assert_eq!(view.messages()[0].committed_at_micros(), user_timestamp);
    let taskrun = UnauthenticatedReplayPromotionProjectionV1::decode(&taskrun_bytes).unwrap();
    let ReplayPromotionProjectionViewV1::TaskRun(view) = taskrun.view() else {
        panic!("taskrun promotion")
    };
    assert_eq!(view.aggregate_id(), *begun.taskrun_id.as_bytes());
    assert_eq!(view.semantic_state().lifecycle().as_str(), "running");
    assert_ne!(view.promotion_digest(), &[0; 32]);
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET promotion_projection_digest = zeroblob(32)
         WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
        )
        .unwrap();
    drop(connection);
    drop(store);
    assert!(
        StoreTransaction::open(
            database.to_str().unwrap(),
            RuntimeAuthorityId("v18-promotion".into()),
            guard()
        )
        .is_err()
    );
}

#[test]
fn incomplete_v19_history_rolls_back_the_entire_v20_rebuild() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_through_v19_for_test(&connection).unwrap();
    let taskrun_id: TaskRunId = "018f2e3a-7000-7000-8000-0000000000f1".parse().unwrap();
    let event_id: EventId = "018f2e3a-7000-7000-8000-0000000000f2".parse().unwrap();
    let command_id: CommandId = "018f2e3a-7000-7000-8000-0000000000f3".parse().unwrap();
    let event = EventEnvelope::from_parts(
        event_id,
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        command_id,
        IdempotencyKey::new("v18-incomplete").unwrap(),
        1,
        Actor::new("v18").unwrap(),
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let payload = TaskRunEventCodec.encode(event.payload()).unwrap();
    let digest = compute_integrity_digest_with_global_position(&event, 1, &payload).unwrap();
    connection.execute("INSERT INTO aggregate_streams (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) VALUES (1, ?1, 1, ?2, 1, 1)", params![taskrun_id.as_bytes(), event_id.as_bytes()]).unwrap();
    connection.execute("INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile) VALUES (?1, 1, ?2, 1, 1, 1, 0, 1, NULL, ?3, ?4, ?5, ?6, ?7, ?2, 1, 1)", params![event_id.as_bytes(), taskrun_id.as_bytes(), command_id.as_bytes(), event.idempotency_key().as_str().as_bytes(), event.actor().as_str().as_bytes(), payload, digest.as_bytes()]).unwrap();
    // V19 cannot have constructed a snapshot for a stream added after its migration.
    connection
        .execute(
            "UPDATE aggregate_streams SET current_version = 2 WHERE aggregate_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    assert!(apply_migrations(&connection).is_err());
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        19
    );
    let promotion_column: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('aggregate_state_snapshots') WHERE name = 'promotion_projection_bytes')", [], |row| row.get(0)).unwrap();
    assert!(!promotion_column);
}

#[test]
fn nonempty_v15_histories_upgrade_directly_to_v20_without_v19_waypoint() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_through_v15_for_test(&connection).unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000101".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000102".parse().unwrap();
    let taskrun_id: TaskRunId = "018f2e3a-7000-7000-8000-000000000103".parse().unwrap();
    insert_conversation_created(&connection, conversation_id, workspace_id);
    insert_taskrun_created(&connection, taskrun_id);
    apply_migrations(&connection).unwrap();
    let v19_markers: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM schema_version WHERE version = 19",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(v19_markers, 0);
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM aggregate_state_snapshots",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

fn insert_conversation_created(
    connection: &Connection,
    id: ConversationId,
    workspace: WorkspaceId,
) {
    let event_id: EventId = "018f2e3a-7000-7000-8000-000000000104".parse().unwrap();
    let command: CommandId = "018f2e3a-7000-7000-8000-000000000105".parse().unwrap();
    let event = EventEnvelope::from_parts(
        event_id,
        AggregateId::Conversation(id),
        AggregateId::Conversation(id),
        None,
        command,
        IdempotencyKey::new("v15-conversation").unwrap(),
        1,
        Actor::new("v15").unwrap(),
        Sensitivity::Public,
        ConversationEvent::ConversationCreated {
            workspace_id: workspace,
        },
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let payload = ConversationEventCodec.encode(event.payload()).unwrap();
    let digest = compute_integrity_digest_v2_with_global_position(&event, 1, &payload).unwrap();
    connection.execute("INSERT INTO aggregate_streams (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) VALUES (2, ?1, 1, ?2, 1, 1)", params![id.as_bytes(), event_id.as_bytes()]).unwrap();
    connection.execute("INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile) VALUES (?1, 2, ?2, 1, 1, 1, 0, 1, NULL, ?3, ?4, ?5, ?6, ?7, ?2, 2, 2)", params![event_id.as_bytes(), id.as_bytes(), command.as_bytes(), event.idempotency_key().as_str().as_bytes(), event.actor().as_str().as_bytes(), payload, digest.as_bytes()]).unwrap();
}

fn insert_taskrun_created(connection: &Connection, id: TaskRunId) {
    let event_id: EventId = "018f2e3a-7000-7000-8000-000000000106".parse().unwrap();
    let command: CommandId = "018f2e3a-7000-7000-8000-000000000107".parse().unwrap();
    let event = EventEnvelope::from_parts(
        event_id,
        AggregateId::TaskRun(id),
        AggregateId::TaskRun(id),
        None,
        command,
        IdempotencyKey::new("v15-taskrun").unwrap(),
        1,
        Actor::new("v15").unwrap(),
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
        1,
        Timestamp::from_unix_micros(2),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let payload = TaskRunEventCodec.encode(event.payload()).unwrap();
    let digest = compute_integrity_digest_with_global_position(&event, 2, &payload).unwrap();
    connection.execute("INSERT INTO aggregate_streams (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) VALUES (1, ?1, 1, ?2, 2, 2)", params![id.as_bytes(), event_id.as_bytes()]).unwrap();
    connection.execute("INSERT INTO events (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile) VALUES (?1, 1, ?2, 1, 2, 2, 0, 1, NULL, ?3, ?4, ?5, ?6, ?7, ?2, 1, 1)", params![event_id.as_bytes(), id.as_bytes(), command.as_bytes(), event.idempotency_key().as_str().as_bytes(), event.actor().as_str().as_bytes(), payload, digest.as_bytes()]).unwrap();
}
