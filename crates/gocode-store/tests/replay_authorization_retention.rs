//! Authorization lease races and retention continuity for durable replay.

use std::sync::{Arc, Mutex};

use gocode_application::ports::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    ReplayEvent, ReplayOpenResult, ReplaySession, ReplayStorePort,
};
use gocode_application::replay_service::{ReplayDeliveryPrecommitGuard, ReplayService};
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AggregateId, AttemptId, CommandId, ConversationId, EventId, EventLogLineageId, IdempotencyKey,
    IntegrityDigest, MessageId, TaskRunId,
};
use gocode_domain::message::MessageText;
use gocode_domain::replay::ReplayScope;
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use gocode_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
use gocode_store::integrity::{
    compute_integrity_digest_v2_with_global_position, compute_integrity_digest_with_global_position,
};
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::apply_migrations;
use rusqlite::Connection;
use tempfile::TempDir;

const AUTHORITY: [u8; 16] = [0xAA; 16];
const AGGREGATE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0xbb,
];
const LINEAGE: [u8; 16] = [0xBB; 16];
const SECRET: [u8; 32] = [0xCC; 32];

#[derive(Clone)]
struct MutableAuthorization {
    state: Arc<Mutex<AuthorizationState>>,
    ceiling: Sensitivity,
}

struct AuthorizationState {
    epoch: i64,
    leases_until_revocation: Option<usize>,
}

impl MutableAuthorization {
    fn new(epoch: i64, ceiling: Sensitivity) -> Self {
        Self {
            state: Arc::new(Mutex::new(AuthorizationState {
                epoch,
                leases_until_revocation: None,
            })),
            ceiling,
        }
    }

    fn revoke(&self) {
        self.state.lock().unwrap().epoch += 1;
    }

    fn revoke_after_next_lease(&self) {
        self.state.lock().unwrap().leases_until_revocation = Some(2);
    }
}

impl ReplayAuthorizationPort for MutableAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        let mut state = self.state.lock().unwrap();
        if let Some(remaining) = state.leases_until_revocation.as_mut() {
            *remaining -= 1;
            if *remaining == 0 {
                state.epoch += 1;
                state.leases_until_revocation = None;
            }
        }
        ReplayAuthorizationLease::new(request.principal_id.clone(), state.epoch, self.ceiling)
    }
}

struct RevokingDeliveryGuard(MutableAuthorization);

impl ReplayDeliveryPrecommitGuard for RevokingDeliveryGuard {
    fn inspect(
        &self,
        _session: &ReplaySession,
        _events: &[ReplayEvent],
    ) -> Result<(), ReplayError> {
        self.0.revoke();
        Ok(())
    }
}

struct AvailableDeliveryGuard;

impl ReplayDeliveryPrecommitGuard for AvailableDeliveryGuard {
    fn inspect(
        &self,
        _session: &ReplaySession,
        _events: &[ReplayEvent],
    ) -> Result<(), ReplayError> {
        Ok(())
    }
}

fn event_id(position: i64) -> [u8; 16] {
    let mut bytes = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0,
    ];
    bytes[14..].copy_from_slice(&u16::try_from(position).unwrap().to_be_bytes());
    bytes
}

fn insert_taskrun_event(connection: &Connection, sequence: i64, position: i64) {
    let event_id_bytes = event_id(position);
    let taskrun_id = TaskRunId::from_bytes(AGGREGATE);
    let idempotency_key = IdempotencyKey::new(format!("replay-event-{position}")).unwrap();
    let actor = Actor::new("test-actor").unwrap();
    let payload = TaskRunEvent::TaskRunCreated;
    let payload_bytes = TaskRunEventCodec.encode(&payload).unwrap();
    let envelope = EventEnvelope::from_parts(
        EventId::from_bytes(event_id_bytes),
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        CommandId::from_bytes(event_id_bytes),
        idempotency_key.clone(),
        1,
        actor,
        Sensitivity::Public,
        payload,
        u64::try_from(sequence).unwrap(),
        Timestamp::from_unix_micros(0),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_with_global_position(&envelope, position, &payload_bytes).unwrap();
    connection
        .execute(
            "INSERT INTO events (
                event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
                sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
                payload, integrity_digest, correlation_id, correlation_type, integrity_profile
             ) VALUES (?1, 1, ?2, ?3, ?4, 0, 0, 1, NULL, ?1, ?5, ?6, ?7, ?8, ?2, 1, 1)",
            rusqlite::params![
                event_id_bytes.as_slice(),
                AGGREGATE.as_slice(),
                sequence,
                position,
                idempotency_key.as_str().as_bytes(),
                b"test-actor".as_slice(),
                payload_bytes,
                digest.as_bytes().as_slice(),
            ],
        )
        .unwrap();
}

fn insert_sensitive_conversation_event(connection: &Connection) {
    let conversation_id = ConversationId::from_bytes(AGGREGATE);
    let event_id_bytes = event_id(1);
    let payload = ConversationEvent::UserMessageAppended {
        message_id: MessageId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x21,
        ]),
        taskrun_id: TaskRunId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x22,
        ]),
        attempt_id: AttemptId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0x23,
        ]),
        text: MessageText::new("classified").unwrap(),
    };
    let payload_bytes = ConversationEventCodec.encode(&payload).unwrap();
    let idempotency_key = IdempotencyKey::new("replay-sensitive-1").unwrap();
    let envelope = EventEnvelope::from_parts(
        EventId::from_bytes(event_id_bytes),
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        None,
        CommandId::from_bytes(event_id_bytes),
        idempotency_key.clone(),
        1,
        Actor::new("test-actor").unwrap(),
        Sensitivity::Sensitive,
        payload,
        1,
        Timestamp::from_unix_micros(0),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_v2_with_global_position(&envelope, 1, &payload_bytes).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (2, ?1, 1, ?2, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), event_id_bytes.as_slice()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO events (
                event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
                sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
                payload, integrity_digest, correlation_id, correlation_type, integrity_profile
             ) VALUES (?1, 2, ?2, 1, 1, 0, 2, 1, NULL, ?1, ?3, ?4, ?5, ?6, ?2, 2, 2)",
            rusqlite::params![
                event_id_bytes.as_slice(),
                AGGREGATE.as_slice(),
                idempotency_key.as_str().as_bytes(),
                b"test-actor".as_slice(),
                payload_bytes,
                digest.as_bytes().as_slice(),
            ],
        )
        .unwrap();
}

fn store_with_events(count: i64) -> ReplayStore {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (1, ?1, ?2, ?3, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), count, event_id(count).as_slice()],
        )
        .unwrap();
    for position in 1..=count {
        insert_taskrun_event(&connection, position, position);
    }
    ReplayStore::new(connection)
}

fn file_store_with_events(count: i64) -> (ReplayStore, Connection, TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (1, ?1, ?2, ?3, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), count, event_id(count).as_slice()],
        )
        .unwrap();
    for position in 1..=count {
        insert_taskrun_event(&connection, position, position);
    }
    drop(connection);
    let store_connection = Connection::open(&path).unwrap();
    let observer = Connection::open(&path).unwrap();
    (ReplayStore::new(store_connection), observer, directory)
}

fn service(store: ReplayStore, authorization: MutableAuthorization) -> ReplayService {
    ReplayService::new_authorized(
        Arc::new(store),
        SECRET,
        EventLogLineageId::from_bytes(LINEAGE),
        Arc::new(authorization),
    )
}

fn scope() -> ReplayScope {
    ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: AGGREGATE,
    }
}

#[tokio::test]
async fn revocation_after_page_selection_returns_no_page_and_preserves_progress() {
    let (store, observer, _directory) = file_store_with_events(101);
    let authorization = MutableAuthorization::new(7, Sensitivity::Sensitive);
    let service = service(store.clone(), authorization.clone());
    let (session, _) = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap();
    let before = session.last_delivered_position;

    let error = service
        .read_page(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            Arc::new(RevokingDeliveryGuard(authorization)),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
    let persisted: Option<i64> = observer
        .query_row(
            "SELECT last_delivered_position
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(persisted, before);
}

#[tokio::test]
async fn revocation_after_ack_validation_preserves_acknowledged_cursor() {
    let (store, observer, _directory) = file_store_with_events(1);
    let authorization = MutableAuthorization::new(7, Sensitivity::Sensitive);
    let service = service(store, authorization.clone());
    let (session, events) = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap();
    let cursor = service
        .build_cursor_from_event(&events[0], &scope())
        .unwrap();
    authorization.revoke_after_next_lease();

    let error = service
        .acknowledge(&session.session_id, "principal", 1, &AUTHORITY, 7, &cursor)
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
    let last_acked: Option<i64> = observer
        .query_row(
            "SELECT last_acked_position FROM _replay_subscriptions WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_acked, None);
}

#[tokio::test]
async fn live_event_revocation_stops_before_event_and_preserves_progress() {
    let (store, writer, _directory) = file_store_with_events(1);
    let authorization = MutableAuthorization::new(7, Sensitivity::Sensitive);
    let service = service(store, authorization.clone());
    let (session, events) = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap();
    let cursor = service
        .build_cursor_from_event(&events[0], &scope())
        .unwrap();
    service
        .acknowledge(&session.session_id, "principal", 1, &AUTHORITY, 7, &cursor)
        .await
        .unwrap();
    service
        .complete_catch_up(&session.session_id, "principal", 1, &AUTHORITY, 7)
        .await
        .unwrap();
    service
        .continue_live(&session.session_id, "principal", 1, &AUTHORITY, 7)
        .await
        .unwrap();
    insert_taskrun_event(&writer, 2, 2);
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 2, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![event_id(2).as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();

    let error = service
        .poll_live(
            &session.session_id,
            "principal",
            1,
            &AUTHORITY,
            7,
            Arc::new(RevokingDeliveryGuard(authorization)),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
    let last_delivered: Option<i64> = writer
        .query_row(
            "SELECT last_delivered_position FROM _replay_subscriptions WHERE session_id = ?1",
            [session.session_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_delivered, Some(1));
}

#[tokio::test]
async fn sensitivity_denied_stops_before_session_and_denied_cursor() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    insert_sensitive_conversation_event(&connection);
    let store = ReplayStore::new(connection);
    let service = service(store, MutableAuthorization::new(0, Sensitivity::Public));

    let error = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            0,
            2,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::SensitivityDenied));
}

#[tokio::test]
async fn retained_prefix_gap_returns_authorized_floor_without_cursor_jump() {
    let (store, writer, _directory) = file_store_with_events(3);
    let authorization = MutableAuthorization::new(7, Sensitivity::Sensitive);
    let service = service(store, authorization);
    let (_, events) = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            &AGGREGATE,
            None,
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap();
    let cursor = service
        .build_cursor_from_event(&events[0], &scope())
        .unwrap();
    let session_count_before: i64 = writer
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap();
    writer
        .execute("DELETE FROM events WHERE global_position = 1", [])
        .unwrap();

    let error = service
        .open_session(
            "principal",
            1,
            &AUTHORITY,
            7,
            1,
            &AGGREGATE,
            Some(cursor),
            Arc::new(AvailableDeliveryGuard),
        )
        .await
        .unwrap_err();

    match error {
        ReplayError::ReplayRetentionGap {
            floor_cursor: Some(floor_cursor),
            gap_range_ref,
        } => {
            assert_eq!(floor_cursor.global_position, 2);
            assert_ne!(gap_range_ref.integrity().as_bytes(), &[0; 32]);
        }
        other => panic!("unexpected gap result: {other:?}"),
    }
    let session_count_after: i64 = writer
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(session_count_after, session_count_before);
}

#[tokio::test]
async fn retention_manifest_proves_one_contiguous_snapshot() {
    let store = store_with_events(3);

    let manifest = store
        .retention_manifest(&EventLogLineageId::from_bytes(LINEAGE), &SECRET)
        .await
        .unwrap();

    assert_eq!(
        manifest.lineage_id(),
        &EventLogLineageId::from_bytes(LINEAGE)
    );
    assert_eq!(manifest.retention_generation(), 0);
    assert_eq!(manifest.retained_floor(), Some(1));
    assert_eq!(manifest.high_water_position(), 3);
    assert!(manifest.maximum_encoded_event_bytes() > 0);
    assert_ne!(manifest.no_gap_evidence().as_bytes(), &[0; 32]);
}

#[tokio::test]
async fn empty_retention_manifest_has_no_floor_and_zero_high_water() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    let store = ReplayStore::new(connection);

    let manifest = store
        .retention_manifest(&EventLogLineageId::from_bytes(LINEAGE), &SECRET)
        .await
        .unwrap();

    assert_eq!(manifest.retained_floor(), None);
    assert_eq!(manifest.high_water_position(), 0);
    assert_eq!(manifest.maximum_encoded_event_bytes(), 0);
}

#[test]
fn gap_reference_is_bound_to_scope_and_authorization_epoch() {
    let lineage = EventLogLineageId::from_bytes(LINEAGE);
    let first = ReplayStore::build_gap_range_ref(&lineage, 0, 3, 4, &scope(), 7, &SECRET);
    let other_scope = ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: [0xDD; 16],
    };
    let second = ReplayStore::build_gap_range_ref(&lineage, 0, 3, 4, &other_scope, 7, &SECRET);
    let third = ReplayStore::build_gap_range_ref(&lineage, 0, 3, 4, &scope(), 8, &SECRET);

    assert_ne!(first, second);
    assert_ne!(first, third);
}

#[allow(dead_code)]
fn opened(result: ReplayOpenResult) -> (ReplaySession, Vec<ReplayEvent>) {
    match result {
        ReplayOpenResult::Opened { session, events } => (session, events),
        ReplayOpenResult::RetentionGap { .. } => panic!("unexpected retention gap"),
    }
}
