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
    IntegrityDigest, MessageId, TaskRunId, WorkspaceId,
};
use gocode_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};
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

    fn mutate_with_current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
        mutation: &mut dyn FnMut(&ReplayAuthorizationLease) -> Result<usize, ReplayError>,
    ) -> Result<usize, ReplayError> {
        let mut state = self.state.lock().unwrap();
        if let Some(remaining) = state.leases_until_revocation.as_mut() {
            *remaining -= 1;
            if *remaining == 0 {
                state.epoch += 1;
                state.leases_until_revocation = None;
            }
        }
        let lease =
            ReplayAuthorizationLease::new(request.principal_id.clone(), state.epoch, self.ceiling)?;
        mutation(&lease)
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

fn insert_conversation_event(
    connection: &Connection,
    sequence: i64,
    position: i64,
    payload: ConversationEvent,
) {
    let conversation_id = ConversationId::from_bytes(AGGREGATE);
    let event_id_bytes = event_id(position);
    let sensitivity = payload.sensitivity();
    let payload_bytes = ConversationEventCodec.encode(&payload).unwrap();
    let idempotency_key = IdempotencyKey::new(format!("replay-conversation-{position}")).unwrap();
    let envelope = EventEnvelope::from_parts(
        EventId::from_bytes(event_id_bytes),
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        None,
        CommandId::from_bytes(event_id_bytes),
        idempotency_key.clone(),
        1,
        Actor::new("test-actor").unwrap(),
        sensitivity,
        payload,
        u64::try_from(sequence).unwrap(),
        Timestamp::from_unix_micros(0),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_v2_with_global_position(&envelope, position, &payload_bytes)
            .unwrap();
    connection
        .execute(
            "INSERT INTO events (
                event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
                sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
                payload, integrity_digest, correlation_id, correlation_type, integrity_profile
             ) VALUES (?1, 2, ?2, ?3, ?4, 0, ?5, 1, NULL, ?1, ?6, ?7, ?8, ?9, ?2, 2, 2)",
            rusqlite::params![
                event_id_bytes.as_slice(),
                AGGREGATE.as_slice(),
                sequence,
                position,
                match sensitivity {
                    Sensitivity::Public => 0,
                    Sensitivity::Internal => 1,
                    Sensitivity::Sensitive => 2,
                },
                idempotency_key.as_str().as_bytes(),
                b"test-actor".as_slice(),
                payload_bytes,
                digest.as_bytes().as_slice(),
            ],
        )
        .unwrap();
}

fn insert_sensitive_conversation_event(connection: &Connection) {
    connection
        .execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (2, ?1, 1, ?2, 0, 0)",
            rusqlite::params![AGGREGATE.as_slice(), event_id(1).as_slice()],
        )
        .unwrap();
    insert_conversation_event(
        connection,
        1,
        1,
        ConversationEvent::UserMessageAppended {
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
        },
    );
}
