//! ReplayStore — SQLite-backed replay subscription persistence.
//!
//! Implements [`gocode_application::ports::ReplayStorePort`] using
//! the `_replay_subscriptions` table and the `events` table.
//!
//! All SQL operations are dispatched through [`tokio::task::spawn_blocking`]
//! to avoid blocking the async runtime.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use gocode_application::ports::{
    ReplayError, ReplayEvent, ReplaySession, ReplayState, ReplayStorePort,
};
use gocode_application::replay_service::ReplayDeliveryPrecommitGuard;
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AggregateId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use gocode_domain::replay::ReplayCursor;
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, params};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
use crate::integrity::{
    compute_integrity_digest_v2_with_global_position, compute_integrity_digest_with_global_position,
};

// ── HMAC ─────────────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;
const HIGH_WATER_REF_SCHEMA_VERSION: u32 = 1;

/// Build a 77-byte HMAC-protected `HighWaterRef`.
///
/// Layout: `authority_id[16] || floor_present[1] || retained_floor[8u64be] ||
/// retention_generation[8u64be] || ref_schema_version[4u32be] ||
/// global_position[8u64be] || proof[32]`.
///
/// The proof is `HMAC-SHA256(server_secret, all preceding fields || session_id[16])`.
fn build_high_water_ref(
    authority_id: &[u8; 16],
    floor: Option<i64>,
    global_position: i64,
    server_secret: &[u8; 32],
    session_id: &[u8; 16],
) -> Vec<u8> {
    let floor_present = if floor.is_some() { 1u8 } else { 0u8 };
    let floor_bytes = (floor.unwrap_or(0) as u64).to_be_bytes();
    let gen_bytes = 0u64.to_be_bytes(); // retention_generation = 0
    let schema_bytes = HIGH_WATER_REF_SCHEMA_VERSION.to_be_bytes();
    let pos_bytes = (global_position as u64).to_be_bytes();

    let mut msg = Vec::with_capacity(16 + 1 + 8 + 8 + 4 + 8 + 16);
    msg.extend_from_slice(authority_id);
    msg.push(floor_present);
    msg.extend_from_slice(&floor_bytes);
    msg.extend_from_slice(&gen_bytes);
    msg.extend_from_slice(&schema_bytes);
    msg.extend_from_slice(&pos_bytes);
    msg.extend_from_slice(session_id);

    let mut mac = HmacSha256::new_from_slice(server_secret).unwrap();
    mac.update(&msg);
    let proof = mac.finalize().into_bytes();

    let mut hw = Vec::with_capacity(77);
    hw.extend_from_slice(authority_id);
    hw.push(floor_present);
    hw.extend_from_slice(&floor_bytes);
    hw.extend_from_slice(&gen_bytes);
    hw.extend_from_slice(&schema_bytes);
    hw.extend_from_slice(&pos_bytes);
    hw.extend_from_slice(&proof);
    hw
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn invalid_column(index: usize, data_type: rusqlite::types::Type) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        data_type,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid canonical replay event column",
        )),
    )
}

fn replay_row_error(context: &'static str, error: rusqlite::Error) -> ReplayError {
    if matches!(
        error,
        rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
            | rusqlite::Error::InvalidColumnType(..)
    ) {
        ReplayError::Integrity("stored replay event failed integrity validation".to_owned())
    } else {
        ReplayError::Storage(format!("{context}: {error}"))
    }
}

fn fixed_blob<const N: usize>(blob: Vec<u8>, index: usize) -> rusqlite::Result<[u8; N]> {
    blob.try_into()
        .map_err(|_| invalid_column(index, rusqlite::types::Type::Blob))
}

fn optional_event_id(blob: Option<Vec<u8>>, index: usize) -> rusqlite::Result<Option<[u8; 16]>> {
    blob.map(|value| fixed_blob(value, index)).transpose()
}

fn taskrun_event_type(event: &TaskRunEvent) -> &'static str {
    match event {
        TaskRunEvent::TaskRunCreated => "TaskRunCreated",
        TaskRunEvent::TaskRunQueued => "TaskRunQueued",
        TaskRunEvent::TaskRunAdmitted => "TaskRunAdmitted",
        TaskRunEvent::AttemptStarted { .. } => "AttemptStarted",
        TaskRunEvent::WaitStarted => "WaitStarted",
        TaskRunEvent::Resumed => "Resumed",
        TaskRunEvent::RetryStarted { .. } => "RetryStarted",
        TaskRunEvent::RetryCompleted { .. } => "RetryCompleted",
        TaskRunEvent::CheckpointStarted => "CheckpointStarted",
        TaskRunEvent::CheckpointCommitted => "CheckpointCommitted",
        TaskRunEvent::CancellationRequested => "CancellationRequested",
        TaskRunEvent::CancellationCompleted => "CancellationCompleted",
        TaskRunEvent::TaskRunCompleted { .. } => "TaskRunCompleted",
        TaskRunEvent::TaskRunFailed { .. } => "TaskRunFailed",
        TaskRunEvent::BudgetExhausted => "BudgetExhausted",
        TaskRunEvent::PolicyDenied => "PolicyDenied",
        TaskRunEvent::ReconciliationStarted => "ReconciliationStarted",
        TaskRunEvent::Reconciled => "Reconciled",
        TaskRunEvent::Unrecoverable => "Unrecoverable",
        TaskRunEvent::TaskRunCancelled => "TaskRunCancelled",
        TaskRunEvent::LoopCycleStarted { .. } => "LoopCycleStarted",
        TaskRunEvent::ContextCommitted { .. } => "ContextCommitted",
        TaskRunEvent::PlanCommitted { .. } => "PlanCommitted",
        TaskRunEvent::StepOutcomeRecorded { .. } => "StepOutcomeRecorded",
        TaskRunEvent::LoopCycleCompleted { .. } => "LoopCycleCompleted",
        TaskRunEvent::NextCycleCreated { .. } => "NextCycleCreated",
        TaskRunEvent::RetryScheduled { .. } => "RetryScheduled",
        TaskRunEvent::ActivateScheduledRetryAttempt { .. } => "ActivateScheduledRetryAttempt",
        TaskRunEvent::RecoveryResumeStarted { .. } => "RecoveryResumeStarted",
        TaskRunEvent::LoopCheckpointStarted { .. } => "LoopCheckpointStarted",
        TaskRunEvent::LoopCheckpointRecorded { .. } => "LoopCheckpointRecorded",
        TaskRunEvent::LoopCheckpointCommitted { .. } => "LoopCheckpointCommitted",
        TaskRunEvent::LoopWakeAccepted { .. } => "LoopWakeAccepted",
    }
}

fn conversation_event_type(event: &ConversationEvent) -> &'static str {
    match event {
        ConversationEvent::ConversationCreated { .. } => "ConversationCreated",
        ConversationEvent::UserMessageAppended { .. } => "UserMessageAppended",
        ConversationEvent::AssistantMessageAppended { .. } => "AssistantMessageAppended",
        ConversationEvent::GenerationFailed { .. } => "GenerationFailed",
        ConversationEvent::ConversationClosed => "ConversationClosed",
    }
}

fn validated_event_id(bytes: [u8; 16], index: usize) -> rusqlite::Result<EventId> {
    let id = EventId::from_bytes(bytes);
    id.to_string()
        .parse()
        .map_err(|_| invalid_column(index, rusqlite::types::Type::Blob))
}

fn validated_command_id(bytes: [u8; 16], index: usize) -> rusqlite::Result<CommandId> {
    let id = CommandId::from_bytes(bytes);
    id.to_string()
        .parse()
        .map_err(|_| invalid_column(index, rusqlite::types::Type::Blob))
}

fn validate_replay_event_integrity(event: &ReplayEvent) -> rusqlite::Result<String> {
    let sequence = u64::try_from(event.sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| invalid_column(3, rusqlite::types::Type::Integer))?;
    if event.global_position <= 0 {
        return Err(invalid_column(4, rusqlite::types::Type::Integer));
    }
    if event.schema_version == 0 {
        return Err(invalid_column(7, rusqlite::types::Type::Integer));
    }
    let event_id = validated_event_id(event.event_id, 0)?;
    let causation_id = event
        .causation_id
        .map(|id| validated_event_id(id, 8))
        .transpose()?;
    let command_id = validated_command_id(event.command_id, 9)?;
    let idempotency_key = IdempotencyKey::new(event.idempotency_key.clone())
        .map_err(|_| invalid_column(10, rusqlite::types::Type::Blob))?;
    if event
        .actor
        .as_bytes()
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f)
    {
        return Err(invalid_column(11, rusqlite::types::Type::Blob));
    }
    let actor = Actor::new(event.actor.clone())
        .map_err(|_| invalid_column(11, rusqlite::types::Type::Blob))?;
    let sensitivity = match event.sensitivity {
        0 => Sensitivity::Public,
        1 => Sensitivity::Internal,
        2 => Sensitivity::Sensitive,
        _ => return Err(invalid_column(6, rusqlite::types::Type::Integer)),
    };
    let integrity_digest = IntegrityDigest::from_bytes(event.integrity_digest);
    let timestamp = Timestamp::from_unix_micros(event.timestamp);

    match event.aggregate_type {
        1 => {
            if event.correlation_type != 1
                || event.integrity_profile != 1
                || event.correlation_id != event.aggregate_id
                || sensitivity != Sensitivity::Public
            {
                return Err(invalid_column(15, rusqlite::types::Type::Integer));
            }
            let taskrun_id = TaskRunId::from_bytes(event.aggregate_id);
            let taskrun_id: TaskRunId = taskrun_id
                .to_string()
                .parse()
                .map_err(|_| invalid_column(2, rusqlite::types::Type::Blob))?;
            let payload = TaskRunEventCodec
                .decode(&event.payload)
                .map_err(|_| invalid_column(12, rusqlite::types::Type::Blob))?;
            let event_type = taskrun_event_type(&payload).to_owned();
            let envelope = EventEnvelope::from_parts(
                event_id,
                AggregateId::TaskRun(taskrun_id),
                AggregateId::TaskRun(taskrun_id),
                causation_id,
                command_id,
                idempotency_key,
                event.schema_version,
                actor,
                sensitivity,
                payload,
                sequence,
                timestamp,
                integrity_digest,
            );
            let expected = compute_integrity_digest_with_global_position(
                &envelope,
                event.global_position,
                &event.payload,
            )
            .map_err(|_| invalid_column(13, rusqlite::types::Type::Blob))?;
            if expected.as_bytes() != &event.integrity_digest {
                return Err(invalid_column(13, rusqlite::types::Type::Blob));
            }
            Ok(event_type)
        }
        2 => {
            if event.correlation_type != 2
                || event.integrity_profile != 2
                || event.correlation_id != event.aggregate_id
            {
                return Err(invalid_column(15, rusqlite::types::Type::Integer));
            }
            let conversation_id = ConversationId::from_bytes(event.aggregate_id);
            let conversation_id: ConversationId = conversation_id
                .to_string()
                .parse()
                .map_err(|_| invalid_column(2, rusqlite::types::Type::Blob))?;
            let payload = ConversationEventCodec
                .decode(&event.payload)
                .map_err(|_| invalid_column(12, rusqlite::types::Type::Blob))?;
            if payload.sensitivity() != sensitivity {
                return Err(invalid_column(6, rusqlite::types::Type::Integer));
            }
            let event_type = conversation_event_type(&payload).to_owned();
            let envelope = EventEnvelope::from_parts(
                event_id,
                AggregateId::Conversation(conversation_id),
                AggregateId::Conversation(conversation_id),
                causation_id,
                command_id,
                idempotency_key,
                event.schema_version,
                actor,
                sensitivity,
                payload,
                sequence,
                timestamp,
                integrity_digest,
            );
            let expected = compute_integrity_digest_v2_with_global_position(
                &envelope,
                event.global_position,
                &event.payload,
            )
            .map_err(|_| invalid_column(13, rusqlite::types::Type::Blob))?;
            if expected.as_bytes() != &event.integrity_digest {
                return Err(invalid_column(13, rusqlite::types::Type::Blob));
            }
            Ok(event_type)
        }
        _ => Err(invalid_column(1, rusqlite::types::Type::Integer)),
    }
}

/// Read a [`ReplayEvent`] from a rusqlite row.
///
/// Column layout: 0=event_id, 1=aggregate_type, 2=aggregate_id,
/// 3=sequence, 4=global_position, 5=timestamp, 6=sensitivity,
/// 7=schema_version, 12=payload, 14=correlation_id, 15=correlation_type.
fn read_replay_event(row: &rusqlite::Row) -> rusqlite::Result<ReplayEvent> {
    let event_id = fixed_blob(row.get(0)?, 0)?;
    let aggregate_type: i32 = row.get(1)?;
    let aggregate_id = fixed_blob(row.get(2)?, 2)?;
    let sequence: i64 = row.get(3)?;
    let global_position: i64 = row.get(4)?;
    let timestamp: i64 = row.get(5)?;
    let sensitivity: i32 = row.get(6)?;
    if !matches!(sensitivity, 0..=2) {
        return Err(invalid_column(6, rusqlite::types::Type::Integer));
    }
    let schema_version: u32 = row.get(7)?;
    let causation_id = optional_event_id(row.get(8)?, 8)?;
    let command_id = fixed_blob(row.get(9)?, 9)?;
    let idempotency_key = String::from_utf8(row.get(10)?)
        .ok()
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or_else(|| invalid_column(10, rusqlite::types::Type::Blob))?;
    let actor = String::from_utf8(row.get(11)?)
        .ok()
        .and_then(|value| Actor::new(value).ok())
        .ok_or_else(|| invalid_column(11, rusqlite::types::Type::Blob))?;
    let payload: Vec<u8> = row.get(12)?;
    let integrity_digest = fixed_blob(row.get(13)?, 13)?;
    let correlation_id = fixed_blob(row.get(14)?, 14)?;
    let correlation_type: i32 = row.get(15)?;
    if !matches!(correlation_type, 1 | 2) {
        return Err(invalid_column(15, rusqlite::types::Type::Integer));
    }
    let integrity_profile: i32 = row.get(16)?;
    if !matches!(integrity_profile, 1 | 2) {
        return Err(invalid_column(16, rusqlite::types::Type::Integer));
    }
    let mut event = ReplayEvent {
        global_position,
        event_id,
        aggregate_type,
        aggregate_id,
        payload,
        timestamp,
        event_type: String::new(),
        sequence,
        sensitivity,
        schema_version,
        causation_id,
        command_id,
        idempotency_key: idempotency_key.as_str().to_owned(),
        actor: actor.as_str().to_owned(),
        integrity_digest,
        correlation_id,
        correlation_type,
        integrity_profile,
    };
    event.event_type = validate_replay_event_integrity(&event)?;
    Ok(event)
}

fn validate_contiguous_sequence(
    events: &[ReplayEvent],
    expected_first: u64,
) -> Result<(), ReplayError> {
    let mut expected = expected_first;
    for event in events {
        let sequence = u64::try_from(event.sequence)
            .map_err(|_| ReplayError::Integrity("invalid replay aggregate sequence".to_owned()))?;
        if sequence != expected {
            return Err(ReplayError::Integrity(
                "replay aggregate sequence gap".to_owned(),
            ));
        }
        expected = expected.checked_add(1).ok_or_else(|| {
            ReplayError::Integrity("replay aggregate sequence overflow".to_owned())
        })?;
    }
    Ok(())
}

/// Создаёт server-issued proof completion, связанный с immutable session data.
fn build_catch_up_completion_proof(session: &ReplaySession, server_secret: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(16 + session.high_water_ref.len() + 1 + 8);
    message.extend_from_slice(&session.session_id);
    message.extend_from_slice(&session.high_water_ref);
    match session.last_acked_position {
        Some(position) => {
            message.push(1);
            message.extend_from_slice(&position.to_be_bytes());
        }
        None => message.push(0),
    }
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("fixed HMAC key size");
    mac.update(&message);
    mac.finalize().into_bytes().to_vec()
}

/// Read a [`ReplaySession`] from a rusqlite row.
fn read_replay_session(row: &rusqlite::Row) -> rusqlite::Result<ReplaySession> {
    let session_id_blob: Vec<u8> = row.get(0)?;
    let principal_id: String = row.get(1)?;
    let session_generation: i64 = row.get(2)?;
    let authority_id_blob: Vec<u8> = row.get(3)?;
    let authorization_epoch: i64 = row.get(4)?;
    let aggregate_type: i32 = row.get(5)?;
    let aggregate_id_blob: Vec<u8> = row.get(6)?;
    let retained_floor: Option<i64> = row.get(7)?;
    let retention_generation: i64 = row.get(8)?;
    let high_water_position: i64 = row.get(9)?;
    let next_page_position: Option<i64> = row.get(10)?;
    let last_delivered_position: Option<i64> = row.get(11)?;
    let last_acked_position: Option<i64> = row.get(12)?;
    let state_str: String = row.get(13)?;
    let high_water_ref: Vec<u8> = row.get(14)?;
    let catch_up_completion: Option<Vec<u8>> = row.get(15)?;
    let live_delivery_id: Option<Vec<u8>> = row.get(16)?;
    let created_at: String = row.get(17)?;

    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&session_id_blob);
    let mut authority_id = [0u8; 16];
    authority_id.copy_from_slice(&authority_id_blob);
    let mut aggregate_id = [0u8; 16];
    aggregate_id.copy_from_slice(&aggregate_id_blob);

    let state = ReplayState::from_db(&state_str).ok_or_else(|| rusqlite::Error::InvalidQuery)?;

    Ok(ReplaySession {
        session_id,
        principal_id,
        session_generation,
        authority_id,
        authorization_epoch,
        aggregate_type,
        aggregate_id,
        retained_floor,
        retention_generation,
        high_water_position,
        next_page_position,
        last_delivered_position,
        last_acked_position,
        state: state.clone(),
        high_water_ref,
        catch_up_completion,
        live_delivery_id,
        created_at,
    })
}

/// Validate authorization binding: principal_id, generation, authority_id, epoch.
fn validate_auth(
    session: &ReplaySession,
    principal_id: &str,
    generation: i64,
    authority_id: &[u8; 16],
    epoch: i64,
) -> Result<(), ReplayError> {
    if session.principal_id != principal_id {
        return Err(ReplayError::Unauthorized("principal mismatch".to_string()));
    }
    if session.session_generation != generation {
        return Err(ReplayError::StaleGeneration);
    }
    if session.authority_id != *authority_id {
        return Err(ReplayError::Unauthorized("authority mismatch".to_string()));
    }
    if session.authorization_epoch != epoch {
        return Err(ReplayError::Unauthorized("epoch mismatch".to_string()));
    }
    Ok(())
}

fn validate_cursor_event(
    conn: &Connection,
    cursor: &ReplayCursor,
    expected_aggregate_type: i32,
    expected_aggregate_id: &[u8; 16],
) -> Result<(), ReplayError> {
    let event = conn
        .query_row(
            "SELECT event_id, aggregate_type, aggregate_id, sequence,
                    global_position, timestamp, sensitivity, schema_version,
                    causation_id, command_id, idempotency_key, actor,
                    payload, integrity_digest, correlation_id,
                    correlation_type, integrity_profile
             FROM events
             WHERE global_position = ?1
               AND aggregate_type = ?2
               AND aggregate_id = ?3",
            params![
                cursor.global_position,
                expected_aggregate_type,
                expected_aggregate_id.as_slice()
            ],
            read_replay_event,
        )
        .optional()
        .map_err(|error| replay_row_error("read cursor event", error))?;
    let Some(event) = event else {
        return Err(ReplayError::CursorInvalid {
            reason: "cursor does not identify a committed event".to_string(),
        });
    };
    let cursor_aggregate_id = match &cursor.aggregate_id {
        gocode_domain::id::AggregateId::TaskRun(id) => id.as_bytes(),
        gocode_domain::id::AggregateId::Conversation(id) => id.as_bytes(),
        gocode_domain::id::AggregateId::Workspace(id) => id.as_bytes(),
    };
    let cursor_sensitivity = match cursor.sensitivity {
        gocode_domain::event::Sensitivity::Public => 0,
        gocode_domain::event::Sensitivity::Internal => 1,
        gocode_domain::event::Sensitivity::Sensitive => 2,
    };
    let scope_matches = matches!(
        &cursor.scope,
        gocode_domain::replay::ReplayScope::Aggregate {
            aggregate_type: cursor_type,
            aggregate_id: cursor_id,
        } if i32::from(*cursor_type) == expected_aggregate_type
            && cursor_id == expected_aggregate_id
    );
    if event.event_id.as_slice() != cursor.event_id.as_bytes()
        || event.aggregate_type != expected_aggregate_type
        || event.aggregate_id.as_slice() != cursor_aggregate_id
        || u64::try_from(event.sequence).ok() != Some(cursor.sequence)
        || event.sensitivity != cursor_sensitivity
        || event.event_type != cursor.event_type
        || !scope_matches
    {
        return Err(ReplayError::CursorInvalid {
            reason: "cursor does not identify a committed event".to_string(),
        });
    }
    Ok(())
}

fn read_last_acked_event(
    conn: &Connection,
    session: &ReplaySession,
) -> Result<Option<ReplayEvent>, ReplayError> {
    let Some(position) = session.last_acked_position else {
        return Ok(None);
    };
    conn.query_row(
        "SELECT event_id, aggregate_type, aggregate_id, sequence,
                global_position, timestamp, sensitivity, schema_version,
                causation_id, command_id, idempotency_key, actor,
                payload, integrity_digest, correlation_id,
                correlation_type, integrity_profile
         FROM events
         WHERE global_position = ?1
           AND aggregate_type = ?2
           AND aggregate_id = ?3",
        params![
            position,
            session.aggregate_type,
            session.aggregate_id.as_slice()
        ],
        read_replay_event,
    )
    .optional()
    .map_err(|error| replay_row_error("read acknowledged replay event", error))?
    .ok_or_else(|| ReplayError::Integrity("acknowledged replay event is unavailable".to_owned()))
    .map(Some)
}

fn read_session_event_at(
    conn: &Connection,
    session: &ReplaySession,
    position: i64,
    context: &'static str,
) -> Result<Option<ReplayEvent>, ReplayError> {
    conn.query_row(
        "SELECT event_id, aggregate_type, aggregate_id, sequence,
                global_position, timestamp, sensitivity, schema_version,
                causation_id, command_id, idempotency_key, actor,
                payload, integrity_digest, correlation_id,
                correlation_type, integrity_profile
         FROM events
         WHERE global_position = ?1
           AND aggregate_type = ?2
           AND aggregate_id = ?3",
        params![
            position,
            session.aggregate_type,
            session.aggregate_id.as_slice()
        ],
        read_replay_event,
    )
    .optional()
    .map_err(|error| replay_row_error(context, error))
}

fn next_sequence_after(event: &ReplayEvent) -> Result<u64, ReplayError> {
    u64::try_from(event.sequence)
        .map_err(|_| ReplayError::Integrity("invalid replay aggregate sequence".to_owned()))?
        .checked_add(1)
        .ok_or_else(|| ReplayError::Integrity("replay aggregate sequence overflow".to_owned()))
}

// ── ReplayStore ──────────────────────────────────────────────────────────────

/// SQLite-backed [`ReplayStorePort`] implementation.
///
/// Uses an in-memory or file-backed SQLite connection behind a mutex.
/// All database operations are dispatched through [`tokio::task::spawn_blocking`].
#[derive(Clone)]
pub struct ReplayStore {
    conn: Arc<Mutex<Connection>>,
}

impl ReplayStore {
    /// Create a new `ReplayStore` from an existing SQLite connection.
    ///
    /// The connection must contain the `_replay_subscriptions` table.
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Generate a random session ID (16 bytes).
    fn generate_session_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        id
    }
}

// ── ReplayStorePort impl ─────────────────────────────────────────────────────

#[async_trait]
impl ReplayStorePort for ReplayStore {
    async fn open_session(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        from_cursor: Option<&ReplayCursor>,
        server_secret: &[u8; 32],
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;
        let aggregate_id_copy = *aggregate_id;
        let from_cursor = from_cursor.cloned();
        let from_position = from_cursor.as_ref().map(|cursor| cursor.global_position);
        let server_secret = *server_secret;

        tokio::task::spawn_blocking(move || {
            let mut conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| ReplayError::Storage(format!("transaction: {}", e)))?;

            // Capture current high-water mark
            let high_water: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(global_position), 0) FROM events",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| ReplayError::Storage(format!("high water: {}", e)))?;
            let stream_version: Option<i64> = tx
                .query_row(
                    "SELECT current_version
                     FROM aggregate_streams
                     WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                    params![aggregate_type, aggregate_id_copy.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    ReplayError::Storage(format!("read replay stream version: {error}"))
                })?;
            let last_sequence: Option<i64> = tx
                .query_row(
                    "SELECT MAX(sequence)
                     FROM events
                     WHERE aggregate_type = ?1
                       AND aggregate_id = ?2
                       AND global_position <= ?3",
                    params![aggregate_type, aggregate_id_copy.as_slice(), high_water],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    ReplayError::Storage(format!("read replay stream sequence: {error}"))
                })?;
            match (stream_version, last_sequence) {
                (None, None) | (Some(0), None) => {}
                (Some(version), Some(sequence))
                    if version > 0 && sequence > 0 && version == sequence => {}
                _ => {
                    return Err(ReplayError::Integrity(
                        "replay stream head does not match retained events".to_owned(),
                    ));
                }
            }
            if let Some(cursor) = &from_cursor {
                validate_cursor_event(&tx, cursor, aggregate_type, &aggregate_id_copy)?;
            }

            // Generate session ID
            let session_id = Self::generate_session_id();

            // Build high_water_ref
            let high_water_ref = build_high_water_ref(
                &authority_id,
                None, // retained_floor = None
                high_water,
                &server_secret,
                &session_id,
            );

            // Read one look-ahead row so an exactly full page is not mistaken
            // for an unfinished page.
            let mut events = {
                let mut stmt = tx
                    .prepare(
                        "SELECT event_id, aggregate_type, aggregate_id, sequence,
                                global_position, timestamp, sensitivity, schema_version,
                                causation_id, command_id, idempotency_key, actor,
                                payload, integrity_digest, correlation_id,
                                correlation_type, integrity_profile
                         FROM events
                         WHERE aggregate_type = ?1 AND aggregate_id = ?2
                           AND global_position >= ?3
                           AND global_position <= ?4
                         ORDER BY global_position
                         LIMIT 101",
                    )
                    .map_err(|e| ReplayError::Storage(format!("prepare: {}", e)))?;

                stmt.query_map(
                    params![
                        aggregate_type,
                        aggregate_id_copy.as_slice(),
                        from_position.unwrap_or(0),
                        high_water,
                    ],
                    read_replay_event,
                )
                .map_err(|e| ReplayError::Storage(format!("query events: {}", e)))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| replay_row_error("collect events", error))?
            };
            validate_contiguous_sequence(
                &events,
                from_cursor.as_ref().map_or(1, |cursor| cursor.sequence),
            )?;

            // Compute initial cursors from first page
            let has_more = events.len() > 100;
            events.truncate(100);
            let last_delivered = events.last().map(|e| e.global_position);
            let next_page = if has_more {
                Some(
                    last_delivered
                        .and_then(|position| position.checked_add(1))
                        .ok_or_else(|| {
                            ReplayError::Integrity(
                                "global position overflow while opening replay session".to_string(),
                            )
                        })?,
                )
            } else {
                None
            };
            let candidate = ReplaySession {
                session_id,
                principal_id: principal_id.clone(),
                session_generation,
                authority_id,
                authorization_epoch,
                aggregate_type,
                aggregate_id: aggregate_id_copy,
                retained_floor: None,
                retention_generation: 0,
                high_water_position: high_water,
                next_page_position: next_page,
                last_delivered_position: last_delivered,
                last_acked_position: None,
                state: ReplayState::CatchingUp,
                high_water_ref: high_water_ref.clone(),
                catch_up_completion: None,
                live_delivery_id: None,
                created_at: String::new(),
            };
            delivery_guard.inspect(&candidate, &events)?;

            // Insert session row with computed cursors
            tx.execute(
                "INSERT INTO _replay_subscriptions (
                    session_id, principal_id, session_generation, authority_id,
                    authorization_epoch, aggregate_type, aggregate_id,
                    retention_generation, high_water_position,
                    next_page_position, last_delivered_position,
                    state, high_water_ref, created_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8,
                    ?9, ?10,
                    'catching_up', ?11, datetime('now')
                )",
                params![
                    session_id.as_slice(),
                    principal_id.as_str(),
                    session_generation,
                    authority_id.as_slice(),
                    authorization_epoch,
                    aggregate_type,
                    aggregate_id_copy.as_slice(),
                    high_water,
                    next_page,
                    last_delivered,
                    high_water_ref.as_slice(),
                ],
            )
            .map_err(|e| ReplayError::Storage(format!("insert session: {}", e)))?;

            tx.commit()
                .map_err(|e| ReplayError::Storage(format!("commit: {}", e)))?;

            // Re-read the session to get all fields
            let session = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .map_err(|e| ReplayError::Storage(format!("re-read session: {}", e)))?;

            Ok((session, events))
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }

    async fn read_page(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        limit: usize,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        if limit == 0 {
            return Err(ReplayError::Integrity(
                "replay page limit must be greater than zero".to_string(),
            ));
        }
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            // Read session and validate auth
            let session: ReplaySession = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .optional()
                .map_err(|e| ReplayError::Storage(format!("read session: {}", e)))?
                .ok_or(ReplayError::SessionNotFound)?;

            validate_auth(&session, &principal_id, generation, &authority_id, epoch)?;

            if session.state != ReplayState::CatchingUp {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }

            let expected_first = match session.last_delivered_position {
                Some(position) => {
                    let event = read_session_event_at(
                        &conn,
                        &session,
                        position,
                        "read previous replay page event",
                    )?
                    .ok_or_else(|| {
                        ReplayError::Integrity(
                            "previously delivered replay event is unavailable".to_owned(),
                        )
                    })?;
                    next_sequence_after(&event)?
                }
                None => 1,
            };

            // Determine the cursor position to read after
            let cursor = session.last_delivered_position.unwrap_or(-1);

            let mut stmt = conn
                .prepare(
                    "SELECT event_id, aggregate_type, aggregate_id, sequence,
                            global_position, timestamp, sensitivity, schema_version,
                            causation_id, command_id, idempotency_key, actor,
                            payload, integrity_digest, correlation_id,
                            correlation_type, integrity_profile
                      FROM events
                      WHERE aggregate_type = ?1 AND aggregate_id = ?2
                        AND global_position > ?3
                        AND global_position <= ?4
                      ORDER BY global_position
                      LIMIT ?5",
                )
                .map_err(|e| ReplayError::Storage(format!("prepare: {}", e)))?;

            let aggregate_type = session.aggregate_type;
            let aggregate_id = session.aggregate_id;

            let fetch_limit = limit
                .checked_add(1)
                .ok_or_else(|| ReplayError::Integrity("replay page limit overflow".to_string()))?;
            let fetch_limit = i64::try_from(fetch_limit)
                .map_err(|_| ReplayError::Integrity("replay page limit overflow".to_string()))?;
            let mut events = stmt
                .query_map(
                    params![
                        aggregate_type,
                        aggregate_id.as_slice(),
                        cursor,
                        session.high_water_position,
                        fetch_limit
                    ],
                    read_replay_event,
                )
                .map_err(|e| ReplayError::Storage(format!("query events: {}", e)))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| replay_row_error("collect events", error))?;

            if session.next_page_position.is_some() && events.is_empty() {
                return Err(ReplayError::Integrity(
                    "replay catch-up suffix is unavailable".to_owned(),
                ));
            }
            validate_contiguous_sequence(&events, expected_first)?;

            let has_more = events.len() > limit;
            events.truncate(limit);

            let next_page = match events.last() {
                Some(last_event) if has_more => {
                    Some(last_event.global_position.checked_add(1).ok_or_else(|| {
                        ReplayError::Integrity(
                            "global position overflow while reading replay page".to_string(),
                        )
                    })?)
                }
                Some(_) => None,
                None => session.next_page_position,
            };
            let mut candidate = session.clone();
            if let Some(last_event) = events.last() {
                candidate.last_delivered_position = Some(last_event.global_position);
                candidate.next_page_position = next_page;
            }
            delivery_guard.inspect(&candidate, &events)?;

            // Commit cursors only after the transport has classified the exact
            // serialized delivery.
            if let Some(last_event) = events.last() {
                conn.execute(
                    "UPDATE _replay_subscriptions
                     SET last_delivered_position = ?1,
                         next_page_position = ?2
                     WHERE session_id = ?3",
                    params![last_event.global_position, next_page, session_id.as_slice(),],
                )
                .map_err(|e| ReplayError::Storage(format!("update cursors: {}", e)))?;
            }

            let session = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .map_err(|error| ReplayError::Storage(format!("re-read paged session: {error}")))?;

            Ok((session, events))
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }

    async fn acknowledge(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        cursor: &ReplayCursor,
    ) -> Result<(), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;
        let cursor = cursor.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {e}")))?;
            let session: ReplaySession = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                        authorization_epoch, aggregate_type, aggregate_id,
                        retained_floor, retention_generation, high_water_position,
                        next_page_position, last_delivered_position, last_acked_position,
                        state, high_water_ref, catch_up_completion, live_delivery_id,
                        created_at FROM _replay_subscriptions WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .optional()
                .map_err(|e| ReplayError::Storage(format!("read session: {e}")))?
                .ok_or(ReplayError::SessionNotFound)?;
            validate_auth(&session, &principal_id, generation, &authority_id, epoch)?;
            if !matches!(session.state, ReplayState::CatchingUp | ReplayState::Live) {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }
            let position = cursor.global_position;
            let last_delivered = session
                .last_delivered_position
                .ok_or(ReplayError::NotAcknowledged)?;
            if position > last_delivered {
                return Err(ReplayError::NotAcknowledged);
            }
            validate_cursor_event(
                &conn,
                &cursor,
                session.aggregate_type,
                &session.aggregate_id,
            )?;
            match session.last_acked_position {
                Some(last_acked) if position < last_acked => {
                    return Err(ReplayError::AlreadyAcknowledged);
                }
                Some(last_acked) if position == last_acked => return Ok(()),
                _ => {}
            }
            conn.execute(
                "UPDATE _replay_subscriptions SET last_acked_position = ?1 WHERE session_id = ?2",
                params![position, session_id.as_slice()],
            )
            .map_err(|e| ReplayError::Storage(format!("acknowledge: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {e}")))?
    }

    async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        server_secret: &[u8; 32],
    ) -> Result<(ReplaySession, Option<ReplayEvent>), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;
        let server_secret = *server_secret;

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            // Read session and validate auth
            let session: ReplaySession = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .optional()
                .map_err(|e| ReplayError::Storage(format!("read session: {}", e)))?
                .ok_or(ReplayError::SessionNotFound)?;

            validate_auth(&session, &principal_id, generation, &authority_id, epoch)?;

            if session.state == ReplayState::CatchUpComplete
                && session.catch_up_completion.is_some()
            {
                let last_acked_event = read_last_acked_event(&conn, &session)?;
                return Ok((session, last_acked_event));
            }
            if session.state != ReplayState::CatchingUp {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }

            if session.next_page_position.is_some() {
                return Err(ReplayError::NotAcknowledged);
            }
            let last_in_scope: Option<i64> = conn
                .query_row(
                    "SELECT MAX(global_position)
                     FROM events
                     WHERE aggregate_type = ?1
                       AND aggregate_id = ?2
                       AND global_position <= ?3",
                    params![
                        session.aggregate_type,
                        session.aggregate_id.as_slice(),
                        session.high_water_position
                    ],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    ReplayError::Storage(format!("read scoped high water: {error}"))
                })?;
            match (last_in_scope, session.last_delivered_position) {
                (Some(expected), Some(last_delivered)) if last_delivered != expected => {
                    return Err(ReplayError::NotAcknowledged);
                }
                (Some(expected), Some(last_delivered))
                    if session.last_acked_position != Some(last_delivered)
                        || last_delivered != expected =>
                {
                    return Err(ReplayError::NotAcknowledged);
                }
                (Some(_), None) | (None, Some(_)) => return Err(ReplayError::NotAcknowledged),
                (Some(_), Some(_)) | (None, None) => {}
            }
            let proof = build_catch_up_completion_proof(&session, &server_secret);

            let affected = conn
                .execute(
                    "UPDATE _replay_subscriptions
                          SET state = 'catch_up_complete',
                          catch_up_completion = ?1
                     WHERE session_id = ?2
                       AND state = 'catching_up'
                       AND principal_id = ?3
                       AND session_generation = ?4
                       AND authority_id = ?5
                       AND authorization_epoch = ?6",
                    params![
                        proof.as_slice(),
                        session_id.as_slice(),
                        principal_id.as_str(),
                        generation,
                        authority_id.as_slice(),
                        epoch,
                    ],
                )
                .map_err(|e| ReplayError::Storage(format!("update: {}", e)))?;

            if affected != 1 {
                return Err(ReplayError::Integrity(format!(
                    "expected 1 row affected, got {}",
                    affected
                )));
            }

            // Re-read the session
            let session = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .map_err(|e| ReplayError::Storage(format!("re-read session: {}", e)))?;

            let last_acked_event = read_last_acked_event(&conn, &session)?;
            Ok((session, last_acked_event))
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }

    async fn continue_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<ReplaySession, ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            // Read session and validate auth
            let session: ReplaySession = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .optional()
                .map_err(|e| ReplayError::Storage(format!("read session: {}", e)))?
                .ok_or(ReplayError::SessionNotFound)?;

            validate_auth(&session, &principal_id, generation, &authority_id, epoch)?;

            if session.state != ReplayState::CatchUpComplete {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }

            // CAS: catch_up_complete → activating_live (only one activator wins)
            let affected = conn
                .execute(
                    "UPDATE _replay_subscriptions
                     SET state = 'activating_live'
                     WHERE session_id = ?1
                       AND state = 'catch_up_complete'
                       AND principal_id = ?2
                       AND session_generation = ?3
                       AND authority_id = ?4
                       AND authorization_epoch = ?5",
                    params![
                        session_id.as_slice(),
                        principal_id.as_str(),
                        generation,
                        authority_id.as_slice(),
                        epoch,
                    ],
                )
                .map_err(|e| ReplayError::Storage(format!("cas activating: {}", e)))?;

            if affected != 1 {
                return Err(ReplayError::InvalidState(
                    "another activator already claimed this session".to_string(),
                ));
            }

            // Generate live_delivery_id
            let mut live_delivery_id = [0u8; 16];
            OsRng.fill_bytes(&mut live_delivery_id);

            // Immediately transition activating_live → live
            let affected = conn
                .execute(
                    "UPDATE _replay_subscriptions
                     SET state = 'live',
                         live_delivery_id = ?1
                     WHERE session_id = ?2
                       AND state = 'activating_live'
                       AND principal_id = ?3
                       AND session_generation = ?4
                       AND authority_id = ?5
                       AND authorization_epoch = ?6",
                    params![
                        live_delivery_id.as_slice(),
                        session_id.as_slice(),
                        principal_id.as_str(),
                        generation,
                        authority_id.as_slice(),
                        epoch,
                    ],
                )
                .map_err(|e| ReplayError::Storage(format!("cas live: {}", e)))?;

            if affected != 1 {
                return Err(ReplayError::Integrity(
                    "live transition failed after activating_live CAS".to_string(),
                ));
            }

            // Re-read the session
            let session = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .map_err(|e| ReplayError::Storage(format!("re-read session: {}", e)))?;

            Ok(session)
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }

    async fn poll_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            // Read session and validate auth
            let session: ReplaySession = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .optional()
                .map_err(|e| ReplayError::Storage(format!("read session: {}", e)))?
                .ok_or(ReplayError::SessionNotFound)?;

            validate_auth(&session, &principal_id, generation, &authority_id, epoch)?;

            if session.state != ReplayState::Live {
                return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
            }

            let expected_first = match session.last_delivered_position {
                Some(position) => {
                    let event = read_session_event_at(
                        &conn,
                        &session,
                        position,
                        "read previous live replay event",
                    )?
                    .ok_or_else(|| {
                        ReplayError::Integrity(
                            "previously delivered live replay event is unavailable".to_owned(),
                        )
                    })?;
                    next_sequence_after(&event)?
                }
                None => 1,
            };

            // Continue after the most recent event delivered by this live
            // lane, while never moving behind the catch-up high-water mark.
            let cursor = session
                .last_delivered_position
                .unwrap_or(session.high_water_position)
                .max(session.high_water_position);

            let mut stmt = conn
                .prepare(
                    "SELECT event_id, aggregate_type, aggregate_id, sequence,
                            global_position, timestamp, sensitivity, schema_version,
                            causation_id, command_id, idempotency_key, actor,
                            payload, integrity_digest, correlation_id,
                            correlation_type, integrity_profile
                     FROM events
                     WHERE aggregate_type = ?1 AND aggregate_id = ?2
                       AND global_position > ?3
                     ORDER BY global_position
                     LIMIT 100",
                )
                .map_err(|e| ReplayError::Storage(format!("prepare: {}", e)))?;

            let aggregate_type = session.aggregate_type;
            let aggregate_id = session.aggregate_id;

            let events = stmt
                .query_map(
                    params![aggregate_type, aggregate_id.as_slice(), cursor],
                    read_replay_event,
                )
                .map_err(|e| ReplayError::Storage(format!("query events: {}", e)))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| replay_row_error("collect events", error))?;

            validate_contiguous_sequence(&events, expected_first)?;

            let mut candidate = session.clone();
            if let Some(last_event) = events.last() {
                candidate.last_delivered_position = Some(last_event.global_position);
            }
            delivery_guard.inspect(&candidate, &events)?;

            // Commit progress only after the transport has classified the
            // exact serialized live deliveries.
            if let Some(last_event) = events.last() {
                conn.execute(
                    "UPDATE _replay_subscriptions
                     SET last_delivered_position = ?1
                     WHERE session_id = ?2",
                    params![last_event.global_position, session_id.as_slice()],
                )
                .map_err(|e| ReplayError::Storage(format!("update cursors: {}", e)))?;
            }

            let session = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .map_err(|error| ReplayError::Storage(format!("re-read live session: {error}")))?;

            Ok((session, events))
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }

    async fn close_session(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            // Read session and validate auth
            let session: ReplaySession = conn
                .query_row(
                    "SELECT session_id, principal_id, session_generation, authority_id,
                            authorization_epoch, aggregate_type, aggregate_id,
                            retained_floor, retention_generation, high_water_position,
                            next_page_position, last_delivered_position, last_acked_position,
                            state, high_water_ref, catch_up_completion, live_delivery_id,
                            created_at
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    params![session_id.as_slice()],
                    read_replay_session,
                )
                .optional()
                .map_err(|e| ReplayError::Storage(format!("read session: {}", e)))?
                .ok_or(ReplayError::SessionNotFound)?;

            validate_auth(&session, &principal_id, generation, &authority_id, epoch)?;

            // Allow close from CatchUpComplete or Live
            match session.state {
                ReplayState::CatchUpComplete | ReplayState::Live => {}
                _ => {
                    return Err(ReplayError::InvalidState(session.state.as_db().to_string()));
                }
            }

            let affected = conn
                .execute(
                    "UPDATE _replay_subscriptions
                     SET state = 'closed'
                     WHERE session_id = ?1
                       AND state IN ('catch_up_complete', 'live')
                       AND principal_id = ?2
                       AND session_generation = ?3
                       AND authority_id = ?4
                       AND authorization_epoch = ?5",
                    params![
                        session_id.as_slice(),
                        principal_id.as_str(),
                        generation,
                        authority_id.as_slice(),
                        epoch,
                    ],
                )
                .map_err(|e| ReplayError::Storage(format!("close: {}", e)))?;

            if affected != 1 {
                return Err(ReplayError::InvalidState(
                    "session was already closed or state changed".to_string(),
                ));
            }

            Ok(())
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }
}

// ── Public helpers ───────────────────────────────────────────────────────────

/// Public re-export for testing: build a `HighWaterRef`.
pub fn build_test_high_water_ref(
    authority_id: &[u8; 16],
    floor: Option<i64>,
    global_position: i64,
    server_secret: &[u8; 32],
    session_id: &[u8; 16],
) -> Vec<u8> {
    build_high_water_ref(
        authority_id,
        floor,
        global_position,
        server_secret,
        session_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_high_water_ref_deterministic() {
        let auth = [0x01u8; 16];
        let sess = [0x02u8; 16];
        let secret = [0x03u8; 32];

        let ref1 = build_high_water_ref(&auth, None, 42, &secret, &sess);
        let ref2 = build_high_water_ref(&auth, None, 42, &secret, &sess);

        assert_eq!(ref1, ref2);
        assert_eq!(ref1.len(), 77);
    }

    #[test]
    fn test_hmac_high_water_ref_differs() {
        let auth = [0x01u8; 16];
        let sess = [0x02u8; 16];
        let secret = [0x03u8; 32];

        let ref1 = build_high_water_ref(&auth, None, 42, &secret, &sess);
        let ref2 = build_high_water_ref(&auth, None, 43, &secret, &sess);

        assert_ne!(ref1, ref2);
    }

    #[test]
    fn test_hmac_high_water_ref_differs_on_secret() {
        let auth = [0x01u8; 16];
        let sess = [0x02u8; 16];
        let secret1 = [0x03u8; 32];
        let secret2 = [0x04u8; 32];

        let ref1 = build_high_water_ref(&auth, None, 42, &secret1, &sess);
        let ref2 = build_high_water_ref(&auth, None, 42, &secret2, &sess);

        assert_ne!(ref1, ref2);
    }

    #[test]
    fn test_hmac_high_water_ref_with_floor() {
        let auth = [0x01u8; 16];
        let sess = [0x02u8; 16];
        let secret = [0x03u8; 32];

        let ref1 = build_high_water_ref(&auth, Some(10), 42, &secret, &sess);
        let ref2 = build_high_water_ref(&auth, None, 42, &secret, &sess);

        assert_ne!(ref1, ref2);
        assert_eq!(ref1.len(), 77);
    }

    #[test]
    fn high_water_ref_uses_its_own_schema_version() {
        let high_water_ref = build_high_water_ref(&[0x01; 16], None, 42, &[0x03; 32], &[0x02; 16]);

        assert_eq!(&high_water_ref[33..37], &1_u32.to_be_bytes());
    }
}
