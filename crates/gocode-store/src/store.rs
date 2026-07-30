//! Store — SQLite-backed persistence adapter.
//!
//! Provides:
//! - [`StoreTransaction`] — opens, configures, and migrates the database
//! - [`EventStore`] impl — loads task run event streams
//! - [`UnitOfWork`] impl — idempotency lookup + atomic commit
//! - [`IdGenerator`] impl — UUIDv7-based unique IDs
//! - [`Clock`] impl — system wall clock in microseconds

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_application::fingerprint::CommandFingerprint;
use gocode_application::ports::{
    AggregateScope, BeginTextGenerationCommit, Clock, ClockError, CommandCommit, CommitError,
    CommitResult, ConversationCommit, ConversationCommitResult, ConversationLoadedStream,
    ConversationReceipt, ConversationReceiptLookup, ConversationRepository,
    ConversationTextRepository, EventStore as AppEventStore, EventStoreError,
    FinishTextGenerationCommit, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream,
    OperationTag, ReceiptLookup, RejectTextGenerationCommit, RuntimeAuthorityId,
    StorageFailureKind, TextGenerationCommitResult, TextGenerationPhase, TextGenerationReceipt,
    TextGenerationReceiptLookup, UnitOfWork,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity, UncommittedEvent};
use gocode_domain::id::{
    AggregateId, AttemptId, CommandId, ConversationId, EventId, IntegrityDigest, MessageId,
    TaskRunId,
};
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::codec::{
    CommandOutcomeCodec, ConversationEventCodec, ConversationReceiptCodec, IdempotencyScopeCodec,
    StoreCodec, TaskRunEventCodec, TextGenerationReceiptCodec,
};
use crate::integrity::{
    compute_integrity_digest_v2_with_global_position, compute_integrity_digest_with_global_position,
};
use crate::schema::{apply_migrations, open_with_pragmas, run_startup_gates};

/// Maximum event count per commit (safety bound).
const MAX_EVENTS_PER_COMMIT: usize = 1_000;

const CORRELATION_TYPE_TASK_RUN: i64 = 1;
const CORRELATION_TYPE_CONVERSATION: i64 = 2;
const INTEGRITY_PROFILE_V1: i64 = 1;
const INTEGRITY_PROFILE_V2: i64 = 2;

fn stored_sensitivity(value: i64) -> Result<Sensitivity, EventStoreError> {
    match value {
        0 => Ok(Sensitivity::Public),
        1 => Ok(Sensitivity::Internal),
        2 => Ok(Sensitivity::Sensitive),
        _ => Err(EventStoreError::CorruptData),
    }
}

const fn sensitivity_value(value: Sensitivity) -> i64 {
    match value {
        Sensitivity::Public => 0,
        Sensitivity::Internal => 1,
        Sensitivity::Sensitive => 2,
    }
}

#[derive(Clone, Copy)]
enum StoredCorrelationType {
    TaskRun,
    Conversation,
}

impl StoredCorrelationType {
    fn from_i64(value: i64) -> Result<Self, EventStoreError> {
        match value {
            CORRELATION_TYPE_TASK_RUN => Ok(Self::TaskRun),
            CORRELATION_TYPE_CONVERSATION => Ok(Self::Conversation),
            _ => Err(EventStoreError::CorruptData),
        }
    }

    const fn as_i64(self) -> i64 {
        match self {
            Self::TaskRun => CORRELATION_TYPE_TASK_RUN,
            Self::Conversation => CORRELATION_TYPE_CONVERSATION,
        }
    }
}

/// Inner state shared between clones via `Arc`.
struct StoreInner {
    writer: Mutex<Connection>,
    reader: Mutex<Connection>,
    id_counter: AtomicU64,
}

/// SQLite-backed store with a single writer connection.
///
/// Implements [`AppEventStore`], [`UnitOfWork`], [`IdGenerator`], and [`Clock`].
/// Safe to clone — clones share the same connections via `Arc`.
///
/// # Concurrency
///
/// All writes go through a single `Mutex<Connection>`. Reads (loads, receipt
/// lookups) use a separate read connection to avoid blocking the writer.
#[derive(Clone)]
pub struct StoreTransaction {
    inner: Arc<StoreInner>,
    runtime_authority_id: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

/// Current time as Unix microseconds (for stream row creation).
fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

impl StoreTransaction {
    /// Open a database at `db_path`, apply migrations, run startup gates.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The database cannot be opened
    /// - PRAGMA setup fails
    /// - Migrations fail
    /// - Startup integrity checks fail
    pub fn open(
        db_path: &str,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Result<Self, CommitError> {
        let writer = open_with_pragmas(db_path).map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::Unavailable)
        })?;

        apply_migrations(&writer).map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::CorruptData)
        })?;

        run_startup_gates(&writer, db_path).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        // The admitted writer owns lifecycle classification. A read-only
        // connection cannot mutate WAL state and deliberately avoids a second
        // preflight/classification pass.
        let reader = if db_path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        }
        .map_err(|_| {
            CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::Unavailable)
        })?;

        Ok(Self {
            inner: Arc::new(StoreInner {
                writer: Mutex::new(writer),
                reader: Mutex::new(reader),
                id_counter: AtomicU64::new(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                ),
            }),
            runtime_authority_id,
            prohibited_content,
        })
    }

    /// Return the runtime authority ID.
    pub fn runtime_authority_id(&self) -> &RuntimeAuthorityId {
        &self.runtime_authority_id
    }

    /// Generate a UUIDv7 byte array from the monotonic counter.
    fn generate_uuid(&self) -> [u8; 16] {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let counter = self.inner.id_counter.fetch_add(1, Ordering::SeqCst);

        let mut bytes = [0u8; 16];
        bytes[0..6].copy_from_slice(&ts.to_be_bytes()[2..8]);
        bytes[6] = 0x70 | (bytes[6] & 0x0F);
        bytes[8] = 0x80 | (bytes[8] & 0x3F);
        bytes[10..16].copy_from_slice(&counter.to_be_bytes()[2..8]);

        bytes
    }
}

// ── EventStore impl ──────────────────────────────────────────────────────

impl AppEventStore for StoreTransaction {
    fn load_task_run(&self, taskrun_id: TaskRunId) -> Result<LoadedStream, EventStoreError> {
        let mut conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = conn.transaction().map_err(map_event_store_read_error)?;
        let taskrun_bytes = taskrun_id.as_bytes();

        let stream: Option<(i64, Option<Vec<u8>>)> = tx
            .query_row(
                "SELECT current_version, last_event_id
                 FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                params![CORRELATION_TYPE_TASK_RUN, taskrun_bytes],
                |row| Ok((row.get(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .map_err(map_event_store_read_error)?;

        let (current_version, last_event_id_bytes) = match stream {
            Some((cv, lei)) => (cv as u64, lei),
            None => {
                return Err(EventStoreError::NotFound);
            }
        };

        let mut stmt = tx
            .prepare(
                "SELECT event_id, sequence, timestamp, schema_version,
                        causation_id, command_id, idempotency_key, actor,
                        payload, integrity_digest, correlation_id,
                        correlation_type, integrity_profile, global_position
                 FROM events
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2
                 ORDER BY sequence ASC",
            )
            .map_err(map_event_store_read_error)?;

        let event_rows = stmt
            .query_map(params![CORRELATION_TYPE_TASK_RUN, taskrun_bytes], |row| {
                let eid: Vec<u8> = row.get(0)?;
                let seq: i64 = row.get(1)?;
                let ts: i64 = row.get(2)?;
                let sv: i64 = row.get(3)?;
                let cid_opt: Option<Vec<u8>> = row.get(4)?;
                let cmd: Vec<u8> = row.get(5)?;
                let ikey: Vec<u8> = row.get(6)?;
                let act: Vec<u8> = row.get(7)?;
                let payload_bytes: Vec<u8> = row.get(8)?;
                let digest_bytes: Vec<u8> = row.get(9)?;
                let correlation_bytes: Vec<u8> = row.get(10)?;
                let correlation_type: i64 = row.get(11)?;
                let integrity_profile: i64 = row.get(12)?;
                let global_position: i64 = row.get(13)?;
                Ok((
                    eid,
                    seq as u64,
                    ts,
                    sv as u32,
                    cid_opt,
                    cmd,
                    ikey,
                    act,
                    payload_bytes,
                    digest_bytes,
                    correlation_bytes,
                    correlation_type,
                    integrity_profile,
                    global_position,
                ))
            })
            .map_err(map_event_store_read_error)?;

        let codec = TaskRunEventCodec;
        let mut events = Vec::new();

        for row in event_rows {
            let (
                eid_bytes,
                seq,
                ts_micros,
                schema_ver,
                causation_bytes,
                cmd_bytes,
                ikey_bytes,
                actor_bytes,
                payload_bytes,
                digest_bytes,
                correlation_bytes,
                correlation_type,
                integrity_profile,
                global_position,
            ) = row.map_err(map_event_store_read_error)?;

            let event_id = EventId::from_bytes(
                eid_bytes
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let command_id = CommandId::from_bytes(
                cmd_bytes
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let idempotency_key = gocode_domain::id::IdempotencyKey::new(
                String::from_utf8_lossy(&ikey_bytes).as_ref(),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
            let actor = Actor::new(String::from_utf8_lossy(&actor_bytes).as_ref())
                .map_err(|_| EventStoreError::CorruptData)?;
            let causation_id = causation_bytes.map(|b| {
                let arr: [u8; 16] = b.try_into().unwrap_or([0u8; 16]);
                EventId::from_bytes(arr)
            });
            let integrity_digest = IntegrityDigest::from_bytes(
                digest_bytes
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let payload = codec
                .decode(&payload_bytes)
                .map_err(|_| EventStoreError::CorruptData)?;
            let aggregate_id = AggregateId::TaskRun(taskrun_id);
            if integrity_profile != INTEGRITY_PROFILE_V1 {
                return Err(EventStoreError::CorruptData);
            }
            let correlation_id = match StoredCorrelationType::from_i64(correlation_type)? {
                StoredCorrelationType::TaskRun => TaskRunId::from_bytes(
                    correlation_bytes
                        .try_into()
                        .map_err(|_| EventStoreError::CorruptData)?,
                ),
                StoredCorrelationType::Conversation => return Err(EventStoreError::CorruptData),
            };
            if correlation_id != taskrun_id {
                return Err(EventStoreError::CorruptData);
            }

            let envelope = EventEnvelope::from_parts(
                event_id,
                aggregate_id.clone(),
                AggregateId::TaskRun(correlation_id),
                causation_id,
                command_id,
                idempotency_key,
                schema_ver,
                actor,
                Sensitivity::Public,
                payload,
                seq,
                Timestamp::from_unix_micros(ts_micros),
                integrity_digest,
            );
            let expected_digest = compute_integrity_digest_with_global_position(
                &envelope,
                global_position,
                &payload_bytes,
            )
            .map_err(|_| EventStoreError::CorruptData)?;
            if envelope.integrity_digest() != &expected_digest {
                return Err(EventStoreError::CorruptData);
            }

            events.push(envelope);
        }

        let last_event_id = last_event_id_bytes.map(|b| {
            let arr: [u8; 16] = b.try_into().unwrap_or([0u8; 16]);
            EventId::from_bytes(arr)
        });
        drop(stmt);
        tx.commit().map_err(map_event_store_read_error)?;

        Ok(LoadedStream {
            events,
            current_version,
            last_event_id,
        })
    }
}

// ── ConversationRepository impl ─────────────────────────────────────────

impl ConversationRepository for StoreTransaction {
    fn load_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<ConversationLoadedStream, EventStoreError> {
        let conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let stream = conn
            .query_row(
                "SELECT current_version, last_event_id
                 FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?
            .ok_or(EventStoreError::NotFound)?;
        let current_version = u64::try_from(stream.0).map_err(|_| EventStoreError::CorruptData)?;
        let last_event_id = stream.1.map(parse_event_id).transpose()?;

        let mut statement = conn
            .prepare(
                "SELECT event_id, sequence, global_position, timestamp, sensitivity,
                        schema_version, causation_id, command_id, idempotency_key,
                        actor, payload, integrity_digest, correlation_id,
                        correlation_type, integrity_profile
                 FROM events
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2
                 ORDER BY sequence",
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let rows = statement
            .query_map(
                params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, Vec<u8>>(11)?,
                        row.get::<_, Vec<u8>>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, i64>(14)?,
                    ))
                },
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let codec = ConversationEventCodec;
        let aggregate_id = AggregateId::Conversation(conversation_id);
        let mut events = Vec::new();

        for row in rows {
            let (
                event_id,
                sequence,
                global_position,
                timestamp,
                sensitivity,
                schema_version,
                causation_id,
                command_id,
                idempotency_key,
                actor,
                payload,
                stored_digest,
                correlation_id,
                correlation_type,
                integrity_profile,
            ) = row.map_err(|_| EventStoreError::CorruptData)?;
            if correlation_type != CORRELATION_TYPE_CONVERSATION
                || integrity_profile != INTEGRITY_PROFILE_V2
                || correlation_id.as_slice() != conversation_id.as_bytes()
            {
                return Err(EventStoreError::CorruptData);
            }
            let sequence = u64::try_from(sequence).map_err(|_| EventStoreError::CorruptData)?;
            let schema_version =
                u32::try_from(schema_version).map_err(|_| EventStoreError::CorruptData)?;
            let payload_value = codec
                .decode(&payload)
                .map_err(|_| EventStoreError::CorruptData)?;
            let sensitivity = stored_sensitivity(sensitivity)?;
            if sensitivity != payload_value.sensitivity() {
                return Err(EventStoreError::CorruptData);
            }
            let envelope = EventEnvelope::from_parts(
                parse_event_id(event_id)?,
                aggregate_id.clone(),
                aggregate_id.clone(),
                causation_id.map(parse_event_id).transpose()?,
                parse_command_id(command_id)?,
                gocode_domain::id::IdempotencyKey::new(
                    String::from_utf8(idempotency_key).map_err(|_| EventStoreError::CorruptData)?,
                )
                .map_err(|_| EventStoreError::CorruptData)?,
                schema_version,
                Actor::new(String::from_utf8(actor).map_err(|_| EventStoreError::CorruptData)?)
                    .map_err(|_| EventStoreError::CorruptData)?,
                sensitivity,
                payload_value,
                sequence,
                Timestamp::from_unix_micros(timestamp),
                parse_integrity_digest(stored_digest)?,
            );
            let expected_digest = compute_integrity_digest_v2_with_global_position(
                &envelope,
                global_position,
                &payload,
            )
            .map_err(|_| EventStoreError::CorruptData)?;
            if envelope.integrity_digest() != &expected_digest {
                return Err(EventStoreError::CorruptData);
            }
            events.push(envelope);
        }

        if events.len() as u64 != current_version
            || events
                .iter()
                .enumerate()
                .any(|(index, event)| event.sequence() != index as u64 + 1)
            || events.last().map(|event| *event.event_id()) != last_event_id
        {
            return Err(EventStoreError::CorruptData);
        }

        Ok(ConversationLoadedStream {
            events,
            current_version,
            last_event_id,
        })
    }

    fn lookup_conversation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &gocode_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ConversationReceiptLookup, CommitError> {
        let conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let by_command = conn
            .query_row(
                "SELECT idempotency_scope_bytes, fingerprint, command_outcome
                 FROM command_receipts WHERE command_id = ?1",
                params![command_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if let Some((stored_scope, stored_fingerprint, stored_outcome)) = by_command {
            let stored_fingerprint = parse_fingerprint(stored_fingerprint)?;
            if stored_scope == scope && stored_fingerprint == *fingerprint {
                let stored_result = ConversationReceiptCodec
                    .decode(&stored_outcome)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
                return Ok(ConversationReceiptLookup::Duplicate { stored_result });
            }
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: command_id,
                attempted_command_id: command_id,
                stored_fingerprint,
                attempted_fingerprint: *fingerprint,
            });
        }

        if let Some((stored_command, stored_fingerprint)) = conn
            .query_row(
                "SELECT command_id, fingerprint FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope, idempotency_key.as_str().as_bytes()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        {
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: parse_command_id_for_commit(stored_command)?,
                attempted_command_id: command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: *fingerprint,
            });
        }
        Ok(ConversationReceiptLookup::Miss)
    }

    fn commit_conversation(
        &self,
        payload: ConversationCommit,
    ) -> Result<ConversationCommitResult, CommitError> {
        if payload.events.len() != 1 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let event = &payload.events[0];
        let conversation_id = match (event.aggregate_id(), event.correlation_id()) {
            (AggregateId::Conversation(aggregate), AggregateId::Conversation(correlation))
                if aggregate == correlation =>
            {
                *aggregate
            }
            _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
        };
        match event.payload() {
            ConversationEvent::ConversationCreated { workspace_id }
                if *workspace_id == payload.workspace_id => {}
            _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
        }
        let scope_matches = matches!(
            &payload.idempotency_scope,
            IdempotencyScope {
                runtime_authority_id,
                operation: OperationTag::CreateConversation,
                aggregate_scope:
                    AggregateScope::NewConversation {
                        conversation_id: scoped_conversation_id,
                        workspace_id: scoped_workspace_id,
                    },
                ..
            } if runtime_authority_id == &self.runtime_authority_id
                && scoped_conversation_id == &conversation_id
                && scoped_workspace_id == &payload.workspace_id
        );
        let expected_fingerprint =
            CommandFingerprint::for_create_conversation(&conversation_id, &payload.workspace_id);
        if !scope_matches
            || event.command_id() != &payload.command_id
            || event.idempotency_key() != &payload.idempotency_key
            || payload.command_fingerprint != expected_fingerprint
            || event.schema_version() != 1
            || event.sensitivity() != &Sensitivity::Public
            || event.causation_id().is_some()
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }

        let mut conn = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(&payload.idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;

        if let Some((stored_scope, stored_fingerprint, stored_outcome)) = tx
            .query_row(
                "SELECT idempotency_scope_bytes, fingerprint, command_outcome
                 FROM command_receipts WHERE command_id = ?1",
                params![payload.command_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        {
            let stored_fingerprint = parse_fingerprint(stored_fingerprint)?;
            if stored_scope == scope && stored_fingerprint == payload.command_fingerprint {
                let stored_result = ConversationReceiptCodec
                    .decode(&stored_outcome)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
                return Ok(ConversationCommitResult::Duplicate { stored_result });
            }
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: payload.command_id,
                attempted_command_id: payload.command_id,
                stored_fingerprint,
                attempted_fingerprint: payload.command_fingerprint,
            });
        }
        if let Some((stored_command, stored_fingerprint)) = tx
            .query_row(
                "SELECT command_id, fingerprint FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope, payload.idempotency_key.as_str().as_bytes()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        {
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: parse_command_id_for_commit(stored_command)?,
                attempted_command_id: payload.command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: payload.command_fingerprint,
            });
        }

        let existing_version = tx
            .query_row(
                "SELECT current_version FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if let Some(actual) = existing_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: u64::try_from(actual)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            });
        }
        if payload.expected_version != 0 {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: 0,
            });
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CommitError::ClockFailure)
            .and_then(|duration| {
                i64::try_from(duration.as_micros()).map_err(|_| CommitError::ClockFailure)
            })?;
        let global_position = tx
            .query_row(
                "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let next_global_position = global_position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let timestamp = Timestamp::from_unix_micros(now);
        let payload_bytes = ConversationEventCodec
            .encode(event.payload())
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let envelope = EventEnvelope::from_parts(
            *event.event_id(),
            AggregateId::Conversation(conversation_id),
            AggregateId::Conversation(conversation_id),
            event.causation_id().copied(),
            *event.command_id(),
            event.idempotency_key().clone(),
            event.schema_version(),
            event.actor().clone(),
            *event.sensitivity(),
            event.payload().clone(),
            1,
            timestamp,
            IntegrityDigest::from_bytes([0; 32]),
        );
        let digest = compute_integrity_digest_v2_with_global_position(
            &envelope,
            global_position,
            &payload_bytes,
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        guard_event_components(
            self.prohibited_content.as_ref(),
            event,
            CORRELATION_TYPE_CONVERSATION,
            conversation_id.as_bytes(),
            1,
            global_position,
            now,
            &payload_bytes,
            digest,
            INTEGRITY_PROFILE_V2,
        )?;

        tx.execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id,
              last_timestamp, created_at)
             VALUES (?1, ?2, 1, ?3, ?4, ?4)",
            params![
                CORRELATION_TYPE_CONVERSATION,
                conversation_id.as_bytes(),
                event.event_id().as_bytes(),
                now,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tx.execute(
            "INSERT INTO events
             (event_id, aggregate_type, aggregate_id, sequence, global_position,
              timestamp, sensitivity, schema_version, causation_id, command_id,
              idempotency_key, actor, payload, integrity_digest, correlation_id,
              correlation_type, integrity_profile)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?3, ?2, ?13)",
            params![
                event.event_id().as_bytes(),
                CORRELATION_TYPE_CONVERSATION,
                conversation_id.as_bytes(),
                global_position,
                now,
                event.schema_version() as i64,
                event.causation_id().map(EventId::as_bytes),
                event.command_id().as_bytes(),
                event.idempotency_key().as_str().as_bytes(),
                event.actor().as_str().as_bytes(),
                payload_bytes,
                digest.as_bytes(),
                INTEGRITY_PROFILE_V2,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tx.execute(
            "UPDATE event_log_state SET next_global_position = ?1 WHERE singleton = 1",
            params![next_global_position],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;

        let result = ConversationReceipt {
            conversation_id,
            workspace_id: payload.workspace_id,
            new_version: 1,
            committed_at: timestamp,
        };
        let outcome = ConversationReceiptCodec
            .encode(&result)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tx.execute(
            "INSERT INTO command_receipts
             (command_id, idempotency_scope_bytes, idempotency_key, fingerprint,
              command_outcome, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                payload.command_id.as_bytes(),
                scope,
                payload.idempotency_key.as_str().as_bytes(),
                payload.command_fingerprint.as_bytes(),
                outcome,
                now,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(ConversationCommitResult::Committed { result })
    }
}

// ── ConversationTextRepository impl ────────────────────────────────────

impl ConversationTextRepository for StoreTransaction {
    fn lookup_text_generation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &gocode_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<TextGenerationReceiptLookup, CommitError> {
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        lookup_text_receipt(
            &connection,
            command_id,
            idempotency_key,
            &scope,
            fingerprint,
        )
    }

    fn begin_text_generation(
        &self,
        payload: BeginTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        validate_begin_text_payload(&payload, &self.runtime_authority_id)?;
        let conversation_id = payload.receipt.conversation_id;
        let taskrun_id = payload.receipt.taskrun_id;
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(&payload.idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;

        if let TextGenerationReceiptLookup::Duplicate { stored_result } = lookup_text_receipt(
            &transaction,
            payload.command_id,
            &payload.idempotency_key,
            &scope,
            &payload.command_fingerprint,
        )? {
            return Ok(TextGenerationCommitResult::Duplicate { stored_result });
        }

        let (conversation_version, conversation_last_event, conversation_last_timestamp) =
            transaction
                .query_row(
                    "SELECT current_version, last_event_id, last_timestamp
                     FROM aggregate_streams
                     WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                    params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<Vec<u8>>>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
                .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let conversation_version = u64::try_from(conversation_version)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if conversation_version != payload.expected_conversation_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_conversation_version,
                actual: conversation_version,
            });
        }
        let conversation_last_event = conversation_last_event
            .map(parse_event_id_for_commit)
            .transpose()?;
        if payload.conversation_events[0].causation_id().copied() != conversation_last_event {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let workspace_payload: Vec<u8> = transaction
            .query_row(
                "SELECT payload FROM events
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2 AND sequence = 1",
                params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if !matches!(
            ConversationEventCodec.decode(&workspace_payload),
            Ok(ConversationEvent::ConversationCreated { workspace_id })
                if workspace_id == payload.receipt.workspace_id
        ) {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let taskrun_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM aggregate_streams
                    WHERE aggregate_type = ?1 AND aggregate_id = ?2
                 )",
                params![CORRELATION_TYPE_TASK_RUN, taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if taskrun_exists {
            return Err(CommitError::VersionConflict {
                expected: 0,
                actual: 1,
            });
        }

        let now = current_time_micros()?;
        if conversation_last_timestamp.is_some_and(|last| now < last) {
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(
                    conversation_last_timestamp.unwrap_or(now),
                ),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let global_position = next_global_position(&transaction)?;
        let total_events = payload
            .conversation_events
            .len()
            .checked_add(payload.taskrun_events.len())
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let next_global_position = global_position
            .checked_add(
                i64::try_from(total_events).map_err(|_| CommitError::GlobalPositionExhausted)?,
            )
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let conversation_sequence =
            conversation_version
                .checked_add(1)
                .ok_or(CommitError::VersionExhausted {
                    current: conversation_version,
                    event_count: payload.conversation_events.len(),
                })?;
        let _ = guard_conversation_event(
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            conversation_sequence,
            global_position,
            now,
        )?;
        let mut guarded_position = global_position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        for (index, event) in payload.taskrun_events.iter().enumerate() {
            let _ = guard_taskrun_event(
                self.prohibited_content.as_ref(),
                event,
                u64::try_from(index + 1)
                    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
                guarded_position,
                now,
            )?;
            guarded_position = guarded_position
                .checked_add(1)
                .ok_or(CommitError::GlobalPositionExhausted)?;
        }

        transaction
            .execute(
                "INSERT INTO aggregate_streams
                 (aggregate_type, aggregate_id, current_version, last_event_id,
                  last_timestamp, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![
                    CORRELATION_TYPE_TASK_RUN,
                    taskrun_id.as_bytes(),
                    payload.receipt.taskrun_version as i64,
                    payload.taskrun_events.last().unwrap().event_id().as_bytes(),
                    now,
                ],
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;

        let mut position = global_position;
        append_conversation_event(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            conversation_sequence,
            position,
            now,
        )?;
        position = position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        for (index, event) in payload.taskrun_events.iter().enumerate() {
            append_taskrun_event(
                &transaction,
                self.prohibited_content.as_ref(),
                event,
                u64::try_from(index + 1)
                    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
                position,
                now,
            )?;
            position = position
                .checked_add(1)
                .ok_or(CommitError::GlobalPositionExhausted)?;
        }
        update_stream_head(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            conversation_id.as_bytes(),
            conversation_version,
            payload.receipt.conversation_version,
            *payload.conversation_events[0].event_id(),
            now,
        )?;
        update_global_position(&transaction, next_global_position)?;
        let outcome = TextGenerationReceiptCodec
            .encode(&payload.receipt)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        transaction
            .execute(
                "INSERT INTO command_receipts
                 (command_id, idempotency_scope_bytes, idempotency_key, fingerprint,
                  command_outcome, committed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    payload.command_id.as_bytes(),
                    scope,
                    payload.idempotency_key.as_str().as_bytes(),
                    payload.command_fingerprint.as_bytes(),
                    outcome,
                    now,
                ],
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        transaction
            .commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }

    fn finish_text_generation(
        &self,
        payload: FinishTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        validate_finish_text_payload(&payload, &self.runtime_authority_id)?;
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(&payload.idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let stored = match lookup_text_receipt(
            &transaction,
            payload.command_id,
            &payload.idempotency_key,
            &scope,
            &payload.command_fingerprint,
        )? {
            TextGenerationReceiptLookup::Miss => {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
            TextGenerationReceiptLookup::Duplicate { stored_result } => stored_result,
        };
        if matches!(
            stored.phase,
            TextGenerationPhase::Completed
                | TextGenerationPhase::Rejected
                | TextGenerationPhase::ProhibitedInputRejected
        ) {
            return Ok(TextGenerationCommitResult::Duplicate {
                stored_result: stored,
            });
        }
        let expected_completed = TextGenerationReceipt {
            phase: TextGenerationPhase::Completed,
            conversation_version: stored.conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: stored.conversation_version,
                    event_count: 1,
                },
            )?,
            taskrun_version: stored.taskrun_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: stored.taskrun_version,
                    event_count: 1,
                },
            )?,
            ..stored.clone()
        };
        if stored.phase != TextGenerationPhase::Started
            || stored.conversation_version != payload.expected_conversation_version
            || stored.taskrun_version != payload.expected_taskrun_version
            || payload.receipt != expected_completed
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }

        let conversation_head = load_stream_head_for_commit(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
        )?;
        let taskrun_head = load_stream_head_for_commit(
            &transaction,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
        )?;
        if conversation_head.0 != payload.expected_conversation_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_conversation_version,
                actual: conversation_head.0,
            });
        }
        if taskrun_head.0 != payload.expected_taskrun_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_taskrun_version,
                actual: taskrun_head.0,
            });
        }
        if payload.conversation_events[0].causation_id().copied() != conversation_head.1
            || payload.taskrun_events[0].causation_id().copied() != taskrun_head.1
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let now = current_time_micros()?;
        let latest_timestamp = conversation_head.2.max(taskrun_head.2);
        if latest_timestamp.is_some_and(|last| now < last) {
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(latest_timestamp.unwrap_or(now)),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let global_position = next_global_position(&transaction)?;
        let next_global_position = global_position
            .checked_add(2)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let _ = guard_conversation_event(
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            global_position,
            now,
        )?;
        let taskrun_global_position = global_position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let _ = guard_taskrun_event(
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_global_position,
            now,
        )?;
        append_conversation_event(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            global_position,
            now,
        )?;
        append_taskrun_event(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_global_position,
            now,
        )?;
        update_stream_head(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
            payload.expected_conversation_version,
            payload.receipt.conversation_version,
            *payload.conversation_events[0].event_id(),
            now,
        )?;
        update_stream_head(
            &transaction,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
            payload.expected_taskrun_version,
            payload.receipt.taskrun_version,
            *payload.taskrun_events[0].event_id(),
            now,
        )?;
        update_global_position(&transaction, next_global_position)?;
        let outcome = TextGenerationReceiptCodec
            .encode(&payload.receipt)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let updated = transaction
            .execute(
                "UPDATE command_receipts
                 SET command_outcome = ?1, committed_at = ?2
                 WHERE command_id = ?3 AND idempotency_scope_bytes = ?4
                   AND idempotency_key = ?5 AND fingerprint = ?6",
                params![
                    outcome,
                    now,
                    payload.command_id.as_bytes(),
                    scope,
                    payload.idempotency_key.as_str().as_bytes(),
                    payload.command_fingerprint.as_bytes(),
                ],
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if updated != 1 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        transaction
            .commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }

    fn reject_text_generation(
        &self,
        payload: RejectTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        validate_reject_text_payload(&payload, &self.runtime_authority_id)?;
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let scope = IdempotencyScopeCodec
            .encode(&payload.idempotency_scope)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let stored = match lookup_text_receipt(
            &transaction,
            payload.command_id,
            &payload.idempotency_key,
            &scope,
            &payload.command_fingerprint,
        )? {
            TextGenerationReceiptLookup::Miss => {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
            TextGenerationReceiptLookup::Duplicate { stored_result } => stored_result,
        };
        if matches!(
            stored.phase,
            TextGenerationPhase::Completed
                | TextGenerationPhase::Rejected
                | TextGenerationPhase::ProhibitedInputRejected
        ) {
            return Ok(TextGenerationCommitResult::Duplicate {
                stored_result: stored,
            });
        }
        let expected_rejected = TextGenerationReceipt {
            phase: payload.receipt.phase,
            conversation_version: stored.conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: stored.conversation_version,
                    event_count: 1,
                },
            )?,
            taskrun_version: stored.taskrun_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: stored.taskrun_version,
                    event_count: 1,
                },
            )?,
            ..stored.clone()
        };
        if stored.phase != TextGenerationPhase::Started
            || stored.conversation_version != payload.expected_conversation_version
            || stored.taskrun_version != payload.expected_taskrun_version
            || payload.receipt != expected_rejected
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }

        let conversation_head = load_stream_head_for_commit(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
        )?;
        let taskrun_head = load_stream_head_for_commit(
            &transaction,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
        )?;
        if conversation_head.0 != payload.expected_conversation_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_conversation_version,
                actual: conversation_head.0,
            });
        }
        if taskrun_head.0 != payload.expected_taskrun_version {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_taskrun_version,
                actual: taskrun_head.0,
            });
        }
        if payload.conversation_events[0].causation_id().copied() != conversation_head.1
            || payload.taskrun_events[0].causation_id().copied() != taskrun_head.1
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let now = current_time_micros()?;
        let latest_timestamp = conversation_head.2.max(taskrun_head.2);
        if latest_timestamp.is_some_and(|last| now < last) {
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(latest_timestamp.unwrap_or(now)),
                attempted: Timestamp::from_unix_micros(now),
            });
        }
        let global_position = next_global_position(&transaction)?;
        let next_global_position = global_position
            .checked_add(2)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let _ = guard_conversation_event(
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            global_position,
            now,
        )?;
        let taskrun_global_position = global_position
            .checked_add(1)
            .ok_or(CommitError::GlobalPositionExhausted)?;
        let _ = guard_taskrun_event(
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_global_position,
            now,
        )?;
        append_conversation_event(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            global_position,
            now,
        )?;
        append_taskrun_event(
            &transaction,
            self.prohibited_content.as_ref(),
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_global_position,
            now,
        )?;
        update_stream_head(
            &transaction,
            CORRELATION_TYPE_CONVERSATION,
            stored.conversation_id.as_bytes(),
            payload.expected_conversation_version,
            payload.receipt.conversation_version,
            *payload.conversation_events[0].event_id(),
            now,
        )?;
        update_stream_head(
            &transaction,
            CORRELATION_TYPE_TASK_RUN,
            stored.taskrun_id.as_bytes(),
            payload.expected_taskrun_version,
            payload.receipt.taskrun_version,
            *payload.taskrun_events[0].event_id(),
            now,
        )?;
        update_global_position(&transaction, next_global_position)?;
        let outcome = TextGenerationReceiptCodec
            .encode(&payload.receipt)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let updated = transaction
            .execute(
                "UPDATE command_receipts
                 SET command_outcome = ?1, committed_at = ?2
                 WHERE command_id = ?3 AND idempotency_scope_bytes = ?4
                   AND idempotency_key = ?5 AND fingerprint = ?6",
                params![
                    outcome,
                    now,
                    payload.command_id.as_bytes(),
                    scope,
                    payload.idempotency_key.as_str().as_bytes(),
                    payload.command_fingerprint.as_bytes(),
                ],
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if updated != 1 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        transaction
            .commit()
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        Ok(TextGenerationCommitResult::Committed {
            result: payload.receipt,
        })
    }
}

fn lookup_text_receipt(
    connection: &Connection,
    command_id: CommandId,
    idempotency_key: &gocode_domain::id::IdempotencyKey,
    scope: &[u8],
    fingerprint: &CommandFingerprint,
) -> Result<TextGenerationReceiptLookup, CommitError> {
    let by_command = connection
        .query_row(
            "SELECT idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome
             FROM command_receipts WHERE command_id = ?1",
            params![command_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if let Some((stored_scope, stored_key, stored_fingerprint, stored_outcome)) = by_command {
        let stored_fingerprint = parse_fingerprint(stored_fingerprint)?;
        if stored_scope == scope
            && stored_key == idempotency_key.as_str().as_bytes()
            && stored_fingerprint == *fingerprint
        {
            let stored_result = TextGenerationReceiptCodec
                .decode(&stored_outcome)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            return Ok(TextGenerationReceiptLookup::Duplicate { stored_result });
        }
        return Err(CommitError::IdempotencyConflict {
            stored_command_id: command_id,
            attempted_command_id: command_id,
            stored_fingerprint,
            attempted_fingerprint: *fingerprint,
        });
    }
    if let Some((stored_command, stored_fingerprint)) = connection
        .query_row(
            "SELECT command_id, fingerprint FROM command_receipts
             WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
            params![scope, idempotency_key.as_str().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
    {
        return Err(CommitError::IdempotencyConflict {
            stored_command_id: parse_command_id_for_commit(stored_command)?,
            attempted_command_id: command_id,
            stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
            attempted_fingerprint: *fingerprint,
        });
    }
    Ok(TextGenerationReceiptLookup::Miss)
}

fn validate_begin_text_payload(
    payload: &BeginTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    if payload.conversation_events.len() != 1
        || payload.taskrun_events.len() != 4
        || payload.receipt.phase != TextGenerationPhase::Started
        || payload.receipt.taskrun_version != 4
        || payload.receipt.conversation_version
            != payload.expected_conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_conversation_version,
                    event_count: 1,
                },
            )?
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let scope_matches = matches!(
        &payload.idempotency_scope,
        IdempotencyScope {
            runtime_authority_id,
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
            ..
        } if runtime_authority_id == authority
            && *conversation_id == payload.receipt.conversation_id
    );
    let conversation_event = &payload.conversation_events[0];
    let text = match conversation_event.payload() {
        ConversationEvent::UserMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
        } if *message_id == payload.receipt.user_message_id
            && *taskrun_id == payload.receipt.taskrun_id
            && *attempt_id == payload.receipt.attempt_id =>
        {
            text
        }
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let expected_fingerprint = CommandFingerprint::for_generate_conversation_text(
        &payload.receipt.conversation_id,
        payload.expected_conversation_version,
        text,
    );
    if !scope_matches
        || payload.command_fingerprint != expected_fingerprint
        || !valid_event_context(
            conversation_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::Conversation(payload.receipt.conversation_id),
            Sensitivity::Sensitive,
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let expected_taskrun_payloads = [
        TaskRunEvent::TaskRunCreated,
        TaskRunEvent::TaskRunQueued,
        TaskRunEvent::TaskRunAdmitted,
        TaskRunEvent::AttemptStarted {
            attempt_id: payload.receipt.attempt_id,
        },
    ];
    for (index, (event, expected_payload)) in payload
        .taskrun_events
        .iter()
        .zip(expected_taskrun_payloads.iter())
        .enumerate()
    {
        if event.payload() != expected_payload
            || !valid_event_context(
                event,
                payload.command_id,
                &payload.idempotency_key,
                AggregateId::TaskRun(payload.receipt.taskrun_id),
                Sensitivity::Public,
            )
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let expected_causation = index
            .checked_sub(1)
            .map(|previous| *payload.taskrun_events[previous].event_id());
        if event.causation_id().copied() != expected_causation {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    Ok(())
}

fn validate_finish_text_payload(
    payload: &FinishTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    if payload.conversation_events.len() != 1
        || payload.taskrun_events.len() != 1
        || payload.receipt.phase != TextGenerationPhase::Completed
        || payload.receipt.conversation_version
            != payload.expected_conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_conversation_version,
                    event_count: 1,
                },
            )?
        || payload.receipt.taskrun_version
            != payload.expected_taskrun_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_taskrun_version,
                    event_count: 1,
                },
            )?
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let scope_matches = matches!(
        &payload.idempotency_scope,
        IdempotencyScope {
            runtime_authority_id,
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
            ..
        } if runtime_authority_id == authority
            && *conversation_id == payload.receipt.conversation_id
    );
    let conversation_event = &payload.conversation_events[0];
    let message_matches = matches!(
        conversation_event.payload(),
        ConversationEvent::AssistantMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            ..
        } if *message_id == payload.receipt.assistant_message_id
            && *taskrun_id == payload.receipt.taskrun_id
            && *attempt_id == payload.receipt.attempt_id
    );
    let taskrun_event = &payload.taskrun_events[0];
    if !scope_matches
        || !message_matches
        || !matches!(
            taskrun_event.payload(),
            TaskRunEvent::TaskRunCompleted {
                result: gocode_domain::command::TerminalResult::Success
            }
        )
        || !valid_event_context(
            conversation_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::Conversation(payload.receipt.conversation_id),
            Sensitivity::Sensitive,
        )
        || !valid_event_context(
            taskrun_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::TaskRun(payload.receipt.taskrun_id),
            Sensitivity::Public,
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

fn validate_reject_text_payload(
    payload: &RejectTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    if payload.conversation_events.len() != 1
        || payload.taskrun_events.len() != 1
        || !matches!(
            payload.receipt.phase,
            TextGenerationPhase::Rejected | TextGenerationPhase::ProhibitedInputRejected
        )
        || payload.receipt.conversation_version
            != payload.expected_conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_conversation_version,
                    event_count: 1,
                },
            )?
        || payload.receipt.taskrun_version
            != payload.expected_taskrun_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_taskrun_version,
                    event_count: 1,
                },
            )?
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let scope_matches = matches!(
        &payload.idempotency_scope,
        IdempotencyScope {
            runtime_authority_id,
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
            ..
        } if runtime_authority_id == authority
            && *conversation_id == payload.receipt.conversation_id
    );
    let conversation_event = &payload.conversation_events[0];
    let rejection_matches = matches!(
        conversation_event.payload(),
        ConversationEvent::GenerationFailed {
            taskrun_id,
            attempt_id,
            reason: gocode_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
        } if *taskrun_id == payload.receipt.taskrun_id
            && *attempt_id == payload.receipt.attempt_id
    );
    let taskrun_event = &payload.taskrun_events[0];
    if !scope_matches
        || !rejection_matches
        || !matches!(
            taskrun_event.payload(),
            TaskRunEvent::TaskRunFailed { reason }
                if reason == "provider_output_rejected"
        )
        || !valid_event_context(
            conversation_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::Conversation(payload.receipt.conversation_id),
            Sensitivity::Public,
        )
        || !valid_event_context(
            taskrun_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::TaskRun(payload.receipt.taskrun_id),
            Sensitivity::Public,
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

fn valid_event_context<E>(
    event: &UncommittedEvent<E>,
    command_id: CommandId,
    idempotency_key: &gocode_domain::id::IdempotencyKey,
    aggregate_id: AggregateId,
    sensitivity: Sensitivity,
) -> bool {
    event.command_id() == &command_id
        && event.idempotency_key() == idempotency_key
        && event.aggregate_id() == &aggregate_id
        && event.correlation_id() == &aggregate_id
        && event.schema_version() == 1
        && event.sensitivity() == &sensitivity
}

fn current_time_micros() -> Result<i64, CommitError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CommitError::ClockFailure)
        .and_then(|duration| {
            i64::try_from(duration.as_micros()).map_err(|_| CommitError::ClockFailure)
        })
}

fn next_global_position(transaction: &rusqlite::Transaction<'_>) -> Result<i64, CommitError> {
    transaction
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

fn update_global_position(
    transaction: &rusqlite::Transaction<'_>,
    next: i64,
) -> Result<(), CommitError> {
    transaction
        .execute(
            "UPDATE event_log_state SET next_global_position = ?1 WHERE singleton = 1",
            params![next],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}

fn load_stream_head_for_commit(
    transaction: &rusqlite::Transaction<'_>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
) -> Result<(u64, Option<EventId>, Option<i64>), CommitError> {
    let (version, event_id, timestamp) = transaction
        .query_row(
            "SELECT current_version, last_event_id, last_timestamp
             FROM aggregate_streams
             WHERE aggregate_type = ?1 AND aggregate_id = ?2",
            params![aggregate_type, aggregate_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok((
        u64::try_from(version).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        event_id.map(parse_event_id_for_commit).transpose()?,
        timestamp,
    ))
}

#[allow(clippy::too_many_arguments)]
fn update_stream_head(
    transaction: &rusqlite::Transaction<'_>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    expected_version: u64,
    new_version: u64,
    event_id: EventId,
    timestamp: i64,
) -> Result<(), CommitError> {
    let updated = transaction
        .execute(
            "UPDATE aggregate_streams
             SET current_version = ?1, last_event_id = ?2, last_timestamp = ?3
             WHERE aggregate_type = ?4 AND aggregate_id = ?5
               AND current_version = ?6",
            params![
                new_version as i64,
                event_id.as_bytes(),
                timestamp,
                aggregate_type,
                aggregate_id,
                expected_version as i64,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if updated != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

fn append_conversation_event(
    transaction: &rusqlite::Transaction<'_>,
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<ConversationEvent>,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(), CommitError> {
    let (payload, digest, conversation_id) = guard_conversation_event(
        prohibited_content,
        event,
        sequence,
        global_position,
        timestamp,
    )?;
    insert_event(
        transaction,
        event,
        CORRELATION_TYPE_CONVERSATION,
        conversation_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        INTEGRITY_PROFILE_V2,
    )
}

fn guard_conversation_event(
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<ConversationEvent>,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(Vec<u8>, IntegrityDigest, ConversationId), CommitError> {
    let conversation_id = match event.aggregate_id() {
        AggregateId::Conversation(id) => *id,
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let payload = ConversationEventCodec
        .encode(event.payload())
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let envelope = EventEnvelope::from_parts(
        *event.event_id(),
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        event.causation_id().copied(),
        *event.command_id(),
        event.idempotency_key().clone(),
        event.schema_version(),
        event.actor().clone(),
        *event.sensitivity(),
        event.payload().clone(),
        sequence,
        Timestamp::from_unix_micros(timestamp),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_v2_with_global_position(&envelope, global_position, &payload)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    guard_event_components(
        prohibited_content,
        event,
        CORRELATION_TYPE_CONVERSATION,
        conversation_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        INTEGRITY_PROFILE_V2,
    )?;
    Ok((payload, digest, conversation_id))
}

fn append_taskrun_event(
    transaction: &rusqlite::Transaction<'_>,
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<TaskRunEvent>,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(), CommitError> {
    let (payload, digest, taskrun_id) = guard_taskrun_event(
        prohibited_content,
        event,
        sequence,
        global_position,
        timestamp,
    )?;
    insert_event(
        transaction,
        event,
        CORRELATION_TYPE_TASK_RUN,
        taskrun_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        INTEGRITY_PROFILE_V1,
    )
}

fn guard_taskrun_event(
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<TaskRunEvent>,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(Vec<u8>, IntegrityDigest, TaskRunId), CommitError> {
    let taskrun_id = match event.aggregate_id() {
        AggregateId::TaskRun(id) => *id,
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let payload = TaskRunEventCodec
        .encode(event.payload())
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let envelope = EventEnvelope::from_parts(
        *event.event_id(),
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        event.causation_id().copied(),
        *event.command_id(),
        event.idempotency_key().clone(),
        event.schema_version(),
        event.actor().clone(),
        *event.sensitivity(),
        event.payload().clone(),
        sequence,
        Timestamp::from_unix_micros(timestamp),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_with_global_position(&envelope, global_position, &payload)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    guard_event_components(
        prohibited_content,
        event,
        CORRELATION_TYPE_TASK_RUN,
        taskrun_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        INTEGRITY_PROFILE_V1,
    )?;
    Ok((payload, digest, taskrun_id))
}

#[allow(clippy::too_many_arguments)]
fn guard_event_components<E>(
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<E>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    sequence: u64,
    global_position: i64,
    timestamp: i64,
    payload: &[u8],
    digest: IntegrityDigest,
    integrity_profile: i64,
) -> Result<(), CommitError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"GOCODE_STORED_EVENT_V1\0");
    append_guard_component(&mut encoded, event.event_id().as_bytes());
    append_guard_component(&mut encoded, &aggregate_type.to_be_bytes());
    append_guard_component(&mut encoded, aggregate_id);
    append_guard_component(&mut encoded, &sequence.to_be_bytes());
    append_guard_component(&mut encoded, &global_position.to_be_bytes());
    append_guard_component(&mut encoded, &timestamp.to_be_bytes());
    append_guard_component(
        &mut encoded,
        &sensitivity_value(*event.sensitivity()).to_be_bytes(),
    );
    append_guard_component(&mut encoded, &event.schema_version().to_be_bytes());
    match event.causation_id() {
        Some(id) => append_guard_component(&mut encoded, id.as_bytes()),
        None => append_guard_component(&mut encoded, &[]),
    }
    append_guard_component(&mut encoded, event.command_id().as_bytes());
    append_guard_component(&mut encoded, event.idempotency_key().as_str().as_bytes());
    append_guard_component(&mut encoded, event.actor().as_str().as_bytes());
    append_guard_component(&mut encoded, payload);
    append_guard_component(&mut encoded, digest.as_bytes());
    let (correlation_id, correlation_type) = match event.correlation_id() {
        AggregateId::TaskRun(id) => (id.as_bytes(), CORRELATION_TYPE_TASK_RUN),
        AggregateId::Conversation(id) => (id.as_bytes(), CORRELATION_TYPE_CONVERSATION),
        AggregateId::Workspace(_) => {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    };
    append_guard_component(&mut encoded, correlation_id);
    append_guard_component(&mut encoded, &correlation_type.to_be_bytes());
    append_guard_component(&mut encoded, &integrity_profile.to_be_bytes());

    match prohibited_content.inspect(CanonicalContentBoundary::CanonicalMutation, &encoded) {
        Ok(ContentDisposition::Allowed { .. }) => Ok(()),
        Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
            Err(storage_failure(StorageFailureKind::PolicyDenied))
        }
    }
}

fn append_guard_component(encoded: &mut Vec<u8>, component: &[u8]) {
    encoded.extend_from_slice(&(component.len() as u64).to_be_bytes());
    encoded.extend_from_slice(component);
}

#[allow(clippy::too_many_arguments)]
fn insert_event<E>(
    transaction: &rusqlite::Transaction<'_>,
    event: &UncommittedEvent<E>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    sequence: u64,
    global_position: i64,
    timestamp: i64,
    payload: &[u8],
    digest: IntegrityDigest,
    integrity_profile: i64,
) -> Result<(), CommitError> {
    transaction
        .execute(
            "INSERT INTO events
             (event_id, aggregate_type, aggregate_id, sequence, global_position,
              timestamp, sensitivity, schema_version, causation_id, command_id,
              idempotency_key, actor, payload, integrity_digest, correlation_id,
              correlation_type, integrity_profile)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?3, ?2, ?15)",
            params![
                event.event_id().as_bytes(),
                aggregate_type,
                aggregate_id,
                sequence as i64,
                global_position,
                timestamp,
                sensitivity_value(*event.sensitivity()),
                event.schema_version() as i64,
                event.causation_id().map(EventId::as_bytes),
                event.command_id().as_bytes(),
                event.idempotency_key().as_str().as_bytes(),
                event.actor().as_str().as_bytes(),
                payload,
                digest.as_bytes(),
                integrity_profile,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}

fn parse_event_id(bytes: Vec<u8>) -> Result<EventId, EventStoreError> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| EventStoreError::CorruptData)?;
    let id = EventId::from_bytes(bytes);
    id.to_string()
        .parse::<EventId>()
        .map_err(|_| EventStoreError::CorruptData)
}

fn parse_command_id(bytes: Vec<u8>) -> Result<CommandId, EventStoreError> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| EventStoreError::CorruptData)?;
    let id = CommandId::from_bytes(bytes);
    id.to_string()
        .parse::<CommandId>()
        .map_err(|_| EventStoreError::CorruptData)
}

fn parse_integrity_digest(bytes: Vec<u8>) -> Result<IntegrityDigest, EventStoreError> {
    Ok(IntegrityDigest::from_bytes(
        bytes.try_into().map_err(|_| EventStoreError::CorruptData)?,
    ))
}

fn parse_command_id_for_commit(bytes: Vec<u8>) -> Result<CommandId, CommitError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let id = CommandId::from_bytes(bytes);
    id.to_string()
        .parse::<CommandId>()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

fn parse_event_id_for_commit(bytes: Vec<u8>) -> Result<EventId, CommitError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let id = EventId::from_bytes(bytes);
    id.to_string()
        .parse::<EventId>()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

fn parse_fingerprint(bytes: Vec<u8>) -> Result<CommandFingerprint, CommitError> {
    Ok(CommandFingerprint::from_bytes(bytes.try_into().map_err(
        |_| storage_failure(StorageFailureKind::CorruptData),
    )?))
}

const fn storage_failure(kind: StorageFailureKind) -> CommitError {
    CommitError::StorageFailure(kind)
}

fn map_event_store_read_error(error: rusqlite::Error) -> EventStoreError {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            EventStoreError::Unavailable
        }
        _ => EventStoreError::CorruptData,
    }
}

fn map_commit_read_error(error: rusqlite::Error) -> CommitError {
    let kind = match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            StorageFailureKind::Unavailable
        }
        _ => StorageFailureKind::CorruptData,
    };
    storage_failure(kind)
}

// ── UnitOfWork impl ──────────────────────────────────────────────────────

impl UnitOfWork for StoreTransaction {
    fn lookup_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &gocode_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        let mut conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = conn.transaction().map_err(map_commit_read_error)?;

        let scope_codec = IdempotencyScopeCodec;
        let scope_bytes = scope_codec.encode(idempotency_scope).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        let cmd_id_bytes = command_id.as_bytes();
        let ikey_bytes = idempotency_key.as_str().as_bytes();

        // Check by command_id first
        let by_cmd_id: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT idempotency_scope_bytes, fingerprint, command_outcome
                 FROM command_receipts
                 WHERE command_id = ?1",
                params![cmd_id_bytes],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(map_commit_read_error)?;

        if let Some((stored_scope, stored_fp, outcome_bytes)) = by_cmd_id {
            let stored_fp_arr: [u8; 32] = stored_fp.try_into().unwrap_or([0; 32]);
            let stored_fingerprint = CommandFingerprint::from_bytes(stored_fp_arr);

            if stored_scope == scope_bytes && stored_fingerprint == *fingerprint {
                let outcome_codec = CommandOutcomeCodec;
                let stored_result = outcome_codec.decode(&outcome_bytes).map_err(|_| {
                    CommitError::StorageFailure(
                        gocode_application::ports::StorageFailureKind::CorruptData,
                    )
                })?;
                return Ok(ReceiptLookup::Duplicate { stored_result });
            } else {
                return Err(CommitError::IdempotencyConflict {
                    stored_command_id: command_id,
                    attempted_command_id: command_id,
                    stored_fingerprint,
                    attempted_fingerprint: *fingerprint,
                });
            }
        }

        // Check by (scope_bytes, idempotency_key)
        let by_scope: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT command_id, fingerprint
                 FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope_bytes, ikey_bytes],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(map_commit_read_error)?;

        if let Some((stored_cmd, stored_fp)) = by_scope {
            let stored_cmd_id = CommandId::from_bytes(stored_cmd.try_into().unwrap_or([0; 16]));
            let stored_fp_arr: [u8; 32] = stored_fp.try_into().unwrap_or([0; 32]);
            let stored_fingerprint = CommandFingerprint::from_bytes(stored_fp_arr);
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: stored_cmd_id,
                attempted_command_id: command_id,
                stored_fingerprint,
                attempted_fingerprint: *fingerprint,
            });
        }

        tx.commit().map_err(map_commit_read_error)?;
        Ok(ReceiptLookup::Miss)
    }

    fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
        if payload.events.len() > MAX_EVENTS_PER_COMMIT {
            return Err(CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            ));
        }
        if payload.events.is_empty() {
            return Err(CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            ));
        }

        let mut conn = self.inner.writer.lock().unwrap();
        let taskrun_id = match payload.events[0].correlation_id() {
            AggregateId::TaskRun(taskrun_id) => *taskrun_id,
            _ => {
                return Err(CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                ));
            }
        };
        for event in &payload.events {
            match event.correlation_id() {
                AggregateId::TaskRun(correlation_id) if *correlation_id == taskrun_id => {}
                _ => {
                    return Err(CommitError::StorageFailure(
                        gocode_application::ports::StorageFailureKind::IntegrityViolation,
                    ));
                }
            }
        }
        let taskrun_bytes = taskrun_id.as_bytes();

        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::Unavailable,
                )
            })?;

        // Step 1: Receipt lookup inside transaction
        let scope_codec = IdempotencyScopeCodec;
        let scope_bytes = scope_codec
            .encode(&payload.idempotency_scope)
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;

        // Dedup by command_id
        let existing: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT idempotency_scope_bytes, command_outcome
                 FROM command_receipts WHERE command_id = ?1",
                params![payload.command_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        if let Some((stored_scope, outcome_bytes)) = existing {
            let _ = tx.commit();
            if stored_scope == scope_bytes {
                let outcome_codec = CommandOutcomeCodec;
                let stored_result = outcome_codec.decode(&outcome_bytes).map_err(|_| {
                    CommitError::StorageFailure(
                        gocode_application::ports::StorageFailureKind::CorruptData,
                    )
                })?;
                return Ok(CommitResult::Duplicate { stored_result });
            } else {
                return Err(CommitError::IdempotencyConflict {
                    stored_command_id: payload.command_id,
                    attempted_command_id: payload.command_id,
                    stored_fingerprint: payload.command_fingerprint,
                    attempted_fingerprint: payload.command_fingerprint,
                });
            }
        }

        // Check scope+key collision
        let scope_key_exists: bool = tx
            .query_row(
                "SELECT COUNT(*) FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope_bytes, payload.idempotency_key.as_str().as_bytes(),],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);

        if scope_key_exists {
            let _ = tx.rollback();
            return Err(CommitError::IdempotencyConflict {
                stored_command_id: payload.command_id,
                attempted_command_id: payload.command_id,
                stored_fingerprint: payload.command_fingerprint,
                attempted_fingerprint: payload.command_fingerprint,
            });
        }

        // Step 2: Version check
        let stream_row = tx
            .query_row(
                "SELECT current_version, last_timestamp
                 FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                params![CORRELATION_TYPE_TASK_RUN, taskrun_bytes],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::CorruptData,
                )
            })?;

        let (current_version, last_timestamp, new_stream) = match stream_row {
            Some((version, timestamp)) => (version, timestamp, false),
            None if payload.expected_version == 0 => (0, None, true),
            None => {
                let _ = tx.rollback();
                return Err(CommitError::VersionConflict {
                    expected: payload.expected_version,
                    actual: 0,
                });
            }
        };

        if payload.expected_version != current_version as u64 {
            let _ = tx.rollback();
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: current_version as u64,
            });
        }

        // Step 3: Clock check
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CommitError::ClockFailure)?
            .as_micros() as i64;

        if let Some(last_ts) = last_timestamp
            && now < last_ts
        {
            let _ = tx.rollback();
            return Err(CommitError::ClockRegression {
                last_timestamp: Timestamp::from_unix_micros(last_ts),
                attempted: Timestamp::from_unix_micros(now),
            });
        }

        // Step 4: Allocate global position
        let base_gp: i64 = tx
            .query_row(
                "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::CorruptData,
                )
            })?;

        let new_gp = base_gp
            .checked_add(payload.events.len() as i64)
            .ok_or(CommitError::GlobalPositionExhausted)?;

        // Step 5-6: Insert events + update stream
        let event_codec = TaskRunEventCodec;
        let outcome_codec = CommandOutcomeCodec;
        let new_version = current_version + payload.events.len() as i64;
        let envelope_timestamp = Timestamp::from_unix_micros(now);
        for (i, event) in payload.events.iter().enumerate() {
            let sequence = u64::try_from(current_version + 1 + i as i64)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
            let global_position = base_gp
                .checked_add(i as i64)
                .ok_or(CommitError::GlobalPositionExhausted)?;
            let _ = guard_taskrun_event(
                self.prohibited_content.as_ref(),
                event,
                sequence,
                global_position,
                now,
            )?;
        }
        if new_stream {
            tx.execute(
                "INSERT INTO aggregate_streams
                 (aggregate_type, aggregate_id, current_version, last_event_id,
                  last_timestamp, created_at)
                 VALUES (?1, ?2, 0, NULL, NULL, ?3)",
                params![CORRELATION_TYPE_TASK_RUN, taskrun_bytes, now_micros()],
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;
        }

        for (i, event) in payload.events.iter().enumerate() {
            let seq = current_version + 1 + i as i64;
            let gp = base_gp + i as i64;

            let payload_bytes = event_codec.encode(event.payload()).map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;

            let correlation_id = match event.correlation_id() {
                AggregateId::TaskRun(correlation_id) if *correlation_id == taskrun_id => {
                    correlation_id
                }
                _ => {
                    return Err(CommitError::StorageFailure(
                        gocode_application::ports::StorageFailureKind::IntegrityViolation,
                    ));
                }
            };

            // Build temporary envelope for digest computation
            let aggregate_id = AggregateId::TaskRun(taskrun_id);
            let temp_envelope = EventEnvelope::from_parts(
                *event.event_id(),
                aggregate_id.clone(),
                AggregateId::TaskRun(*correlation_id),
                event.causation_id().copied(),
                *event.command_id(),
                event.idempotency_key().clone(),
                event.schema_version(),
                event.actor().clone(),
                *event.sensitivity(),
                event.payload().clone(),
                seq as u64,
                envelope_timestamp,
                IntegrityDigest::from_bytes([0; 32]),
            );

            let digest =
                compute_integrity_digest_with_global_position(&temp_envelope, gp, &payload_bytes)
                    .map_err(|_| {
                    CommitError::StorageFailure(
                        gocode_application::ports::StorageFailureKind::IntegrityViolation,
                    )
                })?;

            let causation_bytes: Option<&[u8]> =
                event.causation_id().map(|eid| eid.as_bytes() as &[u8]);

            tx.execute(
                "INSERT INTO events
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
                  sensitivity, schema_version, causation_id,
                  command_id, idempotency_key, actor, payload, integrity_digest,
                  correlation_id, correlation_type, integrity_profile)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                         ?15, ?16, ?17)",
                params![
                    event.event_id().as_bytes(),
                    CORRELATION_TYPE_TASK_RUN,
                    taskrun_bytes,
                    seq,
                    gp,
                    now,
                    0_i64,
                    event.schema_version() as i64,
                    causation_bytes,
                    event.command_id().as_bytes(),
                    event.idempotency_key().as_str().as_bytes(),
                    event.actor().as_str().as_bytes(),
                    payload_bytes,
                    digest.as_bytes(),
                    correlation_id.as_bytes(),
                    StoredCorrelationType::TaskRun.as_i64(),
                    INTEGRITY_PROFILE_V1,
                ],
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;
        }

        // Update stream metadata
        let last_event = payload.events.last().unwrap();
        if current_version == 0 {
            // Stream row was inserted before events (see version check above).
            // UPDATE to fill in version and event metadata.
            tx.execute(
                "UPDATE aggregate_streams
                 SET current_version = ?1, last_event_id = ?2, last_timestamp = ?3
                 WHERE aggregate_type = ?4 AND aggregate_id = ?5",
                params![
                    new_version,
                    last_event.event_id().as_bytes(),
                    now,
                    CORRELATION_TYPE_TASK_RUN,
                    taskrun_bytes,
                ],
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;
        } else {
            tx.execute(
                "UPDATE aggregate_streams
                 SET current_version = ?1, last_event_id = ?2, last_timestamp = ?3
                 WHERE aggregate_type = ?4 AND aggregate_id = ?5",
                params![
                    new_version,
                    last_event.event_id().as_bytes(),
                    now,
                    CORRELATION_TYPE_TASK_RUN,
                    taskrun_bytes,
                ],
            )
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;
        }

        // Update global position
        tx.execute(
            "UPDATE event_log_state SET next_global_position = ?1 WHERE singleton = 1",
            params![new_gp],
        )
        .map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        // Insert receipt
        let outcome_bytes = outcome_codec.encode(&payload.command_result).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        tx.execute(
            "INSERT INTO command_receipts
             (command_id, idempotency_scope_bytes, idempotency_key,
              fingerprint, command_outcome, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                payload.command_id.as_bytes(),
                scope_bytes,
                payload.idempotency_key.as_str().as_bytes(),
                payload.command_fingerprint.as_bytes(),
                outcome_bytes,
                now,
            ],
        )
        .map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        // Step 9: Commit transaction
        tx.commit().map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        Ok(CommitResult::Committed {
            new_version: new_version as u64,
        })
    }
}

// ── IdGenerator impl ─────────────────────────────────────────────────────

impl IdGenerator for StoreTransaction {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        Ok(TaskRunId::from_bytes(self.generate_uuid()))
    }

    fn next_conversation_id(&self) -> Result<gocode_domain::id::ConversationId, IdGenerationError> {
        Ok(gocode_domain::id::ConversationId::from_bytes(
            self.generate_uuid(),
        ))
    }

    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok(AttemptId::from_bytes(self.generate_uuid()))
    }

    fn next_message_id(&self) -> Result<MessageId, IdGenerationError> {
        Ok(MessageId::from_bytes(self.generate_uuid()))
    }

    fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
        if count == 0 {
            return Err(IdGenerationError::Exhausted);
        }
        let ids: Vec<EventId> = (0..count)
            .map(|_| EventId::from_bytes(self.generate_uuid()))
            .collect();
        Ok(ids)
    }
}

// ── Clock impl ───────────────────────────────────────────────────────────

impl Clock for StoreTransaction {
    fn now(&self) -> Result<Timestamp, ClockError> {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::Unavailable)?
            .as_micros() as i64;
        Ok(Timestamp::from_unix_micros(micros))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gocode_domain::id::IdempotencyKey;
    use gocode_security::SecretBroker;

    fn available_guard() -> Arc<dyn ProhibitedContentPort> {
        Arc::new(SecretBroker::new().prohibited_content_guard())
    }

    fn temp_db_path(name: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("gocode-store-{name}-{unique}.sqlite"))
            .to_string_lossy()
            .into_owned()
    }

    fn cleanup_db(db_path: &str) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{db_path}{suffix}"));
        }
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
            principal_id: gocode_application::ports::PrincipalId("test-principal".into()),
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
}
