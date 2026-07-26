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
    Clock, ClockError, CommandCommit, CommitError, CommitResult, EventStore as AppEventStore,
    EventStoreError, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream, ReceiptLookup,
    RuntimeAuthorityId, UnitOfWork,
};
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{AggregateId, AttemptId, CommandId, EventId, IntegrityDigest, TaskRunId};
use gocode_domain::timestamp::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

use crate::codec::{CommandOutcomeCodec, IdempotencyScopeCodec, StoreCodec, TaskRunEventCodec};
use crate::integrity::compute_integrity_digest_with_global_position;
use crate::schema::{apply_migrations, open_with_pragmas, run_startup_gates};

/// Maximum event count per commit (safety bound).
const MAX_EVENTS_PER_COMMIT: usize = 1_000;

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

        // Second connection for reads
        let reader = open_with_pragmas(db_path).map_err(|_| {
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
        let conn = self.inner.reader.lock().unwrap();
        let taskrun_bytes = taskrun_id.as_bytes();

        let stream: Option<(i64, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT current_version, last_event_id
                 FROM task_run_streams
                 WHERE taskrun_id = ?1",
                params![taskrun_bytes],
                |row| Ok((row.get(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .ok();

        let (current_version, last_event_id_bytes) = match stream {
            Some((cv, lei)) => (cv as u64, lei),
            None => {
                return Err(EventStoreError::NotFound);
            }
        };

        let mut stmt = conn
            .prepare(
                "SELECT event_id, sequence, timestamp, schema_version,
                        causation_id, command_id, idempotency_key, actor,
                        payload, integrity_digest
                 FROM events
                 WHERE taskrun_id = ?1
                 ORDER BY sequence ASC",
            )
            .map_err(|_| EventStoreError::CorruptData)?;

        let event_rows = stmt
            .query_map(params![taskrun_bytes], |row| {
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
                ))
            })
            .map_err(|_| EventStoreError::CorruptData)?;

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
            ) = row.map_err(|_| EventStoreError::CorruptData)?;

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
            let causation_id = causation_bytes.map(|b| EventId::from_bytes(b.try_into().unwrap()));
            let integrity_digest = IntegrityDigest::from_bytes(
                digest_bytes
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let payload = codec
                .decode(&payload_bytes)
                .map_err(|_| EventStoreError::CorruptData)?;
            let aggregate_id = AggregateId::TaskRun(taskrun_id);

            let envelope = EventEnvelope::from_parts(
                event_id,
                aggregate_id,
                taskrun_id,
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

            events.push(envelope);
        }

        let last_event_id = last_event_id_bytes.map(|b| EventId::from_bytes(b.try_into().unwrap()));

        Ok(LoadedStream {
            events,
            current_version,
            last_event_id,
        })
    }
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
        let conn = self.inner.reader.lock().unwrap();

        let scope_codec = IdempotencyScopeCodec;
        let scope_bytes = scope_codec.encode(idempotency_scope).map_err(|_| {
            CommitError::StorageFailure(
                gocode_application::ports::StorageFailureKind::IntegrityViolation,
            )
        })?;

        let cmd_id_bytes = command_id.as_bytes();
        let ikey_bytes = idempotency_key.as_str().as_bytes();

        // Check by command_id first
        let by_cmd_id: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT idempotency_scope_bytes, fingerprint, command_outcome
                 FROM command_receipts
                 WHERE command_id = ?1",
                params![cmd_id_bytes],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

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
        let by_scope: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT command_id, fingerprint
                 FROM command_receipts
                 WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
                params![scope_bytes, ikey_bytes],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

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
        let taskrun_id = *payload.events[0].taskrun_id();
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
                 FROM task_run_streams WHERE taskrun_id = ?1",
                params![taskrun_bytes],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()
            .map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::CorruptData,
                )
            })?;

        let (current_version, last_timestamp) = match stream_row {
            Some(row) => row,
            None if payload.expected_version == 0 => {
                // New aggregate — insert placeholder stream row before events
                tx.execute(
                    "INSERT INTO task_run_streams
                     (taskrun_id, current_version, last_event_id, last_timestamp, created_at)
                     VALUES (?1, 0, NULL, NULL, ?2)",
                    params![taskrun_bytes, now_micros()],
                )
                .map_err(|_| {
                    CommitError::StorageFailure(
                        gocode_application::ports::StorageFailureKind::IntegrityViolation,
                    )
                })?;
                (0, None)
            }
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
            let seq = current_version + 1 + i as i64;
            let gp = base_gp + i as i64;

            let payload_bytes = event_codec.encode(event.payload()).map_err(|_| {
                CommitError::StorageFailure(
                    gocode_application::ports::StorageFailureKind::IntegrityViolation,
                )
            })?;

            // Build temporary envelope for digest computation
            let aggregate_id = AggregateId::TaskRun(taskrun_id);
            let temp_envelope = EventEnvelope::from_parts(
                *event.event_id(),
                aggregate_id,
                taskrun_id,
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
                compute_integrity_digest_with_global_position(&temp_envelope, gp, &payload_bytes);

            let causation_bytes: Option<&[u8]> =
                event.causation_id().map(|eid| eid.as_bytes() as &[u8]);

            tx.execute(
                "INSERT INTO events
                 (event_id, taskrun_id, sequence, global_position, timestamp,
                  aggregate_type, sensitivity, schema_version, causation_id,
                  command_id, idempotency_key, actor, payload, integrity_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    event.event_id().as_bytes(),
                    taskrun_bytes,
                    seq,
                    gp,
                    now,
                    1_i64,
                    0_i64,
                    event.schema_version() as i64,
                    causation_bytes,
                    event.command_id().as_bytes(),
                    event.idempotency_key().as_str().as_bytes(),
                    event.actor().as_str().as_bytes(),
                    payload_bytes,
                    digest.as_bytes(),
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
                "UPDATE task_run_streams
                 SET current_version = ?1, last_event_id = ?2, last_timestamp = ?3
                 WHERE taskrun_id = ?4",
                params![
                    new_version,
                    last_event.event_id().as_bytes(),
                    now,
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
                "UPDATE task_run_streams
                 SET current_version = ?1, last_event_id = ?2, last_timestamp = ?3
                 WHERE taskrun_id = ?4",
                params![
                    new_version,
                    last_event.event_id().as_bytes(),
                    now,
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

    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok(AttemptId::from_bytes(self.generate_uuid()))
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
