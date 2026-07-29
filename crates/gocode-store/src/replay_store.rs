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
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, params};

use hmac::{Hmac, Mac};
use sha2::Sha256;

// ── HMAC ─────────────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;

/// Build a 77-byte HMAC-protected `HighWaterRef`.
///
/// Layout: `authority_id[16] || floor_present[1] || retained_floor[8u64be] ||
/// retention_generation[8u64be] || schema_version[4u32be] ||
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
    let schema_bytes = 8u32.to_be_bytes(); // schema_version = 8
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

/// Derive a human-readable event type from the aggregate type discriminant.
fn event_type_from_aggregate(aggregate_type: i32) -> String {
    match aggregate_type {
        1 => "TaskRunEvent".to_string(),
        2 => "ConversationEvent".to_string(),
        _ => "Unknown".to_string(),
    }
}

/// Read a [`ReplayEvent`] from a rusqlite row.
///
/// Column layout: 0=event_id, 1=aggregate_type, 2=aggregate_id,
/// 3=sequence, 4=global_position, 5=timestamp, ..., 12=payload.
fn read_replay_event(row: &rusqlite::Row) -> rusqlite::Result<ReplayEvent> {
    let event_id_blob: Vec<u8> = row.get(0)?;
    let aggregate_type: i32 = row.get(1)?;
    let aggregate_id_blob: Vec<u8> = row.get(2)?;
    let global_position: i64 = row.get(4)?;
    let timestamp: i64 = row.get(5)?;
    let payload: Vec<u8> = row.get(12)?;

    let mut event_id = [0u8; 16];
    event_id.copy_from_slice(&event_id_blob);
    let mut aggregate_id = [0u8; 16];
    aggregate_id.copy_from_slice(&aggregate_id_blob);

    let event_type = event_type_from_aggregate(aggregate_type);

    Ok(ReplayEvent {
        global_position,
        event_id,
        aggregate_type,
        aggregate_id,
        payload,
        timestamp,
        event_type,
    })
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
    /// The connection must have the v8 schema applied (including
    /// the `_replay_subscriptions` table).
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
        server_secret: &[u8; 32],
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        let conn = Arc::clone(&self.conn);
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;
        let aggregate_id_copy = *aggregate_id;
        let server_secret = *server_secret;

        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|e| ReplayError::Storage(format!("lock poisoned: {}", e)))?;

            let tx = conn
                .unchecked_transaction()
                .map_err(|e| ReplayError::Storage(format!("transaction: {}", e)))?;

            // Capture current high-water mark
            let high_water: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(global_position), 0) FROM events",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| ReplayError::Storage(format!("high water: {}", e)))?;

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

            // Read first page of events (LIMIT 100) BEFORE insert to set initial cursors
            let events = {
                let mut stmt = tx
                    .prepare(
                        "SELECT event_id, aggregate_type, aggregate_id, sequence,
                                global_position, timestamp, sensitivity, schema_version,
                                causation_id, command_id, idempotency_key, actor,
                                payload, integrity_digest, correlation_id,
                                correlation_type, integrity_profile
                         FROM events
                         WHERE aggregate_type = ?1 AND aggregate_id = ?2
                         ORDER BY global_position
                         LIMIT 100",
                    )
                    .map_err(|e| ReplayError::Storage(format!("prepare: {}", e)))?;

                stmt.query_map(
                    params![aggregate_type, aggregate_id_copy.as_slice()],
                    read_replay_event,
                )
                .map_err(|e| ReplayError::Storage(format!("query events: {}", e)))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ReplayError::Storage(format!("collect events: {}", e)))?
            };

            // Compute initial cursors from first page
            let last_delivered = events.last().map(|e| e.global_position);
            let next_page = if events.len() < 100 {
                None
            } else {
                last_delivered.map(|pos| pos + 1)
            };

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
    ) -> Result<Vec<ReplayEvent>, ReplayError> {
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
                     ORDER BY global_position
                     LIMIT ?4",
                )
                .map_err(|e| ReplayError::Storage(format!("prepare: {}", e)))?;

            let aggregate_type = session.aggregate_type;
            let aggregate_id = session.aggregate_id;

            let events = stmt
                .query_map(
                    params![
                        aggregate_type,
                        aggregate_id.as_slice(),
                        cursor,
                        limit as i64
                    ],
                    read_replay_event,
                )
                .map_err(|e| ReplayError::Storage(format!("query events: {}", e)))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ReplayError::Storage(format!("collect events: {}", e)))?;

            // Update cursors if events were delivered
            if let Some(last_event) = events.last() {
                let next_page = if events.len() < limit {
                    None
                } else {
                    Some(last_event.global_position + 1)
                };

                conn.execute(
                    "UPDATE _replay_subscriptions
                     SET last_delivered_position = ?1,
                         next_page_position = ?2
                     WHERE session_id = ?3",
                    params![last_event.global_position, next_page, session_id.as_slice(),],
                )
                .map_err(|e| ReplayError::Storage(format!("update cursors: {}", e)))?;
            }

            Ok(events)
        })
        .await
        .map_err(|e| ReplayError::Storage(format!("join error: {}", e)))?
    }

    async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        catch_up_completion_proof: &[u8],
    ) -> Result<ReplaySession, ReplayError> {
        let conn = Arc::clone(&self.conn);
        let session_id = *session_id;
        let principal_id = principal_id.to_string();
        let authority_id = *authority_id;
        let proof = catch_up_completion_proof.to_vec();

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

            let affected = conn
                .execute(
                    "UPDATE _replay_subscriptions
                     SET state = 'catch_up_complete',
                         catch_up_completion = ?1,
                         last_acked_position = last_delivered_position
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

            Ok(session)
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
    ) -> Result<Vec<ReplayEvent>, ReplayError> {
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

            // Poll for events after high-water mark
            let cursor = session.high_water_position;

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
                     ORDER BY global_position",
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
                .map_err(|e| ReplayError::Storage(format!("collect events: {}", e)))?;

            // Update last_delivered_position if events were delivered
            if let Some(last_event) = events.last() {
                conn.execute(
                    "UPDATE _replay_subscriptions
                     SET last_delivered_position = ?1
                     WHERE session_id = ?2",
                    params![last_event.global_position, session_id.as_slice()],
                )
                .map_err(|e| ReplayError::Storage(format!("update cursors: {}", e)))?;
            }

            Ok(events)
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
}
