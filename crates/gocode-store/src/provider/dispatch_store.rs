use std::path::Path;
use std::sync::Mutex;

use gocode_provider::{
    DispatchAttemptId, PreparedProviderRecord as ContractPreparedProviderRecord, ProviderCallId,
    ProviderDispatchClaim as ContractProviderDispatchClaim, ProviderDispatchRepository,
    ProviderRepositoryClaimOutcome, ProviderRepositoryError, ProviderRepositoryState,
    ProviderStreamId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::schema::{
    apply_migrations, open_with_pragmas, preflight_existing_file, run_startup_gates,
};

const PREPARED_DOMAIN: &[u8] = b"GOCODE_PROVIDER_PREPARED_V1\0";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Durable metadata of one non-effecting prepared provider request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedProviderRecord {
    /// Durable provider call identity.
    pub call_id: ProviderCallId,
    /// Exact prepared request digest.
    pub prepared_digest: [u8; 32],
    /// Committed render evidence digest.
    pub render_digest: [u8; 32],
    /// Exact adapter/model/profile digest.
    pub profile_digest: [u8; 32],
}

/// Result of persisting prepared request metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistPreparedOutcome {
    /// A new immutable record was inserted.
    Inserted,
    /// The exact existing record was observed.
    Replayed,
}

/// Atomic request for one provider dispatch claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDispatchClaim {
    /// Owning provider call.
    pub call_id: ProviderCallId,
    /// Durable dispatch attempt.
    pub attempt_id: DispatchAttemptId,
    /// Single-use permit identity returned only to the winner.
    pub permit_id: [u8; 16],
    /// Exact prepared request digest.
    pub prepared_digest: [u8; 32],
    /// Exact committed render digest.
    pub render_digest: [u8; 32],
    /// Exact provider profile digest.
    pub profile_digest: [u8; 32],
    /// Token budget reservation.
    pub token_reservation_id: [u8; 16],
    /// Cost budget reservation.
    pub cost_reservation_id: [u8; 16],
    /// Current non-zero worker fencing token.
    pub fencing_token: u64,
    /// Stable provider idempotency key.
    pub provider_idempotency_key: String,
}

/// Durable provider dispatch state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderDispatchState {
    /// Permit exists but network admission has not produced stream evidence.
    Dispatching,
    /// Adapter returned an exact stream identity.
    Streaming,
    /// Terminal settlement evidence was committed.
    Settled,
    /// Recovery cannot prove the external effect disposition.
    Uncertain,
}

/// Durable dispatch record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDispatchRecord {
    /// Dispatch attempt identity.
    pub attempt_id: DispatchAttemptId,
    /// Owning provider call identity.
    pub call_id: ProviderCallId,
    /// Current durable or recovery-projected state.
    pub state: ProviderDispatchState,
    /// Optional normalized stream identity.
    pub stream_id: Option<ProviderStreamId>,
    /// Optional terminal settlement digest.
    pub settlement_digest: Option<[u8; 32]>,
    fencing_token: u64,
    permit_id: [u8; 16],
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
    provider_idempotency_key: String,
    prepared_digest: [u8; 32],
    render_digest: [u8; 32],
    profile_digest: [u8; 32],
}

/// Outcome of atomic provider dispatch claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderClaimOutcome {
    /// Compare-and-swap winner receives the single-use permit.
    Winner {
        /// Permit identity bound to this exact claim.
        permit_id: [u8; 16],
    },
    /// Exact replay observes state but receives no permit.
    Existing {
        /// Existing attempt identity.
        attempt_id: DispatchAttemptId,
        /// Existing durable state.
        state: ProviderDispatchState,
    },
}

/// Request to bind a normalized stream to a dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkProviderStreaming {
    /// Dispatch attempt identity.
    pub attempt_id: DispatchAttemptId,
    /// Current fencing token.
    pub fencing_token: u64,
    /// Normalized stream identity.
    pub stream_id: ProviderStreamId,
}

/// Request to settle a provider dispatch terminally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettleProviderDispatch {
    /// Dispatch attempt identity.
    pub attempt_id: DispatchAttemptId,
    /// Current fencing token.
    pub fencing_token: u64,
    /// Exact settlement evidence digest.
    pub settlement_digest: [u8; 32],
}

/// Durable provider-store failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderStoreError {
    /// Store could not be opened or written.
    #[error("provider store is unavailable")]
    Unavailable,
    /// Persisted bytes or enum values are invalid.
    #[error("provider store contains corrupt data")]
    CorruptData,
    /// Prepared identity was reused with different content.
    #[error("prepared provider record conflicts with existing content")]
    PreparedConflict,
    /// Dispatch claim does not match the committed prepared record.
    #[error("provider dispatch claim does not match prepared evidence")]
    PreparedMismatch,
    /// Attempt or call already has a different dispatch claim.
    #[error("provider dispatch claim conflicts with existing claim")]
    ClaimConflict,
    /// Fencing token is zero or does not match the durable attempt.
    #[error("provider dispatch fencing token is stale")]
    StaleFencingToken,
    /// Attempt was not found.
    #[error("provider dispatch attempt was not found")]
    NotFound,
    /// Existing stream differs from the replay.
    #[error("provider stream binding conflicts with existing binding")]
    StreamConflict,
    /// Existing settlement differs from the replay.
    #[error("provider settlement conflicts with existing settlement")]
    SettlementConflict,
    /// Requested transition follows terminal settlement.
    #[error("provider dispatch is already terminal")]
    AlreadyTerminal,
    /// Idempotency key violates its stable bound.
    #[error("provider idempotency key is invalid")]
    InvalidIdempotencyKey,
}

/// Repository-owned SQLite provider dispatch store.
pub struct SqliteProviderDispatchStore {
    connection: Mutex<Connection>,
}

impl SqliteProviderDispatchStore {
    /// Opens the store, applies additive migrations and runs startup gates.
    pub fn open(path: &Path) -> Result<Self, ProviderStoreError> {
        preflight_existing_file(path).map_err(|_| ProviderStoreError::Unavailable)?;
        let path = path.to_str().ok_or(ProviderStoreError::Unavailable)?;
        let connection = open_with_pragmas(path).map_err(|_| ProviderStoreError::Unavailable)?;
        apply_migrations(&connection).map_err(|_| ProviderStoreError::Unavailable)?;
        run_startup_gates(&connection, path).map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Persists immutable prepared metadata or returns exact replay.
    pub fn persist_prepared(
        &self,
        record: &PreparedProviderRecord,
    ) -> Result<PersistPreparedOutcome, ProviderStoreError> {
        let record_digest = prepared_record_digest(record);
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        if let Some(stored) = load_prepared(&connection, record.call_id)? {
            return if stored == *record {
                Ok(PersistPreparedOutcome::Replayed)
            } else {
                Err(ProviderStoreError::PreparedConflict)
            };
        }
        connection
            .execute(
                "INSERT INTO provider_prepared_requests
                 (call_id, prepared_digest, render_digest, profile_digest, record_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    record.call_id.as_bytes().as_slice(),
                    record.prepared_digest.as_slice(),
                    record.render_digest.as_slice(),
                    record.profile_digest.as_slice(),
                    record_digest.as_slice(),
                ],
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(PersistPreparedOutcome::Inserted)
    }

    /// Loads and integrity-checks prepared metadata.
    pub fn get_prepared(
        &self,
        call_id: ProviderCallId,
    ) -> Result<Option<PreparedProviderRecord>, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        load_prepared(&connection, call_id)
    }

    /// Atomically claims one dispatch. Only the insert winner receives permit.
    pub fn claim(
        &self,
        claim: &ProviderDispatchClaim,
    ) -> Result<ProviderClaimOutcome, ProviderStoreError> {
        validate_claim(claim)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let prepared = load_prepared(&transaction, claim.call_id)?
            .ok_or(ProviderStoreError::PreparedMismatch)?;
        if prepared.prepared_digest != claim.prepared_digest
            || prepared.render_digest != claim.render_digest
            || prepared.profile_digest != claim.profile_digest
        {
            return Err(ProviderStoreError::PreparedMismatch);
        }
        if let Some(existing) = load_dispatch_by_attempt(&transaction, claim.attempt_id)? {
            if dispatch_matches_claim(&existing, claim) {
                return Ok(ProviderClaimOutcome::Existing {
                    attempt_id: existing.attempt_id,
                    state: existing.state,
                });
            }
            return Err(ProviderStoreError::ClaimConflict);
        }
        if load_dispatch_by_call(&transaction, claim.call_id)?.is_some() {
            return Err(ProviderStoreError::ClaimConflict);
        }
        insert_dispatch(&transaction, claim)?;
        transaction
            .commit()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(ProviderClaimOutcome::Winner {
            permit_id: claim.permit_id,
        })
    }

    /// Binds a normalized stream with expected-fence idempotency.
    pub fn mark_streaming(
        &self,
        request: &MarkProviderStreaming,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&connection, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match (record.state, record.stream_id) {
            (ProviderDispatchState::Dispatching, None) => {
                connection
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 2, stream_id = ?1 WHERE attempt_id = ?2 AND state = 1",
                        params![
                            request.stream_id.as_bytes().as_slice(),
                            request.attempt_id.as_bytes().as_slice()
                        ],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Streaming, Some(existing)) if existing == request.stream_id => {
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Dispatching, Some(_)) => Err(ProviderStoreError::CorruptData),
            (ProviderDispatchState::Streaming, _) => Err(ProviderStoreError::StreamConflict),
            (ProviderDispatchState::Settled, _) => Err(ProviderStoreError::AlreadyTerminal),
            (ProviderDispatchState::Uncertain, _) => Err(ProviderStoreError::AlreadyTerminal),
        }
    }

    /// Commits terminal settlement or returns exact replay.
    pub fn settle(
        &self,
        request: &SettleProviderDispatch,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&connection, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        if record.state == ProviderDispatchState::Settled {
            return if record.settlement_digest == Some(request.settlement_digest) {
                Ok(ProviderDispatchState::Settled)
            } else {
                Err(ProviderStoreError::SettlementConflict)
            };
        }
        if record.state == ProviderDispatchState::Uncertain {
            return Err(ProviderStoreError::AlreadyTerminal);
        }
        connection
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 3, settlement_digest = ?1 WHERE attempt_id = ?2 AND state IN (1, 2)",
                params![
                    request.settlement_digest.as_slice(),
                    request.attempt_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        Ok(ProviderDispatchState::Settled)
    }

    /// Loads one durable dispatch record.
    pub fn get_dispatch(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Option<ProviderDispatchRecord>, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        load_dispatch_by_attempt(&connection, attempt_id)
    }

    /// Marks a claimed or streaming dispatch uncertain with expected fencing.
    pub fn mark_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&connection, attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, fencing_token)?;
        match record.state {
            ProviderDispatchState::Settled => Err(ProviderStoreError::AlreadyTerminal),
            ProviderDispatchState::Uncertain => Ok(ProviderDispatchState::Uncertain),
            ProviderDispatchState::Dispatching | ProviderDispatchState::Streaming => {
                connection
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 4 WHERE attempt_id = ?1 AND state IN (1, 2)",
                        [attempt_id.as_bytes().as_slice()],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::Uncertain)
            }
        }
    }

    /// Returns incomplete dispatches projected conservatively as uncertain.
    pub fn reopen_incomplete(&self) -> Result<Vec<ProviderDispatchRecord>, ProviderStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT attempt_id, call_id, permit_id, token_reservation_id,
                        cost_reservation_id, fencing_token, provider_idempotency_key,
                        prepared_digest, render_digest, profile_digest, state,
                        stream_id, settlement_digest
                 FROM provider_dispatch_attempts WHERE state IN (1, 2)
                 ORDER BY attempt_id",
            )
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let rows = statement
            .query_map([], decode_dispatch_row)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let mut records = Vec::new();
        for row in rows {
            let mut record = row.map_err(|_| ProviderStoreError::CorruptData)?;
            record.state = ProviderDispatchState::Uncertain;
            records.push(record);
        }
        Ok(records)
    }
}

impl ProviderDispatchRepository for SqliteProviderDispatchStore {
    fn persist_prepared(
        &self,
        record: &ContractPreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::persist_prepared(
            self,
            &PreparedProviderRecord {
                call_id: record.call_id,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn claim(
        &self,
        claim: &ContractProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError> {
        SqliteProviderDispatchStore::claim(
            self,
            &ProviderDispatchClaim {
                call_id: claim.call_id,
                attempt_id: claim.attempt_id,
                permit_id: claim.permit_id,
                prepared_digest: claim.prepared_digest,
                render_digest: claim.render_digest,
                profile_digest: claim.profile_digest,
                token_reservation_id: claim.token_reservation_id,
                cost_reservation_id: claim.cost_reservation_id,
                fencing_token: claim.fencing_token,
                provider_idempotency_key: claim.provider_idempotency_key.clone(),
            },
        )
        .map(|outcome| match outcome {
            ProviderClaimOutcome::Winner { permit_id } => {
                ProviderRepositoryClaimOutcome::Winner { permit_id }
            }
            ProviderClaimOutcome::Existing { attempt_id, state } => {
                ProviderRepositoryClaimOutcome::Existing {
                    attempt_id,
                    state: repository_state(state),
                }
            }
        })
        .map_err(repository_error)
    }

    fn mark_streaming(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        stream_id: ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_streaming(
            self,
            &MarkProviderStreaming {
                attempt_id,
                fencing_token,
                stream_id,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn mark_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_uncertain(self, attempt_id, fencing_token)
            .map(|_| ())
            .map_err(repository_error)
    }
}

fn validate_claim(claim: &ProviderDispatchClaim) -> Result<(), ProviderStoreError> {
    if claim.fencing_token == 0 {
        return Err(ProviderStoreError::StaleFencingToken);
    }
    if claim.provider_idempotency_key.is_empty()
        || claim.provider_idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || claim
            .provider_idempotency_key
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderStoreError::InvalidIdempotencyKey);
    }
    Ok(())
}

fn prepared_record_digest(record: &PreparedProviderRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_DOMAIN);
    hasher.update(record.call_id.as_bytes());
    hasher.update(record.prepared_digest);
    hasher.update(record.render_digest);
    hasher.update(record.profile_digest);
    hasher.finalize().into()
}

fn load_prepared(
    connection: &Connection,
    call_id: ProviderCallId,
) -> Result<Option<PreparedProviderRecord>, ProviderStoreError> {
    let stored = connection
        .query_row(
            "SELECT prepared_digest, render_digest, profile_digest, record_digest
             FROM provider_prepared_requests WHERE call_id = ?1",
            [call_id.as_bytes().as_slice()],
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
        .map_err(|_| ProviderStoreError::CorruptData)?;
    let Some((prepared, render, profile, stored_digest)) = stored else {
        return Ok(None);
    };
    let record = PreparedProviderRecord {
        call_id,
        prepared_digest: fixed_bytes(prepared)?,
        render_digest: fixed_bytes(render)?,
        profile_digest: fixed_bytes(profile)?,
    };
    if fixed_bytes::<32>(stored_digest)? != prepared_record_digest(&record) {
        return Err(ProviderStoreError::CorruptData);
    }
    Ok(Some(record))
}

fn insert_dispatch(
    transaction: &Transaction<'_>,
    claim: &ProviderDispatchClaim,
) -> Result<(), ProviderStoreError> {
    let fencing_token =
        i64::try_from(claim.fencing_token).map_err(|_| ProviderStoreError::StaleFencingToken)?;
    transaction
        .execute(
            "INSERT INTO provider_dispatch_attempts
             (attempt_id, call_id, permit_id, token_reservation_id,
              cost_reservation_id, fencing_token, provider_idempotency_key,
              prepared_digest, render_digest, profile_digest, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.call_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                fencing_token,
                claim.provider_idempotency_key,
                claim.prepared_digest.as_slice(),
                claim.render_digest.as_slice(),
                claim.profile_digest.as_slice(),
            ],
        )
        .map_err(|_| ProviderStoreError::Unavailable)?;
    Ok(())
}

fn load_dispatch_by_attempt(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<Option<ProviderDispatchRecord>, ProviderStoreError> {
    connection
        .query_row(
            "SELECT attempt_id, call_id, permit_id, token_reservation_id,
                    cost_reservation_id, fencing_token, provider_idempotency_key,
                    prepared_digest, render_digest, profile_digest, state,
                    stream_id, settlement_digest
             FROM provider_dispatch_attempts WHERE attempt_id = ?1",
            [attempt_id.as_bytes().as_slice()],
            decode_dispatch_row,
        )
        .optional()
        .map_err(|_| ProviderStoreError::CorruptData)
}

fn load_dispatch_by_call(
    connection: &Connection,
    call_id: ProviderCallId,
) -> Result<Option<ProviderDispatchRecord>, ProviderStoreError> {
    connection
        .query_row(
            "SELECT attempt_id, call_id, permit_id, token_reservation_id,
                    cost_reservation_id, fencing_token, provider_idempotency_key,
                    prepared_digest, render_digest, profile_digest, state,
                    stream_id, settlement_digest
             FROM provider_dispatch_attempts WHERE call_id = ?1",
            [call_id.as_bytes().as_slice()],
            decode_dispatch_row,
        )
        .optional()
        .map_err(|_| ProviderStoreError::CorruptData)
}

fn decode_dispatch_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProviderDispatchRecord> {
    let attempt_id = fixed_bytes_sql::<16>(row.get(0)?)?;
    let call_id = fixed_bytes_sql::<16>(row.get(1)?)?;
    let permit_id = fixed_bytes_sql::<16>(row.get(2)?)?;
    let token_reservation_id = fixed_bytes_sql::<16>(row.get(3)?)?;
    let cost_reservation_id = fixed_bytes_sql::<16>(row.get(4)?)?;
    let fencing_token: i64 = row.get(5)?;
    let state = decode_state(row.get(10)?)?;
    let stream_id = row
        .get::<_, Option<Vec<u8>>>(11)?
        .map(fixed_bytes_sql::<16>)
        .transpose()?
        .map(ProviderStreamId::from_bytes);
    let settlement_digest = row
        .get::<_, Option<Vec<u8>>>(12)?
        .map(fixed_bytes_sql::<32>)
        .transpose()?;
    Ok(ProviderDispatchRecord {
        attempt_id: DispatchAttemptId::from_bytes(attempt_id),
        call_id: ProviderCallId::from_bytes(call_id),
        state,
        stream_id,
        settlement_digest,
        fencing_token: u64::try_from(fencing_token).map_err(|_| rusqlite::Error::InvalidQuery)?,
        permit_id,
        token_reservation_id,
        cost_reservation_id,
        provider_idempotency_key: row.get(6)?,
        prepared_digest: fixed_bytes_sql(row.get(7)?)?,
        render_digest: fixed_bytes_sql(row.get(8)?)?,
        profile_digest: fixed_bytes_sql(row.get(9)?)?,
    })
}

fn decode_state(value: i64) -> rusqlite::Result<ProviderDispatchState> {
    match value {
        1 => Ok(ProviderDispatchState::Dispatching),
        2 => Ok(ProviderDispatchState::Streaming),
        3 => Ok(ProviderDispatchState::Settled),
        4 => Ok(ProviderDispatchState::Uncertain),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn dispatch_matches_claim(record: &ProviderDispatchRecord, claim: &ProviderDispatchClaim) -> bool {
    record.call_id == claim.call_id
        && record.permit_id == claim.permit_id
        && record.token_reservation_id == claim.token_reservation_id
        && record.cost_reservation_id == claim.cost_reservation_id
        && record.fencing_token == claim.fencing_token
        && record.provider_idempotency_key == claim.provider_idempotency_key
        && record.prepared_digest == claim.prepared_digest
        && record.render_digest == claim.render_digest
        && record.profile_digest == claim.profile_digest
}

fn verify_fence(
    record: &ProviderDispatchRecord,
    fencing_token: u64,
) -> Result<(), ProviderStoreError> {
    if fencing_token == 0 || record.fencing_token != fencing_token {
        Err(ProviderStoreError::StaleFencingToken)
    } else {
        Ok(())
    }
}

const fn repository_state(state: ProviderDispatchState) -> ProviderRepositoryState {
    match state {
        ProviderDispatchState::Dispatching => ProviderRepositoryState::Dispatching,
        ProviderDispatchState::Streaming => ProviderRepositoryState::Streaming,
        ProviderDispatchState::Settled => ProviderRepositoryState::Settled,
        ProviderDispatchState::Uncertain => ProviderRepositoryState::Uncertain,
    }
}

const fn repository_error(error: ProviderStoreError) -> ProviderRepositoryError {
    match error {
        ProviderStoreError::Unavailable => ProviderRepositoryError::Unavailable,
        ProviderStoreError::CorruptData => ProviderRepositoryError::CorruptData,
        ProviderStoreError::PreparedMismatch => ProviderRepositoryError::PreparedMismatch,
        ProviderStoreError::StaleFencingToken => ProviderRepositoryError::StaleFencingToken,
        ProviderStoreError::PreparedConflict
        | ProviderStoreError::ClaimConflict
        | ProviderStoreError::NotFound
        | ProviderStoreError::StreamConflict
        | ProviderStoreError::SettlementConflict
        | ProviderStoreError::AlreadyTerminal
        | ProviderStoreError::InvalidIdempotencyKey => ProviderRepositoryError::Conflict,
    }
}

fn fixed_bytes<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], ProviderStoreError> {
    bytes
        .try_into()
        .map_err(|_| ProviderStoreError::CorruptData)
}

fn fixed_bytes_sql<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
