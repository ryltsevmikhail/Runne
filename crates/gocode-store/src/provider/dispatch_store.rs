use std::path::Path;
use std::sync::Mutex;

use gocode_provider::{
    DispatchAttemptId, PreparedProviderRecord as ContractPreparedProviderRecord,
    ProviderCallDigestVersion, ProviderCallId,
    ProviderDispatchClaim as ContractProviderDispatchClaim, ProviderDispatchRepository,
    ProviderPreEffectRejection, ProviderRepositoryClaimOutcome, ProviderRepositoryError,
    ProviderRepositoryState, ProviderStreamId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::schema::{apply_migrations, open_with_pragmas, run_startup_gates};

const PREPARED_V1_DOMAIN: &[u8] = b"GOCODE_PROVIDER_PREPARED_V1\0";
const PREPARED_V2_DOMAIN: &[u8] = b"GOCODE_PROVIDER_PREPARED_V2\0";

/// Durable metadata of one non-effecting prepared provider request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedProviderRecord {
    /// Durable provider call identity.
    pub call_id: ProviderCallId,
    /// Exact canonical provider-call digest contract.
    pub call_digest_version: ProviderCallDigestVersion,
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
    /// A typed local rejection proves the external effect did not begin.
    RejectedBeforeEffect,
    /// Adapter returned an exact stream identity.
    Streaming,
    /// Terminal evidence is durable but authoritative completion is pending.
    TerminalPendingCommit,
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
    /// Exact typed reason when dispatch was rejected before external effect.
    pub pre_effect_rejection: Option<ProviderPreEffectRejection>,
    call_digest_version: ProviderCallDigestVersion,
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
    /// Existing pre-effect rejection differs from the replay.
    #[error("provider pre-effect rejection conflicts with existing rejection")]
    RejectionConflict,
    /// Terminal settlement was attempted before a durable stream binding.
    #[error("provider settlement requires a streaming dispatch")]
    SettlementBeforeStreaming,
    /// Authoritative settlement was attempted before terminal evidence was durable.
    #[error("provider settlement requires terminal pending evidence")]
    SettlementBeforeTerminal,
    /// Requested transition follows terminal settlement.
    #[error("provider dispatch is already terminal")]
    AlreadyTerminal,
    /// Idempotency key violates its stable bound.
    #[error("provider idempotency key is invalid")]
    InvalidIdempotencyKey,
    /// Caller-selected V12 claim path is disabled after runtime-owned V13 admission.
    #[error("legacy caller-selected provider claim is disabled")]
    LegacyClaimDisabled,
}

/// Repository-owned SQLite provider dispatch store.
pub struct SqliteProviderDispatchStore {
    connection: Mutex<Connection>,
}

impl SqliteProviderDispatchStore {
    /// Opens the store, applies additive migrations and runs startup gates.
    pub fn open(path: &Path) -> Result<Self, ProviderStoreError> {
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
                 (call_id, prepared_digest, render_digest, profile_digest, record_digest,
                  call_digest_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    record.call_id.as_bytes().as_slice(),
                    record.prepared_digest.as_slice(),
                    record.render_digest.as_slice(),
                    record.profile_digest.as_slice(),
                    record_digest.as_slice(),
                    encode_digest_version(record.call_digest_version),
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

    /// Rejects the retired caller-selected V12 claim path.
    ///
    /// V13 inserts a claim only through the runtime authority issuer, in the
    /// same transaction as semantic admission and both budget reservations.
    pub fn claim(
        &self,
        _claim: &ProviderDispatchClaim,
    ) -> Result<ProviderClaimOutcome, ProviderStoreError> {
        Err(ProviderStoreError::LegacyClaimDisabled)
    }

    /// Binds a normalized stream with expected-fence idempotency.
    pub fn mark_streaming(
        &self,
        request: &MarkProviderStreaming,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match (record.state, record.stream_id) {
            (ProviderDispatchState::Dispatching, None) => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 3, stream_id = ?1 WHERE attempt_id = ?2 AND state = 1",
                        params![
                            request.stream_id.as_bytes().as_slice(),
                            request.attempt_id.as_bytes().as_slice()
                        ],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Streaming, Some(existing)) if existing == request.stream_id => {
                Ok(ProviderDispatchState::Streaming)
            }
            (ProviderDispatchState::Dispatching, Some(_)) => Err(ProviderStoreError::CorruptData),
            (ProviderDispatchState::Streaming, _) => Err(ProviderStoreError::StreamConflict),
            (
                ProviderDispatchState::RejectedBeforeEffect
                | ProviderDispatchState::TerminalPendingCommit
                | ProviderDispatchState::Settled
                | ProviderDispatchState::Uncertain,
                _,
            ) => Err(ProviderStoreError::AlreadyTerminal),
        }
    }

    /// Commits or exactly replays a typed rejection proved to precede dispatch.
    pub fn mark_rejected_before_effect(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        rejection: ProviderPreEffectRejection,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, fencing_token)?;
        match (record.state, record.pre_effect_rejection) {
            (ProviderDispatchState::Dispatching, None) => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 2, pre_effect_rejection = ?1
                         WHERE attempt_id = ?2 AND state = 1
                           AND pre_effect_rejection IS NULL",
                        params![
                            encode_pre_effect_rejection(rejection),
                            attempt_id.as_bytes().as_slice(),
                        ],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::RejectedBeforeEffect)
            }
            (ProviderDispatchState::RejectedBeforeEffect, Some(existing))
                if existing == rejection =>
            {
                Ok(ProviderDispatchState::RejectedBeforeEffect)
            }
            (ProviderDispatchState::RejectedBeforeEffect, Some(_)) => {
                Err(ProviderStoreError::RejectionConflict)
            }
            (ProviderDispatchState::Dispatching, Some(_))
            | (ProviderDispatchState::RejectedBeforeEffect, None) => {
                Err(ProviderStoreError::CorruptData)
            }
            (
                ProviderDispatchState::Streaming
                | ProviderDispatchState::TerminalPendingCommit
                | ProviderDispatchState::Settled
                | ProviderDispatchState::Uncertain,
                _,
            ) => Err(ProviderStoreError::AlreadyTerminal),
        }
    }

    /// Commits or exactly replays terminal evidence pending authoritative completion.
    pub fn mark_terminal_pending(
        &self,
        request: &SettleProviderDispatch,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match (record.state, record.settlement_digest) {
            (ProviderDispatchState::Streaming, None) => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 4, settlement_digest = ?1
                         WHERE attempt_id = ?2 AND state = 3
                           AND settlement_digest IS NULL",
                        params![
                            request.settlement_digest.as_slice(),
                            request.attempt_id.as_bytes().as_slice(),
                        ],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::TerminalPendingCommit)
            }
            (ProviderDispatchState::TerminalPendingCommit, Some(existing))
                if existing == request.settlement_digest =>
            {
                Ok(ProviderDispatchState::TerminalPendingCommit)
            }
            (ProviderDispatchState::Settled, Some(existing))
                if existing == request.settlement_digest =>
            {
                Ok(ProviderDispatchState::Settled)
            }
            (
                ProviderDispatchState::TerminalPendingCommit | ProviderDispatchState::Settled,
                Some(_),
            ) => Err(ProviderStoreError::SettlementConflict),
            (ProviderDispatchState::Dispatching, _) => {
                Err(ProviderStoreError::SettlementBeforeStreaming)
            }
            (ProviderDispatchState::RejectedBeforeEffect | ProviderDispatchState::Uncertain, _) => {
                Err(ProviderStoreError::AlreadyTerminal)
            }
            (ProviderDispatchState::Streaming, Some(_))
            | (ProviderDispatchState::TerminalPendingCommit, None)
            | (ProviderDispatchState::Settled, None) => Err(ProviderStoreError::CorruptData),
        }
    }

    /// Commits terminal settlement or returns exact replay.
    pub fn settle(
        &self,
        request: &SettleProviderDispatch,
    ) -> Result<ProviderDispatchState, ProviderStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, request.attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, request.fencing_token)?;
        match record.state {
            ProviderDispatchState::Settled => {
                if record.settlement_digest == Some(request.settlement_digest) {
                    Ok(ProviderDispatchState::Settled)
                } else {
                    Err(ProviderStoreError::SettlementConflict)
                }
            }
            ProviderDispatchState::TerminalPendingCommit => {
                if record.settlement_digest != Some(request.settlement_digest) {
                    return Err(ProviderStoreError::SettlementConflict);
                }
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 5 WHERE attempt_id = ?1 AND state = 4",
                        [request.attempt_id.as_bytes().as_slice()],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                Ok(ProviderDispatchState::Settled)
            }
            ProviderDispatchState::Dispatching => {
                Err(ProviderStoreError::SettlementBeforeStreaming)
            }
            ProviderDispatchState::Streaming => Err(ProviderStoreError::SettlementBeforeTerminal),
            ProviderDispatchState::RejectedBeforeEffect | ProviderDispatchState::Uncertain => {
                Err(ProviderStoreError::AlreadyTerminal)
            }
        }
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
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderStoreError::Unavailable)?;
        let record = load_dispatch_by_attempt(&transaction, attempt_id)?
            .ok_or(ProviderStoreError::NotFound)?;
        verify_fence(&record, fencing_token)?;
        match record.state {
            ProviderDispatchState::RejectedBeforeEffect | ProviderDispatchState::Settled => {
                Err(ProviderStoreError::AlreadyTerminal)
            }
            ProviderDispatchState::Uncertain => Ok(ProviderDispatchState::Uncertain),
            ProviderDispatchState::Dispatching
            | ProviderDispatchState::Streaming
            | ProviderDispatchState::TerminalPendingCommit => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_dispatch_attempts
                         SET state = 6 WHERE attempt_id = ?1 AND state IN (1, 3, 4)",
                        [attempt_id.as_bytes().as_slice()],
                    )
                    .map_err(|_| ProviderStoreError::Unavailable)?;
                if changed != 1 {
                    return Err(ProviderStoreError::CorruptData);
                }
                transaction
                    .commit()
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
                "SELECT dispatch.attempt_id, dispatch.call_id, dispatch.permit_id,
                        dispatch.token_reservation_id, dispatch.cost_reservation_id,
                        dispatch.fencing_token, dispatch.provider_idempotency_key,
                        dispatch.prepared_digest, dispatch.render_digest,
                        dispatch.profile_digest, dispatch.state, dispatch.stream_id,
                        dispatch.settlement_digest, dispatch.pre_effect_rejection,
                        prepared.call_digest_version, prepared.record_digest
                 FROM provider_dispatch_attempts AS dispatch
                 JOIN provider_prepared_requests AS prepared
                   ON prepared.call_id = dispatch.call_id
                 WHERE dispatch.state IN (1, 3, 4)
                 ORDER BY dispatch.attempt_id",
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
    fn load_prepared(
        &self,
        call_id: ProviderCallId,
    ) -> Result<Option<ContractPreparedProviderRecord>, ProviderRepositoryError> {
        SqliteProviderDispatchStore::get_prepared(self, call_id)
            .map(|record| {
                record.map(|record| ContractPreparedProviderRecord {
                    call_id: record.call_id,
                    call_digest_version: record.call_digest_version,
                    prepared_digest: record.prepared_digest,
                    render_digest: record.render_digest,
                    profile_digest: record.profile_digest,
                })
            })
            .map_err(repository_error)
    }

    fn persist_prepared(
        &self,
        record: &ContractPreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::persist_prepared(
            self,
            &PreparedProviderRecord {
                call_id: record.call_id,
                call_digest_version: record.call_digest_version,
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

    fn mark_rejected_before_effect(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        rejection: ProviderPreEffectRejection,
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_rejected_before_effect(
            self,
            attempt_id,
            fencing_token,
            rejection,
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn mark_terminal_pending(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::mark_terminal_pending(
            self,
            &SettleProviderDispatch {
                attempt_id,
                fencing_token,
                settlement_digest,
            },
        )
        .map(|_| ())
        .map_err(repository_error)
    }

    fn settle(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        SqliteProviderDispatchStore::settle(
            self,
            &SettleProviderDispatch {
                attempt_id,
                fencing_token,
                settlement_digest,
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

fn prepared_record_digest(record: &PreparedProviderRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    match record.call_digest_version {
        ProviderCallDigestVersion::V1 => hasher.update(PREPARED_V1_DOMAIN),
        ProviderCallDigestVersion::V2 => {
            hasher.update(PREPARED_V2_DOMAIN);
            hasher.update([2]);
        }
    }
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
            "SELECT prepared_digest, render_digest, profile_digest, record_digest,
                    call_digest_version
             FROM provider_prepared_requests WHERE call_id = ?1",
            [call_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderStoreError::CorruptData)?;
    let Some((prepared, render, profile, stored_digest, digest_version)) = stored else {
        return Ok(None);
    };
    let record = PreparedProviderRecord {
        call_id,
        call_digest_version: decode_digest_version(digest_version)?,
        prepared_digest: fixed_bytes(prepared)?,
        render_digest: fixed_bytes(render)?,
        profile_digest: fixed_bytes(profile)?,
    };
    if fixed_bytes::<32>(stored_digest)? != prepared_record_digest(&record) {
        return Err(ProviderStoreError::CorruptData);
    }
    Ok(Some(record))
}

const fn encode_digest_version(version: ProviderCallDigestVersion) -> i64 {
    match version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    }
}

fn decode_digest_version(value: i64) -> Result<ProviderCallDigestVersion, ProviderStoreError> {
    match value {
        1 => Ok(ProviderCallDigestVersion::V1),
        2 => Ok(ProviderCallDigestVersion::V2),
        _ => Err(ProviderStoreError::CorruptData),
    }
}

fn load_dispatch_by_attempt(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<Option<ProviderDispatchRecord>, ProviderStoreError> {
    connection
        .query_row(
            "SELECT dispatch.attempt_id, dispatch.call_id, dispatch.permit_id,
                    dispatch.token_reservation_id, dispatch.cost_reservation_id,
                    dispatch.fencing_token, dispatch.provider_idempotency_key,
                    dispatch.prepared_digest, dispatch.render_digest,
                    dispatch.profile_digest, dispatch.state, dispatch.stream_id,
                    dispatch.settlement_digest, dispatch.pre_effect_rejection,
                    prepared.call_digest_version, prepared.record_digest
             FROM provider_dispatch_attempts AS dispatch
             JOIN provider_prepared_requests AS prepared
               ON prepared.call_id = dispatch.call_id
             WHERE dispatch.attempt_id = ?1",
            [attempt_id.as_bytes().as_slice()],
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
    let pre_effect_rejection = row
        .get::<_, Option<i64>>(13)?
        .map(decode_pre_effect_rejection)
        .transpose()?;
    let call_digest_version = decode_digest_version_sql(row.get(14)?)?;
    let prepared_digest = fixed_bytes_sql(row.get(7)?)?;
    let render_digest = fixed_bytes_sql(row.get(8)?)?;
    let profile_digest = fixed_bytes_sql(row.get(9)?)?;
    let prepared = PreparedProviderRecord {
        call_id: ProviderCallId::from_bytes(call_id),
        call_digest_version,
        prepared_digest,
        render_digest,
        profile_digest,
    };
    if fixed_bytes_sql::<32>(row.get(15)?)? != prepared_record_digest(&prepared) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let record = ProviderDispatchRecord {
        attempt_id: DispatchAttemptId::from_bytes(attempt_id),
        call_id: ProviderCallId::from_bytes(call_id),
        state,
        stream_id,
        settlement_digest,
        pre_effect_rejection,
        call_digest_version,
        fencing_token: u64::try_from(fencing_token).map_err(|_| rusqlite::Error::InvalidQuery)?,
        permit_id,
        token_reservation_id,
        cost_reservation_id,
        provider_idempotency_key: row.get(6)?,
        prepared_digest,
        render_digest,
        profile_digest,
    };
    if dispatch_record_shape_is_valid(&record) {
        Ok(record)
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

fn dispatch_record_shape_is_valid(record: &ProviderDispatchRecord) -> bool {
    match record.state {
        ProviderDispatchState::Dispatching => {
            record.stream_id.is_none()
                && record.settlement_digest.is_none()
                && record.pre_effect_rejection.is_none()
        }
        ProviderDispatchState::RejectedBeforeEffect => {
            record.stream_id.is_none()
                && record.settlement_digest.is_none()
                && record.pre_effect_rejection.is_some()
        }
        ProviderDispatchState::Streaming => {
            record.stream_id.is_some()
                && record.settlement_digest.is_none()
                && record.pre_effect_rejection.is_none()
        }
        ProviderDispatchState::TerminalPendingCommit => {
            record.stream_id.is_some()
                && record.settlement_digest.is_some()
                && record.pre_effect_rejection.is_none()
        }
        ProviderDispatchState::Settled => {
            (record.stream_id.is_some()
                || record.call_digest_version == ProviderCallDigestVersion::V1)
                && record.settlement_digest.is_some()
                && record.pre_effect_rejection.is_none()
        }
        ProviderDispatchState::Uncertain => {
            record.pre_effect_rejection.is_none()
                && (record.settlement_digest.is_none() || record.stream_id.is_some())
        }
    }
}

fn decode_digest_version_sql(value: i64) -> rusqlite::Result<ProviderCallDigestVersion> {
    match value {
        1 => Ok(ProviderCallDigestVersion::V1),
        2 => Ok(ProviderCallDigestVersion::V2),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn decode_state(value: i64) -> rusqlite::Result<ProviderDispatchState> {
    match value {
        1 => Ok(ProviderDispatchState::Dispatching),
        2 => Ok(ProviderDispatchState::RejectedBeforeEffect),
        3 => Ok(ProviderDispatchState::Streaming),
        4 => Ok(ProviderDispatchState::TerminalPendingCommit),
        5 => Ok(ProviderDispatchState::Settled),
        6 => Ok(ProviderDispatchState::Uncertain),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

const fn encode_pre_effect_rejection(rejection: ProviderPreEffectRejection) -> i64 {
    match rejection {
        ProviderPreEffectRejection::CredentialUnavailable => 1,
        ProviderPreEffectRejection::CredentialAccessDenied => 2,
        ProviderPreEffectRejection::ProfileRejected => 3,
        ProviderPreEffectRejection::CapabilityDenied => 4,
        ProviderPreEffectRejection::BudgetDenied => 5,
        ProviderPreEffectRejection::AdmissionRejected => 6,
        ProviderPreEffectRejection::AdapterRejected => 7,
    }
}

fn decode_pre_effect_rejection(value: i64) -> rusqlite::Result<ProviderPreEffectRejection> {
    match value {
        1 => Ok(ProviderPreEffectRejection::CredentialUnavailable),
        2 => Ok(ProviderPreEffectRejection::CredentialAccessDenied),
        3 => Ok(ProviderPreEffectRejection::ProfileRejected),
        4 => Ok(ProviderPreEffectRejection::CapabilityDenied),
        5 => Ok(ProviderPreEffectRejection::BudgetDenied),
        6 => Ok(ProviderPreEffectRejection::AdmissionRejected),
        7 => Ok(ProviderPreEffectRejection::AdapterRejected),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
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
        ProviderDispatchState::RejectedBeforeEffect => {
            ProviderRepositoryState::RejectedBeforeEffect
        }
        ProviderDispatchState::Streaming => ProviderRepositoryState::Streaming,
        ProviderDispatchState::TerminalPendingCommit => {
            ProviderRepositoryState::TerminalPendingCommit
        }
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
        | ProviderStoreError::RejectionConflict
        | ProviderStoreError::SettlementBeforeStreaming
        | ProviderStoreError::SettlementBeforeTerminal
        | ProviderStoreError::AlreadyTerminal
        | ProviderStoreError::InvalidIdempotencyKey
        | ProviderStoreError::LegacyClaimDisabled => ProviderRepositoryError::Conflict,
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
