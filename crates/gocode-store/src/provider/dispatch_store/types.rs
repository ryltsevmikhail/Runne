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
