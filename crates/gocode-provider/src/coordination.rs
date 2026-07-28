use thiserror::Error;

use crate::{DispatchAttemptId, ProviderCallId, ProviderStreamId};

/// Immutable provider prepare metadata persisted before dispatch claim.
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

/// Runtime-neutral atomic provider dispatch claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDispatchClaim {
    /// Owning provider call.
    pub call_id: ProviderCallId,
    /// Durable dispatch attempt.
    pub attempt_id: DispatchAttemptId,
    /// Winner-only single-use permit identity.
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

/// Repository-visible provider dispatch state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRepositoryState {
    /// Dispatch claim exists.
    Dispatching,
    /// Adapter stream identity is durable.
    Streaming,
    /// Exact terminal settlement is durable.
    Settled,
    /// External effect disposition is ambiguous.
    Uncertain,
}

/// Result of one atomic provider repository claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderRepositoryClaimOutcome {
    /// Compare-and-swap winner receives the single-use permit.
    Winner {
        /// Permit bound to the exact claim.
        permit_id: [u8; 16],
    },
    /// Exact replay receives state but no permit.
    Existing {
        /// Existing attempt identity.
        attempt_id: DispatchAttemptId,
        /// Existing state.
        state: ProviderRepositoryState,
    },
}

/// Runtime-neutral repository failure disposition.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderRepositoryError {
    /// Persistence is unavailable.
    #[error("provider repository is unavailable")]
    Unavailable,
    /// Durable state is corrupt.
    #[error("provider repository contains corrupt data")]
    CorruptData,
    /// Identity was reused with different semantic input.
    #[error("provider repository identity conflict")]
    Conflict,
    /// Claim evidence does not match prepared evidence.
    #[error("provider claim does not match prepared evidence")]
    PreparedMismatch,
    /// Fencing token is stale.
    #[error("provider repository fencing token is stale")]
    StaleFencingToken,
}

/// Persistence boundary consumed by application provider orchestration.
pub trait ProviderDispatchRepository: Send + Sync {
    /// Persists or exactly replays immutable prepare metadata.
    fn persist_prepared(
        &self,
        record: &PreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError>;

    /// Atomically claims dispatch and returns a permit only to the winner.
    fn claim(
        &self,
        claim: &ProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError>;

    /// Binds the normalized stream after adapter dispatch acknowledgement.
    fn mark_streaming(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        stream_id: ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError>;

    /// Conservatively marks a claimed effect uncertain.
    fn mark_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderRepositoryError>;
}
