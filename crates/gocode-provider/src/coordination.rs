use thiserror::Error;

use crate::{DispatchAttemptId, ProviderCallDigestVersion, ProviderCallId, ProviderStreamId};

/// Immutable provider prepare metadata persisted before dispatch claim.
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
    /// Claimed attempt was proved not to have crossed the adapter effect boundary.
    RejectedBeforeEffect,
    /// Adapter stream identity is durable.
    Streaming,
    /// Terminal provider evidence is durable and awaits authoritative completion.
    TerminalPendingCommit,
    /// Exact terminal settlement is durable.
    Settled,
    /// External effect disposition is ambiguous.
    Uncertain,
}

/// Closed reason proving a claimed provider attempt did not dispatch externally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPreEffectRejection {
    /// Required credential is not configured.
    CredentialUnavailable,
    /// Secure-store policy denied credential access.
    CredentialAccessDenied,
    /// Exact provider profile was unavailable or incompatible.
    ProfileRejected,
    /// Runtime capability or approval denied the effect.
    CapabilityDenied,
    /// Token or cost reservation denied the effect.
    BudgetDenied,
    /// Runtime admission rejected an invalid or stale binding before dispatch.
    AdmissionRejected,
    /// Adapter rejected validated local preparation before network start.
    AdapterRejected,
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
    /// Loads immutable prepare metadata to select an exact replay digest domain.
    fn load_prepared(
        &self,
        call_id: ProviderCallId,
    ) -> Result<Option<PreparedProviderRecord>, ProviderRepositoryError>;

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

    /// Commits an exact terminal rejection proved to precede external dispatch.
    fn mark_rejected_before_effect(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        rejection: ProviderPreEffectRejection,
    ) -> Result<(), ProviderRepositoryError>;

    /// Commits exact terminal evidence before authoritative completion.
    fn mark_terminal_pending(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError>;

    /// Commits exact terminal settlement evidence after stream binding.
    fn settle(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
        settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError>;

    /// Conservatively marks a claimed effect uncertain.
    fn mark_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderRepositoryError>;
}
