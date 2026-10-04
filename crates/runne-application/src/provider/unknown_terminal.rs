use crate::provider::ProviderJournalKeyBinding;
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{
    DispatchAttemptId, ProviderCallDigestVersion, ProviderTerminalDisposition, ProviderUsage,
};

use super::{ProviderEncryptedPayload, ProviderExecutionError, ProviderJournalAppendRequest};

/// Exact non-secret binding for one normalized provider stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderEventJournalContext {
    /// Durable provider dispatch attempt.
    pub attempt_id: DispatchAttemptId,
    /// Current runtime-issued fencing token.
    pub fencing_token: u64,
    /// Exact prepared call digest contract.
    pub call_digest_version: ProviderCallDigestVersion,
    /// Exact immutable provider profile.
    pub profile_digest: [u8; 32],
    /// Current runtime generation.
    pub runtime_generation: u64,
}

/// Stable reason why a factual terminal cannot become a known financial settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderUnknownAccountingReason {
    /// The provider terminal carried no usage object.
    UsageUnavailable,
    /// Exact usage exists, but the pinned price revision was unavailable.
    PricingUnavailable,
    /// Exact usage exists, but the pinned pricer rejected its quote.
    PricingInvalid,
    /// Exact usage was priced in a currency different from the admitted currency.
    CurrencyMismatch,
}

/// Opaque selector for one runtime-authenticated Unknown terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderTerminalUnknownSelector {
    attempt_id: DispatchAttemptId,
    terminal_sequence: u64,
    fencing_token: u64,
}

impl ProviderTerminalUnknownSelector {
    #[doc(hidden)]
    pub const fn new(
        attempt_id: DispatchAttemptId,
        terminal_sequence: u64,
        fencing_token: u64,
    ) -> Self {
        Self {
            attempt_id,
            terminal_sequence,
            fencing_token,
        }
    }

    /// Returns the selected provider attempt.
    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.attempt_id
    }
    /// Returns the selected terminal journal sequence.
    pub const fn terminal_sequence(&self) -> u64 {
        self.terminal_sequence
    }
    /// Returns the original runtime-issued fence.
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }
}

/// Provider execution state captured together with the source rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderUnknownSourceState {
    /// The attempt remains active before terminal application.
    Running,
    /// The factual provider response completed.
    Completed,
    /// The factual provider response failed.
    Failed,
    /// The factual provider response was incomplete.
    Incomplete,
    /// The local TaskRun cancellation workflow is active.
    Cancelling,
    /// The local TaskRun cancellation workflow is closed.
    Cancelled,
}

/// One exact reservation row copied from the same transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderUnknownReservationSnapshot {
    /// Original immutable reservation identity.
    pub reservation_id: [u8; 16],
    /// Canonical persisted dimension: token usage is 1 and cost is 2.
    pub dimension: u8,
    /// Original admitted amount.
    pub reserved_amount: u64,
    /// Previously settled amount; Unknown does not invent a new amount.
    pub settled_amount: Option<u64>,
    /// Whether the reservation is still held by the source attempt.
    pub held: bool,
}

/// Immutable original identity and reservation pins retained by a v63 receipt.
#[derive(Clone)]
pub struct ProviderUnknownTerminalOriginalBinding {
    /// Exact admitted runtime authority.
    pub runtime_authority_id: [u8; 16],
    /// Original writer identity from the admission transaction.
    pub writer_owner_id: String,
    /// Digest of the original admission's owner/fence commitment. This is not
    /// an independent historical lease witness.
    pub writer_lease_digest: [u8; 32],
    /// Original authority revision admitted for this request.
    pub authority_revision: u64,
    /// Original capability/grant binding, if the route requires a grant.
    pub grant_digest: Option<[u8; 32]>,
    /// Exact database generation.
    pub database_generation: u64,
    /// Exact runtime generation and fence from source admission.
    pub runtime_generation: u64,
    /// Exact dispatch attempt selected by the durable provider rows.
    pub dispatch_attempt_id: DispatchAttemptId,
    /// Canonical TaskRun identity.
    pub taskrun_id: TaskRunId,
    /// Canonical execution attempt identity.
    pub execution_attempt_id: AttemptId,
    /// Canonical Conversation identity.
    pub conversation_id: ConversationId,
    /// Original authenticated principal.
    pub principal_id: String,
    /// Exact provider identity selected by the immutable profile.
    pub provider_id: String,
    /// Original provider idempotency key, not a remote response id.
    pub provider_idempotency_key: String,
    /// Canonical request digest and original admission/profile pins.
    pub request_digest: [u8; 32],
    /// Original Begin command receipt digest.
    pub begin_receipt_digest: [u8; 32],
    /// Original Started receipt digest.
    pub started_receipt_digest: [u8; 32],
    /// Original claim receipt digest when this path has a claim.
    pub claim_receipt_digest: Option<[u8; 32]>,
    /// Original exact admission digest.
    pub admission_digest: [u8; 32],
    /// Digest of the original verified V26 committed-effect proof.
    pub committed_effect_digest: [u8; 32],
    /// Original validated TaskRun history digest through Started.
    pub taskrun_history_digest: [u8; 32],
    /// Original validated Conversation history digest through Started.
    pub conversation_history_digest: [u8; 32],
    /// Original TaskRun stream version at Started.
    pub taskrun_stream_version: u64,
    /// Original Conversation stream version at Started.
    pub conversation_stream_version: u64,
    /// Exact immutable profile and pricing pins.
    pub profile_digest: [u8; 32],
    /// Exact admitted pricing revision.
    pub pricing_revision_digest: [u8; 32],
    /// Currency pinned by the original admission/reservations.
    pub admission_currency: String,
    /// Exact call digest contract.
    pub call_digest_version: ProviderCallDigestVersion,
    /// Original admitted writer fence.
    pub fencing_token: u64,
    /// Whether the original writer allowed output publication.
    pub publication_allowed: bool,
    /// Both original reservation rows, in canonical dimension order.
    pub reservations: [ProviderUnknownReservationSnapshot; 2],
}

/// Mutable same-transaction facts used to validate the requested transition.
/// These facts are deliberately excluded from the immutable receipt MAC so a
/// later ACK, cancellation, or valid writer-head advance cannot rewrite history.
#[derive(Clone)]
pub struct ProviderUnknownTerminalCurrentFacts {
    /// Current source, authority, grant, output, and ACK state digest.
    pub current_source_state_digest: [u8; 32],
    /// Current TaskRun stream version from the same read transaction.
    pub taskrun_stream_version: u64,
    /// Current Conversation stream version from the same read transaction.
    pub conversation_stream_version: u64,
    /// Exact current authority revision and grant digest/state.
    pub authority_revision: u64,
    /// Digest of the exact durable grant row, if this provider uses one.
    pub grant_digest: Option<[u8; 32]>,
    /// Whether that exact grant remains active in the snapshot.
    pub grant_active: bool,
    /// Current source status; it does not change the factual journal status.
    pub source_state: ProviderUnknownSourceState,
    /// Whether the captured current TaskRun still authorizes publication for
    /// this exact execution attempt.
    pub output_publication_allowed: bool,
    /// Existing outbox and application ACK digests, when present.
    pub existing_outbox_digest: Option<[u8; 32]>,
    /// Stable existing outbox identity, present with its encrypted output.
    pub existing_outbox_id: Option<[u8; 16]>,
    /// Original publication command identity, present only when an outbox was published.
    pub existing_application_idempotency_key: Option<String>,
    /// Existing authoritative application receipt digest, when present.
    pub existing_application_ack_digest: Option<[u8; 32]>,
    /// Stored Unknown reason, present only for idempotent historical replay.
    pub existing_unknown_reason: Option<ProviderUnknownAccountingReason>,
    /// Exact historical usage retained by an existing Unknown receipt.
    pub existing_unknown_usage: Option<ProviderUsage>,
    /// Factual disposition retained by an existing Unknown receipt.
    pub existing_unknown_disposition: Option<ProviderTerminalDisposition>,
    /// Stored immutable Unknown receipt MAC, present only on replay.
    pub existing_unknown_commitment: Option<[u8; 32]>,
    /// Existing Completed ciphertext reused exactly on replay.
    pub existing_completed_output: Option<ProviderEncryptedPayload>,
}

mod snapshot;
pub use snapshot::{
    ProviderUnknownCommittedEffectFields, ProviderUnknownCommittedEffectProof,
    ProviderUnknownTerminalFact, ProviderUnknownTerminalFactAuthenticator,
    ProviderUnknownTerminalSnapshot,
};
