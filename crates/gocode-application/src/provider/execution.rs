use core::fmt;

use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchAttemptId, PreparedProviderRecord, ProviderCall, ProviderCallDigestVersion,
};
use thiserror::Error;

use super::{ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderCoordinatorRequest};

impl ProviderCoordinatorRequest {
    pub(crate) fn authority_request(
        &self,
        prepared: PreparedProviderRecord,
    ) -> Result<ProviderAuthorityIssueRequest, ProviderAdmissionError> {
        let requested_output_tokens = u64::from(self.requested_output_tokens);
        if self.requested_output_tokens != self.call.max_output_tokens() {
            return Err(ProviderAdmissionError::InvalidSemanticContext);
        }
        let request = ProviderAuthorityIssueRequest {
            principal_id: self.principal_id.clone(),
            conversation_id: self.conversation_id,
            taskrun_id: self.taskrun_id,
            execution_attempt_id: self.execution_attempt_id,
            prepared,
            pricing_revision_digest: self.pricing_revision_digest,
            requested_input_tokens: self.requested_input_tokens,
            requested_output_tokens,
            max_cost_micros: self.max_cost_micros,
            currency: self.currency.clone(),
            provider_idempotency_key: self.provider_idempotency_key.clone(),
        };
        request.validate()?;
        Ok(request)
    }
}

pub(crate) fn validate_issued_claim(
    call: &ProviderCall,
    issue: &ProviderAuthorityIssueRequest,
    claim: &gocode_provider::ProviderDispatchClaim,
) -> Result<(), ProviderAdmissionError> {
    if claim.call_id != call.call_id()
        || claim.prepared_digest != issue.prepared.prepared_digest
        || claim.render_digest != issue.prepared.render_digest
        || claim.profile_digest != issue.prepared.profile_digest
        || claim.provider_idempotency_key != issue.provider_idempotency_key
    {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(())
}

/// Non-secret secure-store binding for one provider journal key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderJournalKeyBinding {
    key_id: [u8; 16],
    key_version: u64,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
}

impl ProviderJournalKeyBinding {
    /// Constructs an exact authority/generation-bound key reference.
    pub fn new(
        key_id: [u8; 16],
        key_version: u64,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
    ) -> Result<Self, ProviderExecutionError> {
        if key_id == [0; 16]
            || key_version == 0
            || runtime_authority_id == [0; 16]
            || database_generation == 0
        {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        Ok(Self {
            key_id,
            key_version,
            runtime_authority_id,
            database_generation,
        })
    }

    /// Returns the non-secret key identity.
    pub const fn key_id(self) -> [u8; 16] {
        self.key_id
    }

    /// Returns the positive key version.
    pub const fn key_version(self) -> u64 {
        self.key_version
    }

    /// Returns the bound runtime authority.
    pub const fn runtime_authority_id(self) -> [u8; 16] {
        self.runtime_authority_id
    }

    /// Returns the bound database generation.
    pub const fn database_generation(self) -> u64 {
        self.database_generation
    }
}

/// AEAD ciphertext and non-secret integrity metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderEncryptedPayload {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    plaintext_len: u64,
    plaintext_digest: [u8; 32],
}

impl ProviderEncryptedPayload {
    /// Constructs bounded encrypted payload metadata.
    pub fn new(
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
        plaintext_len: u64,
        plaintext_digest: [u8; 32],
    ) -> Result<Self, ProviderExecutionError> {
        let expected_ciphertext_len = usize::try_from(plaintext_len)
            .ok()
            .and_then(|length| length.checked_add(16));
        if nonce == [0; 12]
            || !(16..=4_194_304).contains(&ciphertext.len())
            || expected_ciphertext_len != Some(ciphertext.len())
            || plaintext_digest == [0; 32]
        {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        Ok(Self {
            nonce,
            ciphertext,
            plaintext_len,
            plaintext_digest,
        })
    }

    /// Returns the unique AEAD nonce.
    pub const fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Returns ciphertext including the AEAD tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the authenticated plaintext byte length.
    pub const fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// Returns the authenticated plaintext digest.
    pub const fn plaintext_digest(&self) -> &[u8; 32] {
        &self.plaintext_digest
    }
}

impl fmt::Debug for ProviderEncryptedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderEncryptedPayload")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

/// One encrypted normalized provider stream event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderJournalAppendRequest {
    /// Durable provider dispatch attempt.
    pub attempt_id: DispatchAttemptId,
    /// Current runtime-issued fencing token.
    pub fencing_token: u64,
    /// Exact contiguous event sequence.
    pub sequence: u64,
    /// Closed normalized event-kind code.
    pub event_kind: u8,
    /// Whether this is a normalized terminal event.
    pub terminal: bool,
    /// Call digest domain used by the prepared request.
    pub call_digest_version: ProviderCallDigestVersion,
    /// Exact provider profile digest.
    pub profile_digest: [u8; 32],
    /// Runtime generation bound into AEAD AAD.
    pub runtime_generation: u64,
    /// Exact journal key reference.
    pub key: ProviderJournalKeyBinding,
    /// Ciphertext and integrity metadata.
    pub encrypted: ProviderEncryptedPayload,
}

/// Durable marker opened before one provider stream poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderPollRequest {
    /// Durable provider dispatch attempt.
    pub attempt_id: DispatchAttemptId,
    /// Current runtime-issued fencing token.
    pub fencing_token: u64,
    /// Exact cursor that the adapter will poll.
    pub cursor: u64,
    /// Exact provider profile digest.
    pub profile_digest: [u8; 32],
    /// Current runtime generation.
    pub runtime_generation: u64,
}

/// Idempotent encrypted journal append result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderJournalAppendOutcome {
    /// New ciphertext was committed.
    Inserted,
    /// Exact ciphertext replay was observed.
    Replayed,
}

/// Store-derived immutable pricing binding for one admitted attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTerminalPricingBinding {
    pricing_revision_digest: [u8; 32],
    currency: String,
    reserved_input_tokens: u64,
    reserved_output_tokens: u64,
    reserved_cost_micros: u64,
}

impl ProviderTerminalPricingBinding {
    /// Constructs the exact pricing and worst-case reservation binding loaded
    /// from authoritative admission state.
    pub fn with_reservation(
        pricing_revision_digest: [u8; 32],
        currency: String,
        reserved_input_tokens: u64,
        reserved_output_tokens: u64,
        reserved_cost_micros: u64,
    ) -> Result<Self, ProviderExecutionError> {
        if pricing_revision_digest == [0; 32]
            || currency.len() != 3
            || !currency.bytes().all(|byte| byte.is_ascii_uppercase())
            || reserved_output_tokens == 0
            || reserved_cost_micros == 0
            || reserved_input_tokens
                .checked_add(reserved_output_tokens)
                .is_none()
        {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        Ok(Self {
            pricing_revision_digest,
            currency,
            reserved_input_tokens,
            reserved_output_tokens,
            reserved_cost_micros,
        })
    }

    /// Returns the exact immutable pricing revision.
    pub const fn pricing_revision_digest(&self) -> &[u8; 32] {
        &self.pricing_revision_digest
    }

    /// Returns the reservation currency.
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Returns the admitted worst-case input-token reservation.
    pub const fn reserved_input_tokens(&self) -> u64 {
        self.reserved_input_tokens
    }

    /// Returns the admitted worst-case output-token reservation.
    pub const fn reserved_output_tokens(&self) -> u64 {
        self.reserved_output_tokens
    }

    /// Returns the admitted worst-case cost reservation in micro-units.
    pub const fn reserved_cost_micros(&self) -> u64 {
        self.reserved_cost_micros
    }
}

/// Idempotent terminal commit result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderTerminalCommitOutcome {
    /// New terminal transaction was committed.
    Committed,
    /// Exact terminal transaction replay was observed.
    Replayed,
}

/// Durable encrypted terminal outbox projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTerminalOutboxRecord {
    /// Stable outbox identity.
    pub outbox_id: [u8; 16],
    /// Owning provider attempt.
    pub attempt_id: DispatchAttemptId,
    /// Runtime-issued fence that owns the provider attempt.
    pub fencing_token: u64,
    /// Authenticated principal bound at runtime admission.
    pub principal_id: String,
    /// Authoritative Conversation receiving the completion.
    pub conversation_id: ConversationId,
    /// Authoritative TaskRun owning the effect.
    pub taskrun_id: TaskRunId,
    /// Runtime execution attempt bound to the provider dispatch.
    pub execution_attempt_id: AttemptId,
    /// Terminal journal sequence.
    pub terminal_sequence: u64,
    /// Exact prepared call digest domain.
    pub call_digest_version: ProviderCallDigestVersion,
    /// Exact key reference.
    pub key: ProviderJournalKeyBinding,
    /// Encrypted recoverable output.
    pub encrypted_output: ProviderEncryptedPayload,
    /// Exact runtime generation.
    pub runtime_generation: u64,
    /// Exact profile digest.
    pub profile_digest: [u8; 32],
    /// Exact settlement digest.
    pub settlement_digest: [u8; 32],
    /// Stable Conversation completion key.
    pub application_idempotency_key: String,
}

/// Provider stream recovery and outbox store failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderExecutionError {
    /// Native journal key is absent or has the wrong authority/generation.
    #[error("provider journal key is unavailable")]
    JournalKeyUnavailable,
    /// AEAD metadata, ciphertext, sequence or durable journal data is corrupt.
    #[error("provider journal is corrupt")]
    JournalCorrupt,
    /// A nonce was reused within a key version.
    #[error("provider journal nonce was reused")]
    NonceReuse,
    /// Event sequence is not the exact next durable sequence.
    #[error("provider journal sequence mismatch")]
    SequenceMismatch,
    /// Runtime generation/fence no longer owns the attempt.
    #[error("provider execution generation is stale")]
    StaleGeneration,
    /// Attempt is already uncertain and may not progress automatically.
    #[error("provider execution is uncertain")]
    AttemptUncertain,
    /// No exact durable poll marker authorizes this new event append.
    #[error("provider poll was not durably armed")]
    PollNotArmed,
    /// Terminal evidence or replay differs from the durable transaction.
    #[error("provider terminal transaction conflicts")]
    TerminalConflict,
    /// Usage or charge exceeds the exact durable reservations.
    #[error("provider settlement exceeds its reservation")]
    ReservationMismatch,
    /// Outbox receipt differs from a durable application.
    #[error("provider terminal outbox conflicts")]
    OutboxConflict,
    /// Durable provider execution repository is unavailable.
    #[error("provider execution repository is unavailable")]
    StoreUnavailable,
}

/// Durable encrypted provider journal and terminal outbox port.
pub trait ProviderExecutionStore: Send + Sync {
    /// Activates a new key reference and retires the previous active reference.
    fn activate_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError>;

    /// Counts journal/outbox references to one key version.
    fn journal_key_reference_count(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError>;

    /// Removes retired key metadata only after reference count reaches zero.
    fn remove_retired_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError>;

    /// Opens an exact cursor-bound marker before calling the provider.
    fn begin_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError>;

    /// Commits one encrypted event before the next adapter poll.
    fn append_encrypted_event(
        &self,
        request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError>;

    /// Loads exact encrypted events for recovery/decryption.
    fn load_encrypted_events(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError>;

    /// Loads exact pricing revision/currency from authoritative admission.
    fn load_terminal_pricing_binding(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError>;

    /// Loads pending encrypted terminal outbox records.
    fn pending_terminal_outbox(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError>;

    /// Applies an exact authoritative Conversation completion receipt.
    fn acknowledge_terminal_outbox(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), ProviderExecutionError>;

    /// Freezes an attempt after a possible unjournaled external byte/effect.
    fn mark_execution_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderExecutionError>;
}
