use core::fmt;

use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{DispatchAttemptId, ProviderCallDigestVersion};
use thiserror::Error;

/// Non-secret runne-secure-store binding for one provider journal key.
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
