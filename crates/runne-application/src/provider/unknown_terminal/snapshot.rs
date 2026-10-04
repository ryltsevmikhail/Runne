use core::fmt;
use sha2::{Digest, Sha256};

use super::*;

/// Original V26 committed-effect MAC fields copied from one store snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderUnknownCommittedEffectFields {
    /// Original issuance MAC included in the committed-effect proof.
    pub issuance_mac: [u8; 32],
    /// Original dispatch identity.
    pub attempt_id: [u8; 16],
    /// Original admitted provider identity.
    pub provider_id: String,
    /// Original runtime launch generation.
    pub launch_generation: u64,
    /// Credential lifecycle revision at effect start.
    pub lifecycle_revision: u64,
    /// Credential lifecycle fence at effect start.
    pub credential_fence: u64,
    /// Active credential version at effect start.
    pub credential_version: u64,
    /// Active credential reference digest at effect start.
    pub credential_ref_digest: [u8; 32],
    /// Historical credential lease owner.
    pub lease_owner: [u8; 16],
    /// Historical credential lease expiry.
    pub lease_expires_at: i64,
    /// Historical credential lease fencing token.
    pub lease_fence: u64,
    /// Original effect start timestamp.
    pub effect_started_at: i64,
    /// Original effect expiry timestamp.
    pub effect_expires_at: i64,
}

/// Non-secret retained V26 proof data for the original committed effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderUnknownCommittedEffectProof {
    /// Exact retained journal-key binding used by the original proof.
    pub binding: ProviderJournalKeyBinding,
    /// Original committed-effect MAC fields.
    pub fields: ProviderUnknownCommittedEffectFields,
    /// Original committed-effect MAC.
    pub mac: [u8; 32],
}

impl ProviderUnknownCommittedEffectProof {
    /// Stable digest for binding the original effect proof into the Unknown receipt.
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"GOCODE_PROVIDER_UNKNOWN_ORIGINAL_EFFECT_V1\0");
        hash.update(self.binding.key_id());
        hash.update(self.binding.key_version().to_be_bytes());
        hash.update(self.binding.runtime_authority_id());
        hash.update(self.binding.database_generation().to_be_bytes());
        frame(&mut hash, &self.fields.issuance_mac);
        frame(&mut hash, &self.fields.attempt_id);
        frame(&mut hash, self.fields.provider_id.as_bytes());
        hash.update(self.fields.launch_generation.to_be_bytes());
        hash.update(self.fields.lifecycle_revision.to_be_bytes());
        hash.update(self.fields.credential_fence.to_be_bytes());
        hash.update(self.fields.credential_version.to_be_bytes());
        frame(&mut hash, &self.fields.credential_ref_digest);
        frame(&mut hash, &self.fields.lease_owner);
        hash.update(self.fields.lease_expires_at.to_be_bytes());
        hash.update(self.fields.lease_fence.to_be_bytes());
        hash.update(self.fields.effect_started_at.to_be_bytes());
        hash.update(self.fields.effect_expires_at.to_be_bytes());
        hash.update(self.mac);
        hash.finalize().into()
    }
}

fn frame(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

/// Immutable data copied by persistence from its single immediate transaction.
///
/// The source binding is strongly typed and canonically encoded by runtime;
/// the encrypted journal is supplied separately for AEAD-chain validation.
#[derive(Clone)]
pub struct ProviderUnknownTerminalSnapshot {
    selector: ProviderTerminalUnknownSelector,
    context: ProviderEventJournalContext,
    original: ProviderUnknownTerminalOriginalBinding,
    original_effect: ProviderUnknownCommittedEffectProof,
    current: ProviderUnknownTerminalCurrentFacts,
    journal: Vec<ProviderJournalAppendRequest>,
}

impl ProviderUnknownTerminalSnapshot {
    /// Builds a snapshot only from rows read by one persistence transaction.
    #[doc(hidden)]
    pub fn from_store_transaction(
        selector: ProviderTerminalUnknownSelector,
        context: ProviderEventJournalContext,
        original: ProviderUnknownTerminalOriginalBinding,
        original_effect: ProviderUnknownCommittedEffectProof,
        current: ProviderUnknownTerminalCurrentFacts,
        journal: Vec<ProviderJournalAppendRequest>,
    ) -> Result<Self, ProviderExecutionError> {
        if selector.attempt_id != context.attempt_id
            || selector.fencing_token != context.fencing_token
            || original.dispatch_attempt_id != context.attempt_id
            || original.fencing_token != context.fencing_token
            || original.runtime_generation != context.runtime_generation
            || original.runtime_generation == 0
            || original.fencing_token == 0
            || original.profile_digest != context.profile_digest
            || original.profile_digest == [0; 32]
            || original.call_digest_version != context.call_digest_version
            || selector.terminal_sequence == 0
            || original.database_generation == 0
            || original.runtime_authority_id == [0; 16]
            || original.writer_owner_id.is_empty()
            || original.writer_lease_digest == [0; 32]
            || original.authority_revision == 0
            || original.principal_id.is_empty()
            || original.provider_id.is_empty()
            || original.provider_idempotency_key.is_empty()
            || original.admission_currency.is_empty()
            || original.request_digest == [0; 32]
            || original.begin_receipt_digest == [0; 32]
            || original.started_receipt_digest == [0; 32]
            || original.admission_digest == [0; 32]
            || original.pricing_revision_digest == [0; 32]
            || original.taskrun_history_digest == [0; 32]
            || original.conversation_history_digest == [0; 32]
            || original.committed_effect_digest != original_effect.digest()
            || original_effect.fields.attempt_id != *context.attempt_id.as_bytes()
            || original_effect.fields.provider_id != original.provider_id
            || original_effect.binding.runtime_authority_id() != original.runtime_authority_id
            || original_effect.binding.database_generation() != original.database_generation
            || original_effect.mac == [0; 32]
            || original.taskrun_stream_version == 0
            || original.conversation_stream_version == 0
            || original.reservations[0].reservation_id == [0; 16]
            || original.reservations[1].reservation_id == [0; 16]
            || original.reservations[0].reservation_id == original.reservations[1].reservation_id
            || original.reservations[0].dimension != 1
            || original.reservations[1].dimension != 2
            || original
                .reservations
                .iter()
                .any(|reserve| !reserve.held || reserve.settled_amount.is_some())
            || current.current_source_state_digest == [0; 32]
            || current.existing_unknown_reason.is_some()
                != current.existing_unknown_commitment.is_some()
            || current.existing_outbox_id.is_some()
                != current.existing_application_idempotency_key.is_some()
            || (current.existing_outbox_id.is_some() && current.existing_completed_output.is_none())
            || journal.is_empty()
            || !journal.iter().any(|record| {
                record.sequence == selector.terminal_sequence
                    && record.terminal
                    && record.attempt_id == selector.attempt_id
                    && record.fencing_token == selector.fencing_token
            })
        {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        Ok(Self {
            selector,
            context,
            original,
            original_effect,
            current,
            journal,
        })
    }

    /// Returns the exact attempt/sequence selector copied by persistence.
    pub const fn selector(&self) -> ProviderTerminalUnknownSelector {
        self.selector
    }

    /// Returns the non-secret normalized stream context.
    pub const fn context(&self) -> ProviderEventJournalContext {
        self.context
    }

    /// Returns the immutable original admission and history pins.
    pub const fn original(&self) -> &ProviderUnknownTerminalOriginalBinding {
        &self.original
    }

    /// Returns the exact original V26 committed-effect proof copied by the store.
    pub const fn original_effect(&self) -> &ProviderUnknownCommittedEffectProof {
        &self.original_effect
    }

    /// Returns mutable current-source facts captured in the same transaction.
    pub const fn current(&self) -> &ProviderUnknownTerminalCurrentFacts {
        &self.current
    }

    /// Returns encrypted journal records copied by the same transaction.
    pub fn journal(&self) -> &[ProviderJournalAppendRequest] {
        &self.journal
    }
}

impl fmt::Debug for ProviderUnknownTerminalSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderUnknownTerminalSnapshot")
            .field("journal_records", &self.journal.len())
            .field("source_binding", &"<redacted>")
            .finish()
    }
}

/// Authenticated factual Unknown journal result, independent of remote IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderUnknownTerminalFact {
    /// Exact factual stream disposition.
    pub disposition: ProviderTerminalDisposition,
    /// Exact provider usage, if the terminal carried it.
    pub usage: Option<ProviderUsage>,
    /// Digest of the authenticated Completed output, when present.
    pub output_digest: Option<[u8; 32]>,
    /// Whether the immutable source recorded an application outbox.
    pub output_was_published: bool,
    /// Whether the caller's transaction validated an application ACK.
    pub output_was_applied: bool,
}

/// Runtime keyring callback for authenticating source1 terminal evidence.
pub trait ProviderUnknownTerminalFactAuthenticator: Send + Sync {
    /// Authenticates the journal, AEAD output and immutable Unknown receipt.
    fn authenticate_unknown_terminal(
        &self,
        snapshot: &ProviderUnknownTerminalSnapshot,
    ) -> Result<ProviderUnknownTerminalFact, ProviderExecutionError>;
}
