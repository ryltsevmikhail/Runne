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
    /// Returns the active non-secret journal-key binding without key bytes.
    fn active_journal_key_binding(
        &self,
    ) -> Result<Option<ProviderJournalKeyBinding>, ProviderExecutionError> {
        Err(ProviderExecutionError::StoreUnavailable)
    }

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
