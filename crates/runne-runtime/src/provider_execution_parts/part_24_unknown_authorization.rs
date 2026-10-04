/// Runtime-authenticated factual terminal authorization; contains no price or charge.
pub struct ProviderUnknownTerminalAuthorization {
    attempt_id: DispatchAttemptId,
    terminal_sequence: u64,
    reason: ProviderUnknownAccountingReason,
    disposition: ProviderTerminalDisposition,
    usage: Option<ProviderUsage>,
    encrypted_output: Option<ProviderEncryptedPayload>,
    /// Stable encryption identity, also used if the completed fact is audit-only.
    outbox_id: [u8; 16],
    /// Published output identity; absent for audit-only completed facts.
    published_outbox_id: Option<[u8; 16]>,
    /// Published application identity; absent for audit-only completed facts.
    application_idempotency_key: Option<String>,
    journal_digest: [u8; 32],
    source_binding_digest: [u8; 32],
    commitment: [u8; 32],
}

impl ProviderUnknownTerminalAuthorization {
    /// The authenticated provider attempt.
    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.attempt_id
    }
    /// The selected factual terminal status.
    pub const fn disposition(&self) -> ProviderTerminalDisposition {
        self.disposition
    }
    /// The terminal event sequence authenticated by the runtime.
    pub const fn terminal_sequence(&self) -> u64 {
        self.terminal_sequence
    }
    /// The exact usage fact; `None` means the provider supplied no usage.
    pub const fn usage(&self) -> Option<ProviderUsage> {
        self.usage
    }
    /// The closed accounting-unknown reason.
    pub const fn reason(&self) -> ProviderUnknownAccountingReason {
        self.reason
    }
    /// The sealed output, present only for factual Completed terminals.
    pub const fn encrypted_output(&self) -> Option<&ProviderEncryptedPayload> {
        self.encrypted_output.as_ref()
    }
    /// The stable runtime-derived output identity.
    pub const fn outbox_id(&self) -> &[u8; 16] {
        &self.outbox_id
    }
    /// Published outbox identity, absent when cancellation/audit withheld output.
    pub const fn published_outbox_id(&self) -> Option<&[u8; 16]> {
        self.published_outbox_id.as_ref()
    }
    /// Stable application command identity, absent when output was withheld.
    pub fn application_idempotency_key(&self) -> Option<&str> {
        self.application_idempotency_key.as_deref()
    }
    /// Digest of the complete immutable encrypted journal snapshot.
    pub const fn journal_digest(&self) -> &[u8; 32] {
        &self.journal_digest
    }
    /// Digest of the canonical original source and reservation binding.
    pub const fn source_binding_digest(&self) -> &[u8; 32] {
        &self.source_binding_digest
    }
    /// Domain-separated authentication of all transaction and terminal fields.
    pub const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
}

impl fmt::Debug for ProviderUnknownTerminalAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderUnknownTerminalAuthorization")
            .field("terminal_sequence", &self.terminal_sequence)
            .field("reason", &self.reason)
            .field("disposition", &self.disposition)
            .field("usage_present", &self.usage.is_some())
            .field("has_output", &self.encrypted_output.is_some())
            .finish_non_exhaustive()
    }
}

mod unknown_auth_private {
    pub trait Sealed {}
}

/// Sealed callback invoked by persistence while its immutable transaction is open.
/// Implementations receive no database handle and must not re-enter persistence.
/// A persistence adapter supporting Unknown writes must also implement replay,
/// compare this authorization with the stored commitment, and reuse its stored
/// ciphertext before it can continue through the legacy Known path.
pub trait ProviderUnknownTerminalAuthenticator: unknown_auth_private::Sealed + Send + Sync {
    /// Authenticates the complete same-transaction snapshot and returns a sealed fact.
    fn authenticate(
        &self,
        snapshot: &ProviderUnknownTerminalSnapshot,
    ) -> Result<ProviderUnknownTerminalAuthorization, ProviderExecutionError>;
}
