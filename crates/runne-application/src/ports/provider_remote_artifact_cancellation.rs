/// Authenticated factual remote terminal state used only to close a durable
/// accepted cancellation. The store revalidates every field in its write tx.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProviderRemoteArtifactCancellationEvidence {
    dispatch_attempt_id: [u8; 16],
    artifact_digest: [u8; 32],
    terminal_disposition: crate::provider::ProviderRemoteTerminalDisposition,
    cancellation_command_id: [u8; 16],
    cancellation_event_id: [u8; 16],
    cancellation_taskrun_version: u64,
}

impl ProviderRemoteArtifactCancellationEvidence {
    /// Constructs the opaque evidence passed to the atomic cancellation UoW.
    #[must_use]
    pub fn new(
        dispatch_attempt_id: [u8; 16],
        artifact_digest: [u8; 32],
        terminal_disposition: crate::provider::ProviderRemoteTerminalDisposition,
        cancellation_command_id: [u8; 16],
        cancellation_event_id: [u8; 16],
        cancellation_taskrun_version: u64,
    ) -> Option<Self> {
        (dispatch_attempt_id != [0; 16]
            && artifact_digest != [0; 32]
            && cancellation_command_id != [0; 16]
            && cancellation_event_id != [0; 16]
            && cancellation_taskrun_version > 0)
            .then_some(Self {
                dispatch_attempt_id,
                artifact_digest,
                terminal_disposition,
                cancellation_command_id,
                cancellation_event_id,
                cancellation_taskrun_version,
            })
    }

    pub const fn dispatch_attempt_id(&self) -> &[u8; 16] {
        &self.dispatch_attempt_id
    }

    pub const fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }

    pub const fn terminal_disposition(&self) -> crate::provider::ProviderRemoteTerminalDisposition {
        self.terminal_disposition
    }

    pub const fn cancellation_command_id(&self) -> &[u8; 16] {
        &self.cancellation_command_id
    }

    pub const fn cancellation_event_id(&self) -> &[u8; 16] {
        &self.cancellation_event_id
    }

    pub const fn cancellation_taskrun_version(&self) -> u64 {
        self.cancellation_taskrun_version
    }
}

impl std::fmt::Debug for ProviderRemoteArtifactCancellationEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderRemoteArtifactCancellationEvidence")
            .field("terminal_disposition", &self.terminal_disposition)
            .field(
                "cancellation_taskrun_version",
                &self.cancellation_taskrun_version,
            )
            .finish_non_exhaustive()
    }
}

/// Atomic closure of a started text receipt after a saved remote fact and an
/// exact accepted cancellation are proven in one immediate transaction.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationAfterRemoteArtifactCancellationCommit {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub idempotency_scope: IdempotencyScope,
    pub command_fingerprint: CommandFingerprint,
    pub expected_conversation_version: u64,
    pub expected_started_taskrun_version: u64,
    pub evidence: ProviderRemoteArtifactCancellationEvidence,
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    pub receipt: TextGenerationReceipt,
}
