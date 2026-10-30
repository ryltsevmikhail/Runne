/// Atomic persistence boundary for conversation streams and create receipts.
pub trait ConversationRepository {
    /// Lists an ordered bounded page owned by the exact principal and workspace.
    /// The extra 101st item allows transport adapters to detect continuation.
    fn list_conversations(
        &self,
        _principal: &PrincipalId,
        _workspace: WorkspaceId,
        _limit: u16,
        _after: Option<ConversationId>,
    ) -> Result<Vec<(ConversationId, ConversationLoadedStream)>, EventStoreError> {
        Err(EventStoreError::Unavailable)
    }

    /// Loads a committed conversation stream.
    fn load_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<ConversationLoadedStream, EventStoreError>;

    /// Looks up the durable result of a create-conversation command.
    /// A duplicate requires the exact command ID, scope, idempotency key, and
    /// semantic fingerprint (which binds the delivery-context
    /// `context_scope`); changing any field is a conflict. Receipts stored by
    /// older fingerprint formats stay exact replays when the durable
    /// context-scope marker agrees with `context_scope`.
    fn lookup_conversation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
        context_scope: runne_domain::conversation::ConversationContextScope,
    ) -> Result<ConversationReceiptLookup, CommitError>;

    /// Atomically rechecks the full command identity, appends conversation
    /// events, and stores their create receipt.
    fn commit_conversation(
        &self,
        payload: ConversationCommit,
    ) -> Result<ConversationCommitResult, CommitError>;
}

/// Atomic persistence boundary for coordinated Conversation text execution.
pub trait ConversationTextRepository {
    /// Looks up the durable phase of an idempotent text-generation command.
    fn lookup_text_generation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<TextGenerationReceiptLookup, CommitError>;

    /// Confirms that a rejected v6 receipt is the exact no-provider-admission
    /// cancellation proof, including continued absence of linked effects.
    /// Adapters that do not persist this proof fail closed by returning `false`.
    fn validate_no_admission_cancellation_receipt(
        &self,
        _receipt: &TextGenerationReceipt,
    ) -> Result<bool, CommitError> {
        Ok(false)
    }

    /// Confirms an exact terminal receipt produced by the shared D2 cancellation writer.
    fn validate_d2_tool_loop_cancellation_receipt(
        &self,
        _receipt: &TextGenerationReceipt,
        _evidence: D2ToolLoopCancellationEvidence,
    ) -> Result<bool, CommitError> {
        Ok(false)
    }

    /// Looks up a claimed receipt while validating its immutable claim tuple.
    fn lookup_claimed_text_generation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
        assignment: &TaskRunAssignmentIdentity,
        claim_version: u64,
    ) -> Result<TextGenerationReceiptLookup, CommitError> {
        let _ = (assignment, claim_version);
        self.lookup_text_generation_receipt(
            command_id,
            idempotency_key,
            idempotency_scope,
            fingerprint,
        )
    }

    /// Atomically appends the user message, starts its TaskRun, and stores a
    /// `Started` receipt before provider execution.
    fn begin_text_generation(
        &self,
        payload: BeginTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError>;

    /// Atomically appends only the user message to an already claimed run.
    /// Implementations without this boundary fail closed for compatibility.
    fn begin_claimed_text_generation(
        &self,
        _payload: BeginClaimedTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    }

    /// Atomically appends assistant output, completes its TaskRun, and advances
    /// the original receipt to `Completed`.
    fn finish_text_generation(
        &self,
        payload: FinishTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError>;

    /// Atomically releases the generation, fails its TaskRun, and advances the
    /// original receipt to `Rejected` without an assistant message.
    fn reject_text_generation(
        &self,
        payload: RejectTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError>;

    /// Atomically closes a started receipt without output when a winning
    /// cancellation follows an exact durable provider terminal settlement.
    fn reject_text_generation_after_terminal_cancellation(
        &self,
        _payload: RejectTextGenerationAfterTerminalCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    }

    /// Atomically closes a started receipt from an authenticated Source1 fact.
    /// This proof carries no financial settlement or Known disposition.
    fn reject_text_generation_after_unknown_terminal_cancellation(
        &self,
        _payload: RejectTextGenerationAfterUnknownTerminalCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    }

    /// Atomically closes a started receipt from an authenticated RemoteArtifact
    /// plus exact accepted-cancellation witness. Legacy journal proofs remain
    /// on `reject_text_generation_after_terminal_cancellation`.
    fn reject_text_generation_after_remote_artifact_cancellation(
        &self,
        _payload: RejectTextGenerationAfterRemoteArtifactCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    }

    /// Atomically closes a started receipt after an exact durable pre-effect rejection.
    fn reject_text_generation_after_pre_effect_cancellation(
        &self,
        _payload: RejectTextGenerationAfterPreEffectCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    }

    /// Atomically closes a started text attempt when cancellation won before
    /// any provider admission. Implementations must prove the exact no-effect history.
    fn reject_text_generation_after_no_admission_cancellation(
        &self,
        _payload: RejectTextGenerationAfterNoAdmissionCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    }

    /// D2 cancellation through the shared atomic terminal writer after the
    /// store verifies all exact invocation stop/no-start evidence.
    fn reject_text_generation_after_d2_tool_loop_cancellation(
        &self,
        _payload: RejectTextGenerationAfterD2ToolLoopCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    }

    /// Atomically rejects a pre-cycle D2 restart only after proving the exact
    /// assignment and absence of native tool invocation evidence.
    fn reject_text_generation_after_d2_tool_loop_restart(
        &self,
        _payload: RejectTextGenerationAfterD2ToolLoopRestartCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        Err(CommitError::StorageFailure(StorageFailureKind::Unavailable))
    }
}

/// A committed conversation stream.
#[derive(Debug, Clone)]
pub struct ConversationLoadedStream {
    /// Events ordered by their contiguous stream sequence.
    pub events: Vec<EventEnvelope<ConversationEvent>>,
    /// Last committed stream sequence, or zero for an empty stream.
    pub current_version: u64,
    /// Last committed event identity, if any.
    pub last_event_id: Option<EventId>,
}

/// Durable result of a create-conversation command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationReceipt {
    /// Conversation created by the command.
    pub conversation_id: ConversationId,
    /// Workspace recorded by the creation event.
    pub workspace_id: WorkspaceId,
    /// Resulting stream version.
    pub new_version: u64,
    /// Persistence-authoritative commit timestamp.
    pub committed_at: Timestamp,
}

/// Result of a conversation receipt lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationReceiptLookup {
    /// No matching receipt exists.
    Miss,
    /// The exact command was committed previously.
    Duplicate {
        /// Original durable result.
        stored_result: ConversationReceipt,
    },
}

/// Atomic conversation event and receipt commit payload.
#[derive(Debug, Clone)]
pub struct ConversationCommit {
    /// Unique command identity.
    pub command_id: CommandId,
    /// Client-provided idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Full uniqueness scope for the key.
    pub idempotency_scope: IdempotencyScope,
    /// Deterministic semantic command fingerprint.
    pub command_fingerprint: CommandFingerprint,
    /// Expected conversation stream version.
    pub expected_version: u64,
    /// Conversation events to append.
    pub events: Vec<UncommittedEvent<ConversationEvent>>,
    /// Workspace expected in the creation event and receipt.
    pub workspace_id: WorkspaceId,
    /// Durable delivery-context marker recorded with the creation event.
    pub context_scope: runne_domain::conversation::ConversationContextScope,
}

/// Result of an atomic conversation commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationCommitResult {
    /// Events and receipt were committed.
    Committed {
        /// Durable create result.
        result: ConversationReceipt,
    },
    /// The exact command was committed previously.
    Duplicate {
        /// Original durable create result.
        stored_result: ConversationReceipt,
    },
}
