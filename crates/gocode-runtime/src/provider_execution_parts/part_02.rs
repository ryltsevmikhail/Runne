/// Typed runtime provider execution failure with no key/plaintext material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuntimeProviderExecutionError {
    /// Native secure-store key was absent or had a different binding.
    #[error("provider journal key is unavailable")]
    JournalKeyUnavailable,
    /// Secure-store backend cannot retain recovery key versions.
    #[error("provider journal key retention is unsupported")]
    KeyRetentionUnsupported,
    /// Ciphertext, AAD, sequence or normalized event bytes failed validation.
    #[error("provider journal recovery failed closed")]
    JournalCorrupt,
    /// Durable journal/outbox commit was unavailable.
    #[error("provider journal persistence is unavailable")]
    PersistenceUnavailable,
    /// Adapter stream polling failed before a new event was accepted.
    #[error("provider stream polling failed")]
    AdapterStreamUnavailable,
    /// Provider bytes arrived but their local commit could not be proven.
    #[error("provider journal commit was lost and the attempt is uncertain")]
    JournalCommitLost,
    /// Attempt generation/state no longer permits automatic progression.
    #[error("provider execution recovery is frozen")]
    RecoveryFrozen,
    /// Terminal usage/accounting/outbox transaction was rejected.
    #[error("provider terminal transaction was rejected")]
    TerminalRejected,
    /// Terminal output was prohibited or policy state was unavailable.
    #[error("provider terminal output was denied by policy")]
    PolicyDenied,
    /// Exact immutable pricing could not be resolved.
    #[error("provider terminal pricing is unavailable")]
    PricingUnavailable,
    /// Authoritative Conversation completion is temporarily unavailable.
    #[error("provider terminal application is unavailable")]
    ApplicationUnavailable,
    /// Authoritative Conversation completion conflicts with the outbox.
    #[error("provider terminal application conflicts")]
    ApplicationConflict,
}

/// Closed errors from authoritative terminal outbox application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderTerminalApplicationError {
    /// The application service is temporarily unavailable and may be retried.
    #[error("terminal application is unavailable")]
    Unavailable,
    /// The stable completion identity conflicts with authoritative state.
    #[error("terminal application conflicts")]
    Conflict,
}

/// Idempotent authoritative completion boundary for terminal provider output.
///
/// Implementations must use `record.application_idempotency_key` as the exact
/// command identity. A replay after application commit but before outbox
/// acknowledgement must return the original non-zero receipt digest.
pub trait ProviderTerminalOutboxApplication: Send + Sync {
    /// Applies one policy-approved plaintext output in runtime memory.
    fn complete_provider_terminal(
        &self,
        record: &ProviderTerminalOutboxRecord,
        output: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError>;
}

/// Closed failures while reconstructing one original canonical command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderTerminalConversationResolveError {
    /// Durable application state is temporarily unavailable.
    #[error("terminal conversation state is unavailable")]
    Unavailable,
    /// Durable identities or command evidence conflict.
    #[error("terminal conversation state conflicts")]
    Conflict,
}

/// Exact original command evidence required for idempotent Conversation finish.
#[derive(Debug, Clone)]
pub struct RecoveredProviderConversationCommand {
    /// Authenticated original command context.
    pub context: ApplicationCommandContext,
    /// Original user-message command.
    pub original: BeginConversationTextInput,
    /// Durable started (or exact already-terminal replay) receipt.
    pub started: TextGenerationReceipt,
}

/// Durable resolver for the original canonical Conversation command.
pub trait ProviderTerminalConversationResolver: Send + Sync {
    /// Reconstructs exact command evidence from authoritative application state.
    fn resolve_provider_terminal_conversation(
        &self,
        record: &ProviderTerminalOutboxRecord,
    ) -> Result<RecoveredProviderConversationCommand, ProviderTerminalConversationResolveError>;
}

/// Production terminal application through the existing Conversation service.
pub struct ConversationProviderTerminalApplication<R> {
    resolver: R,
    service: Arc<dyn ConversationTextCommandService>,
}

impl<R> ConversationProviderTerminalApplication<R> {
    /// Binds authoritative resolution and the existing idempotent finish service.
    pub fn new(resolver: R, service: Arc<dyn ConversationTextCommandService>) -> Self {
        Self { resolver, service }
    }
}

impl<R> ProviderTerminalOutboxApplication for ConversationProviderTerminalApplication<R>
where
    R: ProviderTerminalConversationResolver,
{
    fn complete_provider_terminal(
        &self,
        record: &ProviderTerminalOutboxRecord,
        output: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError> {
        let recovered = self
            .resolver
            .resolve_provider_terminal_conversation(record)
            .map_err(|error| match error {
                ProviderTerminalConversationResolveError::Unavailable => {
                    ProviderTerminalApplicationError::Unavailable
                }
                ProviderTerminalConversationResolveError::Conflict => {
                    ProviderTerminalApplicationError::Conflict
                }
            })?;
        if recovered.context.principal_id.0 != record.principal_id
            || recovered.started.conversation_id != record.conversation_id
            || recovered.started.taskrun_id != record.taskrun_id
            || recovered.started.attempt_id != record.execution_attempt_id
        {
            return Err(ProviderTerminalApplicationError::Conflict);
        }
        let text = std::str::from_utf8(output)
            .ok()
            .and_then(|text| MessageText::new(text.to_owned()).ok())
            .ok_or(ProviderTerminalApplicationError::Conflict)?;
        let receipt = self
            .service
            .finish_text(
                &recovered.context,
                FinishConversationTextInput {
                    original: recovered.original,
                    started: recovered.started,
                    completion: ConversationTextCompletion::AssistantText(text),
                },
            )
            .map_err(map_conversation_terminal_error)?;
        if receipt.phase != TextGenerationPhase::Completed
            || receipt.conversation_id != record.conversation_id
            || receipt.taskrun_id != record.taskrun_id
            || receipt.attempt_id != record.execution_attempt_id
        {
            return Err(ProviderTerminalApplicationError::Conflict);
        }
        Ok(conversation_receipt_digest(record, &receipt))
    }
}

fn map_conversation_terminal_error(
    error: ConversationTextServiceError,
) -> ProviderTerminalApplicationError {
    match error {
        ConversationTextServiceError::StoredDataUnavailable
        | ConversationTextServiceError::Commit(_) => ProviderTerminalApplicationError::Unavailable,
        ConversationTextServiceError::ProhibitedSecretMaterial
        | ConversationTextServiceError::ConversationNotFound
        | ConversationTextServiceError::Conflict
        | ConversationTextServiceError::ConversationDomain(_)
        | ConversationTextServiceError::TaskRunDomain
        | ConversationTextServiceError::IdGeneration(_)
        | ConversationTextServiceError::MaterializationFailed
        | ConversationTextServiceError::ReceiptMismatch => {
            ProviderTerminalApplicationError::Conflict
        }
    }
}

fn conversation_receipt_digest(
    record: &ProviderTerminalOutboxRecord,
    receipt: &TextGenerationReceipt,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_PROVIDER_CONVERSATION_RECEIPT_V1\0");
    hasher.update(record.outbox_id);
    hasher.update(record.settlement_digest);
    hasher.update(receipt.conversation_id.as_bytes());
    hasher.update(receipt.taskrun_id.as_bytes());
    hasher.update(receipt.attempt_id.as_bytes());
    hasher.update(receipt.user_message_id.as_bytes());
    hasher.update(receipt.assistant_message_id.as_bytes());
    hasher.update(receipt.conversation_version.to_be_bytes());
    hasher.update(receipt.taskrun_version.to_be_bytes());
    hasher.finalize().into()
}

/// Runtime service that owns journal keys, AEAD, pinned terminal policy and
/// commit-before-next-poll.
pub struct RuntimeProviderExecution<'a, K: ?Sized, S, P> {
    keyring: &'a K,
    store: &'a S,
    pricing: &'a P,
    prohibited_content: &'a dyn ProhibitedContentPort,
    redaction: &'a dyn ProviderEventRedaction,
    random: SystemRandom,
    active_key: Mutex<Option<ProviderJournalKeyBinding>>,
}

impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Constructs one service with immutable pricing and prohibited-content
    /// policy pinned for its full lifetime.
    pub fn new(
        keyring: &'a K,
        store: &'a S,
        pricing: &'a P,
        prohibited_content: &'a dyn ProhibitedContentPort,
        redaction: &'a dyn ProviderEventRedaction,
    ) -> Self {
        Self {
            keyring,
            store,
            pricing,
            prohibited_content,
            redaction,
            random: SystemRandom::new(),
            active_key: Mutex::new(None),
        }
    }

}
