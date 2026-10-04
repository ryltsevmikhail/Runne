/// Typed runtime provider execution failure with no key/plaintext material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuntimeProviderExecutionError {
    /// Native runne-secure-store key was absent or had a different binding.
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
    /// The TaskRun has an exact pending cancellation successor; retain the
    /// sealed terminal output until cancellation can be authoritatively settled.
    #[error("terminal application is deferred by pending cancellation")]
    Deferred,
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

    /// Settles an exact durable provider terminal only from the independent
    /// cancellation scanner or boot recovery path. Foreground completion
    /// always uses `complete_provider_terminal`.
    fn complete_provider_terminal_cancellation(
        &self,
        _record: &ProviderTerminalOutboxRecord,
        _output: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError> {
        Err(ProviderTerminalApplicationError::Deferred)
    }
}

/// Closed failures while reconstructing one original canonical command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderTerminalConversationResolveError {
    /// A valid cancellation is pending; terminal output must remain sealed.
    #[error("terminal conversation application is deferred by pending cancellation")]
    Deferred,
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
    /// Exact cancellation successor, present only for a proved terminal cleanup.
    pub terminal_cancellation: Option<RecoveredProviderTerminalCancellation>,
    /// The source fact is authentic but no longer owns the current writer or
    /// generation. Acknowledging it must not append Conversation/TaskRun events.
    pub audit_only: bool,
}

/// Closed source-bound cancellation evidence returned by the durable resolver.
#[derive(Debug, Clone, Copy)]
pub enum RecoveredProviderTerminalCancellation {
    /// Legacy terminal facts authenticated by the StreamJournal path.
    StreamJournal(runne_application::ports::ProviderTerminalCancellationEvidence),
    /// Source1 Unknown fact and exact accepted cancellation, without finance.
    UnknownJournal(
        runne_application::ports::ProviderUnknownTerminalCancellationEvidence,
    ),
    /// Remote artifact plus exact accepted cancellation, revalidated at commit.
    RemoteArtifact(runne_application::ports::ProviderRemoteArtifactCancellationEvidence),
}

/// Durable resolver for the original canonical Conversation command.
pub trait ProviderTerminalConversationResolver: Send + Sync {
    /// Reconstructs exact command evidence from authoritative application state.
    fn resolve_provider_terminal_conversation(
        &self,
        record: &ProviderTerminalOutboxRecord,
    ) -> Result<RecoveredProviderConversationCommand, ProviderTerminalConversationResolveError>;

    /// Reconstructs the original command from a source-bound no-outbox fact.
    fn resolve_remote_terminal_without_output(
        &self,
        _attempt_id: runne_provider::DispatchAttemptId,
    ) -> Result<Option<RecoveredProviderNoOutputCommand>, ProviderTerminalConversationResolveError>
    {
        Ok(None)
    }
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
        self.complete_inner(record, output, false)
    }

    fn complete_provider_terminal_cancellation(
        &self,
        record: &ProviderTerminalOutboxRecord,
        output: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError> {
        self.complete_inner(record, output, true)
    }
}

impl<R> ConversationProviderTerminalApplication<R>
where
    R: ProviderTerminalConversationResolver,
{
    fn complete_inner(
        &self,
        record: &ProviderTerminalOutboxRecord,
        output: &[u8],
        cancellation_owner: bool,
    ) -> Result<[u8; 32], ProviderTerminalApplicationError> {
        let recovered = self
            .resolver
            .resolve_provider_terminal_conversation(record)
            .map_err(|error| match error {
                ProviderTerminalConversationResolveError::Unavailable => {
                    ProviderTerminalApplicationError::Unavailable
                }
                ProviderTerminalConversationResolveError::Deferred => {
                    ProviderTerminalApplicationError::Deferred
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
        if recovered.audit_only {
            return match record.source {
                runne_application::provider::ProviderTerminalOutboxSource::RemoteArtifact { .. } => {
                    Ok(remote_artifact_audit_receipt_digest(record))
                }
                runne_application::provider::ProviderTerminalOutboxSource::UnknownJournal { .. } => {
                    Ok(unknown_journal_audit_receipt_digest(record))
                }
                runne_application::provider::ProviderTerminalOutboxSource::StreamJournal => {
                    Err(ProviderTerminalApplicationError::Conflict)
                }
            };
        }
        let cancellation_pending = recovered.terminal_cancellation.is_some()
            && recovered.started.phase == TextGenerationPhase::Started;
        let remote_artifact_cancellation = matches!(
            &recovered.terminal_cancellation,
            Some(RecoveredProviderTerminalCancellation::RemoteArtifact(_))
        );
        if cancellation_pending != cancellation_owner {
            return Err(ProviderTerminalApplicationError::Deferred);
        }
        let completion = match (&record.source, recovered.terminal_cancellation) {
            (
                runne_application::provider::ProviderTerminalOutboxSource::StreamJournal,
                Some(RecoveredProviderTerminalCancellation::StreamJournal(evidence)),
            ) => {
                runne_application::commands::ConversationTextCompletion::TerminalSettledCancellation {
                    evidence,
                }
            }
            (
                runne_application::provider::ProviderTerminalOutboxSource::UnknownJournal { .. },
                Some(RecoveredProviderTerminalCancellation::UnknownJournal(evidence)),
            ) => runne_application::commands::ConversationTextCompletion::UnknownJournalSettledCancellation {
                evidence,
            },
            (
                runne_application::provider::ProviderTerminalOutboxSource::RemoteArtifact { .. },
                Some(RecoveredProviderTerminalCancellation::RemoteArtifact(evidence)),
            ) => runne_application::commands::ConversationTextCompletion::RemoteArtifactSettledCancellation {
                evidence,
            },
            (_, None) => {
                let text = std::str::from_utf8(output)
                    .ok()
                    .and_then(|text| MessageText::new(text.to_owned()).ok())
                    .ok_or(ProviderTerminalApplicationError::Conflict)?;
                runne_application::commands::ConversationTextCompletion::AssistantText(text)
            }
            _ => return Err(ProviderTerminalApplicationError::Conflict),
        };
        let receipt = self
            .service
            .finish_text(
                &recovered.context,
                FinishConversationTextInput {
                    original: recovered.original,
                    started: recovered.started,
                    completion,
                },
            )
            .map_err(map_conversation_terminal_error)?;
        if (recovered.terminal_cancellation.is_none()
            && receipt.phase != TextGenerationPhase::Completed)
            || (recovered.terminal_cancellation.is_some()
                && receipt.phase != TextGenerationPhase::Rejected)
            || receipt.conversation_id != record.conversation_id
            || receipt.taskrun_id != record.taskrun_id
            || receipt.attempt_id != record.execution_attempt_id
        {
            return Err(ProviderTerminalApplicationError::Conflict);
        }
        if remote_artifact_cancellation {
            Ok(remote_artifact_audit_receipt_digest(record))
        } else {
            Ok(conversation_receipt_digest(record, &receipt))
        }
    }
}

include!("part_02_terminal_helpers.rs");
