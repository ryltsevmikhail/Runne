/// Reconstructed canonical command for a remote terminal with no publishable
/// output. The source store revalidates the artifact and generation at commit.
#[derive(Debug, Clone)]
pub struct RecoveredProviderNoOutputCommand {
    pub context: runne_application::ports::ApplicationCommandContext,
    pub original: runne_application::commands::BeginConversationTextInput,
    pub started: runne_application::ports::TextGenerationReceipt,
    pub disposition: RecoveredProviderNoOutputDisposition,
}

/// Closed workflow action for an authenticated no-output remote fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredProviderNoOutputDisposition {
    Failure(runne_domain::conversation::GenerationFailureReason),
    Cancellation(runne_application::ports::ProviderRemoteArtifactCancellationEvidence),
}

/// Application boundary for authenticated remote terminal facts without an
/// output outbox. Implementations must be idempotent by exact source attempt.
pub trait ProviderRemoteNoOutputApplication: Send + Sync {
    fn apply_remote_terminal_without_output(
        &self,
        attempt_id: runne_provider::DispatchAttemptId,
    ) -> Result<bool, ProviderTerminalApplicationError>;
}

impl<R> ProviderRemoteNoOutputApplication for ConversationProviderTerminalApplication<R>
where
    R: ProviderTerminalConversationResolver,
{
    fn apply_remote_terminal_without_output(
        &self,
        attempt_id: runne_provider::DispatchAttemptId,
    ) -> Result<bool, ProviderTerminalApplicationError> {
        let Some(recovered) = self
            .resolver
            .resolve_remote_terminal_without_output(attempt_id)
            .map_err(map_terminal_resolve_error)?
        else {
            return Ok(false);
        };
        if recovered.started.phase != TextGenerationPhase::Started {
            return Err(ProviderTerminalApplicationError::Conflict);
        }
        let completion = match recovered.disposition {
            RecoveredProviderNoOutputDisposition::Failure(reason) => {
                runne_application::commands::ConversationTextCompletion::Rejected { reason }
            }
            RecoveredProviderNoOutputDisposition::Cancellation(evidence) => {
                runne_application::commands::ConversationTextCompletion::RemoteArtifactSettledCancellation { evidence }
            }
        };
        self.service
            .finish_text(
                &recovered.context,
                runne_application::commands::FinishConversationTextInput {
                    started: recovered.started,
                    original: recovered.original,
                    completion,
                },
            )
            .map_err(|error| match error {
                runne_application::conversation_text_service::ConversationTextServiceError::Conflict
                | runne_application::conversation_text_service::ConversationTextServiceError::ReceiptMismatch => ProviderTerminalApplicationError::Conflict,
                _ => ProviderTerminalApplicationError::Unavailable,
            })?;
        Ok(true)
    }
}

fn map_terminal_resolve_error(
    error: ProviderTerminalConversationResolveError,
) -> ProviderTerminalApplicationError {
    match error {
        ProviderTerminalConversationResolveError::Deferred => {
            ProviderTerminalApplicationError::Deferred
        }
        ProviderTerminalConversationResolveError::Unavailable => {
            ProviderTerminalApplicationError::Unavailable
        }
        ProviderTerminalConversationResolveError::Conflict => {
            ProviderTerminalApplicationError::Conflict
        }
    }
}

impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Applies a source-bound authenticated terminal fact that has no output
    /// outbox. A missing candidate is an idempotent no-op; the application
    /// resolver distinguishes active closure from audit-only history.
    pub fn apply_remote_terminal_without_output<A: ProviderRemoteNoOutputApplication>(
        &self,
        attempt_id: DispatchAttemptId,
        application: &A,
    ) -> Result<bool, RuntimeProviderExecutionError> {
        application
            .apply_remote_terminal_without_output(attempt_id)
            .map_err(|error| match error {
                ProviderTerminalApplicationError::Deferred => {
                    RuntimeProviderExecutionError::RecoveryFrozen
                }
                ProviderTerminalApplicationError::Unavailable => {
                    RuntimeProviderExecutionError::ApplicationUnavailable
                }
                ProviderTerminalApplicationError::Conflict => {
                    RuntimeProviderExecutionError::ApplicationConflict
                }
            })
    }
}
