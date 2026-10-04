type ConversationDrafts =
    Vec<runne_domain::event::DomainEventDraft<runne_domain::conversation::ConversationEvent>>;
type TaskRunDrafts =
    Vec<runne_domain::event::DomainEventDraft<runne_domain::task_run::TaskRunEvent>>;
type TerminalDraftsResult =
    Result<(TextGenerationPhase, ConversationDrafts, TaskRunDrafts), ConversationTextServiceError>;

fn terminal_drafts(
    completion: ConversationTextCompletion,
    receipt: &TextGenerationReceipt,
    conversation: &Conversation,
    taskrun: &TaskRun,
) -> TerminalDraftsResult {
    let failed_reason = runne_domain::conversation::GenerationFailureReason::Cancelled;
    let failed = |phase, reason| {
        let conversation_drafts = conversation
            .decide(runne_domain::command::ConversationCommand::FailGeneration {
                taskrun_id: receipt.taskrun_id,
                attempt_id: receipt.attempt_id,
                reason,
            })
            .map_err(ConversationTextServiceError::ConversationDomain)?;
        let taskrun_drafts = taskrun
            .decide(TaskRunCommand::FailGeneration { reason })
            .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
        Ok((phase, conversation_drafts, taskrun_drafts))
    };
    match completion {
        ConversationTextCompletion::AssistantText(assistant_text) => {
            let conversation_drafts = conversation
                .decide(
                    runne_domain::command::ConversationCommand::AppendAssistantMessage {
                        message_id: receipt.assistant_message_id,
                        taskrun_id: receipt.taskrun_id,
                        attempt_id: receipt.attempt_id,
                        text: assistant_text,
                    },
                )
                .map_err(ConversationTextServiceError::ConversationDomain)?;
            let taskrun_drafts = taskrun
                .decide(TaskRunCommand::Complete {
                    result: TerminalResult::Success,
                })
                .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
            Ok((
                TextGenerationPhase::Completed,
                conversation_drafts,
                taskrun_drafts,
            ))
        }
        ConversationTextCompletion::PreEffectRejectedCancellation { .. }
        | ConversationTextCompletion::TerminalSettledCancellation { .. }
        | ConversationTextCompletion::UnknownJournalSettledCancellation { .. }
        | ConversationTextCompletion::RemoteArtifactSettledCancellation { .. }
        | ConversationTextCompletion::NoProviderAdmissionCancellation { .. } => {
            let conversation_drafts = conversation
                .decide(runne_domain::command::ConversationCommand::FailGeneration {
                    taskrun_id: receipt.taskrun_id,
                    attempt_id: receipt.attempt_id,
                    reason: failed_reason,
                })
                .map_err(ConversationTextServiceError::ConversationDomain)?;
            let taskrun_drafts = taskrun
                .decide(TaskRunCommand::CompleteCancellation)
                .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
            Ok((
                TextGenerationPhase::Rejected,
                conversation_drafts,
                taskrun_drafts,
            ))
        }
        ConversationTextCompletion::ProhibitedInputRejected { reason } => {
            failed(TextGenerationPhase::ProhibitedInputRejected, reason)
        }
        ConversationTextCompletion::Rejected { reason } => {
            failed(TextGenerationPhase::Rejected, reason)
        }
    }
}
