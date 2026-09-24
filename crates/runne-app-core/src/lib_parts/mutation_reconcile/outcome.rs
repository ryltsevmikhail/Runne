use runne_local_store::{CanonicalMutationOutcome as LedgerOutcome, GenerationAssistant};
use runne_runtime_client::{
    CommandReconciliationOutcome as Outcome, ConversationGenerationFailureReason,
    ConversationMessageRole,
};

pub(crate) fn reconciliation_outcome_to_ledger(
    command: &runne_local_store::NormalizedMutationCommand,
    outcome: &Outcome,
) -> Result<LedgerOutcome, AppCoreError> {
    let value = match outcome {
        Outcome::ConversationTextCompleted(_)
        | Outcome::ConversationTextRejected(_)
        | Outcome::ConversationTextProhibitedInputRejected(_) => generation_outcome(outcome)?,
        Outcome::ProjectCreated(value) => LedgerOutcome::ProjectCreate {
            project_id: reconciliation_ledger_id(value.project_id())?,
            new_version: value.new_version(),
        },
        Outcome::ProjectRenamed(value) => LedgerOutcome::ProjectRename {
            project_id: reconciliation_ledger_id(value.project_id())?,
            new_version: value.new_version(),
        },
        Outcome::ProjectArchived(value) => LedgerOutcome::ProjectArchive {
            project_id: reconciliation_ledger_id(value.project_id())?,
            new_version: value.new_version(),
        },
        Outcome::ProjectDeleted(value) => LedgerOutcome::ProjectDelete {
            project_id: reconciliation_ledger_id(value.project_id())?,
            new_version: value.new_version(),
        },
        Outcome::WorkspaceCreated(value) => LedgerOutcome::WorkspaceCreate {
            workspace_id: reconciliation_ledger_id(value.workspace_id())?,
            new_version: value.new_version(),
        },
        Outcome::WorkspaceRootBound(value) => LedgerOutcome::WorkspaceBindRoot {
            workspace_id: reconciliation_ledger_id(value.workspace_id())?,
            new_version: value.new_version(),
        },
        Outcome::WorkspaceOpened(value) => LedgerOutcome::WorkspaceOpen {
            workspace_id: reconciliation_ledger_id(value.workspace_id())?,
            new_version: value.new_version(),
        },
        Outcome::ConversationCreated(value) => LedgerOutcome::ConversationCreate {
            conversation_id: reconciliation_ledger_id(value.conversation_id)?,
            workspace_id: reconciliation_ledger_id(value.workspace_id)?,
            stream_version: value.stream_version,
            committed_at: value.committed_at,
        },
        Outcome::TaskRunCancellationRequested(value) => {
            LedgerOutcome::TaskRunCancellationRequested {
                task_run_id: reconciliation_ledger_id(value.task_run_id())?,
                new_version: value.stream_version(),
            }
        }
        Outcome::TaskRunSubmitted(value) => LedgerOutcome::TaskRunSubmitted {
            task_run_id: reconciliation_ledger_id(value.task_run_id())?,
            new_version: value.stream_version(),
        },
        Outcome::ApprovalDecision(value) => LedgerOutcome::ApprovalRespond {
            approval_id: reconciliation_ledger_id(value.approval_id())?,
            new_version: value.new_version(),
            state: match value.state() {
                runne_runtime_client::ApprovalStateDto::Approved => {
                    runne_local_store::ApprovalOutcomeState::Approved
                }
                runne_runtime_client::ApprovalStateDto::Denied => {
                    runne_local_store::ApprovalOutcomeState::Denied
                }
                runne_runtime_client::ApprovalStateDto::Expired => {
                    runne_local_store::ApprovalOutcomeState::Expired
                }
                runne_runtime_client::ApprovalStateDto::Cancelled => {
                    runne_local_store::ApprovalOutcomeState::Cancelled
                }
                runne_runtime_client::ApprovalStateDto::Pending => {
                    return Err(AppCoreError::MutationUnavailable);
                }
            },
        },
    };
    value
        .correlates_to_command(command)
        .then_some(value)
        .ok_or(AppCoreError::MutationUnavailable)
}

fn generation_outcome(outcome: &Outcome) -> Result<LedgerOutcome, AppCoreError> {
    use runne_local_store::{GenerationFailureReason, GenerationTerminal};
    match outcome {
        Outcome::ConversationTextCompleted(value) => Ok(LedgerOutcome::Generation {
            terminal: GenerationTerminal::Completed,
            conversation_id: reconciliation_ledger_id(value.conversation_id)?,
            task_run_id: reconciliation_ledger_id(value.task_run_id)?,
            attempt_id: reconciliation_ledger_id(value.attempt_id)?,
            conversation_stream_version: value.conversation_stream_version,
            task_run_stream_version: value.task_run_stream_version,
            user_message: ledger_message(&value.user_message)?,
            assistant: Box::new(GenerationAssistant::Completed(ledger_message(
                &value.assistant_message,
            )?)),
        }),
        Outcome::ConversationTextRejected(value)
        | Outcome::ConversationTextProhibitedInputRejected(value) => {
            Ok(LedgerOutcome::Generation {
                terminal: if matches!(outcome, Outcome::ConversationTextRejected(_)) {
                    GenerationTerminal::Rejected
                } else {
                    GenerationTerminal::Prohibited
                },
                conversation_id: reconciliation_ledger_id(value.conversation_id)?,
                task_run_id: reconciliation_ledger_id(value.task_run_id)?,
                attempt_id: reconciliation_ledger_id(value.attempt_id)?,
                conversation_stream_version: value.conversation_stream_version,
                task_run_stream_version: value.task_run_stream_version,
                user_message: ledger_message(&value.user_message)?,
                assistant: Box::new(GenerationAssistant::Rejected {
                    reserved_message_id: reconciliation_ledger_id(value.reserved_assistant_message_id)?,
                    reason: match value.reason {
                        ConversationGenerationFailureReason::ProviderOutputRejected => {
                            GenerationFailureReason::ProviderOutputRejected
                        }
                    },
                }),
            })
        }
        _ => Err(AppCoreError::MutationUnavailable),
    }
}

fn reconciliation_ledger_id(
    value: CanonicalId,
) -> Result<runne_local_store::BoundedCanonicalId, AppCoreError> {
    runne_local_store::BoundedCanonicalId::parse(value.to_string().as_bytes())
        .map_err(|_| AppCoreError::MutationUnavailable)
}

fn ledger_message(
    value: &runne_runtime_client::ConversationMessage,
) -> Result<runne_local_store::LedgerMessage, AppCoreError> {
    Ok(runne_local_store::LedgerMessage {
        message_id: reconciliation_ledger_id(value.message_id)?,
        role: match value.role {
            ConversationMessageRole::User => runne_local_store::MessageRole::User,
            ConversationMessageRole::Assistant => runne_local_store::MessageRole::Assistant,
        },
        task_run_id: reconciliation_ledger_id(value.task_run_id)?,
        attempt_id: reconciliation_ledger_id(value.attempt_id)?,
        text: value.text.clone(),
        committed_at: value.committed_at,
    })
}
