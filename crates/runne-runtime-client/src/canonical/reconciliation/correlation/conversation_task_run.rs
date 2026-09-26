use super::super::reconciliation_wire::{OutcomeWire, TextTerminalWire};
use super::super::{
    CommandReconciliationOutcome, CommandReconciliationWitness, ConversationCreated,
    RuntimeApiError, TaskRunCancellationAcknowledgement, TaskRunSubmitAcknowledgement,
    invalid_response,
};
use super::correlation_text;

pub(super) fn correlate_conversation(
    witness: &CommandReconciliationWitness,
    outcome: OutcomeWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    match (witness, outcome) {
        (
            CommandReconciliationWitness::CreateConversation {
                conversation_id,
                workspace_id,
            },
            OutcomeWire::CreateConversation {
                conversation_id: id,
                workspace_id: workspace,
                stream_version: 1,
                committed_at,
            },
        ) if *conversation_id == id && *workspace_id == workspace => Ok(
            CommandReconciliationOutcome::ConversationCreated(ConversationCreated {
                conversation_id: id,
                workspace_id: workspace,
                stream_version: 1,
                committed_at,
            }),
        ),
        (
            CommandReconciliationWitness::CreateTextOnlyConversation {
                conversation_id,
                workspace_id,
            },
            OutcomeWire::CreateConversation {
                conversation_id: id,
                workspace_id: workspace,
                stream_version: 1,
                committed_at,
            },
        ) if *conversation_id == id && *workspace_id == workspace => Ok(
            CommandReconciliationOutcome::ConversationCreated(ConversationCreated {
                conversation_id: id,
                workspace_id: workspace,
                stream_version: 1,
                committed_at,
            }),
        ),
        _ => Err(invalid_response()),
    }
}

pub(super) fn correlate_generation(
    witness: &CommandReconciliationWitness,
    outcome: OutcomeWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    match (witness, outcome) {
        (
            CommandReconciliationWitness::GenerateConversationText {
                conversation_id,
                expected_version,
                text,
            },
            OutcomeWire::GenerateConversationText {
                terminal,
                conversation_id: actual,
                task_run_id,
                attempt_id,
                conversation_stream_version,
                task_run_stream_version,
                user_message,
                assistant_message,
                reserved_assistant_message_id,
                reason,
            },
        ) => correlation_text::correlate_text(
            *conversation_id,
            *expected_version,
            text,
            TextTerminalWire {
                terminal,
                conversation_id: actual,
                task_run_id,
                attempt_id,
                conversation_stream_version,
                task_run_stream_version,
                user_message,
                assistant_message,
                reserved_assistant_message_id,
                reason,
            },
        ),
        _ => Err(invalid_response()),
    }
}

pub(super) fn correlate_task_run(
    witness: &CommandReconciliationWitness,
    outcome: OutcomeWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    match (witness, outcome) {
        (
            CommandReconciliationWitness::CancelTaskRun {
                task_run_id,
                expected_version,
            },
            OutcomeWire::CancelTaskRun {
                task_run_id: actual,
                new_version,
            },
        ) if *task_run_id == actual && expected_version.checked_add(1) == Some(new_version) => {
            Ok(CommandReconciliationOutcome::TaskRunCancellationRequested(
                TaskRunCancellationAcknowledgement::observed(actual, new_version),
            ))
        }
        (
            CommandReconciliationWitness::SubmitTaskRun { .. },
            OutcomeWire::SubmitTaskRun {
                task_run_id: actual,
                new_version: 2,
            },
        ) => Ok(CommandReconciliationOutcome::TaskRunSubmitted(
            TaskRunSubmitAcknowledgement::observed(actual, 2),
        )),
        _ => Err(invalid_response()),
    }
}
