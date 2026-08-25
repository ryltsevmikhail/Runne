use super::{
    ApprovalDecisionDto, CanonicalId, CommandReconciliationOutcome, CommandReconciliationWitness,
    ConversationCreated, ConversationGenerationFailureReason, ConversationMessage,
    ConversationMessageRole, ConversationTextRejection, ConversationTextResult,
    ProjectCommandAcknowledgement, RuntimeApiError, TaskRunCancellationAcknowledgement,
    WorkspaceCommandAcknowledgement, ApprovalDecisionAcknowledgementDto, ApprovalStateDto,
    invalid_response, validate_message_text,
};
use super::reconciliation_wire::{
    FailureReasonWire, MessageRoleWire, MessageWire, OutcomeWire, TextTerminalKind,
    TextTerminalWire, ApprovalStateWire,
};

pub(super) fn correlate(
    witness: &CommandReconciliationWitness,
    outcome: OutcomeWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    let next = |value: u64| value.checked_add(1).ok_or_else(invalid_response);
    match (witness, outcome) {
        (CommandReconciliationWitness::CreateProject { project_id, .. }, OutcomeWire::CreateProject { project_id: id, new_version: 1 }) if *project_id == id => Ok(CommandReconciliationOutcome::ProjectCreated(ProjectCommandAcknowledgement::observed(id, 1))),
        (CommandReconciliationWitness::ArchiveProject { project_id, expected_version }, OutcomeWire::ArchiveProject { project_id: id, new_version }) if *project_id == id && next(*expected_version)? == new_version => Ok(CommandReconciliationOutcome::ProjectArchived(ProjectCommandAcknowledgement::observed(id, new_version))),
        (CommandReconciliationWitness::DeleteProject { project_id, expected_version }, OutcomeWire::DeleteProject { project_id: id, new_version }) if *project_id == id && next(*expected_version)? == new_version => Ok(CommandReconciliationOutcome::ProjectDeleted(ProjectCommandAcknowledgement::observed(id, new_version))),
        (CommandReconciliationWitness::CreateWorkspace { workspace_id, .. }, OutcomeWire::CreateWorkspace { workspace_id: id, new_version: 1 }) if *workspace_id == id => Ok(CommandReconciliationOutcome::WorkspaceCreated(WorkspaceCommandAcknowledgement::observed(id, 1))),
        (CommandReconciliationWitness::BindWorkspaceRoot { workspace_id, expected_version, .. }, OutcomeWire::BindWorkspaceRoot { workspace_id: id, new_version }) if *workspace_id == id && next(*expected_version)? == new_version => Ok(CommandReconciliationOutcome::WorkspaceRootBound(WorkspaceCommandAcknowledgement::observed(id, new_version))),
        (CommandReconciliationWitness::OpenWorkspace { workspace_id, expected_version }, OutcomeWire::OpenWorkspace { workspace_id: id, new_version }) if *workspace_id == id && next(*expected_version)? == new_version => Ok(CommandReconciliationOutcome::WorkspaceOpened(WorkspaceCommandAcknowledgement::observed(id, new_version))),
        (CommandReconciliationWitness::CreateConversation { conversation_id, workspace_id }, OutcomeWire::CreateConversation { conversation_id: id, workspace_id: workspace, stream_version: 1, committed_at }) if *conversation_id == id && *workspace_id == workspace => Ok(CommandReconciliationOutcome::ConversationCreated(ConversationCreated { conversation_id: id, workspace_id: workspace, stream_version: 1, committed_at })),
        (CommandReconciliationWitness::GenerateConversationText { conversation_id, expected_version, text }, OutcomeWire::GenerateConversationText { terminal, conversation_id: actual, task_run_id, attempt_id, conversation_stream_version, task_run_stream_version, user_message, assistant_message, reserved_assistant_message_id, reason }) => correlate_text(*conversation_id, *expected_version, text, TextTerminalWire { terminal, conversation_id: actual, task_run_id, attempt_id, conversation_stream_version, task_run_stream_version, user_message, assistant_message, reserved_assistant_message_id, reason }),
        (CommandReconciliationWitness::CancelTaskRun { task_run_id, expected_version }, OutcomeWire::CancelTaskRun { task_run_id: actual, new_version }) if *task_run_id == actual && expected_version.checked_add(1) == Some(new_version) => Ok(CommandReconciliationOutcome::TaskRunCancellationRequested(TaskRunCancellationAcknowledgement::observed(actual, new_version))),
        (CommandReconciliationWitness::ApprovalDecision { approval_id, expected_version, decision, .. }, OutcomeWire::ApprovalDecision { approval_id: actual, new_version, task_run_id, state }) if *approval_id == actual && expected_version.checked_add(1) == Some(new_version) && decision_state_matches(*decision, state) => Ok(CommandReconciliationOutcome::ApprovalDecision(ApprovalDecisionAcknowledgementDto::observed(actual, task_run_id, new_version, approval_state(state)) .map_err(|_| invalid_response())?)),
        _ => Err(invalid_response()),
    }
}

const fn decision_state_matches(
    expected: ApprovalDecisionDto,
    observed: ApprovalStateWire,
) -> bool {
    matches!(
        (expected, observed),
        (ApprovalDecisionDto::Approve, ApprovalStateWire::Approved)
            | (ApprovalDecisionDto::Deny, ApprovalStateWire::Denied)
    )
}

const fn approval_state(value: ApprovalStateWire) -> ApprovalStateDto {
    match value {
        ApprovalStateWire::Approved => ApprovalStateDto::Approved,
        ApprovalStateWire::Denied => ApprovalStateDto::Denied,
        ApprovalStateWire::Expired => ApprovalStateDto::Expired,
        ApprovalStateWire::Cancelled => ApprovalStateDto::Cancelled,
    }
}

fn correlate_text(
    conversation_id: CanonicalId,
    expected_version: u64,
    input: &str,
    terminal: TextTerminalWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    match terminal.terminal {
        TextTerminalKind::Completed => completed(conversation_id, expected_version, input, terminal),
        TextTerminalKind::Rejected => rejection(conversation_id, expected_version, input, terminal, false),
        TextTerminalKind::ProhibitedInputRejected => rejection(conversation_id, expected_version, input, terminal, true),
    }
}

fn completed(conversation: CanonicalId, expected: u64, input: &str, wire: TextTerminalWire) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    validate_terminal(conversation, expected, input, &wire)?;
    let assistant = wire.assistant_message.into_option().ok_or_else(invalid_response)?;
    if wire.reserved_assistant_message_id.is_present() || wire.reason.is_present() { return Err(invalid_response()); }
    validate_message(&assistant, MessageRoleWire::Assistant, wire.task_run_id, wire.attempt_id)?;
    if wire.user_message.message_id == assistant.message_id { return Err(invalid_response()); }
    Ok(CommandReconciliationOutcome::ConversationTextCompleted(Box::new(ConversationTextResult {
        conversation_id: wire.conversation_id, task_run_id: wire.task_run_id,
        attempt_id: wire.attempt_id, conversation_stream_version: wire.conversation_stream_version,
        task_run_stream_version: wire.task_run_stream_version,
        user_message: message(wire.user_message), assistant_message: message(*assistant),
    })))
}

fn rejection(conversation: CanonicalId, expected: u64, input: &str, wire: TextTerminalWire, prohibited: bool) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    validate_terminal(conversation, expected, input, &wire)?;
    if wire.assistant_message.is_present() { return Err(invalid_response()); }
    let reserved = wire.reserved_assistant_message_id.into_option().ok_or_else(invalid_response)?;
    if wire.user_message.message_id == reserved { return Err(invalid_response()); }
    let reason = match wire.reason.into_option().ok_or_else(invalid_response)? { FailureReasonWire::ProviderOutputRejected => ConversationGenerationFailureReason::ProviderOutputRejected };
    let value = ConversationTextRejection {
        conversation_id: wire.conversation_id, task_run_id: wire.task_run_id,
        attempt_id: wire.attempt_id, conversation_stream_version: wire.conversation_stream_version,
        task_run_stream_version: wire.task_run_stream_version, user_message: message(wire.user_message),
        reserved_assistant_message_id: reserved, reason,
    };
    Ok(if prohibited { CommandReconciliationOutcome::ConversationTextProhibitedInputRejected(Box::new(value)) } else { CommandReconciliationOutcome::ConversationTextRejected(Box::new(value)) })
}

fn validate_terminal(conversation: CanonicalId, expected: u64, input: &str, wire: &TextTerminalWire) -> Result<(), RuntimeApiError> {
    if conversation != wire.conversation_id || expected.checked_add(2) != Some(wire.conversation_stream_version) || wire.task_run_stream_version != 5 || wire.user_message.text != input { return Err(invalid_response()); }
    validate_message(&wire.user_message, MessageRoleWire::User, wire.task_run_id, wire.attempt_id)
}

fn validate_message(wire: &MessageWire, role: MessageRoleWire, task: CanonicalId, attempt: CanonicalId) -> Result<(), RuntimeApiError> {
    validate_message_text(&wire.text).map_err(|_| invalid_response())?;
    if wire.role != role || wire.task_run_id != task || wire.attempt_id != attempt { return Err(invalid_response()); }
    Ok(())
}

fn message(wire: MessageWire) -> ConversationMessage {
    ConversationMessage { message_id: wire.message_id, role: match wire.role { MessageRoleWire::User => ConversationMessageRole::User, MessageRoleWire::Assistant => ConversationMessageRole::Assistant }, task_run_id: wire.task_run_id, attempt_id: wire.attempt_id, text: wire.text, committed_at: wire.committed_at }
}
