use super::super::reconciliation_wire::{
    FailureReasonWire, MessageRoleWire, MessageWire, TextTerminalKind, TextTerminalWire,
};
use super::super::{
    CanonicalId, CommandReconciliationOutcome, RuntimeApiError, invalid_response,
    validate_message_text,
};
use super::super::{
    ConversationGenerationFailureReason, ConversationMessage, ConversationMessageRole,
    ConversationTextRejection, ConversationTextResult,
};

pub(super) fn correlate_text(
    conversation_id: CanonicalId,
    expected_version: u64,
    input: &str,
    terminal: TextTerminalWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    match terminal.terminal {
        TextTerminalKind::Completed => {
            completed(conversation_id, expected_version, input, terminal)
        }
        TextTerminalKind::Rejected => {
            rejection(conversation_id, expected_version, input, terminal, false)
        }
        TextTerminalKind::ProhibitedInputRejected => {
            rejection(conversation_id, expected_version, input, terminal, true)
        }
    }
}

fn completed(
    conversation: CanonicalId,
    expected: u64,
    input: &str,
    wire: TextTerminalWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    validate_terminal(conversation, expected, input, &wire)?;
    let assistant = wire
        .assistant_message
        .into_option()
        .ok_or_else(invalid_response)?;
    if wire.reserved_assistant_message_id.is_present() || wire.reason.is_present() {
        return Err(invalid_response());
    }
    validate_message(
        &assistant,
        MessageRoleWire::Assistant,
        wire.task_run_id,
        wire.attempt_id,
    )?;
    if wire.user_message.message_id == assistant.message_id {
        return Err(invalid_response());
    }
    Ok(CommandReconciliationOutcome::ConversationTextCompleted(
        Box::new(ConversationTextResult {
            conversation_id: wire.conversation_id,
            task_run_id: wire.task_run_id,
            attempt_id: wire.attempt_id,
            conversation_stream_version: wire.conversation_stream_version,
            task_run_stream_version: wire.task_run_stream_version,
            user_message: message(wire.user_message),
            assistant_message: message(*assistant),
        }),
    ))
}

fn rejection(
    conversation: CanonicalId,
    expected: u64,
    input: &str,
    wire: TextTerminalWire,
    prohibited: bool,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    validate_terminal(conversation, expected, input, &wire)?;
    if wire.assistant_message.is_present() {
        return Err(invalid_response());
    }
    let reserved = wire
        .reserved_assistant_message_id
        .into_option()
        .ok_or_else(invalid_response)?;
    if wire.user_message.message_id == reserved {
        return Err(invalid_response());
    }
    let reason = match wire.reason.into_option().ok_or_else(invalid_response)? {
        FailureReasonWire::ProviderOutputRejected => {
            ConversationGenerationFailureReason::ProviderOutputRejected
        }
    };
    let value = ConversationTextRejection {
        conversation_id: wire.conversation_id,
        task_run_id: wire.task_run_id,
        attempt_id: wire.attempt_id,
        conversation_stream_version: wire.conversation_stream_version,
        task_run_stream_version: wire.task_run_stream_version,
        user_message: message(wire.user_message),
        reserved_assistant_message_id: reserved,
        reason,
    };
    Ok(if prohibited {
        CommandReconciliationOutcome::ConversationTextProhibitedInputRejected(Box::new(value))
    } else {
        CommandReconciliationOutcome::ConversationTextRejected(Box::new(value))
    })
}

fn validate_terminal(
    conversation: CanonicalId,
    expected: u64,
    input: &str,
    wire: &TextTerminalWire,
) -> Result<(), RuntimeApiError> {
    if conversation != wire.conversation_id
        || expected.checked_add(2) != Some(wire.conversation_stream_version)
        || wire.task_run_stream_version != 5
        || wire.user_message.text != input
    {
        return Err(invalid_response());
    }
    validate_message(
        &wire.user_message,
        MessageRoleWire::User,
        wire.task_run_id,
        wire.attempt_id,
    )
}

fn validate_message(
    wire: &MessageWire,
    role: MessageRoleWire,
    task: CanonicalId,
    attempt: CanonicalId,
) -> Result<(), RuntimeApiError> {
    validate_message_text(&wire.text).map_err(|_| invalid_response())?;
    if wire.role != role || wire.task_run_id != task || wire.attempt_id != attempt {
        return Err(invalid_response());
    }
    Ok(())
}

fn message(wire: MessageWire) -> ConversationMessage {
    ConversationMessage {
        message_id: wire.message_id,
        role: match wire.role {
            MessageRoleWire::User => ConversationMessageRole::User,
            MessageRoleWire::Assistant => ConversationMessageRole::Assistant,
        },
        task_run_id: wire.task_run_id,
        attempt_id: wire.attempt_id,
        text: wire.text,
        committed_at: wire.committed_at,
    }
}
