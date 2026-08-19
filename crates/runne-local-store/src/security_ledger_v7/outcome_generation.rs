use super::codec;
use super::outcome::{
    CanonicalMutationOutcome, GenerationAssistant, GenerationFailureReason, GenerationTerminal,
    LedgerMessage, MessageRole,
};
use crate::SecurityStateError;

pub(super) fn generation(
    input: &mut &[u8],
) -> Result<CanonicalMutationOutcome, SecurityStateError> {
    let terminal = terminal(codec::byte(input)?).ok_or(SecurityStateError::InvalidTransition)?;
    let conversation_id = codec::id(input)?;
    let task_run_id = codec::id(input)?;
    let attempt_id = codec::id(input)?;
    let conversation_stream_version = version(input)?;
    let task_run_stream_version = version(input)?;
    let user_message = message_read(input)?;
    if user_message.role != MessageRole::User
        || user_message.task_run_id != task_run_id
        || user_message.attempt_id != attempt_id
    {
        return Err(SecurityStateError::InvalidTransition);
    }
    let assistant = match codec::byte(input)? {
        1 => {
            let value = message_read(input)?;
            if terminal != GenerationTerminal::Completed
                || value.role != MessageRole::Assistant
                || value.task_run_id != task_run_id
                || value.attempt_id != attempt_id
                || value.message_id == user_message.message_id
            {
                return Err(SecurityStateError::InvalidTransition);
            }
            GenerationAssistant::Completed(value)
        }
        2 => {
            if terminal == GenerationTerminal::Completed {
                return Err(SecurityStateError::InvalidTransition);
            }
            GenerationAssistant::Rejected {
                reserved_message_id: codec::id(input)?,
                reason: GenerationFailureReason::from_tag(codec::byte(input)?)
                    .ok_or(SecurityStateError::InvalidTransition)?,
            }
        }
        _ => return Err(SecurityStateError::InvalidTransition),
    };
    Ok(CanonicalMutationOutcome::Generation {
        terminal,
        conversation_id,
        task_run_id,
        attempt_id,
        conversation_stream_version,
        task_run_stream_version,
        user_message,
        assistant: Box::new(assistant),
    })
}

pub(super) fn validate(
    terminal: GenerationTerminal,
    task_run_id: &crate::BoundedCanonicalId,
    attempt_id: &crate::BoundedCanonicalId,
    user_message: &LedgerMessage,
    assistant: &GenerationAssistant,
) -> Result<(), SecurityStateError> {
    if user_message.role != MessageRole::User
        || user_message.task_run_id != *task_run_id
        || user_message.attempt_id != *attempt_id
    {
        return Err(SecurityStateError::InvalidTransition);
    }
    match assistant {
        GenerationAssistant::Completed(value) => (terminal == GenerationTerminal::Completed
            && value.role == MessageRole::Assistant
            && value.task_run_id == *task_run_id
            && value.attempt_id == *attempt_id
            && value.message_id != user_message.message_id)
            .then_some(())
            .ok_or(SecurityStateError::InvalidTransition),
        GenerationAssistant::Rejected {
            reserved_message_id,
            ..
        } => (terminal != GenerationTerminal::Completed
            && *reserved_message_id != user_message.message_id)
            .then_some(())
            .ok_or(SecurityStateError::InvalidTransition),
    }
}
pub(super) fn message(
    output: &mut Vec<u8>,
    value: &LedgerMessage,
) -> Result<(), SecurityStateError> {
    codec::put_id(output, &value.message_id)?;
    output.push(match value.role {
        MessageRole::User => 1,
        MessageRole::Assistant => 2,
    });
    codec::put_id(output, &value.task_run_id)?;
    codec::put_id(output, &value.attempt_id)?;
    codec::put_message_text(output, &value.text)?;
    valid(value.committed_at)?;
    output.extend(value.committed_at.to_be_bytes());
    Ok(())
}
pub(super) fn put_versions(output: &mut Vec<u8>, values: &[u64]) -> Result<(), SecurityStateError> {
    for value in values {
        output.extend(valid(*value)?.to_be_bytes());
    }
    Ok(())
}
pub(super) fn version(input: &mut &[u8]) -> Result<u64, SecurityStateError> {
    valid(codec::u64(input)?)
}
pub(super) const fn terminal_tag(value: GenerationTerminal) -> u8 {
    match value {
        GenerationTerminal::Completed => 1,
        GenerationTerminal::Rejected => 2,
        GenerationTerminal::Prohibited => 3,
    }
}
const fn terminal(value: u8) -> Option<GenerationTerminal> {
    match value {
        1 => Some(GenerationTerminal::Completed),
        2 => Some(GenerationTerminal::Rejected),
        3 => Some(GenerationTerminal::Prohibited),
        _ => None,
    }
}
fn message_read(input: &mut &[u8]) -> Result<LedgerMessage, SecurityStateError> {
    Ok(LedgerMessage {
        message_id: codec::id(input)?,
        role: match codec::byte(input)? {
            1 => MessageRole::User,
            2 => MessageRole::Assistant,
            _ => return Err(SecurityStateError::InvalidTransition),
        },
        task_run_id: codec::id(input)?,
        attempt_id: codec::id(input)?,
        text: codec::message_text(input)?,
        committed_at: version(input)?,
    })
}
fn valid(value: u64) -> Result<u64, SecurityStateError> {
    (value != 0)
        .then_some(value)
        .ok_or(SecurityStateError::InvalidTransition)
}
