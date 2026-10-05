use super::*;

pub(super) fn verify_conversation(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<(), CommitError> {
    let stream = super::super::conversation::load_conversation_from_connection(
        connection,
        receipt.conversation_id,
    )
    .map_err(|_| invalid())?;
    let user_index = usize::try_from(
        receipt
            .conversation_version
            .checked_sub(2)
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    let failed_index = usize::try_from(
        receipt
            .conversation_version
            .checked_sub(1)
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    let user = stream.events.get(user_index).ok_or_else(invalid)?;
    let failed = stream.events.get(failed_index).ok_or_else(invalid)?;
    if !matches!(user.payload(),ConversationEvent::UserMessageAppended{message_id,taskrun_id,attempt_id,..}
        if *message_id==receipt.user_message_id && *taskrun_id==receipt.taskrun_id && *attempt_id==receipt.attempt_id)
        || !matches!(failed.payload(),ConversationEvent::GenerationFailed{taskrun_id,attempt_id,reason:runne_domain::conversation::GenerationFailureReason::Cancelled}
            if *taskrun_id==receipt.taskrun_id && *attempt_id==receipt.attempt_id)
        || failed.causation_id().copied() != Some(*user.event_id())
        || failed.command_id() != user.command_id()
        || failed.idempotency_key() != user.idempotency_key()
    {
        return Err(invalid());
    }
    Ok(())
}
