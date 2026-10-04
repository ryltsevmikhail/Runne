use super::*;

pub(super) fn conversation_has_started_text(
    tx: &rusqlite::Transaction<'_>,
    conversation_id: runne_domain::id::ConversationId,
    taskrun_id: TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
) -> Result<bool, Error> {
    let stream =
        super::super::super::conversation::load_conversation_from_connection(tx, conversation_id)
            .map_err(|_| Error::CorruptData)?;
    for event in stream.events {
        match event.payload() {
            ConversationEvent::UserMessageAppended {
                taskrun_id: stored_taskrun,
                attempt_id: stored_attempt,
                ..
            } if *stored_taskrun == taskrun_id && *stored_attempt == attempt_id => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

pub(super) fn has_text_generation_receipt(
    tx: &rusqlite::Transaction<'_>,
    conversation_id: runne_domain::id::ConversationId,
    taskrun_id: TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
) -> Result<bool, Error> {
    let mut statement = tx
        .prepare("SELECT idempotency_scope_bytes,command_outcome FROM command_receipts")
        .map_err(|_| Error::CorruptData)?;
    let mut rows = statement.query([]).map_err(|_| Error::CorruptData)?;
    while let Some(row) = rows.next().map_err(|_| Error::CorruptData)? {
        let scope_bytes: Vec<u8> = row.get(0).map_err(|_| Error::CorruptData)?;
        let scope = IdempotencyScopeCodec
            .decode(&scope_bytes)
            .map_err(|_| Error::CorruptData)?;
        if scope.operation != OperationTag::GenerateConversationText
            || scope.aggregate_scope != (AggregateScope::ExistingConversation { conversation_id })
        {
            continue;
        }
        let outcome: Vec<u8> = row.get(1).map_err(|_| Error::CorruptData)?;
        let receipt = TextGenerationReceiptCodec
            .decode(&outcome)
            .map_err(|_| Error::CorruptData)?;
        if receipt.taskrun_id == taskrun_id && receipt.attempt_id == attempt_id {
            return Ok(true);
        }
    }
    Ok(false)
}
