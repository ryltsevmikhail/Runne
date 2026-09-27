pub(crate) fn validate_all_text_only_taskrun_lineage(
    connection: &Connection,
) -> Result<(), CommitError> {
    use crate::codec::{IdempotencyScopeCodec, StoreCodec, TextGenerationReceiptCodec};

    let mut statement = connection
        .prepare(
            "SELECT taskrun_id, conversation_id, workspace_id, principal_id,
                    origin_command_id, origin_operation, context_scope
             FROM text_only_taskrun_lineage ORDER BY taskrun_id",
        )
        .map_err(corrupt)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(corrupt)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(corrupt)?;
    drop(statement);
    for (taskrun, conversation, workspace, principal, command, operation, marker) in rows {
        let (Ok(taskrun), Ok(conversation), Ok(workspace), Ok(command)) = (
            <[u8; 16]>::try_from(taskrun.as_slice()),
            <[u8; 16]>::try_from(conversation.as_slice()),
            <[u8; 16]>::try_from(workspace.as_slice()),
            <[u8; 16]>::try_from(command.as_slice()),
        ) else {
            return Err(corrupt(rusqlite::Error::InvalidQuery));
        };
        let (scope_bytes, outcome): (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT idempotency_scope_bytes, command_outcome FROM command_receipts WHERE command_id=?1",
                [command],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(corrupt)?;
        let scope = IdempotencyScopeCodec
            .decode(&scope_bytes)
            .map_err(|_| corrupt(rusqlite::Error::InvalidQuery))?;
        let receipt = TextGenerationReceiptCodec
            .decode(&outcome)
            .map_err(|_| corrupt(rusqlite::Error::InvalidQuery))?;
        if operation != OperationTag::GenerateConversationText as i64
            || marker != ConversationContextScope::TextOnly.as_str()
            || principal != scope.principal_id.0
            || scope.operation != OperationTag::GenerateConversationText
            || !matches!(scope.aggregate_scope, AggregateScope::ExistingConversation { conversation_id: id } if id.as_bytes() == &conversation)
            || receipt.taskrun_id.as_bytes() != &taskrun
            || receipt.conversation_id.as_bytes() != &conversation
            || receipt.workspace_id.as_bytes() != &workspace
        {
            return Err(corrupt(rusqlite::Error::InvalidQuery));
        }
        let command_id = CommandId::from_bytes(command);
        validate_text_only(
            connection,
            TaskRunId::from_bytes(taskrun),
            ConversationId::from_bytes(conversation),
            WorkspaceId::from_bytes(workspace),
            command_id,
            &scope,
        )?;
    }
    Ok(())
}

fn validate_text_only_taskrun_event(
    connection: &Connection,
    taskrun_id: [u8; 16],
    command_id: [u8; 16],
) -> Result<(), CommitError> {
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use runne_domain::task_run::TaskRunEvent;

    let event: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT payload, command_id FROM events
             WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [taskrun_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(corrupt)?;
    if !matches!(event,
        Some((payload, command))
            if command.as_slice() == command_id.as_slice()
                && matches!(TaskRunEventCodec.decode(&payload), Ok(TaskRunEvent::TaskRunCreated))
    ) {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    Ok(())
}

fn validate_text_only_conversation_event(
    connection: &Connection,
    conversation_id: [u8; 16],
    taskrun_id: [u8; 16],
    command_id: [u8; 16],
    receipt: &runne_application::ports::TextGenerationReceipt,
) -> Result<(), CommitError> {
    use crate::codec::{ConversationEventCodec, StoreCodec};

    let mut statement = connection
        .prepare(
            "SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1
             AND command_id=?2 ORDER BY sequence",
        )
        .map_err(corrupt)?;
    let events = statement
        .query_map(params![conversation_id, command_id], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(corrupt)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(corrupt)?;
    drop(statement);
    let matching_user_events = events
        .iter()
        .filter(|payload| {
            matches!(ConversationEventCodec.decode(payload),
                Ok(ConversationEvent::UserMessageAppended {
                    message_id, taskrun_id: event_taskrun, attempt_id, ..
                }) if message_id == receipt.user_message_id
                    && event_taskrun.as_bytes() == &taskrun_id
                    && attempt_id == receipt.attempt_id)
        })
        .count();
    if matching_user_events != 1 {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    Ok(())
}
