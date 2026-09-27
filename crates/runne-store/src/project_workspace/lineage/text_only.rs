type StoredTextOnlyLineage = (Vec<u8>, Vec<u8>, String, Vec<u8>, i64, String);

fn text_conversation_id(scope: &IdempotencyScope) -> Result<ConversationId, CommitError> {
    if scope.operation != OperationTag::GenerateConversationText {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    match scope.aggregate_scope {
        AggregateScope::ExistingConversation { conversation_id } => Ok(conversation_id),
        _ => Err(corrupt(rusqlite::Error::InvalidQuery)),
    }
}

fn read_conversation_scope(
    connection: &Connection,
    conversation_id: ConversationId,
) -> Result<ConversationContextScope, CommitError> {
    let marker: Option<String> = connection
        .query_row(
            "SELECT context_scope FROM conversation_context_scope WHERE conversation_id=?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(corrupt)?;
    marker
        .as_deref()
        .and_then(ConversationContextScope::parse)
        .ok_or_else(|| corrupt(rusqlite::Error::InvalidQuery))
}

fn record_text_only(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    scope: &IdempotencyScope,
) -> Result<(), CommitError> {
    validate_text_only_conversation(transaction, conversation_id, workspace_id)?;
    transaction
        .execute(
            "INSERT INTO text_only_taskrun_lineage
             (taskrun_id, conversation_id, workspace_id, principal_id,
              origin_command_id, origin_operation, context_scope)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                taskrun_id.as_bytes(),
                conversation_id.as_bytes(),
                workspace_id.as_bytes(),
                scope.principal_id.0,
                command_id.as_bytes(),
                OperationTag::GenerateConversationText as i64,
                ConversationContextScope::TextOnly.as_str(),
            ],
        )
        .map_err(corrupt)?;
    Ok(())
}

fn validate_text_only(
    connection: &Connection,
    taskrun_id: TaskRunId,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    scope: &IdempotencyScope,
) -> Result<(), CommitError> {
    let row: Option<StoredTextOnlyLineage> = connection
        .query_row(
            "SELECT conversation_id, workspace_id, principal_id,
                    origin_command_id, origin_operation, context_scope
             FROM text_only_taskrun_lineage WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(corrupt)?;
    let Some((stored_conversation, stored_workspace, principal, stored_command, operation, marker)) =
        row
    else {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    };
    if stored_conversation != conversation_id.as_bytes()
        || stored_workspace != workspace_id.as_bytes()
        || principal != scope.principal_id.0
        || stored_command != command_id.as_bytes()
        || operation != OperationTag::GenerateConversationText as i64
        || marker != ConversationContextScope::TextOnly.as_str()
    {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    let workspace_owner_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM task_run_workspace_lineage WHERE taskrun_id=?1)",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(corrupt)?;
    if workspace_owner_exists {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    validate_text_only_conversation(connection, conversation_id, workspace_id)?;
    validate_text_only_receipt(
        connection,
        taskrun_id,
        conversation_id,
        workspace_id,
        command_id,
        scope,
    )
}

fn validate_text_only_conversation(
    connection: &Connection,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
) -> Result<(), CommitError> {
    use crate::codec::{ConversationEventCodec, StoreCodec};

    if read_conversation_scope(connection, conversation_id)? != ConversationContextScope::TextOnly {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence=1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(corrupt)?
        .ok_or_else(|| corrupt(rusqlite::Error::InvalidQuery))?;
    if !matches!(ConversationEventCodec.decode(&payload),
        Ok(ConversationEvent::ConversationCreated { workspace_id: stored }) if stored == workspace_id
    ) {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    Ok(())
}

fn validate_text_only_receipt(
    connection: &Connection,
    taskrun_id: TaskRunId,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    scope: &IdempotencyScope,
) -> Result<(), CommitError> {
    use crate::codec::{IdempotencyScopeCodec, StoreCodec, TextGenerationReceiptCodec};

    let (scope_bytes, outcome): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT idempotency_scope_bytes, command_outcome FROM command_receipts WHERE command_id=?1",
            [command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(corrupt)?;
    let stored_scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| corrupt(rusqlite::Error::InvalidQuery))?;
    let receipt = TextGenerationReceiptCodec
        .decode(&outcome)
        .map_err(|_| corrupt(rusqlite::Error::InvalidQuery))?;
    if &stored_scope != scope
        || receipt.taskrun_id != taskrun_id
        || receipt.conversation_id != conversation_id
        || receipt.workspace_id != workspace_id
    {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    validate_text_only_taskrun_event(connection, taskrun_id.into_bytes(), command_id.into_bytes())?;
    validate_text_only_conversation_event(
        connection,
        conversation_id.into_bytes(),
        taskrun_id.into_bytes(),
        command_id.into_bytes(),
        &receipt,
    )
}
