use runne_application::ports::{
    AggregateScope, CommitError, IdempotencyScope, OperationTag, StorageFailureKind,
};
use runne_domain::conversation::{ConversationContextScope, ConversationEvent};
use runne_domain::id::{CommandId, ConversationId, TaskRunId, WorkspaceId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub(crate) fn record_direct_taskrun_lineage(
    transaction: &Transaction<'_>,
    scope: &IdempotencyScope,
    taskrun_id: TaskRunId,
    command_id: CommandId,
    has_prompt: bool,
) -> Result<(), CommitError> {
    let (workspace_id, conversation_id) = match (&scope.operation, &scope.aggregate_scope) {
        (OperationTag::CreateTaskRun, AggregateScope::NewTaskRun { workspace_id, .. }) => {
            (*workspace_id, None)
        }
        (
            OperationTag::SubmitTaskRun,
            AggregateScope::NewTaskRun {
                conversation_id,
                workspace_id,
            },
        ) => (*workspace_id, Some(*conversation_id)),
        _ => return Ok(()),
    };
    if let Some(conversation_id) = conversation_id
        && has_prompt
    {
        validate_submit_conversation(transaction, conversation_id, workspace_id)?;
    }
    record(
        transaction,
        taskrun_id,
        workspace_id,
        command_id,
        scope.operation as i64,
        &scope.principal_id.0,
    )
}

fn validate_submit_conversation(
    transaction: &Transaction<'_>,
    conversation_id: ConversationId,
    workspace_id: WorkspaceId,
) -> Result<(), CommitError> {
    use crate::codec::{ConversationEventCodec, StoreCodec};

    let payload = transaction
        .query_row(
            "SELECT payload FROM events
             WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1",
            [conversation_id.as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(corrupt)?
        .ok_or_else(|| corrupt(rusqlite::Error::InvalidQuery))?;
    if !matches!(ConversationEventCodec.decode(&payload),
        Ok(ConversationEvent::ConversationCreated { workspace_id: stored }) if stored == workspace_id
    ) {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    let context_scope = transaction
        .query_row(
            "SELECT context_scope FROM conversation_context_scope WHERE conversation_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(corrupt)?;
    if context_scope.as_deref() != Some(ConversationContextScope::Workspace.as_str()) {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    Ok(())
}

pub(crate) fn record_text_taskrun_lineage(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    scope: &IdempotencyScope,
) -> Result<(), CommitError> {
    record(
        transaction,
        taskrun_id,
        workspace_id,
        command_id,
        OperationTag::GenerateConversationText as i64,
        &scope.principal_id.0,
    )
}

pub(crate) fn validate_direct_taskrun_lineage(
    connection: &Connection,
    scope: &IdempotencyScope,
    taskrun_id: TaskRunId,
    command_id: CommandId,
) -> Result<(), CommitError> {
    let AggregateScope::NewTaskRun { workspace_id, .. } = scope.aggregate_scope else {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    };
    validate(
        connection,
        taskrun_id,
        workspace_id,
        command_id,
        scope.operation as i64,
        &scope.principal_id.0,
    )
}

pub(crate) fn validate_text_taskrun_lineage(
    connection: &Connection,
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    scope: &IdempotencyScope,
) -> Result<(), CommitError> {
    validate(
        connection,
        taskrun_id,
        workspace_id,
        command_id,
        OperationTag::GenerateConversationText as i64,
        &scope.principal_id.0,
    )
}

fn record(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    operation: i64,
    principal_id: &str,
) -> Result<(), CommitError> {
    let canonical = transaction
        .query_row(
            "SELECT w.project_id, w.principal_id, w.live,
                    h.project_id, h.principal_id, h.classification
             FROM workspaces w
             LEFT JOIN workspace_identity_history h ON h.workspace_id = w.workspace_id
             WHERE w.workspace_id = ?1",
            [workspace_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(corrupt)?;
    let project_id = match canonical {
        Some((project_id, owner, 1, Some(history_project), Some(history_owner), Some(kind)))
            if project_id.len() == 16
                && project_id == history_project
                && owner == principal_id
                && owner == history_owner
                && kind == "canonical" =>
        {
            project_id
        }
        Some(_) => return Err(corrupt(rusqlite::Error::InvalidQuery)),
        None => return Err(corrupt(rusqlite::Error::InvalidQuery)),
    };
    transaction
        .execute(
            "INSERT INTO task_run_workspace_lineage
             (taskrun_id, workspace_id, project_id, classification,
              origin_command_id, origin_operation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                taskrun_id.as_bytes(),
                workspace_id.as_bytes(),
                project_id,
                "canonical",
                command_id.as_bytes(),
                operation,
            ],
        )
        .map_err(corrupt)?;
    Ok(())
}

fn validate(
    connection: &Connection,
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    operation: i64,
    principal_id: &str,
) -> Result<(), CommitError> {
    let row = connection
        .query_row(
            "SELECT workspace_id, project_id, classification,
                    origin_command_id, origin_operation
             FROM task_run_workspace_lineage WHERE taskrun_id = ?1",
            [taskrun_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(corrupt)?
        .ok_or_else(|| corrupt(rusqlite::Error::InvalidQuery))?;
    let history = connection
        .query_row(
            "SELECT project_id, principal_id, classification
             FROM workspace_identity_history WHERE workspace_id = ?1",
            [workspace_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(corrupt)?;
    let classification_valid = match (row.2.as_str(), row.1.as_ref(), history) {
        ("canonical", Some(project), Some((Some(bound), Some(owner), kind))) => {
            project == &bound && owner == principal_id && kind == "canonical"
        }
        ("legacy_unbound", None, Some((None, None, kind))) => kind == "legacy_unbound",
        _ => false,
    };
    if row.0 != workspace_id.as_bytes()
        || row.3 != command_id.as_bytes()
        || row.4 != operation
        || !classification_valid
    {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    }
    Ok(())
}

fn corrupt(_: rusqlite::Error) -> CommitError {
    CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)
}
