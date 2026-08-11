use gocode_application::ports::{
    AggregateScope, CommitError, IdempotencyScope, OperationTag, StorageFailureKind,
};
use gocode_domain::id::{CommandId, TaskRunId, WorkspaceId};
use rusqlite::{OptionalExtension, Transaction, params};

pub(crate) fn record_direct_taskrun_lineage(
    transaction: &Transaction<'_>,
    scope: &IdempotencyScope,
    taskrun_id: TaskRunId,
    command_id: CommandId,
) -> Result<(), CommitError> {
    let workspace_id = match (&scope.operation, &scope.aggregate_scope) {
        (OperationTag::CreateTaskRun, AggregateScope::NewTaskRun { workspace_id, .. }) => {
            *workspace_id
        }
        _ => return Ok(()),
    };
    record(
        transaction,
        taskrun_id,
        workspace_id,
        command_id,
        OperationTag::CreateTaskRun as i64,
        &scope.principal_id.0,
    )
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
    transaction: &Transaction<'_>,
    scope: &IdempotencyScope,
    taskrun_id: TaskRunId,
    command_id: CommandId,
) -> Result<(), CommitError> {
    let AggregateScope::NewTaskRun { workspace_id, .. } = scope.aggregate_scope else {
        return Err(corrupt(rusqlite::Error::InvalidQuery));
    };
    validate(
        transaction,
        taskrun_id,
        workspace_id,
        command_id,
        OperationTag::CreateTaskRun as i64,
    )
}

pub(crate) fn validate_text_taskrun_lineage(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
) -> Result<(), CommitError> {
    validate(
        transaction,
        taskrun_id,
        workspace_id,
        command_id,
        OperationTag::GenerateConversationText as i64,
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
            "SELECT project_id, principal_id, live FROM workspaces WHERE workspace_id = ?1",
            [workspace_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(corrupt)?;
    let (project_id, classification) = match canonical {
        Some((project_id, owner, 1)) if project_id.len() == 16 && owner == principal_id => {
            (Some(project_id), "canonical")
        }
        Some(_) => return Err(corrupt(rusqlite::Error::InvalidQuery)),
        None => {
            if canonical_project_from_lineage(transaction, workspace_id)
                .map_err(corrupt)?
                .is_some()
            {
                return Err(corrupt(rusqlite::Error::InvalidQuery));
            }
            (None, "legacy_unbound")
        }
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
                classification,
                command_id.as_bytes(),
                operation,
            ],
        )
        .map_err(corrupt)?;
    Ok(())
}

fn canonical_project_from_lineage(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
) -> rusqlite::Result<Option<Vec<u8>>> {
    transaction
        .query_row(
            "SELECT project_id FROM task_run_workspace_lineage
             WHERE workspace_id = ?1 AND classification = 'canonical' LIMIT 1",
            [workspace_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
}

fn validate(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
    command_id: CommandId,
    operation: i64,
) -> Result<(), CommitError> {
    let row = transaction
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
    let classification_valid = match (row.2.as_str(), row.1.as_ref()) {
        ("canonical", Some(project)) => project.len() == 16,
        ("legacy_unbound", None) => true,
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
