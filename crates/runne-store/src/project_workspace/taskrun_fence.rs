use runne_application::commands::CommandOutcome;
use runne_application::ports::{
    AggregateScope, IdempotencyScope, OperationTag, ProjectWorkspaceRepositoryError as Error,
    TextGenerationPhase,
};
use runne_domain::id::{CommandId, ProjectId, TaskRunId, WorkspaceId};
use rusqlite::{OptionalExtension, Transaction};

use crate::codec::{
    CommandOutcomeCodec, IdempotencyScopeCodec, StoreCodec, TextGenerationReceiptCodec,
};

use super::taskrun_replay::task_run_is_terminal;

pub(super) fn ensure_project_task_runs_terminal(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
) -> Result<(), Error> {
    super::taskrun_audit::ensure_all_taskrun_streams_have_lineage(transaction)?;
    super::taskrun_origins::ensure_target_origins_have_lineage(transaction, project_id)?;
    let mut statement = transaction
        .prepare(
            "SELECT taskrun_id, workspace_id, classification,
                    origin_command_id, origin_operation
             FROM task_run_workspace_lineage WHERE project_id = ?1 ORDER BY taskrun_id",
        )
        .map_err(|_| Error::Unavailable)?;
    let rows = statement
        .query_map([project_id.as_bytes()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|_| Error::Unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Error::Unavailable)?;
    drop(statement);

    for (taskrun, workspace, classification, command, operation) in rows {
        if classification != "canonical" {
            return Err(Error::InvariantViolation);
        }
        let taskrun_id = TaskRunId::from_bytes(parse_id(taskrun)?);
        let workspace_id = WorkspaceId::from_bytes(parse_id(workspace)?);
        let origin_command_id = CommandId::from_bytes(parse_id(command)?);
        validate_unambiguous_workspace(transaction, workspace_id, project_id)?;
        validate_origin(
            transaction,
            taskrun_id,
            workspace_id,
            origin_command_id.into_bytes(),
            operation,
        )?;
        if !task_run_is_terminal(transaction, taskrun_id, origin_command_id)? {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

fn validate_unambiguous_workspace(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    project_id: ProjectId,
) -> Result<(), Error> {
    let mut statement = transaction
        .prepare(
            "SELECT DISTINCT project_id FROM task_run_workspace_lineage
             WHERE workspace_id = ?1 AND classification = 'canonical'",
        )
        .map_err(|_| Error::Unavailable)?;
    let projects = statement
        .query_map([workspace_id.as_bytes()], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| Error::Unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Error::Unavailable)?;
    if projects.len() != 1 || parse_id(projects[0].clone())? != project_id.into_bytes() {
        return Err(Error::InvariantViolation);
    }
    Ok(())
}

fn validate_origin(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
    command_id: [u8; 16],
    operation: i64,
) -> Result<(), Error> {
    let row = transaction
        .query_row(
            "SELECT idempotency_scope_bytes, command_outcome FROM command_receipts
             WHERE command_id = ?1",
            [command_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::InvariantViolation)?;
    let scope = IdempotencyScopeCodec
        .decode(&row.0)
        .map_err(|_| Error::InvariantViolation)?;
    let owner: Option<String> = transaction
        .query_row(
            "SELECT principal_id FROM workspaces WHERE workspace_id = ?1",
            [workspace_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::Unavailable)?;
    if owner.as_deref() != Some(scope.principal_id.0.as_str()) {
        return Err(Error::InvariantViolation);
    }
    match operation {
        1 => validate_direct_origin(scope, &row.1, taskrun_id, workspace_id),
        18 => validate_text_origin(scope, &row.1, taskrun_id, workspace_id),
        20 => validate_submit_origin(scope, &row.1, taskrun_id, workspace_id),
        _ => Err(Error::InvariantViolation),
    }
}

fn validate_direct_origin(
    scope: IdempotencyScope,
    outcome: &[u8],
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
) -> Result<(), Error> {
    if scope.operation != OperationTag::CreateTaskRun
        || !matches!(scope.aggregate_scope, AggregateScope::NewTaskRun { workspace_id: value, .. } if value == workspace_id)
        || !matches!(CommandOutcomeCodec.decode(outcome), Ok(CommandOutcome::TaskRunCreated { taskrun_id: value, new_version: 1 }) if value == taskrun_id)
    {
        return Err(Error::InvariantViolation);
    }
    Ok(())
}

fn validate_submit_origin(
    scope: IdempotencyScope,
    outcome: &[u8],
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
) -> Result<(), Error> {
    if scope.operation != OperationTag::SubmitTaskRun
        || !matches!(scope.aggregate_scope, AggregateScope::NewTaskRun { workspace_id: value, .. } if value == workspace_id)
        || !matches!(CommandOutcomeCodec.decode(outcome), Ok(CommandOutcome::TaskRunSubmitted { taskrun_id: value, new_version: 2 }) if value == taskrun_id)
    {
        return Err(Error::InvariantViolation);
    }
    Ok(())
}

fn validate_text_origin(
    scope: IdempotencyScope,
    outcome: &[u8],
    taskrun_id: TaskRunId,
    workspace_id: WorkspaceId,
) -> Result<(), Error> {
    let receipt = TextGenerationReceiptCodec
        .decode(outcome)
        .map_err(|_| Error::InvariantViolation)?;
    let version_valid = match receipt.phase {
        TextGenerationPhase::Started => receipt.taskrun_version == 4,
        TextGenerationPhase::Completed
        | TextGenerationPhase::Rejected
        | TextGenerationPhase::ProhibitedInputRejected => receipt.taskrun_version == 5,
    };
    if scope.operation != OperationTag::GenerateConversationText
        || !matches!(scope.aggregate_scope, AggregateScope::ExistingConversation { conversation_id } if conversation_id == receipt.conversation_id)
        || receipt.taskrun_id != taskrun_id
        || receipt.workspace_id != workspace_id
        || !version_valid
    {
        return Err(Error::InvariantViolation);
    }
    Ok(())
}

fn parse_id(value: Vec<u8>) -> Result<[u8; 16], Error> {
    value.try_into().map_err(|_| Error::InvariantViolation)
}
