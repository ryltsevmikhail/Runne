use gocode_application::commands::CommandOutcome;
use gocode_application::ports::{
    AggregateScope, IdempotencyScope, OperationTag, ProjectWorkspaceRepositoryError as Error,
};
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::id::{ProjectId, TaskRunId, WorkspaceId};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::codec::{
    CommandOutcomeCodec, ConversationEventCodec, IdempotencyScopeCodec, StoreCodec,
    TextGenerationReceiptCodec,
};

pub(super) fn ensure_target_origins_have_lineage(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
) -> Result<(), Error> {
    let mut statement = transaction
        .prepare(
            "SELECT command_id, idempotency_scope_bytes, command_outcome FROM command_receipts",
        )
        .map_err(|_| Error::Unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|_| Error::Unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Error::Unavailable)?;
    drop(statement);
    for (command, scope, outcome) in rows {
        let Ok(scope) = IdempotencyScopeCodec.decode(&scope) else {
            continue;
        };
        let Some((taskrun, workspace, operation)) =
            target_origin(transaction, project_id, &scope, &outcome)?
        else {
            continue;
        };
        let exact: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM task_run_workspace_lineage
                 WHERE taskrun_id = ?1 AND workspace_id = ?2
                   AND origin_command_id = ?3 AND origin_operation = ?4
                   AND project_id = ?5 AND classification = 'canonical')",
                params![
                    taskrun.as_bytes(),
                    workspace.as_bytes(),
                    command,
                    operation,
                    project_id.as_bytes()
                ],
                |row| row.get(0),
            )
            .map_err(|_| Error::Unavailable)?;
        if !exact {
            return Err(Error::InvariantViolation);
        }
    }
    Ok(())
}

fn target_origin(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
    scope: &IdempotencyScope,
    outcome: &[u8],
) -> Result<Option<(TaskRunId, WorkspaceId, i64)>, Error> {
    match scope.operation {
        OperationTag::CreateTaskRun => {
            direct_target_origin(transaction, project_id, scope, outcome)
        }
        OperationTag::GenerateConversationText => {
            text_target_origin(transaction, project_id, scope, outcome)
        }
        _ => Ok(None),
    }
}

fn direct_target_origin(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
    scope: &IdempotencyScope,
    outcome: &[u8],
) -> Result<Option<(TaskRunId, WorkspaceId, i64)>, Error> {
    let AggregateScope::NewTaskRun { workspace_id, .. } = scope.aggregate_scope else {
        return Ok(None);
    };
    if !workspace_belongs(transaction, workspace_id, project_id)? {
        return Ok(None);
    }
    let CommandOutcome::TaskRunCreated { taskrun_id, .. } = CommandOutcomeCodec
        .decode(outcome)
        .map_err(|_| Error::InvariantViolation)?
    else {
        return Err(Error::InvariantViolation);
    };
    Ok(Some((taskrun_id, workspace_id, 1)))
}

fn text_target_origin(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
    scope: &IdempotencyScope,
    outcome: &[u8],
) -> Result<Option<(TaskRunId, WorkspaceId, i64)>, Error> {
    let receipt = TextGenerationReceiptCodec.decode(outcome).ok();
    let conversation_id = match scope.aggregate_scope {
        AggregateScope::ExistingConversation { conversation_id } => Some(conversation_id),
        _ => None,
    };
    let conversation_workspace = conversation_id
        .map(|id| conversation_workspace(transaction, id))
        .transpose()?
        .flatten();
    let targets_project = match (receipt.as_ref(), conversation_workspace) {
        (Some(value), Some(conversation)) => {
            workspace_belongs(transaction, value.workspace_id, project_id)?
                || workspace_belongs(transaction, conversation, project_id)?
        }
        (Some(value), None) => workspace_belongs(transaction, value.workspace_id, project_id)?,
        (None, Some(conversation)) => workspace_belongs(transaction, conversation, project_id)?,
        (None, None) => false,
    };
    if !targets_project {
        return Ok(None);
    }
    let receipt = receipt.ok_or(Error::InvariantViolation)?;
    let conversation_workspace = conversation_workspace.ok_or(Error::InvariantViolation)?;
    if conversation_id != Some(receipt.conversation_id)
        || conversation_workspace != receipt.workspace_id
    {
        return Err(Error::InvariantViolation);
    }
    Ok(Some((receipt.taskrun_id, receipt.workspace_id, 18)))
}

fn conversation_workspace(
    transaction: &Transaction<'_>,
    id: gocode_domain::id::ConversationId,
) -> Result<Option<WorkspaceId>, Error> {
    let payload = transaction
        .query_row(
            "SELECT payload FROM events
             WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1",
            [id.as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| Error::Unavailable)?;
    Ok(
        payload.and_then(|payload| match ConversationEventCodec.decode(&payload) {
            Ok(ConversationEvent::ConversationCreated { workspace_id }) => Some(workspace_id),
            _ => None,
        }),
    )
}

fn workspace_belongs(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    project_id: ProjectId,
) -> Result<bool, Error> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM workspaces
             WHERE workspace_id = ?1 AND project_id = ?2)",
            params![workspace_id.as_bytes(), project_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| Error::Unavailable)
}
