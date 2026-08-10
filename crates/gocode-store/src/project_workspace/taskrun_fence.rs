use std::collections::HashMap;

use gocode_application::commands::CommandOutcome;
use gocode_application::ports::{
    AggregateScope, IdempotencyScope, OperationTag, ProjectWorkspaceRepositoryError as Error,
};
use gocode_domain::id::{ProjectId, TaskRunId, WorkspaceId};
use gocode_domain::task_run::TaskRunEvent;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::codec::{CommandOutcomeCodec, IdempotencyScopeCodec, StoreCodec, TaskRunEventCodec};

pub(super) fn ensure_project_task_runs_terminal(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
) -> Result<(), Error> {
    let workspaces = project_workspaces(transaction, project_id)?;
    let mut statement = transaction
        .prepare("SELECT idempotency_scope_bytes, command_outcome FROM command_receipts")
        .map_err(|_| Error::Unavailable)?;
    let receipts = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|_| Error::Unavailable)?;
    for row in receipts {
        let (scope_bytes, outcome_bytes) = row.map_err(|_| Error::Unavailable)?;
        let scope = IdempotencyScopeCodec
            .decode(&scope_bytes)
            .map_err(|_| Error::InvariantViolation)?;
        if scope.operation != OperationTag::CreateTaskRun {
            continue;
        }
        let workspace_id = match scope.aggregate_scope {
            AggregateScope::NewTaskRun { workspace_id, .. } => workspace_id,
            _ => return Err(Error::InvariantViolation),
        };
        let (linked_project, workspace_principal) = workspaces
            .get(&workspace_id)
            .cloned()
            .ok_or(Error::InvariantViolation)?;
        if workspace_principal != scope.principal_id.0 {
            return Err(Error::InvariantViolation);
        }
        if linked_project != project_id {
            continue;
        }
        let taskrun_id = match CommandOutcomeCodec
            .decode(&outcome_bytes)
            .map_err(|_| Error::InvariantViolation)?
        {
            CommandOutcome::TaskRunCreated {
                taskrun_id,
                new_version: 1,
            } => taskrun_id,
            _ => return Err(Error::InvariantViolation),
        };
        if !task_run_is_terminal(transaction, taskrun_id)? {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

pub(crate) fn validate_taskrun_workspace_scope(
    transaction: &Transaction<'_>,
    scope: &IdempotencyScope,
) -> Result<(), Error> {
    let AggregateScope::NewTaskRun { workspace_id, .. } = scope.aggregate_scope else {
        return Ok(());
    };
    if scope.operation != OperationTag::CreateTaskRun {
        return Ok(());
    }
    let project_workspace_active: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM project_workspace_command_receipts)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| Error::Unavailable)?;
    if !project_workspace_active {
        return Ok(());
    }
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM workspaces
                WHERE workspace_id = ?1 AND principal_id = ?2 AND live = 1
             )",
            params![workspace_id.as_bytes(), scope.principal_id.0],
            |row| row.get(0),
        )
        .map_err(|_| Error::Unavailable)?;
    if exists { Ok(()) } else { Err(Error::NotFound) }
}

fn project_workspaces(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
) -> Result<HashMap<WorkspaceId, (ProjectId, String)>, Error> {
    let mut statement = transaction
        .prepare("SELECT workspace_id, project_id, principal_id FROM workspaces")
        .map_err(|_| Error::Unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| Error::Unavailable)?;
    let mut workspaces = HashMap::new();
    for row in rows {
        let (workspace, project, principal) = row.map_err(|_| Error::Unavailable)?;
        let workspace = WorkspaceId::from_bytes(
            workspace
                .try_into()
                .map_err(|_| Error::InvariantViolation)?,
        );
        let project =
            ProjectId::from_bytes(project.try_into().map_err(|_| Error::InvariantViolation)?);
        workspaces.insert(workspace, (project, principal));
    }
    if !workspaces.values().any(|(value, _)| *value == project_id) {
        // No Workspace relationship for this Project is valid only when no
        // TaskRun create receipt references an unknown Workspace; the caller's
        // receipt scan enforces that fail-closed condition.
    }
    Ok(workspaces)
}

fn task_run_is_terminal(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
) -> Result<bool, Error> {
    let version = transaction
        .query_row(
            "SELECT current_version FROM aggregate_streams
             WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::InvariantViolation)?;
    if version <= 0 {
        return Err(Error::InvariantViolation);
    }
    let mut statement = transaction
        .prepare(
            "SELECT sequence, payload FROM events
             WHERE aggregate_type = 1 AND aggregate_id = ?1 ORDER BY sequence ASC",
        )
        .map_err(|_| Error::Unavailable)?;
    let rows = statement
        .query_map([taskrun_id.as_bytes()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|_| Error::Unavailable)?;
    let mut terminal = false;
    let mut count = 0_i64;
    for row in rows {
        let (sequence, payload) = row.map_err(|_| Error::Unavailable)?;
        count += 1;
        if sequence != count || terminal {
            return Err(Error::InvariantViolation);
        }
        let event = TaskRunEventCodec
            .decode(&payload)
            .map_err(|_| Error::InvariantViolation)?;
        if count == 1 && event != TaskRunEvent::TaskRunCreated {
            return Err(Error::InvariantViolation);
        }
        terminal = matches!(
            event,
            TaskRunEvent::CancellationCompleted
                | TaskRunEvent::TaskRunCompleted { .. }
                | TaskRunEvent::TaskRunFailed { .. }
                | TaskRunEvent::BudgetExhausted
                | TaskRunEvent::PolicyDenied
                | TaskRunEvent::Unrecoverable
                | TaskRunEvent::TaskRunCancelled
        );
    }
    if count != version {
        return Err(Error::InvariantViolation);
    }
    Ok(terminal)
}
