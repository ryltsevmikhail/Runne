use runne_application::ports::{
    AggregateScope, CommitError, OperationTag, StorageFailureKind, UnknownSuccessorCommit,
};
use runne_domain::id::ProjectId;
use rusqlite::{OptionalExtension, Transaction};

type UnknownSuccessorOwnerRow = (
    Vec<u8>,
    String,
    i64,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
);
type UnknownSuccessorOriginRow = (Vec<u8>, Vec<u8>, Vec<u8>, String, i64);

pub(super) fn canonical_origin(
    tx: &Transaction<'_>,
    origin: &crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin,
    payload: &UnknownSuccessorCommit,
) -> Result<ProjectId, CommitError> {
    if payload.idempotency_scope.operation != OperationTag::SupersedeUnknownTaskRun
        || payload.idempotency_scope.aggregate_scope
            != (AggregateScope::ExistingTaskRun {
                taskrun_id: payload.predecessor_taskrun_id,
            })
    {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let verified_project = origin
        .project_id
        .ok_or_else(|| fail(StorageFailureKind::PolicyDenied))?;
    let row: Option<(Vec<u8>, Vec<u8>, String, i64)> = tx
        .query_row(
            "SELECT workspace_id,project_id,classification,origin_operation
             FROM task_run_workspace_lineage WHERE taskrun_id=?1",
            [payload.predecessor_taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let project = match row {
        Some((workspace, project, classification, operation)) => {
            if classification != "canonical"
                || operation != OperationTag::SubmitTaskRun as i64
                || workspace.as_slice() != origin.workspace_id.as_bytes()
            {
                return Err(fail(StorageFailureKind::PolicyDenied));
            }
            ProjectId::from_bytes(parse_id(project)?)
        }
        None => verified_successor_project(tx, payload.predecessor_taskrun_id, origin)?,
    };
    if project != verified_project {
        return Err(fail(StorageFailureKind::IntegrityViolation));
    }
    let owner: Option<UnknownSuccessorOwnerRow> = tx
        .query_row(
            "SELECT w.project_id,w.principal_id,w.live,
                    h.project_id,h.principal_id,h.classification
             FROM workspaces w
             LEFT JOIN workspace_identity_history h ON h.workspace_id=w.workspace_id
             WHERE w.workspace_id=?1",
            [origin.workspace_id.as_bytes()],
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
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if owner.as_ref().is_none_or(
        |(found_project, principal, live, history_project, history_principal, kind)| {
            found_project.as_slice() != project.as_bytes()
                || principal != &origin.principal_id.0
                || *live != 1
                || history_project.as_deref() != Some(project.as_bytes())
                || history_principal.as_deref() != Some(origin.principal_id.0.as_str())
                || kind.as_deref() != Some("canonical")
        },
    ) {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    Ok(project)
}

fn verified_successor_project(
    tx: &Transaction<'_>,
    taskrun_id: runne_domain::id::TaskRunId,
    origin: &crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin,
) -> Result<ProjectId, CommitError> {
    let row: Option<UnknownSuccessorOriginRow> = tx
        .query_row(
            "SELECT conversation_id,workspace_id,project_id,principal_id,origin_operation
             FROM taskrun_unknown_successor_receipts WHERE successor_taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let Some((conversation, workspace, project, principal, operation)) = row else {
        return Err(fail(StorageFailureKind::PolicyDenied));
    };
    if operation != OperationTag::SupersedeUnknownTaskRun as i64
        || conversation.as_slice() != origin.conversation_id.as_bytes()
        || workspace.as_slice() != origin.workspace_id.as_bytes()
        || principal != origin.principal_id.0
    {
        return Err(fail(StorageFailureKind::IntegrityViolation));
    }
    Ok(ProjectId::from_bytes(parse_id(project)?))
}

fn parse_id(bytes: Vec<u8>) -> Result<[u8; 16], CommitError> {
    bytes
        .try_into()
        .map_err(|_| fail(StorageFailureKind::CorruptData))
}

fn fail(kind: StorageFailureKind) -> CommitError {
    CommitError::StorageFailure(kind)
}
