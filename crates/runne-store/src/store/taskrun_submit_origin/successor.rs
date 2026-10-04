use super::*;
use runne_application::ports::{AggregateScope, OperationTag};
use runne_domain::task_run::TaskRunEvent;
type FirstTaskRunEventRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type SuccessorAdmissionIdentityRow = (
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
);

mod receipt;

/// Reads the immutable predecessor edge so callers can verify long histories iteratively.
pub(super) fn predecessor(
    connection: &Connection,
    taskrun_id: TaskRunId,
) -> Result<Option<TaskRunId>, CommitError> {
    let first: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT payload,command_id FROM events
         WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((payload, command)) = first else {
        return Ok(None);
    };
    let event = TaskRunEventCodec
        .decode(&payload)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !matches!(event, TaskRunEvent::TaskRunSubmitted { .. }) {
        return Ok(None);
    }
    let command = CommandId::from_bytes(fixed(command)?);
    let (scope, _, _, _) = super::submit_receipt(connection, command)?;
    if scope.operation != OperationTag::SupersedeUnknownTaskRun {
        return Ok(None);
    }
    let predecessor: Vec<u8> = connection.query_row(
        "SELECT predecessor_taskrun_id FROM taskrun_unknown_successor_receipts WHERE command_id=?1",
        [command.as_bytes()], |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(Some(TaskRunId::from_bytes(fixed(predecessor)?)))
}

/// Verifies the source-specific v57 receipt for a successor TaskRun origin.
pub(super) fn verify(
    connection: &Connection,
    taskrun_id: TaskRunId,
    expected_authority: Option<&RuntimeAuthorityId>,
    original: Option<&VerifiedTaskRunSubmitOrigin>,
) -> Result<Option<VerifiedTaskRunSubmitOrigin>, CommitError> {
    super::super::taskrun_claim::stream_validate::verify_stream(connection, taskrun_id, None)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let first: Option<FirstTaskRunEventRow> = connection
        .query_row(
            "SELECT payload,command_id,idempotency_key,actor FROM events
         WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((payload, command_bytes, key, actor_bytes)) = first else {
        return Ok(None);
    };
    let command_id = CommandId::from_bytes(fixed(command_bytes.clone())?);
    let event = TaskRunEventCodec
        .decode(&payload)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let TaskRunEvent::TaskRunSubmitted {
        conversation_id,
        workspace_id,
        input,
    } = event
    else {
        return Ok(None);
    };
    let (scope, receipt_key, fingerprint, outcome) = super::submit_receipt(connection, command_id)?;
    if scope.operation != OperationTag::SupersedeUnknownTaskRun {
        return Ok(None);
    }
    if receipt_key != key
        || expected_authority.is_some_and(|authority| scope.runtime_authority_id != *authority)
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let actor = Actor::new(
        String::from_utf8(actor_bytes)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
    )
    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let queued: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT command_id,idempotency_key,payload FROM events
         WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=2",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((queued_command, queued_key, queued_payload)) = queued else {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    };
    if queued_command != command_bytes
        || queued_key != key
        || TaskRunEventCodec
            .decode(&queued_payload)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
            != TaskRunEvent::TaskRunQueued
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let original =
        original.ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let project_id = receipt::verify_receipt(
        connection,
        receipt::SuccessorReceiptVerification {
            taskrun_id,
            conversation: conversation_id,
            workspace: workspace_id,
            input: &input,
            scope: &scope,
            command_id,
            key: &key,
            fingerprint: &fingerprint,
            outcome: &outcome,
            original,
        },
    )?;
    Ok(Some(VerifiedTaskRunSubmitOrigin {
        conversation_id,
        workspace_id,
        project_id: Some(project_id),
        input,
        principal_id: scope.principal_id,
        actor,
    }))
}

fn verify_historical_workspace(
    connection: &Connection,
    principal: &str,
    workspace: runne_domain::id::WorkspaceId,
    project: Option<&[u8]>,
) -> Result<(), CommitError> {
    let identity: Option<SuccessorAdmissionIdentityRow> = connection
        .query_row(
            "SELECT w.project_id,w.principal_id,h.project_id,h.principal_id,h.classification
         FROM workspaces w LEFT JOIN workspace_identity_history h ON h.workspace_id=w.workspace_id
         WHERE w.workspace_id=?1",
            [workspace.as_bytes()],
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
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if identity
        .as_ref()
        .is_none_or(|(found, owner, historic, historic_owner, kind)| {
            Some(found.as_slice()) != project
                || owner != principal
                || historic.as_deref() != project
                || historic_owner.as_deref() != Some(principal)
                || kind.as_deref() != Some("canonical")
        })
    {
        return Err(storage_failure(StorageFailureKind::PolicyDenied));
    }
    Ok(())
}

fn event_id(connection: &Connection, taskrun: TaskRunId) -> Result<[u8; 16], CommitError> {
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT event_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [taskrun.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    fixed(bytes)
}

fn fixed(bytes: Vec<u8>) -> Result<[u8; 16], CommitError> {
    bytes
        .try_into()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
    hash.finalize().into()
}

fn acknowledgement_digest() -> [u8; 32] {
    runne_application::commands::UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1
        .digest()
        .into_bytes()
}
