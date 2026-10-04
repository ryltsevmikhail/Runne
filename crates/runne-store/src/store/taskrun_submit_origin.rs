use super::parse_helpers::storage_failure;
use super::*;
use runne_application::ports::{PrincipalId, RuntimeAuthorityId};
use runne_domain::id::ProjectId;
use runne_domain::task_run::TaskRunInput;

mod remote_terminal_source;
mod successor;
pub(crate) use remote_terminal_source::{
    RemoteTerminalTaskRunApplicability, VerifiedRemoteTerminalTaskRunSource,
    verify_remote_terminal_taskrun_source,
};

/// Immutable facts proven by a v2 submit event, its exact command receipt, and lineage.
#[derive(Clone)]
pub(crate) struct VerifiedTaskRunSubmitOrigin {
    pub(crate) conversation_id: ConversationId,
    pub(crate) workspace_id: runne_domain::id::WorkspaceId,
    pub(crate) project_id: Option<ProjectId>,
    pub(crate) input: TaskRunInput,
    pub(crate) principal_id: PrincipalId,
    pub(crate) actor: Actor,
}

type OriginEventRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type SubmitReceiptRow = (IdempotencyScope, Vec<u8>, Vec<u8>, Vec<u8>);

/// Proves a v2 SubmitTaskRun origin. Historical/manual TaskRunCreated origins
/// return `None`; their separate contracts must remain valid without a submit receipt.
pub(crate) fn verify_submitted_v2_origin(
    connection: &Connection,
    taskrun_id: TaskRunId,
    expected_authority: &RuntimeAuthorityId,
) -> Result<Option<VerifiedTaskRunSubmitOrigin>, CommitError> {
    verify_origin(connection, taskrun_id, Some(expected_authority))
}

/// Validates the immutable historical submit receipt without asserting a
/// current runtime owner; schema readiness uses it only to prove local origin.
pub(crate) fn verify_submitted_v2_origin_for_readiness(
    connection: &Connection,
    taskrun_id: TaskRunId,
) -> Result<Option<VerifiedTaskRunSubmitOrigin>, CommitError> {
    verify_origin(connection, taskrun_id, None)
}

fn verify_origin(
    connection: &Connection,
    taskrun_id: TaskRunId,
    expected_authority: Option<&RuntimeAuthorityId>,
) -> Result<Option<VerifiedTaskRunSubmitOrigin>, CommitError> {
    let mut cursor = taskrun_id;
    let mut successors = Vec::new();
    let mut seen = Vec::new();
    while let Some(predecessor) = successor::predecessor(connection, cursor)? {
        if seen.contains(&cursor) || seen.contains(&predecessor) {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        seen.push(cursor);
        successors.push(cursor);
        cursor = predecessor;
    }
    let root_authority = if successors.is_empty() {
        expected_authority
    } else {
        None
    };
    let Some(mut origin) = verify_submitted_v2_origin_inner(connection, cursor, root_authority)?
    else {
        return Ok(None);
    };
    for successor_id in successors.into_iter().rev() {
        let authority = (successor_id == taskrun_id)
            .then_some(expected_authority)
            .flatten();
        origin = successor::verify(connection, successor_id, authority, Some(&origin))?
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    }
    Ok(Some(origin))
}

fn verify_submitted_v2_origin_inner(
    connection: &Connection,
    taskrun_id: TaskRunId,
    expected_authority: Option<&RuntimeAuthorityId>,
) -> Result<Option<VerifiedTaskRunSubmitOrigin>, CommitError> {
    super::taskrun_claim::stream_validate::verify_stream(connection, taskrun_id, None)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let (payload, command_bytes, key, actor_bytes): OriginEventRow = connection
        .query_row(
            "SELECT payload,command_id,idempotency_key,actor FROM events
             WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let command_id = CommandId::from_bytes(
        command_bytes
            .as_slice()
            .try_into()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
    );
    let actor = Actor::new(
        String::from_utf8(actor_bytes)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
    )
    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
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
    let (queued_command, queued_key, queued_payload): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT command_id,idempotency_key,payload FROM events
             WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=2",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if queued_command != command_bytes
        || queued_key != key
        || TaskRunEventCodec
            .decode(&queued_payload)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
            != TaskRunEvent::TaskRunQueued
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let (scope, stored_key, fingerprint, outcome) = submit_receipt(connection, command_id)?;
    if stored_key != key
        || expected_authority.is_some_and(|authority| scope.runtime_authority_id != *authority)
        || scope.operation != OperationTag::SubmitTaskRun
        || !matches!(scope.aggregate_scope,
            AggregateScope::NewTaskRun { conversation_id: c, workspace_id: w }
                if c == conversation_id && w == workspace_id)
        || fingerprint.as_slice()
            != CommandFingerprint::for_submit(&conversation_id, &workspace_id, &input)
                .as_bytes()
                .as_slice()
        || CommandOutcomeCodec
            .decode(&outcome)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
            != (runne_application::commands::CommandOutcome::TaskRunSubmitted {
                taskrun_id,
                new_version: 2,
            })
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    crate::project_workspace::lineage::validate_direct_taskrun_lineage(
        connection, &scope, taskrun_id, command_id,
    )?;
    let project: Option<Vec<u8>> = connection
        .query_row(
            "SELECT project_id FROM task_run_workspace_lineage
         WHERE taskrun_id=?1 AND classification='canonical' AND origin_operation=20",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let project_id = project
        .map(|bytes| {
            let bytes: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            Ok::<_, CommitError>(ProjectId::from_bytes(bytes))
        })
        .transpose()?;
    Ok(Some(VerifiedTaskRunSubmitOrigin {
        conversation_id,
        workspace_id,
        project_id,
        input,
        principal_id: scope.principal_id,
        actor,
    }))
}

fn submit_receipt(
    connection: &Connection,
    command_id: CommandId,
) -> Result<SubmitReceiptRow, CommitError> {
    let (scope_bytes, key, fingerprint, outcome): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
             FROM command_receipts WHERE command_id=?1",
            [command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    Ok((scope, key, fingerprint, outcome))
}
