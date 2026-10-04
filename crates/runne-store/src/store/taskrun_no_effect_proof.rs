use super::*;
use runne_application::ports::RuntimeAuthorityId;
use runne_application::ports::{EventStoreError, TaskRunNoEffectReleaseError as ReleaseError};

pub(super) fn authenticated_local_denial(
    connection: &Connection,
    taskrun_id: TaskRunId,
) -> Result<bool, EventStoreError> {
    type LocalRow = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<i64>,
        Option<Vec<u8>>,
    );
    let local: Option<LocalRow> = connection
        .query_row(
            "SELECT conversation_id,workspace_id,command_digest,attempt_id,node_id,managed_area_identity,node_epoch,fence,approval_id
             FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND state='denied' AND exit_code IS NULL",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::Unavailable)?;
    let Some((conversation, workspace, digest, attempt, node, area, epoch, fence, approval)) =
        local
    else {
        return Ok(false);
    };
    let (Some(approval), None, None, None, None, None) =
        (approval, attempt, node, area, epoch, fence)
    else {
        return Ok(false);
    };
    let Some(origin) = super::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
        connection, taskrun_id,
    )
    .map_err(|_| EventStoreError::CorruptData)?
    else {
        return Ok(false);
    };
    let Some(command) = origin.input.local_command() else {
        return Ok(false);
    };
    if approval.len() != 16
        || approval == [0; 16]
        || digest.as_slice() != command.intent_digest()
        || conversation.as_slice() != origin.conversation_id.as_bytes()
        || workspace.as_slice() != origin.workspace_id.as_bytes()
    {
        return Ok(false);
    }
    let approval_id = uuid::Uuid::from_slice(&approval)
        .map_err(|_| EventStoreError::CorruptData)?
        .to_string();
    let taskrun = taskrun_id.to_string();
    let match_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM approvals WHERE approval_id=?1 AND task_run_id=?2
             AND attempt_id IS NULL AND principal_id=?3 AND action='local_command.execute'
             AND ((state=3 AND decision=2) OR state IN (4,5))",
            rusqlite::params![approval_id, taskrun, origin.principal_id.0],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::Unavailable)?;
    Ok(match_count == 1)
}

/// Proves that a claimed submission never began canonical text generation.
/// The caller holds a read snapshot or an immediate write transaction so the
/// conversation history and receipts are checked against one SQLite view.
pub(super) fn has_generation_evidence(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    authority: &RuntimeAuthorityId,
) -> Result<bool, EventStoreError> {
    let local_state: Option<String> = connection
        .query_row(
            "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| EventStoreError::Unavailable)?;
    if local_state.as_deref() == Some("denied") {
        return Ok(!authenticated_local_denial(connection, taskrun_id)?);
    }
    let local_may_have_started: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_attempts
              WHERE taskrun_id=?1 AND NOT (
                state IN ('preflight','approval_pending','approved','no_effect_terminal')
                AND attempt_id IS NULL AND managed_area_identity IS NULL
              ))",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::Unavailable)?;
    if local_may_have_started {
        // A launch-intent row is durable before the trusted child is created,
        // so every bound/launch state remains a possible effect after a crash.
        return Ok(true);
    }
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let submitted = TaskRunEventCodec
        .decode(&payload)
        .map_err(|_| EventStoreError::CorruptData)?;
    let conversation_id = match submitted {
        TaskRunEvent::TaskRunSubmitted { .. } => {
            super::taskrun_submit_origin::verify_submitted_v2_origin(
                connection, taskrun_id, authority,
            )
            .map_err(|_| EventStoreError::CorruptData)?
            .ok_or(EventStoreError::CorruptData)?
            .conversation_id
        }
        _ => return Err(EventStoreError::CorruptData),
    };
    let conversation =
        super::conversation::load_conversation_from_connection(connection, conversation_id)
            .map_err(|_| EventStoreError::CorruptData)?;
    let began = conversation.events.iter().any(|event| {
        matches!(
            event.payload(),
            ConversationEvent::UserMessageAppended {
                taskrun_id: stored_taskrun,
                attempt_id: stored_attempt,
                ..
            } if *stored_taskrun == taskrun_id && *stored_attempt == attempt_id
        )
    });
    if began {
        return Ok(true);
    }
    has_generation_receipt(connection, conversation_id, taskrun_id, attempt_id)
}

fn has_generation_receipt(
    connection: &Connection,
    conversation_id: ConversationId,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) -> Result<bool, EventStoreError> {
    // ExistingConversation scopes end with tag 0x03 and the raw conversation
    // ID, allowing this bounded per-conversation lookup without scanning every
    // command receipt in the database.
    let mut statement = connection
        .prepare(
            "SELECT idempotency_scope_bytes,command_outcome FROM command_receipts
             WHERE substr(idempotency_scope_bytes,-17,1)=X'03'
               AND substr(idempotency_scope_bytes,-16)=?1",
        )
        .map_err(|_| EventStoreError::Unavailable)?;
    let rows = statement
        .query_map([conversation_id.as_bytes()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|_| EventStoreError::Unavailable)?;
    for row in rows {
        let (scope_bytes, outcome_bytes) = row.map_err(|_| EventStoreError::CorruptData)?;
        let scope = IdempotencyScopeCodec
            .decode(&scope_bytes)
            .map_err(|_| EventStoreError::CorruptData)?;
        if scope.operation != OperationTag::GenerateConversationText
            || scope.aggregate_scope != (AggregateScope::ExistingConversation { conversation_id })
        {
            continue;
        }
        let receipt = TextGenerationReceiptCodec
            .decode(&outcome_bytes)
            .map_err(|_| EventStoreError::CorruptData)?;
        if receipt.conversation_id != conversation_id {
            return Err(EventStoreError::CorruptData);
        }
        if receipt.taskrun_id == taskrun_id && receipt.attempt_id == attempt_id {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn require_no_generation_evidence(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    authority: &RuntimeAuthorityId,
) -> Result<(), ReleaseError> {
    match has_generation_evidence(connection, taskrun_id, attempt_id, authority) {
        Ok(false) => Ok(()),
        Ok(true) => Err(ReleaseError::DispatchMayHaveStarted),
        Err(_) => Err(ReleaseError::CorruptData),
    }
}
