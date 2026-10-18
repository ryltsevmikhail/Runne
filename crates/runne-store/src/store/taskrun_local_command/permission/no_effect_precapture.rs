use super::no_effect;
use runne_application::ports::{
    EventStoreError, ExecutionNodeId, RuntimeAuthorityId, TaskRunAssignmentIdentity, TaskRunFence,
};
use runne_domain::{
    id::{AttemptId, TaskRunId},
    task_run::TaskRunState,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

type ProofResult = Result<bool, EventStoreError>;

pub(super) fn release_proof_matches(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    authority: &RuntimeAuthorityId,
    expected: Option<&TaskRunAssignmentIdentity>,
    marked: bool,
) -> Result<bool, EventStoreError> {
    if !no_effect::current_route(connection, taskrun_id)?
        || marked != expected.is_some()
        || no_effect::has_no_effect_release_receipt(connection, taskrun_id)?
    {
        return Ok(false);
    }
    let Some((identity, claim_version)) = load_identity(connection, taskrun_id, attempt_id)? else {
        return Ok(false);
    };
    if expected.is_some_and(|value| value != &identity)
        || !claim_matches(connection, &identity, claim_version, None)?
        || !local_row_matches(
            connection,
            &identity,
            Some(authority),
            if marked {
                "no_effect_terminal"
            } else {
                "preflight"
            },
            !marked,
        )?
        || !no_effect::occupation_matches(connection, &identity, "active", None)?
        || no_effect::has_runtime_evidence(connection, &identity)?
        || has_extra_effect(connection, taskrun_id)?
    {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn settled_matches(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    fence: u64,
    event_id: &[u8; 16],
    release_version: u64,
) -> Result<bool, EventStoreError> {
    if !no_effect::current_route(connection, taskrun_id)? {
        return Ok(false);
    }
    let Some((identity, claim_version)) = load_identity(connection, taskrun_id, attempt_id)? else {
        return Ok(false);
    };
    if identity.fence.0 != fence
        || !claim_matches(
            connection,
            &identity,
            claim_version,
            Some((event_id, release_version)),
        )?
        || !local_row_matches(connection, &identity, None, "no_effect_terminal", false)?
        || !no_effect::occupation_matches(connection, &identity, "released", Some(event_id))?
        || no_effect::has_runtime_evidence(connection, &identity)?
        || has_extra_effect(connection, taskrun_id)?
        || !has_exact_release_receipt(connection, &identity, event_id, release_version)?
    {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn mark_terminal(
    tx: &Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    node: &uuid::Uuid,
    now: i64,
) -> Result<usize, EventStoreError> {
    let epoch = i64::try_from(identity.node_epoch).map_err(|_| EventStoreError::CorruptData)?;
    let fence = i64::try_from(identity.fence.0).map_err(|_| EventStoreError::CorruptData)?;
    if uuid::Uuid::parse_str(&identity.node_id.0).ok() != Some(*node) {
        return Err(EventStoreError::CorruptData);
    }
    tx.execute(
        "UPDATE taskrun_local_command_attempts
         SET attempt_id=?1,node_id=?2,node_epoch=?3,fence=?4,state='no_effect_terminal',updated_at=?5
         WHERE taskrun_id=?6 AND state='preflight' AND attempt_id IS NULL AND node_id IS NULL
           AND node_epoch IS NULL AND fence IS NULL AND executable_digest IS NULL
           AND workspace_version IS NULL AND admitted_root_version IS NULL
           AND admitted_root_identity IS NULL AND trust_epoch IS NULL AND trust_revision IS NULL
           AND source_policy_version IS NULL AND command_policy_version IS NULL
           AND approval_id IS NULL AND managed_area_identity IS NULL
           AND stdout=X'' AND stderr=X'' AND exit_code IS NULL
           AND EXISTS(SELECT 1 FROM taskrun_local_permission_routes r
             WHERE r.taskrun_id=taskrun_local_command_attempts.taskrun_id
               AND r.route=2 AND r.provenance=3 AND r.cutover_version=68)
           AND NOT EXISTS(SELECT 1 FROM x2_permission_bindings WHERE taskrun_id=?6)
           AND NOT EXISTS(SELECT 1 FROM x2_permission_human WHERE taskrun_id=?6)
           AND NOT EXISTS(SELECT 1 FROM x2_permission_admission WHERE taskrun_id=?6)
           AND NOT EXISTS(SELECT 1 FROM x2_permission_spent WHERE taskrun_id=?6)
           AND NOT EXISTS(SELECT 1 FROM x2_permission_stop WHERE taskrun_id=?6)
           AND NOT EXISTS(SELECT 1 FROM x2_permission_terminal WHERE taskrun_id=?6)",
        params![
            identity.attempt_id.as_bytes(),
            node.as_bytes(),
            epoch,
            fence,
            now,
            identity.taskrun_id.as_bytes(),
        ],
    )
    .map_err(|_| EventStoreError::CorruptData)
}

fn load_identity(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) -> Result<Option<(TaskRunAssignmentIdentity, u64)>, EventStoreError> {
    let row: Option<(Vec<u8>, i64, i64, i64)> = connection
        .query_row(
            "SELECT node_id,node_epoch,fence,new_version FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2
               AND (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2)=1",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((node_bytes, epoch, fence, version)) = row else {
        return Ok(None);
    };
    let Ok(node) = <[u8; 16]>::try_from(node_bytes.as_slice()) else {
        return Ok(None);
    };
    let parsed = uuid::Uuid::from_bytes(node);
    let (Ok(node_epoch), Ok(fence), Ok(claim_version)) = (
        u64::try_from(epoch),
        u64::try_from(fence),
        u64::try_from(version),
    ) else {
        return Ok(None);
    };
    if parsed.is_nil() || node_epoch == 0 || fence == 0 || claim_version == 0 {
        return Ok(None);
    }
    Ok(Some((
        TaskRunAssignmentIdentity {
            taskrun_id,
            attempt_id,
            node_id: ExecutionNodeId(parsed.to_string()),
            node_epoch,
            fence: TaskRunFence(fence),
        },
        claim_version,
    )))
}

fn claim_matches(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
    claim_version: u64,
    release: Option<(&[u8; 16], u64)>,
) -> Result<bool, EventStoreError> {
    let task = crate::store::taskrun_claim::verify_assignment_history(connection, identity)
        .map_err(|_| EventStoreError::CorruptData)?;
    let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        connection,
        identity.taskrun_id,
        None,
    )
    .map_err(|_| EventStoreError::CorruptData)?;
    if let Some((event_id, version)) = release {
        let Some(last) = stream.events.last() else {
            return Ok(false);
        };
        Ok(claim_version.checked_add(1) == Some(version)
            && stream.version == version
            && task.state() == TaskRunState::Failed
            && task.active_attempt().is_none()
            && last.event_id().as_bytes() == event_id
            && matches!(last.payload(), runne_domain::task_run::TaskRunEvent::TaskRunFailed { reason } if reason == "dispatch_not_started"))
    } else {
        Ok(stream.version == claim_version
            && task.state() == TaskRunState::Running
            && task.active_attempt() == Some(&identity.attempt_id))
    }
}

fn local_row_matches(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
    authority: Option<&RuntimeAuthorityId>,
    state: &str,
    unbound: bool,
) -> Result<bool, EventStoreError> {
    let origin = match authority {
        Some(authority) => crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
            connection,
            identity.taskrun_id,
            authority,
        ),
        None => crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
            connection,
            identity.taskrun_id,
        ),
    }
    .map_err(|_| EventStoreError::CorruptData)?;
    let Some(origin) = origin else {
        return Ok(false);
    };
    let Some(command) = origin.input.local_command() else {
        return Ok(false);
    };
    let node =
        uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| EventStoreError::CorruptData)?;
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_attempts a
             JOIN taskrun_local_permission_routes r USING(taskrun_id)
             WHERE a.taskrun_id=?1 AND a.conversation_id=?2 AND a.workspace_id=?3
               AND a.command_digest=?4 AND a.state=?10
               AND ((?5=1 AND a.attempt_id IS NULL AND a.node_id IS NULL
                     AND a.node_epoch IS NULL AND a.fence IS NULL)
                 OR (?5=0 AND a.attempt_id=?6 AND a.node_id=?7
                     AND a.node_epoch=?8 AND a.fence=?9))
               AND a.executable_digest IS NULL AND a.workspace_version IS NULL
               AND a.admitted_root_version IS NULL AND a.admitted_root_identity IS NULL
               AND a.trust_epoch IS NULL AND a.trust_revision IS NULL
               AND a.source_policy_version IS NULL AND a.command_policy_version IS NULL
               AND a.approval_id IS NULL AND a.managed_area_identity IS NULL
               AND a.stdout=X'' AND a.stderr=X'' AND a.exit_code IS NULL
               AND r.route=2 AND r.provenance=3 AND r.cutover_version=68
               AND NOT EXISTS(SELECT 1 FROM x2_permission_bindings WHERE taskrun_id=?1)
               AND NOT EXISTS(SELECT 1 FROM x2_permission_human WHERE taskrun_id=?1)
               AND NOT EXISTS(SELECT 1 FROM x2_permission_admission WHERE taskrun_id=?1)
               AND NOT EXISTS(SELECT 1 FROM x2_permission_spent WHERE taskrun_id=?1)
               AND NOT EXISTS(SELECT 1 FROM x2_permission_stop WHERE taskrun_id=?1)
               AND NOT EXISTS(SELECT 1 FROM x2_permission_terminal WHERE taskrun_id=?1))",
            params![
                identity.taskrun_id.as_bytes(),
                origin.conversation_id.as_bytes(),
                origin.workspace_id.as_bytes(),
                command.intent_digest().as_slice(),
                if unbound { 1_i64 } else { 0_i64 },
                identity.attempt_id.as_bytes(),
                node.as_bytes(),
                i64::try_from(identity.node_epoch).map_err(|_| EventStoreError::CorruptData)?,
                i64::try_from(identity.fence.0).map_err(|_| EventStoreError::CorruptData)?,
                state,
            ],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)
}

fn has_extra_effect(connection: &Connection, taskrun_id: TaskRunId) -> ProofResult {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1)
              OR EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1)",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)
}

fn has_exact_release_receipt(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
    event_id: &[u8; 16],
    version: u64,
) -> Result<bool, EventStoreError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_no_effect_release_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3
               AND failure_event_id=?4 AND new_version=?5",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes(),
                i64::try_from(identity.fence.0).map_err(|_| EventStoreError::CorruptData)?,
                event_id.as_slice(),
                i64::try_from(version).map_err(|_| EventStoreError::CorruptData)?,
            ],
            |row| row.get::<_, i64>(0).map(|count| count == 1),
        )
        .map_err(|_| EventStoreError::CorruptData)
}
