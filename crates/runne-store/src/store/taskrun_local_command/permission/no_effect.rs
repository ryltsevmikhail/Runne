use super::codec;
use crate::store::taskrun_claim;
use runne_application::ports::{EventStoreError, RuntimeAuthorityId, TaskRunAssignmentIdentity};
use runne_domain::{id::TaskRunId, task_run::TaskRunState};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

type OccupationRow = (Vec<u8>, Vec<u8>, i64, String, String, Option<Vec<u8>>);

pub(crate) fn current_route(
    connection: &Connection,
    taskrun_id: TaskRunId,
) -> Result<bool, EventStoreError> {
    let table: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='taskrun_local_permission_routes')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::Unavailable)?;
    if !table {
        return Ok(false);
    }
    let route: Option<(i64, i64, i64)> = connection
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    match route {
        Some((2, 3, 68)) => Ok(true),
        Some((1, 1, 68) | (1, 2, 68)) | None => Ok(false),
        Some(_) => Err(EventStoreError::CorruptData),
    }
}

pub(crate) fn pre_release_matches(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    authority: &RuntimeAuthorityId,
) -> Result<bool, EventStoreError> {
    release_proof_matches(connection, taskrun_id, attempt_id, authority, None, false)
}

pub(crate) fn marked_pre_release_matches(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
    authority: &RuntimeAuthorityId,
) -> Result<bool, EventStoreError> {
    release_proof_matches(
        connection,
        identity.taskrun_id,
        identity.attempt_id,
        authority,
        Some(identity),
        true,
    )
}

fn release_proof_matches(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    authority: &RuntimeAuthorityId,
    expected_identity: Option<&TaskRunAssignmentIdentity>,
    terminal_capture: bool,
) -> Result<bool, EventStoreError> {
    if !current_route(connection, taskrun_id)? {
        return Ok(false);
    }
    let capture = crate::store::test_support_diagnostics::on_error(
        "no_effect.capture",
        super::no_effect_capture::load_capture(
            connection,
            taskrun_id,
            Some(attempt_id),
            terminal_capture,
        ),
    )?;
    let Some((record, identity)) = capture else {
        return super::no_effect_precapture::release_proof_matches(
            connection,
            taskrun_id,
            attempt_id,
            authority,
            expected_identity,
            terminal_capture,
        );
    };
    if record.runtime_authority_id != authority.0
        || expected_identity.is_some_and(|expected| expected != &identity)
    {
        crate::store::test_support_diagnostics::record("no_effect.capture");
        return Ok(false);
    }
    if !crate::store::test_support_diagnostics::on_error(
        "no_effect.claim",
        claim_matches(connection, &identity, &record, false),
    )? {
        crate::store::test_support_diagnostics::record("no_effect.claim");
        return Ok(false);
    }
    if !crate::store::test_support_diagnostics::on_error(
        "no_effect.occupation",
        occupation_matches(connection, &identity, "active", None),
    )? {
        crate::store::test_support_diagnostics::record("no_effect.occupation");
        return Ok(false);
    }
    if crate::store::test_support_diagnostics::on_error(
        "no_effect.runtime_evidence",
        has_runtime_evidence(connection, &identity),
    )? || !crate::store::test_support_diagnostics::on_error(
        "no_effect.policy_stop",
        super::no_effect_policy_stop::allows_only_exact_reason2_claim_stop(
            connection, &identity, &record,
        ),
    )? {
        crate::store::test_support_diagnostics::record("no_effect.runtime_evidence");
        return Ok(false);
    }
    if crate::store::test_support_diagnostics::on_error(
        "no_effect.release",
        has_no_effect_release_receipt(connection, taskrun_id),
    )? {
        crate::store::test_support_diagnostics::record("no_effect.release");
        return Ok(false);
    }
    Ok(true)
}

pub(crate) fn settled_matches(
    connection: &Connection,
    taskrun_id: TaskRunId,
) -> Result<bool, EventStoreError> {
    if !current_route(connection, taskrun_id)? {
        return Ok(false);
    }
    let receipt: Option<(Vec<u8>, i64, Vec<u8>, i64)> = connection
        .query_row(
            "SELECT attempt_id,fence,failure_event_id,new_version FROM taskrun_no_effect_release_receipts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((attempt, fence, event, version)) = receipt else {
        return Ok(false);
    };
    let attempt_id = runne_domain::id::AttemptId::from_bytes(
        attempt
            .as_slice()
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?,
    );
    let event_id: [u8; 16] = event
        .as_slice()
        .try_into()
        .map_err(|_| EventStoreError::CorruptData)?;
    let capture =
        super::no_effect_capture::load_capture(connection, taskrun_id, Some(attempt_id), true)?;
    let Some((record, identity)) = capture else {
        return super::no_effect_precapture::settled_matches(
            connection,
            taskrun_id,
            attempt_id,
            u64::try_from(fence).map_err(|_| EventStoreError::CorruptData)?,
            &event_id,
            u64::try_from(version).map_err(|_| EventStoreError::CorruptData)?,
        );
    };
    if identity.fence.0 != u64::try_from(fence).map_err(|_| EventStoreError::CorruptData)?
        || !claim_matches(connection, &identity, &record, true)?
        || !occupation_matches(connection, &identity, "released", Some(&event_id))?
        || has_runtime_evidence(connection, &identity)?
        || !super::no_effect_policy_stop::allows_only_exact_reason2_claim_stop(
            connection, &identity, &record,
        )?
    {
        return Ok(false);
    }
    let stream = taskrun_claim::stream_validate::verify_stream(connection, taskrun_id, None)
        .map_err(|_| EventStoreError::CorruptData)?;
    let last = stream.events.last().ok_or(EventStoreError::CorruptData)?;
    Ok(stream.state == TaskRunState::Failed
        && stream.active_attempt.is_none()
        && stream.version == u64::try_from(version).map_err(|_| EventStoreError::CorruptData)?
        && last.event_id().as_bytes() == &event_id
        && matches!(last.payload(), runne_domain::task_run::TaskRunEvent::TaskRunFailed { reason } if reason == "dispatch_not_started"))
}

fn claim_matches(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
    record: &codec::CaptureV1,
    terminal: bool,
) -> Result<bool, EventStoreError> {
    let task = taskrun_claim::verify_assignment_history(connection, identity)
        .map_err(|_| EventStoreError::CorruptData)?;
    let stream =
        taskrun_claim::stream_validate::verify_stream(connection, identity.taskrun_id, None)
            .map_err(|_| EventStoreError::CorruptData)?;
    let version: Option<i64> = connection.query_row(
        "SELECT new_version FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3",
        params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.fence.0 as i64],
        |row| row.get(0),
    ).optional().map_err(|_| EventStoreError::CorruptData)?;
    Ok(version == i64::try_from(record.claim_stream_version).ok()
        && if terminal {
            task.state() == TaskRunState::Failed && task.active_attempt().is_none()
        } else {
            task.state() == TaskRunState::Running
                && task.active_attempt() == Some(&identity.attempt_id)
                && stream.version == record.claim_stream_version
        })
}

pub(super) fn occupation_matches(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
    state: &str,
    release_event: Option<&[u8; 16]>,
) -> Result<bool, EventStoreError> {
    let row: Option<OccupationRow> = connection.query_row(
        "SELECT attempt_id,node_id,node_epoch,state,dispatch_intent,release_event_id FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
        params![identity.taskrun_id.as_bytes(),identity.fence.0 as i64],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
    ).optional().map_err(|_| EventStoreError::CorruptData)?;
    Ok(
        row.is_some_and(|(attempt, node, epoch, saved, intent, event)| {
            attempt.as_slice() == identity.attempt_id.as_bytes()
                && uuid::Uuid::parse_str(&identity.node_id.0)
                    .is_ok_and(|id| node.as_slice() == id.as_bytes())
                && epoch == identity.node_epoch as i64
                && saved == state
                && intent == "absent"
                && event.as_deref() == release_event.map(|value| value.as_slice())
        }),
    )
}

pub(super) fn has_runtime_evidence(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
) -> Result<bool, EventStoreError> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM x2_permission_spent WHERE taskrun_id=?1 AND attempt_id=?2)
          OR EXISTS(SELECT 1 FROM x2_permission_terminal WHERE taskrun_id=?1 AND attempt_id=?2)
          OR EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?3)
          OR EXISTS(SELECT 1 FROM taskrun_provider_bindings WHERE taskrun_id=?1)
          OR EXISTS(SELECT 1 FROM provider_execution_admissions WHERE taskrun_id=?1)
          OR EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1 AND fence=?3)",
        params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.fence.0 as i64],
        |row| row.get(0),
    ).map_err(|_| EventStoreError::CorruptData)
}

pub(super) fn has_no_effect_release_receipt(
    connection: &Connection,
    taskrun_id: TaskRunId,
) -> Result<bool, EventStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE taskrun_id=?1)",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)
}

pub(crate) fn mark_terminal(
    tx: &Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    node: &uuid::Uuid,
    now: i64,
) -> Result<usize, EventStoreError> {
    let precapture = super::no_effect_precapture::mark_terminal(tx, identity, node, now)?;
    if precapture != 0 {
        return Ok(precapture);
    }
    tx.execute(
        "UPDATE taskrun_local_command_attempts SET state='no_effect_terminal',updated_at=?1
         WHERE taskrun_id=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND fence=?6
           AND state IN ('approval_pending','approved') AND managed_area_identity IS NULL
           AND stdout=X'' AND stderr=X'' AND exit_code IS NULL",
        params![
            now,
            identity.taskrun_id.as_bytes(),
            identity.attempt_id.as_bytes(),
            node.as_bytes(),
            identity.node_epoch as i64,
            identity.fence.0 as i64
        ],
    )
    .map_err(|_| EventStoreError::CorruptData)
}
