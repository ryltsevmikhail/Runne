use crate::codec::{
    CommandOutcomeCodec as RetainedCommandOutcomeCodec,
    IdempotencyScopeCodec as RetainedIdempotencyScopeCodec,
    TaskRunEventCodec as RetainedTaskRunEventCodec,
};
use runne_application::fingerprint::CommandFingerprint as RetainedCommandFingerprint;
use runne_application::ports::{
    AggregateScope as RetainedAggregateScope, OperationTag as RetainedOperationTag,
};
use runne_domain::task_run::TaskRunEvent as RetainedTaskRunEvent;
use sha2::Sha256 as RetainedSha256;

type RetainedEventRow = (i64, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>, Vec<u8>);
type RetainedReceiptRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn retained_legacy_bound_matches(
    connection: &Connection,
    taskrun_id: &[u8],
    state: &str,
) -> SqliteResult<bool> {
    let Some(facts) = v68_legacy_binding_facts(connection, taskrun_id)? else {
        return Ok(false);
    };
    if facts.state != state {
        return Ok(false);
    }
    match state {
        "denied" => {
            let Ok(id) = <[u8; 16]>::try_from(taskrun_id) else {
                return Ok(false);
            };
            crate::store::authenticated_local_denial(
                connection,
                runne_domain::id::TaskRunId::from_bytes(id),
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)
        }
        "no_effect_terminal" => {
            if v68_legacy_terminal_matches(connection, taskrun_id, state)? {
                return Ok(true);
            }
            retained_queued_cancellation_matches(connection, taskrun_id, &facts.origin)
        }
        "approval_pending" | "approved" | "launch_intent" | "release_reserved" | "running"
        | "cancel_requested" | "stop_unconfirmed" | "outcome_unknown" | "completed"
        | "cancelled" => Ok(true),
        _ => Ok(false),
    }
}

fn retained_queued_cancellation_matches(
    connection: &Connection,
    taskrun_bytes: &[u8],
    origin: &crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin,
) -> SqliteResult<bool> {
    let Ok(id) = <[u8; 16]>::try_from(taskrun_bytes) else {
        return Ok(false);
    };
    let taskrun_id = runne_domain::id::TaskRunId::from_bytes(id);
    let local_is_unbound: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM taskrun_local_command_attempts
            WHERE taskrun_id=?1 AND state='no_effect_terminal'
              AND attempt_id IS NULL AND node_id IS NULL AND node_epoch IS NULL
              AND fence IS NULL AND managed_area_identity IS NULL AND exit_code IS NULL
              AND length(stdout)=0 AND length(stderr)=0
        )",
        [taskrun_bytes],
        |row| row.get(0),
    )?;
    if !local_is_unbound {
        return Ok(false);
    }
    let occupation_evidence: i64 = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM taskrun_fence_counters WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_dispatch_intents WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_provider_bindings WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_provider_round_bindings WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM provider_execution_admissions WHERE taskrun_id=?1)",
        [taskrun_bytes],
        |row| row.get(0),
    )?;
    if occupation_evidence != 0 {
        return Ok(false);
    }

    let mut statement = connection.prepare(
        "SELECT sequence,event_id,causation_id,command_id,payload,idempotency_key FROM events
         WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
    )?;
    let events: Vec<RetainedEventRow> = statement
        .query_map([taskrun_bytes], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?
        .collect::<SqliteResult<_>>()?;
    if events.len() != 4
        || events
            .iter()
            .enumerate()
            .any(|(index, event)| event.0 != index as i64 + 1)
        || events[1].2.as_deref() != Some(events[0].1.as_slice())
        || events[2].2.as_deref() != Some(events[1].1.as_slice())
        || events[3].2.as_deref() != Some(events[2].1.as_slice())
        || events[0].3 != events[1].3
        || events[0].5 != events[1].5
        || events[2].3 == events[3].3
    {
        return Ok(false);
    }
    let payloads = events
        .iter()
        .map(|event| RetainedTaskRunEventCodec.decode(&event.4))
        .collect::<Result<Vec<_>, _>>();
    let Ok(payloads) = payloads else {
        return Ok(false);
    };
    if !matches!(
        &payloads[0],
        RetainedTaskRunEvent::TaskRunSubmitted { conversation_id, workspace_id, .. }
            if *conversation_id == origin.conversation_id && *workspace_id == origin.workspace_id
    ) || payloads[1] != RetainedTaskRunEvent::TaskRunQueued
        || payloads[2] != RetainedTaskRunEvent::CancellationRequested
        || payloads[3] != RetainedTaskRunEvent::CancellationCompleted
    {
        return Ok(false);
    }
    let head: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT current_version,last_event_id FROM aggregate_streams
             WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_bytes],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if head != Some((4, events[3].1.clone())) {
        return Ok(false);
    }
    let Some(submit_authority) = retained_submitted_authority(connection, taskrun_bytes, origin)?
    else {
        return Ok(false);
    };
    if !retained_cancel_request_receipt_matches(
        connection,
        &events[2],
        taskrun_id,
        origin,
        &submit_authority,
    )? {
        return Ok(false);
    }
    retained_cancel_completion_receipt_matches(
        connection,
        &events[3],
        taskrun_id,
        origin,
        &submit_authority,
    )
}

fn retained_submitted_authority(
    connection: &Connection,
    taskrun_id: &[u8],
    origin: &crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin,
) -> SqliteResult<Option<runne_application::ports::RuntimeAuthorityId>> {
    let scope_bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT receipt.idempotency_scope_bytes FROM events AS event
             JOIN command_receipts AS receipt ON receipt.command_id=event.command_id
             WHERE event.aggregate_type=1 AND event.aggregate_id=?1 AND event.sequence=1",
            [taskrun_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(scope_bytes) = scope_bytes else {
        return Ok(None);
    };
    let Ok(scope) = RetainedIdempotencyScopeCodec.decode(&scope_bytes) else {
        return Ok(None);
    };
    if scope.operation != RetainedOperationTag::SubmitTaskRun
        || scope.principal_id != origin.principal_id
        || scope.aggregate_scope
            != (RetainedAggregateScope::NewTaskRun {
                conversation_id: origin.conversation_id,
                workspace_id: origin.workspace_id,
            })
    {
        return Ok(None);
    }
    Ok(Some(scope.runtime_authority_id))
}

fn retained_cancel_request_receipt_matches(
    connection: &Connection,
    event: &RetainedEventRow,
    taskrun_id: runne_domain::id::TaskRunId,
    origin: &crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin,
    authority: &runne_application::ports::RuntimeAuthorityId,
) -> SqliteResult<bool> {
    let Some((scope, key, fingerprint, outcome)) = retained_command_receipt(connection, &event.3)?
    else {
        return Ok(false);
    };
    let Ok(scope) = RetainedIdempotencyScopeCodec.decode(&scope) else {
        return Ok(false);
    };
    let expected_fingerprint = RetainedCommandFingerprint::for_cancel(&taskrun_id, 2);
    let Ok(outcome) = RetainedCommandOutcomeCodec.decode(&outcome) else {
        return Ok(false);
    };
    Ok(scope.operation == RetainedOperationTag::CancelTaskRun
        && scope.runtime_authority_id == *authority
        && scope.principal_id == origin.principal_id
        && scope.aggregate_scope == (RetainedAggregateScope::ExistingTaskRun { taskrun_id })
        && key == event.5
        && fingerprint == expected_fingerprint.as_bytes()
        && outcome
            == (runne_application::commands::CommandOutcome::TaskRunCancellationRequested {
                taskrun_id,
                new_version: 3,
            }))
}

fn retained_cancel_completion_receipt_matches(
    connection: &Connection,
    event: &RetainedEventRow,
    taskrun_id: runne_domain::id::TaskRunId,
    origin: &crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin,
    authority: &runne_application::ports::RuntimeAuthorityId,
) -> SqliteResult<bool> {
    let Some((scope, key, fingerprint, outcome)) = retained_command_receipt(connection, &event.3)?
    else {
        return Ok(false);
    };
    let Ok(scope) = RetainedIdempotencyScopeCodec.decode(&scope) else {
        return Ok(false);
    };
    let mut hasher = RetainedSha256::new();
    hasher.update(b"runne-taskrun-queued-cancellation-complete-v1");
    hasher.update(taskrun_id.as_bytes());
    hasher.update(3_u64.to_be_bytes());
    let expected_fingerprint = RetainedCommandFingerprint::from_bytes(hasher.finalize().into());
    let Ok(outcome) = RetainedCommandOutcomeCodec.decode(&outcome) else {
        return Ok(false);
    };
    Ok(
        scope.operation == RetainedOperationTag::CompleteQueuedCancellation
            && scope.runtime_authority_id == *authority
            && scope.principal_id == origin.principal_id
            && scope.aggregate_scope == (RetainedAggregateScope::ExistingTaskRun { taskrun_id })
            && key == event.5
            && fingerprint == expected_fingerprint.as_bytes()
            && outcome
                == (runne_application::commands::CommandOutcome::TaskRunCancellationCompleted {
                    taskrun_id,
                    new_version: 4,
                }),
    )
}

fn retained_command_receipt(
    connection: &Connection,
    command_id: &[u8],
) -> SqliteResult<Option<RetainedReceiptRow>> {
    connection
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
             FROM command_receipts WHERE command_id=?1",
            [command_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
}
