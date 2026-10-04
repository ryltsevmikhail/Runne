use super::command_receipt::{command_id_exists, duplicate, idempotency_key_exists};
use super::*;
#[path = "claimed/proof.rs"]
mod proof;
use proof::{conversation_has_started_text, has_text_generation_receipt};

type HistoryRow = (i64, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>);
type ClaimReceiptRow = (Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>, Vec<u8>);

impl StoreTransaction {
    pub(super) fn complete_claimed_cancellation_impl(
        &self,
        request: Request,
    ) -> Result<ResultKind, Error> {
        let taskrun_id = super::event_taskrun_id(&request.cancellation_completed)?;
        if request.idempotency_scope.operation != OperationTag::CompleteQueuedCancellation
            || request.idempotency_scope.aggregate_scope
                != (AggregateScope::ExistingTaskRun { taskrun_id })
            || request.cancellation_completed.payload() != &TaskRunEvent::CancellationCompleted
            || request.cancellation_completed.command_id() != &request.command_id
            || request.cancellation_completed.idempotency_key() != &request.idempotency_key
        {
            return Err(Error::CorruptData);
        }
        let scope = IdempotencyScopeCodec
            .encode(&request.idempotency_scope)
            .map_err(|_| Error::CorruptData)?;
        let mut writer = self.inner.writer.lock().map_err(|_| Error::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        if let Some(receipt) = duplicate(&tx, &request, &scope, taskrun_id)? {
            tx.commit().map_err(|_| Error::Unavailable)?;
            return Ok(ResultKind::Duplicate(receipt));
        }
        if command_id_exists(&tx, request.command_id)?
            || idempotency_key_exists(&tx, &scope, &request.idempotency_key)?
        {
            return Err(Error::IdempotencyConflict);
        }
        let (last_event, last_timestamp): (Vec<u8>, i64) = tx.query_row(
            "SELECT last_event_id,last_timestamp FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1 AND current_version=?2",
            params![taskrun_id.as_bytes(), request.expected_version as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|_| Error::CorruptData)?
            .ok_or(Error::StaleVersion { expected: request.expected_version, actual: 0 })?;
        if request
            .cancellation_completed
            .causation_id()
            .map(|event| event.as_bytes().as_slice())
            != Some(last_event.as_slice())
        {
            return Err(Error::CorruptData);
        }
        let identity = prove_claimed_no_begin(
            &tx,
            taskrun_id,
            request.expected_version,
            &self.runtime_authority_id,
        )?;
        let now: i64 = tx
            .query_row(
                "SELECT CAST((julianday('now')-2440587.5)*86400000000 AS INTEGER)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| Error::Unavailable)?;
        let now = now.max(last_timestamp);
        let position: i64 = tx
            .query_row(
                "SELECT next_global_position FROM event_log_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| Error::CorruptData)?;
        let next = request
            .expected_version
            .checked_add(1)
            .ok_or(Error::CorruptData)?;
        append_taskrun_event(
            &tx,
            self.prohibited_content.as_ref(),
            &request.cancellation_completed,
            next,
            position,
            now,
        )
        .map_err(|_| Error::CorruptData)?;
        if tx.execute(
            "UPDATE aggregate_streams SET current_version=?1,last_event_id=?2,last_timestamp=?3 WHERE aggregate_type=1 AND aggregate_id=?4 AND current_version=?5",
            params![next as i64, request.cancellation_completed.event_id().as_bytes(), now,
                taskrun_id.as_bytes(), request.expected_version as i64],
        ).map_err(|_| Error::CorruptData)? != 1 {
            return Err(Error::StaleVersion { expected: request.expected_version, actual: request.expected_version });
        }
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_id.as_bytes(),
        )
        .map_err(|_| Error::CorruptData)?;
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='no_effect_terminal',updated_at=?1
             WHERE taskrun_id=?2 AND state IN ('preflight','approval_pending','approved')
               AND attempt_id IS NULL AND managed_area_identity IS NULL",
            params![now / 1000, taskrun_id.as_bytes()],
        )
        .map_err(|_| Error::CorruptData)?;
        tx.execute(
            "UPDATE event_log_state SET next_global_position=?1 WHERE singleton=1 AND next_global_position=?2",
            params![position.checked_add(1).ok_or(Error::CorruptData)?, position],
        ).map_err(|_| Error::CorruptData)?;
        tx.execute(
            "INSERT INTO taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![taskrun_id.as_bytes(), identity.fence, identity.attempt.as_slice(),
                identity.node.as_slice(), identity.epoch, request.cancellation_completed.event_id().as_bytes(), next as i64],
        ).map_err(|_| Error::AlreadyClaimed)?;
        if tx.execute(
            "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6 AND state='active' AND dispatch_intent='absent' AND release_event_id IS NULL",
            params![request.cancellation_completed.event_id().as_bytes(), taskrun_id.as_bytes(),
                identity.fence, identity.attempt.as_slice(), identity.node.as_slice(), identity.epoch],
        ).map_err(|_| Error::CorruptData)? != 1 {
            return Err(Error::AlreadyClaimed);
        }
        let outcome = runne_application::commands::CommandOutcome::TaskRunCancellationCompleted {
            taskrun_id,
            new_version: next,
        };
        let bytes = CommandOutcomeCodec
            .encode(&outcome)
            .map_err(|_| Error::CorruptData)?;
        tx.execute(
            "INSERT INTO command_receipts(command_id,idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome,committed_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![request.command_id.as_bytes(), scope, request.idempotency_key.as_str().as_bytes(),
                request.command_fingerprint.as_bytes(), bytes, now],
        ).map_err(|_| Error::IdempotencyConflict)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        Ok(ResultKind::Committed(Receipt {
            taskrun_id,
            new_version: next,
        }))
    }
}

struct ClaimedIdentity {
    attempt: Vec<u8>,
    node: Vec<u8>,
    epoch: i64,
    fence: i64,
}

fn prove_claimed_no_begin(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
    expected: u64,
    authority: &runne_application::ports::RuntimeAuthorityId,
) -> Result<ClaimedIdentity, Error> {
    let mut statement = tx.prepare(
        "SELECT sequence,event_id,causation_id,command_id,payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
    ).map_err(|_| Error::CorruptData)?;
    let rows: Vec<HistoryRow> = statement
        .query_map([taskrun_id.as_bytes()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(|_| Error::CorruptData)?
        .collect::<Result<_, _>>()
        .map_err(|_| Error::CorruptData)?;
    drop(statement);
    if rows.len() != usize::try_from(expected).map_err(|_| Error::CorruptData)?
        || rows.is_empty()
        || rows.last().is_none_or(|row| row.0 as u64 != expected)
    {
        return Err(Error::NotCancelling);
    }
    let events = rows
        .iter()
        .map(|row| {
            TaskRunEventCodec
                .decode(&row.4)
                .map_err(|_| Error::CorruptData)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if events
        .first()
        .is_none_or(|event| !matches!(event, TaskRunEvent::TaskRunSubmitted { .. }))
        || events.get(1) != Some(&TaskRunEvent::TaskRunQueued)
        || events.get(2) != Some(&TaskRunEvent::TaskRunAdmitted)
        || events.last() != Some(&TaskRunEvent::CancellationRequested)
        || rows
            .iter()
            .enumerate()
            .skip(1)
            .any(|(index, row)| row.2.as_deref() != Some(rows[index - 1].1.as_slice()))
    {
        return Err(Error::NotCancelling);
    }
    super::super::taskrun_submit_origin::verify_submitted_v2_origin(tx, taskrun_id, authority)
        .map_err(|_| Error::CorruptData)?
        .ok_or(Error::NotCancelling)?;
    let attempt = match events.get(3) {
        Some(TaskRunEvent::AttemptStarted { attempt_id }) if rows.len() == 5 => attempt_id,
        _ => return Err(Error::AlreadyClaimed),
    };
    let claim: Option<ClaimReceiptRow> = tx.query_row(
        "SELECT attempt_id,node_id,node_epoch,fence,new_version,admitted_event_id,started_event_id FROM taskrun_claim_receipts WHERE taskrun_id=?1",
        [taskrun_id.as_bytes()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
    ).optional().map_err(|_| Error::CorruptData)?;
    let Some((claim_attempt, node, epoch, fence, new_version, admitted, started)) = claim else {
        return Err(Error::AlreadyClaimed);
    };
    if claim_attempt.as_slice() != attempt.as_bytes()
        || new_version != 4
        || admitted != rows[2].1
        || started != rows[3].1
        || rows[2].3 != rows[3].3
    {
        return Err(Error::AlreadyClaimed);
    }
    let node_uuid = uuid::Uuid::from_slice(&node).map_err(|_| Error::CorruptData)?;
    let claim_identity = runne_application::ports::TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: *attempt,
        node_id: runne_application::ports::ExecutionNodeId(node_uuid.to_string()),
        node_epoch: u64::try_from(epoch).map_err(|_| Error::CorruptData)?,
        fence: runne_application::ports::TaskRunFence(
            u64::try_from(fence).map_err(|_| Error::CorruptData)?,
        ),
    };
    super::super::taskrun_claim::verify_cancelling_assignment(tx, &claim_identity, expected)
        .map_err(|_| Error::CorruptData)?;
    let occupation: Option<i64> = tx.query_row(
        "SELECT 1 FROM taskrun_assignments a JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) WHERE a.taskrun_id=?1 AND a.fence=?2 AND a.attempt_id=?3 AND a.node_id=?4 AND a.node_epoch=?5 AND o.attempt_id=a.attempt_id AND o.node_id=a.node_id AND o.node_epoch=a.node_epoch AND o.state='active' AND o.dispatch_intent='absent' AND o.release_event_id IS NULL",
        params![taskrun_id.as_bytes(),fence,claim_attempt.as_slice(),node.as_slice(),epoch], |row| row.get(0),
    ).optional().map_err(|_| Error::CorruptData)?;
    if occupation != Some(1) {
        return Err(Error::AlreadyClaimed);
    }
    let local_effect_without_stop: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_attempts WHERE taskrun_id=?1)
           AND NOT EXISTS(SELECT 1 FROM taskrun_local_command_attempts WHERE taskrun_id=?1
             AND attempt_id IS NULL AND managed_area_identity IS NULL
             AND state IN ('preflight','approval_pending','approved','no_effect_terminal'))
           AND NOT EXISTS(SELECT 1 FROM taskrun_local_command_attempts WHERE taskrun_id=?1
             AND attempt_id=?2 AND node_epoch=?3 AND fence=?4
             AND managed_area_identity IS NOT NULL AND state IN ('completed','cancelled'))",
            params![
                taskrun_id.as_bytes(),
                claim_attempt.as_slice(),
                epoch,
                fence
            ],
            |row| row.get(0),
        )
        .map_err(|_| Error::CorruptData)?;
    let remote_effect: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2) OR EXISTS(SELECT 1 FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2) OR EXISTS(SELECT 1 FROM provider_execution_admissions WHERE taskrun_id=?1 AND execution_attempt_id=?3)",
        params![taskrun_id.as_bytes(),fence,claim_attempt.as_slice()], |row| row.get(0),
    ).map_err(|_| Error::CorruptData)?;
    if remote_effect || local_effect_without_stop {
        return Err(Error::AlreadyClaimed);
    }
    let conversation_id = match &events[0] {
        TaskRunEvent::TaskRunSubmitted {
            conversation_id, ..
        } => *conversation_id,
        _ => return Err(Error::NotCancelling),
    };
    if conversation_has_started_text(tx, conversation_id, taskrun_id, *attempt)?
        || has_text_generation_receipt(tx, conversation_id, taskrun_id, *attempt)?
    {
        return Err(Error::AlreadyClaimed);
    }
    Ok(ClaimedIdentity {
        attempt: claim_attempt,
        node,
        epoch,
        fence,
    })
}
