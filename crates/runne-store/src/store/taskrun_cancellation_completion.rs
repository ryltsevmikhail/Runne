use super::event_guard::append_taskrun_event;
use super::*;
use runne_application::ports::{
    CompleteQueuedCancellationError as Error, CompleteQueuedCancellationReceipt as Receipt,
    CompleteQueuedCancellationRequest as Request, CompleteQueuedCancellationResult as ResultKind,
    TaskRunCancellationCompletionPort,
};
use rusqlite::TransactionBehavior;

#[path = "taskrun_cancellation_completion/claimed.rs"]
mod claimed;
#[path = "taskrun_cancellation_completion/command_receipt.rs"]
mod command_receipt;
#[path = "taskrun_cancellation_completion/proof.rs"]
mod proof;
use command_receipt::{command_id_exists, duplicate, idempotency_key_exists};

impl TaskRunCancellationCompletionPort for StoreTransaction {
    fn complete_queued_cancellation(&self, request: Request) -> Result<ResultKind, Error> {
        if request.idempotency_scope.operation != OperationTag::CompleteQueuedCancellation
            || request.idempotency_scope.aggregate_scope
                != (AggregateScope::ExistingTaskRun {
                    taskrun_id: event_taskrun_id(&request.cancellation_completed)?,
                })
            || request.cancellation_completed.payload() != &TaskRunEvent::CancellationCompleted
            || request.cancellation_completed.command_id() != &request.command_id
            || request.cancellation_completed.idempotency_key() != &request.idempotency_key
        {
            return Err(Error::CorruptData);
        }
        let taskrun_id = event_taskrun_id(&request.cancellation_completed)?;
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
        if command_id_exists(&tx, request.command_id)? {
            return Err(Error::IdempotencyConflict);
        }
        if idempotency_key_exists(&tx, &scope, &request.idempotency_key)? {
            return Err(Error::IdempotencyConflict);
        }
        proof::prove_unclaimed_cancelling(
            &tx,
            taskrun_id,
            request.expected_version,
            &self.runtime_authority_id,
        )?;
        let (last_event, last_timestamp): (Vec<u8>, i64) = tx.query_row(
            "SELECT last_event_id,last_timestamp FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_id.as_bytes()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|_| Error::CorruptData)?;
        if request
            .cancellation_completed
            .causation_id()
            .map(|event| event.as_bytes().as_slice())
            != Some(last_event.as_slice())
        {
            return Err(Error::CorruptData);
        }
        let now: i64 = tx
            .query_row(
                "SELECT CAST((julianday('now')-2440587.5)*86400000000 AS INTEGER)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| Error::Unavailable)?
            .max(last_timestamp);
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
        if tx
            .execute(
                "UPDATE aggregate_streams SET current_version=?1,last_event_id=?2,last_timestamp=?3
             WHERE aggregate_type=1 AND aggregate_id=?4 AND current_version=?5",
                params![
                    next as i64,
                    request.cancellation_completed.event_id().as_bytes(),
                    now,
                    taskrun_id.as_bytes(),
                    request.expected_version as i64
                ],
            )
            .map_err(|_| Error::CorruptData)?
            != 1
        {
            return Err(Error::StaleVersion {
                expected: request.expected_version,
                actual: request.expected_version,
            });
        }
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            CORRELATION_TYPE_TASK_RUN,
            taskrun_id.as_bytes(),
        )
        .map_err(|_| Error::CorruptData)?;
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='no_effect_terminal',updated_at=?1
             WHERE taskrun_id=?2 AND state IN ('preflight','approval_pending','approved')",
            params![now, taskrun_id.as_bytes()],
        )
        .map_err(|_| Error::CorruptData)?;
        tx.execute(
            "UPDATE event_log_state SET next_global_position=?1 WHERE singleton=1 AND next_global_position=?2",
            params![position.checked_add(1).ok_or(Error::CorruptData)?, position],
        ).map_err(|_| Error::CorruptData)?;
        let outcome = runne_application::commands::CommandOutcome::TaskRunCancellationCompleted {
            taskrun_id,
            new_version: next,
        };
        let outcome_bytes = CommandOutcomeCodec
            .encode(&outcome)
            .map_err(|_| Error::CorruptData)?;
        tx.execute(
            "INSERT INTO command_receipts(command_id,idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome,committed_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![request.command_id.as_bytes(), scope, request.idempotency_key.as_str().as_bytes(),
                request.command_fingerprint.as_bytes(), outcome_bytes, now],
        ).map_err(|_| Error::IdempotencyConflict)?;
        tx.commit().map_err(|_| Error::Unavailable)?;
        Ok(ResultKind::Committed(Receipt {
            taskrun_id,
            new_version: next,
        }))
    }

    fn complete_claimed_taskrun_cancellation(&self, request: Request) -> Result<ResultKind, Error> {
        self.complete_claimed_cancellation_impl(request)
    }
}

fn event_taskrun_id(event: &UncommittedEvent<TaskRunEvent>) -> Result<TaskRunId, Error> {
    match event.aggregate_id() {
        AggregateId::TaskRun(taskrun_id) => Ok(*taskrun_id),
        _ => Err(Error::CorruptData),
    }
}
