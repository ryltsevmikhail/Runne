use super::*;
use runne_application::ports::RuntimeAuthorityId;

type HistoryRow = (i64, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>, Vec<u8>);
type SubmitReceiptRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub(super) fn prove_unclaimed_cancelling(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
    expected: u64,
    authority: &RuntimeAuthorityId,
) -> Result<(), Error> {
    prove_unclaimed(tx, taskrun_id, expected, authority, false)
}

pub(crate) fn prove_unclaimed_cancelled(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
    authority: &RuntimeAuthorityId,
) -> Result<(), Error> {
    prove_unclaimed(tx, taskrun_id, 4, authority, true)
}

fn prove_unclaimed(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
    expected: u64,
    authority: &RuntimeAuthorityId,
    completed: bool,
) -> Result<(), Error> {
    let actual: Option<i64> = tx
        .query_row(
            "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::CorruptData)?;
    let actual = actual.ok_or(Error::CorruptData)?;
    if u64::try_from(actual).ok() != Some(expected) {
        return Err(Error::StaleVersion {
            expected,
            actual: u64::try_from(actual).map_err(|_| Error::CorruptData)?,
        });
    }
    let occupied: i64 = tx
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1)
          +(SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1)
          +(SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1)
          +(SELECT COUNT(*) FROM taskrun_dispatch_intents WHERE taskrun_id=?1)
          +(SELECT COUNT(*) FROM taskrun_provider_bindings WHERE taskrun_id=?1)
          +(SELECT COUNT(*) FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND state NOT IN ('preflight','approval_pending','approved','no_effect_terminal'))
          +(SELECT COUNT(*) FROM provider_execution_admissions WHERE taskrun_id=?1)",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| Error::CorruptData)?;
    if occupied != 0 {
        return Err(Error::AlreadyClaimed);
    }
    if actual != if completed { 4 } else { 3 } {
        return Err(Error::NotCancelling);
    }
    let verified =
        super::super::taskrun_claim::stream_validate::verify_stream(tx, taskrun_id, Some(expected))
            .map_err(|_| Error::CorruptData)?;
    if verified.state
        != if completed {
            runne_domain::task_run::TaskRunState::Cancelled
        } else {
            runne_domain::task_run::TaskRunState::Cancelling
        }
    {
        return Err(Error::NotCancelling);
    }
    let mut statement = tx
        .prepare(
            "SELECT sequence,event_id,causation_id,command_id,payload,idempotency_key FROM events
         WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
        )
        .map_err(|_| Error::CorruptData)?;
    let rows: Vec<HistoryRow> = statement
        .query_map([taskrun_id.as_bytes()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(|_| Error::CorruptData)?
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::CorruptData)?;
    if rows.len() != if completed { 4 } else { 3 }
        || rows
            .iter()
            .enumerate()
            .any(|(index, row)| row.0 != index as i64 + 1)
    {
        return Err(Error::NotCancelling);
    }
    let first = TaskRunEventCodec
        .decode(&rows[0].4)
        .map_err(|_| Error::CorruptData)?;
    let second = TaskRunEventCodec
        .decode(&rows[1].4)
        .map_err(|_| Error::CorruptData)?;
    let third = TaskRunEventCodec
        .decode(&rows[2].4)
        .map_err(|_| Error::CorruptData)?;
    let submitted = matches!(&first, TaskRunEvent::TaskRunSubmitted { .. })
        && second == TaskRunEvent::TaskRunQueued;
    let legacy = first == TaskRunEvent::TaskRunCreated && second == TaskRunEvent::TaskRunQueued;
    if !submitted && !legacy {
        return Err(Error::NotCancelling);
    }
    prove_submit_receipt(tx, taskrun_id, &rows, &first, authority)?;
    if third != TaskRunEvent::CancellationRequested
        || rows[1].2.as_deref() != Some(rows[0].1.as_slice())
        || rows[2].2.as_deref() != Some(rows[1].1.as_slice())
        || rows[1].3 != rows[0].3
        || rows[1].5 != rows[0].5
    {
        return Err(Error::NotCancelling);
    }
    let (head_version, head_event): (i64, Vec<u8>) = tx
        .query_row(
            "SELECT current_version,last_event_id FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| Error::CorruptData)?;
    if head_version != actual || head_event != rows.last().ok_or(Error::CorruptData)?.1 {
        return Err(Error::CorruptData);
    }
    if completed {
        super::read_proof::verify_completion(
            tx,
            taskrun_id,
            authority,
            &rows,
            verified.events.last().ok_or(Error::CorruptData)?.actor(),
        )?;
    }
    Ok(())
}

fn prove_submit_receipt(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
    rows: &[HistoryRow],
    first: &TaskRunEvent,
    authority: &RuntimeAuthorityId,
) -> Result<(), Error> {
    let command = CommandId::from_bytes(
        rows[0]
            .3
            .as_slice()
            .try_into()
            .map_err(|_| Error::CorruptData)?,
    );
    let receipt: Option<SubmitReceiptRow> = tx
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
             FROM command_receipts WHERE command_id=?1",
            [command.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| Error::CorruptData)?;
    let Some((scope_bytes, key, fingerprint, outcome)) = receipt else {
        return Err(Error::NotCancelling);
    };
    let scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| Error::CorruptData)?;
    let (conversation_id, workspace_id) = match scope.aggregate_scope {
        AggregateScope::NewTaskRun {
            conversation_id,
            workspace_id,
        } if scope.runtime_authority_id == *authority
            && scope.operation == OperationTag::SubmitTaskRun =>
        {
            (conversation_id, workspace_id)
        }
        _ => return Err(Error::NotCancelling),
    };
    let expected_fingerprint = match first {
        TaskRunEvent::TaskRunCreated => {
            CommandFingerprint::for_submit_legacy(&conversation_id, &workspace_id)
        }
        TaskRunEvent::TaskRunSubmitted {
            conversation_id: stored_conversation,
            workspace_id: stored_workspace,
            input,
        } if *stored_conversation == conversation_id && *stored_workspace == workspace_id => {
            CommandFingerprint::for_submit(&conversation_id, &workspace_id, input)
        }
        _ => return Err(Error::NotCancelling),
    };
    if key != rows[0].5 || key != rows[1].5 || fingerprint != expected_fingerprint.as_bytes() {
        return Err(Error::NotCancelling);
    }
    if CommandOutcomeCodec
        .decode(&outcome)
        .map_err(|_| Error::CorruptData)?
        != (runne_application::commands::CommandOutcome::TaskRunSubmitted {
            taskrun_id,
            new_version: 2,
        })
    {
        return Err(Error::NotCancelling);
    }
    crate::project_workspace::lineage::validate_direct_taskrun_lineage(
        tx, &scope, taskrun_id, command,
    )
    .map_err(|_| Error::CorruptData)?;
    Ok(())
}
