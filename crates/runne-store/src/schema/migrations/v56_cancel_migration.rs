type V56TaskRunEventRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>);

use runne_domain::id::{AttemptId, TaskRunId};

fn backfill_v56_cancel_fences(tx: &Transaction<'_>) -> SqliteResult<()> {
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use runne_domain::id::TaskRunId;
    use runne_domain::task_run::TaskRunEvent;

    let events: Vec<V56TaskRunEventRow> = tx
        .prepare(
            "SELECT event_id,aggregate_id,sequence,payload FROM events
             WHERE aggregate_type=1 ORDER BY aggregate_id,sequence",
        )?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<_, _>>()?;
    for (event_id, taskrun, version, payload) in events {
        let decoded: Result<TaskRunEvent, _> = TaskRunEventCodec.decode(&payload);
        if !matches!(decoded, Ok(TaskRunEvent::CancellationRequested)) {
            continue;
        }
        let taskrun_id = TaskRunId::from_bytes(
            taskrun
                .as_slice()
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        );
        let prefix_version = u64::try_from(
            version
                .checked_sub(1)
                .ok_or(rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let Some(attempt) = crate::store::taskrun_claim::active_attempt_at_verified_version(
            tx,
            taskrun_id,
            prefix_version,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        else {
            continue;
        };
        let mut statement = tx.prepare(
            "SELECT dispatch_attempt_id FROM provider_execution_admissions
             WHERE taskrun_id=?1 AND execution_attempt_id=?2 ORDER BY dispatch_attempt_id LIMIT 2",
        )?;
        let dispatches = statement
            .query_map(rusqlite::params![taskrun, attempt.as_bytes()], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if dispatches.is_empty() {
            continue;
        }
        if dispatches.len() != 1 || dispatches[0].len() != 16 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let existing: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT cancellation_event_id,cancellation_version
                 FROM taskrun_provider_cancel_fences WHERE dispatch_attempt_id=?1",
                [&dispatches[0]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((saved_event, saved_version)) = existing {
            if saved_version >= version || saved_event.len() != 16 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            continue;
        }
        tx.execute(
            "INSERT INTO taskrun_provider_cancel_fences
             (taskrun_id,taskrun_attempt_id,dispatch_attempt_id,cancellation_event_id,cancellation_version,created_at)
             SELECT ?1,?2,?3,?4,?5,timestamp FROM events WHERE event_id=?4",
            rusqlite::params![taskrun, attempt.as_bytes(), dispatches[0], event_id, version],
        )?;
    }
    Ok(())
}

fn v56_cancel_fences_cover_cancellations(
    connection: &Connection,
    allow_v64_d2: bool,
) -> SqliteResult<bool> {
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use runne_domain::id::TaskRunId;
    use runne_domain::task_run::TaskRunEvent;
    use runne_provider::DispatchAttemptId;

    type CancellationEventRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>);
    let events: Vec<CancellationEventRow> = connection
        .prepare(
            "SELECT event_id,aggregate_id,sequence,payload FROM events
             WHERE aggregate_type=1 ORDER BY aggregate_id,sequence",
        )?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<_, _>>()?;
    for (event_id, taskrun, version, payload) in events {
        let decoded: Result<TaskRunEvent, _> = TaskRunEventCodec.decode(&payload);
        if !matches!(decoded, Ok(TaskRunEvent::CancellationRequested)) {
            continue;
        }
        let taskrun = match <[u8; 16]>::try_from(taskrun.as_slice()) {
            Ok(bytes) => TaskRunId::from_bytes(bytes),
            Err(_) => return Ok(false),
        };
        let prefix_version = match version.checked_sub(1).and_then(|v| u64::try_from(v).ok()) {
            Some(value) => value,
            None => return Ok(false),
        };
        let Some(attempt) = crate::store::taskrun_claim::active_attempt_at_verified_version(
            connection,
            taskrun,
            prefix_version,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        else {
            continue;
        };
        if allow_v64_d2 && has_d2_rounds(connection, taskrun, attempt)? {
            if !v64_d2_cancel_fence_covers(connection, taskrun, attempt, &event_id, version)? {
                return Ok(false);
            }
            continue;
        }
        let mut statement = connection.prepare(
            "SELECT dispatch_attempt_id FROM provider_execution_admissions
             WHERE taskrun_id=?1 AND execution_attempt_id=?2 ORDER BY dispatch_attempt_id LIMIT 2",
        )?;
        let dispatches = statement
            .query_map(
                rusqlite::params![taskrun.as_bytes(), attempt.as_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if dispatches.is_empty() {
            continue;
        }
        if dispatches.len() != 1 || dispatches[0].len() != 16 {
            return Ok(false);
        }
        let dispatch = DispatchAttemptId::from_bytes(
            dispatches[0]
                .as_slice()
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        );
        let saved_version: Option<i64> = connection
            .query_row(
                "SELECT cancellation_version FROM taskrun_provider_cancel_fences
                 WHERE dispatch_attempt_id=?1 AND taskrun_id=?2 AND taskrun_attempt_id=?3",
                rusqlite::params![dispatch.as_bytes(), taskrun.as_bytes(), attempt.as_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(saved_version) = saved_version else {
            return Ok(false);
        };
        if saved_version > version
            || !crate::provider::taskrun_provider_cancel_fence_matches(
                connection, taskrun, attempt, dispatch,
            )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn has_d2_rounds(
    connection: &Connection,
    taskrun: TaskRunId,
    attempt: AttemptId,
) -> SqliteResult<bool> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_provider_round_bindings
         WHERE taskrun_id=?1 AND attempt_id=?2)",
        rusqlite::params![taskrun.as_bytes(), attempt.as_bytes()],
        |row| row.get(0),
    )
}

fn v64_d2_cancel_fence_covers(
    connection: &Connection,
    taskrun: TaskRunId,
    attempt: AttemptId,
    event_id: &[u8],
    cancel_version: i64,
) -> SqliteResult<bool> {
    let first: Option<(Vec<u8>, i64, i64, i64)> = connection
        .query_row(
            "SELECT node_id,node_epoch,fence,original_claim_version
             FROM taskrun_provider_round_bindings
             WHERE taskrun_id=?1 AND attempt_id=?2 ORDER BY round_index LIMIT 1",
            rusqlite::params![taskrun.as_bytes(), attempt.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((node, epoch, fence, original)) = first else {
        return Ok(false);
    };
    let (Ok(node_id), Ok(node_epoch), Ok(fence), Ok(original_claim_version), Ok(cancel_version_u64)) = (
        <[u8; 16]>::try_from(node.as_slice()),
        u64::try_from(epoch),
        u64::try_from(fence),
        u64::try_from(original),
        u64::try_from(cancel_version),
    ) else {
        return Ok(false);
    };
    let evidence = runne_application::ports::D2ToolLoopCancellationEvidence {
        node_id,
        node_epoch,
        fence,
        cancellation_taskrun_version: cancel_version_u64,
    };
    if crate::store::verify_d2_cancelled_provider_rounds(
        connection,
        taskrun,
        attempt,
        evidence,
        original_claim_version,
        cancel_version_u64,
    )
    .is_err()
    {
        return Ok(false);
    }
    let latest: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT a.dispatch_attempt_id FROM taskrun_provider_round_bindings b
             LEFT JOIN provider_execution_admissions a ON a.taskrun_id=b.taskrun_id
               AND a.execution_attempt_id=b.attempt_id AND a.call_id=b.call_id
             WHERE b.taskrun_id=?1 AND b.attempt_id=?2
             ORDER BY b.round_index DESC LIMIT 1",
            rusqlite::params![taskrun.as_bytes(), attempt.as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    let latest = latest.flatten();
    let fences: Vec<(Vec<u8>, Vec<u8>, i64)> = connection
        .prepare(
            "SELECT dispatch_attempt_id,cancellation_event_id,cancellation_version
             FROM taskrun_provider_cancel_fences WHERE taskrun_id=?1 AND taskrun_attempt_id=?2",
        )?
        .query_map(rusqlite::params![taskrun.as_bytes(), attempt.as_bytes()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<_, _>>()?;
    match latest {
        Some(dispatch) if fences.len() == 1 => Ok(
            fences[0].0 == dispatch && fences[0].1 == event_id && fences[0].2 == cancel_version,
        ),
        None => Ok(fences.is_empty()),
        _ => Ok(false),
    }
}
