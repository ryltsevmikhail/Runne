type V56TaskRunEventRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>);

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

fn v56_cancel_fences_cover_cancellations(connection: &Connection) -> SqliteResult<bool> {
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use runne_domain::id::TaskRunId;
    use runne_domain::task_run::TaskRunEvent;
    use runne_provider::DispatchAttemptId;

    let events: Vec<(Vec<u8>, i64, Vec<u8>)> = connection
        .prepare(
            "SELECT aggregate_id,sequence,payload FROM events
             WHERE aggregate_type=1 ORDER BY aggregate_id,sequence",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    for (taskrun, version, payload) in events {
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
