use runne_domain::id::EventId;

type ProviderCancelFenceRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);

pub(crate) fn taskrun_provider_cancel_fence_matches(
    connection: &rusqlite::Connection,
    taskrun_id: TaskRunId,
    taskrun_attempt_id: AttemptId,
    dispatch_attempt_id: DispatchAttemptId,
) -> rusqlite::Result<bool> {
    let row: Option<ProviderCancelFenceRow> = connection
        .query_row(
            "SELECT taskrun_id,taskrun_attempt_id,cancellation_event_id,cancellation_version
             FROM taskrun_provider_cancel_fences WHERE dispatch_attempt_id=?1",
            [dispatch_attempt_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((saved_taskrun, saved_attempt, saved_event, saved_version)) = row else {
        return Ok(false);
    };
    if saved_taskrun != taskrun_id.as_bytes() || saved_attempt != taskrun_attempt_id.as_bytes() {
        return Ok(false);
    }
    cancel_fence_event_matches(
        connection,
        &saved_taskrun,
        &saved_attempt,
        &saved_event,
        saved_version,
    )
}

pub(crate) fn record_taskrun_provider_cancel_fence(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
    event_id: EventId,
    event_version: i64,
    created_at: i64,
) -> rusqlite::Result<()> {
    if event_version <= 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let installed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
         AND name='taskrun_provider_cancel_fences')",
        [],
        |row| row.get(0),
    )?;
    if !installed {
        return Ok(());
    }
    let Some(attempt) = verified_cancel_attempt(tx, taskrun_id, event_id, event_version, true)?
    else {
        return Ok(());
    };
    let d2_table_installed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
         AND name='taskrun_provider_round_bindings')",
        [],
        |row| row.get(0),
    )?;
    let d2_active = if d2_table_installed {
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_provider_round_bindings WHERE taskrun_id=?1 AND fence=(SELECT fence FROM taskrun_assignments WHERE taskrun_id=?1 AND attempt_id=?2))",
            rusqlite::params![taskrun_id.as_bytes(), attempt.as_bytes()],
            |row| row.get(0),
        )?
    } else {
        false
    };
    let candidates = if d2_active {
        d2_cancel_candidate(tx, taskrun_id, attempt, event_id, event_version)?
    } else {
        let mut statement = tx.prepare(
            "SELECT dispatch_attempt_id FROM provider_execution_admissions
             WHERE taskrun_id=?1 AND execution_attempt_id=?2 ORDER BY dispatch_attempt_id LIMIT 2",
        )?;
        statement
            .query_map(
                rusqlite::params![taskrun_id.as_bytes(), attempt.as_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    if candidates.is_empty() {
        return Ok(());
    }
    if candidates.len() > 1 || candidates.iter().any(|id| id.len() != 16) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    for dispatch in candidates {
        let prior: Option<ProviderCancelFenceRow> = tx.query_row(
            "SELECT taskrun_id,taskrun_attempt_id,cancellation_event_id,cancellation_version FROM taskrun_provider_cancel_fences WHERE dispatch_attempt_id=?1",
            [&dispatch], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional()?;
        if let Some((saved_taskrun, saved_attempt, saved_event, saved_version)) = prior {
            if saved_taskrun != taskrun_id.as_bytes()
                || saved_attempt != attempt.as_bytes()
                || saved_version >= event_version
                || !cancel_fence_event_matches(
                    tx,
                    &saved_taskrun,
                    &saved_attempt,
                    &saved_event,
                    saved_version,
                )?
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            continue;
        }
        tx.execute("INSERT INTO taskrun_provider_cancel_fences(taskrun_id,taskrun_attempt_id,dispatch_attempt_id,cancellation_event_id,cancellation_version,created_at) VALUES(?1,?2,?3,?4,?5,?6)",rusqlite::params![taskrun_id.as_bytes(),attempt.as_bytes(),dispatch,event_id.as_bytes(),event_version,created_at])?;
    }
    Ok(())
}

/// D2 calls are sequential: only the latest call can still be remote-pending.
/// Earlier admissions must have an applied ToolProposal terminal before we fence
/// the latest dispatch with the unique TaskRun cancellation event.
fn d2_cancel_candidate(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
    attempt: AttemptId,
    event_id: EventId,
    cancel_version: i64,
) -> rusqlite::Result<Vec<Vec<u8>>> {
    if !cancel_fence_event_matches(
        tx,
        taskrun_id.as_bytes(),
        attempt.as_bytes(),
        event_id.as_bytes(),
        cancel_version,
    )? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let first: (Vec<u8>, i64, i64, i64) = tx.query_row(
        "SELECT node_id,node_epoch,fence,original_claim_version
         FROM taskrun_provider_round_bindings WHERE taskrun_id=?1 AND attempt_id=?2
         ORDER BY round_index LIMIT 1",
        rusqlite::params![taskrun_id.as_bytes(), attempt.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let node_id = <[u8; 16]>::try_from(first.0.as_slice())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let original_claim_version = u64::try_from(first.3)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let evidence = runne_application::ports::D2ToolLoopCancellationEvidence {
        node_id,
        node_epoch: u64::try_from(first.1).map_err(|_| rusqlite::Error::InvalidQuery)?,
        fence: u64::try_from(first.2).map_err(|_| rusqlite::Error::InvalidQuery)?,
        cancellation_taskrun_version: u64::try_from(cancel_version)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    };
    let claim_matches: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE taskrun_id=?1
         AND attempt_id=?2 AND fence=?3 AND node_id=?4 AND node_epoch=?5 AND new_version=?6)",
        rusqlite::params![taskrun_id.as_bytes(), attempt.as_bytes(), first.2, first.0,
            first.1, original_claim_version as i64],
        |row| row.get(0),
    )?;
    if !claim_matches {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if crate::store::verify_d2_cancelled_provider_rounds(
        tx,
        taskrun_id,
        attempt,
        evidence,
        original_claim_version,
        evidence.cancellation_taskrun_version,
    ).is_err() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut statement = tx.prepare(
        "SELECT a.dispatch_attempt_id FROM taskrun_provider_round_bindings b
         LEFT JOIN provider_execution_admissions a ON a.call_id=b.call_id
           AND a.taskrun_id=b.taskrun_id AND a.execution_attempt_id=b.attempt_id
         WHERE b.taskrun_id=?1 AND b.attempt_id=?2 ORDER BY b.round_index",
    )?;
    let dispatches: Vec<Option<Vec<u8>>> = statement
        .query_map(
            rusqlite::params![taskrun_id.as_bytes(), attempt.as_bytes()],
            |row| row.get(0),
        )?
        .collect::<Result<_, _>>()?;
    drop(statement);
    if dispatches.is_empty() || dispatches.len() > 3 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(dispatches.last().cloned().flatten().into_iter().collect())
}

fn cancel_fence_event_matches(
    tx: &rusqlite::Connection,
    taskrun: &[u8],
    attempt: &[u8],
    event_id: &[u8],
    version: i64,
) -> rusqlite::Result<bool> {
    let (Ok(taskrun), Ok(event), Ok(version)) = (
        <[u8; 16]>::try_from(taskrun),
        <[u8; 16]>::try_from(event_id),
        u64::try_from(version),
    ) else {
        return Ok(false);
    };
    Ok(verified_cancel_attempt(
        tx,
        TaskRunId::from_bytes(taskrun),
        EventId::from_bytes(event),
        i64::try_from(version).map_err(|_| rusqlite::Error::InvalidQuery)?,
        false,
    )?
    .is_some_and(|active| active.as_bytes() == attempt))
}

fn verified_cancel_attempt(
    connection: &rusqlite::Connection,
    taskrun_id: TaskRunId,
    event_id: EventId,
    event_version: i64,
    require_head: bool,
) -> rusqlite::Result<Option<AttemptId>> {
    if event_version <= 1 {
        return Ok(None);
    }
    let payload: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM events WHERE event_id=?1 AND aggregate_type=1
             AND aggregate_id=?2 AND sequence=?3",
            rusqlite::params![event_id.as_bytes(), taskrun_id.as_bytes(), event_version],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let decoded: Result<runne_domain::task_run::TaskRunEvent, _> =
        crate::codec::StoreCodec::decode(&crate::codec::TaskRunEventCodec, &payload);
    if !matches!(
        decoded,
        Ok(runne_domain::task_run::TaskRunEvent::CancellationRequested)
    ) {
        return Ok(None);
    }
    if require_head {
        let current: Option<i64> = connection
            .query_row(
                "SELECT current_version FROM aggregate_streams
                 WHERE aggregate_type=1 AND aggregate_id=?1",
                [taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        if current != Some(event_version) {
            return Ok(None);
        }
    }
    let prefix_version =
        u64::try_from(event_version - 1).map_err(|_| rusqlite::Error::InvalidQuery)?;
    crate::store::taskrun_claim::active_attempt_at_verified_version(
        connection,
        taskrun_id,
        prefix_version,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)
}
