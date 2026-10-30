use super::*;
use rusqlite::OptionalExtension;

type NodeRegistrationRow = (i64, i64, String, String, String, i64, i64, i64);
pub(super) fn ensure_live_node(
    tx: &rusqlite::Transaction<'_>,
    node_id: [u8; 16],
    request: &TaskRunClaimRequest,
    now: i64,
) -> Result<(), ClaimError> {
    let authority: Option<Vec<u8>> = tx
        .query_row(
            "SELECT authority_id FROM _authority WHERE id=1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ClaimError::CorruptData)?;
    let generation: Option<String> = tx
        .query_row(
            "SELECT value FROM _daemon_info WHERE key='launch_generation'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ClaimError::CorruptData)?;
    let Some(authority) = authority else {
        return Err(ClaimError::CorruptData);
    };
    if authority.len() != 16 || authority.iter().all(|byte| *byte == 0) {
        return Err(ClaimError::CorruptData);
    }
    let Some(generation) = generation else {
        return Err(ClaimError::CorruptData);
    };
    let parsed_generation = generation
        .parse::<u64>()
        .map_err(|_| ClaimError::CorruptData)?;
    if parsed_generation == 0 || parsed_generation.to_string() != generation {
        return Err(ClaimError::CorruptData);
    }
    if authority.as_slice() != node_id.as_slice() || parsed_generation != request.node_epoch {
        return Err(ClaimError::NodeUnavailable);
    }
    let row: Option<NodeRegistrationRow> = tx.query_row(
        "SELECT launch_generation,descriptor_version,platform,executor_protocol,workspace_backend,capacity,heartbeat_at_ms,expires_at_ms FROM execution_nodes WHERE node_id=?1",
        [node_id.as_slice()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
    ).optional().map_err(|_| ClaimError::CorruptData)?;
    let Some((epoch, version, platform, protocol, workspace, capacity, heartbeat, expiry)) = row
    else {
        return Err(ClaimError::NodeUnavailable);
    };
    if epoch <= 0
        || version != 1
        || platform != current_node_platform()
        || protocol != "runne-taskrun-v1"
        || workspace != "git-worktree-v1"
        || capacity <= 0
        || u32::try_from(capacity).is_err()
        || heartbeat <= 0
        || heartbeat > now
        || expiry <= now
        || expiry <= heartbeat
        || expiry - heartbeat > 300_000
    {
        return Err(ClaimError::CorruptData);
    }
    if epoch as u64 != request.node_epoch || request.node_epoch == 0 {
        return Err(ClaimError::NodeUnavailable);
    }
    Ok(())
}

pub(super) fn allocate_fence(
    tx: &rusqlite::Transaction<'_>,
    taskrun: TaskRunId,
) -> Result<u64, ClaimError> {
    let prior: Option<i64> = tx
        .query_row(
            "SELECT last_fence FROM taskrun_fence_counters WHERE taskrun_id=?1",
            [taskrun.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ClaimError::CorruptData)?;
    let next = prior
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(ClaimError::CorruptData)?;
    tx.execute("INSERT INTO taskrun_fence_counters(taskrun_id,last_fence) VALUES(?1,?2) ON CONFLICT(taskrun_id) DO UPDATE SET last_fence=excluded.last_fence", rusqlite::params![taskrun.as_bytes(), next])
        .map_err(|_| ClaimError::CorruptData)?;
    u64::try_from(next).map_err(|_| ClaimError::CorruptData)
}

pub(super) fn append_claim_events(
    store: &StoreTransaction,
    tx: &rusqlite::Transaction<'_>,
    request: &TaskRunClaimRequest,
    current: i64,
    now: i64,
) -> Result<(), ClaimError> {
    let next: i64 = tx
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ClaimError::CorruptData)?;
    if current > i64::MAX - 2 || next <= 0 || next > i64::MAX - 2 {
        return Err(ClaimError::CorruptData);
    }
    for (offset, event) in [&request.admitted_event, &request.started_event]
        .into_iter()
        .enumerate()
    {
        let sequence =
            u64::try_from(current + offset as i64 + 1).map_err(|_| ClaimError::CorruptData)?;
        crate::store::event_guard::append_taskrun_event(
            tx,
            store.prohibited_content.as_ref(),
            event,
            sequence,
            next + offset as i64,
            now,
        )
        .map_err(|_| ClaimError::CorruptData)?;
    }
    let head = request.started_event.event_id().as_bytes();
    let updated = tx.execute("UPDATE aggregate_streams SET current_version=?1,last_event_id=?2,last_timestamp=?3 WHERE aggregate_type=1 AND aggregate_id=?4",
        rusqlite::params![current+2, head, now, request.taskrun_id.as_bytes()]).map_err(|_| ClaimError::CorruptData)?;
    if updated != 1 {
        return Err(ClaimError::CorruptData);
    }
    crate::store::snapshot::refresh_aggregate_snapshot(
        tx,
        CORRELATION_TYPE_TASK_RUN,
        request.taskrun_id.as_bytes(),
    )
    .map_err(|_| ClaimError::CorruptData)?;
    let updated = tx
        .execute(
            "UPDATE event_log_state SET next_global_position=?1 WHERE singleton=1",
            [next + 2],
        )
        .map_err(|_| ClaimError::CorruptData)?;
    if updated != 1 {
        return Err(ClaimError::CorruptData);
    }
    Ok(())
}

/// Platform recorded by the local execution node.
const fn current_node_platform() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "macos")]
    {
        "darwin"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "unsupported"
    }
}
