use super::parse_helpers::*;
use super::*;

pub(super) fn current_time_micros() -> Result<i64, CommitError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CommitError::ClockFailure)
        .and_then(|duration| {
            i64::try_from(duration.as_micros()).map_err(|_| CommitError::ClockFailure)
        })
}

pub(super) fn next_global_position(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<i64, CommitError> {
    transaction
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
}

pub(super) fn update_global_position(
    transaction: &rusqlite::Transaction<'_>,
    next: i64,
) -> Result<(), CommitError> {
    transaction
        .execute(
            "UPDATE event_log_state SET next_global_position = ?1 WHERE singleton = 1",
            params![next],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}

pub(super) fn load_stream_head_for_commit(
    transaction: &rusqlite::Transaction<'_>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
) -> Result<(u64, Option<EventId>, Option<i64>), CommitError> {
    let (version, event_id, timestamp) = transaction
        .query_row(
            "SELECT current_version, last_event_id, last_timestamp
             FROM aggregate_streams
             WHERE aggregate_type = ?1 AND aggregate_id = ?2",
            params![aggregate_type, aggregate_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok((
        u64::try_from(version).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        event_id.map(parse_event_id_for_commit).transpose()?,
        timestamp,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn update_stream_head(
    transaction: &rusqlite::Transaction<'_>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    expected_version: u64,
    new_version: u64,
    event_id: EventId,
    timestamp: i64,
) -> Result<(), CommitError> {
    let updated = transaction
        .execute(
            "UPDATE aggregate_streams
             SET current_version = ?1, last_event_id = ?2, last_timestamp = ?3
             WHERE aggregate_type = ?4 AND aggregate_id = ?5
               AND current_version = ?6",
            params![
                new_version as i64,
                event_id.as_bytes(),
                timestamp,
                aggregate_type,
                aggregate_id,
                expected_version as i64,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if updated != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}
