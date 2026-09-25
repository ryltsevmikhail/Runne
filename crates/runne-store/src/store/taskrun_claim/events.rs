use super::*;

pub(super) fn validate_queued_stream(
    tx: &rusqlite::Transaction<'_>,
    id: TaskRunId,
    expected: u64,
) -> Result<i64, ClaimError> {
    let verified = stream_validate::verify_stream(tx, id, Some(expected))?;
    if verified.state != TaskRunState::Queued {
        return Err(ClaimError::NotQueued);
    }
    i64::try_from(verified.version).map_err(|_| ClaimError::CorruptData)
}

pub(super) fn database_now_ms(tx: &rusqlite::Transaction<'_>) -> Result<i64, ClaimError> {
    tx.query_row(
        "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
        [],
        |row| row.get(0),
    )
    .map_err(|_| ClaimError::Unavailable)
}
