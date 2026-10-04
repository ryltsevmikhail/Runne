fn fail(kind: StorageFailureKind) -> CommitError { CommitError::StorageFailure(kind) }

fn event_position(tx: &Transaction<'_>) -> Result<i64, CommitError> {
    tx.query_row("SELECT next_global_position FROM event_log_state WHERE singleton=1", [], |row| row.get(0))
        .map_err(|_| fail(StorageFailureKind::CorruptData))
}

fn update_head(tx: &Transaction<'_>, kind: i64, id: &[u8; 16], version: i64, event_id: &[u8; 16], timestamp: i64) -> Result<(), CommitError> {
    let changed = tx.execute(
        "UPDATE aggregate_streams SET current_version=?1,last_event_id=?2,last_timestamp=?3
         WHERE aggregate_type=?4 AND aggregate_id=?5",
        params![version, event_id, timestamp, kind, id],
    ).map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 { return Err(fail(StorageFailureKind::IntegrityViolation)); }
    Ok(())
}
