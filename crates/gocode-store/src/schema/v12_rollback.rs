/// Verifies the exact V11 snapshot while the V12 write fence is open.
///
/// In-place restore is prohibited until the database owner can atomically
/// switch authority and fence stale handles.
pub fn rollback_pre_v12_snapshot(db_path: &Path) -> Result<(), SchemaRollbackError> {
    if !db_path.is_absolute() || !path_is_safe(db_path) {
        return Err(SchemaRollbackError::UnsafePath);
    }
    let original_identity = file_identity(db_path).map_err(|_| SchemaRollbackError::UnsafePath)?;
    let connection = open_with_pragmas(db_path.to_str().ok_or(SchemaRollbackError::UnsafePath)?)
        .map_err(|_| SchemaRollbackError::StoreUnavailable)?;
    let version: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?;
    if !is_supported_pre_v12_rollback_source(&connection, version)
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?
    {
        return Err(SchemaRollbackError::UnsupportedSchema);
    }
    let fence = load_v12_upgrade_fence(&connection)
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?
        .ok_or(SchemaRollbackError::UnsupportedSchema)?;
    if v12_write_latch_closed(&connection).map_err(|_| SchemaRollbackError::UnsupportedSchema)?
        || !current_v12_high_water_matches(&connection, &fence)?
    {
        return Err(SchemaRollbackError::RollbackClosed);
    }
    let snapshot_filename = fence
        .snapshot_filename
        .as_deref()
        .ok_or(SchemaRollbackError::SnapshotUnavailable)?;
    let snapshot_digest = fence
        .snapshot_digest
        .as_deref()
        .ok_or(SchemaRollbackError::SnapshotUnavailable)?;
    let snapshot_path = resolve_private_snapshot(db_path, snapshot_filename)?;
    if sha256_file(&snapshot_path)
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?
        .as_slice()
        != snapshot_digest
    {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    let snapshot_identity =
        file_identity(&snapshot_path).map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    let snapshot = open_existing_read_only(&snapshot_path)
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    if !is_released_provider_v11(&snapshot, 11)
        .map_err(|_| SchemaRollbackError::SnapshotMismatch)?
        || !snapshot_high_water_matches(&snapshot, &fence)
    {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    recheck_rollback_fence(
        &connection,
        db_path,
        &original_identity,
        &snapshot_path,
        snapshot_digest,
        &snapshot_identity,
        &fence,
    )?;
    Err(SchemaRollbackError::AuthoritySwitchUnavailable)
}

fn is_supported_pre_v12_rollback_source(conn: &Connection, version: i64) -> SqliteResult<bool> {
    match version {
        12 => is_released_provider_v12(conn, version),
        13 => is_released_provider_v13(conn, version),
        _ => Ok(false),
    }
}

fn current_v12_high_water_matches(
    conn: &Connection,
    fence: &V12UpgradeFenceRow,
) -> Result<bool, SchemaRollbackError> {
    high_water_matches(conn, fence).map_err(|_| SchemaRollbackError::UnsupportedSchema)
}

fn snapshot_high_water_matches(conn: &Connection, fence: &V12UpgradeFenceRow) -> bool {
    high_water_matches(conn, fence).unwrap_or(false)
}

fn high_water_matches(conn: &Connection, fence: &V12UpgradeFenceRow) -> SqliteResult<bool> {
    let event: i64 = conn.query_row(
        "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let prepared: i64 = conn.query_row(
        "SELECT COUNT(*) FROM provider_prepared_requests",
        [],
        |row| row.get(0),
    )?;
    let attempts: i64 = conn.query_row(
        "SELECT COUNT(*) FROM provider_dispatch_attempts",
        [],
        |row| row.get(0),
    )?;
    Ok(event == fence.baseline_event_next_position
        && prepared == fence.baseline_provider_prepared_count
        && attempts == fence.baseline_provider_attempt_count)
}

fn recheck_rollback_fence(
    conn: &Connection,
    database: &Path,
    expected_database: &FileIdentity,
    snapshot: &Path,
    expected_digest: &[u8],
    expected_snapshot: &FileIdentity,
    fence: &V12UpgradeFenceRow,
) -> Result<(), SchemaRollbackError> {
    if &file_identity(database).map_err(|_| SchemaRollbackError::UnsafePath)? != expected_database {
        return Err(SchemaRollbackError::UnsafePath);
    }
    if &file_identity(snapshot).map_err(|_| SchemaRollbackError::SnapshotMismatch)?
        != expected_snapshot
        || sha256_file(snapshot)
            .map_err(|_| SchemaRollbackError::SnapshotMismatch)?
            .as_slice()
            != expected_digest
    {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    let version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?;
    if !is_supported_pre_v12_rollback_source(conn, version)
        .map_err(|_| SchemaRollbackError::UnsupportedSchema)?
        || v12_write_latch_closed(conn).map_err(|_| SchemaRollbackError::UnsupportedSchema)?
        || !current_v12_high_water_matches(conn, fence)?
    {
        return Err(SchemaRollbackError::RollbackClosed);
    }
    Ok(())
}

fn resolve_private_snapshot(
    db_path: &Path,
    snapshot_filename: &str,
) -> Result<PathBuf, SchemaRollbackError> {
    if !safe_snapshot_filename(snapshot_filename) {
        return Err(SchemaRollbackError::UnsafePath);
    }
    let database = fs::canonicalize(db_path).map_err(|_| SchemaRollbackError::UnsafePath)?;
    let parent = database.parent().ok_or(SchemaRollbackError::UnsafePath)?;
    let snapshot = parent.join(snapshot_filename);
    let metadata =
        fs::symlink_metadata(&snapshot).map_err(|_| SchemaRollbackError::SnapshotUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SchemaRollbackError::SnapshotMismatch);
    }
    let snapshot = fs::canonicalize(snapshot).map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
    if snapshot.parent() != Some(parent) {
        return Err(SchemaRollbackError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let database_metadata =
            fs::metadata(database).map_err(|_| SchemaRollbackError::SnapshotMismatch)?;
        if metadata.uid() != database_metadata.uid()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(SchemaRollbackError::SnapshotMismatch);
        }
    }
    Ok(snapshot)
}
