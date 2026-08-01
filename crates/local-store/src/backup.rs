fn verify_pre_v4_backup_path(path: &Path) -> Result<PreV4MigrationBackup, StoreOpenError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| StoreOpenError::MigrationBackupUnavailable)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreOpenError::MigrationBackupUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreOpenError::MigrationBackupUnavailable);
        }
    }
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| StoreOpenError::MigrationBackupUnavailable)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| StoreOpenError::MigrationBackupUnavailable)?;
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| StoreOpenError::MigrationBackupUnavailable)?;
    let meta_version: i64 = connection
        .query_row(
            "SELECT schema_version FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreOpenError::MigrationBackupUnavailable)?;
    if integrity != "ok" || user_version != 3 || meta_version != 3 {
        return Err(StoreOpenError::MigrationBackupUnavailable);
    }
    Ok(PreV4MigrationBackup {
        path: path.to_path_buf(),
        schema_version: 3,
    })
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), StoreOpenError> {
    let parent = path
        .parent()
        .ok_or(StoreOpenError::MigrationBackupUnavailable)?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StoreOpenError::MigrationBackupUnavailable)
}

#[cfg(not(unix))]
fn sync_parent_directory(_: &Path) -> Result<(), StoreOpenError> {
    Ok(())
}
