fn verify_pre_v4_backup_path(path: &Path) -> Result<PreV4MigrationBackup, StoreOpenError> {
    verify_migration_backup_path(path, 3)
}

fn verify_pre_v5_backup_path(path: &Path) -> Result<PreV4MigrationBackup, StoreOpenError> {
    verify_migration_backup_path(path, 4).and_then(|backup| {
        crate::recent_root_schema::validate_v4_projects(&open_backup(path)?)
            .map_err(|_| StoreOpenError::PreV5BackupInvalid)?;
        Ok(backup)
    })
}

fn verify_migration_backup_path(
    path: &Path,
    schema_version: u32,
) -> Result<PreV4MigrationBackup, StoreOpenError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| StoreOpenError::MigrationBackupUnavailable)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreOpenError::MigrationBackupUnavailable);
    }
    if schema_version == 4 && !backup_sidecars_absent(path)? {
        return Err(StoreOpenError::MigrationBackupUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreOpenError::MigrationBackupUnavailable);
        }
    }
    let connection = open_backup(path)
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
    if integrity != "ok"
        || user_version != i64::from(schema_version)
        || meta_version != i64::from(schema_version)
    {
        return Err(StoreOpenError::MigrationBackupUnavailable);
    }
    Ok(PreV4MigrationBackup {
        path: path.to_path_buf(),
        schema_version,
    })
}

fn open_backup(path: &Path) -> Result<Connection, StoreOpenError> {
    Connection::open_with_flags(
        backup_uri(path).map_err(|_| StoreOpenError::MigrationBackupUnavailable)?,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| StoreOpenError::MigrationBackupUnavailable)
}

fn backup_uri(path: &Path) -> Result<String, StoreOpenError> {
    let path = path.to_str().ok_or(StoreOpenError::PreV5BackupRecoveryRequired)?;
    let escaped = path.bytes().fold(String::new(), |mut uri, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _ = write!(uri, "%{byte:02X}");
        }
        uri
    });
    Ok(format!("file:{escaped}?mode=ro&immutable=1"))
}

pub(crate) fn backup_sidecars_absent(path: &Path) -> Result<bool, StoreOpenError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sibling = path.as_os_str().to_os_string();
        sibling.push(suffix);
        match std::fs::symlink_metadata(PathBuf::from(sibling)) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreOpenError::MigrationBackupUnavailable),
        }
    }
    Ok(true)
}
