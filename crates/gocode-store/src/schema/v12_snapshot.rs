struct PrivateDatabaseBackup {
    filename: String,
    digest: [u8; 32],
}

struct V11UpgradeSnapshot {
    backup: Option<PrivateDatabaseBackup>,
    baseline_event_next_position: i64,
    baseline_provider_prepared_count: i64,
    baseline_provider_attempt_count: i64,
}

struct V12UpgradeFenceRow {
    snapshot_filename: Option<String>,
    snapshot_digest: Option<Vec<u8>>,
    baseline_event_next_position: i64,
    baseline_provider_prepared_count: i64,
    baseline_provider_attempt_count: i64,
}

fn create_v11_upgrade_snapshot(conn: &Connection) -> SqliteResult<V11UpgradeSnapshot> {
    let version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if version != 11 || !is_released_provider_v11(conn, 11)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(V11UpgradeSnapshot {
        backup: conn
            .path()
            .filter(|path| !path.is_empty())
            .map(|path| create_private_database_backup(conn, Path::new(path)))
            .transpose()?,
        baseline_event_next_position: conn.query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?,
        baseline_provider_prepared_count: conn.query_row(
            "SELECT COUNT(*) FROM provider_prepared_requests",
            [],
            |row| row.get(0),
        )?,
        baseline_provider_attempt_count: conn.query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts",
            [],
            |row| row.get(0),
        )?,
    })
}

fn create_private_database_backup(
    _conn: &Connection,
    source: &Path,
) -> SqliteResult<PrivateDatabaseBackup> {
    let source = fs::canonicalize(source).map_err(io_error)?;
    if !path_is_safe(&source) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    let filename = format!(
        "{}.gocode-v11-pre-v12-{:032x}.sqlite",
        source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| rusqlite::Error::InvalidPath(source.clone()))?,
        rand::random::<u128>()
    );
    let path = source
        .parent()
        .ok_or_else(|| rusqlite::Error::InvalidPath(source.clone()))?
        .join(&filename);
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    drop(file);
    let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    if !is_released_provider_v11(&source, 11)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    source.backup(DatabaseName::Main, &path, None)?;
    secure_file_permissions(&path).map_err(io_error)?;
    let snapshot = Connection::open(&path)?;
    let version: i64 = snapshot.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    let integrity: String = snapshot.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if version != 11
        || integrity != "ok"
        || snapshot.prepare("PRAGMA foreign_key_check")?.exists([])?
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    drop(snapshot);
    Ok(PrivateDatabaseBackup {
        filename,
        digest: sha256_file(&path).map_err(io_error)?,
    })
}

fn load_v12_upgrade_fence(conn: &Connection) -> SqliteResult<Option<V12UpgradeFenceRow>> {
    conn.query_row("SELECT snapshot_filename, snapshot_digest, baseline_event_next_position, baseline_provider_prepared_count, baseline_provider_attempt_count FROM schema_upgrade_fence WHERE id = 1", [], |row| Ok(V12UpgradeFenceRow { snapshot_filename: row.get(0)?, snapshot_digest: row.get(1)?, baseline_event_next_position: row.get(2)?, baseline_provider_prepared_count: row.get(3)?, baseline_provider_attempt_count: row.get(4)? })).optional()
}

fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn io_error(error: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn safe_snapshot_filename(filename: &str) -> bool {
    !filename.is_empty()
        && filename.len() <= 255
        && !filename.contains(['/', '\\'])
        && Path::new(filename)
            .file_name()
            .and_then(|name| name.to_str())
            == Some(filename)
}
