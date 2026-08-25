fn open_connection_for_profile(
    db_path: &Path,
    mode: ConnectionMode,
) -> SqliteResult<(Connection, Option<ConnectionIdentityGuard>)> {
    open_connection_for_profile_with_hook(db_path, mode, |_| Ok(()))
}

fn open_connection_for_profile_with_hook<F>(
    db_path: &Path,
    mode: ConnectionMode,
    mut identity_hook: F,
) -> SqliteResult<(Connection, Option<ConnectionIdentityGuard>)>
where
    F: FnMut(IdentityHookStage) -> SqliteResult<()>,
{
    let is_memory = db_path == Path::new(":memory:");
    let is_new_file = !is_memory && !db_path.exists();
    if !is_memory && !path_is_safe(db_path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    if mode == ConnectionMode::Reader && is_new_file {
        return Err(rusqlite::Error::InvalidPath(db_path.to_path_buf()));
    }
    if mode == ConnectionMode::Reader && !is_memory && existing_sidecar_present(db_path) {
        return open_owner_private_hot_reader(db_path, identity_hook)
            .map(|(connection, guard)| (connection, Some(guard)));
    }

    let identity = if !is_memory && !is_new_file {
        preflight_existing_file(db_path)?;
        Some(ConnectionIdentityGuard::main(db_path).map_err(diagnostic_error)?)
    } else if is_new_file {
        Some(create_new_database_file(db_path)?)
    } else {
        None
    };
    identity_hook(IdentityHookStage::Retained)?;

    let connection = open_profile_connection(db_path, mode, is_memory)?;
    identity_hook(IdentityHookStage::Opened)?;
    verify_connection_identity(&connection, identity.as_ref())?;
    if !is_memory && !is_new_file {
        connection.execute_batch("PRAGMA query_only = ON;")?;
        classify_existing_connection(&connection)?;
        identity_hook(IdentityHookStage::Classified)?;
        verify_connection_identity(&connection, identity.as_ref())?;
        connection.execute_batch("PRAGMA query_only = OFF;")?;
    }

    if is_new_file {
        #[cfg(any(unix, windows))]
        secure_file_permissions(db_path)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    }
    if mode == ConnectionMode::Writer && !is_memory {
        verify_connection_identity(&connection, identity.as_ref())?;
        initialize_wal_once(&connection)?;
        if is_new_file {
            secure_present_sidecars(db_path)?;
        }
    }
    verify_connection_identity(&connection, identity.as_ref())?;
    Ok((connection, identity))
}

fn open_owner_private_hot_reader<F>(
    path: &Path,
    mut identity_hook: F,
) -> SqliteResult<(Connection, ConnectionIdentityGuard)>
where
    F: FnMut(IdentityHookStage) -> SqliteResult<()>,
{
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, identity_hook);
        Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent))
    }
    #[cfg(any(unix, windows))]
    {
        let mut identity = ConnectionIdentityGuard::owner_private(path).map_err(diagnostic_error)?;
        identity_hook(IdentityHookStage::Retained)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        identity_hook(IdentityHookStage::Opened)?;
        identity.retain_created_sidecars()?;
        identity.verify(&connection)?;
        connection.execute_batch("PRAGMA query_only = ON;")?;
        classify_existing_connection(&connection)?;
        identity_hook(IdentityHookStage::Classified)?;
        identity.verify_with_sidecar_handle(&connection)?;
        connection.execute_batch("PRAGMA query_only = OFF;")?;
        Ok((connection, identity))
    }
}

fn create_new_database_file(path: &Path) -> SqliteResult<ConnectionIdentityGuard> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    match options
        .write(true)
        .open(path)
    {
        Ok(file) => ConnectionIdentityGuard::from_created(path, file).map_err(diagnostic_error),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(diagnostic_error(
            SchemaOpenDiagnostic::FileIdentityUncertain,
        )),
        Err(error) => Err(rusqlite::Error::ToSqlConversionFailure(Box::new(error))),
    }
}

fn open_profile_connection(
    path: &Path,
    mode: ConnectionMode,
    is_memory: bool,
) -> SqliteResult<Connection> {
    if is_memory {
        return Connection::open_in_memory();
    }
    let flags = if mode == ConnectionMode::Reader {
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
    };
    Connection::open_with_flags(path, flags)
}

fn initialize_wal_once(connection: &Connection) -> SqliteResult<()> {
    let current: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if current.eq_ignore_ascii_case("wal") {
        return Ok(());
    }
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(profile_mismatch("journal_mode", &journal_mode, "wal"));
    }
    Ok(())
}

fn secure_present_sidecars(path: &Path) -> SqliteResult<()> {
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    #[cfg(any(unix, windows))]
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(path, suffix);
        if sidecar.exists() {
            secure_file_permissions(&sidecar)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        }
    }
    Ok(())
}
