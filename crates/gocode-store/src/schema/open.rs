fn open_connection_for_profile(
    db_path: &Path,
    mode: ConnectionMode,
) -> SqliteResult<Connection> {
    let is_memory = db_path == Path::new(":memory:");
    let is_new_file = !is_memory && !db_path.exists();
    if !is_memory && !path_is_safe(db_path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    if mode == ConnectionMode::Reader && is_new_file {
        return Err(rusqlite::Error::InvalidPath(db_path.to_path_buf()));
    }
    if mode == ConnectionMode::Reader && !is_memory && existing_sidecar_present(db_path) {
        return open_owner_private_hot_reader(db_path);
    }

    let existing_identity = if !is_memory && !is_new_file {
        preflight_existing_file(db_path)?;
        Some(file_identity(db_path).map_err(diagnostic_error)?)
    } else {
        None
    };
    if is_new_file {
        create_new_database_file(db_path)?;
    }

    let connection = open_profile_connection(db_path, mode, is_memory)?;
    if let Some(identity) = existing_identity {
        connection.execute_batch("PRAGMA query_only = ON;")?;
        classify_existing_connection(&connection)?;
        if file_identity(db_path).map_err(diagnostic_error)? != identity {
            return Err(diagnostic_error(
                SchemaOpenDiagnostic::FileIdentityUncertain,
            ));
        }
        connection.execute_batch("PRAGMA query_only = OFF;")?;
    }

    if is_new_file {
        #[cfg(unix)]
        secure_file_permissions(db_path)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    }
    if mode == ConnectionMode::Writer && !is_memory {
        initialize_wal_once(&connection)?;
        if is_new_file {
            secure_present_sidecars(db_path)?;
        }
    }
    Ok(connection)
}

fn open_owner_private_hot_reader(path: &Path) -> SqliteResult<Connection> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent))
    }
    #[cfg(unix)]
    {
        let file_set = owner_private_recovery_file_set(path).map_err(diagnostic_error)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.execute_batch("PRAGMA query_only = ON;")?;
        classify_existing_connection(&connection)?;
        if !recovery_file_set_unchanged(path, &file_set).map_err(diagnostic_error)? {
            return Err(diagnostic_error(
                SchemaOpenDiagnostic::FileIdentityUncertain,
            ));
        }
        connection.execute_batch("PRAGMA query_only = OFF;")?;
        Ok(connection)
    }
}

fn create_new_database_file(path: &Path) -> SqliteResult<()> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => drop(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(diagnostic_error(
                SchemaOpenDiagnostic::FileIdentityUncertain,
            ));
        }
        Err(error) => return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(error))),
    }
    Ok(())
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
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(path, suffix);
        if sidecar.exists() {
            secure_file_permissions(&sidecar)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        }
    }
    Ok(())
}
