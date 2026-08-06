/// Open a database connection with the standard set of PRAGMAs.
pub fn open_with_pragmas(db_path: &str) -> SqliteResult<Connection> {
    let is_memory = db_path == ":memory:";
    let path = Path::new(db_path);
    let is_new_file = !is_memory && !path.exists();
    let mut existing_identity = None;
    if !is_memory && !path_is_safe(path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    if !is_memory && !is_new_file {
        existing_identity = Some(file_identity(path).map_err(diagnostic_error)?);
        preflight_existing_file(path)?;
    }
    if is_new_file {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => drop(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A competing creator won the race. Treat its file as existing
                // and never initialise it through this caller.
                return Err(diagnostic_error(
                    SchemaOpenDiagnostic::FileIdentityUncertain,
                ));
            }
            Err(error) => return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(error))),
        }
    }
    let conn = if !is_memory && !is_new_file {
        Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?
    } else {
        Connection::open(db_path)?
    };

    if let Some(identity) = existing_identity {
        conn.execute_batch("PRAGMA query_only = ON;")?;
        classify_existing_connection(&conn)?;
        if file_identity(path).map_err(diagnostic_error)? != identity {
            return Err(diagnostic_error(
                SchemaOpenDiagnostic::FileIdentityUncertain,
            ));
        }
        conn.execute_batch("PRAGMA query_only = OFF;")?;
    }

    if is_new_file {
        #[cfg(unix)]
        secure_file_permissions(path)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    }

    configure_writable_pragmas(&conn)?;

    // WAL sidecars are created by the PRAGMA above. Secure them before this
    // newly created database is returned for writable migrations.
    if is_new_file {
        secure_present_sidecars(path)?;
    }

    Ok(conn)
}

fn configure_writable_pragmas(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;

    // macOS-specific: fullfsync
    #[cfg(target_os = "macos")]
    {
        conn.execute_batch("PRAGMA fullfsync = ON;")?;
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

// ── Authority ID ────────────────────────────────────────────────────────
