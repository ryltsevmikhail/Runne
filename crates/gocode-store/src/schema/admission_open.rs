/// Reject unsupported existing database schemas without changing the file.
///
/// File-backed verification stores call this before enabling WAL or applying
/// migrations, so an unsupported future or candidate schema remains untouched.
pub fn preflight_existing_file(db_path: &Path) -> SqliteResult<()> {
    if !path_is_safe(db_path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    let identity = file_identity(db_path).map_err(diagnostic_error)?;
    let metadata = fs::metadata(db_path)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    if metadata.len() == 0 {
        return Err(diagnostic_error(SchemaOpenDiagnostic::ZeroByteDatabase));
    }
    let sidecar_present = existing_sidecar_present(db_path);
    if sidecar_present && !identity_is_admitted(db_path).map_err(diagnostic_error)? {
        return Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent));
    }
    if sidecar_present {
        return Ok(());
    }

    let immutable_uri = immutable_read_only_uri(db_path).map_err(diagnostic_error)?;
    let conn = Connection::open_with_flags(
        immutable_uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    classify_existing_connection(&conn)?;
    drop(conn);
    if file_identity(db_path).map_err(diagnostic_error)? != identity {
        return Err(diagnostic_error(
            SchemaOpenDiagnostic::FileIdentityUncertain,
        ));
    }
    Ok(())
}

/// Opens one already-classified database read-only without creating WAL
/// sidecars when the main file is self-contained.
///
/// An already-admitted hot WAL in the current process uses SQLite's normal
/// read-only view so committed WAL data is not ignored.
pub fn open_existing_read_only(db_path: &Path) -> SqliteResult<Connection> {
    preflight_existing_file(db_path)?;
    if existing_sidecar_present(db_path) {
        return Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY);
    }
    let immutable_uri = immutable_read_only_uri(db_path).map_err(diagnostic_error)?;
    Connection::open_with_flags(
        immutable_uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

/// Validates an owner-private hot-WAL file set, runs an exact read-only
/// protected-runtime check, and admits only that unchanged file identity for
/// the next writable open in this process.
///
/// This is deliberately separate from [`open_existing_read_only`]: arbitrary
/// databases with WAL sidecars remain rejected. The caller must validate its
/// signed stable runtime binding in `validate`; a rejected validation never
/// admits the file for a writable open.
pub fn with_protected_recovery_read_only_admission<F>(
    db_path: &Path,
    validate: F,
) -> SqliteResult<()>
where
    F: FnOnce(&Connection) -> SqliteResult<()>,
{
    #[cfg(not(unix))]
    {
        let _ = (db_path, validate);
        return Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent));
    }
    #[cfg(unix)]
    {
        validate_owner_private_recovery_files(db_path).map_err(diagnostic_error)?;
        let identity = file_identity(db_path).map_err(diagnostic_error)?;
        let connection = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        classify_existing_connection(&connection)?;
        validate(&connection)?;
        if file_identity(db_path).map_err(diagnostic_error)? != identity {
            return Err(diagnostic_error(
                SchemaOpenDiagnostic::FileIdentityUncertain,
            ));
        }
        validate_owner_private_recovery_files(db_path).map_err(diagnostic_error)?;
        admit_identity(db_path).map_err(diagnostic_error)
    }
}
