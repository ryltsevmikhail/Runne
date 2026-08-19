/// Reject unsupported existing database schemas without changing the file.
///
/// File-backed verification stores call this before enabling WAL or applying
/// migrations, so an unsupported future or candidate schema remains untouched.
pub fn preflight_existing_file(db_path: &Path) -> SqliteResult<()> {
    drop(open_classified_immutable_read_only(db_path)?);
    Ok(())
}

fn open_classified_immutable_read_only(db_path: &Path) -> SqliteResult<Connection> {
    open_classified_immutable_read_only_with_hook(db_path, |_| Ok(()))
}

fn open_classified_immutable_read_only_with_hook<F>(
    db_path: &Path,
    mut identity_hook: F,
) -> SqliteResult<Connection>
where
    F: FnMut(IdentityHookStage) -> SqliteResult<()>,
{
    if !path_is_safe(db_path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::UnsafePath));
    }
    let identity = ConnectionIdentityGuard::main(db_path).map_err(diagnostic_error)?;
    let metadata = fs::metadata(db_path)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    if metadata.len() == 0 {
        return Err(diagnostic_error(SchemaOpenDiagnostic::ZeroByteDatabase));
    }
    if existing_sidecar_present(db_path) {
        return Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent));
    }
    identity_hook(IdentityHookStage::Retained)?;

    let immutable_uri = immutable_read_only_uri(db_path).map_err(diagnostic_error)?;
    let conn = Connection::open_with_flags(
        immutable_uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    identity_hook(IdentityHookStage::Opened)?;
    identity.verify(&conn)?;
    classify_existing_connection(&conn)?;
    identity_hook(IdentityHookStage::Classified)?;
    identity.verify(&conn)?;
    Ok(conn)
}

/// Opens one already-classified self-contained database read-only without
/// creating WAL sidecars.
pub fn open_existing_read_only(db_path: &Path) -> SqliteResult<Connection> {
    open_classified_immutable_read_only(db_path)
}

/// Opens a validated owner-private existing database and retains its profile proof.
///
/// On Unix, the validator receives the same connection that is later returned.
/// It runs with `query_only` enabled, after schema classification and before
/// any writable PRAGMA is applied. The owner-private main/WAL/SHM file set is
/// checked again before writes are enabled. Default openers never inherit this
/// authorization.
/// Windows intentionally fails closed until it has an equivalent protected
/// handle-based implementation.
pub fn reopen_managed_connection_validated<F>(
    db_path: &Path,
    mode: ConnectionMode,
    validate: F,
) -> SqliteResult<ManagedConnection>
where
    F: FnOnce(&Connection) -> SqliteResult<()>,
{
    reopen_managed_connection_validated_with_hook(db_path, mode, |_| Ok(()), validate)
}

fn reopen_managed_connection_validated_with_hook<F, H>(
    db_path: &Path,
    mode: ConnectionMode,
    mut identity_hook: H,
    validate: F,
) -> SqliteResult<ManagedConnection>
where
    F: FnOnce(&Connection) -> SqliteResult<()>,
    H: FnMut(IdentityHookStage) -> SqliteResult<()>,
{
    if !matches!(mode, ConnectionMode::Reader | ConnectionMode::ValidatedReopen) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    #[cfg(not(unix))]
    {
        let _ = (db_path, mode, identity_hook, validate);
        Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent))
    }
    #[cfg(unix)]
    {
        let mut identity = ConnectionIdentityGuard::owner_private(db_path).map_err(diagnostic_error)?;
        identity_hook(IdentityHookStage::Retained)?;
        let flags = if mode == ConnectionMode::Reader {
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
        };
        let connection = Connection::open_with_flags(db_path, flags)?;
        identity_hook(IdentityHookStage::Opened)?;
        identity.retain_created_sidecars()?;
        identity.verify(&connection)?;
        connection.execute_batch("PRAGMA query_only = ON;")?;
        classify_existing_connection(&connection)?;
        identity_hook(IdentityHookStage::Classified)?;
        validate(&connection)?;
        identity.retain_created_sidecars()?;
        identity.verify_with_sidecar_handle(&connection)?;
        connection.execute_batch("PRAGMA query_only = OFF;")?;
        managed_after_profile(connection, mode, false, Some(identity))
    }
}

/// Compatibility protected read-only preflight that retains no authorization.
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
        Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent))
    }
    #[cfg(unix)]
    {
        let mut identity = ConnectionIdentityGuard::owner_private(db_path).map_err(diagnostic_error)?;
        let connection = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        identity.verify(&connection)?;
        classify_existing_connection(&connection)?;
        validate(&connection)?;
        identity.retain_created_sidecars()?;
        identity.verify_with_sidecar_handle(&connection)?;
        Ok(())
    }
}
