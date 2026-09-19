use crate::project_trust_store::{
    PROJECT_TRUST_IDENTITY_SQL, PROJECT_TRUST_SCHEMA_KIND, PROJECT_TRUST_SCHEMA_VERSION,
    PROJECT_TRUST_SIDECAR_VERSION, PROJECT_TRUST_TRUST_SQL,
};

pub(crate) fn reopen_managed_project_trust_sidecar(
    path: &Path,
    expected_authority: [u8; 16],
) -> SqliteResult<(ManagedConnection, u64)> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, expected_authority);
        Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent))
    }
    #[cfg(any(unix, windows))]
    {
        let mut identity =
            ConnectionIdentityGuard::owner_private(path).map_err(diagnostic_error)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        identity.retain_created_sidecars()?;
        identity.verify(&connection)?;
        connection.execute_batch("PRAGMA query_only = ON;")?;
        classify_project_trust_sidecar(&connection)?;
        let instance_epoch = validate_project_trust_authority(&connection, expected_authority)?;
        identity.retain_created_sidecars()?;
        identity.verify_with_sidecar_handle(&connection)?;
        connection.execute_batch("PRAGMA query_only = OFF;")?;
        let managed = managed_after_profile(
            connection,
            ConnectionMode::ValidatedReopen,
            false,
            Some(identity),
        )?;
        Ok((managed, instance_epoch))
    }
}

fn classify_project_trust_sidecar(connection: &Connection) -> SqliteResult<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != PROJECT_TRUST_SIDECAR_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let catalog = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    let expected = [
        ("table", "project_trust", PROJECT_TRUST_TRUST_SQL),
        ("table", "project_trust_schema", PROJECT_TRUST_IDENTITY_SQL),
    ];
    if catalog.len() != expected.len()
        || catalog.iter().zip(expected).any(
            |((kind, name, sql), (expected_kind, expected_name, expected_sql))| {
                kind != expected_kind || name != expected_name || sql != expected_sql
            },
        )
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn validate_project_trust_authority(
    connection: &Connection,
    expected_authority: [u8; 16],
) -> SqliteResult<u64> {
    let identity = connection.query_row(
        "SELECT schema_kind, schema_version, instance_epoch, authority_id
         FROM project_trust_schema WHERE id = 1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        },
    )?;
    if identity.0 != PROJECT_TRUST_SCHEMA_KIND
        || identity.1 != PROJECT_TRUST_SCHEMA_VERSION
        || identity.2 <= 0
        || identity.3 != expected_authority
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    u64::try_from(identity.2).map_err(|_| rusqlite::Error::InvalidQuery)
}
