const SCANNER_SIDECAR_KIND: &str = "gocode.provider-scanner-recovery";
const SCANNER_SIDECAR_VERSION: i64 = 1;

pub(crate) const SCANNER_IDENTITY_SQL: &str = "CREATE TABLE scanner_recovery_schema (id INTEGER PRIMARY KEY CHECK(id = 1), schema_kind TEXT NOT NULL CHECK(schema_kind = 'gocode.provider-scanner-recovery'), schema_version INTEGER NOT NULL CHECK(schema_version = 1), authority_id BLOB NOT NULL CHECK(length(authority_id) = 16))";
pub(crate) const SCANNER_RECOVERY_SQL: &str = "CREATE TABLE provider_scanner_recovery (attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16), fencing_token INTEGER NOT NULL CHECK(fencing_token > 0), policy_epoch INTEGER NOT NULL CHECK(policy_epoch > 0), matcher_epoch INTEGER NOT NULL CHECK(matcher_epoch > 0), algorithm_version INTEGER NOT NULL CHECK(algorithm_version > 0), tail_id BLOB CHECK(tail_id IS NULL OR length(tail_id) = 16), tail_version INTEGER CHECK(tail_version IS NULL OR tail_version > 0), binding_digest BLOB CHECK(binding_digest IS NULL OR length(binding_digest) = 32), checkpoint_sequence INTEGER CHECK(checkpoint_sequence IS NULL OR checkpoint_sequence > 0), checkpoint_cursor INTEGER CHECK(checkpoint_cursor IS NULL OR checkpoint_cursor >= 0), checkpoint_safe_high_water INTEGER CHECK(checkpoint_safe_high_water IS NULL OR checkpoint_safe_high_water >= 0), checkpoint_id BLOB CHECK(checkpoint_id IS NULL OR length(checkpoint_id) = 16), checkpoint_digest BLOB CHECK(checkpoint_digest IS NULL OR length(checkpoint_digest) = 32), durable_cursor INTEGER NOT NULL DEFAULT 0 CHECK(durable_cursor >= 0), durable_safe_high_water INTEGER NOT NULL DEFAULT 0 CHECK(durable_safe_high_water >= 0), durable_checkpoint_digest BLOB CHECK(durable_checkpoint_digest IS NULL OR length(durable_checkpoint_digest) = 32), disposition INTEGER CHECK(disposition IS NULL OR disposition BETWEEN 1 AND 6), CHECK((tail_id IS NULL AND tail_version IS NULL AND binding_digest IS NULL AND checkpoint_sequence IS NULL AND checkpoint_cursor IS NULL AND checkpoint_safe_high_water IS NULL AND checkpoint_id IS NULL AND checkpoint_digest IS NULL) OR (tail_id IS NOT NULL AND tail_version IS NOT NULL AND binding_digest IS NOT NULL AND checkpoint_sequence IS NOT NULL AND checkpoint_cursor IS NOT NULL AND checkpoint_safe_high_water IS NOT NULL AND checkpoint_id IS NOT NULL AND checkpoint_digest IS NOT NULL)))";

pub(crate) fn reopen_managed_scanner_sidecar(
    path: &Path,
    expected_authority: [u8; 16],
) -> SqliteResult<ManagedConnection> {
    #[cfg(not(unix))]
    {
        let _ = (path, expected_authority);
        Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent))
    }
    #[cfg(unix)]
    {
        let file_set = owner_private_recovery_file_set(path).map_err(diagnostic_error)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.execute_batch("PRAGMA query_only = ON;")?;
        classify_scanner_sidecar(&connection)?;
        validate_scanner_authority(&connection, expected_authority)?;
        if !recovery_file_set_unchanged(path, &file_set).map_err(diagnostic_error)? {
            return Err(diagnostic_error(
                SchemaOpenDiagnostic::FileIdentityUncertain,
            ));
        }
        connection.execute_batch("PRAGMA query_only = OFF;")?;
        managed_after_profile(connection, ConnectionMode::ValidatedReopen, false)
    }
}

fn classify_scanner_sidecar(connection: &Connection) -> SqliteResult<()> {
    let version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCANNER_SIDECAR_VERSION {
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
        (
            "table",
            "provider_scanner_recovery",
            SCANNER_RECOVERY_SQL,
        ),
        ("table", "scanner_recovery_schema", SCANNER_IDENTITY_SQL),
    ];
    if catalog.len() != expected.len()
        || catalog
            .iter()
            .zip(expected)
            .any(|((kind, name, sql), (expected_kind, expected_name, expected_sql))| {
                kind != expected_kind || name != expected_name || sql != expected_sql
            })
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn validate_scanner_authority(
    connection: &Connection,
    expected_authority: [u8; 16],
) -> SqliteResult<()> {
    let identity = connection.query_row(
        "SELECT schema_kind, schema_version, authority_id
         FROM scanner_recovery_schema WHERE id = 1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        },
    )?;
    if identity
        == (
            SCANNER_SIDECAR_KIND.to_owned(),
            SCANNER_SIDECAR_VERSION,
            expected_authority.to_vec(),
        )
    {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}
