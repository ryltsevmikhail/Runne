/// Generate a new random authority ID.
pub fn generate_authority_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

/// Read the authority ID from the database.
/// Returns None if no row exists.
pub fn read_authority_id(conn: &Connection) -> SqliteResult<Option<[u8; 16]>> {
    let mut stmt = conn.prepare("SELECT authority_id FROM _authority WHERE id = 1")?;
    let mut rows = stmt.query([])?;
    match rows.next()? {
        Some(row) => {
            let blob: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&blob);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

/// Insert authority ID (only if no row exists — idempotent).
pub fn ensure_authority_id(conn: &Connection, authority_id: &[u8; 16]) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO _authority (id, authority_id) VALUES (1, ?1)",
        rusqlite::params![authority_id.as_slice()],
    )?;
    Ok(())
}

/// Returns the durable UUIDv7 identity of the current Event Log lineage,
/// creating it once for a newly initialized database.
pub fn ensure_event_log_lineage_id(conn: &Connection) -> SqliteResult<EventLogLineageId> {
    const KEY: &str = "event_log_lineage_id";

    conn.execute(
        "INSERT OR IGNORE INTO _daemon_info (key, value) VALUES (?1, ?2)",
        (KEY, uuid::Uuid::now_v7().to_string()),
    )?;
    let value: String = conn.query_row(
        "SELECT value FROM _daemon_info WHERE key = ?1",
        [KEY],
        |row| row.get(0),
    )?;
    value.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

/// Reads the existing Event Log lineage without creating or rewriting it.
pub fn read_event_log_lineage_id(conn: &Connection) -> SqliteResult<Option<EventLogLineageId>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'event_log_lineage_id'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| {
            value.parse().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

/// Creates or verifies the exact prepared first-activation lineage.
pub fn ensure_exact_event_log_lineage_id(
    conn: &Connection,
    expected: EventLogLineageId,
) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO _daemon_info (key, value)
         VALUES ('event_log_lineage_id', ?1)",
        [expected.to_string()],
    )?;
    if read_event_log_lineage_id(conn)? == Some(expected) {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

/// Creates or verifies the exact durable first-activation preparation ID.
pub fn ensure_exact_first_activation_preparation(
    conn: &Connection,
    preparation_id: &[u8; 16],
) -> SqliteResult<()> {
    if validate_uuid_v7_bytes(preparation_id).is_err() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let expected = uuid::Uuid::from_bytes(*preparation_id).to_string();
    conn.execute(
        "INSERT OR IGNORE INTO _daemon_info (key, value)
         VALUES ('protected_first_activation_preparation_v1', ?1)",
        [&expected],
    )?;
    let actual: String = conn.query_row(
        "SELECT value FROM _daemon_info
         WHERE key = 'protected_first_activation_preparation_v1'",
        [],
        |row| row.get(0),
    )?;
    if actual == expected {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

/// Reads the durable first-activation preparation identity without mutation.
pub fn read_first_activation_preparation(conn: &Connection) -> SqliteResult<Option<[u8; 16]>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM _daemon_info
             WHERE key = 'protected_first_activation_preparation_v1'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| {
            let parsed = uuid::Uuid::parse_str(&value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            let bytes = *parsed.as_bytes();
            validate_uuid_v7_bytes(&bytes).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(bytes)
        })
        .transpose()
}

/// Read-only classification for a committed or safely resumable first activation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FirstActivationResumeState {
    /// Exact identity is durable and at least one protected launch completed.
    Prepared,
    /// Exact identity is durable, but sidecar provisioning did not yet reach
    /// launch-authority consumption or generation allocation.
    RecoverablePrepared,
    /// Migrations may have created the file, but no launch was consumed or run.
    RecoverablePartial,
}

/// Atomically creates or verifies the complete prepared first-activation identity.
pub fn ensure_exact_first_activation_identity(
    conn: &Connection,
    authority_id: &[u8; 16],
    lineage_id: EventLogLineageId,
    preparation_id: &[u8; 16],
) -> SqliteResult<()> {
    validate_uuid_v7_bytes(authority_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    validate_uuid_v7_bytes(preparation_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| {
        ensure_authority_id(conn, authority_id)?;
        ensure_exact_event_log_lineage_id(conn, lineage_id)?;
        ensure_exact_first_activation_preparation(conn, preparation_id)?;
        if read_authority_id(conn)? != Some(*authority_id)
            || read_event_log_lineage_id(conn)? != Some(lineage_id)
            || read_first_activation_preparation(conn)? != Some(*preparation_id)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(())
    })();
    match result {
        Ok(()) => conn.execute_batch("COMMIT"),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

/// Classifies an existing database before resuming an exact prepared activation.
///
/// A partial database is recoverable only before any launch generation or
/// protected launch authority has been persisted, and only when its authority
/// is absent or already equals the signed prepared authority.
pub fn preflight_first_activation_resume(
    conn: &Connection,
    authority_id: &[u8; 16],
    lineage_id: EventLogLineageId,
    preparation_id: &[u8; 16],
) -> SqliteResult<FirstActivationResumeState> {
    validate_uuid_v7_bytes(authority_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    validate_uuid_v7_bytes(preparation_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let authority = read_authority_id(conn)?;
    let lineage = read_event_log_lineage_id(conn)?;
    let preparation = read_first_activation_preparation(conn)?;
    let launch_generation: Option<String> = conn
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let consumed_authorities: i64 = conn.query_row(
        "SELECT COUNT(*) FROM _daemon_info
         WHERE key LIKE 'protected_launch_authority_v1:%'",
        [],
        |row| row.get(0),
    )?;
    if authority == Some(*authority_id)
        && lineage == Some(lineage_id)
        && preparation == Some(*preparation_id)
    {
        return match (launch_generation.is_some(), consumed_authorities > 0) {
            (true, true) => Ok(FirstActivationResumeState::Prepared),
            (false, false) => Ok(FirstActivationResumeState::RecoverablePrepared),
            _ => Err(rusqlite::Error::InvalidQuery),
        };
    }
    if authority.is_none_or(|actual| actual == *authority_id)
        && lineage.is_none()
        && preparation.is_none()
        && launch_generation.is_none()
        && consumed_authorities == 0
    {
        return Ok(FirstActivationResumeState::RecoverablePartial);
    }
    Err(rusqlite::Error::InvalidQuery)
}
