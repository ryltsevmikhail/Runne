/// Closed result of durably consuming one protected launch authority.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LaunchAuthorityConsumptionError {
    /// The same non-secret authority identity was already consumed.
    AlreadyConsumed,
    /// The authority identity is not a UUIDv7.
    InvalidAuthority,
    /// SQLite could not atomically persist the consumption record.
    Storage,
}

impl fmt::Display for LaunchAuthorityConsumptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyConsumed => "launch authority already consumed",
            Self::InvalidAuthority => "launch authority is invalid",
            Self::Storage => "launch authority storage unavailable",
        })
    }
}

impl std::error::Error for LaunchAuthorityConsumptionError {}

/// Atomically consumes a non-secret launch-authority identity.
///
/// The durable marker is inserted under `BEGIN IMMEDIATE` and is never
/// removed. Callers must complete this before allocating a launch generation.
pub fn consume_protected_launch_authority(
    conn: &Connection,
    launch_authority_id: &[u8; 16],
) -> Result<(), LaunchAuthorityConsumptionError> {
    if validate_uuid_v7_bytes(launch_authority_id).is_err() {
        return Err(LaunchAuthorityConsumptionError::InvalidAuthority);
    }
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| LaunchAuthorityConsumptionError::Storage)?;
    let key = format!(
        "protected_launch_authority_v1:{}",
        uuid::Uuid::from_bytes(*launch_authority_id)
    );
    let result = conn.execute(
        "INSERT OR IGNORE INTO _daemon_info (key, value) VALUES (?1, 'consumed')",
        [key],
    );
    match result {
        Ok(1) => conn
            .execute_batch("COMMIT")
            .map_err(|_| LaunchAuthorityConsumptionError::Storage),
        Ok(0) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(LaunchAuthorityConsumptionError::AlreadyConsumed)
        }
        Ok(_) | Err(_) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(LaunchAuthorityConsumptionError::Storage)
        }
    }
}

/// Allocates the next durable positive daemon launch generation.
///
/// The read, validation, increment, and write occur under one `BEGIN
/// IMMEDIATE` transaction. Corrupt state is never rewritten.
pub fn next_launch_generation(conn: &Connection) -> SqliteResult<u64> {
    const KEY: &str = "launch_generation";
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| {
        let current: Option<String> = conn
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = ?1",
                [KEY],
                |row| row.get(0),
            )
            .optional()?;
        let generation = match current {
            None => 1,
            Some(value) => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| launch_generation_corruption())?;
                if parsed == 0 || parsed.to_string() != value {
                    return Err(launch_generation_corruption());
                }
                parsed
                    .checked_add(1)
                    .ok_or_else(launch_generation_corruption)?
            }
        };
        conn.execute(
            "INSERT INTO _daemon_info (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (KEY, generation.to_string()),
        )?;
        Ok(generation)
    })();
    match result {
        Ok(generation) => {
            conn.execute_batch("COMMIT")?;
            Ok(generation)
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

/// Reserves a unique durable generation for one daemon-owned launch prelude.
///
/// This deliberately shares the canonical counter and transaction semantics
/// with ordinary daemon launch allocation; crash gaps remain valid.
pub fn reserve_launch_generation_for_prelude(conn: &Connection) -> SqliteResult<u64> {
    next_launch_generation(conn)
}

/// Confirms that a previously reserved positive generation is still current.
///
/// This is read-only: stale, future, zero, and corrupt values fail closed
/// without repairing or advancing the canonical launch counter.
pub fn validate_reserved_launch_generation(conn: &Connection, expected: u64) -> SqliteResult<()> {
    if expected == 0 {
        return Err(launch_generation_corruption());
    }
    let value: String = conn.query_row(
        "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
        [],
        |row| row.get(0),
    )?;
    let current = value
        .parse::<u64>()
        .map_err(|_| launch_generation_corruption())?;
    if current == 0 || current.to_string() != value || current != expected {
        return Err(launch_generation_corruption());
    }
    Ok(())
}

fn launch_generation_corruption() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "corrupt launch generation",
    )))
}

#[cfg(test)]
mod authority_launch_tests {
    use super::*;

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE _daemon_info (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .unwrap();
        connection
    }

    #[test]
    fn reserved_generations_are_unique_and_only_the_current_value_validates() {
        let connection = connection();
        assert_eq!(reserve_launch_generation_for_prelude(&connection).unwrap(), 1);
        assert_eq!(reserve_launch_generation_for_prelude(&connection).unwrap(), 2);
        assert!(validate_reserved_launch_generation(&connection, 2).is_ok());
        for invalid in [0, 1, 3] {
            assert!(validate_reserved_launch_generation(&connection, invalid).is_err());
        }
        assert_eq!(
            connection
                .query_row("SELECT value FROM _daemon_info WHERE key = 'launch_generation'", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "2"
        );
        connection
            .execute(
                "UPDATE _daemon_info SET value = '9' WHERE key = 'launch_generation'",
                [],
            )
            .unwrap();
        assert_eq!(reserve_launch_generation_for_prelude(&connection).unwrap(), 10);
        assert!(validate_reserved_launch_generation(&connection, 10).is_ok());
    }

    #[test]
    fn corrupt_and_overflowed_generations_fail_closed_without_rewrite() {
        let connection = connection();
        connection.execute("INSERT INTO _daemon_info VALUES ('launch_generation', '00')", []).unwrap();
        assert!(validate_reserved_launch_generation(&connection, 1).is_err());
        assert!(reserve_launch_generation_for_prelude(&connection).is_err());
        connection.execute("UPDATE _daemon_info SET value = ?1", [u64::MAX.to_string()]).unwrap();
        assert!(reserve_launch_generation_for_prelude(&connection).is_err());
        assert_eq!(connection.query_row("SELECT value FROM _daemon_info", [], |row| row.get::<_, String>(0)).unwrap(), u64::MAX.to_string());
    }
}
