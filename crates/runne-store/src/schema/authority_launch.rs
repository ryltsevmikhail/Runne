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

/// Confirms that a reserved generation is still current and has not been consumed.
///
/// This read-only check is used while a live daemon temporarily defers a stale
/// node lease during its own enrollment transition. A consumed-generation
/// watermark is authoritative even though consuming a reservation does not
/// advance the launch-generation counter.
pub fn validate_unconsumed_reserved_launch_generation(
    conn: &Connection,
    expected: u64,
) -> SqliteResult<()> {
    const CONSUMED_KEY: &str = "enrollment_launch_generation_consumed_v1";
    if expected == 0 {
        return Err(launch_generation_corruption());
    }
    // Read the canonical generation and consumption watermark in one SQLite
    // statement so an external writer cannot consume between separate reads.
    let (current, consumed): (Option<String>, Option<String>) = conn.query_row(
        "SELECT
                (SELECT value FROM _daemon_info WHERE key = 'launch_generation'),
                (SELECT value FROM _daemon_info WHERE key = ?1)",
        [CONSUMED_KEY],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let Some(current) = current else {
        return Err(launch_generation_corruption());
    };
    let current = parse_launch_generation(&current)?;
    if current != expected {
        return Err(launch_generation_corruption());
    }
    if let Some(consumed) = consumed {
        let consumed = parse_launch_generation(&consumed)?;
        if consumed >= expected {
            return Err(launch_generation_corruption());
        }
    }
    Ok(())
}

/// Atomically consumes the current enrollment launch reservation exactly once.
///
/// The high-water marker records the last consumed reservation. Reservations
/// skipped by a crash remain valid gaps, but a consumed value cannot replay.
pub fn consume_reserved_launch_generation(conn: &Connection, expected: u64) -> SqliteResult<()> {
    const CONSUMED_KEY: &str = "enrollment_launch_generation_consumed_v1";
    if expected == 0 {
        return Err(launch_generation_corruption());
    }
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| {
        let current: String = conn.query_row(
            "SELECT value FROM _daemon_info WHERE key = 'launch_generation'",
            [],
            |row| row.get(0),
        )?;
        let current = parse_launch_generation(&current)?;
        if current != expected {
            return Err(launch_generation_corruption());
        }
        let consumed: Option<String> = conn
            .query_row(
                "SELECT value FROM _daemon_info WHERE key = ?1",
                [CONSUMED_KEY],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(consumed) = consumed {
            let consumed = parse_launch_generation(&consumed)?;
            if consumed > current || consumed == expected {
                return Err(launch_generation_corruption());
            }
        }
        conn.execute(
            "INSERT INTO _daemon_info (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (CONSUMED_KEY, expected.to_string()),
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn parse_launch_generation(value: &str) -> SqliteResult<u64> {
    let generation = value
        .parse::<u64>()
        .map_err(|_| launch_generation_corruption())?;
    if generation == 0 || generation.to_string() != value {
        return Err(launch_generation_corruption());
    }
    Ok(generation)
}

fn launch_generation_corruption() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "corrupt launch generation",
    )))
}

#[cfg(test)]
#[path = "authority_launch_tests.rs"]
mod authority_launch_tests;
