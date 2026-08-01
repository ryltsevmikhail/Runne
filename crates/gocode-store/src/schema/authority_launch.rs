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

fn launch_generation_corruption() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "corrupt launch generation",
    )))
}
