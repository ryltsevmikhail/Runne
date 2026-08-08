use std::ops::{Deref, DerefMut};

/// Factory-selected role for a managed SQLite connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Writable connection opened through the ordinary safe-file admission.
    Writer,
    /// Read-only connection whose connection-level query fence remains enabled.
    Reader,
    /// Writable existing connection admitted by a caller-owned validation closure.
    ValidatedReopen,
}

/// Non-forgeable proof that the factory applied and read back the profile.
pub struct ConnectionProfileCapability {
    mode: ConnectionMode,
    memory_database: bool,
}

/// SQLite connection that retains its factory-issued profile capability.
pub struct ManagedConnection {
    connection: Connection,
    _validated: ConnectionProfileCapability,
}

mod managed_authority {
    pub trait Sealed {}
}

/// Sealed marker implemented only by factory-created managed connections.
pub trait ManagedConnectionAuthority: managed_authority::Sealed {}

impl managed_authority::Sealed for ManagedConnection {}
impl ManagedConnectionAuthority for ManagedConnection {}

impl Deref for ManagedConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl DerefMut for ManagedConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

/// Successful startup-integrity and managed-profile verification.
pub struct Readiness {
    _private: (),
}

/// Successful publication-time managed-profile verification.
pub struct PublicationPermit {
    _private: (),
}

/// Opens a new or safely classified database using a managed writer/reader profile.
pub fn open_managed_connection(
    path: &Path,
    mode: ConnectionMode,
) -> SqliteResult<ManagedConnection> {
    if mode == ConnectionMode::ValidatedReopen {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let connection = open_connection_for_profile(path, mode)?;
    managed_after_profile(connection, mode, path == Path::new(":memory:"))
}

fn managed_after_profile(
    connection: Connection,
    mode: ConnectionMode,
    memory_database: bool,
) -> SqliteResult<ManagedConnection> {
    connection.execute_batch(
        "PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    #[cfg(target_os = "macos")]
    connection.execute_batch("PRAGMA fullfsync = ON;")?;
    if mode == ConnectionMode::Reader {
        connection.execute_batch("PRAGMA query_only = ON;")?;
    }
    let capability = ConnectionProfileCapability {
        mode,
        memory_database,
    };
    verify_managed_profile(&connection, &capability)?;
    Ok(ManagedConnection {
        connection,
        _validated: capability,
    })
}

fn verify_managed_profile(
    connection: &Connection,
    capability: &ConnectionProfileCapability,
) -> SqliteResult<()> {
    let journal_mode = if capability.memory_database {
        "memory"
    } else {
        "wal"
    };
    verify_pragma(connection, "journal_mode", journal_mode)?;
    verify_pragma(connection, "synchronous", "2")?;
    verify_pragma(connection, "foreign_keys", "1")?;
    verify_pragma(connection, "busy_timeout", "5000")?;
    #[cfg(target_os = "macos")]
    verify_pragma(connection, "fullfsync", "1")?;
    verify_pragma(
        connection,
        "query_only",
        if capability.mode == ConnectionMode::Reader {
            "1"
        } else {
            "0"
        },
    )
}

/// Runs integrity/schema gates only for a factory-managed connection.
pub fn readiness_from_managed(connection: &ManagedConnection) -> SqliteResult<Readiness> {
    verify_managed_profile(&connection.connection, &connection._validated)?;
    run_startup_gates_raw(&connection.connection, "")?;
    Ok(Readiness { _private: () })
}

/// Re-verifies the managed profile and schema before publication.
pub fn publication_from_managed(
    connection: &ManagedConnection,
) -> SqliteResult<PublicationPermit> {
    verify_managed_profile(&connection.connection, &connection._validated)?;
    run_startup_gates_raw(&connection.connection, "")?;
    Ok(PublicationPermit { _private: () })
}

fn profile_mismatch(name: &str, actual: &str, expected: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
        Some(format!(
            "PRAGMA {name} = '{actual}', expected '{expected}'"
        )),
    )
}
