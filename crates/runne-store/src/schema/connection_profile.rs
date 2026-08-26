use std::ops::Deref;

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
///
/// Mutable dereferencing is deliberately unavailable, so public callers cannot
/// replace the factory-opened connection while retaining its capability.
///
/// ```compile_fail
/// use runne_store::schema::ManagedConnection;
/// use rusqlite::Connection;
///
/// fn replace_factory_connection(
///     managed: &mut ManagedConnection,
///     replacement: Connection,
/// ) -> Connection {
///     std::mem::replace(&mut **managed, replacement)
/// }
/// ```
pub struct ManagedConnection {
    connection: Connection,
    _validated: ConnectionProfileCapability,
    identity: Option<ConnectionIdentityGuard>,
}

mod managed_authority {
    pub trait Sealed {}
}

/// Sealed marker implemented only by factory-created managed connections.
pub trait ManagedConnectionAuthority: managed_authority::Sealed {}

impl managed_authority::Sealed for ManagedConnection {}
impl ManagedConnectionAuthority for ManagedConnection {}

impl ManagedConnection {
    pub(crate) fn with_connection_mut<T>(
        &mut self,
        operation: impl FnOnce(&mut Connection) -> T,
    ) -> T {
        operation(&mut self.connection)
    }

    pub(crate) fn transaction(&mut self) -> SqliteResult<Transaction<'_>> {
        self.connection.transaction()
    }

    pub(crate) fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> SqliteResult<Transaction<'_>> {
        self.connection.transaction_with_behavior(behavior)
    }
}

impl Deref for ManagedConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
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
    let (connection, identity) = open_connection_for_profile(path, mode)?;
    managed_after_profile(connection, mode, path == Path::new(":memory:"), identity)
}

#[cfg(test)]
pub(crate) fn open_test_shared_writer(db_path: &Path) -> SqliteResult<ManagedConnection> {
    let connection = Connection::open(db_path)?;
    connection.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
    )?;
    Ok(ManagedConnection {
        connection,
        _validated: ConnectionProfileCapability {
            mode: ConnectionMode::Writer,
            memory_database: false,
        },
        identity: None,
    })
}

fn managed_after_profile(
    connection: Connection,
    mode: ConnectionMode,
    memory_database: bool,
    mut identity: Option<ConnectionIdentityGuard>,
) -> SqliteResult<ManagedConnection> {
    verify_connection_identity(&connection, identity.as_ref())?;
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
    if let Some(identity) = identity.as_mut() {
        identity.retain_created_sidecars()?;
    }
    verify_connection_identity(&connection, identity.as_ref())?;
    Ok(ManagedConnection {
        connection,
        _validated: capability,
        identity,
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
    verify_connection_identity(&connection.connection, connection.identity.as_ref())?;
    verify_managed_profile(&connection.connection, &connection._validated)?;
    run_startup_gates_raw(&connection.connection, "")?;
    Ok(Readiness { _private: () })
}

/// Re-verifies the managed profile and schema before publication.
pub fn publication_from_managed(connection: &ManagedConnection) -> SqliteResult<PublicationPermit> {
    verify_connection_identity(&connection.connection, connection.identity.as_ref())?;
    verify_managed_profile(&connection.connection, &connection._validated)?;
    run_startup_gates_raw(&connection.connection, "")?;
    Ok(PublicationPermit { _private: () })
}

fn verify_connection_identity(
    connection: &Connection,
    identity: Option<&ConnectionIdentityGuard>,
) -> SqliteResult<()> {
    match identity {
        Some(identity) => identity.verify_with_sidecar_handle(connection),
        None => Ok(()),
    }
}

fn profile_mismatch(name: &str, actual: &str, expected: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
        Some(format!("PRAGMA {name} = '{actual}', expected '{expected}'")),
    )
}
