#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;

use gocode_application::ports::{CommitError, RuntimeAuthorityId};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_domain::id::EventLogLineageId;
use gocode_store::schema::{
    apply_migrations, ensure_authority_id, ensure_event_log_lineage_id, generate_authority_id,
    open_existing_with_pragmas_validated, open_with_pragmas, read_authority_id,
    read_event_log_lineage_id,
};
use gocode_store::store::StoreTransaction;
use gocode_store::{
    migration_store::SqliteMigrationControlStore,
    provider::{SqliteProviderDispatchStore, SqliteProviderExecutionStore},
};
use rusqlite::{Connection, Error as SqliteError, OpenFlags};
use tempfile::TempDir;

pub struct ValidatedTestDatabase {
    _root: TempDir,
    path: String,
}

impl ValidatedTestDatabase {
    pub fn new(name: &str) -> Self {
        let root = tempfile::Builder::new().prefix(name).tempdir().unwrap();
        let daemon_dir = root.path().join("gocode-daemon");
        std::fs::create_dir(&daemon_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&daemon_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            _root: root,
            path: daemon_dir
                .join("event-log.sqlite")
                .to_str()
                .unwrap()
                .to_owned(),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn as_path(&self) -> &Path {
        Path::new(&self.path)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MainDatabaseIdentity {
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
}

pub fn initialize_database_identity(db_path: &str) -> Result<MainDatabaseIdentity, SqliteError> {
    let connection = open_with_pragmas(db_path)?;
    apply_migrations(&connection)?;
    ensure_authority_id(&connection, &generate_authority_id())?;
    let _ = ensure_event_log_lineage_id(&connection)?;
    read_main_database_identity(&connection)
}

pub fn initialize_store(
    db_path: &str,
    runtime_authority_id: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
) -> Result<(StoreTransaction, MainDatabaseIdentity), CommitError> {
    let writer = open_with_pragmas(db_path).map_err(unavailable)?;
    apply_migrations(&writer).map_err(corrupt)?;
    ensure_authority_id(&writer, &generate_authority_id()).map_err(corrupt)?;
    let _ = ensure_event_log_lineage_id(&writer).map_err(corrupt)?;
    let identity = read_main_database_identity(&writer).map_err(corrupt)?;
    let reader = open_reader(db_path).map_err(unavailable)?;
    StoreTransaction::open_with_connections(
        db_path,
        writer,
        reader,
        runtime_authority_id,
        prohibited_content,
    )
    .map(|store| (store, identity))
}

pub fn reopen_store(
    db_path: &str,
    identity: MainDatabaseIdentity,
    runtime_authority_id: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
) -> Result<StoreTransaction, CommitError> {
    let writer = open_validated_connection(db_path, identity).map_err(unavailable)?;
    let reader = open_validated_reader(db_path, identity).map_err(unavailable)?;
    StoreTransaction::open_with_connections(
        db_path,
        writer,
        reader,
        runtime_authority_id,
        prohibited_content,
    )
}

pub fn open_provider_dispatch(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<SqliteProviderDispatchStore, gocode_store::provider::ProviderStoreError> {
    let connection = open_validated_connection(db_path, identity)
        .map_err(|_| gocode_store::provider::ProviderStoreError::Unavailable)?;
    SqliteProviderDispatchStore::open_with_connection(db_path, connection)
}

pub fn open_provider_execution(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<SqliteProviderExecutionStore, gocode_application::provider::ProviderAdmissionError> {
    let connection = open_validated_connection(db_path, identity)
        .map_err(|_| gocode_application::provider::ProviderAdmissionError::RepositoryFailure)?;
    SqliteProviderExecutionStore::open_with_connection(db_path, connection)
}

pub struct ProviderTestDatabase {
    database: ValidatedTestDatabase,
    identity: MainDatabaseIdentity,
}

impl ProviderTestDatabase {
    pub fn new(name: &str) -> Self {
        let database = ValidatedTestDatabase::new(name);
        let identity = initialize_database_identity(database.path()).unwrap();
        Self { database, identity }
    }

    pub fn path(&self) -> &str {
        self.database.path()
    }

    pub fn as_path(&self) -> &Path {
        self.database.as_path()
    }

    pub fn dispatch(&self) -> SqliteProviderDispatchStore {
        open_provider_dispatch(self.path(), self.identity).unwrap()
    }

    pub fn execution(&self) -> SqliteProviderExecutionStore {
        open_provider_execution(self.path(), self.identity).unwrap()
    }

    pub fn connection(&self) -> Connection {
        open_validated_connection(self.path(), self.identity).unwrap()
    }

    pub fn query_connection(&self) -> Connection {
        let connection = self.connection();
        connection.execute_batch("PRAGMA query_only = ON;").unwrap();
        connection
    }
}

pub struct MigrationTestDatabase {
    database: ValidatedTestDatabase,
    identity: MainDatabaseIdentity,
}

impl MigrationTestDatabase {
    pub fn new(name: &str) -> Self {
        let database = ValidatedTestDatabase::new(name);
        let identity = initialize_database_identity(database.path()).unwrap();
        Self { database, identity }
    }

    pub fn open(&self) -> SqliteMigrationControlStore {
        let connection = open_validated_connection(self.database.path(), self.identity).unwrap();
        SqliteMigrationControlStore::open_with_connection(self.database.path(), connection).unwrap()
    }
}

fn open_validated_reader(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<Connection, SqliteError> {
    let reader = open_validated_connection(db_path, identity)?;
    reader.execute_batch("PRAGMA query_only = ON;")?;
    Ok(reader)
}

pub(super) fn open_validated_connection(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<Connection, SqliteError> {
    open_existing_with_pragmas_validated(Path::new(db_path), |connection| {
        validate_main_database_identity(connection, identity)
    })
}

fn read_main_database_identity(
    connection: &Connection,
) -> Result<MainDatabaseIdentity, SqliteError> {
    Ok(MainDatabaseIdentity {
        authority_id: read_authority_id(connection)?.ok_or(SqliteError::InvalidQuery)?,
        lineage_id: read_event_log_lineage_id(connection)?.ok_or(SqliteError::InvalidQuery)?,
    })
}

fn validate_main_database_identity(
    connection: &Connection,
    identity: MainDatabaseIdentity,
) -> Result<(), SqliteError> {
    if read_main_database_identity(connection)? == identity {
        Ok(())
    } else {
        Err(SqliteError::InvalidQuery)
    }
}

fn open_reader(db_path: &str) -> Result<Connection, SqliteError> {
    let reader = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    reader.execute_batch("PRAGMA query_only = ON;")?;
    Ok(reader)
}

fn unavailable(_: SqliteError) -> CommitError {
    CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::Unavailable)
}

fn corrupt(_: SqliteError) -> CommitError {
    CommitError::StorageFailure(gocode_application::ports::StorageFailureKind::CorruptData)
}
