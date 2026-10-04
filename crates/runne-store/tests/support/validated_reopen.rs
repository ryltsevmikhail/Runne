#![allow(dead_code)]

mod workspace;
#[allow(unused_imports)]
pub use workspace::seed_canonical_workspace;

use std::path::Path;
use std::sync::Arc;

use runne_application::ports::{CommitError, RuntimeAuthorityId};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::id::EventLogLineageId;
use runne_store::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, ensure_authority_id,
    ensure_event_log_lineage_id, generate_authority_id, open_managed_connection, read_authority_id,
    read_event_log_lineage_id, reopen_managed_connection_validated,
};
use runne_store::store::StoreTransaction;
use runne_store::{
    migration_store::SqliteMigrationControlStore,
    provider::{SqliteProviderDispatchStore, SqliteProviderExecutionStore},
};
use rusqlite::{Connection, Error as SqliteError};
use tempfile::TempDir;

pub struct ValidatedTestDatabase {
    _root: TempDir,
    path: String,
}

impl ValidatedTestDatabase {
    pub fn new(name: &str) -> Self {
        let root = tempfile::Builder::new().prefix(name).tempdir().unwrap();
        let daemon_dir = root.path().join("runne-daemon");
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
    let connection = open_managed_connection(Path::new(db_path), ConnectionMode::Writer)?;
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
    let writer =
        open_managed_connection(Path::new(db_path), ConnectionMode::Writer).map_err(unavailable)?;
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

pub fn initialize_store_with_database_authority(
    db_path: &str,
    database_authority_id: [u8; 16],
    runtime_authority_id: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
) -> Result<(StoreTransaction, MainDatabaseIdentity), CommitError> {
    let writer =
        open_managed_connection(Path::new(db_path), ConnectionMode::Writer).map_err(unavailable)?;
    apply_migrations(&writer).map_err(corrupt)?;
    ensure_authority_id(&writer, &database_authority_id).map_err(corrupt)?;
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
) -> Result<SqliteProviderDispatchStore, runne_store::provider::ProviderStoreError> {
    let connection = open_validated_connection(db_path, identity)
        .map_err(|_| runne_store::provider::ProviderStoreError::Unavailable)?;
    SqliteProviderDispatchStore::open_with_connection(db_path, connection)
}

pub fn open_provider_execution(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<SqliteProviderExecutionStore, runne_application::provider::ProviderAdmissionError> {
    let connection = open_validated_connection(db_path, identity)
        .map_err(|_| runne_application::provider::ProviderAdmissionError::RepositoryFailure)?;
    SqliteProviderExecutionStore::open_with_connection(db_path, connection)
}

pub struct ProviderTestDatabase {
    database: ValidatedTestDatabase,
    identity: MainDatabaseIdentity,
}

impl ProviderTestDatabase {
    pub fn identity(&self) -> MainDatabaseIdentity {
        self.identity
    }

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

    pub fn connection(&self) -> ManagedConnection {
        open_validated_connection(self.path(), self.identity).unwrap()
    }

    pub fn query_connection(&self) -> ManagedConnection {
        open_validated_reader(self.path(), self.identity).unwrap()
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

pub fn open_validated_reader(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<ManagedConnection, SqliteError> {
    reopen_managed_connection_validated(Path::new(db_path), ConnectionMode::Reader, |connection| {
        validate_main_database_identity(connection, identity)
    })
}

pub(super) fn open_validated_connection(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<ManagedConnection, SqliteError> {
    reopen_managed_connection_validated(
        Path::new(db_path),
        ConnectionMode::ValidatedReopen,
        |connection| validate_main_database_identity(connection, identity),
    )
}

fn read_main_database_identity(
    connection: &Connection,
) -> Result<MainDatabaseIdentity, SqliteError> {
    let authority_id = read_authority_id(connection)?.ok_or(SqliteError::InvalidQuery)?;
    let lineage_id = read_event_log_lineage_id(connection)?.ok_or(SqliteError::InvalidQuery)?;
    Ok(MainDatabaseIdentity {
        authority_id,
        lineage_id,
    })
}

fn validate_main_database_identity(
    connection: &Connection,
    identity: MainDatabaseIdentity,
) -> Result<(), SqliteError> {
    let actual = read_main_database_identity(connection)?;
    if actual == identity {
        Ok(())
    } else {
        Err(SqliteError::InvalidQuery)
    }
}

fn open_reader(db_path: &str) -> Result<ManagedConnection, SqliteError> {
    open_managed_connection(Path::new(db_path), ConnectionMode::Reader)
}

fn unavailable(_: SqliteError) -> CommitError {
    CommitError::StorageFailure(runne_application::ports::StorageFailureKind::Unavailable)
}

fn corrupt(_: SqliteError) -> CommitError {
    CommitError::StorageFailure(runne_application::ports::StorageFailureKind::CorruptData)
}
