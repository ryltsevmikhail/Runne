use std::path::PathBuf;

use runne_store::schema::{
    ConnectionMode, ManagedConnection, read_authority_id, read_event_log_lineage_id,
    reopen_managed_connection_validated,
};
use rusqlite::{Connection, Error as SqliteError};
use tempfile::TempDir;

#[derive(Clone, Copy, PartialEq, Eq)]
struct MainDatabaseIdentity {
    authority_id: [u8; 16],
    lineage_id: runne_domain::id::EventLogLineageId,
}

pub(super) struct ReplayTestDatabase {
    _root: TempDir,
    path: PathBuf,
    identity: MainDatabaseIdentity,
}

impl ReplayTestDatabase {
    pub(super) fn capture(root: TempDir, path: PathBuf, connection: &Connection) -> Self {
        Self {
            _root: root,
            path,
            identity: read_main_database_identity(connection).unwrap(),
        }
    }

    pub(super) fn open_writer(&self) -> ManagedConnection {
        self.open_validated_connection(ConnectionMode::ValidatedReopen)
    }

    pub(super) fn open_reader(&self) -> ManagedConnection {
        self.open_validated_connection(ConnectionMode::Reader)
    }

    pub(super) fn replay_store(
        connection: ManagedConnection,
    ) -> runne_store::replay_store::ReplayStore {
        runne_store::replay_store::ReplayStore::new(connection)
    }

    fn open_validated_connection(&self, mode: ConnectionMode) -> ManagedConnection {
        reopen_managed_connection_validated(&self.path, mode, |connection| {
            if read_main_database_identity(connection)? == self.identity {
                Ok(())
            } else {
                Err(SqliteError::InvalidQuery)
            }
        })
        .unwrap()
    }
}

fn read_main_database_identity(
    connection: &Connection,
) -> Result<MainDatabaseIdentity, SqliteError> {
    Ok(MainDatabaseIdentity {
        authority_id: read_authority_id(connection)?.ok_or(SqliteError::InvalidQuery)?,
        lineage_id: read_event_log_lineage_id(connection)?.ok_or(SqliteError::InvalidQuery)?,
    })
}
