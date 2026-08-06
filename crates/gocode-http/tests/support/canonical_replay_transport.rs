use std::path::{Path, PathBuf};

use gocode_store::schema::{
    open_existing_with_pragmas_validated, read_authority_id, read_event_log_lineage_id,
};
use rusqlite::{Connection, Error as SqliteError};
use tempfile::TempDir;

#[derive(Clone, Copy, PartialEq, Eq)]
struct MainDatabaseIdentity {
    authority_id: [u8; 16],
    lineage_id: gocode_domain::id::EventLogLineageId,
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

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn open_writer(&self) -> Connection {
        self.open_validated_connection()
    }

    pub(super) fn open_reader(&self) -> Connection {
        let reader = self.open_validated_connection();
        reader.execute_batch("PRAGMA query_only = ON;").unwrap();
        reader
    }

    pub(super) fn replay_store(connection: Connection) -> gocode_store::replay_store::ReplayStore {
        gocode_store::replay_store::ReplayStore::new(connection)
    }

    fn open_validated_connection(&self) -> Connection {
        open_existing_with_pragmas_validated(&self.path, |connection| {
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
