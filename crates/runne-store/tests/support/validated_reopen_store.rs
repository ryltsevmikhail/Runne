use runne_store::schema::ManagedConnection;
use rusqlite::Error as SqliteError;

use super::validated_reopen::{self, MainDatabaseIdentity};

pub(crate) fn open_validated_reader(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<ManagedConnection, SqliteError> {
    validated_reopen::open_validated_reader(db_path, identity)
}

pub(crate) fn open_validated_writer(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<ManagedConnection, SqliteError> {
    validated_reopen::open_validated_connection(db_path, identity)
}
