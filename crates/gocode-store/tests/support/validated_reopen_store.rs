use rusqlite::{Connection, Error as SqliteError};

use super::validated_reopen::{self, MainDatabaseIdentity};

pub(crate) fn open_validated_reader(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<Connection, SqliteError> {
    let reader = validated_reopen::open_validated_connection(db_path, identity)?;
    reader.execute_batch("PRAGMA query_only = ON;")?;
    Ok(reader)
}

pub(crate) fn open_validated_writer(
    db_path: &str,
    identity: MainDatabaseIdentity,
) -> Result<Connection, SqliteError> {
    validated_reopen::open_validated_connection(db_path, identity)
}
