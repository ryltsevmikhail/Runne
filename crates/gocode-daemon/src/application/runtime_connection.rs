#[cfg(unix)]
use std::path::Path;

use gocode_domain::id::EventLogLineageId;
use gocode_store::schema::{read_authority_id, read_event_log_lineage_id};

use super::*;

pub(super) fn open_runtime_connection(
    db_path: &str,
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
    purpose: &str,
) -> Result<rusqlite::Connection, DaemonError> {
    let result = open_runtime_connection_inner(db_path, authority_id, lineage_id);
    result.map_err(|error| DaemonError::Bootstrap(format!("open {purpose}: {error}")))
}

#[cfg(unix)]
fn open_runtime_connection_inner(
    db_path: &str,
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
) -> rusqlite::Result<rusqlite::Connection> {
    gocode_store::schema::open_existing_with_pragmas_validated(Path::new(db_path), |connection| {
        validate_runtime_identity(connection, authority_id, lineage_id)
    })
}

#[cfg(not(unix))]
fn open_runtime_connection_inner(
    db_path: &str,
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
) -> rusqlite::Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;

    let connection = rusqlite::Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.execute_batch("PRAGMA query_only = ON;")?;
    validate_runtime_identity(&connection, authority_id, lineage_id)?;
    connection.execute_batch(
        "PRAGMA query_only = OFF;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    gocode_store::schema::run_startup_gates(&connection, db_path)?;
    Ok(connection)
}

fn validate_runtime_identity(
    connection: &rusqlite::Connection,
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
) -> rusqlite::Result<()> {
    if read_authority_id(connection)? == Some(authority_id)
        && read_event_log_lineage_id(connection)? == Some(lineage_id)
    {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}
