use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use crate::QualificationReplayLedgerError;

const SCHEMA_ID: &str = "runne/qualification-runner-replay/v3";
const SCHEMA_VERSION: i64 = 3;
type SchemaObject = (String, String, String, Option<String>);

pub fn configure_connection(connection: &Connection) -> Result<(), QualificationReplayLedgerError> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| QualificationReplayLedgerError)?;
    let journal: String = connection
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    if !journal.eq_ignore_ascii_case("delete") {
        return Err(QualificationReplayLedgerError);
    }
    connection
        .execute_batch("PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; PRAGMA foreign_keys=ON;")
        .map_err(|_| QualificationReplayLedgerError)?;
    pragmas_are_exact(connection)
        .and_then(|exact| exact.then_some(()).ok_or(QualificationReplayLedgerError))
}

pub fn pragmas_are_exact(connection: &Connection) -> Result<bool, QualificationReplayLedgerError> {
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    let fullfsync: i64 = connection
        .pragma_query_value(None, "fullfsync", |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    Ok(synchronous == 3
        && fullfsync == 1
        && foreign_keys == 1
        && journal.eq_ignore_ascii_case("delete"))
}

pub fn integrity_is_exact(connection: &Connection) -> Result<bool, QualificationReplayLedgerError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    let foreign_key_error: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| QualificationReplayLedgerError)?;
    let actual_objects = schema_objects(connection)?;
    let expected = expected_schema()?;
    let expected_objects = schema_objects(&expected)?;
    let objects = actual_objects == expected_objects;
    let replay = crate::schema_integrity::replay_associations_are_exact(connection, true, true)?;
    let arms = crate::schema_integrity::bootstrap_arms_are_exact(connection)?;
    Ok(integrity == "ok" && foreign_key_error.is_none() && objects && replay && arms)
}

pub fn initialize_schema(
    connection: &Connection,
    database_was_created: bool,
) -> Result<(), QualificationReplayLedgerError> {
    let mut version = schema_version(connection)?;
    if version == 0 && database_was_created {
        connection
            .execute_batch(crate::schema_v1::V1_SCHEMA_SQL)
            .map_err(|_| QualificationReplayLedgerError)?;
        version = 1;
    }
    if version == 1 {
        upgrade_v1(connection)?;
        version = schema_version(connection)?;
    }
    if version == 2 {
        upgrade_v2(connection)?;
        version = schema_version(connection)?;
    }
    if version != SCHEMA_VERSION || schema_id(connection)? != SCHEMA_ID {
        return Err(QualificationReplayLedgerError);
    }
    Ok(())
}

fn expected_schema() -> Result<Connection, QualificationReplayLedgerError> {
    let connection = Connection::open_in_memory().map_err(|_| QualificationReplayLedgerError)?;
    connection
        .execute_batch(crate::schema_v1::V1_SCHEMA_SQL)
        .and_then(|()| connection.execute_batch(crate::schema_v2::UPGRADE_SQL))
        .and_then(|()| connection.execute_batch(crate::schema_v3::UPGRADE_SQL))
        .map_err(|_| QualificationReplayLedgerError)?;
    Ok(connection)
}

fn upgrade_v1(connection: &Connection) -> Result<(), QualificationReplayLedgerError> {
    transaction(connection, || {
        let version = schema_version(connection)?;
        if version == SCHEMA_VERSION && schema_id(connection)? == SCHEMA_ID {
            return Ok(());
        }
        if version != 1
            || schema_id(connection)? != "runne/qualification-runner-replay/v1"
            || !integrity_and_foreign_keys_are_clean(connection)?
            || schema_objects(connection)? != schema_objects(&v1_schema()?)?
            || !crate::schema_integrity::replay_associations_are_exact(connection, false, false)?
        {
            return Err(QualificationReplayLedgerError);
        }
        connection
            .execute_batch(crate::schema_v2::UPGRADE_SQL)
            .map_err(|_| QualificationReplayLedgerError)?;
        #[cfg(test)]
        migration_crash("before");
        Ok(())
    })?;
    #[cfg(test)]
    migration_crash("after");
    Ok(())
}

fn upgrade_v2(connection: &Connection) -> Result<(), QualificationReplayLedgerError> {
    transaction(connection, || {
        let version = schema_version(connection)?;
        let schema = schema_id(connection)?;
        if version == SCHEMA_VERSION && schema == SCHEMA_ID {
            return Ok(());
        }
        let clean = integrity_and_foreign_keys_are_clean(connection)?;
        let objects = schema_objects(connection)? == schema_objects(&v2_schema()?)?;
        let replay =
            crate::schema_integrity::replay_associations_are_exact(connection, true, false)?;
        if version != 2
            || schema != "runne/qualification-runner-replay/v2"
            || !clean
            || !objects
            || !replay
        {
            return Err(QualificationReplayLedgerError);
        }
        connection
            .execute_batch(crate::schema_v3::UPGRADE_SQL)
            .map_err(|_| QualificationReplayLedgerError)
    })
}

fn transaction(
    connection: &Connection,
    operation: impl FnOnce() -> Result<(), QualificationReplayLedgerError>,
) -> Result<(), QualificationReplayLedgerError> {
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| QualificationReplayLedgerError)?;
    if let Err(error) = operation() {
        let _ = connection.execute_batch("ROLLBACK");
        return Err(error);
    }
    connection
        .execute_batch("COMMIT")
        .map_err(|_| QualificationReplayLedgerError)
}

fn v1_schema() -> Result<Connection, QualificationReplayLedgerError> {
    let connection = Connection::open_in_memory().map_err(|_| QualificationReplayLedgerError)?;
    connection
        .execute_batch(crate::schema_v1::V1_SCHEMA_SQL)
        .map_err(|_| QualificationReplayLedgerError)?;
    Ok(connection)
}

fn v2_schema() -> Result<Connection, QualificationReplayLedgerError> {
    let connection = v1_schema()?;
    connection
        .execute_batch(crate::schema_v2::UPGRADE_SQL)
        .map_err(|_| QualificationReplayLedgerError)?;
    Ok(connection)
}

fn schema_version(connection: &Connection) -> Result<i64, QualificationReplayLedgerError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)
}

fn schema_id(connection: &Connection) -> Result<String, QualificationReplayLedgerError> {
    connection
        .query_row(
            "SELECT schema_id FROM ledger_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| QualificationReplayLedgerError)
}

fn integrity_and_foreign_keys_are_clean(
    connection: &Connection,
) -> Result<bool, QualificationReplayLedgerError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    let foreign_key_error: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| QualificationReplayLedgerError)?;
    Ok(integrity == "ok" && foreign_key_error.is_none())
}

fn schema_objects(
    connection: &Connection,
) -> Result<Vec<SchemaObject>, QualificationReplayLedgerError> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
        .map_err(|_| QualificationReplayLedgerError)?;
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(|_| QualificationReplayLedgerError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| QualificationReplayLedgerError)
}

#[cfg(test)]
fn migration_crash(boundary: &str) {
    if std::env::var("RUNNE_TEST_LEDGER_MIGRATION_CRASH")
        .ok()
        .as_deref()
        == Some(boundary)
    {
        std::process::abort();
    }
}
