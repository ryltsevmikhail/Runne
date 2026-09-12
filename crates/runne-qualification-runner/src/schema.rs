use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use crate::QualificationReplayLedgerError;

const SCHEMA_ID: &str = "runne/qualification-runner-replay/v1";
const SCHEMA_VERSION: i64 = 1;
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
    Ok(integrity == "ok"
        && foreign_key_error.is_none()
        && schema_objects(connection)? == schema_objects(&expected_schema()?)?
        && fault_cases_have_exact_replay_keys(connection)?)
}

fn expected_schema() -> Result<Connection, QualificationReplayLedgerError> {
    let connection = Connection::open_in_memory().map_err(|_| QualificationReplayLedgerError)?;
    connection
        .execute_batch(SCHEMA_SQL)
        .map_err(|_| QualificationReplayLedgerError)?;
    Ok(connection)
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

fn fault_cases_have_exact_replay_keys(
    connection: &Connection,
) -> Result<bool, QualificationReplayLedgerError> {
    let incomplete: Option<i64> = connection.query_row(
        "SELECT 1 FROM fault_cases f LEFT JOIN replay_keys c ON c.domain=1 AND c.replay_key=f.context_id AND c.source_revision=f.source_revision AND c.workflow_run_id=f.workflow_run_id AND c.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys n ON n.domain=2 AND n.replay_key=f.context_nonce AND n.source_revision=f.source_revision AND n.workflow_run_id=f.workflow_run_id AND n.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys t ON t.domain=3 AND t.replay_key=f.ticket_id AND t.source_revision=f.source_revision AND t.workflow_run_id=f.workflow_run_id AND t.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys u ON u.domain=4 AND u.replay_key=f.ticket_nonce AND u.source_revision=f.source_revision AND u.workflow_run_id=f.workflow_run_id AND u.namespace_sha256=f.namespace_sha256 WHERE c.replay_key IS NULL OR n.replay_key IS NULL OR t.replay_key IS NULL OR u.replay_key IS NULL LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    let dangling: Option<i64> = connection.query_row(
        "SELECT 1 FROM replay_keys r WHERE NOT EXISTS (SELECT 1 FROM fault_cases f WHERE r.source_revision=f.source_revision AND r.workflow_run_id=f.workflow_run_id AND r.namespace_sha256=f.namespace_sha256 AND ((r.domain=1 AND r.replay_key=f.context_id) OR (r.domain=2 AND r.replay_key=f.context_nonce) OR (r.domain=3 AND r.replay_key=f.ticket_id) OR (r.domain=4 AND r.replay_key=f.ticket_nonce))) LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    Ok(incomplete.is_none() && dangling.is_none())
}

pub fn initialize_schema(
    connection: &Connection,
    database_was_created: bool,
) -> Result<(), QualificationReplayLedgerError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    if version == 0 && database_was_created {
        if connection.execute_batch(SCHEMA_SQL).is_err() {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(QualificationReplayLedgerError);
        }
    } else if version != SCHEMA_VERSION {
        return Err(QualificationReplayLedgerError);
    }
    let schema: String = connection
        .query_row(
            "SELECT schema_id FROM ledger_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| QualificationReplayLedgerError)?;
    (schema == SCHEMA_ID)
        .then_some(())
        .ok_or(QualificationReplayLedgerError)
}

const SCHEMA_SQL: &str = "BEGIN IMMEDIATE;
CREATE TABLE ledger_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_id TEXT NOT NULL) STRICT;
INSERT INTO ledger_meta VALUES (1, 'runne/qualification-runner-replay/v1');
CREATE TABLE immutable_runs (source_revision BLOB NOT NULL CHECK(length(source_revision)=20), workflow_run_id TEXT NOT NULL, namespace_sha256 BLOB NOT NULL CHECK(length(namespace_sha256)=32), candidate_sha256 BLOB NOT NULL CHECK(length(candidate_sha256)=32), raw_tuple_sha256 BLOB NOT NULL CHECK(length(raw_tuple_sha256)=32), manifest_sha256 BLOB NOT NULL CHECK(length(manifest_sha256)=32), profile_sha256 BLOB NOT NULL CHECK(length(profile_sha256)=32), PRIMARY KEY(source_revision, workflow_run_id, namespace_sha256)) STRICT;
CREATE TABLE replay_keys (domain INTEGER NOT NULL CHECK(domain BETWEEN 1 AND 4), replay_key BLOB NOT NULL CHECK(length(replay_key)=32), source_revision BLOB NOT NULL, workflow_run_id TEXT NOT NULL, namespace_sha256 BLOB NOT NULL, PRIMARY KEY(domain, replay_key), FOREIGN KEY(source_revision, workflow_run_id, namespace_sha256) REFERENCES immutable_runs(source_revision, workflow_run_id, namespace_sha256)) STRICT;
CREATE TABLE fault_cases (context_id BLOB NOT NULL CHECK(length(context_id)=32), context_nonce BLOB NOT NULL CHECK(length(context_nonce)=32), ticket_id BLOB NOT NULL CHECK(length(ticket_id)=32), ticket_nonce BLOB NOT NULL CHECK(length(ticket_nonce)=32), fingerprint BLOB NOT NULL UNIQUE CHECK(length(fingerprint)=32), source_revision BLOB NOT NULL, workflow_run_id TEXT NOT NULL, namespace_sha256 BLOB NOT NULL, FOREIGN KEY(source_revision, workflow_run_id, namespace_sha256) REFERENCES immutable_runs(source_revision, workflow_run_id, namespace_sha256)) STRICT;
PRAGMA user_version=1;
COMMIT;";
