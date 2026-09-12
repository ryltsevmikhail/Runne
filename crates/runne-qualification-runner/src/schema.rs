use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use crate::QualificationReplayLedgerError;

const SCHEMA_ID: &str = "runne/qualification-runner-replay/v2";
const SCHEMA_VERSION: i64 = 2;
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
        && replay_associations_are_exact(connection, true)?)
}

fn expected_schema() -> Result<Connection, QualificationReplayLedgerError> {
    let connection = Connection::open_in_memory().map_err(|_| QualificationReplayLedgerError)?;
    connection
        .execute_batch(crate::schema_v1::V1_SCHEMA_SQL)
        .and_then(|()| connection.execute_batch(UPGRADE_SQL))
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

fn replay_associations_are_exact(
    connection: &Connection,
    include_runs: bool,
) -> Result<bool, QualificationReplayLedgerError> {
    let incomplete: Option<i64> = connection.query_row(
        "SELECT 1 FROM fault_cases f LEFT JOIN replay_keys c ON c.domain=1 AND c.replay_key=f.context_id AND c.source_revision=f.source_revision AND c.workflow_run_id=f.workflow_run_id AND c.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys n ON n.domain=2 AND n.replay_key=f.context_nonce AND n.source_revision=f.source_revision AND n.workflow_run_id=f.workflow_run_id AND n.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys t ON t.domain=3 AND t.replay_key=f.ticket_id AND t.source_revision=f.source_revision AND t.workflow_run_id=f.workflow_run_id AND t.namespace_sha256=f.namespace_sha256 LEFT JOIN replay_keys u ON u.domain=4 AND u.replay_key=f.ticket_nonce AND u.source_revision=f.source_revision AND u.workflow_run_id=f.workflow_run_id AND u.namespace_sha256=f.namespace_sha256 WHERE c.replay_key IS NULL OR n.replay_key IS NULL OR t.replay_key IS NULL OR u.replay_key IS NULL LIMIT 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|_| QualificationReplayLedgerError)?;
    let mut dangling_sql = String::from(
        "SELECT 1 FROM replay_keys r WHERE NOT EXISTS (SELECT 1 FROM fault_cases f WHERE r.source_revision=f.source_revision AND r.workflow_run_id=f.workflow_run_id AND r.namespace_sha256=f.namespace_sha256 AND ((r.domain=1 AND r.replay_key=f.context_id) OR (r.domain=2 AND r.replay_key=f.context_nonce) OR (r.domain=3 AND r.replay_key=f.ticket_id) OR (r.domain=4 AND r.replay_key=f.ticket_nonce)))",
    );
    if include_runs {
        dangling_sql.push_str(" AND NOT EXISTS (SELECT 1 FROM run_bootstraps b WHERE r.source_revision=b.source_revision AND r.workflow_run_id=b.workflow_run_id AND r.namespace_sha256=b.namespace_sha256 AND ((r.domain=1 AND r.replay_key=b.context_id) OR (r.domain=2 AND r.replay_key=b.context_nonce)))");
        let missing: Option<i64> = connection.query_row(
            "SELECT 1 FROM run_bootstraps b LEFT JOIN replay_keys c ON c.domain=1 AND c.replay_key=b.context_id AND c.source_revision=b.source_revision AND c.workflow_run_id=b.workflow_run_id AND c.namespace_sha256=b.namespace_sha256 LEFT JOIN replay_keys n ON n.domain=2 AND n.replay_key=b.context_nonce AND n.source_revision=b.source_revision AND n.workflow_run_id=b.workflow_run_id AND n.namespace_sha256=b.namespace_sha256 WHERE c.replay_key IS NULL OR n.replay_key IS NULL LIMIT 1", [], |row| row.get(0),
        ).optional().map_err(|_| QualificationReplayLedgerError)?;
        if missing.is_some() {
            return Ok(false);
        }
    }
    dangling_sql.push_str(" LIMIT 1");
    let dangling: Option<i64> = connection
        .query_row(&dangling_sql, [], |row| row.get(0))
        .optional()
        .map_err(|_| QualificationReplayLedgerError)?;
    let mut owners_sql = String::from(
        "SELECT 1 FROM replay_keys r WHERE ((SELECT COUNT(*) FROM fault_cases f WHERE r.source_revision=f.source_revision AND r.workflow_run_id=f.workflow_run_id AND r.namespace_sha256=f.namespace_sha256 AND ((r.domain=1 AND r.replay_key=f.context_id) OR (r.domain=2 AND r.replay_key=f.context_nonce) OR (r.domain=3 AND r.replay_key=f.ticket_id) OR (r.domain=4 AND r.replay_key=f.ticket_nonce)))",
    );
    if include_runs {
        owners_sql.push_str(" + (SELECT COUNT(*) FROM run_bootstraps b WHERE r.source_revision=b.source_revision AND r.workflow_run_id=b.workflow_run_id AND r.namespace_sha256=b.namespace_sha256 AND ((r.domain=1 AND r.replay_key=b.context_id) OR (r.domain=2 AND r.replay_key=b.context_nonce)))");
    }
    owners_sql.push_str(") != 1 LIMIT 1");
    let shared: Option<i64> = connection
        .query_row(&owners_sql, [], |row| row.get(0))
        .optional()
        .map_err(|_| QualificationReplayLedgerError)?;
    let mut orphan_sql = String::from(
        "SELECT 1 FROM immutable_runs r WHERE NOT EXISTS (SELECT 1 FROM fault_cases f WHERE r.source_revision=f.source_revision AND r.workflow_run_id=f.workflow_run_id AND r.namespace_sha256=f.namespace_sha256)",
    );
    if include_runs {
        orphan_sql.push_str(" AND NOT EXISTS (SELECT 1 FROM run_bootstraps b WHERE r.source_revision=b.source_revision AND r.workflow_run_id=b.workflow_run_id AND r.namespace_sha256=b.namespace_sha256)");
    }
    orphan_sql.push_str(" LIMIT 1");
    let orphan: Option<i64> = connection
        .query_row(&orphan_sql, [], |row| row.get(0))
        .optional()
        .map_err(|_| QualificationReplayLedgerError)?;
    Ok(incomplete.is_none() && dangling.is_none() && shared.is_none() && orphan.is_none())
}

pub fn initialize_schema(
    connection: &Connection,
    database_was_created: bool,
) -> Result<(), QualificationReplayLedgerError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| QualificationReplayLedgerError)?;
    if version == 0 && database_was_created {
        if connection
            .execute_batch(crate::schema_v1::V1_SCHEMA_SQL)
            .is_err()
        {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(QualificationReplayLedgerError);
        }
        upgrade_v1(connection)?;
    } else if version == 1 {
        upgrade_v1(connection)?;
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

fn upgrade_v1(connection: &Connection) -> Result<(), QualificationReplayLedgerError> {
    // Serialize validation and migration so a concurrent opener sees either exact version.
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| QualificationReplayLedgerError)?;
    let result = (|| {
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| QualificationReplayLedgerError)?;
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        let oracle = Connection::open_in_memory().map_err(|_| QualificationReplayLedgerError)?;
        oracle
            .execute_batch(crate::schema_v1::V1_SCHEMA_SQL)
            .map_err(|_| QualificationReplayLedgerError)?;
        let meta: String = connection
            .query_row(
                "SELECT schema_id FROM ledger_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| QualificationReplayLedgerError)?;
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|_| QualificationReplayLedgerError)?;
        let foreign: Option<i64> = connection
            .query_row(
                "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| QualificationReplayLedgerError)?;
        if version != 1
            || meta != "runne/qualification-runner-replay/v1"
            || integrity != "ok"
            || foreign.is_some()
            || schema_objects(connection)? != schema_objects(&oracle)?
            || !replay_associations_are_exact(connection, false)?
        {
            return Err(QualificationReplayLedgerError);
        }
        connection
            .execute_batch(UPGRADE_BODY)
            .map_err(|_| QualificationReplayLedgerError)?;
        #[cfg(test)]
        migration_crash("before");
        Ok(())
    })();
    if result.is_err() {
        let _ = connection.execute_batch("ROLLBACK");
        return result;
    }
    connection
        .execute_batch("COMMIT")
        .map_err(|_| QualificationReplayLedgerError)?;
    #[cfg(test)]
    migration_crash("after");
    Ok(())
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

const UPGRADE_BODY: &str = "CREATE TABLE run_bootstraps (challenge BLOB NOT NULL CHECK(length(challenge)=32), run_not_after INTEGER NOT NULL CHECK(run_not_after BETWEEN 1 AND 9007199254740991), context_id BLOB NOT NULL UNIQUE CHECK(length(context_id)=32), context_nonce BLOB NOT NULL UNIQUE CHECK(length(context_nonce)=32), fingerprint BLOB NOT NULL UNIQUE CHECK(length(fingerprint)=32), source_revision BLOB NOT NULL, workflow_run_id TEXT NOT NULL, namespace_sha256 BLOB NOT NULL, PRIMARY KEY(source_revision, workflow_run_id, namespace_sha256), FOREIGN KEY(source_revision, workflow_run_id, namespace_sha256) REFERENCES immutable_runs(source_revision, workflow_run_id, namespace_sha256)) STRICT;
UPDATE ledger_meta SET schema_id='runne/qualification-runner-replay/v2' WHERE singleton=1;
PRAGMA user_version=2;";

// Fresh initialization and the oracle use the identical migration body.
const UPGRADE_SQL: &str = UPGRADE_BODY;
