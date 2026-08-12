use crate::{Connection, Digest, SecurityStateError, Sha256};

pub(crate) const LEDGER_SQL: &str = "CREATE TABLE mutation_ledger (runtime_authority_digest BLOB NOT NULL CHECK(length(runtime_authority_digest)=32), principal_digest BLOB NOT NULL CHECK(length(principal_digest)=32), operation_kind TEXT NOT NULL, target_kind TEXT NOT NULL, target_id BLOB NOT NULL, idempotency_key TEXT NOT NULL, expected_version INTEGER NOT NULL CHECK(expected_version>=0), semantic_digest BLOB NOT NULL CHECK(length(semantic_digest)=32), client_disposition TEXT NOT NULL, runtime_disposition TEXT, command_ref BLOB, outcome_ref BLOB, recovery_summary TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at>=0), updated_at INTEGER NOT NULL CHECK(updated_at>=0), PRIMARY KEY(runtime_authority_digest, principal_digest, idempotency_key)) STRICT";
pub(crate) const TRANSACTIONS_SQL: &str = "CREATE TABLE security_transactions (generation INTEGER PRIMARY KEY NOT NULL, transaction_digest BLOB NOT NULL CHECK(length(transaction_digest)=32), previous_anchor_digest BLOB NOT NULL CHECK(length(previous_anchor_digest)=32), sealed_transaction BLOB NOT NULL CHECK(length(sealed_transaction) BETWEEN 1 AND 80), commit_marker INTEGER NOT NULL CHECK(commit_marker=1)) STRICT";
pub(crate) const PROFILE_SQL: &str = "CREATE TABLE security_profile (singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1), profile_identity_digest BLOB NOT NULL CHECK(length(profile_identity_digest)=32), database_identity BLOB NOT NULL CHECK(length(database_identity)=32)) STRICT";

pub(crate) fn validate_v6_schema(connection: &Connection) -> Result<(), SecurityStateError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let meta: (i64, i64, Option<String>, i64) = connection.query_row(
        "SELECT schema_version,db_generation,last_transaction_digest,commit_marker FROM meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if version != 6
        || meta.0 != 6
        || meta.1 < 1
        || meta.2.as_deref().is_none_or(|value| !is_digest(value))
        || meta.3 != 1
        || !table_manifest(connection)?
        || !v5_tables_unchanged(connection)?
    {
        return Err(SecurityStateError::AdmissionFailed);
    }
    Ok(())
}

fn table_manifest(connection: &Connection) -> Result<bool, SecurityStateError> {
    let mut tables = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    tables.sort_unstable();
    let mut expected = crate::recent_root_schema_tables::TABLES
        .map(str::to_owned)
        .to_vec();
    expected.retain(|value| value != "mutation_ledger");
    expected.extend(
        [
            "mutation_ledger",
            "security_profile",
            "security_transactions",
        ]
        .map(str::to_owned),
    );
    expected.sort_unstable();
    if tables != expected || explicit_index_count(connection)? != 0 {
        return Ok(false);
    }
    for (table, sql, indexes) in [
        ("mutation_ledger", LEDGER_SQL, 1),
        ("security_transactions", TRANSACTIONS_SQL, 0),
        ("security_profile", PROFILE_SQL, 0),
    ] {
        if !exact(connection, table, sql)?
            || !strict(connection, table)?
            || automatic_index_count(connection, table)? != indexes
            || foreign_key_count(connection, table)? != 0
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v5_tables_unchanged(connection: &Connection) -> Result<bool, SecurityStateError> {
    for table in crate::recent_root_schema_tables::TABLES {
        if table == "mutation_ledger" {
            continue;
        }
        let Some(expected) = crate::recent_root_schema_tables::expected_sql_hash(5, table) else {
            return Ok(false);
        };
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        if format!(
            "{:x}",
            Sha256::digest(crate::recent_root_schema_normalize::normalize_sql(&actual))
        ) != expected
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn exact(connection: &Connection, table: &str, expected: &str) -> Result<bool, SecurityStateError> {
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    )?;
    Ok(crate::recent_root_schema_normalize::normalize_sql(&actual)
        == crate::recent_root_schema_normalize::normalize_sql(expected))
}
fn strict(connection: &Connection, table: &str) -> Result<bool, SecurityStateError> {
    connection
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE name=?1",
            [table],
            |row| row.get(0),
        )
        .map_err(SecurityStateError::from)
}
fn foreign_key_count(connection: &Connection, table: &str) -> Result<i64, SecurityStateError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)",
            [table],
            |row| row.get(0),
        )
        .map_err(SecurityStateError::from)
}
fn automatic_index_count(connection: &Connection, table: &str) -> Result<i64, SecurityStateError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_index_list(?1) WHERE origin IN ('pk','u')",
            [table],
            |row| row.get(0),
        )
        .map_err(SecurityStateError::from)
}
fn explicit_index_count(connection: &Connection) -> Result<i64, SecurityStateError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND sql IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .map_err(SecurityStateError::from)
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
