use crate::{Connection, Digest, SecurityStateError, Sha256};

pub const LEDGER_SQL: &str = "CREATE TABLE mutation_ledger (runtime_authority_digest BLOB NOT NULL CHECK(length(runtime_authority_digest)=32), principal_digest BLOB NOT NULL CHECK(length(principal_digest)=32), operation_kind TEXT NOT NULL, target_kind TEXT NOT NULL, target_id BLOB NOT NULL, idempotency_key TEXT NOT NULL, expected_version INTEGER NOT NULL CHECK(expected_version>=0), semantic_digest BLOB NOT NULL CHECK(length(semantic_digest)=32), normalized_command BLOB, canonical_outcome BLOB, resend_count INTEGER NOT NULL CHECK(resend_count BETWEEN 0 AND 1), client_disposition TEXT NOT NULL, runtime_disposition TEXT, command_ref BLOB, outcome_ref BLOB, recovery_summary TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at>=0), updated_at INTEGER NOT NULL CHECK(updated_at>=0), CHECK((normalized_command IS NOT NULL AND command_ref IS NOT NULL) OR (client_disposition='manual_resolution' AND runtime_disposition='indeterminate' AND normalized_command IS NULL AND command_ref IS NULL AND canonical_outcome IS NULL AND outcome_ref IS NULL AND resend_count=0 AND recovery_summary='v6_unrecoverable')), CHECK((canonical_outcome IS NULL AND outcome_ref IS NULL) OR (canonical_outcome IS NOT NULL AND outcome_ref IS NOT NULL)), PRIMARY KEY(runtime_authority_digest, principal_digest, idempotency_key)) STRICT";

pub fn validate_v7_schema(connection: &Connection) -> Result<(), SecurityStateError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let meta: (i64, i64, Option<String>, i64) = connection.query_row("SELECT schema_version,db_generation,last_transaction_digest,commit_marker FROM meta WHERE singleton=1", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
    if version != 7
        || meta.0 != 7
        || meta.1 < 1
        || meta.2.as_deref().is_none_or(|value| !digest(value))
        || meta.3 != 1
        || !manifest(connection)?
        || !v5_tables(connection)?
    {
        return Err(SecurityStateError::AdmissionFailed);
    }
    Ok(())
}

fn manifest(connection: &Connection) -> Result<bool, SecurityStateError> {
    let mut actual = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort_unstable();
    let mut expected = crate::recent_root_schema_tables::TABLES
        .map(str::to_owned)
        .to_vec();
    expected.retain(|table| table != "mutation_ledger");
    expected.extend(
        [
            "mutation_ledger",
            "security_profile",
            "security_transactions",
        ]
        .map(str::to_owned),
    );
    expected.sort_unstable();
    if actual != expected || !has_only_canonical_schema_objects(connection)? {
        return Ok(false);
    }
    for (table, sql, indexes) in [
        ("mutation_ledger", LEDGER_SQL, 1),
        (
            "security_transactions",
            crate::security_schema_v6::TRANSACTIONS_SQL,
            0,
        ),
        (
            "security_profile",
            crate::security_schema_v6::PROFILE_SQL,
            0,
        ),
    ] {
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        let strict: i64 = connection.query_row(
            "SELECT strict FROM pragma_table_list WHERE name=?1",
            [table],
            |row| row.get(0),
        )?;
        if crate::recent_root_schema_normalize::normalize_sql(&actual)
            != crate::recent_root_schema_normalize::normalize_sql(sql)
            || strict != 1
            || count(
                connection,
                "SELECT COUNT(*) FROM pragma_index_list(?1) WHERE origin IN ('pk','u')",
                Some(table),
            )? != indexes
            || count(
                connection,
                "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)",
                Some(table),
            )? != 0
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn has_only_canonical_schema_objects(
    connection: &Connection,
) -> Result<bool, SecurityStateError> {
    Ok(count(
        connection,
        "SELECT COUNT(*) FROM sqlite_schema WHERE type IN ('trigger','view') OR (type='index' AND sql IS NOT NULL)",
        None,
    )? == 0)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn v5_tables(connection: &Connection) -> Result<bool, SecurityStateError> {
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

fn count(
    connection: &Connection,
    query: &str,
    table: Option<&str>,
) -> Result<i64, SecurityStateError> {
    table.map_or_else(
        || {
            connection
                .query_row(query, [], |row| row.get(0))
                .map_err(SecurityStateError::from)
        },
        |table| {
            connection
                .query_row(query, [table], |row| row.get(0))
                .map_err(SecurityStateError::from)
        },
    )
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
